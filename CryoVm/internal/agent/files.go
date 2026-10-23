package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

// Sentinel errors for file operations. A *FileError unwraps to one of them,
// so callers can write errors.Is(err, agent.ErrNotFound).
var (
	ErrNotFound   = errors.New("not found")
	ErrPermission = errors.New("permission denied")
	ErrReadOnly   = errors.New("read-only file system")
	ErrExists     = errors.New("already exists")
	ErrIsDir      = errors.New("is a directory")
	ErrNotDir     = errors.New("not a directory")
	ErrChecksum   = errors.New("checksum mismatch")
	ErrInvalid    = errors.New("invalid request")
	ErrIO         = errors.New("i/o error")
	ErrConflict   = errors.New("conflict") // e.g. removing a process that's still running
)

var codeErrors = map[string]error{
	agentproto.CodeNotFound:   ErrNotFound,
	agentproto.CodePermission: ErrPermission,
	agentproto.CodeReadOnly:   ErrReadOnly,
	agentproto.CodeExists:     ErrExists,
	agentproto.CodeIsDir:      ErrIsDir,
	agentproto.CodeNotDir:     ErrNotDir,
	agentproto.CodeChecksum:   ErrChecksum,
	agentproto.CodeInvalid:    ErrInvalid,
	agentproto.CodeCanceled:   context.Canceled,
	agentproto.CodeConflict:   ErrConflict,
}

// FileError is a failure reported by the agent for one path.
type FileError struct {
	Op, Path, Code, Message string
}

func (e *FileError) Error() string { return fmt.Sprintf("%s %s: %s", e.Op, e.Path, e.Message) }

func (e *FileError) Unwrap() error {
	if err, ok := codeErrors[e.Code]; ok {
		return err
	}
	return ErrIO
}

func fileErr(op, path string, m agentproto.Message) error {
	var b agentproto.ErrorBody
	if err := m.Decode(&b); err != nil {
		return fmt.Errorf("%s %s: bad error frame: %w", op, path, err)
	}
	return &FileError{Op: op, Path: path, Code: b.Code, Message: b.Message}
}

type WriteOptions struct {
	Mode   os.FileMode // 0 means 0644
	Mkdirs bool        // create missing parent directories
}

// TransferResult describes what was transferred and verified.
type TransferResult struct {
	Size   int64
	SHA256 string
}

// cancelTransfer asks the agent to abort request id and waits briefly for
// its final frame, so the agent has cleaned up before we return.
func (c *Conn) cancelTransfer(id uint64, p *pendingReq) {
	m, _ := agentproto.New(agentproto.TypeCancel, id, nil)
	if c.send(m) != nil {
		return
	}
	giveUp := time.After(5 * time.Second)
	for {
		select {
		case f := <-p.ch:
			if f.Type == agentproto.TypeDone || f.Type == agentproto.TypeError || f.Type == agentproto.TypeLogsEnd {
				return
			}
		case <-giveUp:
			return
		case <-c.done:
			return
		}
	}
}

// WriteFile uploads r to path inside the sandbox. The file appears only
// once every byte has arrived and its SHA-256 matches; until then the old
// file, if any, is untouched.
//
// r is read in a separate goroutine, so a source that stalls (a quiet pipe
// or network stream) can't stop cancellation from working. If ctx is
// cancelled while r is blocked, that goroutine finishes when r returns;
// closing r releases it.
func (c *Conn) WriteFile(ctx context.Context, path string, r io.Reader, opts WriteOptions) (TransferResult, error) {
	id, p, err := c.register(2*agentproto.Window + 4)
	if err != nil {
		return TransferResult{}, err
	}
	defer c.unregister(id, p)

	open, _ := agentproto.New(agentproto.TypeWriteOpen, id, agentproto.WriteOpen{
		Path: path, Mode: uint32(opts.Mode.Perm()), Mkdirs: opts.Mkdirs,
	})
	if err := c.send(open); err != nil {
		return TransferResult{}, err
	}

	type piece struct {
		data []byte
		err  error
	}
	pieces := make(chan piece)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			buf := make([]byte, agentproto.ChunkSize) // fresh each time: the previous one was handed over
			k, err := io.ReadFull(r, buf)
			select {
			case pieces <- piece{buf[:k], err}:
			case <-stop:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	h := sha256.New()
	var n int64
	inflight := 0

	// handle processes one frame from the agent. An error frame can arrive
	// at any time (bad path, disk full); acks free window space.
	handle := func(f agentproto.Message) error {
		switch f.Type {
		case agentproto.TypeAck:
			inflight--
		case agentproto.TypeError:
			return fileErr("write", path, f)
		}
		return nil
	}

	for sending := true; sending; {
		// Only offer to take the next piece while the window has room.
		var next <-chan piece
		if inflight < agentproto.Window {
			next = pieces
		}
		select {
		case pc := <-next:
			if len(pc.data) > 0 {
				h.Write(pc.data)
				n += int64(len(pc.data))
				m, _ := agentproto.New(agentproto.TypeWriteChunk, id, agentproto.Chunk{Data: pc.data})
				if err := c.send(m); err != nil {
					return TransferResult{}, err
				}
				inflight++
			}
			if pc.err == io.EOF || pc.err == io.ErrUnexpectedEOF {
				sending = false
			} else if pc.err != nil {
				c.cancelTransfer(id, p)
				return TransferResult{}, fmt.Errorf("write %s: reading source: %w", path, pc.err)
			}
		case f := <-p.ch:
			if err := handle(f); err != nil {
				return TransferResult{}, err
			}
		case <-ctx.Done():
			c.cancelTransfer(id, p)
			return TransferResult{}, ctx.Err()
		case <-c.done:
			return TransferResult{}, ErrClosed
		}
	}

	sum := hex.EncodeToString(h.Sum(nil))
	closeMsg, _ := agentproto.New(agentproto.TypeWriteClose, id, agentproto.WriteClose{Size: n, SHA256: sum})
	if err := c.send(closeMsg); err != nil {
		return TransferResult{}, err
	}
	for {
		select {
		case f := <-p.ch:
			switch f.Type {
			case agentproto.TypeDone:
				var d agentproto.Done
				if err := f.Decode(&d); err != nil {
					return TransferResult{}, err
				}
				if d.SHA256 != sum || d.Size != n {
					return TransferResult{}, &FileError{Op: "write", Path: path, Code: agentproto.CodeChecksum, Message: "agent committed different data"}
				}
				return TransferResult{Size: n, SHA256: sum}, nil
			case agentproto.TypeError:
				return TransferResult{}, fileErr("write", path, f)
			}
		case <-ctx.Done():
			c.cancelTransfer(id, p)
			return TransferResult{}, ctx.Err()
		case <-c.done:
			return TransferResult{}, ErrClosed
		}
	}
}

// ReadFile downloads path from the sandbox into w, verifying its SHA-256.
// Each chunk is acknowledged only after w has accepted it, so a slow w slows
// the agent down instead of filling memory. Cancellation is checked between
// chunks: a w that blocks forever blocks ReadFile with it.
func (c *Conn) ReadFile(ctx context.Context, path string, w io.Writer) (TransferResult, error) {
	id, p, err := c.register(2*agentproto.Window + 4)
	if err != nil {
		return TransferResult{}, err
	}
	defer c.unregister(id, p)

	req, _ := agentproto.New(agentproto.TypeRead, id, agentproto.ReadReq{Path: path})
	if err := c.send(req); err != nil {
		return TransferResult{}, err
	}
	h := sha256.New()
	var n int64
	for {
		select {
		case f := <-p.ch:
			switch f.Type {
			case agentproto.TypeChunk:
				var ch agentproto.Chunk
				if err := f.Decode(&ch); err != nil {
					c.cancelTransfer(id, p)
					return TransferResult{}, err
				}
				if _, err := w.Write(ch.Data); err != nil {
					c.cancelTransfer(id, p)
					return TransferResult{}, fmt.Errorf("read %s: writing destination: %w", path, err)
				}
				h.Write(ch.Data)
				n += int64(len(ch.Data))
				ack, _ := agentproto.New(agentproto.TypeAck, id, nil)
				if err := c.send(ack); err != nil {
					return TransferResult{}, err
				}
			case agentproto.TypeDone:
				var d agentproto.Done
				if err := f.Decode(&d); err != nil {
					return TransferResult{}, err
				}
				sum := hex.EncodeToString(h.Sum(nil))
				if d.SHA256 != sum || d.Size != n {
					return TransferResult{}, &FileError{Op: "read", Path: path, Code: agentproto.CodeChecksum, Message: "received data does not match the agent's size or SHA-256"}
				}
				return TransferResult{Size: n, SHA256: sum}, nil
			case agentproto.TypeError:
				return TransferResult{}, fileErr("read", path, f)
			}
		case <-ctx.Done():
			c.cancelTransfer(id, p)
			return TransferResult{}, ctx.Err()
		case <-c.done:
			return TransferResult{}, ErrClosed
		}
	}
}

// simple sends one request and waits for one reply of type want.
func (c *Conn) simple(ctx context.Context, op, typ, want, path string, out any) error {
	return c.call(ctx, op, typ, want, path, agentproto.PathReq{Path: path}, out)
}

// call sends one request with body and waits for one reply of type want.
// out may be nil for replies without a body.
func (c *Conn) call(ctx context.Context, op, typ, want, path string, body, out any) error {
	id, p, err := c.register(1)
	if err != nil {
		return err
	}
	defer c.unregister(id, p)
	m, _ := agentproto.New(typ, id, body)
	if err := c.send(m); err != nil {
		return err
	}
	handle := func(f agentproto.Message) error {
		switch f.Type {
		case want:
			if out == nil {
				return nil
			}
			return f.Decode(out)
		case agentproto.TypeError:
			return fileErr(op, path, f)
		default:
			return fmt.Errorf("%s %s: unexpected %q frame", op, path, f.Type)
		}
	}
	select {
	case f := <-p.ch:
		return handle(f)
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		// A reply and the close can both be ready, and select picks among
		// ready cases at random. The reader delivers every frame before it
		// signals the close, so a reply that came first is already here:
		// take it. (Day 14: the quiesce's "quiesced", sent just before the
		// agent closes its end, sometimes lost this coin toss.)
		select {
		case f := <-p.ch:
			return handle(f)
		default:
			return ErrClosed
		}
	}
}

// ListDir lists a directory. Truncated is true past MaxListEntries.
func (c *Conn) ListDir(ctx context.Context, path string) (agentproto.ListResult, error) {
	var res agentproto.ListResult
	err := c.simple(ctx, "list", agentproto.TypeList, agentproto.TypeListResult, path, &res)
	return res, err
}

// Stat describes one path without following a final symlink.
func (c *Conn) Stat(ctx context.Context, path string) (agentproto.FileInfo, error) {
	var fi agentproto.FileInfo
	err := c.simple(ctx, "stat", agentproto.TypeStat, agentproto.TypeStatResult, path, &fi)
	return fi, err
}
