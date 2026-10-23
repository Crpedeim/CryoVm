package guest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

// sendErr ends request id with an error frame.
func sendErr(w *frameWriter, id uint64, code, msg string) {
	m, _ := agentproto.New(agentproto.TypeError, id, agentproto.ErrorBody{Code: code, Message: msg})
	_ = w.send(m)
}

func sendErrFrom(w *frameWriter, id uint64, err error) {
	sendErr(w, id, errCode(err), err.Error())
}

// errCode maps an OS error to a protocol error code. Order matters: EROFS
// is not a permission error to Go, but check it first anyway, so a
// read-only filesystem is reported as exactly that.
func errCode(err error) string {
	switch {
	case errors.Is(err, syscall.EROFS):
		return agentproto.CodeReadOnly
	case errors.Is(err, fs.ErrNotExist):
		return agentproto.CodeNotFound
	case errors.Is(err, fs.ErrPermission):
		return agentproto.CodePermission
	case errors.Is(err, syscall.EISDIR):
		return agentproto.CodeIsDir
	case errors.Is(err, syscall.ENOTDIR):
		return agentproto.CodeNotDir
	case errors.Is(err, fs.ErrExist):
		return agentproto.CodeExists
	default:
		return agentproto.CodeIO
	}
}

// cleanPath accepts only absolute paths. Relative paths would depend on the
// agent's working directory, which nobody on the host can see.
func cleanPath(p string) (string, bool) {
	if !filepath.IsAbs(p) {
		return "", false
	}
	return filepath.Clean(p), true
}

// runWrite receives an upload into a temporary file next to the target and
// renames it into place only after the size and checksum match. Readers in
// the sandbox see either the old file or the complete new one, never a
// half-written one, and a failed or cancelled upload leaves nothing behind.
func runWrite(ctx context.Context, id uint64, open agentproto.WriteOpen, in <-chan agentproto.Message, w *frameWriter) {
	path, ok := cleanPath(open.Path)
	if !ok {
		sendErr(w, id, agentproto.CodeInvalid, "path must be absolute: "+open.Path)
		return
	}
	dir := filepath.Dir(path)
	if open.Mkdirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			sendErrFrom(w, id, err)
			return
		}
	}
	mode := os.FileMode(open.Mode).Perm()
	if mode == 0 {
		mode = 0o644
	}

	// Same directory, so the final rename stays on one filesystem: rename
	// is only atomic within a filesystem.
	tmp, err := os.CreateTemp(dir, ".sbx-upload-*")
	if err != nil {
		sendErrFrom(w, id, err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()

	h := sha256.New()
	var n int64
	for {
		select {
		case <-ctx.Done():
			sendErr(w, id, agentproto.CodeCanceled, "upload cancelled")
			return
		case m := <-in:
			switch m.Type {
			case agentproto.TypeWriteChunk:
				var c agentproto.Chunk
				if err := m.Decode(&c); err != nil {
					sendErr(w, id, agentproto.CodeInvalid, "bad chunk: "+err.Error())
					return
				}
				if _, err := tmp.Write(c.Data); err != nil {
					sendErrFrom(w, id, err)
					return
				}
				h.Write(c.Data)
				n += int64(len(c.Data))
				// Ack only after the bytes are written: that's what makes
				// this flow control and not just a receipt.
				ack, _ := agentproto.New(agentproto.TypeAck, id, nil)
				_ = w.send(ack)

			case agentproto.TypeWriteClose:
				var wc agentproto.WriteClose
				if err := m.Decode(&wc); err != nil {
					sendErr(w, id, agentproto.CodeInvalid, "bad close: "+err.Error())
					return
				}
				sum := hex.EncodeToString(h.Sum(nil))
				if wc.Size != n || wc.SHA256 != sum {
					sendErr(w, id, agentproto.CodeChecksum, "received data does not match the sender's size or SHA-256")
					return
				}
				if err := tmp.Chmod(mode); err != nil {
					sendErrFrom(w, id, err)
					return
				}
				// Sync before rename: otherwise a crash could leave the new
				// name pointing at a file whose data never reached the disk.
				if err := tmp.Sync(); err != nil {
					sendErrFrom(w, id, err)
					return
				}
				if err := tmp.Close(); err != nil {
					sendErrFrom(w, id, err)
					return
				}
				if err := os.Rename(tmp.Name(), path); err != nil {
					sendErrFrom(w, id, err)
					return
				}
				committed = true
				syncDir(dir) // make the rename itself durable
				done, _ := agentproto.New(agentproto.TypeDone, id, agentproto.Done{Size: n, SHA256: sum})
				_ = w.send(done)
				return
			}
		}
	}
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// runRead streams a file to the host, never more than Window chunks ahead
// of the host's acks.
func runRead(ctx context.Context, id uint64, req agentproto.ReadReq, acks <-chan agentproto.Message, w *frameWriter) {
	path, ok := cleanPath(req.Path)
	if !ok {
		sendErr(w, id, agentproto.CodeInvalid, "path must be absolute: "+req.Path)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		sendErrFrom(w, id, err)
		return
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		sendErrFrom(w, id, err)
		return
	} else if fi.IsDir() {
		sendErr(w, id, agentproto.CodeIsDir, path+" is a directory")
		return
	}

	h := sha256.New()
	buf := make([]byte, agentproto.ChunkSize)
	var n int64
	inflight := 0
	for {
		for inflight >= agentproto.Window {
			select {
			case <-ctx.Done():
				sendErr(w, id, agentproto.CodeCanceled, "download cancelled")
				return
			case <-acks:
				inflight--
			}
		}
		k, err := io.ReadFull(f, buf)
		if k > 0 {
			h.Write(buf[:k])
			n += int64(k)
			m, _ := agentproto.New(agentproto.TypeChunk, id, agentproto.Chunk{Data: buf[:k]})
			if w.send(m) != nil {
				return
			}
			inflight++
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			sendErrFrom(w, id, err)
			return
		}
		select {
		case <-ctx.Done():
			sendErr(w, id, agentproto.CodeCanceled, "download cancelled")
			return
		default:
		}
	}
	done, _ := agentproto.New(agentproto.TypeDone, id, agentproto.Done{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	_ = w.send(done)
}

func infoOf(name string, fi fs.FileInfo) agentproto.FileInfo {
	return agentproto.FileInfo{
		Name:      name,
		Size:      fi.Size(),
		Mode:      uint32(fi.Mode().Perm()),
		ModTime:   fi.ModTime(),
		IsDir:     fi.IsDir(),
		IsSymlink: fi.Mode()&fs.ModeSymlink != 0,
	}
}

func runList(id uint64, req agentproto.PathReq, w *frameWriter) {
	path, ok := cleanPath(req.Path)
	if !ok {
		sendErr(w, id, agentproto.CodeInvalid, "path must be absolute: "+req.Path)
		return
	}
	entries, err := os.ReadDir(path) // sorted by name
	if err != nil {
		sendErrFrom(w, id, err)
		return
	}
	res := agentproto.ListResult{Entries: []agentproto.FileInfo{}}
	for _, e := range entries {
		if len(res.Entries) == agentproto.MaxListEntries {
			res.Truncated = true
			break
		}
		fi, err := e.Info() // like lstat: a symlink is described, not followed
		if err != nil {
			continue // removed while listing
		}
		res.Entries = append(res.Entries, infoOf(e.Name(), fi))
	}
	m, _ := agentproto.New(agentproto.TypeListResult, id, res)
	_ = w.send(m)
}

func runStat(id uint64, req agentproto.PathReq, w *frameWriter) {
	path, ok := cleanPath(req.Path)
	if !ok {
		sendErr(w, id, agentproto.CodeInvalid, "path must be absolute: "+req.Path)
		return
	}
	fi, err := os.Lstat(path)
	if err != nil {
		sendErrFrom(w, id, err)
		return
	}
	m, _ := agentproto.New(agentproto.TypeStatResult, id, infoOf(filepath.Base(path), fi))
	_ = w.send(m)
}
