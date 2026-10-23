// Package agent is the host side of the guest-agent connection. The host
// listens on one Unix socket per sandbox and the agent dials in, so the
// sandbox's identity comes from *which socket* it connected to, never from
// anything the agent claims. The hello's sandbox ID is only a sanity check.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

var ErrClosed = errors.New("agent: connection closed")

// DefaultHelloTimeout bounds how long a fresh connection may take to say
// hello, so a silent connection can't hold the listener hostage.
const DefaultHelloTimeout = 5 * time.Second

// Option configures a Listener.
type Option func(*Listener)

// WithHelloTimeout overrides DefaultHelloTimeout.
func WithHelloTimeout(d time.Duration) Option { return func(l *Listener) { l.helloTimeout = d } }

// Listener accepts agent connections for one sandbox. The newest successful
// connection replaces any older one.
type Listener struct {
	ln           net.Listener
	path         string
	sandboxID    string
	helloTimeout time.Duration // fixed before the accept loop starts: no lock needed

	mu      sync.Mutex
	cur     *Conn
	changed chan struct{} // closed and replaced whenever cur changes
	closed  bool
}

// Listen creates the socket at path, removing a stale one first.
func Listen(path, sandboxID string, opts ...Option) (*Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("agent: listen %s: %w", path, err)
	}
	l := &Listener{ln: ln, path: path, sandboxID: sandboxID, helloTimeout: DefaultHelloTimeout, changed: make(chan struct{})}
	for _, o := range opts {
		o(l)
	}
	go l.acceptLoop()
	return l, nil
}

func (l *Listener) Path() string { return l.path }

func (l *Listener) acceptLoop() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go l.handshake(c) // one slow or silent client must not block the next
	}
}

func (l *Listener) handshake(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(l.helloTimeout))
	m, err := agentproto.Read(c)
	if err != nil || m.Type != agentproto.TypeHello {
		c.Close()
		return
	}
	var h agentproto.Hello
	l.mu.Lock()
	want := l.sandboxID
	l.mu.Unlock()
	if err := m.Decode(&h); err != nil || h.SandboxID != want {
		reject, _ := agentproto.New(agentproto.TypeReject, 0, agentproto.Reject{
			Reason: fmt.Sprintf("this socket belongs to sandbox %q, not %q", want, h.SandboxID),
		})
		_ = agentproto.Write(c, reject)
		c.Close()
		return
	}
	welcome, _ := agentproto.New(agentproto.TypeWelcome, 0, agentproto.Welcome{HostTime: time.Now()})
	if err := agentproto.Write(c, welcome); err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})

	conn := newConn(c, h)
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		conn.Close()
		return
	}
	old := l.cur
	l.cur = conn
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

// Conn waits until a live agent connection exists and returns it.
func (l *Listener) Conn(ctx context.Context) (*Conn, error) {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, ErrClosed
		}
		cur, changed := l.cur, l.changed
		l.mu.Unlock()
		if cur != nil && !cur.isDone() {
			return cur, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("agent: waiting for sandbox %s to connect: %w", l.Expected(), ctx.Err())
		case <-changed: // a new connection arrived, or the listener closed
		}
	}
}

// Close stops accepting, closes the current connection and removes the socket.
// Expect changes which sandbox ID an agent must introduce itself with. A
// fork's listener first expects its source's ID (the agent was started as
// the source), then the fork's own once the agent has been renamed.
func (l *Listener) Expect(id string) {
	l.mu.Lock()
	l.sandboxID = id
	l.mu.Unlock()
}

// Expected is the sandbox ID the listener currently accepts.
func (l *Listener) Expected() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sandboxID
}

// StopAccepting closes the listening socket and removes its file, but
// keeps the current connection. Used before a checkpoint: from then on the
// agent's redials fail at once, so it can't slip back in between letting go
// of its connection and the checkpoint.
func (l *Listener) StopAccepting() error {
	err := l.ln.Close()
	_ = os.Remove(l.path)
	return err
}

// Current returns the connection the agent has now, if any, without
// waiting.
func (l *Listener) Current() *Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cur
}

func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	cur := l.cur
	close(l.changed)
	l.mu.Unlock()
	if cur != nil {
		cur.Close()
	}
	err := l.ln.Close()
	_ = os.Remove(l.path)
	return err
}

// Conn is one live agent connection. Requests from many goroutines are
// matched to their responses by ID.
type Conn struct {
	c     net.Conn
	Hello agentproto.Hello

	writeMu sync.Mutex
	nextID  atomic.Uint64

	mu      sync.Mutex
	pending map[uint64]*pendingReq
	done    chan struct{}
	err     error
}

// pendingReq receives the frames for one request ID. gone is closed when the
// requester stops listening, so the read loop never blocks forever handing a
// frame to someone who has left.
type pendingReq struct {
	ch   chan agentproto.Message
	gone chan struct{}
}

func newConn(c net.Conn, h agentproto.Hello) *Conn {
	conn := &Conn{c: c, Hello: h, pending: map[uint64]*pendingReq{}, done: make(chan struct{})}
	go conn.readLoop()
	return conn
}

// readLoop is the only reader. It routes every frame to its request.
//
// Known limitation: if one request's consumer is slow and its buffer fills,
// the read loop waits for it, and every other request on the connection
// waits too (head-of-line blocking). Per-request flow control would fix it;
// the buffer is large enough that it doesn't matter yet.
func (c *Conn) readLoop() {
	for {
		m, err := agentproto.Read(c.c)
		if err != nil {
			c.fail(err)
			return
		}
		c.mu.Lock()
		p := c.pending[m.ID]
		c.mu.Unlock()
		if p == nil {
			continue // a late frame for a request that already gave up
		}
		select {
		case p.ch <- m:
		case <-p.gone:
		}
	}
}

func (c *Conn) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return
	default:
	}
	c.err = err
	close(c.done)
}

func (c *Conn) isDone() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// Done is closed when the connection breaks.
func (c *Conn) Done() <-chan struct{} { return c.done }

func (c *Conn) Close() error {
	c.fail(ErrClosed)
	return c.c.Close()
}

func (c *Conn) register(buffer int) (uint64, *pendingReq, error) {
	id := c.nextID.Add(1)
	p := &pendingReq{ch: make(chan agentproto.Message, buffer), gone: make(chan struct{})}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isDone() {
		return 0, nil, ErrClosed
	}
	c.pending[id] = p
	return id, p, nil
}

func (c *Conn) unregister(id uint64, p *pendingReq) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
	close(p.gone)
}

func (c *Conn) send(m agentproto.Message) error {
	c.writeMu.Lock()
	err := agentproto.Write(c.c, m)
	c.writeMu.Unlock()
	if err != nil {
		c.fail(err)
	}
	return err
}

// Ping measures one round trip to the agent.
func (c *Conn) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	id, p, err := c.register(1)
	if err != nil {
		return 0, err
	}
	defer c.unregister(id, p)
	m, _ := agentproto.New(agentproto.TypePing, id, nil)
	if err := c.send(m); err != nil {
		return 0, err
	}
	select {
	case resp := <-p.ch:
		if resp.Type != agentproto.TypePong {
			return 0, fmt.Errorf("agent: expected pong, got %q", resp.Type)
		}
		return time.Since(start), nil
	case <-c.done:
		return 0, ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

type ExecRequest struct {
	Args    []string
	Env     []string // KEY=value
	Dir     string
	Stdin   []byte // at most agentproto.MaxStdin
	Timeout time.Duration
	Stdout  io.Writer // receives output as it arrives; nil discards
	Stderr  io.Writer
}

type ExecResult struct {
	ExitCode int    // -1 if a signal ended the command
	Signal   string // e.g. "killed"
	TimedOut bool
}

// Exec runs a command through the agent, streaming its output to the
// request's writers as it arrives. A non-zero exit code is a result, not an
// error. Cancelling ctx asks the agent to kill the command's whole process
// group; Exec then returns ctx's error once the agent confirms.
func (c *Conn) Exec(ctx context.Context, req ExecRequest) (ExecResult, error) {
	if len(req.Args) == 0 {
		return ExecResult{ExitCode: -1}, errors.New("agent: exec: empty command")
	}
	if len(req.Stdin) > agentproto.MaxStdin {
		return ExecResult{ExitCode: -1}, fmt.Errorf("agent: exec: stdin is %d bytes, limit is %d", len(req.Stdin), agentproto.MaxStdin)
	}
	id, p, err := c.register(256)
	if err != nil {
		return ExecResult{ExitCode: -1}, err
	}
	defer c.unregister(id, p)

	m, err := agentproto.New(agentproto.TypeExec, id, agentproto.Exec{
		Args: req.Args, Env: req.Env, Dir: req.Dir, Stdin: req.Stdin, TimeoutMs: req.Timeout.Milliseconds(),
	})
	if err != nil {
		return ExecResult{ExitCode: -1}, err
	}
	if err := c.send(m); err != nil {
		return ExecResult{ExitCode: -1}, err
	}

	ctxDone := ctx.Done()
	var giveUp <-chan time.Time
	for {
		select {
		case f := <-p.ch:
			switch f.Type {
			case agentproto.TypeOutput:
				var o agentproto.Output
				if f.Decode(&o) != nil {
					continue
				}
				w := req.Stdout
				if o.Stream == agentproto.StreamStderr {
					w = req.Stderr
				}
				if w != nil {
					_, _ = w.Write(o.Data)
				}
			case agentproto.TypeExit:
				var e agentproto.Exit
				if err := f.Decode(&e); err != nil {
					return ExecResult{ExitCode: -1}, fmt.Errorf("agent: bad exit frame: %w", err)
				}
				if e.Error != "" {
					return ExecResult{ExitCode: -1}, fmt.Errorf("agent: exec %q: %s", req.Args[0], e.Error)
				}
				res := ExecResult{ExitCode: e.Code, Signal: e.Signal, TimedOut: e.TimedOut}
				if ctxDone == nil { // we cancelled it
					return res, ctx.Err()
				}
				return res, nil
			}
		case <-ctxDone:
			ctxDone = nil // send cancel only once
			cancel, _ := agentproto.New(agentproto.TypeCancel, id, nil)
			_ = c.send(cancel)
			giveUp = time.After(5 * time.Second)
		case <-giveUp:
			return ExecResult{ExitCode: -1}, fmt.Errorf("agent: no exit after cancel: %w", ctx.Err())
		case <-c.done:
			return ExecResult{ExitCode: -1}, ErrClosed
		}
	}
}
