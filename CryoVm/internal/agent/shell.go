package agent

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

type ShellOptions struct {
	SessionID  string // empty: start a new session; otherwise attach to this one
	Cols, Rows uint16
	Command    []string
	Env        []string
	Dir        string
}

// ShellEnd says how an attachment ended. Either the client detached (or
// was displaced) and the session lives on, or the shell itself exited.
type ShellEnd struct {
	Detached bool
	Reason   string
	Exited   bool
	Code     int
	Signal   string
}

// Shell is one attachment to a session in the sandbox.
type Shell struct {
	c         *Conn
	id        uint64
	p         *pendingReq
	SessionID string
	Created   bool

	inCredits chan struct{} // the agent's acks for our input
	writeMu   sync.Mutex
	closeOnce sync.Once
}

// OpenShell starts a session, or attaches to an existing one, and returns
// once the agent has confirmed. Call Run to receive output, and Close when
// done.
func (c *Conn) OpenShell(ctx context.Context, opts ShellOptions) (*Shell, error) {
	id, p, err := c.register(2*agentproto.Window + 8)
	if err != nil {
		return nil, err
	}
	open, _ := agentproto.New(agentproto.TypeShellOpen, id, agentproto.ShellOpen{
		SessionID: opts.SessionID, Cols: opts.Cols, Rows: opts.Rows, Command: opts.Command, Env: opts.Env, Dir: opts.Dir,
	})
	if err := c.send(open); err != nil {
		c.unregister(id, p)
		return nil, err
	}
	select {
	case f := <-p.ch:
		switch f.Type {
		case agentproto.TypeShellReady:
			var r agentproto.ShellReady
			if err := f.Decode(&r); err != nil {
				c.unregister(id, p)
				return nil, err
			}
			s := &Shell{c: c, id: id, p: p, SessionID: r.SessionID, Created: r.Created,
				inCredits: make(chan struct{}, agentproto.Window)}
			for i := 0; i < agentproto.Window; i++ {
				s.inCredits <- struct{}{}
			}
			return s, nil
		case agentproto.TypeError:
			c.unregister(id, p)
			label := opts.SessionID
			if label == "" {
				label = "(new session)"
			}
			return nil, fileErr("shell", label, f)
		default:
			c.unregister(id, p)
			return nil, fmt.Errorf("shell: unexpected %q frame", f.Type)
		}
	case <-ctx.Done():
		c.unregister(id, p)
		return nil, ctx.Err()
	case <-c.done:
		c.unregister(id, p)
		return nil, ErrClosed
	}
}

// Write sends keystrokes. It blocks while the agent has Window input frames
// unacknowledged, so pasting a huge text can't flood the agent.
func (s *Shell) Write(b []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	sent := 0
	for len(b) > 0 {
		chunk := b[:min(len(b), 32<<10)]
		select {
		case <-s.inCredits:
		case <-s.c.done:
			return sent, ErrClosed
		}
		m, _ := agentproto.New(agentproto.TypePtyIn, s.id, agentproto.Chunk{Data: chunk})
		if err := s.c.send(m); err != nil {
			return sent, err
		}
		sent += len(chunk)
		b = b[len(chunk):]
	}
	return sent, nil
}

func (s *Shell) Resize(cols, rows uint16) error {
	m, _ := agentproto.New(agentproto.TypeResize, s.id, agentproto.Resize{Cols: cols, Rows: rows})
	return s.c.send(m)
}

// Detach asks to leave. Run returns once the agent confirms; the session
// keeps running in the sandbox.
func (s *Shell) Detach() error {
	m, _ := agentproto.New(agentproto.TypeDetach, s.id, nil)
	return s.c.send(m)
}

// Run copies the session's output to w until the attachment ends, and says
// how it ended. Each chunk is acknowledged only after w accepted it, so a
// slow terminal slows the shell down instead of piling up output. If ctx is
// cancelled, Run detaches (the session survives) and returns ctx's error.
func (s *Shell) Run(ctx context.Context, w io.Writer) (ShellEnd, error) {
	defer s.Close()
	ctxDone := ctx.Done()
	for {
		select {
		case f := <-s.p.ch:
			switch f.Type {
			case agentproto.TypePtyOut:
				var ch agentproto.Chunk
				if f.Decode(&ch) == nil {
					_, _ = w.Write(ch.Data)
				}
				ack, _ := agentproto.New(agentproto.TypeAck, s.id, nil)
				_ = s.c.send(ack)
			case agentproto.TypeAck:
				select {
				case s.inCredits <- struct{}{}:
				default:
				}
			case agentproto.TypeDetached:
				var d agentproto.Detached
				_ = f.Decode(&d)
				end := ShellEnd{Detached: true, Reason: d.Reason}
				if ctxDone == nil {
					return end, ctx.Err()
				}
				return end, nil
			case agentproto.TypeShellExit:
				var e agentproto.Exit
				_ = f.Decode(&e)
				return ShellEnd{Exited: true, Code: e.Code, Signal: e.Signal}, nil
			case agentproto.TypeError:
				return ShellEnd{}, fileErr("shell", s.SessionID, f)
			}
		case <-ctxDone:
			ctxDone = nil
			_ = s.Detach()
		case <-s.c.done:
			return ShellEnd{}, ErrClosed
		}
	}
}

// Close releases the attachment's request. It doesn't detach: use Detach,
// or cancel Run's context, for that.
func (s *Shell) Close() {
	s.closeOnce.Do(func() { s.c.unregister(s.id, s.p) })
}

// Sessions lists the shell sessions alive in the sandbox.
func (c *Conn) Sessions(ctx context.Context) (agentproto.SessionList, error) {
	var out agentproto.SessionList
	err := c.call(ctx, "sessions", agentproto.TypeShellList, agentproto.TypeShellListed, "", nil, &out)
	return out, err
}

// KillSession ends a session: SIGHUP to its processes, then SIGKILL.
func (c *Conn) KillSession(ctx context.Context, id string) error {
	return c.call(ctx, "kill session", agentproto.TypeShellKill, agentproto.TypeShellKilled, id, agentproto.ShellKill{SessionID: id}, nil)
}
