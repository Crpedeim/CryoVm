package guest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

// ring keeps the most recent bytes written to it, overwriting the oldest.
type ring struct {
	buf  []byte
	pos  int
	full bool
}

func newRing(n int) *ring { return &ring{buf: make([]byte, n)} }

func (r *ring) Write(p []byte) {
	for len(p) > 0 {
		n := copy(r.buf[r.pos:], p)
		p = p[n:]
		r.pos += n
		if r.pos == len(r.buf) {
			r.pos, r.full = 0, true
		}
	}
}

// Bytes returns the contents, oldest first.
func (r *ring) Bytes() []byte {
	if !r.full {
		return append([]byte(nil), r.buf[:r.pos]...)
	}
	return append(append([]byte(nil), r.buf[r.pos:]...), r.buf[:r.pos]...)
}

// attachment is one client connected to a session. Output to it is flow
// controlled with credits, exactly like a download: at most Window frames
// unacknowledged.
type attachment struct {
	id      uint64
	w       *frameWriter
	credits chan struct{}
	gone    chan struct{} // closed when this attachment ends, for any reason
	once    sync.Once
	sendMu  sync.Mutex // keeps replay, live output and the final frame in order
}

func newAttachment(id uint64, w *frameWriter) *attachment {
	a := &attachment{id: id, w: w, credits: make(chan struct{}, agentproto.Window), gone: make(chan struct{})}
	for i := 0; i < agentproto.Window; i++ {
		a.credits <- struct{}{}
	}
	return a
}

func (a *attachment) credit() {
	select {
	case a.credits <- struct{}{}:
	default: // more acks than frames sent: ignore rather than overflow
	}
}

// sendOutput sends terminal output, waiting for credits. It gives up as
// soon as the attachment ends, so a vanished client never blocks the shell.
func (a *attachment) sendOutput(data []byte) {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	for len(data) > 0 {
		chunk := data[:min(len(data), 32<<10)]
		select {
		case <-a.credits:
		case <-a.gone:
			return
		}
		m, _ := agentproto.New(agentproto.TypePtyOut, a.id, agentproto.Chunk{Data: chunk})
		if a.w.send(m) != nil {
			return
		}
		data = data[len(chunk):]
	}
}

// end finishes the attachment with one final frame (nil: none, the
// connection is gone). It closes gone first, so a sendOutput waiting for
// credits lets go of sendMu, then sends the final frame after any output
// already in flight. However an attachment ends, the client gets exactly
// one final frame.
func (a *attachment) end(final *agentproto.Message) {
	a.once.Do(func() {
		close(a.gone)
		if final != nil {
			a.sendMu.Lock()
			_ = a.w.send(*final)
			a.sendMu.Unlock()
		}
	})
}

func detachedFrame(id uint64, reason string) *agentproto.Message {
	m, _ := agentproto.New(agentproto.TypeDetached, id, agentproto.Detached{Reason: reason})
	return &m
}

// shellSession is one shell on a PTY. It belongs to the agent, not to any
// connection: clients come and go, the shell keeps running.
type shellSession struct {
	id      string
	command []string
	started time.Time
	master  *os.File
	pid     int

	mu       sync.Mutex
	scroll   *ring
	att      *attachment
	exited   bool
	pumpDone chan struct{}
	done     chan struct{} // closed when the session has fully ended
}

type sessionTable struct {
	mu    sync.Mutex
	m     map[string]*shellSession
	procs *procTable
}

func newSessionTable(procs *procTable) *sessionTable {
	return &sessionTable{m: map[string]*shellSession{}, procs: procs}
}

func newSessionID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "s-" + hex.EncodeToString(b)
}

var errNoSession = errors.New("no such session")

func defaultShell() []string {
	if _, err := exec.LookPath("bash"); err == nil {
		return []string{"bash"}
	}
	return []string{"sh"}
}

// start launches a new shell on a fresh PTY.
func (t *sessionTable) start(open agentproto.ShellOpen) (*shellSession, error) {
	command := open.Command
	if len(command) == 0 {
		command = defaultShell()
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return nil, err
	}
	cols, rows := open.Cols, open.Rows
	if cols == 0 || rows == 0 {
		cols, rows = 80, 24
	}
	master, slavePath, err := openPTY()
	if err != nil {
		return nil, err
	}
	if err := setWinsize(master, cols, rows); err != nil {
		master.Close()
		return nil, err
	}
	// O_NOCTTY is essential. Opening a terminal without it makes it the
	// opener's controlling terminal if the opener leads a session and has
	// none yet, and inside a sandbox the agent is PID 1, which does. The
	// agent would silently claim the shell's terminal, the shell's own
	// claim (Setctty) would then fail with EPERM, and when the terminal
	// closed, its hangup would be sent to the agent.
	slave, err := os.OpenFile(slavePath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, err
	}
	env := mergeEnv(os.Environ(), append([]string{"TERM=xterm-256color"}, open.Env...))
	attr := &os.ProcAttr{
		Dir:   open.Dir,
		Env:   env,
		Files: []*os.File{slave, slave, slave},
		// A new session with the PTY as its controlling terminal: that's
		// what makes Ctrl+C, job control and SIGWINCH reach the shell.
		// Ctty is a descriptor number in the child: Files[0].
		Sys: &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0},
	}
	pid, status, err := t.procs.start(path, command, attr)
	// Only the shell holds the slave now. When it, and everything it
	// started, has closed it, reads from the master fail with EIO.
	slave.Close()
	if err != nil {
		master.Close()
		return nil, err
	}
	s := &shellSession{
		id: newSessionID(), command: command, started: time.Now(), master: master, pid: pid,
		scroll: newRing(agentproto.ScrollbackSize), pumpDone: make(chan struct{}), done: make(chan struct{}),
	}
	t.mu.Lock()
	t.m[s.id] = s
	t.mu.Unlock()
	go s.pump()
	go t.waitExit(s, status)
	return s, nil
}

func (t *sessionTable) get(id string) (*shellSession, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.m[id]
	if s == nil {
		return nil, errNoSession
	}
	return s, nil
}

// pump copies output from the PTY into the scrollback and to whoever is
// attached. With nobody attached, output still goes to the scrollback, so
// the shell never blocks on a missing client.
func (s *shellSession) pump() {
	defer close(s.pumpDone)
	buf := make([]byte, 32<<10)
	for {
		n, err := s.master.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			s.mu.Lock()
			s.scroll.Write(data)
			att := s.att
			s.mu.Unlock()
			if att != nil {
				att.sendOutput(data)
			}
		}
		if err != nil {
			return
		}
	}
}

// waitExit collects the shell's status, lets its last output drain, and
// tells the attached client (if any) that the session is over.
func (t *sessionTable) waitExit(s *shellSession, status <-chan syscall.WaitStatus) {
	ws := <-status
	select {
	case <-s.pumpDone:
	case <-time.After(drainDelay):
		// A background job still holds the terminal open. The shell is
		// gone, so the session is over: stop reading.
	}
	s.master.Close()
	<-s.pumpDone

	e := agentproto.Exit{Code: -1}
	switch {
	case ws.Exited():
		e.Code = ws.ExitStatus()
	case ws.Signaled():
		e.Signal = ws.Signal().String()
	}
	s.mu.Lock()
	s.exited = true
	att := s.att
	s.att = nil
	s.mu.Unlock()
	if att != nil {
		m, _ := agentproto.New(agentproto.TypeShellExit, att.id, e)
		att.end(&m)
	}
	t.mu.Lock()
	delete(t.m, s.id)
	t.mu.Unlock()
	close(s.done)
}

// attach makes a the session's client. Any previous client is detached.
// The scrollback is replayed first, then live output follows, in order:
// a.sendMu is held from before a is published until the replay is sent,
// so the pump's first live write to a has to wait for it.
func (s *shellSession) attach(a *attachment, created bool) bool {
	a.sendMu.Lock()
	s.mu.Lock()
	if s.exited {
		s.mu.Unlock()
		a.sendMu.Unlock()
		return false
	}
	prev := s.att
	s.att = a
	replay := s.scroll.Bytes()
	s.mu.Unlock()

	if prev != nil {
		prev.end(detachedFrame(prev.id, "another client attached to this session"))
	}
	ready, _ := agentproto.New(agentproto.TypeShellReady, a.id, agentproto.ShellReady{SessionID: s.id, Created: created})
	_ = a.w.send(ready)
	a.sendMu.Unlock()
	if len(replay) > 0 {
		a.sendOutput(replay)
	}
	return true
}

// detachIf removes a as the session's client, if it still is.
func (s *shellSession) detachIf(a *attachment) {
	s.mu.Lock()
	if s.att == a {
		s.att = nil
	}
	s.mu.Unlock()
}

// redraw nudges full-screen programs to repaint after a reattach. The
// replayed bytes can't restore a screen reliably, but changing the size
// makes the kernel send SIGWINCH, and programs like vim redraw everything.
func (s *shellSession) redraw(cols, rows uint16) {
	if cols == 0 || rows == 0 {
		return
	}
	if c, r, err := getWinsize(s.master); err == nil && c == cols && r == rows && cols > 1 {
		_ = setWinsize(s.master, cols-1, rows)
	}
	_ = setWinsize(s.master, cols, rows)
}

// kill ends a session: SIGHUP to the whole process group (what a terminal
// closing sends), then SIGKILL if it hasn't gone within a second.
func (s *shellSession) kill() {
	if s.pid > 1 {
		_ = syscall.Kill(-s.pid, syscall.SIGHUP)
	}
	select {
	case <-s.done:
	case <-time.After(time.Second):
		if s.pid > 1 {
			_ = syscall.Kill(-s.pid, syscall.SIGKILL)
		}
		<-s.done
	}
}

func (t *sessionTable) list() agentproto.SessionList {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := agentproto.SessionList{Sessions: []agentproto.SessionInfo{}}
	for _, s := range t.m {
		s.mu.Lock()
		out.Sessions = append(out.Sessions, agentproto.SessionInfo{
			ID: s.id, Command: s.command, Started: s.started, Attached: s.att != nil, Exited: s.exited,
		})
		s.mu.Unlock()
	}
	return out
}

// closeAll kills every session: the agent is shutting down.
func (t *sessionTable) closeAll() {
	t.mu.Lock()
	all := make([]*shellSession, 0, len(t.m))
	for _, s := range t.m {
		all = append(all, s)
	}
	t.mu.Unlock()
	var wg sync.WaitGroup
	for _, s := range all {
		wg.Add(1)
		go func(s *shellSession) { defer wg.Done(); s.kill() }(s)
	}
	wg.Wait()
}

// runShell serves one attachment: input, resizes and detach from the host,
// until the client detaches, another client takes over, the shell exits,
// or the connection drops. The session survives all but the shell exiting.
func runShell(ctx context.Context, id uint64, open agentproto.ShellOpen, in <-chan agentproto.Message, w *frameWriter, t *sessionTable) {
	var s *shellSession
	created := false
	var err error
	if open.SessionID == "" {
		s, err = t.start(open)
		created = true
	} else {
		s, err = t.get(open.SessionID)
	}
	if err != nil {
		code := errCode(err)
		if errors.Is(err, errNoSession) {
			code = agentproto.CodeNotFound
		}
		sendErr(w, id, code, err.Error())
		return
	}
	a := newAttachment(id, w)
	if !s.attach(a, created) {
		sendErr(w, id, agentproto.CodeNotFound, "session has exited")
		return
	}
	if !created {
		s.redraw(open.Cols, open.Rows)
	}

	for {
		select {
		case m := <-in:
			switch m.Type {
			case agentproto.TypePtyIn:
				var c agentproto.Chunk
				if m.Decode(&c) == nil && len(c.Data) > 0 {
					_, _ = s.master.Write(c.Data)
				}
				ack, _ := agentproto.New(agentproto.TypeAck, id, nil)
				_ = w.send(ack)
			case agentproto.TypeResize:
				var r agentproto.Resize
				if m.Decode(&r) == nil && r.Cols > 0 && r.Rows > 0 {
					_ = setWinsize(s.master, r.Cols, r.Rows)
				}
			case agentproto.TypeAck:
				a.credit()
			case agentproto.TypeDetach:
				s.detachIf(a)
				a.end(detachedFrame(id, "client detached"))
				return
			}
		case <-a.gone:
			return // another client took over, or the shell exited: the final frame was sent
		case <-ctx.Done():
			// The connection dropped. The session lives on for the next client.
			s.detachIf(a)
			a.end(nil)
			return
		}
	}
}
