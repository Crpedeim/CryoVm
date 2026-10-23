package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/Crpedeim/sbx/internal/client"
)

// shell is the sandbox's persistent shell: one terminal session (Day 6),
// so the working directory, variables and anything else a command leaves
// behind carry into the next. Commands run one at a time.
//
// Between commands the session is detached (Day 22). An attached shell
// counts as activity (Day 13), so staying attached would keep the sandbox
// from ever idle-pausing. The session lives on in the sandbox, detached, and
// is reattached for the next command, waking the sandbox if it slept.
//
// Completion is detected with a marker. After each command the shell runs
// a line that prints __SBX_<nonce>_<exit code>__. The nonce is new for each
// command, and the line is built by printf from separate pieces, so the
// terminal echoing the line itself never contains the finished marker:
// only its real output does. Output is everything before the marker.
type shell struct {
	c       *client.Client
	sandbox string

	mu        sync.Mutex // one command at a time
	conn      *client.ShellConn
	sessionID string
	out       *watchBuf
	dead      chan struct{} // closed when the attachment ends
	lost      bool          // a session was lost: the next result says so, once
}

// watchBuf collects a session's output and wakes whoever waits on it.
type watchBuf struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	wake chan struct{}
}

func newWatchBuf() *watchBuf { return &watchBuf{wake: make(chan struct{}, 1)} }

const maxShellBuffer = 32 << 20 // past this, a command's oldest output is dropped

func (w *watchBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buf.Write(p)
	if w.buf.Len() > maxShellBuffer {
		keep := w.buf.Bytes()[w.buf.Len()-maxShellBuffer/2:]
		w.buf.Reset()
		w.buf.WriteString("[... earlier output dropped: over 32 MiB ...]\n")
		w.buf.Write(keep)
	}
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (w *watchBuf) snapshot() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

func (w *watchBuf) reset() {
	w.mu.Lock()
	w.buf.Reset()
	w.mu.Unlock()
}

// setup makes the terminal quiet: no echo, no prompts, no bracketed-paste
// codes around each prompt, no pager waiting for a key.
const setup = `stty -echo 2>/dev/null; bind 'set enable-bracketed-paste off' 2>/dev/null; ` +
	`PS1=''; PS2=''; PROMPT_COMMAND=''; unset HISTFILE; export TERM=dumb PAGER=cat GIT_PAGER=cat`

// open starts (or reattaches to) the session. It returns a notice when a
// new session replaced a lost one: earlier state is gone, and the agent
// should know.
func (s *shell) open(ctx context.Context) (notice string, err error) {
	if s.conn != nil {
		select {
		case <-s.dead:
		default:
			return "", nil // alive
		}
	}
	if s.sessionID != "" { // detached, or the attachment ended: the session may live on
		if conn, err := s.c.Shell(ctx, s.sandbox, client.ShellOptions{SessionID: s.sessionID}); err == nil {
			s.attach(conn)
			// Reattaching replays the session's recent output first (Day 6,
			// for a person's screen). An empty command's marker comes after
			// the replay, in order: discard everything before it.
			if _, _, err := s.run(ctx, "", 10*time.Second); err == nil {
				return "", nil
			}
			_ = s.conn.Close()
		}
		s.lost = true
	}
	if s.lost {
		notice = "[the shell session was lost and a new one started: the working directory and variables from earlier commands are gone]\n"
		s.lost = false
	}
	conn, err := s.c.Shell(ctx, s.sandbox, client.ShellOptions{
		Cols: 200, Rows: 50,
		Command: []string{"/bin/bash", "--noprofile", "--norc", "-i"},
		Env:     []string{"TERM=dumb", "PAGER=cat", "GIT_PAGER=cat"},
	})
	if err != nil {
		return "", fmt.Errorf("opening a shell: %w", err)
	}
	s.attach(conn)
	s.sessionID = conn.SessionID
	if _, _, err := s.run(ctx, setup, 10*time.Second); err != nil {
		return "", fmt.Errorf("setting up the shell: %w", err)
	}
	return notice, nil
}

func (s *shell) attach(conn *client.ShellConn) {
	s.conn, s.out, s.dead = conn, newWatchBuf(), make(chan struct{})
	go func(out *watchBuf, dead chan struct{}) {
		_, _ = conn.Run(out)
		close(dead)
	}(s.out, s.dead)
}

// Exec runs one command in the persistent shell.
func (s *shell) Exec(ctx context.Context, command string, timeout time.Duration) (out string, code int, timedOut bool, notice string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if notice, err = s.open(ctx); err != nil {
		return "", 0, false, "", err
	}
	out, code, err = s.run(ctx, command, timeout)
	if errors.Is(err, errShellExited) {
		// Usually `exit`: not an error to stop on, but the session is gone,
		// and the next command must start a new one (and say so).
		s.sessionID, s.lost = "", true
		return out, -1, false, notice + "[the shell itself exited, so the command's own status is unknown. Did it run `exit`? " +
			"The next command starts a fresh shell, without this one's working directory or variables. " +
			"To end with a status without ending the shell, use a subshell: (exit 1)]\n", nil
	}
	defer s.detach()
	if errors.Is(err, errTimeout) {
		// Interrupt it, then ask for the marker again: Ctrl-C makes the
		// terminal discard queued input, the first marker line included.
		_, _ = s.conn.Write([]byte{3})
		time.Sleep(200 * time.Millisecond)
		nonce := newNonce()
		_, _ = s.conn.Write([]byte(markerLine(nonce)))
		rest, rc, err2 := s.wait(ctx, nonce, 10*time.Second)
		if err2 != nil {
			// It won't stop: let the session go; the next call starts afresh.
			_ = s.conn.Close()
			s.sessionID, s.lost = "", true
			return clean(s.out.snapshot()), 130, true, notice, nil
		}
		return out + rest, rc, true, notice, nil
	}
	return out, code, false, notice, err
}

var (
	errTimeout = errors.New("timed out")
	// errShellExited: the shell itself ended mid-command, typically because
	// the command ran `exit`. The next command starts a fresh session.
	errShellExited = errors.New("the shell exited")
)

func (s *shell) run(ctx context.Context, command string, timeout time.Duration) (string, int, error) {
	s.out.reset()
	nonce := newNonce()
	if _, err := s.conn.Write([]byte(command + "\n" + markerLine(nonce))); err != nil {
		return "", 0, fmt.Errorf("writing to the shell: %w", err)
	}
	return s.wait(ctx, nonce, timeout)
}

// wait reads until the marker for this nonce appears.
func (s *shell) wait(ctx context.Context, nonce string, timeout time.Duration) (string, int, error) {
	marker := regexp.MustCompile(`\r?\n?__SBX_` + nonce + `_(\d+)__`)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		got := s.out.snapshot()
		if m := marker.FindSubmatchIndex(got); m != nil {
			code, _ := strconv.Atoi(string(got[m[2]:m[3]]))
			return clean(got[:m[0]]), code, nil
		}
		select {
		case <-s.out.wake:
		case <-s.dead:
			return clean(s.out.snapshot()), -1, errShellExited
		case <-deadline.C:
			// What it printed so far, for the caller to keep.
			return clean(s.out.snapshot()), 0, errTimeout
		case <-ctx.Done():
			return clean(s.out.snapshot()), 0, ctx.Err()
		}
	}
}

// markerLine captures the command's exit status first, then prints the
// marker from separate pieces (so an echo of this line never matches).
func markerLine(nonce string) string {
	return fmt.Sprintf("__sbx_rc=$?; printf '\\n__SBX_%%s_%%d__\\n' %s \"$__sbx_rc\"\n", nonce)
}

func newNonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ansi matches terminal escape sequences (colors, cursor movement, the
// bracketed-paste codes bash prints around prompts).
var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[=>]`)

func clean(b []byte) string {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	b = bytes.ReplaceAll(b, []byte("\r"), nil)
	return ansi.ReplaceAllString(string(b), "")
}

// detach lets go of the session, which lives on, so the sandbox can sleep.
func (s *shell) detach() {
	if s.conn == nil {
		return
	}
	select {
	case <-s.dead:
		return
	default:
	}
	if s.conn.Detach() == nil {
		select {
		case <-s.dead:
			return
		case <-time.After(2 * time.Second):
		}
	}
	_ = s.conn.Close()
}

func (s *shell) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		_ = s.conn.Close()
	}
}
