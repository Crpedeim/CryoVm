package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// screen collects a shell's output so a test can wait for text to appear.
type screen struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *screen) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *screen) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(s.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("never saw %q; screen so far:\n%s", want, s.String())
}

type running struct {
	sh   *Shell
	scr  *screen
	done chan ShellEnd
}

// open attaches (or starts) a shell and runs its output loop.
func open(t *testing.T, c *Conn, opts ShellOptions) *running {
	t.Helper()
	if len(opts.Command) == 0 && opts.SessionID == "" {
		opts.Command = []string{"sh"} // predictable: no bash rc files or fancy prompt
	}
	sh, err := c.OpenShell(wait(t), opts)
	if err != nil {
		t.Fatalf("open shell: %v", err)
	}
	r := &running{sh: sh, scr: &screen{}, done: make(chan ShellEnd, 1)}
	go func() {
		end, _ := sh.Run(context.Background(), r.scr)
		r.done <- end
	}()
	return r
}

// settle waits until the shell has run everything typed so far. A terminal
// echoes what you type, so a marker that appears in the typed text proves
// nothing: the echo shows "$((n+1))", and only the shell's real output can
// show the computed number. Call it when no command is printing: the echo
// of what it types would land in the middle of that output.
func (r *running) settle(t *testing.T) {
	t.Helper()
	markerMu.Lock()
	markerN++
	n := markerN
	markerMu.Unlock()
	r.typ(t, fmt.Sprintf("echo SETTLED-$((%d+1))\n", n))
	r.scr.waitFor(t, fmt.Sprintf("SETTLED-%d", n+1))
}

var (
	markerMu sync.Mutex
	markerN  = 1000
)

func (r *running) typ(t *testing.T, s string) {
	t.Helper()
	if _, err := r.sh.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
}

func (r *running) end(t *testing.T) ShellEnd {
	t.Helper()
	select {
	case e := <-r.done:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("attachment did not end")
		return ShellEnd{}
	}
}

// connectedL is connected, also returning the listener, for reconnects.
func connectedL(t *testing.T) (*Listener, *Conn) {
	t.Helper()
	path := sockPath(t)
	l, err := Listen(path, "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	t.Cleanup(startGuest(t, "x", path))
	c, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	return l, c
}

func TestShellIsATerminal(t *testing.T) {
	c := connected(t)
	r := open(t, c, ShellOptions{Cols: 100, Rows: 30})
	r.typ(t, "test -t 1 && echo TTY-YES; stty size\n")
	r.scr.waitFor(t, "TTY-YES")
	r.scr.waitFor(t, "30 100")
}

func TestShellStatePersists(t *testing.T) {
	c := connected(t)
	r := open(t, c, ShellOptions{})
	r.typ(t, "cd /tmp && export SBX_GREETING=hello\n")
	r.typ(t, "echo \"dir=$(pwd) greeting=$SBX_GREETING\"\n")
	r.scr.waitFor(t, "dir=/tmp greeting=hello") // the echo shows $(pwd), not /tmp
}

func TestResizeReachesTheShell(t *testing.T) {
	c := connected(t)
	r := open(t, c, ShellOptions{Cols: 80, Rows: 24})
	if err := r.sh.Resize(132, 43); err != nil {
		t.Fatal(err)
	}
	r.typ(t, "stty size\n")
	r.scr.waitFor(t, "43 132")
}

func TestShellExitCode(t *testing.T) {
	c := connected(t)
	r := open(t, c, ShellOptions{})
	r.typ(t, "exit 3\n")
	if e := r.end(t); !e.Exited || e.Code != 3 {
		t.Fatalf("want exited with 3, got %+v", e)
	}
}

// The heart of Day 6: detach, let the shell keep working, come back, and
// find both the session and what happened while you were away.
func TestDetachAndReattach(t *testing.T) {
	c := connected(t)
	r := open(t, c, ShellOptions{})
	id := r.sh.SessionID
	r.typ(t, "cd /tmp; (sleep 0.5; echo printed-while-$((0+1))-away) &\n")
	r.settle(t)
	if err := r.sh.Detach(); err != nil {
		t.Fatal(err)
	}
	if e := r.end(t); !e.Detached {
		t.Fatalf("want detached, got %+v", e)
	}

	time.Sleep(time.Second) // the shell keeps going without anyone attached

	back := open(t, c, ShellOptions{SessionID: id})
	if back.sh.Created || back.sh.SessionID != id {
		t.Fatalf("reattach made a new session: %+v", back.sh)
	}
	back.scr.waitFor(t, "printed-while-1-away") // replayed from the scrollback
	back.typ(t, "pwd\n")
	back.scr.waitFor(t, "/tmp") // and the shell's state is intact
}

func TestConnectionDropKeepsTheSession(t *testing.T) {
	l, c := connectedL(t)
	r := open(t, c, ShellOptions{})
	id := r.sh.SessionID
	r.typ(t, "export SBX_MARK=survived\n")
	r.settle(t)
	c.Close() // the daemon restarted, or the network blinked

	c2, err := l.Conn(wait(t)) // the agent redials on its own
	if err != nil {
		t.Fatal(err)
	}
	back := open(t, c2, ShellOptions{SessionID: id})
	back.typ(t, "echo got-$SBX_MARK\n")
	back.scr.waitFor(t, "got-survived")
}

func TestSecondClientDisplacesTheFirst(t *testing.T) {
	c := connected(t)
	first := open(t, c, ShellOptions{})
	second := open(t, c, ShellOptions{SessionID: first.sh.SessionID})
	if e := first.end(t); !e.Detached || !strings.Contains(e.Reason, "another client") {
		t.Fatalf("first client: %+v", e)
	}
	second.typ(t, "echo still-$((1+1))-here\n")
	second.scr.waitFor(t, "still-2-here")
}

func TestListAndKillSessions(t *testing.T) {
	c := connected(t)
	r := open(t, c, ShellOptions{})
	list, err := c.Sessions(wait(t))
	if err != nil || len(list.Sessions) != 1 || list.Sessions[0].ID != r.sh.SessionID || !list.Sessions[0].Attached {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := c.KillSession(wait(t), r.sh.SessionID); err != nil {
		t.Fatal(err)
	}
	if e := r.end(t); !e.Exited {
		t.Fatalf("a killed session should end its attachment as exited: %+v", e)
	}
	if list, _ := c.Sessions(wait(t)); len(list.Sessions) != 0 {
		t.Fatalf("still listed after kill: %+v", list)
	}
	if err := c.KillSession(wait(t), "s-nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("killing an unknown session: want ErrNotFound, got %v", err)
	}
	if _, err := c.OpenShell(wait(t), ShellOptions{SessionID: "s-nope"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("attaching to an unknown session: want ErrNotFound, got %v", err)
	}
}

// Day 3's buffering puzzle, solved: on a pipe, grep block-buffered and the
// lines arrived all at once. On a terminal, grep sees isatty and flushes
// every line.
func TestTerminalMakesProgramsLineBuffer(t *testing.T) {
	c := connected(t)
	r := open(t, c, ShellOptions{})
	start := time.Now()
	r.typ(t, "for i in 1 2 3; do echo line$i; sleep 0.4; done | grep line\n")
	r.scr.waitFor(t, "line1") // the typed text says "line$i": only output says "line1"
	first := time.Since(start)
	r.settle(t)
	total := time.Since(start)
	if first > total-500*time.Millisecond {
		t.Fatalf("line1 after %s of %s: still block-buffered", first, total)
	}
}

// Lots of output, through the credit window, with nothing lost. Every
// number from 1 to 60000 must arrive. Interactive output mixes in prompts
// (the first number shares a line with "# "), so lines are parsed rather
// than matched exactly.
func TestLargeOutputArrivesWhole(t *testing.T) {
	c := connected(t)
	r := open(t, c, ShellOptions{})
	// The marker rides on the same command line. Typing it separately while
	// seq is still printing would put its echo in the middle of seq's
	// output (typeahead echo: a terminal echoes keystrokes the moment they
	// arrive), splitting a number in two. Typed together, the whole line is
	// echoed before seq even starts.
	r.typ(t, "seq 1 60000; echo SEQ-$((6+1))\n")
	r.scr.waitFor(t, "SEQ-7")
	seen := make([]bool, 60001)
	for _, line := range strings.Split(r.scr.String(), "\n") {
		line = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(line), "# "), "$ ")
		if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= 60000 {
			seen[n] = true
		}
	}
	for n := 1; n <= 60000; n++ {
		if !seen[n] {
			scr := r.scr.String()
			at := strings.Index(scr, fmt.Sprintf("\n%d\r", n-1))
			t.Fatalf("line %d never arrived; screen around it: %q", n, scr[max(0, at):min(len(scr), at+120)])
		}
	}
}

// Ctrl+C is not a signal the client sends: it's the byte 0x03, typed into
// the terminal. The kernel's terminal driver turns it into SIGINT for the
// foreground job, but only if the PTY is the shell's controlling terminal
// (Setsid + Setctty). Without that, the byte is just a byte, and sleep runs on.
func TestCtrlCInterruptsTheForegroundJob(t *testing.T) {
	c := connected(t)
	r := open(t, c, ShellOptions{})
	r.typ(t, "sleep 30\n")
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	r.typ(t, "\x03") // Ctrl+C
	r.settle(t)      // only possible once sleep is gone
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("Ctrl+C took %s to interrupt sleep", took)
	}
}
