package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/guest"
)

// connectedWith starts an in-process agent with an adjusted config and
// returns a connection plus the agent's log directory.
func connectedWith(t *testing.T, adjust func(*guest.Config)) (*Listener, *Conn, string) {
	t.Helper()
	path := sockPath(t)
	l, err := Listen(path, "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	logDir := t.TempDir()
	t.Cleanup(startGuestWith(t, "x", path, func(c *guest.Config) {
		c.LogDir = logDir
		if adjust != nil {
			adjust(c)
		}
	}))
	c, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	return l, c, logDir
}

func startProc(t *testing.T, c *Conn, args ...string) string {
	t.Helper()
	p, err := c.StartProcess(wait(t), ProcStart{Args: args})
	if err != nil {
		t.Fatalf("start %q: %v", args, err)
	}
	if !strings.HasPrefix(p.ID, "p-") || p.PID <= 0 {
		t.Fatalf("bad start result: %+v", p)
	}
	return p.ID
}

func logsOf(t *testing.T, c *Conn, id string, off int64) (string, LogsEnd) {
	t.Helper()
	var b bytes.Buffer
	end, err := c.Logs(wait(t), id, off, false, &b)
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	return b.String(), end
}

func TestProcessRunsDetachedAndLogs(t *testing.T) {
	_, c, _ := connectedWith(t, nil)
	id := startProc(t, c, "sh", "-c", "echo out; echo err >&2; sleep 0.2; echo done")
	info, err := c.Wait(wait(t), id)
	if err != nil || info.Running || info.ExitCode != 0 {
		t.Fatalf("wait: %+v %v", info, err)
	}
	out, end := logsOf(t, c, id, 0)
	// One pipe for both streams: the log keeps the order they were written in.
	if out != "out\nerr\ndone\n" {
		t.Fatalf("log %q", out)
	}
	if end.Next != int64(len(out)) || !end.Exited || info.LogBytes != end.Next {
		t.Fatalf("end %+v, info %+v", end, info)
	}
}

func TestLogsFromAnOffset(t *testing.T) {
	_, c, _ := connectedWith(t, nil)
	id := startProc(t, c, "printf", "0123456789")
	if _, err := c.Wait(wait(t), id); err != nil {
		t.Fatal(err)
	}
	out, end := logsOf(t, c, id, 4)
	if out != "456789" || end.Next != 10 || end.Skipped != 0 {
		t.Fatalf("from 4: %q %+v", out, end)
	}
	out, end = logsOf(t, c, id, 10) // nothing new since last time
	if out != "" || end.Next != 10 {
		t.Fatalf("at the end: %q %+v", out, end)
	}
}

type firstWrite struct {
	first time.Time
	buf   bytes.Buffer
}

func (f *firstWrite) Write(p []byte) (int, error) {
	if f.first.IsZero() {
		f.first = time.Now()
	}
	return f.buf.Write(p)
}

func TestFollowStreamsAsItIsWritten(t *testing.T) {
	_, c, _ := connectedWith(t, nil)
	id := startProc(t, c, "sh", "-c", "for i in 1 2 3; do echo line$i; sleep 0.3; done")
	w := &firstWrite{}
	start := time.Now()
	end, err := c.Logs(wait(t), id, 0, true, w)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if w.buf.String() != "line1\nline2\nline3\n" || !end.Exited {
		t.Fatalf("follow: %q %+v", w.buf.String(), end)
	}
	if w.first.Sub(start) > took-400*time.Millisecond {
		t.Fatalf("first line after %s of %s: follow waited instead of streaming", w.first.Sub(start), took)
	}
}

// A process that leaves a child holding its output pipe: the shell exits at
// once, but sleep keeps the pipe open. Follow must still end, after the
// drain delay, not when the sleep finally ends.
func TestFollowEndsDespiteALingeringChild(t *testing.T) {
	_, c, _ := connectedWith(t, nil)
	id := startProc(t, c, "sh", "-c", "sleep 64.5 & echo started")
	defer func() {
		// The sleep is in the process's group: signal it, ignoring that sh is gone.
		for _, p := range pidsOf("64.5") {
			_ = syscall.Kill(p, syscall.SIGKILL)
		}
	}()
	start := time.Now()
	var b bytes.Buffer
	end, err := c.Logs(wait(t), id, 0, true, &b)
	if err != nil || !strings.Contains(b.String(), "started") || !end.Exited {
		t.Fatalf("follow: %q %+v %v", b.String(), end, err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("follow took %s: it waited for the lingering child", took)
	}
}

func pidsOf(sleepArg string) []int {
	var out []int
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		if b, err := os.ReadFile(filepath.Join(d, "cmdline")); err == nil && string(b) == "sleep\x00"+sleepArg+"\x00" {
			if pid, err := strconv.Atoi(filepath.Base(d)); err == nil {
				out = append(out, pid)
			}
		}
	}
	return out
}

func TestSignalReachesTheWholeGroup(t *testing.T) {
	_, c, _ := connectedWith(t, nil)
	id := startProc(t, c, "sh", "-c", "sleep 61.5 & sleep 61.5")
	deadline := time.Now().Add(2 * time.Second)
	for sleepers("61.5") < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := c.Signal(wait(t), id, int(syscall.SIGTERM)); err != nil {
		t.Fatal(err)
	}
	info, err := c.Wait(wait(t), id)
	if err != nil || info.Running || info.Signal != "terminated" {
		t.Fatalf("after SIGTERM: %+v %v", info, err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := sleepers("61.5"); n != 0 {
		t.Fatalf("%d sleeps survived: the signal reached only the leader", n)
	}
}

func TestProcessSurvivesTheConnectionDropping(t *testing.T) {
	l, c, _ := connectedWith(t, nil)
	id := startProc(t, c, "sh", "-c", "sleep 0.5; echo survived")
	c.Close()
	c2, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	info, err := c2.Wait(wait(t), id)
	if err != nil || info.ExitCode != 0 {
		t.Fatalf("wait after reconnect: %+v %v", info, err)
	}
	if out, _ := logsOf(t, c2, id, 0); out != "survived\n" {
		t.Fatalf("log %q", out)
	}
}

func TestListRemoveAndConflicts(t *testing.T) {
	_, c, logDir := connectedWith(t, nil)
	id := startProc(t, c, "sleep", "30")
	list, err := c.Processes(wait(t))
	if err != nil || len(list) != 1 || !list[0].Running || list[0].ID != id {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := c.RemoveProcess(wait(t), id); !errors.Is(err, ErrConflict) {
		t.Fatalf("removing a running process: want ErrConflict, got %v", err)
	}
	if err := c.Signal(wait(t), id, int(syscall.SIGKILL)); err != nil {
		t.Fatal(err)
	}
	if info, _ := c.Wait(wait(t), id); info.Signal != "killed" {
		t.Fatalf("want killed: %+v", info)
	}
	if err := c.Signal(wait(t), id, int(syscall.SIGTERM)); !errors.Is(err, ErrConflict) {
		t.Fatalf("signalling an exited process: want ErrConflict, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(logDir, id)); err != nil {
		t.Fatalf("log directory should exist before removal: %v", err)
	}
	if err := c.RemoveProcess(wait(t), id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(logDir, id)); !os.IsNotExist(err) {
		t.Fatal("remove left the log directory behind")
	}
	if list, _ := c.Processes(wait(t)); len(list) != 0 {
		t.Fatalf("still listed: %+v", list)
	}
	if err := c.RemoveProcess(wait(t), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing twice: want ErrNotFound, got %v", err)
	}
	if _, err := c.StartProcess(wait(t), ProcStart{Args: []string{"no-such-program-xyz"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing program: want ErrNotFound, got %v", err)
	}
	if _, err := c.StartProcess(wait(t), ProcStart{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no command: want ErrInvalid, got %v", err)
	}
	if err := c.Signal(wait(t), "p-nope", 15); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown process: want ErrNotFound, got %v", err)
	}
}

// With a 1000-byte cap, seq's 8893 bytes rotate several times. Reading
// from 0 must say exactly how many bytes were lost, and return exactly
// the bytes after them.
func TestRotationReportsSkippedBytes(t *testing.T) {
	_, c, _ := connectedWith(t, func(cfg *guest.Config) { cfg.LogFileCap = 1000 })
	id := startProc(t, c, "seq", "1", "2000")
	info, err := c.Wait(wait(t), id)
	if err != nil {
		t.Fatal(err)
	}
	out, end := logsOf(t, c, id, 0)
	if info.LogBytes != 8893 || end.Next != 8893 {
		t.Fatalf("total %d next %d, want 8893", info.LogBytes, end.Next)
	}
	if end.Skipped == 0 || end.Skipped+int64(len(out)) != 8893 {
		t.Fatalf("skipped %d + read %d != 8893", end.Skipped, len(out))
	}
	if !strings.HasSuffix(out, "1999\n2000\n") || len(out) > 2000 {
		t.Fatalf("kept %d bytes ending %q", len(out), out[max(0, len(out)-12):])
	}
}

// When Wait says a process has exited, its exit info must be final: all of
// its output logged, so LogBytes is the true total. The process and its
// last output travel separate paths (the exit status, and the pump copying
// the pipe), so without care Wait can answer while the pump is still
// writing. 288,894 bytes followed by an immediate exit makes that race
// near-certain.
func TestWaitReportsTheFinalLogSize(t *testing.T) {
	_, c, _ := connectedWith(t, nil)
	for i := 0; i < 5; i++ {
		id := startProc(t, c, "seq", "1", "50000")
		info, err := c.Wait(wait(t), id)
		if err != nil {
			t.Fatal(err)
		}
		if info.LogBytes != 288894 {
			t.Fatalf("run %d: Wait reported %d log bytes, but seq wrote 288894: exit was declared before the output drained", i, info.LogBytes)
		}
	}
}

// Renaming the agent (Day 15): new processes see the new identity, and on
// its next reconnect the agent introduces itself by the new name, which the
// listener, told to expect it, accepts.
func TestRenamedAgentReconnectsUnderItsNewName(t *testing.T) {
	dir := t.TempDir()
	l, c, _ := connectedWith(t, func(cfg *guest.Config) {
		cfg.IdentityDir = dir
		cfg.MinBackoff, cfg.MaxBackoff = 5*time.Millisecond, 20*time.Millisecond
	})
	old := l.Expected()
	ack, err := c.SetIdentity(wait(t), "renamed", "gen-42")
	if err != nil || ack.Previous != old || ack.SandboxID != "renamed" || ack.Generation != "gen-42" {
		t.Fatalf("set identity: %+v %v", ack, err)
	}
	var out bytes.Buffer
	if _, err := c.Exec(wait(t), ExecRequest{Args: []string{"sh", "-c", "echo $SBX_SANDBOX_ID $SBX_GENERATION"}, Stdout: &out}); err != nil || out.String() != "renamed gen-42\n" {
		t.Fatalf("a new process's environment: %q %v", out.String(), err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "sandbox-id")); string(b) != "renamed\n" {
		t.Fatalf("published id: %q", b)
	}
	l.Expect("renamed")
	if err := c.Quiesce(wait(t)); err != nil { // make it reconnect
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if next := l.Current(); next != nil && next != c {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the renamed agent never got back in: did its hello still use the old name?")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
