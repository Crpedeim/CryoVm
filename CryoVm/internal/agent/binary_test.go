package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func buildAgent(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "sbx-agent")
	build := exec.Command("go", "build", "-o", bin, "../../cmd/sbx-agent")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// runAgent starts the built binary against a fresh listener.
func runAgent(t *testing.T, bin string, extra ...string) (*Listener, *exec.Cmd, <-chan error) {
	t.Helper()
	path := sockPath(t)
	l, err := Listen(path, "bin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	// -identity-dir: never the machine's real /run/sbx from a test.
	cmd := exec.Command(bin, append([]string{"-id", "bin", "-dial", "unix:" + path, "-identity-dir", t.TempDir()}, extra...)...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return l, cmd, exited
}

// TestRealAgentBinary builds cmd/sbx-agent exactly as it ships (static,
// CGO_ENABLED=0) and runs it as a separate process: hello, ping, reconnect,
// and a clean exit on SIGTERM, the signal Shutdown sends.
func TestRealAgentBinary(t *testing.T) {
	bin := buildAgent(t)
	l, cmd, exited := runAgent(t, bin)

	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatalf("agent never connected: %v", err)
	}
	if conn.Hello.PID != cmd.Process.Pid {
		t.Errorf("hello pid %d, process pid %d", conn.Hello.PID, cmd.Process.Pid)
	}
	if _, err := conn.Ping(wait(t)); err != nil {
		t.Fatalf("ping: %v", err)
	}

	conn.Close()
	again, err := l.Conn(wait(t))
	if err != nil {
		t.Fatalf("agent did not reconnect: %v", err)
	}
	if _, err := again.Ping(wait(t)); err != nil {
		t.Fatalf("ping after reconnect: %v", err)
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("agent did not exit cleanly on SIGTERM: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent ignored SIGTERM")
	}
}

// TestReapAllModeKeepsExitCodesAndReapsOrphans runs the binary in PID 1
// mode (-reap-all; it becomes a child subreaper so orphans come to it, as
// they would to PID 1). Two things must hold at once: every exec gets its
// own exit code back, even with the reaper collecting all children, and
// orphaned processes don't linger as zombies.
func TestReapAllModeKeepsExitCodesAndReapsOrphans(t *testing.T) {
	bin := buildAgent(t)
	l, cmd, _ := runAgent(t, bin, "-reap-all")
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}

	// Many short commands at once: the start-and-register race is real
	// here, and a lost status would show up as a wrong exit code.
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code := i % 50
			res, err := conn.Exec(wait(t), ExecRequest{Args: []string{"sh", "-c", fmt.Sprintf("exit %d", code)}})
			if err != nil || res.ExitCode != code {
				errs <- fmt.Errorf("exec %d: want exit %d, got %+v %v", i, code, res, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	// An orphan: the subshell exits immediately, leaving sleep to be
	// reparented to the agent. When sleep exits, someone must reap it.
	if _, err := conn.Exec(wait(t), ExecRequest{Args: []string{"sh", "-c", "(sleep 0.2 &) ; exit 0"}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if z := zombieChildren(cmd.Process.Pid); len(z) > 0 {
		t.Fatalf("zombie children of the agent: %v", z)
	}
}

// TestReapAllModeTimeoutKillsGroupAndAgentSurvives guards a real bug: in
// reap-all mode the PID handed back for killing was read after Release(),
// which sets it to -1, so a timeout signalled PID 1. Inside a sandbox the
// agent IS PID 1: every timeout would have killed the whole sandbox.
func TestReapAllModeTimeoutKillsGroupAndAgentSurvives(t *testing.T) {
	bin := buildAgent(t)
	l, cmd, exited := runAgent(t, bin, "-reap-all")
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := conn.Exec(wait(t), ExecRequest{
		Args:    []string{"sh", "-c", "sleep 35.5 & sleep 35.5; wait"},
		Timeout: 300 * time.Millisecond,
	})
	if err != nil || !res.TimedOut {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("timeout took %s: the kill didn't reach the command", took)
	}
	time.Sleep(100 * time.Millisecond)
	if n := sleepers("35.5"); n != 0 {
		t.Fatalf("%d sleep processes survived", n)
	}
	select {
	case err := <-exited:
		t.Fatalf("the agent died during the timeout kill: %v", err)
	default:
	}
	if _, err := conn.Ping(wait(t)); err != nil {
		t.Fatalf("agent unresponsive after timeout: %v", err)
	}
	_ = cmd
}

// zombieChildren lists PIDs in state Z whose parent is ppid.
func zombieChildren(ppid int) []int {
	var out []int
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		st, err := os.ReadFile(filepath.Join(d, "status"))
		if err != nil {
			continue
		}
		var state string
		var parent int
		for _, line := range strings.Split(string(st), "\n") {
			if v, ok := strings.CutPrefix(line, "State:"); ok {
				state = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(line, "PPid:"); ok {
				parent, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
		if parent == ppid && strings.HasPrefix(state, "Z") {
			pid, _ := strconv.Atoi(filepath.Base(d))
			out = append(out, pid)
		}
	}
	return out
}

// Sessions outlive connections, but not the agent: when the sandbox shuts
// down, the agent's SIGTERM handler must end every session it owns.
func TestAgentShutdownEndsItsSessions(t *testing.T) {
	bin := buildAgent(t)
	l, cmd, exited := runAgent(t, bin, "-reap-all")
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := conn.OpenShell(wait(t), ShellOptions{Command: []string{"sleep", "31.25"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	deadline := time.Now().Add(2 * time.Second)
	for sleepers("31.25") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if sleepers("31.25") != 1 {
		t.Fatal("setup: the session's process never started")
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not exit")
	}
	time.Sleep(100 * time.Millisecond)
	if n := sleepers("31.25"); n != 0 {
		t.Fatalf("%d session processes outlived the agent", n)
	}
}

// Background processes outlive connections, but not the agent. On SIGTERM
// it sends SIGTERM to each process group, then SIGKILL to whatever ignored
// it. The second process here ignores SIGTERM on purpose.
func TestAgentShutdownStopsBackgroundProcesses(t *testing.T) {
	bin := buildAgent(t)
	l, cmd, exited := runAgent(t, bin, "-reap-all", "-log-dir", t.TempDir())
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.StartProcess(wait(t), ProcStart{Args: []string{"sleep", "62.5"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.StartProcess(wait(t), ProcStart{Args: []string{"sh", "-c", `trap "" TERM; sleep 63.5`}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for (sleepers("62.5") == 0 || sleepers("63.5") == 0) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	start := time.Now()
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(6 * time.Second):
		t.Fatal("agent did not exit")
	}
	took := time.Since(start)
	time.Sleep(100 * time.Millisecond)
	if a, b := sleepers("62.5"), sleepers("63.5"); a+b != 0 {
		t.Fatalf("background processes outlived the agent: %d polite, %d stubborn", a, b)
	}
	// The stubborn one needed the SIGKILL fallback, after about 2 seconds.
	if took < 1500*time.Millisecond {
		t.Fatalf("shutdown took only %s: was the stubborn process really ignoring SIGTERM?", took)
	}
}

// The quiesce cycle a checkpoint relies on, with the real binary: stop
// accepting, quiesce, see the agent let go and stay out, listen again, and
// the agent comes back by itself. A shell session and a background process
// started before must still be there: they live inside the sandbox, not in
// the connection.
func TestQuiesceAndComeBack(t *testing.T) {
	bin := buildAgent(t)
	l, _, exited := runAgent(t, bin, "-reap-all", "-log-dir", t.TempDir())
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := conn.OpenShell(wait(t), ShellOptions{Command: []string{"sh"}})
	if err != nil {
		t.Fatal(err)
	}
	sh.Close()
	p, err := conn.StartProcess(wait(t), ProcStart{Args: []string{"sleep", "67.5"}})
	if err != nil {
		t.Fatal(err)
	}

	path := l.Path()
	if err := l.StopAccepting(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Quiesce(wait(t)); err != nil {
		t.Fatalf("quiesce: %v", err)
	}
	// The agent let go, and with nothing listening it stays out.
	time.Sleep(500 * time.Millisecond)
	if l.Current() != conn {
		t.Fatal("a new connection appeared while nothing was listening")
	}
	select {
	case err := <-exited:
		t.Fatalf("the agent exited: %v", err)
	default:
	}

	// Listen again at the same path: the agent finds it on its next redial.
	l2, err := Listen(path, "bin")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn2, err := l2.Conn(ctx)
	if err != nil {
		t.Fatalf("the agent never came back: %v", err)
	}
	t.Logf("the agent reconnected %s after the listener returned", time.Since(start).Round(time.Millisecond))
	list, err := conn2.Sessions(wait(t))
	if err != nil || len(list.Sessions) != 1 {
		t.Fatalf("the shell session should have survived: %+v %v", list, err)
	}
	procs, _ := conn2.Processes(wait(t))
	if len(procs) != 1 || procs[0].ID != p.ID || !procs[0].Running {
		t.Fatalf("the background process should still be running: %+v", procs)
	}
	_ = conn2.Signal(wait(t), p.ID, 9)
}
