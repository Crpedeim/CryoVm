package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// runAgentLikePID1 starts the agent binary the way gVisor runs it, in the
// two ways that matter for terminals: as a session leader (PID 1 is one),
// and without CAP_SYS_ADMIN, the capability that lets a process override
// the kernel's terminal-ownership rules. Run as root, the agent is switched
// to the nobody user, which drops every capability.
//
// Day 6 shipped a bug only this setup could catch: run inside `go test`,
// the agent is not a session leader, and the bug stayed hidden.
func runAgentLikePID1(t *testing.T, bin string, extra ...string) (*Listener, <-chan error, int) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pid1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// nobody must be able to reach the binary, the socket and a working dir.
	_ = os.Chmod(dir, 0o755)
	agentBin := filepath.Join(dir, "sbx-agent")
	src, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentBin, src, 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "a.sock")
	l, err := Listen(sock, "pid1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	_ = os.Chmod(sock, 0o777)

	logDir := filepath.Join(dir, "logs")
	if err := os.Mkdir(logDir, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(logDir, 0o777) // past the umask: nobody must be able to write here
	args := append([]string{"-id", "pid1", "-dial", "unix:" + sock, "-log-dir", logDir, "-identity-dir", t.TempDir()}, extra...)
	cmd := exec.Command(agentBin, args...)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if os.Geteuid() == 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 65534, Gid: 65534}
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return l, exited, cmd.Process.Pid
}

func TestShellWorksWhenTheAgentLeadsASession(t *testing.T) {
	bin := buildAgent(t)
	l, exited, _ := runAgentLikePID1(t, bin)
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatalf("agent never connected: %v", err)
	}
	sh, err := conn.OpenShell(wait(t), ShellOptions{Command: []string{"sh"}})
	if err != nil {
		t.Fatalf("open shell: %v", err)
	}
	scr := &screen{}
	done := make(chan ShellEnd, 1)
	go func() { e, _ := sh.Run(wait(t), scr); done <- e }()
	_, _ = sh.Write([]byte("test -t 1 && echo TTY-$((1+1))\n"))
	scr.waitFor(t, "TTY-2")
	_, _ = sh.Write([]byte("exit 0\n"))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shell did not exit")
	}
	// The shell is gone and its PTY closed. The agent must not have gone
	// with it: closing a terminal sends SIGHUP to whoever it belongs to.
	select {
	case err := <-exited:
		t.Fatalf("the agent died when the shell's terminal closed: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := conn.Ping(wait(t)); err != nil {
		t.Fatalf("agent unreachable after the shell exited: %v", err)
	}
}

// PID 1 must not die from a stray SIGHUP. Go's default for an unhandled
// SIGHUP is to exit, and when PID 1 exits, the whole sandbox stops.
func TestAgentSurvivesSIGHUP(t *testing.T) {
	bin := buildAgent(t)
	l, exited, pid := runAgentLikePID1(t, bin)
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = syscall.Kill(pid, syscall.SIGHUP)
	select {
	case err := <-exited:
		t.Fatalf("SIGHUP killed the agent: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	if _, err := conn.Ping(wait(t)); err != nil {
		t.Fatalf("agent unreachable after SIGHUP: %v", err)
	}
}

// KillSession sends SIGHUP first, which a shell obeys at once; SIGKILL is
// only the fallback after a second. This proves the agent's SIGHUP handling
// doesn't leak into its children. If the agent *ignored* SIGHUP instead of
// catching it, every shell would inherit "ignore SIGHUP", and each kill
// would have to wait for the SIGKILL fallback.
func TestKillSessionHangsUpTheShell(t *testing.T) {
	bin := buildAgent(t)
	l, _, _ := runAgentLikePID1(t, bin)
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := conn.OpenShell(wait(t), ShellOptions{Command: []string{"sh"}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = sh.Run(wait(t), &screen{}) }()
	start := time.Now()
	if err := conn.KillSession(wait(t), sh.SessionID); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 800*time.Millisecond {
		t.Fatalf("kill took %s: the shell ignored SIGHUP and needed the SIGKILL fallback", took)
	}
}

// Background processes, under the same conditions as gVisor's PID 1: a
// session leader without capabilities. (Day 6's bug only showed up there.)
func TestProcessesWorkWhenTheAgentLeadsASession(t *testing.T) {
	bin := buildAgent(t)
	l, exited, _ := runAgentLikePID1(t, bin)
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	p, err := conn.StartProcess(wait(t), ProcStart{Args: []string{"sh", "-c", "echo from-$((2+3)); sleep 0.2; exit 2"}})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	var out bytes.Buffer
	end, err := conn.Logs(wait(t), p.ID, 0, true, &out)
	if err != nil || out.String() != "from-5\n" || !end.Exited {
		t.Fatalf("follow: %q %+v %v", out.String(), end, err)
	}
	info, err := conn.Wait(wait(t), p.ID)
	if err != nil || info.ExitCode != 2 {
		t.Fatalf("wait: %+v %v", info, err)
	}
	q, err := conn.StartProcess(wait(t), ProcStart{Args: []string{"sh", "-c", "sleep 65.5 & sleep 65.5"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Signal(wait(t), q.ID, 15); err != nil {
		t.Fatal(err)
	}
	if info, err := conn.Wait(wait(t), q.ID); err != nil || info.Signal != "terminated" {
		t.Fatalf("after SIGTERM: %+v %v", info, err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := sleepers("65.5"); n != 0 {
		t.Fatalf("%d sleeps survived the group signal", n)
	}
	select {
	case err := <-exited:
		t.Fatalf("agent died: %v", err)
	default:
	}
}

// The process limit applies to what the agent starts, never to the agent.
// Every way of starting a program (exec, background process, shell) goes
// through the trampoline. With the limit at 10, the user's existing tasks
// (the agent's own Go threads count) already fill it, so the children's
// forks are refused at once, while the agent, unlimited, keeps working.
// Had the limit been on the agent (init), this is exactly when it would
// have failed to create a thread and died.
func TestChildProcessLimitSparesTheAgent(t *testing.T) {
	bin := buildAgent(t)
	l, exited, _ := runAgentLikePID1(t, bin, "-child-nproc", "10")
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	execOut := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if _, err := conn.Exec(wait(t), ExecRequest{Args: args, Stdout: &out, Stderr: &out}); err != nil {
			t.Fatalf("exec %q: %v", args, err)
		}
		return strings.TrimSpace(out.String())
	}
	if got := execOut("sh", "-c", "ulimit -p"); got != "10" {
		t.Fatalf("an exec sees process limit %q, want 10", got)
	}
	p, err := conn.StartProcess(wait(t), ProcStart{Args: []string{"sh", "-c", "ulimit -p"}})
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	if _, err := conn.Logs(wait(t), p.ID, 0, true, &log); err != nil || strings.TrimSpace(log.String()) != "10" {
		t.Fatalf("a background process sees %q %v, want 10", log.String(), err)
	}
	sh, err := conn.OpenShell(wait(t), ShellOptions{Command: []string{"sh"}})
	if err != nil {
		t.Fatal(err)
	}
	scr := &screen{}
	go func() { _, _ = sh.Run(context.Background(), scr) }()
	// Builtins only: forks are refused here, and $(...) would need one.
	// `ulimit -p` prints the limit itself; $((...)) needs no fork either.
	_, _ = sh.Write([]byte("ulimit -p; echo done-$((2+3))\n"))
	scr.waitFor(t, "done-5")
	// The limit is the line just before the marker. (The prompt can share
	// its line, as in "$ 10": Day 6's lesson about interactive output.)
	if !strings.Contains(scr.String(), "10\r\ndone-5") {
		t.Fatalf("a shell should see process limit 10; screen:\n%s", scr.String())
	}
	_ = sh.Detach()

	if _, err := exec.LookPath("python3"); err == nil {
		probe := `import os
n, err = 0, ""
for i in range(40):
    try:
        pid = os.fork()
    except OSError as e:
        err = os.strerror(e.errno); break
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0); n += 1
print("started=%d refused=%s" % (n, err or "none"))`
		got := execOut("python3", "-c", probe)
		var started int
		if _, err := fmt.Sscanf(got, "started=%d", &started); err != nil || started >= 10 || !strings.Contains(got, "Resource temporarily unavailable") {
			t.Fatalf("fork probe under the limit: %q", got)
		}
		t.Logf("fork probe: %s", got)
	}

	// The agent itself is unlimited: it still starts programs and answers.
	if got := execOut("echo", "agent-still-works"); got != "agent-still-works" {
		t.Fatalf("the agent stopped working: %q", got)
	}
	if _, err := conn.Ping(wait(t)); err != nil {
		t.Fatalf("ping: %v", err)
	}
	select {
	case err := <-exited:
		t.Fatalf("the agent died: %v", err)
	default:
	}
}
