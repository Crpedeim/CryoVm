//go:build integration

// Integration tests against real gVisor. They need root and runsc, so they
// only build with -tags integration. From ~/sbx:
//
//	CGO_ENABLED=0 go build -o bin/sbx-agent ./cmd/sbx-agent
//	go test -c -tags integration -o bin/gvisor-it.test ./internal/sandbox/gvisor
//	sudo SBX_RUNSC="$(which runsc)" SBX_AGENT="$PWD/bin/sbx-agent" \
//	  bin/gvisor-it.test -test.v -test.run Integration
//
// Optional: SBX_ROOTFS (default /mnt/sbx/rootfs/ubuntu-24.04), SBX_PLATFORM,
// SBX_RUNSC_FLAGS (e.g. "--debug --debug-log=/tmp/runsc/").
package gvisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/agent"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

func itBackend(t *testing.T, withAgent bool) (*Backend, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration tests need root: run the test binary with sudo")
	}
	runsc := os.Getenv("SBX_RUNSC")
	if runsc == "" {
		runsc = "runsc"
	}
	if _, err := exec.LookPath(runsc); err != nil {
		t.Fatalf("runsc not found (%v); set SBX_RUNSC=\"$(which runsc)\"", err)
	}
	rootfs := os.Getenv("SBX_ROOTFS")
	if rootfs == "" {
		rootfs = "/mnt/sbx/rootfs/ubuntu-24.04"
	}
	if fi, err := os.Stat(rootfs); err != nil || !fi.IsDir() {
		t.Fatalf("rootfs directory %q not found; set SBX_ROOTFS", rootfs)
	}
	state, err := os.MkdirTemp("", "sbxit") // short: the agent socket lives under it
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })

	cfg := Config{RunscPath: runsc, StateDir: state, Platform: os.Getenv("SBX_PLATFORM")}
	if f := os.Getenv("SBX_RUNSC_FLAGS"); f != "" {
		cfg.ExtraFlags = strings.Fields(f)
	}
	if withAgent {
		cfg.AgentPath = os.Getenv("SBX_AGENT")
		if cfg.AgentPath == "" {
			t.Fatal("set SBX_AGENT to a static sbx-agent binary (see this file's header)")
		}
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b, rootfs
}

func itID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1_000_000_000)
}

// runLog returns runsc's output from Create, for failure messages.
func runLog(b *Backend, id string) string {
	out, _ := os.ReadFile(filepath.Join(b.cfg.StateDir, "bundles", id, "runsc-run.log"))
	return string(out)
}

func itExec(t *testing.T, sb sandbox.Sandbox, args ...string) (string, int) {
	t.Helper()
	var out bytes.Buffer
	res, err := sb.Exec(context.Background(), sandbox.ExecRequest{Args: args, Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("exec %q: %v", args, err)
	}
	return strings.TrimSpace(out.String()), res.ExitCode
}

// Day 1: a plain gVisor sandbox runs commands in isolation and cleans up.
func TestIntegrationExecAndShutdown(t *testing.T) {
	b, rootfs := itBackend(t, false)
	ctx := context.Background()
	id := itID("it1")

	start := time.Now()
	sb, err := b.Create(ctx, sandbox.Spec{ID: id, Rootfs: rootfs, VCPUs: 1, MemMiB: 256})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Logf("create: %s", time.Since(start).Round(time.Millisecond))
	defer sb.Shutdown(ctx, 5*time.Second)

	hostKernel, _ := exec.Command("uname", "-r").Output()
	kernel, code := itExec(t, sb, "uname", "-r")
	if code != 0 || kernel == "" {
		t.Fatalf("uname -r: exit %d, output %q", code, kernel)
	}
	if kernel == strings.TrimSpace(string(hostKernel)) {
		t.Errorf("sandbox reports the host's kernel %q: syscalls are not reaching gVisor", kernel)
	}
	t.Logf("kernel: sandbox %q, host %q", kernel, strings.TrimSpace(string(hostKernel)))

	if _, code := itExec(t, sb, "sh", "-c", "exit 3"); code != 3 {
		t.Errorf("exit code: want 3, got %d", code)
	}
	if out, _ := itExec(t, sb, "sh", "-c", "echo probe > /tmp/probe && cat /tmp/probe"); out != "probe" {
		t.Errorf("write+read in sandbox: got %q", out)
	}
	if out, _ := itExec(t, sb, "hostname"); out != "sbx-"+id {
		t.Errorf("hostname: want %q, got %q", "sbx-"+id, out)
	}
	if out, _ := itExec(t, sb, "cat", "/proc/net/dev"); strings.Contains(out, "eth") {
		t.Errorf("network should be loopback only:\n%s", out)
	}

	start = time.Now()
	if err := sb.Shutdown(ctx, 5*time.Second); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	t.Logf("shutdown: %s", time.Since(start).Round(time.Millisecond))
	select {
	case <-sb.Exited():
	case <-time.After(5 * time.Second):
		t.Fatal("Exited() never closed")
	}
	if out, _ := b.runQuiet(ctx, "list"); strings.Contains(string(out), id) {
		t.Errorf("sandbox still listed after shutdown:\n%s", out)
	}
}

// Day 2: the agent is init, dials home through the bind-mounted socket,
// answers pings, survives a dropped connection, and exits on SIGTERM.
func TestIntegrationAgent(t *testing.T) {
	b, rootfs := itBackend(t, true)
	ctx := context.Background()
	id := itID("it2")

	start := time.Now()
	sb, err := b.Create(ctx, sandbox.Spec{ID: id, Rootfs: rootfs, VCPUs: 1, MemMiB: 256})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer sb.Shutdown(ctx, 5*time.Second)

	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := sb.Agent(wctx)
	if err != nil {
		t.Fatalf("agent never connected: %v\nrunsc output:\n%s", err, runLog(b, id))
	}
	t.Logf("agent connected %s after create began: %+v", time.Since(start).Round(time.Millisecond), conn.Hello)
	if conn.Hello.PID != 1 {
		t.Errorf("agent should be the sandbox's init (PID 1), got PID %d", conn.Hello.PID)
	}
	if conn.Hello.SandboxID != id {
		t.Errorf("hello sandbox id %q, want %q", conn.Hello.SandboxID, id)
	}

	var rtts []time.Duration
	for i := 0; i < 100; i++ {
		d, err := conn.Ping(wctx)
		if err != nil {
			t.Fatalf("ping %d: %v", i, err)
		}
		rtts = append(rtts, d)
	}
	slices.Sort(rtts)
	t.Logf("100 pings: min %s, median %s, p99 %s", rtts[0], rtts[50], rtts[98])

	conn.Close()
	again, err := sb.Agent(wctx)
	if err != nil {
		t.Fatalf("agent did not reconnect after the host dropped it: %v", err)
	}
	if _, err := again.Ping(wctx); err != nil {
		t.Fatalf("ping after reconnect: %v", err)
	}

	if out, code := itExec(t, sb, "true"); code != 0 {
		t.Errorf("runsc exec alongside the agent: exit %d %q", code, out)
	}

	if err := sb.Shutdown(ctx, 5*time.Second); err != nil {
		t.Errorf("shutdown needed force, so the agent ignored SIGTERM as PID 1: %v", err)
	}
}

// Day 3: commands run through the agent inside real gVisor: output streams,
// exit codes and signals come back, concurrent commands stay separate,
// timeouts kill the whole process group, and orphans don't become zombies.
func TestIntegrationAgentExec(t *testing.T) {
	b, rootfs := itBackend(t, true)
	ctx := context.Background()
	id := itID("it3")
	sb, err := b.Create(ctx, sandbox.Spec{ID: id, Rootfs: rootfs, VCPUs: 1, MemMiB: 256})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer sb.Shutdown(ctx, 5*time.Second)
	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := sb.Agent(wctx); err != nil {
		t.Fatalf("agent never connected: %v\nrunsc output:\n%s", err, runLog(b, id))
	}

	run := func(req sandbox.ExecRequest) (string, string, sandbox.ExecResult) {
		t.Helper()
		var out, errb bytes.Buffer
		req.Stdout, req.Stderr = &out, &errb
		res, err := sb.Exec(wctx, req)
		if err != nil {
			t.Fatalf("exec %q: %v", req.Args, err)
		}
		return out.String(), errb.String(), res
	}

	// Output, stderr and exit code.
	out, errOut, res := run(sandbox.ExecRequest{Args: []string{"sh", "-c", "echo out; echo err >&2; exit 4"}})
	if out != "out\n" || errOut != "err\n" || res.ExitCode != 4 {
		t.Errorf("basic: stdout=%q stderr=%q res=%+v", out, errOut, res)
	}

	// Streaming: the first line must arrive well before the command ends.
	var first time.Time
	start := time.Now()
	stream := writerFunc(func(p []byte) (int, error) {
		if first.IsZero() {
			first = time.Now()
		}
		return len(p), nil
	})
	if _, err := sb.Exec(wctx, sandbox.ExecRequest{Args: []string{"sh", "-c", "echo a; sleep 1; echo b"}, Stdout: stream}); err != nil {
		t.Fatal(err)
	}
	total := time.Since(start)
	if first.IsZero() || first.Sub(start) > total-500*time.Millisecond {
		t.Errorf("output not streamed: first byte after %s of %s", first.Sub(start), total)
	}
	t.Logf("streaming: first byte after %s, command took %s", first.Sub(start).Round(time.Millisecond), total.Round(time.Millisecond))

	// Two concurrent commands keep their output separate.
	var wg sync.WaitGroup
	outs := make([]string, 2)
	for i := range outs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			o, _, _ := run(sandbox.ExecRequest{Args: []string{"sh", "-c", fmt.Sprintf("for k in 1 2 3 4 5; do echo c%d; sleep 0.05; done", i)}})
			outs[i] = o
		}(i)
	}
	wg.Wait()
	for i, o := range outs {
		if o != strings.Repeat(fmt.Sprintf("c%d\n", i), 5) {
			t.Errorf("concurrent exec %d mixed output: %q", i, o)
		}
	}

	// A timeout kills the whole process group, background job included.
	start = time.Now()
	_, _, res = run(sandbox.ExecRequest{Args: []string{"sh", "-c", "sleep 31.5 & sleep 31.5; wait"}, Timeout: 500 * time.Millisecond})
	took := time.Since(start)
	if !res.TimedOut {
		t.Errorf("timeout: %+v", res)
	}
	if took > 3*time.Second {
		t.Errorf("a 500ms timeout took %s: the kill didn't reach the command", took)
	}
	t.Logf("timeout honoured in %s", took.Round(time.Millisecond))
	survivors, _, _ := run(sandbox.ExecRequest{Args: []string{"sh", "-c",
		`n=0; for f in /proc/[0-9]*/cmdline; do c=$(tr "\0" " " < "$f" 2>/dev/null); [ "$c" = "sleep 31.5 " ] && n=$((n+1)); done; echo $n`}})
	if strings.TrimSpace(survivors) != "0" {
		t.Errorf("%s sleep processes survived the timeout", strings.TrimSpace(survivors))
	}

	// Killed by a signal.
	if _, _, res := run(sandbox.ExecRequest{Args: []string{"sh", "-c", "kill -9 $$"}}); res.Signal != "killed" {
		t.Errorf("signal: %+v", res)
	}

	// Env, working directory, stdin.
	out, _, _ = run(sandbox.ExecRequest{Args: []string{"sh", "-c", "echo $GREETING; pwd; cat"}, Env: []string{"GREETING=hi"}, Dir: "/tmp", Stdin: strings.NewReader("piped")})
	if out != "hi\n/tmp\npiped" {
		t.Errorf("env/dir/stdin: %q", out)
	}

	// Orphans are reaped by the agent (PID 1): no zombies left.
	run(sandbox.ExecRequest{Args: []string{"sh", "-c", "(sleep 0.2 &); exit 0"}})
	time.Sleep(1500 * time.Millisecond)
	zombies, _, _ := run(sandbox.ExecRequest{Args: []string{"sh", "-c", `grep -l "^State:.*Z" /proc/[0-9]*/status 2>/dev/null | wc -l`}})
	if strings.TrimSpace(zombies) != "0" {
		t.Errorf("%s zombie processes inside the sandbox", strings.TrimSpace(zombies))
	}

	// A missing program is an error, not an exit code.
	if _, err := sb.Exec(wctx, sandbox.ExecRequest{Args: []string{"/no/such/program"}}); err == nil {
		t.Error("missing program returned no error")
	}

	if err := sb.Shutdown(ctx, 5*time.Second); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// Day 4: files through the agent inside real gVisor, including the 100 MB
// done-when, checked independently with sha256sum inside the sandbox.
func TestIntegrationFiles(t *testing.T) {
	b, rootfs := itBackend(t, true)
	ctx := context.Background()
	id := itID("it4")
	// 1 GiB: depending on how gVisor backs the sandbox's writable layer, a
	// 100 MB file may count against the sandbox's memory.
	sb, err := b.Create(ctx, sandbox.Spec{ID: id, Rootfs: rootfs, VCPUs: 2, MemMiB: 1024})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer sb.Shutdown(ctx, 5*time.Second)
	wctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, err := sb.Agent(wctx); err != nil {
		t.Fatalf("agent never connected: %v\nrunsc output:\n%s", err, runLog(b, id))
	}
	execOut := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if _, err := sb.Exec(wctx, sandbox.ExecRequest{Args: args, Stdout: &out, Stderr: &out}); err != nil {
			t.Fatalf("exec %q: %v", args, err)
		}
		return strings.TrimSpace(out.String())
	}
	t.Logf("what backs /tmp in the sandbox:\n%s", execOut("df", "-h", "/tmp"))

	// The done-when: 100 MB up, verified three ways, and back down.
	const size = 100 << 20
	srcHash := sha256.New()
	src := io.TeeReader(io.LimitReader(rand.New(rand.NewSource(42)), size), srcHash)
	start := time.Now()
	up, err := sb.WriteFile(wctx, "/tmp/big.bin", src, sandbox.WriteOptions{})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	upTook := time.Since(start)
	want := hex.EncodeToString(srcHash.Sum(nil))
	if up.Size != size || up.SHA256 != want {
		t.Fatalf("upload result %+v, want %s", up, want)
	}
	if got := strings.Fields(execOut("sha256sum", "/tmp/big.bin")); len(got) == 0 || got[0] != want {
		t.Fatalf("sha256sum inside the sandbox disagrees: %v, want %s", got, want)
	}
	if fi, err := sb.Stat(wctx, "/tmp/big.bin"); err != nil || fi.Size != size {
		t.Fatalf("stat: %+v %v", fi, err)
	}
	start = time.Now()
	back := sha256.New()
	if _, err := sb.ReadFile(wctx, "/tmp/big.bin", back); err != nil {
		t.Fatalf("download: %v", err)
	}
	downTook := time.Since(start)
	if hex.EncodeToString(back.Sum(nil)) != want {
		t.Fatal("downloaded data differs")
	}
	mb := float64(size) / (1 << 20)
	t.Logf("100 MB through real gVisor: upload %s (%.0f MB/s), download %s (%.0f MB/s)",
		upTook.Round(time.Millisecond), mb/upTook.Seconds(), downTook.Round(time.Millisecond), mb/downTook.Seconds())
	execOut("rm", "-f", "/tmp/big.bin")

	// Mkdirs and mode: an uploaded script must be runnable.
	script := "#!/bin/sh\necho ran-script\n"
	if _, err := sb.WriteFile(wctx, "/tmp/deep/a/b/hello.sh", strings.NewReader(script), sandbox.WriteOptions{Mode: 0o755, Mkdirs: true}); err != nil {
		t.Fatalf("upload script: %v", err)
	}
	if out := execOut("/tmp/deep/a/b/hello.sh"); out != "ran-script" {
		t.Errorf("uploaded script printed %q", out)
	}
	res, err := sb.ListDir(wctx, "/tmp/deep/a/b")
	if err != nil || len(res.Entries) != 1 || res.Entries[0].Mode != 0o755 {
		t.Errorf("list: %+v %v", res, err)
	}

	// Errors keep their meaning across the sandbox boundary.
	if _, err := sb.ReadFile(wctx, "/no/such/file", io.Discard); !errors.Is(err, agent.ErrNotFound) {
		t.Errorf("missing file: want ErrNotFound, got %v", err)
	}
	if _, err := sb.ReadFile(wctx, "/tmp", io.Discard); !errors.Is(err, agent.ErrIsDir) {
		t.Errorf("directory: want ErrIsDir, got %v", err)
	}
	_, err = sb.WriteFile(wctx, "/sbx/evil", strings.NewReader("x"), sandbox.WriteOptions{})
	if !errors.Is(err, agent.ErrReadOnly) && !errors.Is(err, agent.ErrPermission) {
		t.Errorf("writing into the read-only /sbx must fail, got %v", err)
	}
	t.Logf("writing into /sbx was refused: %v", err)

	if err := sb.Shutdown(ctx, 5*time.Second); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// Day 6: terminal sessions inside real gVisor. The PTY comes from gVisor's
// own kernel: /dev/ptmx and the devpts mount from Day 1's OCI spec.
func TestIntegrationShell(t *testing.T) {
	b, rootfs := itBackend(t, true)
	ctx := context.Background()
	id := itID("it6")
	sb, err := b.Create(ctx, sandbox.Spec{ID: id, Rootfs: rootfs, VCPUs: 1, MemMiB: 256})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer sb.Shutdown(ctx, 5*time.Second)
	wctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	type term struct {
		sh   *agent.Shell
		mu   sync.Mutex
		buf  bytes.Buffer
		done chan sandbox.ShellEnd
	}
	open := func(opts sandbox.ShellOptions) *term {
		t.Helper()
		sh, err := sb.OpenShell(wctx, opts)
		if err != nil {
			t.Fatalf("open shell: %v\nrunsc output:\n%s", err, runLog(b, id))
		}
		tm := &term{sh: sh, done: make(chan sandbox.ShellEnd, 1)}
		go func() {
			end, _ := sh.Run(context.Background(), writerFunc(func(p []byte) (int, error) {
				tm.mu.Lock()
				defer tm.mu.Unlock()
				return tm.buf.Write(p)
			}))
			tm.done <- end
		}()
		return tm
	}
	waitFor := func(tm *term, want string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			tm.mu.Lock()
			ok := strings.Contains(tm.buf.String(), want)
			tm.mu.Unlock()
			if ok {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		tm.mu.Lock()
		defer tm.mu.Unlock()
		t.Fatalf("never saw %q; screen:\n%s", want, tm.buf.String())
	}
	typ := func(tm *term, s string) {
		t.Helper()
		if _, err := tm.sh.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}

	start := time.Now()
	a := open(sandbox.ShellOptions{Cols: 100, Rows: 30})
	t.Logf("session %s started (shell: default) in %s", a.sh.SessionID, time.Since(start).Round(time.Millisecond))
	// Computed markers: the terminal echoes what we type, only output shows sums.
	typ(a, "test -t 1 && echo TTY-$((1+1)); stty size\n")
	waitFor(a, "TTY-2")
	waitFor(a, "30 100")

	if err := a.sh.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	typ(a, "stty size\n")
	waitFor(a, "40 120")

	typ(a, "sleep 30\n")
	time.Sleep(500 * time.Millisecond)
	ctrlC := time.Now()
	typ(a, "\x03")
	typ(a, "echo AFTER-$((3+4))\n")
	waitFor(a, "AFTER-7")
	if took := time.Since(ctrlC); took > 3*time.Second {
		t.Errorf("Ctrl+C took %s inside gVisor", took)
	}

	typ(a, "cd /tmp && export KEPT=yes; (sleep 1; echo while-$((0+1))-away) &\n")
	typ(a, "echo READY-$((8+1))\n")
	waitFor(a, "READY-9")
	if err := a.sh.Detach(); err != nil {
		t.Fatal(err)
	}
	if end := <-a.done; !end.Detached {
		t.Fatalf("want detached: %+v", end)
	}
	time.Sleep(1500 * time.Millisecond)

	back := open(sandbox.ShellOptions{SessionID: a.sh.SessionID, Cols: 100, Rows: 30})
	if back.sh.Created {
		t.Fatal("reattach created a new session")
	}
	waitFor(back, "while-1-away") // printed while nobody was attached, replayed
	typ(back, "echo state=$(pwd)/$KEPT\n")
	waitFor(back, "state=/tmp/yes")

	list, err := sb.Sessions(wctx)
	if err != nil || len(list.Sessions) != 1 {
		t.Fatalf("sessions: %+v %v", list, err)
	}
	typ(back, "exit 5\n")
	if end := <-back.done; !end.Exited || end.Code != 5 {
		t.Fatalf("want exit 5: %+v", end)
	}
}

// Day 7: background processes inside real gVisor. A web server runs
// detached; its logs live in the sandbox; a signal stops it.
func TestIntegrationProcesses(t *testing.T) {
	b, rootfs := itBackend(t, true)
	ctx := context.Background()
	id := itID("it7")
	sb, err := b.Create(ctx, sandbox.Spec{ID: id, Rootfs: rootfs, VCPUs: 1, MemMiB: 256})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer sb.Shutdown(ctx, 5*time.Second)
	wctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if _, err := sb.Agent(wctx); err != nil {
		t.Fatalf("agent: %v\nrunsc output:\n%s", err, runLog(b, id))
	}
	execOut := func(args ...string) (string, int) {
		t.Helper()
		var out bytes.Buffer
		res, err := sb.Exec(wctx, sandbox.ExecRequest{Args: args, Stdout: &out, Stderr: &out})
		if err != nil {
			t.Fatalf("exec %q: %v", args, err)
		}
		return strings.TrimSpace(out.String()), res.ExitCode
	}
	logsNow := func(pid string) string {
		var out bytes.Buffer
		if _, err := sb.Logs(wctx, pid, 0, false, &out); err != nil {
			t.Fatalf("logs: %v", err)
		}
		return out.String()
	}

	// A counter, followed to the end: the basic contract.
	c, err := sb.StartProcess(wctx, sandbox.ProcStart{Args: []string{"sh", "-c", "for i in 1 2 3; do echo count $i; sleep 0.2; done; exit 3"}})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	var followed bytes.Buffer
	end, err := sb.Logs(wctx, c.ID, 0, true, &followed)
	if err != nil || followed.String() != "count 1\ncount 2\ncount 3\n" || !end.Exited {
		t.Fatalf("follow: %q %+v %v", followed.String(), end, err)
	}
	if info, err := sb.Wait(wctx, c.ID); err != nil || info.ExitCode != 3 {
		t.Fatalf("wait: %+v %v", info, err)
	}
	// The log is an ordinary file inside the sandbox.
	if out, _ := execOut("cat", "/var/log/sbx/"+c.ID+"/output.log"); out != "count 1\ncount 2\ncount 3" {
		t.Errorf("log file inside the sandbox: %q", out)
	}

	if _, code := execOut("sh", "-c", "command -v python3"); code != 0 {
		t.Log("no python3 in this rootfs: skipping the web-server part")
		return
	}
	srv, err := sb.StartProcess(wctx, sandbox.ProcStart{
		Args: []string{"python3", "-m", "http.server", "8765", "--bind", "127.0.0.1"},
		Env:  []string{"PYTHONUNBUFFERED=1"}, // a pipe, not a terminal: without this the banner sits in a buffer
	})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logsNow(srv.ID), "Serving HTTP") && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(logsNow(srv.ID), "Serving HTTP") {
		t.Fatalf("server never started; log: %q", logsNow(srv.ID))
	}
	out, _ := execOut("python3", "-c", "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8765/').status)")
	if out != "200" {
		t.Fatalf("request from inside the sandbox: %q", out)
	}
	deadline = time.Now().Add(5 * time.Second)
	for !strings.Contains(logsNow(srv.ID), `"GET / HTTP/1.1" 200`) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(logsNow(srv.ID), `"GET / HTTP/1.1" 200`) {
		t.Fatalf("request not in the server's log: %q", logsNow(srv.ID))
	}
	if err := sb.Signal(wctx, srv.ID, 15); err != nil {
		t.Fatal(err)
	}
	info, err := sb.Wait(wctx, srv.ID)
	if err != nil || info.Running || info.Signal != "terminated" {
		t.Fatalf("after SIGTERM: %+v %v", info, err)
	}
	t.Logf("web server ran detached, served a request, logged it (%d bytes), stopped on SIGTERM", info.LogBytes)
}

// Day 8, part 1: the limits are really in force. Day 1's spec set a memory
// limit and a CPU quota but no cgroup path, so runsc may have ignored them
// all along. This reads the sandbox's actual cgroup on the host.
func TestIntegrationLimitsApplied(t *testing.T) {
	b, rootfs := itBackend(t, true)
	ctx := context.Background()
	id := itID("it8a")
	sb, err := b.Create(ctx, sandbox.Spec{ID: id, Rootfs: rootfs, VCPUs: 1, MemMiB: 256, PidsMax: 256})
	if err != nil {
		t.Fatalf("create: %v\nrunsc output:\n%s", err, runLog(b, id))
	}
	wctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if _, err := sb.Agent(wctx); err != nil {
		t.Fatalf("agent: %v\nrunsc output:\n%s", err, runLog(b, id))
	}
	st, err := sb.Stats(wctx)
	if err != nil {
		t.Fatalf("stats: %v (runsc may not have placed the sandbox in a cgroup)", err)
	}
	t.Logf("cgroup %s: memory limit %d MiB, cpu quota %.2f cores on CPUs %q, pids limit %d, using %d MiB",
		st.Cgroup, st.MemoryLimit>>20, st.CPUQuota, st.CPUs, st.PidsLimit, st.MemoryBytes>>20)
	if !strings.Contains(st.Cgroup, id) {
		t.Errorf("cgroup %q doesn't name the sandbox: is it really the sandbox's own cgroup?", st.Cgroup)
	}
	if st.MemoryLimit != 256<<20 {
		t.Errorf("memory limit %d, want %d", st.MemoryLimit, 256<<20)
	}
	if st.CPUQuota < 0.99 || st.CPUQuota > 1.01 {
		t.Errorf("cpu quota %.2f cores, want 1", st.CPUQuota)
	}
	// 256 processes inside; the host's thread limit is the safety net above.
	if st.PidsLimit != hostPidsFor(256) {
		t.Errorf("host pids limit %d, want %d", st.PidsLimit, hostPidsFor(256))
	}
	var lim bytes.Buffer
	if _, err := sb.Exec(wctx, sandbox.ExecRequest{Args: []string{"sh", "-c", "ulimit -p"}, Stdout: &lim}); err != nil || strings.TrimSpace(lim.String()) != "256" {
		t.Errorf("process limit inside: %q %v, want 256", lim.String(), err)
	}
	dir := sb.(*Sandbox).CgroupDir()
	if err := sb.Shutdown(ctx, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("cgroup %s still exists after shutdown: a leak", dir)
	}
}

// Day 8, part 2: what gVisor actually does under pressure. Only the host's
// safety is asserted; everything else is measured and logged as OBSERVED,
// to decide what Day 8 builds next.
func TestIntegrationLimitsObserved(t *testing.T) {
	b, rootfs := itBackend(t, true)
	ctx := context.Background()
	newSandbox := func(tag string, spec sandbox.Spec) sandbox.Sandbox {
		t.Helper()
		spec.ID, spec.Rootfs = itID(tag), rootfs
		sb, err := b.Create(ctx, spec)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		t.Cleanup(func() { _ = sb.Shutdown(context.Background(), 5*time.Second) })
		wctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if _, err := sb.Agent(wctx); err != nil {
			t.Fatalf("agent: %v", err)
		}
		return sb
	}
	run := func(sb sandbox.Sandbox, timeout time.Duration, args ...string) (string, string, sandbox.ExecResult, error) {
		t.Helper()
		var out, errb bytes.Buffer
		cctx, cancel := context.WithTimeout(ctx, timeout+10*time.Second)
		defer cancel()
		res, err := sb.Exec(cctx, sandbox.ExecRequest{Args: args, Stdout: &out, Stderr: &errb, Timeout: timeout})
		return strings.TrimSpace(out.String()), strings.TrimSpace(errb.String()), res, err
	}

	// CPUs: what a 1-vCPU sandbox reports, and what three busy loops get.
	cpu := newSandbox("it8c", sandbox.Spec{VCPUs: 1, MemMiB: 256, PidsMax: 256})
	nproc, _, _, _ := run(cpu, 10*time.Second, "nproc")
	t.Logf("OBSERVED: nproc in a 1-vCPU sandbox says %q (Day 1 saw 2)", nproc)
	before, err := cpu.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	start := time.Now()
	// PIDs come from $!, not $(jobs -p): in dash (Ubuntu's /bin/sh), jobs
	// inside $( ) runs in a subshell with no jobs, and kills nothing.
	_, _, _, _ = run(cpu, 20*time.Second, "sh", "-c",
		"yes >/dev/null & a=$!; yes >/dev/null & b=$!; yes >/dev/null & c=$!; sleep 3; kill $a $b $c")
	after, _ := cpu.Stats(ctx)
	cores := float64(after.CPUUsage-before.CPUUsage) / float64(time.Since(start))
	t.Logf("OBSERVED: three busy loops got %.2f cores in total; throttled in %d periods (%s)",
		cores, after.ThrottledPeriods-before.ThrottledPeriods, after.CPUThrottled-before.CPUThrottled)
	if cores > 1.25 {
		t.Errorf("a 1-vCPU sandbox used %.2f cores: the CPU quota isn't holding", cores)
	}

	// Memory, with no daemon (so no memory guard): what does the kernel do
	// alone when a process tries to hold 1000 MiB in a 256 MiB sandbox?
	// (tail keeps its whole input when there are no newlines in it.) The
	// guarded version of this is TestIntegrationDaemonMemoryGuard.
	hog := newSandbox("it8m", sandbox.Spec{VCPUs: 1, MemMiB: 256, PidsMax: 4096})
	meminfo, _, _, _ := run(hog, 10*time.Second, "sh", "-c", "grep -E '^(MemTotal|MemAvailable)' /proc/meminfo | tr -s ' ' | tr '\n' ' '")
	t.Logf("OBSERVED: /proc/meminfo inside a 256 MiB sandbox: %s", meminfo)
	hogStart := time.Now()
	_, hogErr, res, err := run(hog, 60*time.Second, "sh", "-c", "head -c 1000m /dev/zero | tail")
	select {
	case <-hog.Exited():
		why := ""
		if r, ok := hog.(sandbox.ExitReasoner); ok {
			why = r.ExitReason()
		}
		t.Logf("OBSERVED: unguarded, the hog took the whole sandbox down after %s; reason: %q", time.Since(hogStart).Round(time.Millisecond), why)
		if !strings.Contains(why, "out-of-memory") {
			t.Errorf("the sandbox died but the reason doesn't say out-of-memory: %q", why)
		}
	case <-time.After(2 * time.Second):
		st, serr := hog.Stats(ctx)
		t.Logf("OBSERVED: unguarded, the sandbox survived the hog. exec: code %d signal %q err %v stderr %q; OOM kills %d, peak %d MiB",
			res.ExitCode, res.Signal, err, tailOf(hogErr, 200), st.OOMKills, st.MemoryPeak>>20)
		if serr == nil && st.MemoryPeak > 256<<20+1<<20 {
			t.Errorf("memory peaked at %d MiB in a 256 MiB sandbox", st.MemoryPeak>>20)
		}
	}

	// How many host threads does gVisor use per process inside? This
	// decides what a sensible pids.max is.
	threads := newSandbox("it8t", sandbox.Spec{VCPUs: 1, MemMiB: 256, PidsMax: 4096})
	idle, _ := threads.Stats(ctx)
	// The sleeps stay up for the measurement, then are killed: Day 8's first
	// run left them running and so spoiled the next probe.
	pidsFile := "/tmp/sleep-pids"
	out, _, _, _ := run(threads, 30*time.Second, "sh", "-c", startSleeps(50, "60")+`sleep 1; echo $pids > `+pidsFile+`; echo "running=$n"`)
	busy, _ := threads.Stats(ctx)
	_, _, _, _ = run(threads, 10*time.Second, "sh", "-c", "kill $(cat "+pidsFile+")")
	t.Logf("OBSERVED: host threads: %d idle, %d with 50 guest sleeps (%s): %.2f host threads per guest process",
		idle.Pids, busy.Pids, out, float64(busy.Pids-idle.Pids)/50)

	// Is RLIMIT_NPROC enforced inside gVisor? If so, it could refuse forks
	// inside the sandbox, instead of a host limit killing all of it. The
	// probe is Python, not shell: in dash a failed fork ends the whole
	// script, so a shell can't count how many forks a limit allowed.
	if _, code := runCode(run(threads, 10*time.Second, "sh", "-c", "command -v python3")); code == 0 {
		time.Sleep(200 * time.Millisecond) // let the killed sleeps go
		out, perr, _, _ := run(threads, 30*time.Second, "python3", "-c", nprocProbe(20, 50))
		t.Logf("OBSERVED: RLIMIT_NPROC 20 set by a process inside gVisor (as root): %s %s", out, tailOf(perr, 200))
	} else {
		t.Log("no python3 in this rootfs: skipping the RLIMIT_NPROC probe")
	}

	// Day 8 v3's promise: a process limit enforced *inside* the sandbox. With
	// 64 allowed, a burst of 100 forks is refused (EAGAIN) once the limit is
	// reached, and the sandbox survives: no host limit is anywhere near.
	forks := newSandbox("it8p", sandbox.Spec{VCPUs: 1, MemMiB: 512, PidsMax: 64})
	if _, code := runCode(run(forks, 10*time.Second, "sh", "-c", "command -v python3")); code == 0 {
		out, perr, _, _ := run(forks, 30*time.Second, "python3", "-c", nprocProbe(0, 100))
		t.Logf("process limit 64 inside, 100 forks tried: %s %s", out, tailOf(perr, 200))
		var started int
		if _, err := fmt.Sscanf(out, "started=%d", &started); err != nil || started >= 64 || !strings.Contains(out, "refused=Resource temporarily unavailable") {
			t.Errorf("want forks refused below 64 with EAGAIN, got %q", out)
		}
	} else {
		_, _, _, _ = run(forks, 30*time.Second, "sh", "-c", startSleeps(100, "60")+`sleep 0.5; kill $pids 2>/dev/null; true`)
	}
	select {
	case <-forks.Exited():
		why := ""
		if r, ok := forks.(sandbox.ExitReasoner); ok {
			why = r.ExitReason()
		}
		t.Errorf("the sandbox died at its process limit; reason: %q", why)
	case <-time.After(time.Second):
		st, _ := forks.Stats(ctx)
		t.Logf("the sandbox survived the burst; host threads %d of %d", st.Pids, st.PidsLimit)
	}
	if o, _, _, err := run(forks, 10*time.Second, "echo", "alive"); err != nil || o != "alive" {
		t.Errorf("sandbox unresponsive after the burst: %q %v", o, err)
	}
}

// startSleeps is shell that starts count background sleeps, counting the
// ones that really started in $n and their PIDs in $pids. It uses only
// builtins: when forks run out, counting must not need a fork (a $(...)
// would fail exactly then). A failed fork leaves $! unchanged, which is
// how a failure is told apart from a success.
func startSleeps(count int, seconds string) string {
	return fmt.Sprintf(`n=0; pids=""; last=""; i=0; while [ $i -lt %d ]; do i=$((i+1)); sleep %s & `+
		`if [ "$!" != "$last" ]; then n=$((n+1)); pids="$pids $!"; last=$!; fi; done; `, count, seconds)
}

// nprocProbe tries the given number of forks and reports how many
// succeeded and why the first refusal happened. With limit > 0 it first
// lowers RLIMIT_NPROC itself; with 0 it relies on the limit the sandbox
// already has. Python, not shell: in dash a failed fork ends the whole
// script, so a shell can't count past a refusal.
func nprocProbe(limit, tries int) string {
	set := ""
	if limit > 0 {
		set = fmt.Sprintf("resource.setrlimit(resource.RLIMIT_NPROC, (%d, %d))\n", limit, limit)
	}
	return `import os, resource, time
` + set + fmt.Sprintf(`n, pids, err = 0, [], ""
for i in range(%d):
    try:
        pid = os.fork()
    except OSError as e:
        err = os.strerror(e.errno)
        break
    if pid == 0:
        # Become a tiny sleep at once. A forked Python child that stays
        # Python slowly turns into a full private copy of the interpreter:
        # updating reference counts writes to every page it touches, and
        # each write breaks copy-on-write sharing. Day 8's first run of this
        # probe OOM-killed its sandbox that way, long before 64 processes.
        try:
            os.execv("/bin/sleep", ["sleep", "61"])
        finally:
            os._exit(127)
    pids.append(pid)
    n += 1
print("started=%%d refused=%%s" %% (n, err or "none"))
for p in pids:
    os.kill(p, 9)
    os.waitpid(p, 0)
`, tries)
}

func runCode(_, _ string, res sandbox.ExecResult, err error) (error, int) {
	if err != nil {
		return err, -1
	}
	return nil, res.ExitCode
}

func tailOf(s string, n int) string {
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

// Day 10: checkpoints of real gVisor sandboxes. Measured and logged, then
// asserted where the design makes a promise.
func TestIntegrationCheckpoint(t *testing.T) {
	b, rootfs := itBackend(t, true)
	ctx := context.Background()
	newSB := func(tag string) sandbox.Sandbox {
		t.Helper()
		sb, err := b.Create(ctx, sandbox.Spec{ID: itID(tag), Rootfs: rootfs, VCPUs: 1, MemMiB: 256, PidsMax: 256})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		t.Cleanup(func() { _ = sb.Shutdown(context.Background(), 5*time.Second) })
		wctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if _, err := sb.Agent(wctx); err != nil {
			t.Fatalf("agent: %v", err)
		}
		return sb
	}
	run := func(sb sandbox.Sandbox, args ...string) (string, error) {
		var out bytes.Buffer
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := sb.Exec(cctx, sandbox.ExecRequest{Args: args, Stdout: &out, Stderr: &out})
		return strings.TrimSpace(out.String()), err
	}
	// State worth saving: a file in the memory-backed /tmp, a background
	// process, a shell session.
	prepare := func(sb sandbox.Sandbox) {
		t.Helper()
		if _, err := run(sb, "sh", "-c", "echo remember-me > /tmp/marker"); err != nil {
			t.Fatal(err)
		}
		if _, err := sb.StartProcess(ctx, sandbox.ProcStart{Args: []string{"sleep", "300"}}); err != nil {
			t.Fatal(err)
		}
		sh, err := sb.OpenShell(ctx, sandbox.ShellOptions{Command: []string{"sh"}})
		if err != nil {
			t.Fatal(err)
		}
		sh.Close()
	}

	// 1. Pause: save everything, stop the sandbox.
	p := newSB("it10p")
	prepare(p)
	before, _ := p.Stats(ctx)
	dir := t.TempDir()
	res, err := p.Checkpoint(ctx, sandbox.CheckpointOptions{Dir: dir})
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	var files []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		fi, _ := e.Info()
		files = append(files, fmt.Sprintf("%s (%d KiB)", e.Name(), fi.Size()>>10))
	}
	t.Logf("OBSERVED: checkpoint of a sandbox using %d MiB: %.1f MiB image in %s; files: %s",
		before.MemoryBytes>>20, float64(res.ImageBytes)/(1<<20), res.Duration.Round(time.Millisecond), strings.Join(files, ", "))
	select {
	case <-p.Exited():
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox kept running after a checkpoint without leave-running")
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Error("the spec should be saved next to the image")
	}

	// 2. Snapshot: save everything, keep running; the agent comes back.
	s := newSB("it10s")
	prepare(s)
	snapStart := time.Now()
	sres, err := s.Checkpoint(ctx, sandbox.CheckpointOptions{Dir: t.TempDir(), LeaveRunning: true})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	out, err := run(s, "cat", "/tmp/marker")
	if err != nil || out != "remember-me" {
		t.Fatalf("after the snapshot: %q %v", out, err)
	}
	t.Logf("OBSERVED: snapshot %.1f MiB in %s; agent answering again %s after the snapshot began",
		float64(sres.ImageBytes)/(1<<20), sres.Duration.Round(time.Millisecond), time.Since(snapStart).Round(time.Millisecond))
	procs, _ := s.Processes(ctx)
	sessions, _ := s.Sessions(ctx)
	if len(procs) != 1 || !procs[0].Running || len(sessions.Sessions) != 1 {
		t.Errorf("the background process and shell session should survive a snapshot: %+v %+v", procs, sessions)
	}

	// 3. Is the quiesce needed? Checkpoint with the agent still connected.
	q := newSB("it10q")
	b.skipQuiesce = true
	_, qerr := q.Checkpoint(ctx, sandbox.CheckpointOptions{Dir: t.TempDir(), LeaveRunning: true})
	b.skipQuiesce = false
	if qerr != nil {
		t.Logf("OBSERVED: without the quiesce, runsc refused: %v", tailOf(qerr.Error(), 300))
		return
	}
	// The question Days 10-11 never asked, and Day 14 v1 paid for: is the
	// *source* still reachable after an unquiesced snapshot?
	rctx, rcancel := context.WithTimeout(ctx, 8*time.Second)
	defer rcancel()
	var probe bytes.Buffer
	_, rerr := q.Exec(rctx, sandbox.ExecRequest{Args: []string{"echo", "still-here"}, Stdout: &probe})
	if rerr == nil {
		t.Logf("OBSERVED: without the quiesce, runsc checkpointed anyway, and the source still answers")
	} else {
		t.Logf("OBSERVED: without the quiesce, runsc checkpointed anyway, but the source no longer answers (%v): why every checkpoint quiesces", rerr)
	}
}

// lockedBuf collects a shell's output from Run's goroutine.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Day 11: restores of real gVisor sandboxes. Everything a sandbox holds
// must come back: a file in the memory-backed /tmp, a background process
// still counting where it stopped, a shell session with its variables and
// working directory. Plus the probe that settles Day 10's open question:
// what becomes of an image taken without the quiesce?
func TestIntegrationRestore(t *testing.T) {
	b, rootfs := itBackend(t, true)
	ctx := context.Background()
	newSB := func(tag string) (sandbox.Sandbox, string) {
		t.Helper()
		id := itID(tag)
		sb, err := b.Create(ctx, sandbox.Spec{ID: id, Rootfs: rootfs, VCPUs: 1, MemMiB: 256, PidsMax: 256})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		wctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if _, err := sb.Agent(wctx); err != nil {
			t.Fatalf("agent: %v", err)
		}
		return sb, id
	}
	run := func(sb sandbox.Sandbox, args ...string) (string, error) {
		var out bytes.Buffer
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := sb.Exec(cctx, sandbox.ExecRequest{Args: args, Stdout: &out, Stderr: &out})
		return strings.TrimSpace(out.String()), err
	}
	// shellSay attaches to a session (or opens one), types a line, and
	// returns what came back within a second. It reports errors rather than
	// stopping the test: a check that fails after the restore must not skip
	// the no-quiesce probe at the end.
	shellSay := func(sb sandbox.Sandbox, sessionID, line string) (string, string, error) {
		t.Helper()
		sh, err := sb.OpenShell(ctx, sandbox.ShellOptions{SessionID: sessionID, Command: []string{"sh"}})
		if err != nil {
			return "", "", err
		}
		out := &lockedBuf{}
		done := make(chan struct{})
		go func() { _, _ = sh.Run(ctx, out); close(done) }()
		_, _ = sh.Write([]byte(line + "\n"))
		time.Sleep(time.Second)
		_ = sh.Detach()
		<-done
		return sh.SessionID, out.String(), nil
	}
	restore := func(id, dir string) (sandbox.Sandbox, time.Duration, error) {
		start := time.Now()
		r, err := b.Restore(ctx, id, dir)
		if err != nil {
			return nil, 0, err
		}
		t.Cleanup(func() { _ = r.Shutdown(context.Background(), 5*time.Second) })
		wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if _, err := r.Agent(wctx); err != nil {
			return r, 0, fmt.Errorf("the agent never came back: %w", err)
		}
		return r, time.Since(start), nil
	}

	sb, id := newSB("it11")
	if _, err := run(sb, "sh", "-c", "echo remember-me > /tmp/marker"); err != nil {
		t.Fatal(err)
	}
	counter, err := sb.StartProcess(ctx, sandbox.ProcStart{Args: []string{"sh", "-c", "i=0; while :; do i=$((i+1)); echo $i; sleep 0.2; done"}})
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := shellSay(sb, "", "X=kept-in-shell; cd /tmp")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	var logBefore bytes.Buffer
	endBefore, _ := sb.Logs(ctx, counter.ID, 0, false, &logBefore)
	uptimeBefore, _ := run(sb, "cut", "-d", " ", "-f1", "/proc/uptime")

	dir := t.TempDir()
	ckres, err := sb.Checkpoint(ctx, sandbox.CheckpointOptions{Dir: dir})
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	<-sb.Exited()
	_ = sb.Shutdown(ctx, 5*time.Second) // clean up after runsc, as the daemon does
	time.Sleep(2 * time.Second)         // time passes while it's paused

	r, took, err := restore(id, dir)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	t.Logf("OBSERVED: checkpoint %.1f MiB; restore took %s until the agent answered (a fresh create takes ~50 ms)",
		float64(ckres.ImageBytes)/(1<<20), took.Round(time.Millisecond))

	if out, err := run(r, "cat", "/tmp/marker"); err != nil || out != "remember-me" {
		t.Errorf("the file in /tmp: %q %v", out, err)
	}
	procs, _ := r.Processes(ctx)
	if len(procs) != 1 || procs[0].ID != counter.ID || !procs[0].Running {
		t.Errorf("the counter should still be running under the same ID: %+v", procs)
	}
	time.Sleep(time.Second)
	var logAfter bytes.Buffer
	if _, err := r.Logs(ctx, counter.ID, endBefore.Next, false, &logAfter); err != nil {
		t.Errorf("logs after: %v", err)
	}
	lastBefore := lastLine(logBefore.String())
	firstAfter := firstLine(logAfter.String())
	t.Logf("OBSERVED: the counter said %s before the checkpoint, then %s after the restore", lastBefore, firstAfter)
	if a, b := atoiOr(lastBefore, -1), atoiOr(firstAfter, -1); a < 1 || b <= a || b > a+20 {
		t.Errorf("the counter should continue where it stopped, not restart: %s then %s", lastBefore, firstAfter)
	}
	if _, said, err := shellSay(r, session, `echo "got:$X:$(pwd)"`); err != nil {
		t.Errorf("reattaching the shell session after the restore: %v", err)
	} else if !strings.Contains(said, "got:kept-in-shell:/tmp") {
		t.Errorf("the shell session should keep its variable and directory; it said:\n%s", tailOf(said, 300))
	}
	uptimeAfter, _ := run(r, "cut", "-d", " ", "-f1", "/proc/uptime")
	t.Logf("OBSERVED: /proc/uptime inside: %s s before the checkpoint, %s s after the restore (2 s paused in between)", uptimeBefore, uptimeAfter)
	if st, err := r.Stats(ctx); err != nil || st.MemoryLimit != 256<<20 {
		t.Errorf("the restored sandbox's limits: %+v %v", st, err)
	}

	// Day 10's open question: restore an image taken without the quiesce.
	q, qid := newSB("it11q")
	if _, err := run(q, "sh", "-c", "echo unquiesced > /tmp/marker"); err != nil {
		t.Fatal(err)
	}
	qdir := t.TempDir()
	b.skipQuiesce = true
	_, qerr := q.Checkpoint(ctx, sandbox.CheckpointOptions{Dir: qdir})
	b.skipQuiesce = false
	if qerr != nil {
		t.Logf("OBSERVED: without the quiesce, the checkpoint itself failed: %v", qerr)
		return
	}
	<-q.Exited()
	_ = q.Shutdown(ctx, 5*time.Second)
	qr, qtook, qerr := restore(qid, qdir)
	switch {
	case qerr != nil && qr == nil:
		t.Logf("OBSERVED: without the quiesce, the restore failed: %v", tailOf(qerr.Error(), 300))
	case qerr != nil:
		t.Logf("OBSERVED: without the quiesce, the restore succeeded but the agent never reconnected: %v", qerr)
	default:
		out, _ := run(qr, "cat", "/tmp/marker")
		t.Logf("OBSERVED: without the quiesce, the restore worked and the agent was back in %s (marker: %q)", qtook.Round(time.Millisecond), out)
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func firstLine(s string) string {
	return strings.Split(strings.TrimSpace(s), "\n")[0]
}

func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

// Day 15 (Day 9's done-when, finally asserted): a memory hog and a fork
// burst in one sandbox leave a second one unaffected. The neighbour answers
// a steady stream of execs throughout, and its limits never change.
func TestIntegrationNeighbourUnaffected(t *testing.T) {
	b, rootfs := itBackend(t, true)
	ctx := context.Background()
	mk := func(tag string, pids int) sandbox.Sandbox {
		t.Helper()
		sb, err := b.Create(ctx, sandbox.Spec{ID: itID(tag), Rootfs: rootfs, VCPUs: 1, MemMiB: 256, PidsMax: pids})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sb.Shutdown(context.Background(), 5*time.Second) })
		wctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if _, err := sb.Agent(wctx); err != nil {
			t.Fatal(err)
		}
		return sb
	}
	noisy, quiet := mk("it15n", 64), mk("it15q", 256)
	echo := func() (time.Duration, error) {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		start := time.Now()
		var out bytes.Buffer
		_, err := quiet.Exec(cctx, sandbox.ExecRequest{Args: []string{"echo", "ok"}, Stdout: &out})
		if err == nil && strings.TrimSpace(out.String()) != "ok" {
			err = fmt.Errorf("got %q", out.String())
		}
		return time.Since(start), err
	}
	var baseline time.Duration
	for i := 0; i < 5; i++ {
		if d, err := echo(); err == nil && d > baseline {
			baseline = d
		}
	}
	limitsBefore, _ := quiet.Stats(ctx)

	done := make(chan string, 1)
	go func() {
		hctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		_, _ = noisy.Exec(hctx, sandbox.ExecRequest{Args: []string{"sh", "-c", "head -c 1000m /dev/zero | tail"}})
		var probe bytes.Buffer
		_, _ = noisy.Exec(hctx, sandbox.ExecRequest{Args: []string{"python3", "-c", nprocProbe(0, 100)}, Stdout: &probe})
		select {
		case <-noisy.Exited():
			done <- "the noisy sandbox was killed"
		default:
			done <- "the noisy sandbox survived; fork probe: " + strings.TrimSpace(probe.String())
		}
	}()
	var worst time.Duration
	var failures, calls int
	var outcome string
loop:
	for {
		select {
		case outcome = <-done:
			break loop
		case <-time.After(200 * time.Millisecond):
			d, err := echo()
			calls++
			if err != nil {
				failures++
				t.Errorf("the neighbour failed to answer: %v", err)
			}
			if d > worst {
				worst = d
			}
		}
	}
	limitsAfter, _ := quiet.Stats(ctx)
	t.Logf("OBSERVED: neighbour exec latency: %s at rest, worst %s across %d execs during the noise (%s)",
		baseline.Round(time.Millisecond), worst.Round(time.Millisecond), calls, outcome)
	if failures > 0 || worst > 2*time.Second {
		t.Errorf("the neighbour was affected: %d failures, worst %s", failures, worst)
	}
	if limitsAfter.MemoryLimit != limitsBefore.MemoryLimit || limitsAfter.PidsLimit != limitsBefore.PidsLimit {
		t.Errorf("the neighbour's limits changed: %+v → %+v", limitsBefore, limitsAfter)
	}
}
