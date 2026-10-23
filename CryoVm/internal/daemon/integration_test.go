//go:build integration

// The daemon on real gVisor: the same stack sbxd runs, end to end. Needs
// root and runsc. From ~/sbx:
//
//	CGO_ENABLED=0 go build -o bin/sbx-agent ./cmd/sbx-agent
//	go test -c -tags integration -o bin/daemon-it.test ./internal/daemon
//	sudo SBX_RUNSC="$(which runsc)" SBX_AGENT="$PWD/bin/sbx-agent" \
//	  bin/daemon-it.test -test.v -test.run Integration
package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/Crpedeim/sbx/internal/netns"
	"github.com/Crpedeim/sbx/internal/proxy"
	"github.com/Crpedeim/sbx/internal/s3"
	"github.com/Crpedeim/sbx/internal/sandbox"
	"github.com/Crpedeim/sbx/internal/store"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
	"github.com/Crpedeim/sbx/internal/registry"
	"github.com/Crpedeim/sbx/internal/sandbox/gvisor"
)

type itEnv struct {
	runsc, agentBin, rootfs, state, db, dir string
}

func itSetup(t *testing.T) itEnv {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration tests need root: run the test binary with sudo")
	}
	e := itEnv{runsc: os.Getenv("SBX_RUNSC"), agentBin: os.Getenv("SBX_AGENT"), rootfs: os.Getenv("SBX_ROOTFS")}
	if e.runsc == "" {
		e.runsc = "runsc"
	}
	if e.rootfs == "" {
		e.rootfs = "/mnt/sbx/rootfs/ubuntu-24.04"
	}
	if e.agentBin == "" {
		t.Fatal(`set SBX_AGENT="$PWD/bin/sbx-agent" (see this file's header)`)
	}
	dir, err := os.MkdirTemp("", "sbxdit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	e.dir, e.state, e.db = dir, filepath.Join(dir, "state"), filepath.Join(dir, "reg.db")
	return e
}

// serve starts a manager and the HTTP API on a Unix socket, as sbxd does.
func (e itEnv) serve(t *testing.T, sock string) (*Manager, *gvisor.Backend, *client.Client, func()) {
	t.Helper()
	d := e.daemon(t, sock)
	return d.m, d.b, d.c, d.stop
}

// itDaemon is one daemon process, as far as a test can make one: a
// manager, its backend, registry and API server.
type itDaemon struct {
	m   *Manager
	b   *gvisor.Backend
	c   *client.Client
	srv *http.Server
	reg *registry.Registry
}

func (e itEnv) daemon(t *testing.T, sock string, adjust ...func(*Config)) *itDaemon {
	t.Helper()
	b, err := gvisor.New(gvisor.Config{RunscPath: e.runsc, StateDir: e.state, AgentPath: e.agentBin})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Open(e.db)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Backend: b, Registry: reg, Rootfs: e.rootfs, LifetimeEvery: 100 * time.Millisecond,
		CheckpointDir: filepath.Join(e.dir, "checkpoints"), Logf: t.Logf}
	for _, f := range adjust {
		f(&cfg)
	}
	m, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: NewHandler(m), ConnContext: ConnContext}
	go srv.Serve(ln)
	return &itDaemon{m: m, b: b, c: client.New(sock), srv: srv, reg: reg}
}

// stop is a clean stop: the stop policy applies.
func (d *itDaemon) stop() {
	d.srv.Close()
	d.m.Close(context.Background())
	d.reg.Close()
}

// crash is kill -9, as near as a test can get: no stop policy, the API and
// every agent listener close as the process would, sandboxes untouched.
func (d *itDaemon) crash() {
	d.srv.Close()
	d.m.closeOnce.Do(func() { close(d.m.stopLifetimes) })
	d.m.mu.Lock()
	for _, sb := range d.m.live {
		if r, ok := sb.(sandbox.Releaser); ok {
			r.Release()
		}
	}
	d.m.live = map[string]sandbox.Sandbox{}
	d.m.mu.Unlock()
	d.reg.Close()
}

// runscStatus is the sandbox's status in `runsc list`, or "" if absent.
func runscStatus(t *testing.T, e itEnv, id string) string {
	for _, line := range strings.Split(runscList(t, e), "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == id {
			return f[2]
		}
	}
	return ""
}

func runscList(t *testing.T, e itEnv) string {
	out, _ := exec.Command(e.runsc, "--root", filepath.Join(e.state, "runsc"), "list").CombinedOutput()
	return string(out)
}

// Day 5's done-when on real gVisor: create → exec → write → read →
// destroy through the HTTP API, with every state change recorded.
func TestIntegrationDaemonLifecycle(t *testing.T) {
	e := itSetup(t)
	_, _, c, stop := e.serve(t, filepath.Join(e.dir, "sbxd.sock"))
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	start := time.Now()
	sb, err := c.Create(ctx, api.CreateRequest{})
	if err != nil || sb.State != api.Running {
		t.Fatalf("create: %+v %v", sb, err)
	}
	t.Logf("create through the API (sandbox + agent ready): %s", time.Since(start).Round(time.Millisecond))

	var out bytes.Buffer
	st, err := c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "uname -r; exit 5"}, Stdout: &out})
	if err != nil || st.Code != 5 || !strings.Contains(out.String(), "gvisor") {
		t.Fatalf("exec: %+v %v %q", st, err, out.String())
	}

	if _, err := c.Put(ctx, sb.ID, "/work/hello.txt", strings.NewReader("hello from the host"), client.PutOptions{Mkdirs: true}); err != nil {
		t.Fatalf("put: %v", err)
	}
	var back bytes.Buffer
	if _, err := c.Fetch(ctx, sb.ID, "/work/hello.txt", &back); err != nil || back.String() != "hello from the host" {
		t.Fatalf("fetch: %q %v", back.String(), err)
	}

	if _, err := c.Destroy(ctx, sb.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	evs, _ := c.Events(ctx, sb.ID)
	if got := states(evs); got != "creating → running → stopping → stopped" {
		t.Fatalf("history: %s", got)
	}
	if l := runscList(t, e); strings.Contains(l, sb.ID) {
		t.Fatalf("runsc still lists the sandbox:\n%s", l)
	}
}

// A daemon that dies without stopping its sandboxes leaves real runsc
// sandboxes behind. The next daemon must reap them, and record why.
// Day 12: a daemon crash, on real gVisor. The sandbox keeps running through
// the outage, and the next daemon adopts it. A counter started before the
// crash shows one unbroken sequence: it never stopped.
func TestIntegrationRestartAdopts(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d1 := e.daemon(t, filepath.Join(e.dir, "a.sock"))
	sb, err := d1.c.Create(ctx, api.CreateRequest{ID: "orphan-it"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := d1.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"sh", "-c", "i=0; while :; do i=$((i+1)); echo $i; sleep 0.2; done"}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	d1.crash()
	if !strings.Contains(runscList(t, e), sb.ID) {
		t.Fatal("setup: the sandbox should outlive its daemon")
	}
	time.Sleep(2 * time.Second) // the outage

	start := time.Now()
	d2 := e.daemon(t, filepath.Join(e.dir, "b.sock"))
	defer d2.stop()
	took := time.Since(start)
	rec, _ := d2.c.Get(ctx, sb.ID)
	if rec.State != api.Running {
		t.Fatalf("want adopted and running: %+v", rec)
	}
	var log strings.Builder
	if _, err := d2.c.Logs(ctx, sb.ID, p.ID, 0, false, &log); err != nil {
		t.Fatal(err)
	}
	nums := strings.Fields(log.String())
	unbroken := len(nums) > 0 && nums[0] == "1"
	for i := 1; i < len(nums) && unbroken; i++ {
		unbroken = atoiOr(nums[i], -1) == atoiOr(nums[i-1], -1)+1
	}
	t.Logf("OBSERVED: the new daemon started, adopting the sandbox, in %s; the counter is at %d, one unbroken sequence: %v",
		took.Round(time.Millisecond), len(nums), unbroken)
	if !unbroken || len(nums) < 15 {
		t.Errorf("the counter should have kept counting through the outage, unbroken: %d numbers", len(nums))
	}
	if st, err := d2.c.Stats(ctx, sb.ID); err != nil || st.MemoryLimit == 0 {
		t.Errorf("stats after adoption (the memory guard needs them): %+v %v", st, err)
	}
	_, _ = d2.c.Destroy(ctx, sb.ID)
}

// Day 6 through the daemon on real gVisor: HTTP upgrade, detach, reattach.
func TestIntegrationDaemonShell(t *testing.T) {
	e := itSetup(t)
	_, _, c, stop := e.serve(t, filepath.Join(e.dir, "sbxd.sock"))
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sb, err := c.Create(ctx, api.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy(ctx, sb.ID)

	a := attach(t, c, sb.ID, client.ShellOptions{Cols: 80, Rows: 24})
	a.typ(t, "cd /tmp; echo HELLO-$((40+2))\n")
	a.scr.waitFor(t, "HELLO-42")
	_ = a.conn.Detach()
	if end := a.end(t); !end.Detached {
		t.Fatalf("want detached: %+v", end)
	}
	b := attach(t, c, sb.ID, client.ShellOptions{SessionID: a.conn.SessionID})
	b.scr.waitFor(t, "HELLO-42")
	b.typ(t, "echo where=$(pwd)\n")
	b.scr.waitFor(t, "where=/tmp")
	b.typ(t, "exit 0\n")
	if end := b.end(t); !end.Exited || end.Code != 0 {
		t.Fatalf("want exit 0: %+v", end)
	}
}

// Day 7 through the daemon on real gVisor: start, follow, wait, remove.
func TestIntegrationDaemonProcesses(t *testing.T) {
	e := itSetup(t)
	_, _, c, stop := e.serve(t, filepath.Join(e.dir, "sbxd.sock"))
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sb, err := c.Create(ctx, api.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy(ctx, sb.ID)

	p, err := c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"sh", "-c", "for i in 1 2 3; do echo tick $i; sleep 0.2; done; exit 7"}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	end, err := c.Logs(ctx, sb.ID, p.ID, 0, true, &out)
	if err != nil || out.String() != "tick 1\ntick 2\ntick 3\n" || !end.Exited || end.Next != 21 {
		t.Fatalf("follow: %q %+v %v", out.String(), end, err)
	}
	info, err := c.Wait(ctx, sb.ID, p.ID)
	if err != nil || info.ExitCode != 7 {
		t.Fatalf("wait: %+v %v", info, err)
	}
	if err := c.RemoveProcess(ctx, sb.ID, p.ID); err != nil {
		t.Fatal(err)
	}
}

// Day 8 through the daemon on real gVisor: limits from the API reach the
// sandbox's cgroup, and stats come back.
func TestIntegrationDaemonLimits(t *testing.T) {
	e := itSetup(t)
	_, _, c, stop := e.serve(t, filepath.Join(e.dir, "sbxd.sock"))
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sb, err := c.Create(ctx, api.CreateRequest{VCPUs: 1, MemMiB: 384, PidsMax: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy(ctx, sb.ID)
	st, err := c.Stats(ctx, sb.ID)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	// 128 processes inside: the host thread limit is 64 + 3 * 128.
	if st.MemoryLimit != 384<<20 || st.PidsLimit != 64+3*128 || st.CPUQuota < 0.99 || st.CPUQuota > 1.01 {
		t.Fatalf("limits through the API: %+v", st)
	}
	t.Logf("cgroup %s using %d MiB of %d MiB", st.Cgroup, st.MemoryBytes>>20, st.MemoryLimit>>20)
}

// Day 8 v2's promise, on real gVisor: a runaway process is killed by the
// memory guard, and the sandbox, with everything else in it, survives.
// Without the guard, the kernel's OOM killer would end the whole sandbox
// (Day 8's first finding).
func TestIntegrationDaemonMemoryGuard(t *testing.T) {
	e := itSetup(t)
	_, _, c, stop := e.serve(t, filepath.Join(e.dir, "sbxd.sock"))
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sb, err := c.Create(ctx, api.CreateRequest{VCPUs: 1, MemMiB: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy(ctx, sb.ID)

	// Something else worth keeping alive in the sandbox.
	bystander, err := c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"sleep", "300"}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	st, err := c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "head -c 1000m /dev/zero | tail"}, Timeout: 60 * time.Second})
	t.Logf("the hog ended after %s: %+v %v", time.Since(start).Round(time.Millisecond), st, err)

	rec, _ := c.Get(ctx, sb.ID)
	if rec.State != api.Running {
		t.Fatalf("the sandbox didn't survive: %+v", rec)
	}
	var note string
	evs, _ := c.Events(ctx, sb.ID)
	for _, ev := range evs {
		if strings.HasPrefix(ev.Detail, "memory guard:") {
			note = ev.Detail
		}
	}
	if note == "" {
		t.Fatal("no memory guard kill in the history")
	}
	t.Logf("history: %s", note)
	if p, err := c.Process(ctx, sb.ID, bystander.ID); err != nil || !p.Running {
		t.Fatalf("the bystander process should still be running: %+v %v", p, err)
	}
	stats, _ := c.Stats(ctx, sb.ID)
	t.Logf("after: %d MiB in use, peak %d MiB, kernel OOM kills %d", stats.MemoryBytes>>20, stats.MemoryPeak>>20, stats.OOMKills)
}

// Day 9 on real gVisor: a sandbox with a 3-second lifetime is destroyed,
// really: gone from runsc and from the host's cgroup tree, with the reason
// in its history and the audit log, and the chain intact.
func TestIntegrationDaemonLifetime(t *testing.T) {
	e := itSetup(t)
	_, _, c, stop := e.serve(t, filepath.Join(e.dir, "sbxd.sock"))
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sb, err := c.Create(ctx, api.CreateRequest{TTLSeconds: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"echo", "before the deadline"}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	var rec api.Sandbox
	for time.Now().Before(deadline) {
		if rec, _ = c.Get(ctx, sb.ID); rec.State == api.Stopped {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if rec.State != api.Stopped {
		t.Fatalf("not destroyed at its deadline: %+v", rec)
	}
	if l := runscList(t, e); strings.Contains(l, sb.ID) {
		t.Fatalf("runsc still has it:\n%s", l)
	}
	if _, err := os.Stat("/sys/fs/cgroup/sbx/" + sb.ID); !os.IsNotExist(err) {
		t.Errorf("its cgroup is still there: %v", err)
	}
	entries, _ := c.Audit(ctx, sb.ID, 20)
	var expired, execd bool
	for _, en := range entries {
		expired = expired || (en.Action == "lifetime.expire" && en.Actor == "sbxd")
		execd = execd || (en.Action == "exec" && strings.Contains(en.Detail, "before the deadline"))
	}
	if !expired || !execd {
		t.Fatalf("audit should hold the exec and the expiry: %+v", entries)
	}
	if v, err := c.VerifyAudit(ctx); err != nil || !v.OK {
		t.Fatalf("verify: %+v %v", v, err)
	}
	t.Logf("destroyed at its deadline; %d audit entries for it, chain intact", len(entries))
}

// Day 10 through the daemon on real gVisor: pause, list, destroy, and the
// image goes with it.
func TestIntegrationDaemonCheckpoint(t *testing.T) {
	e := itSetup(t)
	m, _, c, stop := e.serve(t, filepath.Join(e.dir, "sbxd.sock"))
	defer stop()
	m.cfg.CheckpointDir = filepath.Join(e.dir, "checkpoints")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sb, err := c.Create(ctx, api.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "echo state > /tmp/state"}}); err != nil {
		t.Fatal(err)
	}
	ck, err := c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{})
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	t.Logf("checkpoint %s: %.1f MiB in %dms", ck.ID, float64(ck.ImageBytes)/(1<<20), ck.DurationMs)
	if rec, _ := c.Get(ctx, sb.ID); rec.State != api.Paused {
		t.Fatalf("want paused: %+v", rec)
	}
	if l := runscList(t, e); strings.Contains(l, sb.ID) && !strings.Contains(l, "stopped") {
		t.Fatalf("runsc still runs it:\n%s", l)
	}
	if _, err := c.Destroy(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ck.Path); !os.IsNotExist(err) {
		t.Fatalf("the image outlived its sandbox: %v", err)
	}
}

// Day 11 through the daemon on real gVisor: pause, resume, and what was
// written before is there after.
func TestIntegrationDaemonResume(t *testing.T) {
	e := itSetup(t)
	m, _, c, stop := e.serve(t, filepath.Join(e.dir, "sbxd.sock"))
	defer stop()
	m.cfg.CheckpointDir = filepath.Join(e.dir, "checkpoints")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sb, err := c.Create(ctx, api.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy(ctx, sb.ID)
	if _, err := c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "echo before-the-pause > /tmp/state"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{}); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	start := time.Now()
	rec, err := c.Resume(ctx, sb.ID, "")
	if err != nil || rec.State != api.Running {
		t.Fatalf("resume: %+v %v", rec, err)
	}
	t.Logf("resumed through the API in %s", time.Since(start).Round(time.Millisecond))
	var out strings.Builder
	if _, err := c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"cat", "/tmp/state"}, Stdout: &out}); err != nil || strings.TrimSpace(out.String()) != "before-the-pause" {
		t.Fatalf("after the resume: %q %v", out.String(), err)
	}
}

func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

// Day 12: a clean stop with the pause policy, on real gVisor. The running
// sandbox is checkpointed; the next daemon resumes it, counter and files
// intact.
func TestIntegrationShutdownPausesAndStartResumes(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pause := func(c *Config) { c.OnStop = OnStopPause }
	d1 := e.daemon(t, filepath.Join(e.dir, "a.sock"), pause)
	sb, err := d1.c.Create(ctx, api.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = d1.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "echo through-the-restart > /tmp/state"}})
	p, _ := d1.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"sh", "-c", "i=0; while :; do i=$((i+1)); echo $i; sleep 0.2; done"}})
	time.Sleep(time.Second)
	stopStart := time.Now()
	d1.stop()
	stopTook := time.Since(stopStart)
	if st := runscStatus(t, e, sb.ID); st == "running" {
		t.Fatalf("after a pausing stop, the sandbox should not run:\n%s", runscList(t, e))
	}

	start := time.Now()
	d2 := e.daemon(t, filepath.Join(e.dir, "b.sock"), pause)
	defer d2.stop()
	t.Logf("OBSERVED: the stop paused the sandbox in %s; the next start resumed it in %s",
		stopTook.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
	rec, _ := d2.c.Get(ctx, sb.ID)
	if rec.State != api.Running || rec.ResumeOnStart {
		t.Fatalf("want resumed: %+v", rec)
	}
	var out strings.Builder
	if _, err := d2.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"cat", "/tmp/state"}, Stdout: &out}); err != nil || strings.TrimSpace(out.String()) != "through-the-restart" {
		t.Errorf("the file after the restart: %q %v", out.String(), err)
	}
	var log strings.Builder
	_, _ = d2.c.Logs(ctx, sb.ID, p.ID, 0, false, &log)
	nums := strings.Fields(log.String())
	if len(nums) == 0 || nums[0] != "1" || atoiOr(nums[len(nums)-1], 0) != len(nums) {
		t.Errorf("the counter should continue from where it paused, unbroken: %d numbers, last %q", len(nums), lastOf(nums))
	}
	_, _ = d2.c.Destroy(ctx, sb.ID)
}

func lastOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

// Day 12: the sandbox is gone while the daemon is down (a host reboot does
// this). The next daemon records why, rather than pretending.
func TestIntegrationGoneWhileTheDaemonWasDown(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d1 := e.daemon(t, filepath.Join(e.dir, "a.sock"))
	sb, err := d1.c.Create(ctx, api.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	d1.crash()
	if err := d1.b.Reap(ctx, sb.ID); err != nil { // the reboot
		t.Fatal(err)
	}
	d2 := e.daemon(t, filepath.Join(e.dir, "b.sock"))
	defer d2.stop()
	rec, _ := d2.c.Get(ctx, sb.ID)
	if rec.State != api.Failed || !strings.Contains(rec.Error, "no longer running") {
		t.Fatalf("want failed, no longer running: %+v", rec)
	}
	t.Logf("recorded as: %s", rec.Error)
}

// Day 13 on real gVisor. How much CPU does a truly idle sandbox use (it
// must be under the 5% threshold, or nothing would ever pause)? How long
// does a request on a sleeping sandbox take, against an awake one? And does
// a busy loop really keep a sandbox awake?
func TestIntegrationIdlePauseAndWake(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"), func(c *Config) {
		c.DefaultIdleAction = api.IdlePause
		c.LifetimeEvery = 200 * time.Millisecond
	})
	defer d.stop()
	execTime := func(id string) (time.Duration, string, error) {
		var out strings.Builder
		start := time.Now()
		_, err := d.c.Exec(ctx, id, client.ExecRequest{Args: []string{"cat", "/tmp/note"}, Stdout: &out})
		return time.Since(start), strings.TrimSpace(out.String()), err
	}

	// 1. What does idle cost? A sandbox doing nothing, measured for 3 s.
	quiet, err := d.c.Create(ctx, api.CreateRequest{IdleTimeoutS: -1})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := d.c.Stats(ctx, quiet.ID)
	time.Sleep(3 * time.Second)
	b, _ := d.c.Stats(ctx, quiet.ID)
	idleCores := float64(b.CPUUsageMicros-a.CPUUsageMicros) / 3e6
	t.Logf("OBSERVED: an idle sandbox uses %.4f cores (the idle threshold is 0.05)", idleCores)
	if idleCores >= 0.05 {
		t.Errorf("an idle sandbox is above the threshold: nothing would ever pause")
	}

	// 2. Asleep, then woken by use.
	sb, err := d.c.Create(ctx, api.CreateRequest{IdleTimeoutS: 2})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = d.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "echo kept > /tmp/note"}})
	if _, err := d.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"sleep", "300"}}); err != nil {
		t.Fatal(err)
	}
	awake, _, _ := execTime(sb.ID)
	idleStart := time.Now()
	var rec api.Sandbox
	for time.Since(idleStart) < 20*time.Second {
		if rec, _ = d.c.Get(ctx, sb.ID); rec.State == api.Paused {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if rec.State != api.Paused || !rec.WakeOnUse {
		t.Fatalf("an idle sandbox with a sleeping process should pause: %+v", rec)
	}
	t.Logf("OBSERVED: paused %s after its last use (idle timeout 2 s)", time.Since(idleStart).Round(100*time.Millisecond))
	asleep, out, err := execTime(sb.ID)
	if err != nil || out != "kept" {
		t.Fatalf("an exec should wake it and work: %q %v", out, err)
	}
	t.Logf("OBSERVED: the same exec took %s awake, %s asleep (wake included)", awake.Round(time.Millisecond), asleep.Round(time.Millisecond))
	procs, _ := d.c.Processes(ctx, sb.ID)
	if len(procs) != 1 || !procs[0].Running {
		t.Errorf("the sleeping process should still be there after the wake: %+v", procs)
	}

	// 3. A busy loop is not idle.
	busy, err := d.c.Create(ctx, api.CreateRequest{IdleTimeoutS: 2})
	if err != nil {
		t.Fatal(err)
	}
	loop, err := d.c.StartProcess(ctx, busy.ID, api.ProcStartRequest{Args: []string{"sh", "-c", "while :; do :; done"}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second)
	if rec, _ := d.c.Get(ctx, busy.ID); rec.State != api.Running {
		t.Fatalf("a sandbox computing for 6 s with a 2 s idle timeout was paused: %+v", rec)
	}
	_ = d.c.Signal(ctx, busy.ID, loop.ID, 9)
	stopped := time.Now()
	for time.Since(stopped) < 15*time.Second {
		if rec, _ = d.c.Get(ctx, busy.ID); rec.State == api.Paused {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if rec.State != api.Paused {
		t.Fatalf("once the loop stopped, it should pause: %+v", rec)
	}
	t.Logf("OBSERVED: the busy sandbox stayed awake while computing; paused %s after the loop stopped", time.Since(stopped).Round(100*time.Millisecond))
}

// Day 14 on real gVisor: three forks of one prepared sandbox. Each starts
// with the source's files and processes, then lives its own life, in its
// own cgroup. The source answers again right after, and the forks outlive
// it.
func TestIntegrationFork(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"))
	defer d.stop()
	run := func(id string, args ...string) (string, error) {
		var out strings.Builder
		res, err := d.c.Exec(ctx, id, client.ExecRequest{Args: args, Stdout: &out, Stderr: &out})
		if err == nil && res.Code != 0 {
			err = fmt.Errorf("exit %d", res.Code)
		}
		return strings.TrimSpace(out.String()), err
	}

	src, err := d.c.Create(ctx, api.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run(src.ID, "sh", "-c", "echo prepared > /tmp/base"); err != nil {
		t.Fatal(err)
	}
	counter, err := d.c.StartProcess(ctx, src.ID, api.ProcStartRequest{Args: []string{"sh", "-c", "i=0; while :; do i=$((i+1)); echo $i; sleep 0.2; done"}})
	if err != nil {
		t.Fatal(err)
	}
	srcHost, _ := run(src.ID, "hostname")
	time.Sleep(time.Second)

	start := time.Now()
	forks, err := d.c.Fork(ctx, src.ID, api.ForkRequest{Count: 3})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	took := time.Since(start)
	t.Logf("OBSERVED: 3 forks in %s (%s each, one snapshot)", took.Round(time.Millisecond), (took / 3).Round(time.Millisecond))
	// The check that would have caught Day 14 v1: the source still answers.
	if out, err := run(src.ID, "cat", "/tmp/base"); err != nil || out != "prepared" {
		t.Fatalf("the source after being forked: %q %v", out, err)
	}

	for _, f := range forks {
		if out, err := run(f.ID, "cat", "/tmp/base"); err != nil || out != "prepared" {
			t.Errorf("%s: the source's file: %q %v", f.ID, out, err)
		}
		if _, err := run(f.ID, "sh", "-c", "echo "+f.ID+" > /tmp/whoami"); err != nil {
			t.Errorf("%s: write: %v", f.ID, err)
		}
		procs, _ := d.c.Processes(ctx, f.ID)
		if len(procs) != 1 || procs[0].ID != counter.ID || !procs[0].Running {
			t.Errorf("%s: the counter should be running here too, under the same ID: %+v", f.ID, procs)
		}
		st, err := d.c.Stats(ctx, f.ID)
		if err != nil || st.Cgroup != "/sbx/"+f.ID || st.MemoryLimit == 0 {
			t.Errorf("%s: its own cgroup and limits: %+v %v", f.ID, st, err)
		}
	}
	// Each world is its own: a fork's file is in no one else's.
	for _, f := range forks {
		if out, _ := run(f.ID, "cat", "/tmp/whoami"); out != f.ID {
			t.Errorf("%s sees another fork's file: %q", f.ID, out)
		}
	}
	if out, err := run(src.ID, "cat", "/tmp/whoami"); err == nil {
		t.Errorf("the source sees a fork's file: %q", out)
	}
	forkHost, _ := run(forks[0].ID, "hostname")
	t.Logf("OBSERVED: hostname inside: source %q, fork %q (the fork's spec names it %q)", srcHost, forkHost, forks[0].ID)

	// The counters diverge, each log unbroken from 1.
	time.Sleep(time.Second)
	var flog strings.Builder
	_, _ = d.c.Logs(ctx, forks[0].ID, counter.ID, 0, false, &flog)
	nums := strings.Fields(flog.String())
	unbroken := len(nums) > 5 && nums[0] == "1"
	for i := 1; i < len(nums) && unbroken; i++ {
		unbroken = atoiOr(nums[i], -1) == atoiOr(nums[i-1], -1)+1
	}
	if !unbroken {
		t.Errorf("the fork's counter should carry on from the snapshot, unbroken: %v", nums)
	}
	var mem int64
	for _, f := range forks {
		st, _ := d.c.Stats(ctx, f.ID)
		mem += st.MemoryBytes
	}
	sst, _ := d.c.Stats(ctx, src.ID)
	t.Logf("OBSERVED: memory: source %d MiB; the three forks %d MiB together", sst.MemoryBytes>>20, mem>>20)

	// The forks outlive their source, and its deleted images.
	if _, err := d.c.Destroy(ctx, src.ID); err != nil {
		t.Fatal(err)
	}
	for _, f := range forks {
		if out, err := run(f.ID, "cat", "/tmp/base"); err != nil || out != "prepared" {
			t.Errorf("%s after its source was destroyed: %q %v", f.ID, out, err)
		}
		_, _ = d.c.Destroy(ctx, f.ID)
	}
}

// Day 15 on real gVisor: clones of a sandbox each take their own identity.
// Asserted: each reads its own ID (file and environment), generations all
// differ, fresh kernel randomness differs, a generation-aware program
// diverges, and each clone's clock agrees with the host's. Recorded: whether
// a naive program's clones print the same "random" sequence, the limit no
// outside agent can fix.
func TestIntegrationCloneIdentity(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"))
	defer d.stop()
	run := func(id string, args ...string) string {
		var out strings.Builder
		if _, err := d.c.Exec(ctx, id, client.ExecRequest{Args: args, Stdout: &out}); err != nil {
			t.Errorf("%s: %v: %v", id, args, err)
		}
		return strings.TrimSpace(out.String())
	}
	lastN := func(id, proc string, n int) []string {
		var out strings.Builder
		_, _ = d.c.Logs(ctx, id, proc, 0, false, &out)
		var nums []string
		for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			if !strings.HasPrefix(l, "#") && l != "" {
				nums = append(nums, l)
			}
		}
		if len(nums) > n {
			nums = nums[len(nums)-n:]
		}
		return nums
	}
	common := func(a, b []string) int {
		set := map[string]bool{}
		for _, x := range a {
			set[x] = true
		}
		n := 0
		for _, x := range b {
			if set[x] {
				n++
			}
		}
		return n
	}

	src, err := d.c.Create(ctx, api.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(repoFile(t, "scripts", "generation_aware.py"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.c.Put(ctx, src.ID, "/tmp/generation_aware.py", bytes.NewReader(script), client.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	naive, err := d.c.StartProcess(ctx, src.ID, api.ProcStartRequest{Args: []string{"python3", "-c",
		"import random, time\nwhile True:\n    print(random.random(), flush=True); time.sleep(0.2)"}})
	if err != nil {
		t.Fatal(err)
	}
	aware, err := d.c.StartProcess(ctx, src.ID, api.ProcStartRequest{Args: []string{"python3", "/tmp/generation_aware.py"}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	forks, err := d.c.Fork(ctx, src.ID, api.ForkRequest{Count: 2})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	time.Sleep(2 * time.Second) // let both programs print for a while in each clone

	all := append([]string{src.ID}, forks[0].ID, forks[1].ID)
	gens := map[string]string{}
	entropy := map[string]bool{}
	for _, id := range all {
		if got := run(id, "sh", "-c", `cat "$SBX_IDENTITY_DIR/sandbox-id"`); got != id {
			t.Errorf("%s reads its id as %q", id, got)
		}
		if got := run(id, "sh", "-c", "echo $SBX_SANDBOX_ID"); got != id {
			t.Errorf("%s: a new process's SBX_SANDBOX_ID is %q", id, got)
		}
		gen := run(id, "sh", "-c", `cat "$SBX_IDENTITY_DIR/generation"`)
		if other, dup := gens[gen]; dup || gen == "" {
			t.Errorf("%s shares generation %q with %s", id, gen, other)
		}
		gens[gen] = id
		r := run(id, "sh", "-c", "head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \\n'")
		if entropy[r] || r == "" {
			t.Errorf("%s drew kernel randomness %q that another clone also drew", id, r)
		}
		entropy[r] = true
		before := time.Now()
		guest := run(id, "date", "+%s.%N")
		after := time.Now()
		if g, err := strconv.ParseFloat(guest, 64); err != nil || g < float64(before.UnixNano())/1e9-0.5 || g > float64(after.UnixNano())/1e9+0.5 {
			t.Errorf("%s: its clock says %s; the host's was %d.%09d", id, guest, before.Unix(), before.Nanosecond())
		}
	}
	f1, f2 := forks[0].ID, forks[1].ID
	naiveCommon := common(lastN(f1, naive.ID, 6), lastN(f2, naive.ID, 6))
	awareCommon := common(lastN(f1, aware.ID, 6), lastN(f2, aware.ID, 6))
	t.Logf("OBSERVED: of their last 6 numbers, the two clones' naive programs share %d; their generation-aware programs share %d", naiveCommon, awareCommon)
	if awareCommon != 0 {
		t.Errorf("the generation-aware program should diverge across clones: %d numbers in common", awareCommon)
	}
	for _, id := range all {
		_, _ = d.c.Destroy(ctx, id)
	}
}

// repoFile finds a file in the repository, wherever the test runs from.
// "go test" runs a package's tests in that package's directory, but a
// compiled test binary runs wherever it's started (usually the repo root),
// so a path relative to the working directory works for one and not the
// other (Day 15 found that out). The source file's own location, recorded
// at compile time, works for both on the machine that built it.
func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("can't locate the test's source file")
	}
	return filepath.Join(append([]string{filepath.Dir(self), "..", ".."}, parts...)...)
}

// Day 16 on real gVisor, with real namespaces. Asserted: two sandboxes share
// the inside address and the host sees each from its own; a sandbox reaches
// an external host (the plan's done-when); a sandbox without a network has
// none; a networked sandbox pauses and resumes with its network working; a
// destroy leaves no namespace or link behind.
func TestIntegrationNetwork(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// A stand-in for Day 18's proxy, on the host. Egress open: Day 16's
	// check reaches the internet directly (Day 17 tests the default, deny).
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"), func(c *Config) { c.Egress = netns.EgressOpen; c.ProxyPort = port })
	defer d.stop()
	py := func(id, code string) (string, error) {
		var out strings.Builder
		res, err := d.c.Exec(ctx, id, client.ExecRequest{Args: []string{"python3", "-c", code}, Stdout: &out, Stderr: &out, Timeout: 20 * time.Second})
		if err == nil && res.Code != 0 {
			err = fmt.Errorf("exit %d", res.Code)
		}
		return strings.TrimSpace(out.String()), err
	}
	// connectHome has the sandbox connect to the proxy's address inside
	// (its gateway), through its router to the host, and returns what each
	// side saw. Since Day 17 the host accepts only the proxy port from a
	// sandbox, open egress or not.
	connectHome := func(sb api.Sandbox) (inside, seen string, err error) {
		accepted := make(chan string, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				accepted <- ""
				return
			}
			accepted <- c.RemoteAddr().(*net.TCPAddr).IP.String()
			c.Close()
		}()
		inside, err = py(sb.ID, fmt.Sprintf("import socket; s=socket.create_connection(('%s', %d), 5); print(s.getsockname()[0])",
			netns.ProxyAddr, port))
		if err != nil {
			return inside, "", err
		}
		select {
		case seen = <-accepted:
		case <-time.After(5 * time.Second):
		}
		return inside, seen, nil
	}

	var boxes []api.Sandbox
	for i := 0; i < 2; i++ {
		sb, err := d.c.Create(ctx, api.CreateRequest{Network: true})
		if err != nil {
			t.Fatalf("create with a network: %v", err)
		}
		boxes = append(boxes, sb)
	}
	for _, sb := range boxes {
		inside, seen, err := connectHome(sb)
		t.Logf("OBSERVED: sandbox in slot %d: %s inside; the host sees %s", sb.NetSlot, inside, seen)
		if err != nil || inside != netns.InsideAddr || seen != sb.NetAddr {
			t.Errorf("slot %d: inside %q (want %s), seen %q (want %s), %v", sb.NetSlot, inside, netns.InsideAddr, seen, sb.NetAddr, err)
		}
	}

	// The plan's done-when: an external host, by address (no DNS until Day 18).
	start := time.Now()
	out, err := py(boxes[0].ID, "import socket; socket.create_connection(('1.1.1.1', 443), 10); print('connected')")
	if err != nil || out != "connected" {
		fwd, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		rules, _ := exec.Command("nft", "list", "ruleset").CombinedOutput()
		var hooks []string
		for _, l := range strings.Split(string(rules), "\n") {
			if strings.Contains(l, "hook forward") || strings.Contains(l, "hook postrouting") {
				hooks = append(hooks, strings.TrimSpace(l))
			}
		}
		t.Errorf("reaching 1.1.1.1:443 failed: %q %v (ip_forward=%s; forward/postrouting chains: %v)", out, err, strings.TrimSpace(string(fwd)), hooks)
	} else {
		t.Logf("OBSERVED: reached 1.1.1.1:443 from inside in %s", time.Since(start).Round(time.Millisecond))
	}

	// No network asked for: none at all.
	plain, _ := d.c.Create(ctx, api.CreateRequest{})
	if out, err := py(plain.ID, "import socket; socket.create_connection(('1.1.1.1', 443), 3)"); err == nil {
		t.Errorf("a sandbox without a network connected out: %q", out)
	}

	// Day 16 v2's hypothesis: at boot, runsc moved eth0's address into
	// gVisor, leaving eth0 in the namespace bare. Recorded, not assumed.
	t.Logf("OBSERVED: eth0 in the sandbox's namespace, after boot: %s", netns.InsideState(ctx, boxes[0].ID))

	// Pause and resume a networked sandbox: the open question of Day 16.
	ck, err := d.c.Checkpoint(ctx, boxes[0].ID, api.CheckpointRequest{})
	if err != nil {
		t.Errorf("OBSERVED: checkpointing a networked sandbox failed: %v", err)
	} else if _, err := d.c.Resume(ctx, boxes[0].ID, ""); err != nil {
		t.Errorf("OBSERVED: checkpoint %s worked, but resuming the networked sandbox failed: %v", ck.ID, err)
	} else {
		inside, seen, err := connectHome(boxes[0])
		t.Logf("OBSERVED: a networked sandbox paused (%.1f MiB) and resumed: %s inside, the host sees %s, %v",
			float64(ck.ImageBytes)/(1<<20), inside, seen, err)
		if err != nil || seen != boxes[0].NetAddr {
			// What the restored sandbox itself sees, so a next step isn't
			// designed blind.
			view, _ := py(boxes[0].ID, "import socket; print(socket.if_nameindex()); print(open('/proc/net/route').read())")
			t.Errorf("networking after the resume: seen %q, %v; the sandbox's own view: %s; eth0 now: %s",
				seen, err, view, netns.InsideState(ctx, boxes[0].ID))
		}
	}

	// Destroy leaves nothing behind.
	for _, sb := range append(boxes, plain) {
		if _, err := d.c.Destroy(ctx, sb.ID); err != nil {
			t.Error(err)
		}
	}
	for _, sb := range boxes {
		if netns.Exists(sb.ID) {
			t.Errorf("%s: namespaces left after destroy", sb.ID)
		}
		if _, err := os.Stat("/sys/class/net/" + netns.NamesFor(sb.ID, sb.NetSlot).Host); err == nil {
			t.Errorf("%s: host link left after destroy", sb.ID)
		}
	}
}

// Day 17 on real gVisor, with the default policy: egress denied. The plan's
// done-when: direct connections to any address fail, DNS included. And the
// one way out, the proxy's address, works, seen by the host as this
// sandbox's own address.
func TestIntegrationDefaultDeny(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	proxy, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() {
		for {
			c, err := proxy.Accept()
			if err != nil {
				return
			}
			fmt.Fprintf(c, "%s\n", c.RemoteAddr().(*net.TCPAddr).IP)
			c.Close()
		}
	}()
	hostSvc, _ := net.Listen("tcp4", "0.0.0.0:0") // a host service that isn't the proxy
	defer hostSvc.Close()
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"), func(c *Config) { c.ProxyPort = proxy.Addr().(*net.TCPAddr).Port })
	defer d.stop()
	sb, err := d.c.Create(ctx, api.CreateRequest{Network: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.c.Destroy(ctx, sb.ID)
	py := func(code string) (string, error) {
		var out strings.Builder
		res, err := d.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"python3", "-c", code}, Stdout: &out, Stderr: &out, Timeout: 20 * time.Second})
		if err == nil && res.Code != 0 {
			err = fmt.Errorf("exit %d", res.Code)
		}
		return strings.TrimSpace(out.String()), err
	}
	tcp := func(host string, port int) string {
		return fmt.Sprintf("import socket; s=socket.create_connection(('%s', %d), 3); print('connected')", host, port)
	}
	for name, code := range map[string]string{
		"1.1.1.1:443 (the internet)": tcp("1.1.1.1", 443),
		"DNS over UDP to 1.1.1.1":    "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01', ('1.1.1.1', 53)); s.recv(512); print('answered')",
		"DNS over TCP to 1.1.1.1":    tcp("1.1.1.1", 53),
		"name resolution":            "import socket; print(socket.getaddrinfo('example.com', 443))",
		"the router itself":          tcp(netns.ProxyAddr, 22),
		"a host service":             tcp(netns.HostAddr(sb.NetSlot).String(), hostSvc.Addr().(*net.TCPAddr).Port),
	} {
		start := time.Now()
		if out, err := py(code); err == nil {
			t.Errorf("%s: reachable with egress denied: %q", name, out)
		} else {
			t.Logf("OBSERVED: %s: refused or silent after %s (%s)", name, time.Since(start).Round(time.Millisecond), lastLine(out))
		}
	}
	got, err := py(fmt.Sprintf("import socket; s=socket.create_connection(('%s', %d), 5); print(s.recv(64).decode().strip())",
		netns.ProxyAddr, proxy.Addr().(*net.TCPAddr).Port))
	if err != nil || got != sb.NetAddr {
		t.Fatalf("the proxy path: %q %v; want the host to see %s", got, err, sb.NetAddr)
	}
	t.Logf("OBSERVED: the one way out works: %s:%d, seen by the host as %s", netns.ProxyAddr, proxy.Addr().(*net.TCPAddr).Port, got)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// Day 18 on real gVisor: the plan's done-when. pip install from an
// allowlisted index works through the proxy, a non-allowlisted domain is
// refused, and both are in the audit chain, attributed to the sandbox.
func TestIntegrationEgressProxy(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	free, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"), func(c *Config) { c.ProxyPort = port })
	defer d.stop()
	if _, err := d.m.StartProxy(fmt.Sprintf("0.0.0.0:%d", port), []string{"pypi.org", "files.pythonhosted.org"}); err != nil {
		t.Fatal(err)
	}
	sb, err := d.c.Create(ctx, api.CreateRequest{Network: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.c.Destroy(ctx, sb.ID)
	run := func(timeout time.Duration, args ...string) (string, error) {
		var out strings.Builder
		res, err := d.c.Exec(ctx, sb.ID, client.ExecRequest{Args: args, Stdout: &out, Stderr: &out, Timeout: timeout})
		if err == nil && res.Code != 0 {
			err = fmt.Errorf("exit %d", res.Code)
		}
		return strings.TrimSpace(out.String()), err
	}

	if got, _ := run(10*time.Second, "sh", "-c", "echo $HTTPS_PROXY"); got != fmt.Sprintf("http://10.89.0.1:%d", port) {
		t.Fatalf("HTTPS_PROXY inside: %q", got)
	}
	// The proxy's rules, by raw CONNECT from inside.
	for target, want := range map[string]string{
		"pypi.org:443":    "200",
		"example.com:443": "403",
		"pypi.org:22":     "403",
		"1.1.1.1:443":     "403",
	} {
		code := fmt.Sprintf("import socket; s=socket.create_connection(('10.89.0.1', %d), 5); "+
			"s.sendall(b'CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n'); print(s.recv(200).decode().split()[1])", port, target, target)
		if got, err := run(20*time.Second, "python3", "-c", code); got != want {
			t.Errorf("CONNECT %s: got %q (%v), want %s", target, got, err, want)
		}
	}

	// pip: the rootfs may not have it. If not, get-pip.py is fetched on the
	// host and copied in; it downloads pip itself through the proxy.
	if _, err := run(30*time.Second, "python3", "-m", "pip", "--version"); err != nil {
		resp, err := http.Get("https://bootstrap.pypa.io/get-pip.py")
		if err != nil {
			t.Fatalf("no pip in the rootfs, and the host couldn't fetch get-pip.py: %v", err)
		}
		script, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if _, err := d.c.Put(ctx, sb.ID, "/tmp/get-pip.py", bytes.NewReader(script), client.PutOptions{}); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		out, err := run(4*time.Minute, "python3", "/tmp/get-pip.py", "--break-system-packages", "--no-cache-dir")
		if err != nil {
			t.Fatalf("bootstrapping pip through the proxy: %v\n%s", err, out)
		}
		t.Logf("OBSERVED: the rootfs had no pip; get-pip.py installed it through the proxy in %s", time.Since(start).Round(time.Millisecond))
	} else {
		t.Log("OBSERVED: the rootfs has pip")
	}
	start := time.Now()
	out, err := run(4*time.Minute, "python3", "-m", "pip", "install", "--break-system-packages", "--no-cache-dir", "--target", "/tmp/pk", "six")
	if err != nil {
		t.Fatalf("pip install from PyPI through the proxy: %v\n%s", err, out)
	}
	version, err := run(10*time.Second, "sh", "-c", "PYTHONPATH=/tmp/pk python3 -c 'import six; print(six.__version__)'")
	if err != nil {
		t.Fatalf("importing what pip installed: %v %s", err, version)
	}
	t.Logf("OBSERVED: pip install six through the proxy in %s; six %s imports", time.Since(start).Round(time.Millisecond), version)

	// A non-allowlisted index: refused (no retries, so it fails fast).
	if out, err := run(2*time.Minute, "python3", "-m", "pip", "download", "--no-cache-dir", "--retries", "0", "--timeout", "10",
		"--index-url", "https://example.com/simple/", "-d", "/tmp/dl", "six"); err == nil {
		t.Errorf("pip from a non-allowlisted index should fail:\n%s", out)
	}

	// The audit chain, for this sandbox.
	entries, err := d.c.Audit(ctx, sb.ID, 1000)
	if err != nil {
		t.Fatal(err)
	}
	allowed, denied := map[string]int{}, map[string]string{}
	for _, a := range entries {
		if a.Action != "net.connect" || a.Actor != "sandbox" {
			continue
		}
		host := strings.Fields(a.Detail)[1]
		if a.Outcome == "allowed" {
			allowed[host]++
		} else {
			denied[host] = a.Error
		}
	}
	t.Logf("OBSERVED: audit for %s: allowed %v; denied %v", sb.ID, allowed, denied)
	if allowed["pypi.org:443"] == 0 || allowed["files.pythonhosted.org:443"] == 0 {
		t.Errorf("pip's connections should be in the audit chain: %v", allowed)
	}
	if denied["example.com:443"] != "not on the allowlist" {
		t.Errorf("the refused index should be in the audit chain: %v", denied)
	}
	if v, err := d.c.VerifyAudit(ctx); err != nil || !v.OK {
		t.Errorf("the audit chain should verify: %+v %v", v, err)
	}
}

// Day 19 on real gVisor, the plan's done-when: 3 clones of a networked
// sandbox make allowed requests at once, each attributed to the right
// sandbox in the audit log. Recorded: the MAC gVisor reports inside, and how
// soon after the fork each clone's first request succeeds (a stale neighbor
// cache would show here as a stall).
func TestIntegrationNetworkedClones(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	free, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"), func(c *Config) { c.ProxyPort = port })
	defer d.stop()
	if _, err := d.m.StartProxy(fmt.Sprintf("0.0.0.0:%d", port), []string{"pypi.org"}); err != nil {
		t.Fatal(err)
	}
	py := func(id, code string) (string, error) {
		var out strings.Builder
		res, err := d.c.Exec(ctx, id, client.ExecRequest{Args: []string{"python3", "-c", code}, Stdout: &out, Stderr: &out, Timeout: 30 * time.Second})
		if err == nil && res.Code != 0 {
			err = fmt.Errorf("exit %d", res.Code)
		}
		return strings.TrimSpace(out.String()), err
	}
	src, err := d.c.Create(ctx, api.CreateRequest{Network: true})
	if err != nil {
		t.Fatal(err)
	}
	// gVisor has no /sys/class/net (v1 read it there, failed, and then
	// compared one error message with another: a check that checked
	// nothing). SIOCGIFHWADDR asks the network stack itself.
	readMAC := func(id string) (string, error) {
		return py(id, "import fcntl, socket, struct; s=socket.socket(); "+
			"info=fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', b'eth0')); print(':'.join('%02x' % b for b in info[18:24]))")
	}
	mac, macErr := readMAC(src.ID)
	if macErr != nil {
		t.Logf("OBSERVED: the source's MAC couldn't be read inside gVisor (%s): the clone comparison below is skipped", lastLine(mac))
	} else {
		t.Logf("OBSERVED: the MAC gVisor reports inside the source: %s (the namespace's eth0 is %s)", mac, netns.InsideMAC)
	}

	start := time.Now()
	forks, err := d.c.Fork(ctx, src.ID, api.ForkRequest{Count: 3})
	if err != nil {
		t.Fatalf("fork a networked sandbox: %v", err)
	}
	forked := time.Since(start)
	request := fmt.Sprintf("import socket; s=socket.create_connection(('10.89.0.1', %d), 10); "+
		"s.sendall(b'CONNECT pypi.org:443 HTTP/1.1\\r\\nHost: pypi.org:443\\r\\n\\r\\n'); "+
		"print(s.getsockname()[0], s.recv(200).decode().split()[1])", port)
	type result struct {
		id, out string
		took    time.Duration
		err     error
	}
	results := make(chan result, len(forks))
	at := time.Now()
	for _, f := range forks {
		go func(id string) {
			t0 := time.Now()
			out, err := py(id, request)
			results <- result{id, out, time.Since(t0), err}
		}(f.ID)
	}
	addrs := map[string]string{}
	for range forks {
		r := <-results
		t.Logf("OBSERVED: clone %s: %q in %s", r.id, r.out, r.took.Round(time.Millisecond))
		if r.err != nil || r.out != "10.89.0.2 200" {
			t.Errorf("clone %s: %q %v (want its own 10.89.0.2, and 200)", r.id, r.out, r.err)
		}
	}
	t.Logf("OBSERVED: 3 networked clones in %s; all three requests done %s after they began", forked.Round(time.Millisecond), time.Since(at).Round(time.Millisecond))
	for _, f := range forks {
		if other, dup := addrs[f.NetAddr]; dup || f.NetAddr == "" || f.NetAddr == src.NetAddr {
			t.Errorf("clone %s: address %q (shared with %q?)", f.ID, f.NetAddr, other)
		}
		addrs[f.NetAddr] = f.ID
		entries, err := d.c.Audit(ctx, f.ID, 50)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, a := range entries {
			if a.Action == "net.connect" && a.Actor == "sandbox" && a.Outcome == "allowed" && strings.HasPrefix(a.Detail, "CONNECT pypi.org:443") {
				found = true
			}
		}
		if !found {
			t.Errorf("clone %s: its request isn't attributed to it in the audit log", f.ID)
		}
		if macErr == nil {
			if m, err := readMAC(f.ID); err != nil || m != mac {
				t.Errorf("clone %s reports MAC %q (%v); the source %s", f.ID, m, err, mac)
			}
		}
	}
	if srcEntries, _ := d.c.Audit(ctx, src.ID, 50); len(srcEntries) > 0 {
		for _, a := range srcEntries {
			if a.Action == "net.connect" {
				t.Errorf("a clone's request was attributed to the source: %+v", a)
			}
		}
	}
	for _, sb := range append([]api.Sandbox{src}, forks...) {
		_, _ = d.c.Destroy(ctx, sb.ID)
	}
	for _, sb := range append([]api.Sandbox{src}, forks...) {
		if netns.Exists(sb.ID) {
			t.Errorf("%s: namespaces left after destroy", sb.ID)
		}
	}
}

// Day 20 on real gVisor, the plan's done-when: a Playwright script in a
// browser sandbox loads a public page and saves a screenshot, and requests
// to a private address or 169.254.169.254 are refused and logged. And the
// plan's adjustment: the heavier image's memory, checkpoint size and
// per-clone memory, recorded. Needs the browser image
// (scripts/build-browser-rootfs.sh); skipped without it.
func TestIntegrationBrowser(t *testing.T) {
	e := itSetup(t)
	rootfs := os.Getenv("SBX_BROWSER_ROOTFS")
	if rootfs == "" {
		rootfs = "/mnt/sbx/rootfs/browser"
	}
	if _, err := os.Stat(filepath.Join(rootfs, "usr/local/lib")); err != nil {
		t.Skipf("no browser image at %s: build it with sudo scripts/build-browser-rootfs.sh (or set SBX_BROWSER_ROOTFS)", rootfs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	free, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"), func(c *Config) {
		c.ProxyPort = port
		c.Images = map[string]Image{"browser": {Rootfs: rootfs, MemMiB: 2048, Network: true, Policy: proxy.PolicyBrowse}}
	})
	defer d.stop()
	if _, err := d.m.StartProxy(fmt.Sprintf("0.0.0.0:%d", port), nil); err != nil {
		t.Fatal(err)
	}
	sb, err := d.c.Create(ctx, api.CreateRequest{Image: "browser"})
	if err != nil {
		t.Fatalf("create a browser sandbox: %v", err)
	}
	defer d.c.Destroy(ctx, sb.ID)
	run := func(timeout time.Duration, args ...string) (string, error) {
		var out strings.Builder
		res, err := d.c.Exec(ctx, sb.ID, client.ExecRequest{Args: args, Stdout: &out, Stderr: &out, Timeout: timeout})
		if err == nil && res.Code != 0 {
			err = fmt.Errorf("exit %d", res.Code)
		}
		return strings.TrimSpace(out.String()), err
	}

	// A public page, and a screenshot.
	script, err := os.ReadFile(repoFile(t, "scripts", "screenshot.py"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.c.Put(ctx, sb.ID, "/tmp/screenshot.py", bytes.NewReader(script), client.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	out, err := run(4*time.Minute, "python3", "/tmp/screenshot.py", "https://example.com", "/tmp/shot.png")
	if err != nil || !strings.HasPrefix(out, "200 'Example Domain'") {
		t.Fatalf("loading a public page in Chromium: %v\n%s", err, out)
	}
	t.Logf("OBSERVED: %s", lastLine(out))
	var png bytes.Buffer
	if _, err := d.c.Fetch(ctx, sb.ID, "/tmp/shot.png", &png); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(png.Bytes(), []byte("\x89PNG\r\n\x1a\n")) || png.Len() < 2000 {
		t.Fatalf("the screenshot isn't a real PNG: %d bytes", png.Len())
	}
	_ = os.WriteFile(filepath.Join(os.TempDir(), "sbx-day20-shot.png"), png.Bytes(), 0o644)
	t.Logf("OBSERVED: screenshot %d KiB, copied to %s", png.Len()/1024, filepath.Join(os.TempDir(), "sbx-day20-shot.png"))

	// Private and metadata addresses, from the browser itself.
	probe := `
import os
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(proxy={"server": os.environ["HTTPS_PROXY"]}, args=["--disable-dev-shm-usage"])
    page = b.new_page()
    for url in ["http://169.254.169.254/latest/meta-data/", "https://169.254.169.254/", "http://10.0.0.1/", "https://localhost/"]:
        try:
            r = page.goto(url, timeout=20000)
            print(url, "status", r.status)
        except Exception as e:
            print(url, "error", str(e).splitlines()[0])
    b.close()
`
	out, err = run(3*time.Minute, "python3", "-c", probe)
	if err != nil {
		t.Fatalf("the probe: %v\n%s", err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		t.Logf("OBSERVED: %s", line)
		if strings.Contains(line, "status 200") {
			t.Errorf("reached a private or metadata address: %s", line)
		}
	}
	entries, err := d.c.Audit(ctx, sb.ID, 500)
	if err != nil {
		t.Fatal(err)
	}
	denied := map[string]string{}
	allowed := 0
	for _, a := range entries {
		if a.Action != "net.connect" {
			continue
		}
		if a.Outcome == "allowed" {
			allowed++
		} else {
			denied[strings.Fields(a.Detail)[1]] = a.Error
		}
	}
	t.Logf("OBSERVED: audit: %d allowed connections; denied %v", allowed, denied)
	for target, want := range map[string]string{
		"169.254.169.254:80":  "169.254.169.254 is not a public address",
		"169.254.169.254:443": "169.254.169.254 is not a public address",
		"10.0.0.1:80":         "10.0.0.1 is not a public address",
		"localhost:443":       "localhost resolves to 127.0.0.1, which is not a public address",
	} {
		if denied[target] != want {
			t.Errorf("%s: logged as %q, want %q", target, denied[target], want)
		}
	}

	// The heavier image: memory, checkpoint size, per-clone memory.
	st, _ := d.c.Stats(ctx, sb.ID)
	ck, err := d.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{LeaveRunning: true})
	if err != nil {
		t.Fatalf("checkpoint a browser sandbox: %v", err)
	}
	t.Logf("OBSERVED: a browser sandbox after two Chromium runs: %d MiB in use (peak %d MiB of %d MiB); checkpoint %.1f MiB in %dms",
		st.MemoryBytes>>20, st.MemoryPeak>>20, st.MemoryLimit>>20, float64(ck.ImageBytes)/(1<<20), ck.DurationMs)
	forks, err := d.c.Fork(ctx, sb.ID, api.ForkRequest{Count: 2, Checkpoint: ck.ID})
	if err != nil {
		t.Fatalf("fork a browser sandbox: %v", err)
	}
	var cloneMem []string
	for _, f := range forks {
		fs, _ := d.c.Stats(ctx, f.ID)
		cloneMem = append(cloneMem, fmt.Sprintf("%d MiB", fs.MemoryBytes>>20))
		defer d.c.Destroy(ctx, f.ID)
	}
	t.Logf("OBSERVED: two clones of it: %s", strings.Join(cloneMem, ", "))
}

// Day 21 on real gVisor, the plan's done-when: an MCP client runs commands
// with state carried between calls, and pages through a long log. And, if
// the browser image exists, browse returns a page's text and screenshot.
//
// One daemon for all of it. (v1 started a second daemon on the same
// registry for the browser part; it reconciled the first daemon's live
// sandbox, failed to adopt it and destroyed it. sbxd now locks its registry
// and state directory, so that can't happen outside a test either.)
func TestIntegrationMCP(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rootfs := os.Getenv("SBX_BROWSER_ROOTFS")
	if rootfs == "" {
		rootfs = "/mnt/sbx/rootfs/browser-current"
		if _, err := os.Stat(rootfs); err != nil {
			rootfs = "/mnt/sbx/rootfs/browser"
		}
	}
	_, noBrowser := os.Stat(rootfs)
	free, _ := net.Listen("tcp4", "0.0.0.0:0")
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"), func(c *Config) {
		c.ProxyPort = port
		if noBrowser == nil {
			c.Images = map[string]Image{"browser": {Rootfs: rootfs, MemMiB: 2048, Network: true, Policy: proxy.PolicyBrowse}}
		}
	})
	defer d.stop()
	sb, err := d.c.Create(ctx, api.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.c.Destroy(ctx, sb.ID)
	s := startMCP(t, d.c, sb.ID, "")
	s.call("initialize", map[string]any{"protocolVersion": "2025-06-18"})

	start := time.Now()
	if got, _, _ := s.tool("shell", map[string]any{"command": "cd /tmp && mkdir -p work && cd work && export GREETING=hello && echo ready"}); got != "ready\n[exit code 0]" {
		t.Fatalf("first command: %q", got)
	}
	first := time.Since(start)
	start = time.Now()
	if got, _, _ := s.tool("shell", map[string]any{"command": "pwd; echo $GREETING"}); got != "/tmp/work\nhello\n[exit code 0]" {
		t.Fatalf("state between calls: %q", got)
	}
	t.Logf("OBSERVED: shell round trip: %s for the first call (opening the session), %s after", first.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))

	started, _, _ := s.tool("start_process", map[string]any{"command": "seq 1 200000", "cwd": "/tmp/work"})
	proc := strings.Fields(started)[2]
	var all strings.Builder
	offset, pages := 0, 0
	deadline := time.Now().Add(time.Minute)
	for {
		got, isErr, _ := s.tool("process_logs", map[string]any{"process_id": proc, "offset": offset, "limit": 100000})
		if isErr {
			t.Fatalf("process_logs: %s", got)
		}
		cut := strings.LastIndex(got, "\n[")
		all.WriteString(got[:cut])
		footer := got[cut:]
		pages++
		fmt.Sscanf(footer[strings.Index(footer, "next offset")+len("next offset "):], "%d", &offset)
		if strings.Contains(footer, "more follows") {
			continue
		}
		if strings.Contains(footer, "exited with code 0") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never finished: %q", footer)
		}
		time.Sleep(100 * time.Millisecond)
	}
	want, _ := exec.Command("seq", "1", "200000").Output()
	if all.String() != string(want) {
		t.Fatalf("the paged log: %d bytes, want %d", all.Len(), len(want))
	}
	t.Logf("OBSERVED: a %d-byte log paged in %d pages, joined exactly", all.Len(), pages)

	if noBrowser != nil {
		t.Logf("no browser image at %s: browse not tested", rootfs)
		return
	}
	if _, err := d.m.StartProxy(fmt.Sprintf("0.0.0.0:%d", port), nil); err != nil {
		t.Fatal(err)
	}
	bsb, err := d.c.Create(ctx, api.CreateRequest{Image: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.c.Destroy(ctx, bsb.ID)
	if rec, _ := d.c.Get(ctx, sb.ID); rec.State != api.Running {
		t.Errorf("the first sandbox should still be running: %s", rec.State)
	}
	bs := startMCP(t, d.c, bsb.ID, "")
	start = time.Now()
	got, isErr, content := bs.tool("browse", map[string]any{"url": "https://example.com", "screenshot": true})
	images := 0
	for _, c := range content {
		if c.Type == "image" {
			images++
		}
	}
	if isErr || !strings.HasPrefix(got, "Example Domain") || images != 1 {
		t.Fatalf("browse example.com: %q, %d images", got, images)
	}
	t.Logf("OBSERVED: browse with a screenshot in %s: %q…", time.Since(start).Round(time.Millisecond), strings.SplitN(got, "\n", 2)[0])
	got, _, _ = bs.tool("browse", map[string]any{"url": "https://169.254.169.254/"})
	t.Logf("OBSERVED: browse of the metadata address: %s", strings.SplitN(got, "\n", 2)[0])
	if strings.Contains(got, "(HTTP 200)") {
		t.Errorf("the metadata address answered: %q", got)
	}
}

// Day 22 on real gVisor: with sbx-mcp connected, the sandbox falls asleep
// when idle (the shell is detached between commands), wakes for the next
// command, and the shell's state survives the sleep: the session is
// reattached, not replaced. And what detaching costs per command.
func TestIntegrationMCPSleepAndWake(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"))
	defer d.stop()
	sb, err := d.c.Create(ctx, api.CreateRequest{IdleTimeoutS: 2, IdleAction: api.IdlePause})
	if err != nil {
		t.Fatal(err)
	}
	defer d.c.Destroy(ctx, sb.ID)
	s := startMCP(t, d.c, sb.ID, "")
	if got, _, _ := s.tool("shell", map[string]any{"command": "mkdir -p /tmp/proj && cd /tmp/proj && export STAGE=two && echo ready"}); got != "ready\n[exit code 0]" {
		t.Fatalf("setup: %q", got)
	}
	var awake []time.Duration
	for i := 0; i < 5; i++ {
		start := time.Now()
		s.tool("shell", map[string]any{"command": "true"})
		awake = append(awake, time.Since(start))
	}
	t.Logf("OBSERVED: a shell call while awake (reattach, sync, run, detach): %v", awake)

	deadline := time.Now().Add(30 * time.Second)
	for {
		rec, _ := d.c.Get(ctx, sb.ID)
		if rec.State == api.Paused {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("with sbx-mcp connected, the sandbox never fell asleep: %s", rec.State)
		}
		time.Sleep(200 * time.Millisecond)
	}
	start := time.Now()
	got, isErr, _ := s.tool("shell", map[string]any{"command": "pwd; echo $STAGE"})
	t.Logf("OBSERVED: the sandbox fell asleep with sbx-mcp connected; the next command woke it and answered in %s: %q",
		time.Since(start).Round(time.Millisecond), got)
	if isErr || got != "/tmp/proj\ntwo\n[exit code 0]" {
		t.Fatalf("after sleeping, the shell should keep its directory and variables, with no notice of a new session: %q", got)
	}
}

// The S3 snapshot store on real gVisor, the done-when: checkpoint → upload
// → delete local files → download → restore → exec. A counting process and
// a file must survive the trip. Needs an S3 server: SBX_S3_ENDPOINT,
// SBX_S3_ACCESS_KEY, SBX_S3_SECRET_KEY (scripts/s3-local.sh runs one).
func TestIntegrationSnapshotStore(t *testing.T) {
	ep := os.Getenv("SBX_S3_ENDPOINT")
	if ep == "" {
		t.Skip("no S3 server: run scripts/s3-local.sh, then set SBX_S3_ENDPOINT, SBX_S3_ACCESS_KEY, SBX_S3_SECRET_KEY")
	}
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	bucket := os.Getenv("SBX_S3_BUCKET")
	if bucket == "" {
		bucket = "sbx-it"
	}
	c := &s3.Client{Endpoint: ep, AccessKey: os.Getenv("SBX_S3_ACCESS_KEY"), SecretKey: os.Getenv("SBX_S3_SECRET_KEY")}
	if err := c.MakeBucket(ctx, bucket); err != nil {
		t.Fatal(err)
	}
	st := &store.S3{Client: c, Bucket: bucket, Prefix: fmt.Sprintf("it-%d/", time.Now().UnixNano())}
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"), func(cfg *Config) { cfg.Store, cfg.StoreEvict = st, true })
	defer d.stop()
	sb, err := d.c.Create(ctx, api.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.c.Destroy(ctx, sb.ID)
	if _, err := d.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "echo travelled > /tmp/proof"}}); err != nil {
		t.Fatal(err)
	}
	proc, err := d.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"sh", "-c", "i=0; while :; do i=$((i+1)); echo $i; sleep 0.2; done"}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)

	start := time.Now()
	ck, err := d.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{})
	if err != nil {
		t.Fatalf("pause to the store: %v", err)
	}
	paused := time.Since(start)
	cks, _ := d.c.Checkpoints(ctx, sb.ID)
	if cks[0].Local || !cks[0].Remote {
		t.Fatalf("after the pause: local=%v remote=%v (want the store only)", cks[0].Local, cks[0].Remote)
	}
	if _, err := os.Stat(ck.Path); !os.IsNotExist(err) {
		t.Fatalf("the local copy should be gone: %v", err)
	}
	start = time.Now()
	if _, err := d.c.Resume(ctx, sb.ID, ""); err != nil {
		t.Fatalf("resume from the store: %v", err)
	}
	resumed := time.Since(start)
	var out strings.Builder
	if _, err := d.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"cat", "/tmp/proof"}, Stdout: &out}); err != nil || out.String() != "travelled\n" {
		t.Fatalf("the file after the trip: %q %v", out.String(), err)
	}
	var logs strings.Builder
	_, _ = d.c.Logs(ctx, sb.ID, proc.ID, 0, false, &logs)
	lines := strings.Fields(logs.String())
	for i, l := range lines {
		if l != fmt.Sprint(i+1) {
			t.Fatalf("the counter should run unbroken through the trip: %v", lines)
		}
	}
	evs, _ := d.c.Events(ctx, sb.ID)
	var notes []string
	for _, ev := range evs {
		if strings.HasPrefix(ev.Detail, "uploaded ") || strings.HasPrefix(ev.Detail, "fetched ") {
			notes = append(notes, ev.Detail)
		}
	}
	t.Logf("OBSERVED: image %.1f MiB; the pause, upload included, took %s; %s", float64(ck.ImageBytes)/(1<<20), paused.Round(time.Millisecond), strings.Join(notes, "; "))
	t.Logf("OBSERVED: the resume, fetch included, took %s; the counter reached %d, unbroken", resumed.Round(time.Millisecond), len(lines))
}

// Day 23 on real gVisor: a sandbox holding more than half its memory limit
// must survive being paused, round after round. The benchmark found that a
// checkpoint written through the page cache is charged to the sandbox's own
// memory limit: at 128 of 256 MiB, the fifth pause got the sandbox's kernel
// killed for memory. Checkpoint images now use O_DIRECT when runsc has it.
// Then the same with buffered checkpoints, as a control: logged, not
// asserted, since when an out-of-memory kill strikes isn't deterministic.
func TestIntegrationCheckpointNearTheLimit(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	const touched, rounds = 144, 8 // MiB, of a 256 MiB limit
	hog := []string{"python3", "-c", fmt.Sprintf("import time\nb = bytearray(%d << 20)\nfor i in range(0, len(b), 4096): b[i] = 1\nprint('ready', flush=True)\ntime.sleep(1e9)", touched)}
	run := func(name string, buffered bool) (completed int, err error) {
		d := e.daemon(t, filepath.Join(e.dir, name+".sock"), func(c *Config) {
			if buffered {
				c.Backend.(*gvisor.Backend).SetCheckpointIO("buffered")
			} // else the default, auto: 144 of 256 MiB is over 40%, so direct
		})
		defer d.stop()
		sb, err := d.c.Create(ctx, api.CreateRequest{MemMiB: 256})
		if err != nil {
			return 0, err
		}
		defer d.c.Destroy(ctx, sb.ID)
		p, err := d.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: hog})
		if err != nil {
			return 0, err
		}
		for deadline := time.Now().Add(60 * time.Second); ; {
			var out strings.Builder
			_, _ = d.c.Logs(ctx, sb.ID, p.ID, 0, false, &out)
			if strings.Contains(out.String(), "ready") {
				break
			}
			if time.Now().After(deadline) {
				return 0, fmt.Errorf("the workload never got ready: %q", out.String())
			}
			time.Sleep(200 * time.Millisecond)
		}
		ck, rs := d.b.DirectIO()
		t.Logf("%s: checkpoint O_DIRECT %v, restore O_DIRECT %v", name, ck, rs)
		for i := 0; i < rounds; i++ {
			if _, err := d.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{}); err != nil {
				return i, fmt.Errorf("pause %d: %w", i+1, err)
			}
			if _, err := d.c.Resume(ctx, sb.ID, ""); err != nil {
				return i, fmt.Errorf("resume %d: %w", i+1, err)
			}
		}
		var out strings.Builder
		if _, err := d.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"echo", "alive"}, Stdout: &out}); err != nil || out.String() != "alive\n" {
			return rounds, fmt.Errorf("after %d rounds: %q %v", rounds, out.String(), err)
		}
		return rounds, nil
	}
	if n, err := run("direct", false); err != nil {
		t.Fatalf("holding %d of 256 MiB, %d of %d pause-resume rounds, then: %v", touched, n, rounds, err)
	}
	t.Logf("OBSERVED: holding %d of 256 MiB: %d pause-resume rounds, all fine", touched, rounds)
	n, err := run("buffered", true)
	t.Logf("OBSERVED: the control, buffered checkpoints: %d of %d rounds; %v", n, rounds, err)
}

// Port forwarding on real gVisor: servers an agent started in a sandbox
// with no network at all, reached from the host. One listens on localhost
// alone, one on IPv6's loopback alone (gVisor's netstack has it whether or
// not the host does). Both are listed with their processes, from gVisor's
// own socket tables. Then the sandbox falls asleep, and a request wakes it
// and is answered by the server restored from its checkpoint.
func TestIntegrationPortForwarding(t *testing.T) {
	e := itSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := e.daemon(t, filepath.Join(e.dir, "a.sock"), func(c *Config) { c.LifetimeEvery = 200 * time.Millisecond })
	defer d.stop()
	sb, err := d.c.Create(ctx, api.CreateRequest{IdleTimeoutS: 2, IdleAction: api.IdlePause})
	if err != nil {
		t.Fatal(err)
	}
	defer d.c.Destroy(ctx, sb.ID)
	if _, err := d.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "mkdir -p /tmp/site && echo made-in-the-sandbox > /tmp/site/index.html"}}); err != nil {
		t.Fatal(err)
	}
	for port, bind := range map[string]string{"8000": "127.0.0.1", "8001": "::1"} {
		if _, err := d.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"python3", "-m", "http.server", port, "--bind", bind}, Dir: "/tmp/site"}); err != nil {
			t.Fatal(err)
		}
	}
	listens := func(list api.PortList, port int, addr string) bool {
		for _, p := range list.Ports {
			if p.Port == port && p.Addr == addr {
				return true
			}
		}
		return false
	}
	var list api.PortList
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		list, err = d.c.Ports(ctx, sb.ID)
		if err == nil && listens(list, 8000, "127.0.0.1") && listens(list, 8001, "::1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the servers never showed up listening: %+v %v", list, err)
		}
	}
	for _, p := range list.Ports {
		if p.PID <= 0 || !strings.Contains(p.Command, "http.server") {
			t.Errorf("gVisor's socket tables should name the process holding each port: %+v", p)
		}
	}

	browser := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Minute}
	forwarded := func(port int) string {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go d.c.ServePort(ln, sb.ID, port, nil)
		return "http://" + ln.Addr().String() + "/"
	}
	fetch := func(url string) (string, time.Duration) {
		start := time.Now()
		resp, err := browser.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(b)), time.Since(start)
	}
	url4, url6 := forwarded(8000), forwarded(8001)
	got, took := fetch(url4)
	if got != "made-in-the-sandbox" {
		t.Fatalf("the server on localhost alone: %q", got)
	}
	if got, _ := fetch(url6); got != "made-in-the-sandbox" {
		t.Fatalf("the server on ::1 alone: %q", got)
	}
	t.Logf("OBSERVED: a page through the forward, awake: %s", took.Round(time.Millisecond))
	if _, err := d.c.DialPort(ctx, sb.ID, 9); !errors.Is(err, client.ErrRefused) {
		t.Fatalf("a port nothing listens on: want ErrRefused, got %v", err)
	}

	idle := time.Now()
	for {
		rec, _ := d.c.Get(ctx, sb.ID)
		if rec.State == api.Paused {
			break
		}
		if time.Since(idle) > 30*time.Second {
			t.Fatalf("with no connection open, the sandbox never fell asleep: %s", rec.State)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("OBSERVED: asleep %s after the last request (idle timeout 2 s)", time.Since(idle).Round(100*time.Millisecond))
	got, took = fetch(url4)
	if got != "made-in-the-sandbox" {
		t.Fatalf("after the sandbox slept: %q", got)
	}
	if rec, _ := d.c.Get(ctx, sb.ID); rec.State != api.Running {
		t.Fatalf("the request should have woken it: %s", rec.State)
	}
	t.Logf("OBSERVED: a request to the sleeping sandbox woke it, and its restored server answered, in %s", took.Round(time.Millisecond))
}
