package gvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/agent"
	"github.com/Crpedeim/sbx/internal/guest"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

// TestHelperRunsc is not a real test. When SBX_FAKE_RUNSC is set, the test
// binary re-runs itself as a fake runsc that keeps each sandbox's status in a
// file under --root. Modes:
//
//	normal:     behaves like runsc
//	stubborn:   ignores SIGTERM, like a sandbox whose init won't exit
//	failcreate: `run` fails with an error message
//	failcheckpoint: `checkpoint` fails, leaving the sandbox running
//	failrestore: `restore` fails
func TestHelperRunsc(t *testing.T) {
	mode := os.Getenv("SBX_FAKE_RUNSC")
	if mode == "" {
		return
	}
	os.Exit(fakeRunsc(mode, argsAfterDashes()))
}

func argsAfterDashes() []string {
	for i, a := range os.Args {
		if a == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}

func fakeRunsc(mode string, args []string) int {
	all := strings.Join(args, " ")
	var root string
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		switch args[0] {
		case "--root":
			root, args = args[1], args[2:]
		case "--network", "--platform", "--host-uds":
			args = args[2:]
		default:
			args = args[1:]
		}
	}
	// `runsc list`, in runsc's columns, from the stand-in's state files.
	if root != "" && len(args) == 1 && args[0] == "list" {
		fmt.Println("ID  PID  STATUS  BUNDLE  CREATED  OWNER")
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if strings.Contains(e.Name(), ".") || e.IsDir() {
				continue
			}
			st, _ := os.ReadFile(filepath.Join(root, e.Name()))
			pid, _ := os.ReadFile(filepath.Join(root, e.Name()+".pid"))
			if len(pid) == 0 {
				pid = []byte("0")
			}
			fmt.Printf("%s  %s  %s  -  -  root\n", e.Name(), pid, st)
		}
		return 0
	}
	if root == "" || len(args) < 2 {
		fmt.Fprintln(os.Stderr, "fake runsc: bad arguments")
		return 2
	}
	_ = os.MkdirAll(root, 0o755)
	sub, rest := args[0], args[1:]
	// `runsc checkpoint --help` / `restore --help`: list -direct only in the
	// mode for a runsc that has it (Day 23 asks runsc, not its version).
	if len(rest) == 1 && rest[0] == "--help" {
		fmt.Fprintln(os.Stderr, "Usage: "+sub+" [flags] <container id>")
		if mode == "hasdirect" {
			fmt.Fprintln(os.Stderr, "  -direct\n    \tuse O_DIRECT for the checkpoint pages file")
		}
		fmt.Fprintln(os.Stderr, "  -image-path string\n    \tdirectory path to saved container image")
		return 0
	}
	id := rest[len(rest)-1]
	if sub == "exec" || sub == "kill" || sub == "state" {
		id = rest[0]
	} // delete takes flags first (delete --force <id>), so its ID is the last argument
	statePath := filepath.Join(root, id)
	status := func() string { b, _ := os.ReadFile(statePath); return string(b) }
	setStatus := func(s string) { _ = os.WriteFile(statePath, []byte(s), 0o644) }

	switch sub {
	case "run":
		if mode == "failcreate" {
			fmt.Fprintln(os.Stderr, "creating container: cannot read rootfs: permission denied")
			return 1
		}
		var bundle string
		for i := 0; i+1 < len(rest); i++ {
			if rest[i] == "--bundle" {
				bundle = rest[i+1]
			}
		}
		raw, err := os.ReadFile(filepath.Join(bundle, "config.json"))
		var spec ociSpec
		if err != nil || json.Unmarshal(raw, &spec) != nil || spec.Root.Path == "" {
			fmt.Fprintln(os.Stderr, "bad bundle")
			return 1
		}
		_ = os.WriteFile(statePath+".args", []byte(all), 0o644)
		setStatus("running")
		return 0
	case "state":
		if mode == "flakystate" { // a busy runsc: the call fails, saying nothing about the sandbox
			fmt.Fprintln(os.Stderr, "runsc: waiting for the sandbox's state: connection timed out")
			return 1
		}
		st := status()
		if st == "" {
			fmt.Fprintf(os.Stderr, "loading container %q: file does not exist\n", id)
			return 1
		}
		pid := 0
		if b, err := os.ReadFile(statePath + ".pid"); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		fmt.Printf(`{"id":%q,"status":%q,"pid":%d}`+"\n", id, st, pid)
		return 0
	case "exec":
		if status() != "running" {
			fmt.Fprintln(os.Stderr, "container is not running")
			return 1
		}
		cmd := rest[1:]
		fmt.Println("ran:", strings.Join(cmd, " "))
		if cmd[0] == "exit" && len(cmd) > 1 {
			code, _ := strconv.Atoi(cmd[1])
			return code
		}
		return 0
	case "kill":
		if mode == "stubborn" && rest[1] == "TERM" {
			return 0
		}
		setStatus("stopped")
		return 0
	case "delete":
		_ = os.Remove(statePath)
		return 0
	case "restore":
		if mode == "failrestore" {
			fmt.Fprintln(os.Stderr, "restore failed: the image doesn't match this runsc")
			return 1
		}
		var dir string
		for _, a := range rest {
			if v, ok := strings.CutPrefix(a, "--image-path="); ok {
				dir = v
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "checkpoint.img")); err != nil {
			fmt.Fprintln(os.Stderr, "fake runsc: restore needs an --image-path with an image")
			return 1
		}
		if status() == "running" {
			fmt.Fprintln(os.Stderr, "fake runsc: container already exists")
			return 1
		}
		_ = os.WriteFile(statePath+".args", []byte(all), 0o644) // as run does
		setStatus("running")
		return 0
	case "checkpoint":
		if mode == "failcheckpoint" {
			fmt.Fprintln(os.Stderr, "checkpoint failed: something inside can't be saved")
			return 1
		}
		var dir string
		leave := false
		for _, a := range rest {
			if v, ok := strings.CutPrefix(a, "--image-path="); ok {
				dir = v
			}
			leave = leave || a == "--leave-running"
		}
		if dir == "" || status() != "running" {
			fmt.Fprintln(os.Stderr, "fake runsc: checkpoint needs --image-path and a running sandbox")
			return 1
		}
		_ = os.WriteFile(statePath+".ckargs", []byte(all), 0o644)
		// A stand-in image: real ones hold the sandbox's memory and state.
		_ = os.WriteFile(filepath.Join(dir, "checkpoint.img"), bytes.Repeat([]byte("state"), 4096), 0o600)
		if !leave && mode != "lingers" { // lingers: the sandbox doesn't stop after its checkpoint
			setStatus("stopped")
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "fake runsc: unknown subcommand", sub)
	return 2
}

func newFake(t *testing.T, mode string) (*Backend, string) {
	t.Helper()
	t.Setenv("SBX_FAKE_RUNSC", mode)
	state := t.TempDir()
	b, err := New(Config{RunscPath: os.Args[0], StateDir: state, PollEvery: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	b.cfg.prefixArgs = []string{"-test.run=TestHelperRunsc", "--"}
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	return b, rootfs
}

func waitExited(t *testing.T, sb sandbox.Sandbox) {
	t.Helper()
	select {
	case <-sb.Exited():
	case <-time.After(2 * time.Second):
		t.Fatal("Exited() not closed")
	}
}

func TestLifecycle(t *testing.T) {
	b, rootfs := newFake(t, "normal")
	ctx := context.Background()
	sb, err := b.Create(ctx, sandbox.Spec{ID: "demo", Rootfs: rootfs, VCPUs: 1, MemMiB: 256})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var out bytes.Buffer
	res, err := sb.Exec(ctx, sandbox.ExecRequest{Args: []string{"echo", "hi"}, Stdout: &out})
	if err != nil || res.ExitCode != 0 || !strings.Contains(out.String(), "ran: echo hi") {
		t.Fatalf("exec: res=%+v err=%v out=%q", res, err, out.String())
	}

	res, err = sb.Exec(ctx, sandbox.ExecRequest{Args: []string{"exit", "3"}, Stdout: &out})
	if err != nil || res.ExitCode != 3 {
		t.Fatalf("non-zero exit should be a result, not an error: res=%+v err=%v", res, err)
	}

	if err := sb.Shutdown(ctx, time.Second); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	waitExited(t, sb)
	if _, err := os.Stat(filepath.Join(b.cfg.StateDir, "bundles", "demo")); !os.IsNotExist(err) {
		t.Error("bundle left behind")
	}
	if _, err := os.Stat(filepath.Join(b.cfg.StateDir, "runsc", "demo")); !os.IsNotExist(err) {
		t.Error("runsc state left behind (delete not called)")
	}
	if _, err := sb.Exec(ctx, sandbox.ExecRequest{Args: []string{"true"}}); !errors.Is(err, sandbox.ErrExited) {
		t.Errorf("exec after shutdown: want ErrExited, got %v", err)
	}
}

func TestShutdownKillsStubbornSandbox(t *testing.T) {
	b, rootfs := newFake(t, "stubborn")
	sb, err := b.Create(context.Background(), sandbox.Spec{ID: "stubborn", Rootfs: rootfs})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	err = sb.Shutdown(context.Background(), 150*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "ignored SIGTERM") {
		t.Fatalf("want ignored-SIGTERM error, got %v", err)
	}
	waitExited(t, sb)
}

func TestCreateFailureCarriesRunscMessage(t *testing.T) {
	b, rootfs := newFake(t, "failcreate")
	_, err := b.Create(context.Background(), sandbox.Spec{ID: "broken", Rootfs: rootfs})
	if err == nil || !strings.Contains(err.Error(), "cannot read rootfs") {
		t.Fatalf("want runsc's message in the error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.cfg.StateDir, "bundles", "broken")); !os.IsNotExist(err) {
		t.Error("bundle left behind after failed create")
	}
}

func TestCreateValidatesInput(t *testing.T) {
	b, rootfs := newFake(t, "normal")
	ctx := context.Background()
	if _, err := b.Create(ctx, sandbox.Spec{ID: "../escape", Rootfs: rootfs}); err == nil {
		t.Error("accepted a path-traversal id")
	}
	file := filepath.Join(t.TempDir(), "image.ext4")
	_ = os.WriteFile(file, nil, 0o644)
	if _, err := b.Create(ctx, sandbox.Spec{ID: "img", Rootfs: file}); err == nil {
		t.Error("accepted a file as gVisor rootfs")
	}
	if _, err := New(Config{StateDir: "relative/dir"}); err == nil {
		t.Error("accepted a relative state dir")
	}
}

func TestBuildSpec(t *testing.T) {
	s := sandbox.Spec{ID: "x", VCPUs: 2, MemMiB: 512, PidsMax: 64}

	limited := buildSpec(s, "/rootfs", limits{cgroupPath: "/sbx/x", cpus: "2,3"}, "")
	if limited.Root.Path != "/rootfs" || limited.Hostname != "sbx-x" {
		t.Errorf("root/hostname wrong: %+v %q", limited.Root, limited.Hostname)
	}
	if got := strings.Join(limited.Process.Args, " "); got != "sleep infinity" {
		t.Errorf("init args = %q", got)
	}
	// Day 1 forgot this line, and runsc ignored every limit without it.
	if limited.Linux.CgroupsPath != "/sbx/x" {
		t.Errorf("cgroupsPath = %q: without it, runsc applies no limits", limited.Linux.CgroupsPath)
	}
	r := limited.Linux.Resources
	if r == nil || r.Memory.Limit != 512<<20 || r.Memory.Swap == nil || *r.Memory.Swap != 512<<20 {
		t.Errorf("memory limit or swap wrong: %+v", r)
	}
	if r.CPU.Quota != 2*cpuPeriod || r.CPU.Period != cpuPeriod || r.CPU.Cpus != "2,3" {
		t.Errorf("cpu wrong: %+v", r.CPU)
	}
	// 64 processes inside; the host limit is the safety net above it.
	if r.Pids == nil || r.Pids.Limit != 64+3*64 {
		t.Errorf("host pids limit: %+v, want %d", r.Pids, 64+3*64)
	}
	withAgent := buildSpec(s, "/rootfs", limits{cgroupPath: "/sbx/x"}, "/agentdir")
	if got := strings.Join(withAgent.Process.Args, " "); !strings.HasSuffix(got, "-child-nproc 64") {
		t.Errorf("agent args %q: the process limit goes to the agent", got)
	}
	hasNetNS := false
	for _, ns := range limited.Linux.Namespaces {
		hasNetNS = hasNetNS || ns.Type == "network"
	}
	if !hasNetNS {
		t.Error("missing network namespace")
	}

	rootless := buildSpec(s, "/rootfs", limits{}, "")
	if rootless.Linux.Resources != nil || rootless.Linux.CgroupsPath != "" {
		t.Error("rootless spec must not carry cgroup limits")
	}
	rootlessAgent := buildSpec(s, "/rootfs", limits{}, "/agentdir")
	if got := strings.Join(rootlessAgent.Process.Args, " "); !strings.HasSuffix(got, "-child-nproc 64") {
		t.Errorf("the process limit needs no cgroup: rootless keeps it (%q)", got)
	}
	if _, err := json.Marshal(limited); err != nil {
		t.Fatal(err)
	}
}

func TestCPUsAreSpreadRoundRobin(t *testing.T) {
	b, _ := newFake(t, "normal")
	b.hostCPUs = func() int { return 4 }
	got := []string{b.cpusFor(1), b.cpusFor(1), b.cpusFor(2), b.cpusFor(1), b.cpusFor(1)}
	want := []string{"0", "1", "2,3", "0", "1"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("cpusets %q, want %q", got, want)
	}
	if b.cpusFor(4) != "" || b.cpusFor(0) != "" {
		t.Error("a sandbox with all (or unspecified) CPUs needs no cpuset")
	}
}

// fakeCgroup builds what the kernel would show for pid: /proc/<pid>/cgroup
// naming the cgroup, and that cgroup's control files.
func fakeCgroup(t *testing.T, pid int, path string, files map[string]string) (procRoot, cgRoot string) {
	t.Helper()
	procRoot, cgRoot = t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, strconv.Itoa(pid)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"), []byte("0::"+path+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cgRoot, path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return procRoot, cgRoot
}

// Real cgroup v2 file contents, as the kernel formats them.
var sampleCgroup = map[string]string{
	"memory.current":        "104857600\n",
	"memory.peak":           "209715200\n",
	"memory.max":            "268435456\n",
	"memory.events":         "low 0\nhigh 0\nmax 12\noom 1\noom_kill 1\noom_group_kill 0\n",
	"cpu.stat":              "usage_usec 2500000\nuser_usec 2000000\nsystem_usec 500000\nnr_periods 40\nnr_throttled 9\nthrottled_usec 450000\n",
	"cpu.max":               "100000 100000\n",
	"cpuset.cpus.effective": "1\n",
	"pids.current":          "23\n",
	"pids.max":              "256\n",
}

func TestReadStatsFromACgroupV2Tree(t *testing.T) {
	procRoot, cgRoot := fakeCgroup(t, 4242, "/sbx/x", sampleCgroup)
	cg := cgroupFS{procRoot: procRoot, cgRoot: cgRoot}
	path, err := cg.pathOf(4242)
	if err != nil || path != "/sbx/x" {
		t.Fatalf("pathOf: %q %v", path, err)
	}
	st, err := readStats(cg.dir(path), path)
	if err != nil {
		t.Fatal(err)
	}
	want := sandbox.Stats{
		Cgroup: "/sbx/x", MemoryBytes: 100 << 20, MemoryPeak: 200 << 20, MemoryLimit: 256 << 20, OOMKills: 1,
		CPUUsage: 2500 * time.Millisecond, CPUThrottled: 450 * time.Millisecond, ThrottledPeriods: 9,
		CPUQuota: 1, CPUs: "1", Pids: 23, PidsLimit: 256,
	}
	if st != want {
		t.Fatalf("stats\n got %+v\nwant %+v", st, want)
	}
}

func TestUnlimitedAndMissingFiles(t *testing.T) {
	files := map[string]string{"memory.current": "1\n", "memory.max": "max\n", "cpu.max": "max 100000\n", "pids.max": "max\n"}
	procRoot, cgRoot := fakeCgroup(t, 7, "/sbx/y", files)
	cg := cgroupFS{procRoot: procRoot, cgRoot: cgRoot}
	st, err := readStats(cg.dir("/sbx/y"), "/sbx/y")
	if err != nil {
		t.Fatal(err)
	}
	// "max" means unlimited (0); files an older kernel lacks (memory.peak)
	// are simply absent, not errors.
	if st.MemoryLimit != 0 || st.CPUQuota != 0 || st.PidsLimit != 0 || st.MemoryPeak != 0 || st.MemoryBytes != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestCgroupV1HostIsReportedClearly(t *testing.T) {
	procRoot := t.TempDir()
	_ = os.MkdirAll(filepath.Join(procRoot, "9"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "9", "cgroup"), []byte("4:memory:/x\n1:cpu:/x\n"), 0o644)
	_, err := cgroupFS{procRoot: procRoot}.pathOf(9)
	if err == nil || !strings.Contains(err.Error(), "cgroup v1") {
		t.Fatalf("want a clear cgroup v1 error, got %v", err)
	}
}

func TestExitReasons(t *testing.T) {
	_, cgRoot := fakeCgroup(t, 1, "/sbx/z", map[string]string{"memory.events": "oom 1\noom_kill 1\n", "memory.max": "268435456\n"})
	if r := exitReason(filepath.Join(cgRoot, "sbx", "z")); !strings.Contains(r, "out-of-memory") || !strings.Contains(r, "256 MiB") {
		t.Fatalf("oom reason %q", r)
	}
	// Day 8's second finding: a low pids.max ends the whole sandbox. Either
	// counter is enough evidence.
	_, cgRoot = fakeCgroup(t, 1, "/sbx/z", map[string]string{"memory.events": "oom_kill 0\n", "pids.events": "max 37\n", "pids.max": "64\n"})
	if r := exitReason(filepath.Join(cgRoot, "sbx", "z")); !strings.Contains(r, "host thread limit") || !strings.Contains(r, "64") {
		t.Fatalf("pids.events reason %q", r)
	}
	_, cgRoot = fakeCgroup(t, 1, "/sbx/z", map[string]string{"pids.events": "max 0\n", "pids.peak": "64\n", "pids.max": "64\n"})
	if r := exitReason(filepath.Join(cgRoot, "sbx", "z")); !strings.Contains(r, "host thread limit") {
		t.Fatalf("pids.peak reason %q", r)
	}
	_, cgRoot = fakeCgroup(t, 1, "/sbx/z", map[string]string{"memory.events": "oom 0\noom_kill 0\n", "pids.events": "max 0\n"})
	if r := exitReason(filepath.Join(cgRoot, "sbx", "z")); r != "" {
		t.Fatalf("no limit hit, yet reason %q", r)
	}
}

// Day 8's real failure: the sandbox died at its host thread limit, but the
// cgroup's counters said nothing. The watcher's own samples must still
// explain it.
func TestThreadLimitDeathExplainedFromSamples(t *testing.T) {
	b, rootfs := newFake(t, "normal")
	files := map[string]string{"memory.events": "oom_kill 0\n", "pids.events": "max 0\n", "pids.current": "63\n", "pids.max": "64\n"}
	procRoot, cgRoot := fakeCgroup(t, 4444, "/sbx/bomb", files)
	b.cfg.ProcRoot, b.cfg.CgroupRoot = procRoot, cgRoot
	b.cg = cgroupFS{procRoot: procRoot, cgRoot: cgRoot}
	sb, err := b.Create(context.Background(), sandbox.Spec{ID: "bomb", Rootfs: rootfs})
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(b.cfg.StateDir, "runsc", "bomb")
	_ = os.WriteFile(statePath+".pid", []byte("4444"), 0o644)
	// Wait for the watcher to sample 63 of 64 (not a fixed sleep: under the
	// race detector each fake runsc call is slow, and a guess can be short).
	inner := sb.(*Sandbox)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		inner.mu.Lock()
		sampled := inner.lastPids == 63
		inner.mu.Unlock()
		if sampled {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The sandbox dies, and its cgroup vanishes with it: no counters left.
	_ = os.RemoveAll(filepath.Join(cgRoot, "sbx", "bomb"))
	_ = os.WriteFile(statePath, []byte("stopped"), 0o644)
	select {
	case <-sb.Exited():
	case <-time.After(3 * time.Second):
		t.Fatal("exit not noticed")
	}
	if r := sb.(sandbox.ExitReasoner).ExitReason(); !strings.Contains(r, "host thread limit") || !strings.Contains(r, "63") {
		t.Fatalf("reason %q", r)
	}
}

// When the backend learns a sandbox's cgroup, it sets memory.high to 90%
// of the limit: the kernel starts throttling there, buying the memory
// guard time before memory.max.
func TestMemoryHighIsSetWhenTheCgroupIsLearned(t *testing.T) {
	b, rootfs := newFake(t, "normal")
	procRoot, cgRoot := fakeCgroup(t, 4343, "/sbx/hi", sampleCgroup)
	b.cfg.ProcRoot, b.cfg.CgroupRoot = procRoot, cgRoot
	b.cg = cgroupFS{procRoot: procRoot, cgRoot: cgRoot}
	sb, err := b.Create(context.Background(), sandbox.Spec{ID: "hi", Rootfs: rootfs, MemMiB: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Shutdown(context.Background(), time.Second)
	_ = os.WriteFile(filepath.Join(b.cfg.StateDir, "runsc", "hi.pid"), []byte("4343"), 0o644)
	limit := float64(256 << 20) // a variable: truncated at run time, as the backend does
	want := strconv.FormatInt(int64(limit*memoryHighFraction), 10)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := os.ReadFile(filepath.Join(cgRoot, "sbx", "hi", "memory.high")); string(got) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := os.ReadFile(filepath.Join(cgRoot, "sbx", "hi", "memory.high"))
	t.Fatalf("memory.high = %q, want %s", got, want)
}

// The whole path through the backend: runsc state gives the PID, the PID
// gives the cgroup, the cgroup gives the stats; and when the sandbox dies
// after an OOM kill, it says so.
func TestStatsAndOOMExitThroughTheBackend(t *testing.T) {
	b, rootfs := newFake(t, "normal")
	procRoot, cgRoot := fakeCgroup(t, 4242, "/sbx/oomy", sampleCgroup)
	b.cfg.ProcRoot, b.cfg.CgroupRoot = procRoot, cgRoot
	b.cg = cgroupFS{procRoot: procRoot, cgRoot: cgRoot}
	ctx := context.Background()
	sb, err := b.Create(ctx, sandbox.Spec{ID: "oomy", Rootfs: rootfs, MemMiB: 256})
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(b.cfg.StateDir, "runsc", "oomy")
	_ = os.WriteFile(statePath+".pid", []byte("4242"), 0o644) // the fake runsc reports it

	st, err := sb.Stats(ctx)
	if err != nil || st.Cgroup != "/sbx/oomy" || st.MemoryLimit != 256<<20 || st.Pids != 23 {
		t.Fatalf("stats: %+v %v", st, err)
	}
	// The sandbox stops on its own; its cgroup recorded an OOM kill.
	_ = os.WriteFile(statePath, []byte("stopped"), 0o644)
	select {
	case <-sb.Exited():
	case <-time.After(3 * time.Second):
		t.Fatal("exit not noticed")
	}
	r, ok := sb.(sandbox.ExitReasoner)
	if !ok || !strings.Contains(r.ExitReason(), "out-of-memory") {
		t.Fatalf("exit reason %q", r.ExitReason())
	}
	if _, err := sb.Stats(ctx); !errors.Is(err, sandbox.ErrExited) {
		t.Fatalf("stats after exit: want ErrExited, got %v", err)
	}
}

func newFakeWithAgent(t *testing.T) (*Backend, string) {
	t.Helper()
	agentBin := filepath.Join(t.TempDir(), "sbx-agent")
	if err := os.WriteFile(agentBin, []byte("#!fake agent\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SBX_FAKE_RUNSC", "normal")
	// Short state dir: the agent's Unix socket lives under it, and socket
	// paths are limited to about 108 bytes.
	state, err := os.MkdirTemp("", "sbxg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })
	b, err := New(Config{RunscPath: os.Args[0], StateDir: state, PollEvery: 20 * time.Millisecond, AgentPath: agentBin})
	if err != nil {
		t.Fatal(err)
	}
	b.cfg.prefixArgs = []string{"-test.run=TestHelperRunsc", "--"}
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	_ = os.Mkdir(rootfs, 0o755)
	return b, rootfs
}

func TestCreateWithAgentWiresEverything(t *testing.T) {
	b, rootfs := newFakeWithAgent(t)
	ctx := context.Background()
	sb, err := b.Create(ctx, sandbox.Spec{ID: "ag", Rootfs: rootfs})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	bundle := filepath.Join(b.cfg.StateDir, "bundles", "ag")

	// The agent binary is installed, executable, in the directory that gets mounted.
	fi, err := os.Stat(filepath.Join(bundle, "sbx", agentBinary))
	if err != nil || fi.Mode()&0o111 == 0 {
		t.Fatalf("agent binary not installed executable: %v %v", fi, err)
	}

	// The spec makes the agent init and mounts its directory read-only.
	raw, _ := os.ReadFile(filepath.Join(bundle, "config.json"))
	var spec ociSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(spec.Process.Args, " "); got != "/sbx/sbx-agent -id ag -dial unix:/sbx/agent.sock" {
		t.Errorf("init = %q", got)
	}
	var mounted bool
	for _, m := range spec.Mounts {
		if m.Destination == "/sbx" {
			mounted = m.Source == filepath.Join(bundle, "sbx") && strings.Join(m.Options, ",") == "bind,ro"
		}
	}
	if !mounted {
		t.Errorf("agent dir not bind-mounted read-only at /sbx: %+v", spec.Mounts)
	}

	// runsc was told to allow host Unix sockets.
	args, _ := os.ReadFile(filepath.Join(b.cfg.StateDir, "runsc", "ag.args"))
	if !strings.Contains(string(args), "--host-uds open") {
		t.Errorf("runsc run args missing --host-uds open: %s", args)
	}

	// Play the agent: dial the socket the sandbox would see as /sbx/agent.sock.
	gctx, stop := context.WithCancel(ctx)
	defer stop()
	go guest.Run(gctx, guest.Config{SandboxID: "ag", Dial: "unix:" + filepath.Join(bundle, "sbx", agentSocket), LogDir: t.TempDir(), Logf: t.Logf})

	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := sb.Agent(wctx)
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	if _, err := conn.Ping(wctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// With an agent, Exec must go through it, not `runsc exec`: the fake
	// runsc would answer "ran: ...", the agent really runs the command.
	var out bytes.Buffer
	res, err := sb.Exec(wctx, sandbox.ExecRequest{Args: []string{"sh", "-c", "echo via-agent; exit 5"}, Stdout: &out})
	if err != nil || res.ExitCode != 5 || out.String() != "via-agent\n" {
		t.Fatalf("exec through agent: res=%+v out=%q err=%v", res, out.String(), err)
	}

	if err := sb.Shutdown(ctx, time.Second); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case <-conn.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("agent connection still open after shutdown")
	}
	if _, err := os.Stat(bundle); !os.IsNotExist(err) {
		t.Error("bundle (with agent socket) left behind")
	}
}

func TestCreateWithoutAgent(t *testing.T) {
	b, rootfs := newFake(t, "normal")
	sb, err := b.Create(context.Background(), sandbox.Spec{ID: "plain", Rootfs: rootfs})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Shutdown(context.Background(), time.Second)
	if _, err := sb.Agent(context.Background()); !errors.Is(err, sandbox.ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
	args, _ := os.ReadFile(filepath.Join(b.cfg.StateDir, "runsc", "plain.args"))
	if strings.Contains(string(args), "--host-uds") {
		t.Errorf("host UDS access granted without an agent: %s", args)
	}
}

func TestNewRejectsMissingAgentBinary(t *testing.T) {
	if _, err := New(Config{StateDir: t.TempDir(), AgentPath: "/no/such/sbx-agent"}); err == nil {
		t.Fatal("accepted a missing agent binary")
	}
}

func TestRunscExecFallbackAppliesEnvAndDir(t *testing.T) {
	b, rootfs := newFake(t, "normal")
	ctx := context.Background()
	sb, err := b.Create(ctx, sandbox.Spec{ID: "fallback", Rootfs: rootfs})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Shutdown(ctx, time.Second)

	var out bytes.Buffer
	_, err = sb.Exec(ctx, sandbox.ExecRequest{
		Args: []string{"sh", "-c", "pwd"}, Dir: "/tmp", Env: []string{"FOO=bar"}, Stdout: &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "ran: env -C /tmp FOO=bar sh -c pwd" {
		t.Fatalf("runsc exec got %q", got)
	}
}

func TestFilesGoThroughAgent(t *testing.T) {
	b, rootfs := newFakeWithAgent(t)
	ctx := context.Background()
	sb, err := b.Create(ctx, sandbox.Spec{ID: "files", Rootfs: rootfs})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Shutdown(ctx, time.Second)
	bundle := filepath.Join(b.cfg.StateDir, "bundles", "files")
	gctx, stop := context.WithCancel(ctx)
	defer stop()
	go guest.Run(gctx, guest.Config{SandboxID: "files", Dial: "unix:" + filepath.Join(bundle, "sbx", agentSocket), LogDir: t.TempDir(), Logf: t.Logf})

	// The in-process agent runs on the host, so "sandbox paths" here are
	// host temp paths. Real sandbox paths are covered by the integration test.
	dir := t.TempDir()
	path := filepath.Join(dir, "note.txt")
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := sb.WriteFile(wctx, path, strings.NewReader("hello"), sandbox.WriteOptions{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var back bytes.Buffer
	if _, err := sb.ReadFile(wctx, path, &back); err != nil || back.String() != "hello" {
		t.Fatalf("read: %q %v", back.String(), err)
	}
	res, err := sb.ListDir(wctx, dir)
	if err != nil || len(res.Entries) != 1 || res.Entries[0].Name != "note.txt" {
		t.Fatalf("list: %+v %v", res, err)
	}
	if fi, err := sb.Stat(wctx, path); err != nil || fi.Size != 5 {
		t.Fatalf("stat: %+v %v", fi, err)
	}
	if _, err := sb.ReadFile(wctx, filepath.Join(dir, "missing"), &back); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("missing file: want agent.ErrNotFound, got %v", err)
	}
}

func TestFilesNeedAnAgent(t *testing.T) {
	b, rootfs := newFake(t, "normal")
	sb, err := b.Create(context.Background(), sandbox.Spec{ID: "noagent", Rootfs: rootfs})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Shutdown(context.Background(), time.Second)
	if _, err := sb.ReadFile(context.Background(), "/etc/hostname", io.Discard); !errors.Is(err, sandbox.ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}

func TestReapCleansUpAnOrphanedSandbox(t *testing.T) {
	b, rootfs := newFake(t, "normal")
	ctx := context.Background()
	// Create, then "lose" the handle, as a crashed daemon would.
	if _, err := b.Create(ctx, sandbox.Spec{ID: "orphan", Rootfs: rootfs}); err != nil {
		t.Fatal(err)
	}
	if err := b.Reap(ctx, "orphan"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.cfg.StateDir, "runsc", "orphan")); !os.IsNotExist(err) {
		t.Error("runsc state still present after reap")
	}
	if _, err := os.Stat(filepath.Join(b.cfg.StateDir, "bundles", "orphan")); !os.IsNotExist(err) {
		t.Error("bundle still present after reap")
	}
	if err := b.Reap(ctx, "never-existed"); err != nil {
		t.Errorf("reaping something already gone must not fail: %v", err)
	}
}

// agentSandbox creates a stand-in sandbox whose agent is the real guest
// code, running in this process and dialing the sandbox's socket, as the
// agent inside gVisor would.
func agentSandbox(t *testing.T, mode, id string) (*Backend, sandbox.Sandbox) {
	t.Helper()
	b, rootfs := newFakeWithAgent(t)
	t.Setenv("SBX_FAKE_RUNSC", mode)
	ctx := context.Background()
	sb, err := b.Create(ctx, sandbox.Spec{ID: id, Rootfs: rootfs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sb.Shutdown(context.Background(), time.Second) })
	gctx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)
	bundle := filepath.Join(b.cfg.StateDir, "bundles", id)
	go guest.Run(gctx, guest.Config{SandboxID: id, Dial: "unix:" + filepath.Join(bundle, "sbx", agentSocket),
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 200 * time.Millisecond, LogDir: t.TempDir(), Logf: t.Logf})
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := sb.Agent(wctx); err != nil {
		t.Fatalf("agent never connected: %v", err)
	}
	return b, sb
}

func echoVia(t *testing.T, sb sandbox.Sandbox) string {
	t.Helper()
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := sb.Exec(ctx, sandbox.ExecRequest{Args: []string{"echo", "reachable"}, Stdout: &out}); err != nil {
		t.Fatalf("exec: %v", err)
	}
	return strings.TrimSpace(out.String())
}

func TestCheckpointSavesImageAndStops(t *testing.T) {
	_, sb := agentSandbox(t, "normal", "ckstop")
	dir := filepath.Join(t.TempDir(), "img")
	res, err := sb.Checkpoint(context.Background(), sandbox.CheckpointOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"checkpoint.img", "config.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("image directory lacks %s: %v", f, err)
		}
	}
	if res.ImageBytes <= 0 {
		t.Errorf("image size %d", res.ImageBytes)
	}
	select {
	case <-sb.Exited():
	case <-time.After(5 * time.Second):
		t.Fatal("a checkpoint without leave-running should stop the sandbox")
	}
}

// A snapshot: the sandbox runs on, and the agent finds the new listener.
func TestCheckpointLeaveRunningReconnects(t *testing.T) {
	_, sb := agentSandbox(t, "normal", "cksnap")
	if _, err := sb.Checkpoint(context.Background(), sandbox.CheckpointOptions{Dir: filepath.Join(t.TempDir(), "img"), LeaveRunning: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sb.Exited():
		t.Fatal("left running, yet it stopped")
	default:
	}
	if got := echoVia(t, sb); got != "reachable" {
		t.Fatalf("after the snapshot: %q", got)
	}
}

// A failed checkpoint must not strand the sandbox: running, but with
// nothing listening for its agent.
func TestFailedCheckpointLeavesTheSandboxReachable(t *testing.T) {
	_, sb := agentSandbox(t, "failcheckpoint", "ckfail")
	_, err := sb.Checkpoint(context.Background(), sandbox.CheckpointOptions{Dir: filepath.Join(t.TempDir(), "img")})
	if err == nil || !strings.Contains(err.Error(), "can't be saved") {
		t.Fatalf("want runsc's error, got %v", err)
	}
	if got := echoVia(t, sb); got != "reachable" {
		t.Fatalf("after the failed checkpoint: %q", got)
	}
}

// A restore brings the sandbox back with what it had. Here the agent is the
// in-process guest, which keeps running across the "restore", the way a
// restored agent resumes mid-execution: it reconnects to the new listener,
// still holding its process and shell session.
func TestRestoreBringsItBack(t *testing.T) {
	b, sb := agentSandbox(t, "normal", "rs")
	ctx := context.Background()
	if _, err := sb.StartProcess(ctx, sandbox.ProcStart{Args: []string{"sleep", "68.5"}}); err != nil {
		t.Fatal(err)
	}
	defer exec.Command("pkill", "-f", "^sleep 68.5$").Run()
	sh, err := sb.OpenShell(ctx, sandbox.ShellOptions{Command: []string{"sh"}})
	if err != nil {
		t.Fatal(err)
	}
	sh.Close()
	dir := filepath.Join(t.TempDir(), "img")
	if _, err := sb.Checkpoint(ctx, sandbox.CheckpointOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(filepath.Join(dir, agentBinary))
	if err != nil {
		t.Fatalf("the image should carry its own agent binary: %v", err)
	}
	// The agent gets rebuilt while the sandbox is paused, as happens daily.
	if err := os.WriteFile(b.cfg.AgentPath, []byte("#!a newer agent\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	r, err := b.Restore(ctx, "rs", dir)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	defer r.Shutdown(context.Background(), time.Second)
	installed, _ := os.ReadFile(filepath.Join(b.cfg.StateDir, "bundles", "rs", "sbx", agentBinary))
	if !bytes.Equal(installed, saved) {
		t.Fatal("the restored bundle must use the image's agent, not the rebuilt one")
	}
	if got := echoVia(t, r); got != "reachable" {
		t.Fatalf("after the restore: %q", got)
	}
	procs, _ := r.Processes(ctx)
	sessions, _ := r.Sessions(ctx)
	if len(procs) != 1 || !procs[0].Running || len(sessions.Sessions) != 1 {
		t.Fatalf("the process and the shell session should be there: %+v %+v", procs, sessions)
	}
}

func TestFailedRestoreCleansUp(t *testing.T) {
	b, sb := agentSandbox(t, "normal", "rsfail")
	dir := filepath.Join(t.TempDir(), "img")
	if _, err := sb.Checkpoint(context.Background(), sandbox.CheckpointOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SBX_FAKE_RUNSC", "failrestore")
	if _, err := b.Restore(context.Background(), "rsfail", dir); err == nil || !strings.Contains(err.Error(), "doesn't match") {
		t.Fatalf("want runsc's error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.cfg.StateDir, "bundles", "rsfail")); !os.IsNotExist(err) {
		t.Fatal("a failed restore left its bundle behind")
	}
}

func TestRestoreNeedsAnImage(t *testing.T) {
	b, _ := newFakeWithAgent(t)
	if _, err := b.Restore(context.Background(), "nothing", t.TempDir()); err == nil || !strings.Contains(err.Error(), "no spec") {
		t.Fatalf("want a missing-spec error, got %v", err)
	}
}

// A daemon crash, then a new daemon: the sandbox keeps running (here, the
// stand-in says so), the dead daemon's listener is gone, and a brand-new
// backend adopts it. The agent, redialing all along, reconnects.
func TestAdoptAfterADaemonCrash(t *testing.T) {
	b, sb := agentSandbox(t, "normal", "adopted")
	ctx := context.Background()
	if _, err := sb.StartProcess(ctx, sandbox.ProcStart{Args: []string{"sleep", "69.5"}}); err != nil {
		t.Fatal(err)
	}
	defer exec.Command("pkill", "-f", "^sleep 69.5$").Run()
	sb.(*Sandbox).listener().Close() // the old daemon dies with its socket
	// Real runsc reports the sandbox's PID; the stand-in reads it from here.
	// (A PID that doesn't exist: there's no cgroup to learn in this test.)
	_ = os.WriteFile(filepath.Join(b.cfg.StateDir, "runsc", "adopted.pid"), []byte("999999"), 0o644)

	b2, err := New(b.cfg) // the new daemon's backend: no memory of the old one
	if err != nil {
		t.Fatal(err)
	}
	a, err := b2.Adopt(ctx, "adopted")
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if got := echoVia(t, a); got != "reachable" {
		t.Fatalf("after adoption: %q", got)
	}
	if procs, _ := a.Processes(ctx); len(procs) != 1 || !procs[0].Running {
		t.Fatalf("the process never stopped, and should be listed: %+v", procs)
	}
}

func TestAdoptRefusesWhatIsNotRunning(t *testing.T) {
	b, sb := agentSandbox(t, "normal", "gone")
	statePath := filepath.Join(b.cfg.StateDir, "runsc", "gone")
	_ = os.WriteFile(statePath, []byte("stopped"), 0o644)
	<-sb.Exited()
	b2, _ := New(b.cfg)
	if _, err := b2.Adopt(context.Background(), "gone"); !errors.Is(err, sandbox.ErrExited) {
		t.Fatalf("a stopped sandbox: want ErrExited, got %v", err)
	}
	if _, err := b2.Adopt(context.Background(), "never-existed"); err == nil || !strings.Contains(err.Error(), "no bundle") {
		t.Fatalf("no bundle: %v", err)
	}
}

// A fork is restored under a new ID: its spec becomes its own (cgroup,
// /sbx mount, hostname), and its listener accepts the identity the agent in
// the image will give, the original's. Here a second in-process agent plays
// the restored one: it introduces itself as "forksrc" on the fork's socket.
func TestForkRestoresUnderANewIdentity(t *testing.T) {
	b, sb := agentSandbox(t, "normal", "forksrc")
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "img")
	if _, err := sb.Checkpoint(ctx, sandbox.CheckpointOptions{Dir: dir, LeaveRunning: true}); err != nil {
		t.Fatal(err)
	}
	r, err := b.Restore(ctx, "forked1", dir)
	if err != nil {
		t.Fatalf("restore as a fork: %v", err)
	}
	defer r.Shutdown(context.Background(), time.Second)

	var src, fork ociSpec
	raw, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	_ = json.Unmarshal(raw, &src)
	raw, _ = os.ReadFile(filepath.Join(b.cfg.StateDir, "bundles", "forked1", "config.json"))
	_ = json.Unmarshal(raw, &fork)
	if src.Linux.CgroupsPath != "" && fork.Linux.CgroupsPath != b.cfg.CgroupParent+"/forked1" {
		t.Errorf("the fork's cgroup: %q (the source's: %q)", fork.Linux.CgroupsPath, src.Linux.CgroupsPath)
	}
	for _, mt := range fork.Mounts {
		if mt.Destination == agentMountPoint && mt.Source != filepath.Join(b.cfg.StateDir, "bundles", "forked1", "sbx") {
			t.Errorf("the fork's /sbx mount points at %s", mt.Source)
		}
	}
	if fork.Hostname != "sbx-forked1" || agentIDOf(&fork) != "forksrc" {
		t.Errorf("hostname %q, agent id %q", fork.Hostname, agentIDOf(&fork))
	}

	gctx, stop := context.WithCancel(ctx)
	defer stop()
	go guest.Run(gctx, guest.Config{SandboxID: "forksrc", Dial: "unix:" + filepath.Join(b.cfg.StateDir, "bundles", "forked1", "sbx", agentSocket),
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 200 * time.Millisecond, LogDir: t.TempDir(), Logf: t.Logf})
	if got := echoVia(t, r); got != "reachable" {
		t.Fatalf("the fork's agent should be accepted: %q", got)
	}
}

// The rewrite on its own, on a spec that certainly has a cgroup path: the
// test above can only check the cgroup when the stand-in backend uses one.
func TestForkSpecIsTheForksOwn(t *testing.T) {
	b := &Backend{cfg: Config{CgroupParent: "/sbx"}}
	s := sandbox.Spec{ID: "orig", VCPUs: 1, MemMiB: 256}
	spec := buildSpec(s, "/rootfs", limits{cgroupPath: "/sbx/orig"}, "/state/bundles/orig/sbx")
	b.forkSpec(&spec, "copy", "/state/bundles/copy/sbx")
	if spec.Linux.CgroupsPath != "/sbx/copy" {
		t.Errorf("cgroup %q: a fork sharing its source's cgroup would share its limits", spec.Linux.CgroupsPath)
	}
	found := false
	for _, m := range spec.Mounts {
		if m.Destination == agentMountPoint {
			found = true
			if m.Source != "/state/bundles/copy/sbx" {
				t.Errorf("/sbx mount %q: the fork would use its source's socket", m.Source)
			}
		}
	}
	if !found || spec.Hostname != "sbx-copy" || agentIDOf(&spec) != "orig" {
		t.Errorf("mount found %v, hostname %q, agent id %q (the agent's id must stay the original's)", found, spec.Hostname, agentIDOf(&spec))
	}
}

func TestHostnameIsNotDoublePrefixed(t *testing.T) {
	for id, want := range map[string]string{"sbx-1a2b3c4d": "sbx-1a2b3c4d", "it1-42": "sbx-it1-42", "copy": "sbx-copy"} {
		if got := hostnameFor(id); got != want {
			t.Errorf("hostnameFor(%q) = %q, want %q", id, got, want)
		}
	}
}

// A fork takes its own identity (Day 15): the agent that introduced itself
// as its source is renamed, says what it was, and the listener now expects
// the fork's own ID.
func TestForkTakesItsOwnIdentity(t *testing.T) {
	b, sb := agentSandbox(t, "normal", "idsrc")
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "img")
	if _, err := sb.Checkpoint(ctx, sandbox.CheckpointOptions{Dir: dir, LeaveRunning: true}); err != nil {
		t.Fatal(err)
	}
	r, err := b.Restore(ctx, "idfork", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown(context.Background(), time.Second)
	gctx, stop := context.WithCancel(ctx)
	defer stop()
	go guest.Run(gctx, guest.Config{SandboxID: "idsrc", Dial: "unix:" + filepath.Join(b.cfg.StateDir, "bundles", "idfork", "sbx", agentSocket),
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 200 * time.Millisecond, LogDir: t.TempDir(), Logf: t.Logf})
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := r.Agent(wctx); err != nil {
		t.Fatal(err)
	}
	prev, err := r.SetIdentity(ctx, "idfork", "gen-fork")
	if err != nil || prev != "idsrc" {
		t.Fatalf("set identity: previous %q, %v (want idsrc)", prev, err)
	}
	if got := r.(*Sandbox).listener().Expected(); got != "idfork" {
		t.Fatalf("the listener expects %q, want the fork's own ID", got)
	}
	var out bytes.Buffer
	if _, err := r.Exec(ctx, sandbox.ExecRequest{Args: []string{"sh", "-c", "echo $SBX_SANDBOX_ID"}, Stdout: &out}); err != nil || out.String() != "idfork\n" {
		t.Fatalf("a new process in the fork: %q %v", out.String(), err)
	}
}

// A networked sandbox (Day 16): its spec joins the prepared namespace, and
// runsc runs it, and restores it, with gVisor's own network stack.
func TestNetworkedSandboxUsesThePreparedNamespace(t *testing.T) {
	spec := buildSpec(sandbox.Spec{ID: "n", NetNS: "/run/netns/sbx-n"}, "/rootfs", limits{}, "")
	if netNSOf(&spec) != "/run/netns/sbx-n" || networkMode(&spec) != "sandbox" {
		t.Fatalf("namespace %q, mode %q", netNSOf(&spec), networkMode(&spec))
	}
	plain := buildSpec(sandbox.Spec{ID: "p"}, "/rootfs", limits{}, "")
	if netNSOf(&plain) != "" || networkMode(&plain) != "none" {
		t.Fatalf("a plain sandbox: namespace %q, mode %q", netNSOf(&plain), networkMode(&plain))
	}

	b, rootfs := newFake(t, "normal")
	ctx := context.Background()
	sb, err := b.Create(ctx, sandbox.Spec{ID: "netrun", Rootfs: rootfs, NetNS: "/run/netns/sbx-netrun"})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Shutdown(context.Background(), time.Second)
	runArgs, _ := os.ReadFile(filepath.Join(b.cfg.StateDir, "runsc", "netrun.args"))
	if !strings.Contains(string(runArgs), "--network sandbox") {
		t.Fatalf("runsc run should get --network sandbox: %s", runArgs)
	}
	dir := filepath.Join(t.TempDir(), "img")
	if _, err := sb.Checkpoint(ctx, sandbox.CheckpointOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	<-sb.Exited()
	_ = sb.Shutdown(ctx, time.Second)
	r, err := b.Restore(ctx, "netrun", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown(context.Background(), time.Second)
	restoreArgs, _ := os.ReadFile(filepath.Join(b.cfg.StateDir, "runsc", "netrun.args"))
	if !strings.Contains(string(restoreArgs), "restore") || !strings.Contains(string(restoreArgs), "--network sandbox") {
		t.Fatalf("runsc restore should get --network sandbox too: %s", restoreArgs)
	}
}

// Day 19: a clone joins its own network namespace, not its source's; a
// spec without a network keeps none.
func TestForkSpecJoinsTheClonesOwnNetwork(t *testing.T) {
	b, _ := newFake(t, "normal")
	spec := buildSpec(sandbox.Spec{ID: "src", NetNS: "/run/netns/sbx-src"}, "/rootfs", limits{}, "")
	b.forkSpec(&spec, "copy", "/state/bundles/copy/sbx")
	if got := netNSOf(&spec); got != "/run/netns/sbx-copy" {
		t.Fatalf("the clone's namespace: %q", got)
	}
	plain := buildSpec(sandbox.Spec{ID: "src"}, "/rootfs", limits{}, "")
	b.forkSpec(&plain, "copy", "/state/bundles/copy/sbx")
	if got := netNSOf(&plain); got != "" {
		t.Fatalf("a spec without a network gained one: %q", got)
	}
}

// Day 23: a failed `runsc state` says nothing about the sandbox, so it must
// never count as stopped. (It did: under load, one failed call marked a
// running sandbox exited, its shutdown skipped the kill and the delete, and
// the next restore under its ID was refused.)
func TestAStateErrorIsNotStopped(t *testing.T) {
	_, sb := agentSandbox(t, "normal", "flaky")
	gs := sb.(*Sandbox)
	t.Setenv("SBX_FAKE_RUNSC", "flakystate")
	if gs.stoppedNow() {
		t.Fatal("a failed state call was taken to mean stopped")
	}
	select {
	case <-sb.Exited():
		t.Fatal("a running sandbox was marked exited on a failed state call")
	default:
	}
	t.Setenv("SBX_FAKE_RUNSC", "normal")
	if gs.stoppedNow() {
		t.Fatal("it's still running")
	}
	if err := sb.Shutdown(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	if !gs.stoppedNow() {
		t.Fatal("after shutdown, runsc says it's gone: that counts as stopped")
	}
}

// A pausing checkpoint must leave the sandbox stopped: if runsc doesn't stop
// it, it's killed (its state is saved), never reported paused while running.
func TestAPausingCheckpointLeavesItStopped(t *testing.T) {
	b, sb := agentSandbox(t, "lingers", "linger")
	b.cfg.StopWait = 200 * time.Millisecond
	if _, err := sb.Checkpoint(context.Background(), sandbox.CheckpointOptions{Dir: filepath.Join(t.TempDir(), "img")}); err != nil {
		t.Fatal(err)
	}
	if st, _, err := b.containerState("linger"); err != nil || st != "stopped" {
		t.Fatalf("after a pausing checkpoint: %q %v, want stopped", st, err)
	}
	select {
	case <-sb.Exited():
	default:
		t.Fatal("it should be marked exited")
	}
}

// A restore under an ID whose old container is still registered (stale:
// the daemon asks for a restore only when the sandbox is paused) clears it
// first, instead of being refused.
func TestRestoreClearsAStaleContainer(t *testing.T) {
	b, sb := agentSandbox(t, "normal", "stale")
	dir := filepath.Join(t.TempDir(), "img")
	if _, err := sb.Checkpoint(context.Background(), sandbox.CheckpointOptions{Dir: dir, LeaveRunning: true}); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := b.containerState("stale"); st != "running" {
		t.Fatalf("set-up: the old container should still be registered as running, got %q", st)
	}
	r, err := b.Restore(context.Background(), "stale", dir)
	if err != nil {
		t.Fatalf("restoring over a stale container: %v", err)
	}
	t.Cleanup(func() { _ = r.Shutdown(context.Background(), time.Second) })
	if st, _, err := b.containerState("stale"); err != nil || st != "running" {
		t.Fatalf("after the restore: %q %v", st, err)
	}
}

// Day 23: forced modes. "direct" uses O_DIRECT for both checkpoint and
// restore where runsc has it; "buffered" never; a runsc without it, never.
func TestDirectIOModes(t *testing.T) {
	for _, tc := range []struct {
		name, mode, io string
		want           bool
	}{
		{"direct, runsc has it", "hasdirect", "direct", true},
		{"buffered", "hasdirect", "buffered", false},
		{"direct, runsc lacks it", "normal", "direct", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, sb := agentSandbox(t, tc.mode, "dio")
			b.cfg.CheckpointIO = tc.io
			dir := filepath.Join(t.TempDir(), "img")
			if _, err := sb.Checkpoint(context.Background(), sandbox.CheckpointOptions{Dir: dir}); err != nil {
				t.Fatal(err)
			}
			ck, _ := os.ReadFile(filepath.Join(b.cfg.StateDir, "runsc", "dio.ckargs"))
			if strings.Contains(string(ck), "--direct") != tc.want {
				t.Fatalf("checkpoint args %q: want --direct %v", ck, tc.want)
			}
			r, err := b.Restore(context.Background(), "dio", dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Shutdown(context.Background(), time.Second) })
			rs, _ := os.ReadFile(filepath.Join(b.cfg.StateDir, "runsc", "dio.args"))
			if strings.Contains(string(rs), "--direct") != tc.want {
				t.Fatalf("restore args %q: want --direct %v", rs, tc.want)
			}
		})
	}
}

// "auto" (the default): a checkpoint uses O_DIRECT only when the sandbox
// holds more than 40% of its memory limit, or when that's unknown.
func TestAutoIOFollowsMemoryInUse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		current string // memory.current; "" for no cgroup known
		want    bool
	}{
		{"50 of 256 MiB: buffered", "52428800\n", false},
		{"150 of 256 MiB: direct", "157286400\n", true},
		{"unknown: direct, to be safe", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := newFake(t, "hasdirect")
			s := &Sandbox{b: b, id: "auto", exited: make(chan struct{}), memLimit: 256 << 20}
			if tc.current != "" {
				_, cgRoot := fakeCgroup(t, 1, "/sbx/auto", map[string]string{"memory.current": tc.current, "memory.max": "268435456\n"})
				b.cg.cgRoot, s.cgroupPath = cgRoot, "/sbx/auto"
			}
			_ = os.MkdirAll(filepath.Join(b.cfg.StateDir, "runsc"), 0o755)
			_ = os.WriteFile(filepath.Join(b.cfg.StateDir, "runsc", "auto"), []byte("running"), 0o644)
			if _, err := s.Checkpoint(context.Background(), sandbox.CheckpointOptions{Dir: filepath.Join(t.TempDir(), "img")}); err != nil {
				t.Fatal(err)
			}
			ck, _ := os.ReadFile(filepath.Join(b.cfg.StateDir, "runsc", "auto.ckargs"))
			if strings.Contains(string(ck), "--direct") != tc.want {
				t.Fatalf("checkpoint args %q: want --direct %v", ck, tc.want)
			}
		})
	}
}

// "auto" for a restore: by the image's size against the spec's memory limit.
func TestAutoIOFollowsImageSize(t *testing.T) {
	b, sb := agentSandbox(t, "hasdirect", "img")
	dir := filepath.Join(t.TempDir(), "img")
	if _, err := sb.Checkpoint(context.Background(), sandbox.CheckpointOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	setLimit := func(limit int64) {
		raw, _ := os.ReadFile(filepath.Join(dir, "config.json"))
		var spec map[string]any
		_ = json.Unmarshal(raw, &spec)
		linux, _ := spec["linux"].(map[string]any)
		res, _ := linux["resources"].(map[string]any)
		if res == nil {
			res = map[string]any{}
			linux["resources"] = res
		}
		res["memory"] = map[string]any{"limit": limit}
		out, _ := json.Marshal(spec)
		_ = os.WriteFile(filepath.Join(dir, "config.json"), out, 0o600)
	}
	size := dirSize(dir)
	for _, tc := range []struct {
		name  string
		limit int64
		want  bool
	}{
		{"an image well under 40% of the limit: buffered", size * 10, false},
		{"an image over 40% of the limit: direct", size * 2, true},
	} {
		setLimit(tc.limit)
		r, err := b.Restore(context.Background(), "img", dir)
		if err != nil {
			t.Fatal(err)
		}
		rs, _ := os.ReadFile(filepath.Join(b.cfg.StateDir, "runsc", "img.args"))
		_ = r.Shutdown(context.Background(), time.Second)
		if strings.Contains(string(rs), "--direct") != tc.want {
			t.Fatalf("%s: restore args %q: want --direct %v", tc.name, rs, tc.want)
		}
	}
}

// A checkpoint that fails because the sandbox ran out of memory says so.
func TestCheckpointFailureNamesAnOOMKill(t *testing.T) {
	b, _ := newFake(t, "failcheckpoint")
	_, cgRoot := fakeCgroup(t, 1, "/sbx/oomed", map[string]string{"memory.events": "oom 1\noom_kill 1\n", "memory.max": "268435456\n"})
	b.cg.cgRoot = cgRoot
	s := &Sandbox{b: b, id: "oomed", cgroupPath: "/sbx/oomed", exited: make(chan struct{})}
	_ = os.WriteFile(filepath.Join(b.cfg.StateDir, "runsc", "oomed"), []byte("running"), 0o644)
	_, err := s.Checkpoint(context.Background(), sandbox.CheckpointOptions{Dir: filepath.Join(t.TempDir(), "img")})
	if err == nil || !strings.Contains(err.Error(), "the sandbox was killed by the kernel's out-of-memory killer (memory limit 256 MiB reached) during the checkpoint") {
		t.Fatalf("checkpoint error: %v", err)
	}
}
