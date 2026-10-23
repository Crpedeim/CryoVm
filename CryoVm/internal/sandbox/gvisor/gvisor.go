// Package gvisor runs sandboxes with gVisor's runsc: a user-space kernel that
// intercepts the workload's system calls, so no /dev/kvm is needed.
package gvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Crpedeim/sbx/internal/netns"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Crpedeim/sbx/internal/agent"
	"github.com/Crpedeim/sbx/internal/agentproto"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

type Config struct {
	RunscPath string // default "runsc"
	StateDir  string // absolute; holds runsc's state and one bundle per sandbox
	Platform  string // "", "systrap" or "kvm"; empty uses runsc's default (systrap)

	// StopWait is how long a pausing checkpoint waits for runsc to stop the
	// sandbox once its state is saved, before killing it (default 10s).
	StopWait time.Duration

	// CheckpointIO is how checkpoint images are written and read: "auto"
	// (the default), "direct" or "buffered". A buffered image's page cache
	// is charged to the sandbox's own memory limit: a sandbox holding 128 of
	// 256 MiB was killed by its own checkpoint (Day 23). O_DIRECT avoids it
	// but costs small checkpoints time, so "auto" uses it only where the risk
	// is: when the sandbox holds more than 40% of its limit (buffered, its
	// peak is then under 80%). "direct" always uses it where runsc can;
	// "buffered" never (for filesystems without O_DIRECT, such as tmpfs).
	CheckpointIO string
	Rootless     bool // run without root; resource limits are skipped
	PollEvery    time.Duration

	// AgentPath is the host path of a static sbx-agent binary. When set, the
	// agent becomes each sandbox's init and dials back over a Unix socket.
	// Empty keeps Day 1 behaviour: init sleeps, commands use `runsc exec`.
	AgentPath string

	// ExtraFlags go to every runsc call, before the subcommand. For
	// debugging: []string{"--debug", "--debug-log=/tmp/runsc/"}.
	ExtraFlags []string

	// CgroupParent is where sandboxes' cgroups go: each sandbox gets
	// <CgroupParent>/<id>. Default "/sbx". CgroupRoot and ProcRoot are
	// where the cgroup tree and /proc are mounted; tests point them at
	// fakes. Defaults /sys/fs/cgroup and /proc.
	CgroupParent string
	CgroupRoot   string
	ProcRoot     string

	prefixArgs []string // tests only: arguments placed before runsc's own
}

type Backend struct {
	cfg Config
	cg  cgroupFS

	// skipQuiesce checkpoints without first asking the agent to let go
	// of its connection. Tests only: it shows why the quiesce is needed.
	skipQuiesce bool

	cpuMu    sync.Mutex
	nextCPU  int        // round-robin start for the next sandbox's cpuset
	hostCPUs func() int // runtime.NumCPU; tests substitute

	directOnce                      sync.Once
	directCheckpoint, directRestore bool // runsc has -direct for each (Day 23)
}

// SetCheckpointIO sets the I/O mode ("auto", "direct" or "buffered"). Tests
// use it, before the backend's first checkpoint.
func (b *Backend) SetCheckpointIO(mode string) { b.cfg.CheckpointIO = mode }

// DirectIO reports whether this runsc offers O_DIRECT for checkpoints and
// restores (whether a given one uses it depends on CheckpointIO).
func (b *Backend) DirectIO() (checkpoint, restore bool) { return b.direct() }

// useDirect decides one checkpoint's or restore's I/O: size is what the
// sandbox holds (or the image; -1 if unknown), limit its memory limit (0:
// none). An explicit mode always wins; "auto" decides by the numbers.
func (b *Backend) useDirect(supported bool, size, limit int64) bool {
	switch {
	case !supported || b.cfg.CheckpointIO == "buffered":
		return false
	case b.cfg.CheckpointIO == "direct":
		return true
	case limit <= 0:
		return false // no limit: the page cache can't push it over one
	case size < 0:
		return true // unknown: be safe
	}
	return size*10 > limit*4 // more than 40% of the limit
}

func (b *Backend) direct() (checkpoint, restore bool) {
	b.directOnce.Do(func() {
		has := func(sub string) bool {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			out, _ := b.command(ctx, sub, "--help").CombinedOutput()
			for _, line := range strings.Split(string(out), "\n") {
				if f := strings.Fields(line); len(f) > 0 && (f[0] == "-direct" || f[0] == "--direct") {
					return true
				}
			}
			return false
		}
		b.directCheckpoint, b.directRestore = has("checkpoint"), has("restore")
	})
	return b.directCheckpoint, b.directRestore
}

var _ sandbox.Backend = (*Backend)(nil)

func New(cfg Config) (*Backend, error) {
	if cfg.RunscPath == "" {
		cfg.RunscPath = "runsc"
	}
	if cfg.PollEvery == 0 {
		cfg.PollEvery = 100 * time.Millisecond
	}
	if !filepath.IsAbs(cfg.StateDir) {
		return nil, fmt.Errorf("gvisor: state dir must be absolute, got %q", cfg.StateDir)
	}
	if err := os.MkdirAll(filepath.Join(cfg.StateDir, "bundles"), 0o755); err != nil {
		return nil, err
	}
	if cfg.AgentPath != "" {
		if fi, err := os.Stat(cfg.AgentPath); err != nil || fi.IsDir() {
			return nil, fmt.Errorf("gvisor: agent binary %q not found", cfg.AgentPath)
		}
	}
	if cfg.CgroupParent == "" {
		cfg.CgroupParent = "/sbx"
	}
	if cfg.CgroupRoot == "" {
		cfg.CgroupRoot = "/sys/fs/cgroup"
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	return &Backend{cfg: cfg, cg: cgroupFS{procRoot: cfg.ProcRoot, cgRoot: cfg.CgroupRoot}, hostCPUs: runtime.NumCPU}, nil
}

// cpusFor picks which host CPUs a sandbox may run on. Pinning a 1-vCPU
// sandbox to one CPU is what makes nproc inside it say 1 (Day 1 saw 2).
// Sandboxes are spread round-robin, so they don't all pile onto CPU 0.
func (b *Backend) cpusFor(vcpus int) string {
	host := b.hostCPUs()
	if vcpus <= 0 || vcpus >= host {
		return "" // all of them
	}
	b.cpuMu.Lock()
	start := b.nextCPU
	b.nextCPU = (b.nextCPU + vcpus) % host
	b.cpuMu.Unlock()
	cpus := make([]string, vcpus)
	for i := range cpus {
		cpus[i] = strconv.Itoa((start + i) % host)
	}
	return strings.Join(cpus, ",")
}

func (b *Backend) limitsFor(s sandbox.Spec) limits {
	if b.cfg.Rootless {
		return limits{} // no cgroups without root
	}
	return limits{cgroupPath: b.cfg.CgroupParent + "/" + s.ID, cpus: b.cpusFor(s.VCPUs)}
}

func (b *Backend) Name() string { return "gvisor" }

// Create writes an OCI bundle and starts the sandbox detached.
func (b *Backend) Create(ctx context.Context, s sandbox.Spec) (sandbox.Sandbox, error) {
	if err := sandbox.ValidateID(s.ID); err != nil {
		return nil, err
	}
	rootfs, err := filepath.Abs(s.Rootfs)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(rootfs); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("gvisor: rootfs %q must be a directory", rootfs)
	}

	bundle := filepath.Join(b.cfg.StateDir, "bundles", s.ID)
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		return nil, err
	}
	sb := &Sandbox{b: b, id: s.ID, bundle: bundle, exited: make(chan struct{}), memLimit: int64(s.MemMiB) << 20}
	fail := func(err error) (sandbox.Sandbox, error) {
		if sb.agentLn != nil {
			sb.agentLn.Close()
		}
		_ = os.RemoveAll(bundle)
		return nil, err
	}

	// The host listens before the sandbox starts, so the agent's first dial
	// finds the socket already there.
	var agentDir string
	if b.cfg.AgentPath != "" {
		agentDir = filepath.Join(bundle, "sbx")
		if err := os.MkdirAll(agentDir, 0o755); err != nil {
			return fail(err)
		}
		if err := copyFile(b.cfg.AgentPath, filepath.Join(agentDir, agentBinary), 0o755); err != nil {
			return fail(fmt.Errorf("gvisor: install agent: %w", err))
		}
		ln, err := agent.Listen(filepath.Join(agentDir, agentSocket), s.ID)
		if err != nil {
			return fail(err)
		}
		sb.agentLn = ln
	}

	cfg, err := json.MarshalIndent(buildSpec(s, rootfs, b.limitsFor(s), agentDir), "", "  ")
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), cfg, 0o644); err != nil {
		return fail(err)
	}

	// runsc's output goes to a file, not a pipe: the sandbox inherits these
	// descriptors and outlives `runsc run --detach`, so a pipe would never
	// reach EOF and we would wait forever.
	logPath := filepath.Join(bundle, "runsc-run.log")
	network := "none"
	if s.NetNS != "" {
		network = "sandbox"
	}
	if err := b.runToFile(ctx, logPath, network, "run", "--detach", "--bundle", bundle, s.ID); err != nil {
		return fail(err)
	}

	go sb.watch()
	return sb, nil
}

func (b *Backend) args(sub ...string) []string {
	return b.argsNet("none", sub...)
}

// argsNet is args with a chosen --network: "sandbox" for the run and the
// restore of a sandbox with a prepared namespace (Day 16), "none" otherwise.
func (b *Backend) argsNet(network string, sub ...string) []string {
	a := append([]string{}, b.cfg.prefixArgs...)
	a = append(a, "--root", filepath.Join(b.cfg.StateDir, "runsc"), "--network", network)
	if b.cfg.Platform != "" {
		a = append(a, "--platform", b.cfg.Platform)
	}
	if b.cfg.Rootless {
		a = append(a, "--rootless")
	}
	if b.cfg.AgentPath != "" {
		// Let the sandbox connect to existing host Unix sockets (only those
		// visible through its mounts: here, the agent's). gVisor's default
		// is "none".
		a = append(a, "--host-uds", "open")
	}
	a = append(a, b.cfg.ExtraFlags...)
	return append(a, sub...)
}

func (b *Backend) command(ctx context.Context, sub ...string) *exec.Cmd {
	return b.commandNet(ctx, "none", sub...)
}

func (b *Backend) commandNet(ctx context.Context, network string, sub ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, b.cfg.RunscPath, b.argsNet(network, sub...)...)
	// If something inside the sandbox keeps our output pipe open after runsc
	// exits, stop waiting for it after a short delay instead of hanging.
	cmd.WaitDelay = 2 * time.Second
	return cmd
}

func (b *Backend) runToFile(ctx context.Context, logPath, network string, sub ...string) error {
	f, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := b.commandNet(ctx, network, sub...)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Run(); err != nil {
		out, rerr := os.ReadFile(logPath)
		if rerr != nil {
			// The log went missing: something removed the bundle while
			// runsc ran. Say so: an empty message hides exactly that.
			return fmt.Errorf("runsc %s: %w (its log %s is gone: %v)", sub[0], err, logPath, rerr)
		}
		return fmt.Errorf("runsc %s: %w: %s", sub[0], err, tail(out, 2048))
	}
	return nil
}

func (b *Backend) runQuiet(ctx context.Context, sub ...string) ([]byte, error) {
	var out bytes.Buffer
	cmd := b.command(ctx, sub...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.Bytes(), fmt.Errorf("runsc %s: %w: %s", sub[0], err, tail(out.Bytes(), 2048))
	}
	return out.Bytes(), nil
}

type Sandbox struct {
	b       *Backend
	id      string
	bundle  string
	agentLn *agent.Listener // nil without an agent

	exited     chan struct{}
	exitedOnce sync.Once

	mu         sync.Mutex
	cgroupPath string // learned once the sandbox runs; kept for after it dies
	exitReason string
	memLimit   int64 // bytes; 0: none

	// The last host thread count the watcher saw, and the limit. If the
	// sandbox dies with no counter to explain it, a last sample at the
	// limit still can.
	lastPids, lastPidsMax int64
}

// memoryHighFraction is where the kernel starts throttling a sandbox's
// allocations, as a fraction of its memory limit.
const memoryHighFraction = 0.90

var _ sandbox.Sandbox = (*Sandbox)(nil)

func (s *Sandbox) ID() string { return s.id }

func (s *Sandbox) Exited() <-chan struct{} { return s.exited }

// listener is the agent's listener. A checkpoint can replace it (the agent
// reconnects to a new one), so every read takes the lock.
func (s *Sandbox) listener() *agent.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.agentLn
}

// Agent waits for the guest agent to dial in.
func (s *Sandbox) Agent(ctx context.Context) (*agent.Conn, error) {
	ln := s.listener()
	if ln == nil {
		return nil, fmt.Errorf("gvisor: sandbox created without an agent: %w", sandbox.ErrUnsupported)
	}
	return ln.Conn(ctx)
}

// agentWait bounds how long Exec waits for the agent to (re)connect.
const agentWait = 15 * time.Second

// Exec runs one command inside the sandbox. With an agent it goes through
// the agent, which owns the process: output streams as it arrives, and a
// timeout kills the command's whole process group. Without one it falls
// back to `runsc exec`, where a timeout can only kill runsc's side.
func (s *Sandbox) Exec(ctx context.Context, req sandbox.ExecRequest) (sandbox.ExecResult, error) {
	if len(req.Args) == 0 {
		return sandbox.ExecResult{}, errors.New("exec: empty command")
	}
	select {
	case <-s.exited:
		return sandbox.ExecResult{}, sandbox.ErrExited
	default:
	}
	if s.listener() != nil {
		return s.execViaAgent(ctx, req)
	}
	return s.execViaRunsc(ctx, req)
}

func (s *Sandbox) execViaAgent(ctx context.Context, req sandbox.ExecRequest) (sandbox.ExecResult, error) {
	wctx, cancel := context.WithTimeout(ctx, agentWait)
	conn, err := s.listener().Conn(wctx)
	cancel()
	if err != nil {
		return sandbox.ExecResult{ExitCode: -1}, err
	}
	var stdin []byte
	if req.Stdin != nil {
		// Read one byte past the limit, to tell "exactly at" from "over".
		stdin, err = io.ReadAll(io.LimitReader(req.Stdin, agentproto.MaxStdin+1))
		if err != nil {
			return sandbox.ExecResult{ExitCode: -1}, fmt.Errorf("exec: read stdin: %w", err)
		}
		if len(stdin) > agentproto.MaxStdin {
			return sandbox.ExecResult{ExitCode: -1}, fmt.Errorf("exec: stdin over %d bytes is not supported yet", agentproto.MaxStdin)
		}
	}
	res, err := conn.Exec(ctx, agent.ExecRequest{
		Args: req.Args, Env: req.Env, Dir: req.Dir, Stdin: stdin, Timeout: req.Timeout,
		Stdout: req.Stdout, Stderr: req.Stderr,
	})
	return sandbox.ExecResult{ExitCode: res.ExitCode, Signal: res.Signal, TimedOut: res.TimedOut}, err
}

// conn returns the agent connection, or ErrUnsupported without an agent.
func (s *Sandbox) conn(ctx context.Context) (*agent.Conn, error) {
	ln := s.listener()
	if ln == nil {
		return nil, fmt.Errorf("gvisor: file operations need an agent: %w", sandbox.ErrUnsupported)
	}
	select {
	case <-s.exited:
		return nil, sandbox.ErrExited
	default:
	}
	wctx, cancel := context.WithTimeout(ctx, agentWait)
	defer cancel()
	return ln.Conn(wctx)
}

func (s *Sandbox) WriteFile(ctx context.Context, path string, r io.Reader, opts sandbox.WriteOptions) (sandbox.TransferResult, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.TransferResult{}, err
	}
	return c.WriteFile(ctx, path, r, opts)
}

func (s *Sandbox) ReadFile(ctx context.Context, path string, w io.Writer) (sandbox.TransferResult, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.TransferResult{}, err
	}
	return c.ReadFile(ctx, path, w)
}

func (s *Sandbox) ListDir(ctx context.Context, path string) (sandbox.ListResult, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.ListResult{}, err
	}
	return c.ListDir(ctx, path)
}

func (s *Sandbox) Stat(ctx context.Context, path string) (sandbox.FileInfo, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.FileInfo{}, err
	}
	return c.Stat(ctx, path)
}

func (s *Sandbox) OpenShell(ctx context.Context, opts sandbox.ShellOptions) (*agent.Shell, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	return c.OpenShell(ctx, opts)
}

func (s *Sandbox) Sessions(ctx context.Context) (sandbox.SessionList, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.SessionList{}, err
	}
	return c.Sessions(ctx)
}

func (s *Sandbox) KillSession(ctx context.Context, id string) error {
	c, err := s.conn(ctx)
	if err != nil {
		return err
	}
	return c.KillSession(ctx, id)
}

func (s *Sandbox) StartProcess(ctx context.Context, req sandbox.ProcStart) (sandbox.ProcStarted, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.ProcStarted{}, err
	}
	return c.StartProcess(ctx, req)
}

func (s *Sandbox) Processes(ctx context.Context) ([]sandbox.ProcInfo, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	return c.Processes(ctx)
}

func (s *Sandbox) Signal(ctx context.Context, id string, sig int) error {
	c, err := s.conn(ctx)
	if err != nil {
		return err
	}
	return c.Signal(ctx, id, sig)
}

func (s *Sandbox) Wait(ctx context.Context, id string) (sandbox.ProcInfo, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.ProcInfo{}, err
	}
	return c.Wait(ctx, id)
}

func (s *Sandbox) Logs(ctx context.Context, id string, offset int64, follow bool, w io.Writer) (sandbox.LogsEnd, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.LogsEnd{}, err
	}
	return c.Logs(ctx, id, offset, follow, w)
}

func (s *Sandbox) RemoveProcess(ctx context.Context, id string) error {
	c, err := s.conn(ctx)
	if err != nil {
		return err
	}
	return c.RemoveProcess(ctx, id)
}

func (s *Sandbox) execViaRunsc(ctx context.Context, req sandbox.ExecRequest) (sandbox.ExecResult, error) {
	args := req.Args
	if req.Dir != "" || len(req.Env) > 0 {
		// `env` applies the working directory and variables inside the
		// sandbox, so this path needs no runsc-specific flags.
		pre := []string{"env"}
		if req.Dir != "" {
			pre = append(pre, "-C", req.Dir)
		}
		args = append(append(pre, req.Env...), args...)
	}
	runCtx := ctx
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	cmd := s.b.command(runCtx, append([]string{"exec", s.id}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = req.Stdin, req.Stdout, req.Stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return sandbox.ExecResult{ExitCode: -1}, ctx.Err()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return sandbox.ExecResult{ExitCode: -1, TimedOut: true}, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return sandbox.ExecResult{ExitCode: exitErr.ExitCode()}, nil
	}
	if err != nil {
		return sandbox.ExecResult{ExitCode: -1}, err
	}
	return sandbox.ExecResult{}, nil
}

// Shutdown sends SIGTERM to the sandbox's init, waits up to grace, then
// SIGKILL. It always deletes the sandbox's runsc state and bundle.
func (s *Sandbox) Shutdown(ctx context.Context, grace time.Duration) error {
	defer s.cleanup(ctx)

	select {
	case <-s.exited:
		return nil
	default:
	}
	_, _ = s.b.runQuiet(ctx, "kill", s.id, "TERM")
	select {
	case <-s.exited:
		return nil
	case <-time.After(grace):
	}
	// The watcher only checks on a timer, so the sandbox may have stopped
	// without anyone noticing yet. Ask once more before concluding that
	// SIGTERM was ignored.
	if s.stoppedNow() {
		return nil
	}
	_, _ = s.b.runQuiet(ctx, "kill", s.id, "KILL")
	select {
	case <-s.exited:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("sandbox %s still running after SIGKILL", s.id)
	}
	return fmt.Errorf("sandbox %s ignored SIGTERM for %s (killed)", s.id, grace)
}

func (s *Sandbox) cleanup(ctx context.Context) {
	if ln := s.listener(); ln != nil {
		ln.Close()
	}
	_, _ = s.b.runQuiet(ctx, "delete", s.id)
	_ = os.RemoveAll(s.bundle)
	// runsc normally removes the sandbox's cgroup on delete. If one is left
	// behind, remove it: an empty cgroup directory is deleted with rmdir
	// (os.Remove), never RemoveAll, which the kernel's cgroup files refuse.
	s.mu.Lock()
	path := s.cgroupPath
	s.mu.Unlock()
	if path != "" {
		_ = os.Remove(s.b.cg.dir(path))
	}
}

// CgroupDir is the host path of the sandbox's cgroup, once known.
func (s *Sandbox) CgroupDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cgroupPath == "" {
		return ""
	}
	return s.b.cg.dir(s.cgroupPath)
}

// stoppedNow asks runsc directly and marks the sandbox exited if it has
// stopped or disappeared.
func (s *Sandbox) stoppedNow() bool {
	status, _, err := s.state()
	// Only runsc saying "stopped", or that the container is gone, counts.
	// Treating any error as stopped (as this did until Day 23) marked a
	// still-running sandbox exited when one `runsc state` call failed under
	// load: its shutdown then skipped the kill and the delete, and the next
	// restore under its ID was refused ("in state running").
	if errors.Is(err, errGone) || (err == nil && status == "stopped") {
		s.markExited()
		return true
	}
	return false
}

// markExited closes Exited once, first noting why the sandbox stopped if
// the out-of-memory killer was involved. The cgroup outlives the sandbox
// until runsc deletes it, so its memory.events can still be read here.
func (s *Sandbox) markExited() {
	s.exitedOnce.Do(func() {
		s.mu.Lock()
		if s.cgroupPath != "" {
			s.exitReason = exitReason(s.b.cg.dir(s.cgroupPath))
		}
		// The cgroup may already be gone, or its counters silent: fall back
		// on what the watcher last saw. Within a few threads of the limit
		// counts, because the last sample can be up to a tick old.
		if s.exitReason == "" && s.lastPidsMax > 0 && s.lastPids >= s.lastPidsMax-4 {
			s.exitReason = hostThreadReason(s.lastPidsMax) + fmt.Sprintf(" (last seen at %d)", s.lastPids)
		}
		s.mu.Unlock()
		close(s.exited)
	})
}

// ExitReason says why the sandbox stopped on its own, if known.
func (s *Sandbox) ExitReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exitReason
}

// watch polls runsc until the sandbox stops or disappears. Along the way
// it learns the sandbox's cgroup, which is needed to explain an
// out-of-memory death after the sandbox's process is gone.
func (s *Sandbox) watch() {
	t := time.NewTicker(s.b.cfg.PollEvery)
	defer t.Stop()
	for range t.C {
		status, pid, err := s.state()
		if err != nil || status == "stopped" {
			s.markExited()
			return
		}
		s.learnCgroup(pid)
		s.samplePids()
	}
}

// samplePids records the sandbox's host thread count and limit.
func (s *Sandbox) samplePids() {
	s.mu.Lock()
	path := s.cgroupPath
	s.mu.Unlock()
	if path == "" {
		return
	}
	dir := s.b.cg.dir(path)
	cur, ok1, _ := readStat(dir, "pids.current")
	max, ok2, _ := readStat(dir, "pids.max")
	if ok1 && ok2 {
		s.mu.Lock()
		s.lastPids, s.lastPidsMax = cur, max
		s.mu.Unlock()
	}
}

func (s *Sandbox) learnCgroup(pid int) {
	if pid <= 0 {
		return
	}
	s.mu.Lock()
	known := s.cgroupPath != ""
	s.mu.Unlock()
	if known {
		return
	}
	if path, err := s.b.cg.pathOf(pid); err == nil {
		s.mu.Lock()
		s.cgroupPath = path
		limit := s.memLimit
		s.mu.Unlock()
		if limit > 0 {
			_ = setMemoryHigh(s.b.cg.dir(path), int64(float64(limit)*memoryHighFraction))
		}
	}
}

func (s *Sandbox) status() (string, error) {
	st, _, err := s.state()
	return st, err
}

// state asks runsc for the sandbox's status and its host PID: the PID of
// the gVisor sandbox process, whose cgroup holds everything it costs.
func (s *Sandbox) state() (string, int, error) { return s.b.containerState(s.id) }

// errGone is runsc saying a container doesn't exist: deleted, or never
// made. Any other failure to read its state means "unknown", never "gone".
var errGone = errors.New("gvisor: no such container")

// containerState asks runsc for a container's status and PID.
func (b *Backend) containerState(id string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := b.command(ctx, "state", id).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "does not exist") {
			return "", 0, errGone
		}
		return "", 0, err // a timeout, a busy runsc: unknown
	}
	var st struct {
		Status string `json:"status"`
		Pid    int    `json:"pid"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return "", 0, fmt.Errorf("parse runsc state: %w", err)
	}
	return st.Status, st.Pid, nil
}

// Stats reads the sandbox's resource use from its cgroup on the host.
func (s *Sandbox) Stats(ctx context.Context) (sandbox.Stats, error) {
	select {
	case <-s.exited:
		return sandbox.Stats{}, sandbox.ErrExited
	default:
	}
	if s.b.cfg.Rootless {
		return sandbox.Stats{}, fmt.Errorf("gvisor: no cgroup in rootless mode: %w", sandbox.ErrUnsupported)
	}
	// Fast path: once the cgroup is known, read it directly. The memory
	// guard polls every 100 ms, and spawning `runsc state` that often
	// would cost more than the guard saves.
	s.mu.Lock()
	path := s.cgroupPath
	s.mu.Unlock()
	if path == "" {
		status, pid, err := s.state()
		if err != nil {
			return sandbox.Stats{}, err
		}
		if status == "stopped" || pid <= 0 {
			return sandbox.Stats{}, sandbox.ErrExited
		}
		s.learnCgroup(pid)
		s.mu.Lock()
		path = s.cgroupPath
		s.mu.Unlock()
		if path == "" {
			_, err := s.b.cg.pathOf(pid)
			return sandbox.Stats{}, err
		}
	}
	return readStats(s.b.cg.dir(path), path)
}

// Reclaim asks the agent to kill the process using the most memory.
func (s *Sandbox) Reclaim(ctx context.Context) (sandbox.Reclaimed, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.Reclaimed{}, err
	}
	return c.Reclaim(ctx)
}

func tail(b []byte, n int) []byte {
	b = bytes.TrimSpace(b)
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return b
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Reap force-stops and deletes a sandbox this process holds no handle for,
// such as one a previous daemon left running. It's best effort: a sandbox
// that's already gone is simply cleaned up.
func (b *Backend) Reap(ctx context.Context, id string) error {
	if err := sandbox.ValidateID(id); err != nil {
		return err
	}
	_, _ = b.runQuiet(ctx, "kill", id, "KILL")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out, err := b.command(ctx, "state", id).Output()
		if err != nil {
			break // runsc no longer knows it
		}
		var st struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(out, &st) == nil && st.Status == "stopped" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, _ = b.runQuiet(ctx, "delete", id)
	return os.RemoveAll(filepath.Join(b.cfg.StateDir, "bundles", id))
}

// Checkpoint saves the sandbox's whole state (memory, processes, open
// files, terminals, the memory-backed /tmp) as an image in opts.Dir, with
// `runsc checkpoint`. Without opts.LeaveRunning the sandbox then stops.
//
// First the sandbox is quiesced. The agent's connection to the host is a
// host file descriptor, and a live connection to the outside can't be
// saved into an image. So: stop accepting (the agent's redials now fail at
// once, leaving nothing open), ask the agent to let go, and wait until it
// has. After the checkpoint, if the sandbox runs on, listen again and the
// agent reconnects by itself. If anything fails partway, listen again too:
// the sandbox must not be left running but unreachable.
func (s *Sandbox) Checkpoint(ctx context.Context, opts sandbox.CheckpointOptions) (sandbox.CheckpointResult, error) {
	start := time.Now()
	select {
	case <-s.exited:
		return sandbox.CheckpointResult{}, sandbox.ErrExited
	default:
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return sandbox.CheckpointResult{}, err
	}
	ln := s.listener()
	path := ""
	if ln != nil {
		path = ln.Path()
	}
	// Every checkpoint quiesces, snapshots included. Days 10 and 11 showed
	// that runsc checkpoints a live connection and that a *restored copy*
	// reconnects; Day 14 v1 concluded snapshots could skip the quiesce. Real
	// gVisor proved otherwise: after an unquiesced snapshot the *source's*
	// connection is dead on the host side while the agent inside never
	// notices, so it never redials, and the sandbox is unreachable for
	// good. Neither earlier probe had looked at the source.
	quiesced := false
	if ln != nil && !s.b.skipQuiesce {
		quiesced = true
		_ = ln.StopAccepting()
		if c := ln.Current(); c != nil {
			qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.Quiesce(qctx)
			cancel()
			if err != nil {
				s.relisten(path)
				return sandbox.CheckpointResult{}, fmt.Errorf("gvisor: quiesce the agent: %w", err)
			}
		}
	}

	args := []string{"checkpoint", "--image-path=" + opts.Dir}
	if opts.LeaveRunning {
		args = append(args, "--leave-running")
	}
	if supported, _ := s.b.direct(); supported {
		used := int64(-1) // unknown: be safe
		if dir := s.CgroupDir(); dir != "" {
			if v, ok, _ := readStat(dir, "memory.current"); ok {
				used = v
			}
		}
		if s.b.useDirect(true, used, s.memLimit) {
			args = append(args, "--direct") // the image's write isn't charged to the sandbox
		}
	}
	// runQuiet's error already names the command and carries its output.
	if _, err := s.b.runQuiet(ctx, append(args, s.id)...); err != nil {
		// Say plainly if the sandbox was killed for memory during it.
		if dir := s.CgroupDir(); dir != "" {
			if why := exitReason(dir); why != "" {
				err = fmt.Errorf("%w; the sandbox was %s during the checkpoint", err, why)
			}
		}
		if quiesced && !s.stoppedNow() {
			s.relisten(path)
		}
		return sandbox.CheckpointResult{}, fmt.Errorf("gvisor: %w", err)
	}
	// Measured now, before our own additions: the size of what runsc
	// saved, i.e. what the sandbox holds, comparable across checkpoints.
	imageBytes := dirSize(opts.Dir)
	// The spec travels with the image: a restore needs the same process,
	// mounts and limits. So does the agent binary: a restored agent resumes
	// mid-execution, partly from code pages gVisor reads back from that
	// file. If the file had been rebuilt in the meantime, the restored
	// agent would run a mix of old and new code.
	if raw, err := os.ReadFile(filepath.Join(s.bundle, "config.json")); err == nil {
		_ = os.WriteFile(filepath.Join(opts.Dir, "config.json"), raw, 0o600)
	}
	if bin := filepath.Join(s.bundle, "sbx", agentBinary); fileExists(bin) {
		if err := copyFile(bin, filepath.Join(opts.Dir, agentBinary), 0o700); err != nil {
			if quiesced && !s.stoppedNow() {
				s.relisten(path)
			}
			return sandbox.CheckpointResult{}, fmt.Errorf("gvisor: save the agent binary with the image: %w", err)
		}
	}
	res := sandbox.CheckpointResult{ImageBytes: imageBytes, Duration: time.Since(start)}
	if opts.LeaveRunning {
		if quiesced {
			s.relisten(path)
		}
		return res, nil
	}
	// runsc stops the sandbox once its state is saved. If it hasn't by the
	// deadline, kill it: the state is saved, and a paused sandbox must not
	// still be running (its next restore would be refused).
	wait := s.b.cfg.StopWait
	if wait <= 0 {
		wait = 10 * time.Second
	}
	stopped := false
	for deadline := time.Now().Add(wait); ; {
		if stopped = s.stoppedNow(); stopped || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !stopped {
		_, _ = s.b.runQuiet(ctx, "kill", s.id, "KILL")
		deadline := time.Now().Add(5 * time.Second)
		for !s.stoppedNow() && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if !s.stoppedNow() {
			return res, fmt.Errorf("gvisor: sandbox %s still running %s after its checkpoint, even after SIGKILL", s.id, wait)
		}
	}
	return res, nil
}

// relisten puts a fresh listener at the agent's socket path. The old one
// goes first: closing it removes the socket file, which would delete the
// new one's file if done after.
func (s *Sandbox) relisten(path string) {
	if old := s.listener(); old != nil {
		old.Close()
	}
	ln, err := agent.Listen(path, s.id)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.agentLn = ln
	s.mu.Unlock()
}

func dirSize(dir string) int64 {
	var n int64
	_ = filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			n += fi.Size()
		}
		return nil
	})
	return n
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Restore brings a sandbox back from a checkpoint image, under the ID it
// had, with `runsc restore`.
//
// The image refers to host files by path: the bundle's own files, the
// /sbx mount, the rootfs. So the bundle is rebuilt at exactly the path it
// had, from the saved config.json, with the agent binary saved alongside
// the image, not whichever agent is current. The rootfs must be unchanged:
// files the sandbox only read are read again from it.
//
// The agent comes back mid-execution, in its redial loop (it let go of its
// connection during the quiesce), so the listener goes up first and the
// agent finds it on its next attempt.
func (b *Backend) Restore(ctx context.Context, id, imageDir string) (sandbox.Sandbox, error) {
	if err := sandbox.ValidateID(id); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(imageDir, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("gvisor: the image has no spec: %w", err)
	}
	var spec ociSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("gvisor: the image's spec: %w", err)
	}
	if !fileExists(spec.Root.Path) {
		return nil, fmt.Errorf("gvisor: the image's rootfs %s is gone", spec.Root.Path)
	}
	var memLimit int64
	if r := spec.Linux.Resources; r != nil && r.Memory != nil {
		memLimit = r.Memory.Limit
	}

	bundle := filepath.Join(b.cfg.StateDir, "bundles", id)
	// The agent inside the image says who it was started as. Restored under
	// another ID, this is a fork: its spec must be its own (3.2 of Day 14),
	// and its listener must accept the identity the agent will truthfully
	// give, the original's.
	agentID := agentIDOf(&spec)
	if agentID == "" {
		agentID = id
	}
	if agentID != id {
		b.forkSpec(&spec, id, filepath.Join(bundle, "sbx"))
		if raw, err = json.Marshal(&spec); err != nil {
			return nil, err
		}
	}
	_ = os.RemoveAll(bundle) // a leftover from the checkpoint, or a failed restore
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		return nil, err
	}
	sb := &Sandbox{b: b, id: id, bundle: bundle, exited: make(chan struct{}), memLimit: memLimit}
	fail := func(err error) (sandbox.Sandbox, error) {
		if ln := sb.listener(); ln != nil {
			ln.Close()
		}
		_ = os.RemoveAll(bundle)
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), raw, 0o644); err != nil {
		return fail(err)
	}
	if b.cfg.AgentPath != "" {
		agentDir := filepath.Join(bundle, "sbx")
		if err := os.MkdirAll(agentDir, 0o755); err != nil {
			return fail(err)
		}
		bin := filepath.Join(imageDir, agentBinary)
		if !fileExists(bin) {
			// An image from before Day 11 has no copy: fall back to the
			// current agent, which is only safe if it hasn't been rebuilt.
			bin = b.cfg.AgentPath
		}
		if err := copyFile(bin, filepath.Join(agentDir, agentBinary), 0o755); err != nil {
			return fail(fmt.Errorf("gvisor: install the image's agent: %w", err))
		}
		ln, err := agent.Listen(filepath.Join(agentDir, agentSocket), agentID)
		if err != nil {
			return fail(err)
		}
		sb.agentLn = ln
	}
	logPath := filepath.Join(bundle, "runsc-restore.log")
	// A networked sandbox comes back networked: its image's spec names the
	// namespace, which the daemon has made sure exists (Day 16).
	rargs := []string{"restore", "--detach", "--bundle", bundle, "--image-path=" + imageDir}
	if _, supported := b.direct(); b.useDirect(supported, dirSize(imageDir), memLimit) {
		rargs = append(rargs, "--direct") // reading the image fills no page cache charged to the sandbox
	}
	restore := func() error { return b.runToFile(ctx, logPath, networkMode(&spec), append(rargs, id)...) }
	err = restore()
	// A restore is asked for because the sandbox is paused, so a container
	// still registered under its ID is stale (one that never finished
	// stopping, say). runsc refuses; clear it and try once more. Only then:
	// checking first would cost every restore a runsc call.
	if err != nil && (strings.Contains(err.Error(), "in state") || strings.Contains(err.Error(), "already exists")) {
		_, _ = b.runQuiet(ctx, "delete", "--force", id)
		if _, _, serr := b.containerState(id); !errors.Is(serr, errGone) {
			return fail(fmt.Errorf("gvisor: a stale container %s is registered and couldn't be deleted (%v): %w", id, serr, err))
		}
		err = restore()
	}
	if err != nil {
		return fail(err)
	}
	go sb.watch()
	return sb, nil
}

// Adopt takes charge of a sandbox a previous daemon left running. gVisor
// sandboxes are independent processes (`runsc run --detach`), so a daemon
// crash doesn't stop them: only the agent's connection drops, and the agent
// falls back into its redial loop. Adopting means confirming with runsc that
// the sandbox really runs, rebuilding the handle from the bundle still on
// disk, and listening again so the agent reconnects. Nothing inside stops.
func (b *Backend) Adopt(ctx context.Context, id string) (sandbox.Sandbox, error) {
	if err := sandbox.ValidateID(id); err != nil {
		return nil, err
	}
	bundle := filepath.Join(b.cfg.StateDir, "bundles", id)
	raw, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("gvisor: no bundle for %s: %w", id, err)
	}
	var spec ociSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("gvisor: %s's spec: %w", id, err)
	}
	var memLimit int64
	if r := spec.Linux.Resources; r != nil && r.Memory != nil {
		memLimit = r.Memory.Limit
	}
	sb := &Sandbox{b: b, id: id, bundle: bundle, exited: make(chan struct{}), memLimit: memLimit}
	status, pid, err := sb.state()
	if err != nil || status != "running" || pid <= 0 {
		return nil, fmt.Errorf("gvisor: %s is not running (runsc state %q, pid %d, %v): %w", id, status, pid, err, sandbox.ErrExited)
	}
	if fileExists(filepath.Join(bundle, "sbx", agentBinary)) {
		// Listen replaces the dead daemon's socket file.
		ln, err := agent.Listen(filepath.Join(bundle, "sbx", agentSocket), id)
		if err != nil {
			return nil, err
		}
		sb.agentLn = ln
	}
	go sb.watch()
	return sb, nil
}

// Release lets go of a running sandbox without stopping it: the agent's
// listener closes, as it would if this daemon died, and the agent falls
// back to redialing until another daemon adopts the sandbox.
func (s *Sandbox) Release() {
	if ln := s.listener(); ln != nil {
		ln.Close()
	}
}

// agentIDOf reads the sandbox ID the image's agent was started with: the
// value after -id in its command line.
func agentIDOf(spec *ociSpec) string {
	args := spec.Process.Args
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-id" {
			return args[i+1]
		}
	}
	return ""
}

// forkSpec makes a checkpoint's spec a fork's own. Restored unchanged, the
// fork would share the original's cgroup (its memory and CPU limits!) and
// mount the original's agent directory, socket included. The process
// arguments stay as they were: they describe the agent already running in
// the image, which a restore doesn't start again.
func (b *Backend) forkSpec(spec *ociSpec, id, agentDir string) {
	if spec.Linux.CgroupsPath != "" {
		spec.Linux.CgroupsPath = b.cfg.CgroupParent + "/" + id
	}
	for i := range spec.Mounts {
		if spec.Mounts[i].Destination == agentMountPoint {
			spec.Mounts[i].Source = agentDir
		}
	}
	spec.Hostname = hostnameFor(id)
	// Its own network (Day 19): the image names the source's namespace; the
	// daemon has built one for the fork, by the network package's naming.
	for i := range spec.Linux.Namespaces {
		if spec.Linux.Namespaces[i].Type == "network" && spec.Linux.Namespaces[i].Path != "" {
			spec.Linux.Namespaces[i].Path = netns.Path(id)
		}
	}
}

// SetIdentity renames the agent, then has the listener expect the new name:
// in that order, so a reconnect in between is refused once (and retried by
// the agent) rather than the listener refusing the agent's next hello for
// good.
func (s *Sandbox) SetIdentity(ctx context.Context, id, generation string) (string, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return "", err
	}
	ack, err := c.SetIdentity(ctx, id, generation)
	if err != nil {
		return "", err
	}
	if ln := s.listener(); ln != nil {
		ln.Expect(id)
	}
	return ack.Previous, nil
}
