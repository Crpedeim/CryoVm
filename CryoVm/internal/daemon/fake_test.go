package daemon

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Crpedeim/sbx/internal/agent"
	"github.com/Crpedeim/sbx/internal/guest"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

// fakeBackend is a test backend with no isolation at all: each "sandbox" is
// the real guest agent running inside the test process, so commands and
// files act on the host. That's enough to test everything the daemon adds
// (states, history, HTTP, streaming) without needing gVisor.
type fakeBackend struct {
	mu          sync.Mutex
	failCreate  error
	failRestore error
	restoreTook time.Duration // each restore takes this long (Day 23: fork's concurrency)
	restores    int
	reaped      []string
	created     map[string]*fakeSandbox
	specs       map[string]sandbox.Spec // what each Create was asked for
}

func newFakeBackend() *fakeBackend { return &fakeBackend{created: map[string]*fakeSandbox{}} }

func (b *fakeBackend) Name() string { return "fake" }

func (b *fakeBackend) Create(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	b.mu.Lock()
	fail := b.failCreate
	if b.specs == nil {
		b.specs = map[string]sandbox.Spec{}
	}
	b.specs[spec.ID] = spec
	b.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	dir, err := os.MkdirTemp("", "fk") // short: Unix socket paths are limited
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "agent.sock")
	ln, err := agent.Listen(sock, spec.ID)
	if err != nil {
		return nil, err
	}
	gctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// LogDir inside the temp dir: the default, /var/log/sbx, is only
		// writable by root, and tests must pass for any user.
		_ = guest.Run(gctx, guest.Config{SandboxID: spec.ID, Dial: "unix:" + sock, LogDir: filepath.Join(dir, "logs"), Logf: func(string, ...any) {}})
	}()
	s := &fakeSandbox{id: spec.ID, ln: ln, stop: stop, guestDone: done, dir: dir, exited: make(chan struct{})}
	b.mu.Lock()
	b.created[spec.ID] = s
	b.mu.Unlock()
	return s, nil
}

func (b *fakeBackend) Reap(_ context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reaped = append(b.reaped, id)
	return nil
}

func (b *fakeBackend) get(id string) *fakeSandbox {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.created[id]
}

type fakeSandbox struct {
	id        string
	ln        *agent.Listener
	stop      context.CancelFunc
	guestDone chan struct{}
	dir       string
	exited    chan struct{}
	once      sync.Once

	mu             sync.Mutex
	reason         string
	memory         int64
	reclaims       int
	failCheckpoint error
	cpu            time.Duration // CPU time used so far: a test can make it busy
	cleanupDelay   time.Duration // how long Shutdown's cleanup takes
	cleanedUp      bool
}

func (s *fakeSandbox) end() {
	s.once.Do(func() {
		s.stop()
		<-s.guestDone
		s.ln.Close()
		os.RemoveAll(s.dir)
		close(s.exited)
	})
}

// crash simulates the sandbox dying on its own.
func (s *fakeSandbox) crash() { s.end() }

// crashWith simulates dying for a known reason, like the OOM killer.
func (s *fakeSandbox) crashWith(reason string) {
	s.mu.Lock()
	s.reason = reason
	s.mu.Unlock()
	s.end()
}

func (s *fakeSandbox) ExitReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

// Stats returns fixed numbers, except memory, which a test can set to
// push the memory guard into action.
func (s *fakeSandbox) Stats(context.Context) (sandbox.Stats, error) {
	select {
	case <-s.exited:
		return sandbox.Stats{}, sandbox.ErrExited
	default:
	}
	s.mu.Lock()
	mem, cpu := s.memory, s.cpu
	s.mu.Unlock()
	if mem == 0 {
		mem = 64 << 20
	}
	return sandbox.Stats{Cgroup: "/sbx/" + s.id, MemoryBytes: mem, MemoryLimit: 256 << 20,
		CPUUsage: 1500*time.Millisecond + cpu, CPUQuota: 1, CPUs: "0", Pids: 7, PidsLimit: 512}, nil
}

func (s *fakeSandbox) setMemory(n int64) {
	s.mu.Lock()
	s.memory = n
	s.mu.Unlock()
}

// Reclaim pretends to kill a hog, and brings memory back down.
func (s *fakeSandbox) Reclaim(context.Context) (sandbox.Reclaimed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reclaims++
	s.memory = 64 << 20
	return sandbox.Reclaimed{Killed: true, PID: 42, Command: "tail", RSS: 200 << 20}, nil
}

func (s *fakeSandbox) reclaimCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reclaims
}

func (s *fakeSandbox) ID() string              { return s.id }
func (s *fakeSandbox) Exited() <-chan struct{} { return s.exited }
func (s *fakeSandbox) Shutdown(context.Context, time.Duration) error {
	s.end()
	s.mu.Lock()
	delay := s.cleanupDelay
	s.mu.Unlock()
	time.Sleep(delay) // a slow cleanup (runsc delete, removing the bundle)
	s.mu.Lock()
	s.cleanedUp = true
	s.mu.Unlock()
	return nil
}

func (s *fakeSandbox) wasCleanedUp() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanedUp
}

func (s *fakeSandbox) Agent(ctx context.Context) (*agent.Conn, error) { return s.ln.Conn(ctx) }

func (s *fakeSandbox) conn(ctx context.Context) (*agent.Conn, error) {
	select {
	case <-s.exited:
		return nil, sandbox.ErrExited
	default:
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.ln.Conn(wctx)
}

func (s *fakeSandbox) Exec(ctx context.Context, req sandbox.ExecRequest) (sandbox.ExecResult, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.ExecResult{ExitCode: -1}, err
	}
	var stdin []byte
	if req.Stdin != nil {
		stdin, _ = io.ReadAll(req.Stdin)
	}
	res, err := c.Exec(ctx, agent.ExecRequest{Args: req.Args, Env: req.Env, Dir: req.Dir, Stdin: stdin,
		Timeout: req.Timeout, Stdout: req.Stdout, Stderr: req.Stderr})
	return sandbox.ExecResult{ExitCode: res.ExitCode, Signal: res.Signal, TimedOut: res.TimedOut}, err
}

func (s *fakeSandbox) WriteFile(ctx context.Context, p string, r io.Reader, o sandbox.WriteOptions) (sandbox.TransferResult, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.TransferResult{}, err
	}
	return c.WriteFile(ctx, p, r, o)
}

func (s *fakeSandbox) ReadFile(ctx context.Context, p string, w io.Writer) (sandbox.TransferResult, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.TransferResult{}, err
	}
	return c.ReadFile(ctx, p, w)
}

func (s *fakeSandbox) ListDir(ctx context.Context, p string) (sandbox.ListResult, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.ListResult{}, err
	}
	return c.ListDir(ctx, p)
}

func (s *fakeSandbox) Stat(ctx context.Context, p string) (sandbox.FileInfo, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.FileInfo{}, err
	}
	return c.Stat(ctx, p)
}

func (s *fakeSandbox) OpenShell(ctx context.Context, o sandbox.ShellOptions) (*agent.Shell, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	return c.OpenShell(ctx, o)
}

func (s *fakeSandbox) Sessions(ctx context.Context) (sandbox.SessionList, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.SessionList{}, err
	}
	return c.Sessions(ctx)
}

func (s *fakeSandbox) KillSession(ctx context.Context, id string) error {
	c, err := s.conn(ctx)
	if err != nil {
		return err
	}
	return c.KillSession(ctx, id)
}

func (s *fakeSandbox) StartProcess(ctx context.Context, req sandbox.ProcStart) (sandbox.ProcStarted, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.ProcStarted{}, err
	}
	return c.StartProcess(ctx, req)
}

func (s *fakeSandbox) Processes(ctx context.Context) ([]sandbox.ProcInfo, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	return c.Processes(ctx)
}

func (s *fakeSandbox) Signal(ctx context.Context, id string, sig int) error {
	c, err := s.conn(ctx)
	if err != nil {
		return err
	}
	return c.Signal(ctx, id, sig)
}

func (s *fakeSandbox) Wait(ctx context.Context, id string) (sandbox.ProcInfo, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.ProcInfo{}, err
	}
	return c.Wait(ctx, id)
}

func (s *fakeSandbox) Logs(ctx context.Context, id string, offset int64, follow bool, w io.Writer) (sandbox.LogsEnd, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return sandbox.LogsEnd{}, err
	}
	return c.Logs(ctx, id, offset, follow, w)
}

func (s *fakeSandbox) RemoveProcess(ctx context.Context, id string) error {
	c, err := s.conn(ctx)
	if err != nil {
		return err
	}
	return c.RemoveProcess(ctx, id)
}

// Checkpoint in the fake writes a stand-in image and, unless left running,
// ends the sandbox the way runsc stops a checkpointed one.
func (s *fakeSandbox) Checkpoint(ctx context.Context, opts sandbox.CheckpointOptions) (sandbox.CheckpointResult, error) {
	s.mu.Lock()
	fail := s.failCheckpoint
	s.mu.Unlock()
	if fail != nil {
		return sandbox.CheckpointResult{}, fail
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return sandbox.CheckpointResult{}, err
	}
	img := []byte("fake checkpoint image of " + s.id)
	if err := os.WriteFile(filepath.Join(opts.Dir, "checkpoint.img"), img, 0o600); err != nil {
		return sandbox.CheckpointResult{}, err
	}
	if !opts.LeaveRunning {
		s.end()
	}
	return sandbox.CheckpointResult{ImageBytes: int64(len(img)), Duration: time.Millisecond}, nil
}

// Restore in the fake starts a fresh fake sandbox from a stand-in image.
// It can't bring memory back, but it exercises everything the daemon does
// around a restore.
func (b *fakeBackend) Restore(ctx context.Context, id, imageDir string) (sandbox.Sandbox, error) {
	b.mu.Lock()
	fail, took := b.failRestore, b.restoreTook
	b.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	time.Sleep(took)
	if _, err := os.Stat(filepath.Join(imageDir, "checkpoint.img")); err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.restores++
	b.mu.Unlock()
	return b.Create(ctx, sandbox.Spec{ID: id})
}

// Adopt in the fake hands back a sandbox this backend created that hasn't
// ended: the stand-in for "runsc says it's still running".
func (b *fakeBackend) Adopt(_ context.Context, id string) (sandbox.Sandbox, error) {
	b.mu.Lock()
	sb := b.created[id]
	b.mu.Unlock()
	if sb == nil {
		return nil, fmt.Errorf("fake: %s is not running: %w", id, sandbox.ErrExited)
	}
	select {
	case <-sb.exited:
		return nil, fmt.Errorf("fake: %s has stopped: %w", id, sandbox.ErrExited)
	default:
	}
	return sb, nil
}

// burnCPU adds CPU time, as if the sandbox were computing.
func (s *fakeSandbox) burnCPU(d time.Duration) {
	s.mu.Lock()
	s.cpu += d
	s.mu.Unlock()
}

// SetIdentity in the fake goes to its in-process agent, as for real.
func (s *fakeSandbox) SetIdentity(ctx context.Context, id, generation string) (string, error) {
	c, err := s.conn(ctx)
	if err != nil {
		return "", err
	}
	ack, err := c.SetIdentity(ctx, id, generation)
	if err != nil {
		return "", err
	}
	s.ln.Expect(id)
	return ack.Previous, nil
}

// fakeNet stands in for the host's network namespaces: tests run without
// root. It records what it's asked to do, and can be told to fail.
type fakeNet struct {
	mu         sync.Mutex
	nets       map[string]int // id → slot
	prepared   int
	setups     []string
	teardowns  []string
	refreshes  []string
	failSetup  error
	onTeardown func(id string) // a test's look at the moment of teardown
}

func newFakeNet() *fakeNet { return &fakeNet{nets: map[string]int{}} }

func (f *fakeNet) PrepareHost(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepared++
	return nil
}

func (f *fakeNet) Setup(_ context.Context, id string, slot int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSetup != nil {
		return f.failSetup
	}
	f.nets[id] = slot
	f.setups = append(f.setups, fmt.Sprintf("%s@%d", id, slot))
	return nil
}

func (f *fakeNet) Teardown(_ context.Context, id string, slot int) error {
	f.mu.Lock()
	hook := f.onTeardown
	delete(f.nets, id)
	f.teardowns = append(f.teardowns, id)
	f.mu.Unlock()
	if hook != nil {
		hook(id)
	}
	return nil
}

func (f *fakeNet) Exists(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.nets[id]
	return ok
}

func (f *fakeNet) Owners() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id := range f.nets {
		out = append(out, id)
	}
	return out
}

func (f *fakeNet) Path(id string) string { return "/fake/netns/sbx-" + id }

func (f *fakeNet) Refresh(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes = append(f.refreshes, id)
	return nil
}

func (f *fakeNet) InsideState(context.Context, string) string { return "fake" }

func (f *fakeNet) tornDown(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.teardowns {
		if t == id {
			return true
		}
	}
	return false
}
