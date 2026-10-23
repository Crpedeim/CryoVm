// Package daemon is the long-running host service: it owns the backend,
// records every sandbox in the registry, and serves the HTTP API.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Crpedeim/sbx/internal/netns"
	"github.com/Crpedeim/sbx/internal/proxy"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Crpedeim/sbx/internal/agent"
	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/registry"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

// ErrInvalid marks a request the caller got wrong.
var ErrInvalid = errors.New("invalid request")

// Reaper is implemented by backends that can clean up a sandbox they no
// longer hold a handle to, such as one left running by a previous daemon.
type Reaper interface {
	Reap(ctx context.Context, id string) error
}

type Config struct {
	Backend  sandbox.Backend
	Registry *registry.Registry

	// Defaults for create requests that leave these out.
	Rootfs  string
	Kernel  string // Firecracker only
	VCPUs   int
	MemMiB  int
	PidsMax int // 0 means no default limit

	// The memory guard checks each sandbox every GuardInterval (default
	// 100 ms; negative turns it off). At GuardAt of the memory limit
	// (default 0.85) it asks the agent to kill the process using the most
	// memory, so one runaway process doesn't make the kernel's OOM killer
	// end the whole sandbox.
	GuardInterval time.Duration
	GuardAt       float64

	// Lifetimes. DefaultTTL applies to sandboxes created without one (0:
	// none); DefaultIdle likewise (0: none). LifetimeEvery is how often
	// deadlines are checked (default 1 s).
	DefaultTTL    time.Duration
	DefaultIdle   time.Duration
	LifetimeEvery time.Duration

	// DefaultIdleAction is what the idle timeout does when a sandbox
	// doesn't say: api.IdlePause or api.IdleDestroy (the library default,
	// Day 9's behavior; sbxd defaults to pause). IdleCPU is the CPU use, in
	// cores, above which a sandbox counts as busy even with no API calls
	// (default 0.05): a long build isn't idle.
	DefaultIdleAction string
	IdleCPU           float64

	// OnStop is what Close does with running sandboxes: OnStopDestroy (the
	// default), OnStopPause or OnStopLeave.
	OnStop string

	// Net builds sandboxes' networks (Day 16). Default: the host's real
	// namespaces, through the netns package, with Egress and ProxyPort.
	Net Networker
	// Egress is what networked sandboxes may reach (Day 17): "deny" (the
	// default: only the egress proxy, at 10.89.0.1:ProxyPort inside) or
	// "open" (anything: Day 16's behavior, for debugging).
	Egress    string
	ProxyPort int

	// Images are named sandbox kinds (Day 20): `create -image browser`
	// picks a rootfs, memory, network and egress policy in one word.
	Images map[string]Image

	// Store keeps checkpoint images off this machine (the S3 snapshot
	// store); nil means local disk only. With StoreEvict, the local copy is
	// deleted once the store has it, and fetched again when needed.
	Store      SnapshotStore
	StoreEvict bool

	// CheckpointDir holds checkpoint images, as <dir>/<sandbox>/<checkpoint>/.
	// Default /var/lib/sbx/checkpoints.
	CheckpointDir string

	AgentWait     time.Duration // how long a new sandbox's agent may take to connect
	ShutdownGrace time.Duration
	Logf          func(format string, args ...any)
}

// Manager ties the registry's state machine to the backend's sandboxes.
// The registry is the source of truth for *state*; the live map holds the
// handles needed to *act* on running sandboxes.
type Manager struct {
	cfg  Config
	reg  *registry.Registry
	mu   sync.Mutex
	live map[string]sandbox.Sandbox

	actMu sync.Mutex
	act   map[string]*activity

	stopLifetimes chan struct{}
	closeOnce     sync.Once

	wakeMu sync.Mutex
	waking map[string]chan struct{} // closed when that sandbox's wake finishes

	netOnce sync.Once // the host is prepared for networks once, on first use
	netErr  error

	proxy *proxy.Proxy // the egress proxy, once started (Day 18)

	crashHook func(point string) // tests only: stop here, as a kill -9 would
}

// New creates a Manager. Sandboxes a previous daemon left in a non-final
// state can't be re-attached yet (that's Day 12), so they're reaped if the
// backend knows how, and marked failed either way.
func New(ctx context.Context, cfg Config) (*Manager, error) {
	if cfg.VCPUs == 0 {
		cfg.VCPUs = 1
	}
	if cfg.MemMiB == 0 {
		cfg.MemMiB = 256
	}
	if cfg.GuardInterval == 0 {
		cfg.GuardInterval = 100 * time.Millisecond
	}
	if cfg.GuardAt == 0 {
		cfg.GuardAt = 0.85
	}
	switch cfg.OnStop {
	case "":
		cfg.OnStop = OnStopDestroy
	case OnStopDestroy, OnStopPause, OnStopLeave:
	default:
		return nil, fmt.Errorf("%w: unknown stop policy %q (want destroy, pause or leave)", ErrInvalid, cfg.OnStop)
	}
	switch cfg.Egress {
	case "":
		cfg.Egress = netns.EgressDeny
	case netns.EgressDeny, netns.EgressOpen:
	default:
		return nil, fmt.Errorf("%w: unknown egress mode %q (want deny or open)", ErrInvalid, cfg.Egress)
	}
	if cfg.ProxyPort == 0 {
		cfg.ProxyPort = netns.DefaultProxyPort
	}
	if cfg.Net == nil {
		cfg.Net = hostNetwork{netns.Policy{Egress: cfg.Egress, ProxyPort: cfg.ProxyPort}}
	}
	if cfg.CheckpointDir == "" {
		cfg.CheckpointDir = "/var/lib/sbx/checkpoints"
	}
	switch cfg.DefaultIdleAction {
	case "":
		cfg.DefaultIdleAction = api.IdleDestroy
	case api.IdleDestroy, api.IdlePause:
	default:
		return nil, fmt.Errorf("%w: unknown idle action %q (want pause or destroy)", ErrInvalid, cfg.DefaultIdleAction)
	}
	if cfg.IdleCPU == 0 {
		cfg.IdleCPU = 0.05
	}
	if cfg.LifetimeEvery == 0 {
		cfg.LifetimeEvery = time.Second
	}
	if cfg.AgentWait == 0 {
		cfg.AgentWait = 30 * time.Second
	}
	if cfg.ShutdownGrace == 0 {
		cfg.ShutdownGrace = 5 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	m := &Manager{cfg: cfg, reg: cfg.Registry, live: map[string]sandbox.Sandbox{},
		act: map[string]*activity{}, stopLifetimes: make(chan struct{}), waking: map[string]chan struct{}{}}

	if err := m.reconcile(ctx); err != nil {
		return nil, err
	}
	m.sweepNetworks(ctx)
	m.sweepCheckpoints(ctx)
	go m.lifetimes(m.stopLifetimes)
	return m, nil
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "sbx-" + hex.EncodeToString(b)
}

// Create records the sandbox, starts it, waits for its agent if it has one,
// and only then marks it running: "running" means ready to use.
func (m *Manager) Create(ctx context.Context, req api.CreateRequest) (rec registry.Sandbox, err error) {
	start := time.Now()
	defer func() {
		detail := fmt.Sprintf("vcpus=%d mem=%dMiB pids=%d ttl=%s idle=%s", rec.VCPUs, rec.MemMiB, rec.PidsMax,
			durationOrNone(rec.ExpiresAt, start), secondsOrNone(rec.IdleTimeoutS))
		m.Record(ctx, rec.ID, "sandbox.create", detail, start, err)
	}()
	rec, err = m.create(ctx, req)
	return m.withActivity(rec), err
}

func durationOrNone(at *time.Time, from time.Time) string {
	if at == nil {
		return "none"
	}
	return at.Sub(from).Round(time.Second).String()
}

func secondsOrNone(s int) string {
	if s <= 0 {
		return "none"
	}
	return (time.Duration(s) * time.Second).String()
}

// ttlFor turns a request's TTL into a deadline: 0 means the daemon's
// default, -1 means none.
func (m *Manager) ttlFor(req api.CreateRequest, now time.Time) (*time.Time, error) {
	ttl := time.Duration(req.TTLSeconds) * time.Second
	switch {
	case req.TTLSeconds == 0:
		ttl = m.cfg.DefaultTTL
	case req.TTLSeconds == -1:
		ttl = 0
	case req.TTLSeconds < -1:
		return nil, fmt.Errorf("%w: ttl must be positive, 0 (default) or -1 (none)", ErrInvalid)
	}
	if ttl <= 0 {
		return nil, nil
	}
	at := now.Add(ttl)
	return &at, nil
}

func (m *Manager) create(ctx context.Context, req api.CreateRequest) (registry.Sandbox, error) {
	if req.ID == "" {
		req.ID = newID()
	}
	if err := sandbox.ValidateID(req.ID); err != nil {
		return registry.Sandbox{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// Choosing a rootfs means choosing a host directory for the sandbox to
	// see. With the socket opened to a group (sbxd -sock-group, Day 21), a
	// member could otherwise make / the rootfs and read the host's files
	// from inside. So only the daemon's own user may; others use images.
	if uid, ok := callerUID(ctx); ok && req.Rootfs != "" && uid != uint32(os.Getuid()) {
		return registry.Sandbox{}, fmt.Errorf("%w: only the user running sbxd may choose a rootfs; use the default or -image", ErrInvalid)
	}
	if req.Image != "" {
		img, ok := m.cfg.Images[req.Image]
		if !ok {
			return registry.Sandbox{}, fmt.Errorf("%w: unknown image %q (this daemon has: %s)", ErrInvalid, req.Image, m.imageNames())
		}
		if req.Rootfs == "" {
			req.Rootfs = img.Rootfs
		}
		if req.MemMiB == 0 {
			req.MemMiB = img.MemMiB
		}
		if req.Policy == "" {
			req.Policy = img.Policy
		}
		req.Network = req.Network || img.Network
	}
	switch req.Policy {
	case "", proxy.PolicyAllowlist:
		req.Policy = "" // the default, stored as such
	case proxy.PolicyBrowse:
		if !req.Network {
			return registry.Sandbox{}, fmt.Errorf("%w: a browse policy needs a network (-net)", ErrInvalid)
		}
	default:
		return registry.Sandbox{}, fmt.Errorf("%w: unknown egress policy %q (want allowlist or browse)", ErrInvalid, req.Policy)
	}
	if req.Rootfs == "" {
		req.Rootfs = m.cfg.Rootfs
	}
	if req.VCPUs == 0 {
		req.VCPUs = m.cfg.VCPUs
	}
	if req.MemMiB == 0 {
		req.MemMiB = m.cfg.MemMiB
	}
	if req.PidsMax == 0 {
		req.PidsMax = m.cfg.PidsMax
	}
	if req.VCPUs < 0 || req.MemMiB < 0 || req.PidsMax < 0 {
		return registry.Sandbox{}, fmt.Errorf("%w: limits can't be negative", ErrInvalid)
	}
	expires, err := m.ttlFor(req, time.Now())
	if err != nil {
		return registry.Sandbox{}, err
	}
	idle := req.IdleTimeoutS
	switch {
	case idle == 0:
		idle = int(m.cfg.DefaultIdle / time.Second)
	case idle == -1:
		idle = 0
	case idle < -1:
		return registry.Sandbox{}, fmt.Errorf("%w: idle timeout must be positive, 0 (default) or -1 (none)", ErrInvalid)
	}
	idleAction := req.IdleAction
	switch idleAction {
	case "":
		idleAction = m.cfg.DefaultIdleAction
	case api.IdlePause, api.IdleDestroy:
	default:
		return registry.Sandbox{}, fmt.Errorf("%w: idle action must be pause or destroy, not %q", ErrInvalid, idleAction)
	}
	if req.Rootfs == "" {
		return registry.Sandbox{}, fmt.Errorf("%w: no rootfs given and no default configured", ErrInvalid)
	}
	// A versioned image's name is a link to its current version (Day 21).
	// Store where it points now: the sandbox keeps exactly these files
	// through every pause and resume, however the link moves later.
	if fi, err := os.Lstat(req.Rootfs); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(req.Rootfs)
		if err != nil {
			return registry.Sandbox{}, fmt.Errorf("%w: rootfs %s: %v", ErrInvalid, req.Rootfs, err)
		}
		req.Rootfs = resolved
	}

	rec, err := m.reg.Create(ctx, registry.Sandbox{
		ID: req.ID, Backend: m.cfg.Backend.Name(), Rootfs: req.Rootfs, VCPUs: req.VCPUs, MemMiB: req.MemMiB, PidsMax: req.PidsMax,
		ExpiresAt: expires, IdleTimeoutS: idle, IdleAction: idleAction, NetSlot: slotRequest(req.Network),
		EgressPolicy: req.Policy,
	})
	if err != nil {
		return registry.Sandbox{}, err
	}
	created := rec
	fail := func(cause error) (registry.Sandbox, error) {
		m.teardownNetwork(ctx, created) // before "failed" frees the slot
		rec, _ := m.reg.Transition(context.WithoutCancel(ctx), req.ID, registry.Creating, registry.Failed, cause.Error())
		return rec, cause
	}
	netNS := ""
	var env []string
	if rec.NetSlot > 0 {
		if err := m.setupNetwork(ctx, req.ID, rec.NetSlot); err != nil {
			return fail(fmt.Errorf("network: %w", err))
		}
		netNS = m.cfg.Net.Path(req.ID)
		// With egress denied, the proxy is the only way out: tell every
		// program where it is (Day 18).
		if m.cfg.Egress == netns.EgressDeny {
			env = netns.ProxyEnv(m.cfg.ProxyPort)
		}
	}

	sb, err := m.cfg.Backend.Create(ctx, sandbox.Spec{
		ID: req.ID, Rootfs: req.Rootfs, Kernel: m.cfg.Kernel, VCPUs: req.VCPUs, MemMiB: req.MemMiB, PidsMax: req.PidsMax,
		NetNS: netNS, Env: env,
	})
	if err != nil {
		return fail(err)
	}
	actx, cancel := context.WithTimeout(ctx, m.cfg.AgentWait)
	_, err = sb.Agent(actx)
	cancel()
	if err != nil && !errors.Is(err, sandbox.ErrUnsupported) {
		_ = sb.Shutdown(context.WithoutCancel(ctx), m.cfg.ShutdownGrace)
		return fail(fmt.Errorf("agent never connected: %w", err))
	}

	m.mu.Lock()
	m.live[req.ID] = sb
	m.mu.Unlock()
	m.Hold(req.ID)() // the sandbox starts its life active
	rec, err = m.reg.Transition(ctx, req.ID, registry.Creating, registry.Running, "")
	if err != nil {
		return rec, err
	}
	go m.watch(req.ID, sb)
	return rec, nil
}

// watch runs alongside each live sandbox. It guards its memory, and it
// notices a sandbox that stops on its own (it crashed, was OOM-killed, or
// was killed from outside) and records it as failed, with the reason if
// the backend knows it. A stop that Destroy started has already moved the
// state to stopping, so watch leaves that alone.
func (m *Manager) watch(id string, sb sandbox.Sandbox) {
	var tick <-chan time.Time
	if m.cfg.GuardInterval > 0 {
		t := time.NewTicker(m.cfg.GuardInterval)
		defer t.Stop()
		tick = t.C
	}
	var lastKill time.Time
	for {
		select {
		case <-sb.Exited():
			m.exited(id, sb)
			return
		case <-tick:
			if !m.guard(id, sb, &lastKill) {
				tick = nil // this backend can't be guarded
			}
		}
	}
}

// guard checks one sandbox's memory once. Near the limit, it has the agent
// kill the process using the most memory: the same idea as earlyoom or
// systemd-oomd, a user-space OOM killer that acts before the kernel's.
// The kernel's OOM killer sees the sandbox as one process and would end
// all of it. It returns false if the backend can't be guarded at all.
func (m *Manager) guard(id string, sb sandbox.Sandbox, lastKill *time.Time) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := sb.Stats(ctx)
	if errors.Is(err, sandbox.ErrUnsupported) {
		return false
	}
	if err != nil || st.MemoryLimit == 0 {
		return true
	}
	if float64(st.MemoryBytes) < m.cfg.GuardAt*float64(st.MemoryLimit) || time.Since(*lastKill) < 500*time.Millisecond {
		return true
	}
	*lastKill = time.Now()
	res, err := sb.Reclaim(ctx)
	if err != nil || !res.Killed {
		return true
	}
	detail := fmt.Sprintf("memory guard: killed %s (pid %d, %d MiB) at %d of %d MiB",
		res.Command, res.PID, res.RSS>>20, st.MemoryBytes>>20, st.MemoryLimit>>20)
	_ = m.reg.Note(ctx, id, detail)
	m.Record(withActor(ctx, selfActor), id, "guard.kill", detail, *lastKill, nil)
	m.cfg.Logf("%s: %s", id, detail)
	return true
}

// exited records a sandbox that stopped on its own.
func (m *Manager) exited(id string, sb sandbox.Sandbox) {
	ctx := context.Background()
	rec, err := m.reg.Get(ctx, id)
	if err != nil {
		return
	}
	// Only a running sandbox stopping is a crash. One being checkpointed is
	// stopped by runsc on purpose, and a paused one has no process at all.
	if rec.State == registry.Running {
		detail := "sandbox exited unexpectedly"
		if r, ok := sb.(sandbox.ExitReasoner); ok {
			if why := r.ExitReason(); why != "" {
				detail += ": " + why
			}
		}
		m.teardownNetwork(ctx, rec) // before "failed" frees the slot
		if _, err := m.reg.Transition(ctx, id, rec.State, registry.Failed, detail); err == nil {
			m.cfg.Logf("%s: %s", id, detail)
		}
		m.mu.Lock()
		if m.live[id] == sb {
			delete(m.live, id)
		}
		m.mu.Unlock()
	}
}

// Destroy stops a sandbox. Destroying one that has already stopped or
// failed is not an error: the caller wanted it gone, and it is.
func (m *Manager) Destroy(ctx context.Context, id string) (registry.Sandbox, error) {
	start := time.Now()
	rec, err := m.destroy(ctx, id, "destroy requested")
	m.Record(ctx, id, "sandbox.destroy", "", start, err)
	return rec, err
}

// destroy stops a sandbox, recording why in its history.
func (m *Manager) destroy(ctx context.Context, id, why string) (registry.Sandbox, error) {
	rec, err := m.reg.Get(ctx, id)
	if err != nil {
		return rec, err
	}
	if rec.State.Terminal() {
		return rec, nil
	}
	if rec.State != registry.Running && rec.State != registry.Paused {
		return rec, fmt.Errorf("%w: %s is %s", registry.ErrConflict, id, rec.State)
	}
	if _, err := m.reg.Transition(ctx, id, rec.State, registry.Stopping, why); err != nil {
		return rec, err // a concurrent destroy won the compare-and-set
	}

	m.mu.Lock()
	sb := m.live[id]
	delete(m.live, id)
	m.mu.Unlock()
	m.actMu.Lock()
	delete(m.act, id)
	m.actMu.Unlock()

	// A destroyed sandbox's checkpoint images go with it.
	m.dropCheckpoints(context.WithoutCancel(ctx), id) // the claims, then the data

	detail := "stopped cleanly"
	if rec.State == registry.Paused {
		detail = "paused sandbox deleted, with its checkpoints"
	}
	if sb != nil {
		// The caller's request may be cancelled; the shutdown must finish anyway.
		if err := sb.Shutdown(context.WithoutCancel(ctx), m.cfg.ShutdownGrace); err != nil {
			detail = err.Error()
		}
	}
	m.teardownNetwork(ctx, rec) // before "stopped" frees the slot
	return m.reg.Transition(context.WithoutCancel(ctx), id, registry.Stopping, registry.Stopped, detail)
}

func (m *Manager) Get(ctx context.Context, id string) (registry.Sandbox, error) {
	rec, err := m.reg.Get(ctx, id)
	return m.withActivity(rec), err
}

func (m *Manager) List(ctx context.Context, all bool) ([]registry.Sandbox, error) {
	recs, err := m.reg.List(ctx, !all)
	for i := range recs {
		recs[i] = m.withActivity(recs[i])
	}
	return recs, err
}

func (m *Manager) Events(ctx context.Context, id string) ([]registry.Event, error) {
	return m.reg.Events(ctx, id)
}

// running returns the handle for a sandbox that is running right now.
func (m *Manager) running(ctx context.Context, id string) (sandbox.Sandbox, error) {
	rec, err := m.reg.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if rec.State == registry.Failed {
		// Say why, so nobody has to dig through the daemon's log.
		return nil, fmt.Errorf("%w: sandbox %s has failed (%s); create a new one", registry.ErrConflict, id, rec.Error)
	}
	if rec.State != registry.Running {
		return nil, fmt.Errorf("%w: sandbox %s is %s, not running", registry.ErrConflict, id, rec.State)
	}
	m.mu.Lock()
	sb := m.live[id]
	m.mu.Unlock()
	if sb == nil {
		return nil, fmt.Errorf("%w: %s has no live handle", registry.ErrConflict, id)
	}
	return sb, nil
}

// use returns a running sandbox's handle and marks it active until done is
// called. Every operation on a sandbox's contents goes through it; reading
// its record, history or stats doesn't, so watching a sandbox never keeps
// it alive.
func (m *Manager) use(ctx context.Context, id string) (sandbox.Sandbox, func(), error) {
	if err := m.wake(ctx, id); err != nil {
		return nil, func() {}, err
	}
	sb, err := m.running(ctx, id)
	if err != nil {
		return nil, func() {}, err
	}
	return sb, m.Hold(id), nil
}

func (m *Manager) Exec(ctx context.Context, id string, req sandbox.ExecRequest) (res sandbox.ExecResult, err error) {
	start := time.Now()
	defer func() {
		outcome := fmt.Sprintf(" → exit %d", res.ExitCode)
		if res.Signal != "" {
			outcome = " → killed: " + res.Signal
		}
		if res.TimedOut {
			outcome += " (timed out)"
		}
		m.Record(ctx, id, "exec", quoteArgs(req.Args)+outcome, start, err)
	}()
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return sandbox.ExecResult{ExitCode: -1}, err
	}
	defer done()
	return sb.Exec(ctx, req)
}

func (m *Manager) WriteFile(ctx context.Context, id, path string, r io.Reader, opts sandbox.WriteOptions) (res sandbox.TransferResult, err error) {
	start := time.Now()
	defer func() {
		m.Record(ctx, id, "file.write", fmt.Sprintf("%s (%d bytes, sha256 %.12s)", path, res.Size, res.SHA256), start, err)
	}()
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return sandbox.TransferResult{}, err
	}
	defer done()
	return sb.WriteFile(ctx, path, r, opts)
}

// ReadFile is audited too: what leaves a sandbox matters as much as what
// enters it.
func (m *Manager) ReadFile(ctx context.Context, id, path string, w io.Writer) (res sandbox.TransferResult, err error) {
	start := time.Now()
	defer func() {
		m.Record(ctx, id, "file.read", fmt.Sprintf("%s (%d bytes, sha256 %.12s)", path, res.Size, res.SHA256), start, err)
	}()
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return sandbox.TransferResult{}, err
	}
	defer done()
	return sb.ReadFile(ctx, path, w)
}

func (m *Manager) ListDir(ctx context.Context, id, path string) (sandbox.ListResult, error) {
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return sandbox.ListResult{}, err
	}
	defer done()
	return sb.ListDir(ctx, path)
}

func (m *Manager) Stat(ctx context.Context, id, path string) (sandbox.FileInfo, error) {
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return sandbox.FileInfo{}, err
	}
	defer done()
	return sb.Stat(ctx, path)
}

// OpenShell opens the attachment. The caller holds the sandbox busy for as
// long as the attachment lasts (Hold), and records its end.
func (m *Manager) OpenShell(ctx context.Context, id string, opts sandbox.ShellOptions) (sh *agent.Shell, err error) {
	start := time.Now()
	defer func() {
		detail := "new session"
		if opts.SessionID != "" {
			detail = "attach " + opts.SessionID
		}
		if sh != nil {
			detail += " → " + sh.SessionID
		}
		if len(opts.Command) > 0 {
			detail += " (" + quoteArgs(opts.Command) + ")"
		}
		m.Record(ctx, id, "shell.open", detail, start, err)
	}()
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return nil, err
	}
	defer done()
	return sb.OpenShell(ctx, opts)
}

func (m *Manager) Sessions(ctx context.Context, id string) (sandbox.SessionList, error) {
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return sandbox.SessionList{}, err
	}
	defer done()
	return sb.Sessions(ctx)
}

func (m *Manager) KillSession(ctx context.Context, id, sessionID string) (err error) {
	start := time.Now()
	defer func() { m.Record(ctx, id, "shell.kill", sessionID, start, err) }()
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return err
	}
	defer done()
	return sb.KillSession(ctx, sessionID)
}

func (m *Manager) StartProcess(ctx context.Context, id string, req sandbox.ProcStart) (res sandbox.ProcStarted, err error) {
	start := time.Now()
	defer func() {
		m.Record(ctx, id, "process.start", quoteArgs(req.Args)+" → "+res.ID, start, err)
	}()
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return sandbox.ProcStarted{}, err
	}
	defer done()
	return sb.StartProcess(ctx, req)
}

func (m *Manager) Processes(ctx context.Context, id string) ([]sandbox.ProcInfo, error) {
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return nil, err
	}
	defer done()
	return sb.Processes(ctx)
}

// Process returns one background process's info.
func (m *Manager) Process(ctx context.Context, id, procID string) (sandbox.ProcInfo, error) {
	list, err := m.Processes(ctx, id)
	if err != nil {
		return sandbox.ProcInfo{}, err
	}
	for _, p := range list {
		if p.ID == procID {
			return p, nil
		}
	}
	return sandbox.ProcInfo{}, fmt.Errorf("%w: no process %s", agent.ErrNotFound, procID)
}

func (m *Manager) Signal(ctx context.Context, id, procID string, sig int) (err error) {
	start := time.Now()
	defer func() { m.Record(ctx, id, "process.signal", fmt.Sprintf("%s signal %d", procID, sig), start, err) }()
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return err
	}
	defer done()
	return sb.Signal(ctx, procID, sig)
}

// Wait holds the sandbox busy while it waits: someone is clearly using it.
func (m *Manager) Wait(ctx context.Context, id, procID string) (sandbox.ProcInfo, error) {
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return sandbox.ProcInfo{}, err
	}
	defer done()
	return sb.Wait(ctx, procID)
}

// Logs holds the sandbox busy too, for as long as a log is being followed.
func (m *Manager) Logs(ctx context.Context, id, procID string, offset int64, follow bool, w io.Writer) (sandbox.LogsEnd, error) {
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return sandbox.LogsEnd{}, err
	}
	defer done()
	return sb.Logs(ctx, procID, offset, follow, w)
}

func (m *Manager) RemoveProcess(ctx context.Context, id, procID string) (err error) {
	start := time.Now()
	defer func() { m.Record(ctx, id, "process.remove", procID, start, err) }()
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return err
	}
	defer done()
	return sb.RemoveProcess(ctx, procID)
}

func (m *Manager) Stats(ctx context.Context, id string) (sandbox.Stats, error) {
	sb, err := m.running(ctx, id)
	if err != nil {
		return sandbox.Stats{}, err
	}
	return sb.Stats(ctx)
}

// Close destroys every live sandbox, in parallel. It runs when the daemon
// shuts down, so a normal stop never leaves sandboxes behind.
// Close stops the manager: the lifetime check first, then every live
// sandbox according to the stop policy (Config.OnStop).
func (m *Manager) Close(ctx context.Context) {
	m.closeOnce.Do(func() { close(m.stopLifetimes) })
	// The proxy first: its open tunnels hold sandboxes busy, and a busy
	// sandbox can't be paused for the shutdown.
	m.mu.Lock()
	p := m.proxy
	m.mu.Unlock()
	if p != nil {
		p.Close()
	}
	m.shutdown(ctx)
}

// slotRequest asks the registry for a network slot, or for none.
func slotRequest(network bool) int {
	if network {
		return registry.AllocateSlot
	}
	return 0
}

// Image is a named kind of sandbox (Day 20).
type Image struct {
	Rootfs  string
	MemMiB  int
	Network bool
	Policy  string // egress policy: "" (allowlist) or "browse"
}

func (m *Manager) imageNames() string {
	if len(m.cfg.Images) == 0 {
		return "none"
	}
	var names []string
	for n := range m.cfg.Images {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// Images lists each image's versions (Day 21): which is current, and how
// many live sandboxes use each, paused ones included (they'll resume on it).
// A version that's neither current nor in use is safe to delete.
func (m *Manager) Images(ctx context.Context) ([]api.ImageInfo, error) {
	live, err := m.reg.List(ctx, true) // true: live sandboxes only (stopped and failed ones use nothing)
	if err != nil {
		return nil, err
	}
	using := map[string][2]int{} // rootfs → {sandboxes, of which paused}
	for _, s := range live {
		u := using[s.Rootfs]
		u[0]++
		if s.State == registry.Paused {
			u[1]++
		}
		using[s.Rootfs] = u
	}
	var out []api.ImageInfo
	for _, name := range strings.Split(m.imageNames(), ", ") {
		img, ok := m.cfg.Images[name]
		if !ok {
			continue
		}
		info := api.ImageInfo{Name: name, Path: img.Rootfs, MemMiB: img.MemMiB, Policy: img.Policy}
		current, _ := filepath.EvalSymlinks(img.Rootfs)
		paths := []string{current}
		if prefix, ok := strings.CutSuffix(img.Rootfs, "-current"); ok {
			found, _ := filepath.Glob(prefix + "-[0-9]*")
			paths = paths[:0]
			for _, p := range found {
				if fi, err := os.Stat(p); err == nil && fi.IsDir() && !strings.HasSuffix(p, ".partial") {
					paths = append(paths, p)
				}
			}
		}
		for _, p := range paths {
			u := using[p]
			info.Versions = append(info.Versions, api.ImageVersion{Path: p, Current: p == current, Sandboxes: u[0], Paused: u[1]})
		}
		out = append(out, info)
	}
	return out, nil
}
