package daemon

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/registry"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

const maxForks = 16

// Fork makes new sandboxes from one snapshot of another: the same files,
// processes and shell sessions, each in its own cgroup, diverging from that
// moment on.
//
// Which snapshot: the checkpoint named; or, for a running source, one taken
// now (the source's agent lets go and reconnects within ~60 ms; a busy
// source is refused unless forced); or, for a sleeping source, its latest
// pause, without waking it. One snapshot serves every fork in the request.
func (m *Manager) Fork(ctx context.Context, srcID string, req api.ForkRequest) ([]registry.Sandbox, error) {
	count := req.Count
	if count == 0 {
		count = 1
	}
	if count < 1 || count > maxForks {
		return nil, fmt.Errorf("%w: fork count must be 1 to %d", ErrInvalid, maxForks)
	}
	if req.ID != "" && count > 1 {
		return nil, fmt.Errorf("%w: an ID can only name a single fork", ErrInvalid)
	}
	src, err := m.reg.Get(ctx, srcID)
	if err != nil {
		return nil, err
	}
	// Cheap checks before the snapshot: a request that's going to fail
	// mustn't leave an orphan image behind first.
	if req.ID != "" {
		if err := sandbox.ValidateID(req.ID); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if _, err := m.reg.Get(ctx, req.ID); err == nil {
			return nil, fmt.Errorf("%w: %s", registry.ErrExists, req.ID)
		}
	}

	var ck registry.Checkpoint
	switch {
	case req.Checkpoint != "":
		ck, err = m.pickCheckpoint(ctx, srcID, req.Checkpoint)
	case src.State == registry.Running:
		ck, err = m.Checkpoint(ctx, srcID, api.CheckpointRequest{LeaveRunning: true, Force: req.Force})
	case src.State == registry.Paused:
		ck, err = m.pickCheckpoint(ctx, srcID, "")
	default:
		err = fmt.Errorf("%w: sandbox %s is %s: fork a running or paused sandbox", registry.ErrConflict, srcID, src.State)
	}
	if err != nil {
		return nil, err
	}
	if ck, err = m.ensureLocal(ctx, ck); err != nil { // fetched from the store if need be
		return nil, err
	}

	// The clones are made in parallel, at most one per CPU (Day 23: made
	// one after another, each cost ~75 ms, so 16 took 1.2 s). Each touches
	// only its own registry row (the registry serializes writes), its own
	// namespaces and its own bundle; the image is only read. Every clone is
	// attempted; the ones that succeeded come back in order, with the first
	// error if any failed.
	par := runtime.NumCPU()
	if par < 2 {
		par = 2
	}
	if par > count {
		par = count
	}
	recs := make([]registry.Sandbox, count)
	errs := make([]error, count)
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			recs[i], errs[i] = m.forkOne(ctx, src, ck, req.ID)
		}(i)
	}
	wg.Wait()
	var out []registry.Sandbox
	var first error
	for i := range recs {
		if errs[i] != nil {
			if first == nil {
				first = errs[i]
			}
			continue
		}
		out = append(out, recs[i])
	}
	return out, first
}

// forkOne restores one fork from the image, under a new ID.
func (m *Manager) forkOne(ctx context.Context, src registry.Sandbox, ck registry.Checkpoint, id string) (rec registry.Sandbox, err error) {
	start := time.Now()
	if id == "" {
		id = newID()
	}
	defer func() {
		m.Record(ctx, id, "sandbox.fork", fmt.Sprintf("from %s at %s in %dms", src.ID, ck.ID, time.Since(start).Milliseconds()), start, err)
	}()
	// The fork's own lifetime starts now, under the daemon's default; its
	// limits and idle behavior are the source's.
	expires, _ := m.ttlFor(api.CreateRequest{}, start)
	// Each phase is timed (Day 23): clones made in parallel took as long in
	// total as one after another, so something serializes them; the log
	// line says which phase grows.
	var ph phases
	mark := ph.start()
	rec, err = m.reg.Create(ctx, registry.Sandbox{
		ID: id, Backend: src.Backend, Rootfs: src.Rootfs, VCPUs: src.VCPUs, MemMiB: src.MemMiB, PidsMax: src.PidsMax,
		ExpiresAt: expires, IdleTimeoutS: src.IdleTimeoutS, IdleAction: src.IdleAction, ForkedFrom: src.ID,
		NetSlot:      slotRequest(src.NetSlot > 0), // a networked source's forks are networked (Day 19)
		EgressPolicy: src.EgressPolicy,             // and judged by the same policy (Day 20)
	})
	if err != nil {
		return rec, err
	}
	ph.registry = mark()
	bg := context.WithoutCancel(ctx)
	created := rec
	failed := func(why string) {
		m.teardownNetwork(bg, created) // before "failed" frees the slot
		_, _ = m.reg.Transition(bg, id, registry.Creating, registry.Failed, why)
	}
	// Its own namespaces and router, built before the restore: the restored
	// network stack, with the same inside address and MACs as its source's,
	// finds them as if it had always lived there.
	if rec.NetSlot > 0 {
		if err := m.setupNetwork(bg, id, rec.NetSlot); err != nil {
			failed("fork failed: network: " + err.Error())
			return rec, fmt.Errorf("network: %w", err)
		}
	}
	ph.network = mark()
	sb, err := m.cfg.Backend.Restore(bg, id, ck.Path)
	if err != nil {
		failed("fork failed: " + err.Error())
		return rec, err
	}
	ph.restore = mark()
	actx, cancel := context.WithTimeout(bg, m.cfg.AgentWait)
	_, err = sb.Agent(actx)
	cancel()
	ph.agent = mark()
	if err != nil && !errors.Is(err, sandbox.ErrUnsupported) {
		_ = sb.Shutdown(bg, m.cfg.ShutdownGrace)
		failed("forked, but its agent never connected: " + err.Error())
		return rec, fmt.Errorf("the fork's agent never connected: %w", err)
	}
	m.mu.Lock()
	m.live[id] = sb
	m.mu.Unlock()
	m.Hold(id)()
	rec, err = m.reg.Transition(bg, id, registry.Creating, registry.Running, "forked from "+src.ID+" at "+ck.ID)
	if err != nil {
		return rec, err
	}
	m.renew(bg, id, sb) // its agent still believes it's the source
	go m.watch(id, sb)
	ph.finish = mark()
	m.cfg.Logf("%s: forked from %s at %s in %s (%s)", id, src.ID, ck.ID, time.Since(start).Round(time.Millisecond), ph)
	return m.withActivity(rec), nil
}

// phases times the steps of making one clone (Day 23).
type phases struct {
	registry, network, restore, agent, finish time.Duration
	last                                      time.Time
}

// start begins timing; each call of the returned mark ends one phase.
func (p *phases) start() func() time.Duration {
	p.last = time.Now()
	return func() time.Duration {
		now := time.Now()
		d := now.Sub(p.last)
		p.last = now
		return d
	}
}

func (p phases) String() string {
	ms := func(d time.Duration) int64 { return d.Milliseconds() }
	return fmt.Sprintf("registry %dms, network %dms, restore %dms, agent %dms, finish %dms",
		ms(p.registry), ms(p.network), ms(p.restore), ms(p.agent), ms(p.finish))
}
