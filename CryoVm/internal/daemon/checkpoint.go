package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/registry"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

func newCheckpointID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "ck-" + hex.EncodeToString(b)
}

// busyWith says what's in progress on a sandbox: an exec, an attached
// shell, a followed log, a wait.
func (m *Manager) busyWith(id string) int {
	m.actMu.Lock()
	defer m.actMu.Unlock()
	if a := m.act[id]; a != nil {
		return a.inflight
	}
	return 0
}

// Checkpoint saves a running sandbox's whole state as an image. Without
// LeaveRunning, the sandbox stops and becomes paused: nothing runs, its
// state is on disk, and Day 11 brings it back.
//
// A busy sandbox is refused unless forced: the agent lets go of its
// connection for the checkpoint, which cuts off any exec in flight and
// detaches any shell. While the checkpoint runs, the sandbox is in the
// checkpointing state, and every other operation on it is refused.
func (m *Manager) Checkpoint(ctx context.Context, id string, req api.CheckpointRequest) (registry.Checkpoint, error) {
	return m.checkpoint(ctx, id, req, false)
}

// checkpoint is Checkpoint, also saying whether the pause should wake on
// use: true for an idle pause, false for one you asked for. The flag is set
// before the sandbox becomes paused, so no request can find it paused but
// not yet marked, and be refused instead of waking it.
func (m *Manager) checkpoint(ctx context.Context, id string, req api.CheckpointRequest, wakeOnUse bool) (ck registry.Checkpoint, err error) {
	start := time.Now()
	defer func() {
		detail := ck.ID
		if err == nil {
			mode := "paused"
			if req.LeaveRunning {
				mode = "left running"
			}
			detail = fmt.Sprintf("%s (%.1f MiB in %dms, %s)", ck.ID, float64(ck.ImageBytes)/(1<<20), ck.DurationMs, mode)
		}
		m.Record(ctx, id, "sandbox.checkpoint", detail, start, err)
	}()

	sb, err := m.running(ctx, id)
	if err != nil {
		return ck, err
	}
	if n := m.busyWith(id); n > 0 && !req.Force {
		return ck, fmt.Errorf("%w: sandbox %s is busy (%d operation(s) in progress: an exec, an attached shell, a followed log); finish them, or force the checkpoint and cut them off",
			registry.ErrConflict, id, n)
	}
	// The transition names the checkpoint it's taking: after a crash,
	// reconciliation knows exactly which image belongs to this pause.
	ckID := newCheckpointID()
	if _, err := m.reg.Transition(ctx, id, registry.Running, registry.Checkpointing, "checkpoint "+ckID+" started"); err != nil {
		return ck, err
	}
	// Once started, a checkpoint finishes even if the client goes away:
	// half a checkpoint is worse than none.
	bg := context.WithoutCancel(ctx)
	ck = registry.Checkpoint{ID: ckID, SandboxID: id, CreatedAt: start, LeftRunning: req.LeaveRunning}
	ck.Path = filepath.Join(m.cfg.CheckpointDir, id, ck.ID)
	res, err := sb.Checkpoint(bg, sandbox.CheckpointOptions{Dir: ck.Path, LeaveRunning: req.LeaveRunning})
	if err != nil {
		_ = os.RemoveAll(ck.Path)
		select {
		case <-sb.Exited():
			_, _ = m.reg.Transition(bg, id, registry.Checkpointing, registry.Failed, "checkpoint failed and the sandbox stopped: "+err.Error())
			m.forget(id)
		default:
			_, _ = m.reg.Transition(bg, id, registry.Checkpointing, registry.Running, "checkpoint failed: "+err.Error())
		}
		return ck, err
	}
	ck.ImageBytes, ck.DurationMs = res.ImageBytes, res.Duration.Milliseconds()
	m.crash("checkpoint:after-image") // the image is written, not yet claimed
	if err := m.reg.AddCheckpoint(bg, ck); err != nil {
		return ck, err
	}
	ck.Local = true
	m.offload(bg, ck) // to the store, if there is one
	if cks, err := m.reg.Checkpoints(bg, id); err == nil {
		for _, c := range cks {
			if c.ID == ck.ID {
				ck = c
			}
		}
	}
	if req.LeaveRunning {
		_, err = m.reg.Transition(bg, id, registry.Checkpointing, registry.Running, "snapshot "+ck.ID)
		return ck, err
	}
	_ = m.reg.SetWakeOnUse(bg, id, wakeOnUse)
	why := "checkpointed to " + ck.ID
	if wakeOnUse {
		why = "paused while idle, to " + ck.ID + "; wakes on use"
	}
	// Clean up first, then say paused. The other order had a race: a wake
	// arriving as soon as the state said paused started a restore whose
	// bundle and container the old sandbox's cleanup then deleted (Day 14
	// found it as "runsc restore: exit status 128" with an empty log: the
	// log was in the deleted bundle). Until the state changes, a waker
	// waits, because the sandbox is still checkpointing.
	m.forget(id)
	_ = sb.Shutdown(bg, m.cfg.ShutdownGrace) // already stopped by runsc: this cleans up
	_, err = m.reg.Transition(bg, id, registry.Checkpointing, registry.Paused, why)
	return ck, err
}

// forget drops a sandbox's live handle and activity.
func (m *Manager) forget(id string) {
	m.mu.Lock()
	delete(m.live, id)
	m.mu.Unlock()
	m.actMu.Lock()
	delete(m.act, id)
	m.actMu.Unlock()
}

func (m *Manager) Checkpoints(ctx context.Context, id string) ([]registry.Checkpoint, error) {
	return m.reg.Checkpoints(ctx, id)
}

// Resume brings a paused sandbox back from a checkpoint: by default the one
// that paused it, or any of its earlier snapshots (rolling it back to that
// moment). It's running again once its agent has reconnected. A failed
// restore leaves it paused, with the image intact, to retry.
func (m *Manager) Resume(ctx context.Context, id, checkpointID string) (rec registry.Sandbox, err error) {
	start := time.Now()
	var used string
	defer func() {
		detail := checkpointID
		if err == nil {
			detail = fmt.Sprintf("from %s in %dms", used, time.Since(start).Milliseconds())
		}
		m.Record(ctx, id, "sandbox.resume", detail, start, err)
	}()

	rec, err = m.reg.Get(ctx, id)
	if err != nil {
		return rec, err
	}
	if rec.State != registry.Paused {
		return rec, fmt.Errorf("%w: sandbox %s is %s, not paused", registry.ErrConflict, id, rec.State)
	}
	ck, err := m.pickCheckpoint(ctx, id, checkpointID)
	if err != nil {
		return rec, err
	}
	used = ck.ID
	if ck, err = m.ensureLocal(ctx, ck); err != nil { // fetched from the store if need be
		return rec, err
	}
	if _, err := m.reg.Transition(ctx, id, registry.Paused, registry.Restoring, ""); err != nil {
		return rec, err
	}
	bg := context.WithoutCancel(ctx)
	backToPaused := func(why string) {
		_, _ = m.reg.Transition(bg, id, registry.Restoring, registry.Paused, why)
	}
	// A paused sandbox keeps its network, but a reboot wipes /run/netns:
	// rebuild it, in the same slot, so its address stays the same (Day 16).
	// If it's there, refresh it: at first boot runsc moved eth0's address
	// into gVisor, and a restore looks for it on eth0 again (Day 16 v2).
	if rec.NetSlot > 0 {
		var err error
		if !m.cfg.Net.Exists(id) {
			err = m.setupNetwork(bg, id, rec.NetSlot)
		} else {
			err = m.cfg.Net.Refresh(bg, id)
		}
		if err != nil {
			backToPaused("restore failed: network: " + err.Error())
			return rec, fmt.Errorf("network: %w", err)
		}
	}
	sb, err := m.cfg.Backend.Restore(bg, id, ck.Path)
	if err != nil {
		backToPaused("restore failed: " + err.Error())
		return rec, err
	}
	actx, cancel := context.WithTimeout(bg, m.cfg.AgentWait)
	_, err = sb.Agent(actx)
	cancel()
	if err != nil && !errors.Is(err, sandbox.ErrUnsupported) {
		_ = sb.Shutdown(bg, m.cfg.ShutdownGrace)
		backToPaused("restored, but the agent never reconnected: " + err.Error())
		return rec, fmt.Errorf("the agent never reconnected after the restore: %w", err)
	}
	m.mu.Lock()
	m.live[id] = sb
	m.mu.Unlock()
	m.Hold(id)() // it comes back active
	rec, err = m.reg.Transition(bg, id, registry.Restoring, registry.Running, "restored from "+ck.ID)
	if err != nil {
		return rec, err
	}
	m.renew(bg, id, sb) // a restore may be a duplicate, or a jump in time
	if rec.ResumeOnStart {
		_ = m.reg.SetResumeOnStart(bg, id, false)
		rec.ResumeOnStart = false
	}
	if rec.WakeOnUse {
		_ = m.reg.SetWakeOnUse(bg, id, false)
		rec.WakeOnUse = false
	}
	go m.watch(id, sb)
	return m.withActivity(rec), nil
}

// pickCheckpoint finds the checkpoint to resume from: the named one (which
// must belong to this sandbox), or the newest pause.
func (m *Manager) pickCheckpoint(ctx context.Context, id, want string) (registry.Checkpoint, error) {
	list, err := m.reg.Checkpoints(ctx, id)
	if err != nil {
		return registry.Checkpoint{}, err
	}
	for _, ck := range list {
		if want != "" && ck.ID == want {
			return ck, nil
		}
		if want == "" && !ck.LeftRunning {
			return ck, nil
		}
	}
	if want != "" {
		return registry.Checkpoint{}, fmt.Errorf("%w: sandbox %s has no checkpoint %s", registry.ErrNotFound, id, want)
	}
	return registry.Checkpoint{}, fmt.Errorf("%w: sandbox %s has no checkpoint to resume from", registry.ErrNotFound, id)
}

func (m *Manager) now() time.Time { return time.Now() }
