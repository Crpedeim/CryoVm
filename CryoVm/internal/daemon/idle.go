package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/registry"
)

// wake resumes a sandbox that was paused because it was idle, so whoever is
// using it doesn't notice. It does nothing for any other state: the caller's
// own checks then say what's wrong. A sandbox you paused yourself isn't
// woken: that pause was a decision, not an optimization.
//
// Concurrent requests to the same sleeping sandbox wake it once: the first
// registers in m.waking and resumes it; the rest wait on its channel. The
// check-and-register happens under one lock, so two requests can't both
// decide to be first.
func (m *Manager) wake(ctx context.Context, id string) error {
	// A request arriving during an idle checkpoint waits for it to settle,
	// then wakes the sandbox, rather than failing with "checkpointing".
	for deadline := time.Now().Add(10 * time.Second); ; {
		rec, err := m.reg.Get(ctx, id)
		if err != nil || rec.State != registry.Checkpointing || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}

	m.wakeMu.Lock()
	if ch, ok := m.waking[id]; ok {
		m.wakeMu.Unlock()
		select {
		case <-ch:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	rec, err := m.reg.Get(ctx, id)
	if err != nil || rec.State != registry.Paused || !rec.WakeOnUse {
		m.wakeMu.Unlock()
		return nil
	}
	ch := make(chan struct{})
	m.waking[id] = ch
	m.wakeMu.Unlock()
	defer func() {
		m.wakeMu.Lock()
		delete(m.waking, id)
		m.wakeMu.Unlock()
		close(ch)
	}()

	start := time.Now()
	_, err = m.Resume(context.WithoutCancel(ctx), id, "")
	m.Record(ctx, id, "sandbox.wake", fmt.Sprintf("woken by use in %dms", time.Since(start).Milliseconds()), start, err)
	if err != nil {
		return fmt.Errorf("waking idle sandbox %s: %w", id, err)
	}
	return nil
}

// Ready is for HTTP handlers that check a sandbox before starting a stream:
// it wakes the sandbox if it's asleep, then checks it's running.
func (m *Manager) Ready(ctx context.Context, id string) error {
	if err := m.wake(ctx, id); err != nil {
		return err
	}
	_, err := m.running(ctx, id)
	return err
}

// sampleCPU counts CPU use as activity: if the sandbox used more than
// IdleCPU cores since the last sample, it's busy, API calls or not. A build
// running for twenty minutes with nobody calling the API isn't idle, and
// pausing it would freeze it halfway.
func (m *Manager) sampleCPU(ctx context.Context, id string, now time.Time) {
	m.mu.Lock()
	sb := m.live[id]
	m.mu.Unlock()
	if sb == nil {
		return
	}
	st, err := sb.Stats(ctx)
	if err != nil {
		return
	}
	m.actMu.Lock()
	defer m.actMu.Unlock()
	a := m.act[id]
	if a == nil {
		a = &activity{last: now}
		m.act[id] = a
	}
	if !a.cpuAt.IsZero() && now.After(a.cpuAt) {
		cores := float64(st.CPUUsage-a.cpuUsage) / float64(now.Sub(a.cpuAt))
		if cores > m.cfg.IdleCPU {
			a.last = now // busy computing: not idle
		}
	}
	a.cpuAt, a.cpuUsage = now, st.CPUUsage
}

// idleAct does what a sandbox's idle timeout says: pause it (marked to wake
// on use), or destroy it.
func (m *Manager) idleAct(ctx context.Context, rec registry.Sandbox, idleFor time.Duration) {
	id := rec.ID
	why := fmt.Sprintf("idle for %s (idle timeout %s)", idleFor.Round(time.Second), time.Duration(rec.IdleTimeoutS)*time.Second)
	start := time.Now()
	if rec.IdleAction != api.IdlePause {
		_, err := m.destroy(ctx, id, why)
		m.Record(ctx, id, "idle.expire", why, start, err)
		if err == nil {
			m.cfg.Logf("%s: %s", id, why)
		}
		return
	}
	ck, err := m.checkpoint(ctx, id, api.CheckpointRequest{}, true)
	if err != nil {
		// Something started in the meantime (busy), or the checkpoint
		// failed: either way, try again only after another full timeout.
		m.Hold(id)()
		if !errors.Is(err, registry.ErrConflict) {
			m.cfg.Logf("%s: idle pause failed: %v", id, err)
		}
		return
	}
	m.Record(ctx, id, "idle.pause", why+"; paused to "+ck.ID, start, nil)
	m.cfg.Logf("%s: %s; paused to %s", id, why, ck.ID)
}
