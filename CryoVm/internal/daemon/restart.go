package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/registry"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

// Adopter is implemented by backends that can take charge of a sandbox a
// previous daemon left running.
type Adopter interface {
	Adopt(ctx context.Context, id string) (sandbox.Sandbox, error)
}

// What a daemon does with its running sandboxes when it stops cleanly.
const (
	// OnStopDestroy destroys them: the behavior before Day 12, and the
	// library default, because it leaves nothing behind.
	OnStopDestroy = "destroy"
	// OnStopPause checkpoints them and marks them to resume when a daemon
	// starts again. They survive a host reboot. sbxd's default.
	OnStopPause = "pause"
	// OnStopLeave leaves them running, for the next daemon to adopt: the
	// fastest way through a daemon upgrade, but a host reboot kills them.
	OnStopLeave = "leave"
)

// reconcile settles every sandbox a previous daemon left unfinished. The
// rule: keep what's still true. A sandbox still running is adopted, not
// reaped; one being destroyed is finished off; one whose image is intact is
// paused, or resumed if a shutdown paused it. Only what can't be trusted
// is failed.
func (m *Manager) reconcile(ctx context.Context) error {
	stale, err := m.reg.List(ctx, true)
	if err != nil {
		return err
	}
	actx := withActor(ctx, selfActor)
	var wg sync.WaitGroup
	var resume []string
	for _, s := range stale {
		switch s.State {
		case registry.Paused:
			if s.ResumeOnStart {
				resume = append(resume, s.ID)
			}
		case registry.Restoring:
			// A restore cut short: whatever it started is reaped, but the
			// image is untouched, so back to paused.
			m.reap(ctx, s.ID)
			m.settle(ctx, s, registry.Paused, "daemon restarted during a restore; back to paused")
			if s.ResumeOnStart {
				resume = append(resume, s.ID)
			}
		case registry.Running, registry.Checkpointing:
			wg.Add(1)
			go func(s registry.Sandbox) {
				defer wg.Done()
				m.adopt(actx, s)
			}(s)
		case registry.Stopping:
			// It was being destroyed: finish the job.
			m.reap(ctx, s.ID)
			m.teardownNetwork(ctx, s)
			m.dropCheckpoints(ctx, s.ID) // the claims, then the data
			m.settle(ctx, s, registry.Stopped, "destroy finished after a daemon restart")
		default: // creating: too early to trust
			m.reap(ctx, s.ID)
			m.teardownNetwork(ctx, s)
			m.settle(ctx, s, registry.Failed, "daemon restarted while the sandbox was "+string(s.State)+"; reaped")
		}
	}
	wg.Wait()
	for _, id := range resume {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			m.resumeOnStart(actx, id)
		}(id)
	}
	wg.Wait()
	return nil
}

func (m *Manager) reap(ctx context.Context, id string) {
	if r, ok := m.cfg.Backend.(Reaper); ok {
		_ = r.Reap(ctx, id)
	}
}

func (m *Manager) settle(ctx context.Context, s registry.Sandbox, to api.State, detail string) {
	if _, err := m.reg.Transition(ctx, s.ID, s.State, to, detail); err != nil {
		m.cfg.Logf("%s: %s → %s: %v", s.ID, s.State, to, err)
		return
	}
	m.cfg.Logf("%s: %s", s.ID, detail)
}

// adopt takes charge of a sandbox left running, or fails it if it's gone
// (the host rebooted, say) or comes back without its agent.
func (m *Manager) adopt(ctx context.Context, s registry.Sandbox) {
	fail := func(why string) {
		m.reap(ctx, s.ID)
		m.teardownNetwork(ctx, s)
		m.settle(ctx, s, registry.Failed, "daemon restarted and the sandbox "+why+"; reaped")
	}
	ad, ok := m.cfg.Backend.(Adopter)
	if !ok {
		fail("could not be adopted by this backend")
		return
	}
	sb, err := ad.Adopt(ctx, s.ID)
	if err != nil {
		if ck, ok := m.finishedPause(ctx, s); ok {
			// The pause's image was written and claimed before the daemon
			// died; only the state change was lost. It's paused, not failed.
			m.reap(ctx, s.ID)
			m.settle(ctx, s, registry.Paused, "daemon restarted mid-pause, after checkpoint "+ck.ID+" was saved; paused, and resumable from it")
			return
		}
		fail("was no longer running (" + err.Error() + ")")
		return
	}
	actx, cancel := context.WithTimeout(ctx, m.cfg.AgentWait)
	_, err = sb.Agent(actx)
	cancel()
	if err != nil && !errors.Is(err, sandbox.ErrUnsupported) {
		_ = sb.Shutdown(ctx, m.cfg.ShutdownGrace)
		fail("came back without its agent (" + err.Error() + ")")
		return
	}
	m.mu.Lock()
	m.live[s.ID] = sb
	m.mu.Unlock()
	m.Hold(s.ID)() // its idle clock starts again: the last activity is lost with the old daemon
	if s.State == registry.Checkpointing {
		m.settle(ctx, s, registry.Running, "checkpoint interrupted by a daemon restart; adopted, still running")
	} else {
		_ = m.reg.Note(ctx, s.ID, "adopted after a daemon restart: it never stopped")
		m.cfg.Logf("%s: adopted after a daemon restart", s.ID)
	}
	m.Record(ctx, s.ID, "sandbox.adopt", string(s.State), m.now(), nil)
	go m.watch(s.ID, sb)
}

// resumeOnStart resumes a sandbox a shutdown paused. Once: if the resume
// fails, the sandbox stays paused for someone to look at, rather than being
// retried at every start.
func (m *Manager) resumeOnStart(ctx context.Context, id string) {
	_, err := m.Resume(ctx, id, "")
	_ = m.reg.SetResumeOnStart(ctx, id, false)
	if err != nil {
		m.cfg.Logf("%s: could not resume after the restart: %v; left paused", id, err)
	}
}

// shutdown applies the stop policy to every live sandbox, in parallel.
func (m *Manager) shutdown(ctx context.Context) {
	m.mu.Lock()
	ids := make([]string, 0, len(m.live))
	for id := range m.live {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	actx := withActor(ctx, selfActor)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			switch m.cfg.OnStop {
			case OnStopLeave:
				m.release(id)
				_ = m.reg.Note(ctx, id, "daemon stopped; left running, to be adopted on start")
			case OnStopPause:
				m.pauseForShutdown(actx, id)
			default:
				if _, err := m.Destroy(actx, id); err != nil {
					m.cfg.Logf("destroy %s on shutdown: %v", id, err)
				}
			}
		}(id)
	}
	wg.Wait()
}

// pauseForShutdown checkpoints a sandbox, forced (a shutdown can't wait for
// someone's exec to finish), and marks it to resume on start. If the
// checkpoint fails, the sandbox is left running instead, for the next
// daemon to adopt: still better than destroying it.
func (m *Manager) pauseForShutdown(ctx context.Context, id string) {
	ck, err := m.Checkpoint(ctx, id, api.CheckpointRequest{Force: true})
	if err != nil {
		m.release(id)
		_ = m.reg.Note(ctx, id, fmt.Sprintf("pausing on shutdown failed (%v); left running, to be adopted on start", err))
		m.cfg.Logf("%s: pause on shutdown failed: %v; left running", id, err)
		return
	}
	if err := m.reg.SetResumeOnStart(ctx, id, true); err != nil {
		m.cfg.Logf("%s: paused to %s, but not marked to resume: %v", id, ck.ID, err)
		return
	}
	m.cfg.Logf("%s: paused to %s for the shutdown; resumes on start", id, ck.ID)
}

// release lets go of a live sandbox without stopping it, for another daemon
// to adopt.
func (m *Manager) release(id string) {
	m.mu.Lock()
	sb := m.live[id]
	delete(m.live, id)
	m.mu.Unlock()
	if r, ok := sb.(sandbox.Releaser); ok {
		r.Release()
	}
}

// finishedPause reports whether a sandbox found checkpointing has the image
// that checkpoint was taking, claimed (on disk or in the store), and that
// checkpoint was a pause rather than a snapshot: then the pause completed in
// all but its state change. The transition into checkpointing names the
// checkpoint, so this is an exact match, not a guess from timestamps.
func (m *Manager) finishedPause(ctx context.Context, s registry.Sandbox) (registry.Checkpoint, bool) {
	if s.State != registry.Checkpointing {
		return registry.Checkpoint{}, false
	}
	evs, err := m.reg.Events(ctx, s.ID)
	if err != nil {
		return registry.Checkpoint{}, false
	}
	taking := ""
	for _, e := range evs {
		if e.To == registry.Checkpointing && e.From != e.To {
			taking = strings.TrimSuffix(strings.TrimPrefix(e.Detail, "checkpoint "), " started")
		}
	}
	cks, err := m.reg.Checkpoints(ctx, s.ID)
	if err != nil || taking == "" {
		return registry.Checkpoint{}, false
	}
	for _, ck := range cks {
		if ck.ID == taking && !ck.LeftRunning && (ck.Local || ck.Remote) {
			return ck, true
		}
	}
	return registry.Checkpoint{}, false
}
