package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

func TestCheckpointPausesTheSandbox(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "pauseme"})
	ck, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{})
	if err != nil || !strings.HasPrefix(ck.ID, "ck-") || ck.LeftRunning || ck.ImageBytes <= 0 {
		t.Fatalf("checkpoint: %+v %v", ck, err)
	}
	if _, err := os.Stat(filepath.Join(ck.Path, "checkpoint.img")); err != nil {
		t.Fatalf("no image at %s: %v", ck.Path, err)
	}
	// The backend stopped, as runsc stops a checkpointed sandbox. That is
	// not a crash: the sandbox must stay paused.
	time.Sleep(200 * time.Millisecond)
	rec, _ := e.c.Get(ctx, sb.ID)
	if rec.State != api.Paused {
		t.Fatalf("want paused, got %+v", rec)
	}
	if ev := lastEventTo(t, e, sb.ID, api.Paused); !strings.Contains(ev.Detail, ck.ID) {
		t.Fatalf("history: %+v", ev)
	}
	if _, err := e.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"true"}}); !errors.Is(err, client.ErrConflict) {
		t.Fatalf("exec on a paused sandbox: want ErrConflict, got %v", err)
	}
	list, _ := e.c.Checkpoints(ctx, sb.ID)
	if len(list) != 1 || list[0].ID != ck.ID {
		t.Fatalf("checkpoints: %+v", list)
	}
	if a, ok := auditActions(t, e, sb.ID)["sandbox.checkpoint"]; !ok || !strings.Contains(a.Detail, "paused") {
		t.Fatalf("audit: %+v", a)
	}
}

func lastEventTo(t *testing.T, e *env, id string, to api.State) api.Event {
	t.Helper()
	evs, _ := e.c.Events(tctx(t), id)
	for i := len(evs) - 1; i >= 0; i-- {
		// A transition, not a note: notes (Day 9's Note, Day 15's identity
		// lines) keep the state, so From == To.
		if evs[i].To == to && evs[i].From != evs[i].To {
			return evs[i]
		}
	}
	t.Fatalf("no transition to %s in %+v", to, evs)
	return api.Event{}
}

func TestSnapshotKeepsRunning(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "snap"})
	ck, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{LeaveRunning: true})
	if err != nil || !ck.LeftRunning {
		t.Fatalf("snapshot: %+v %v", ck, err)
	}
	if rec, _ := e.c.Get(ctx, sb.ID); rec.State != api.Running {
		t.Fatalf("a snapshot leaves it running: %+v", rec)
	}
	if _, err := e.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"true"}}); err != nil {
		t.Fatalf("exec after a snapshot: %v", err)
	}
}

func TestBusySandboxIsRefusedUnlessForced(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "busy"})
	go func() { _, _ = e.c.Exec(context.Background(), sb.ID, client.ExecRequest{Args: []string{"sleep", "3"}}) }()
	time.Sleep(300 * time.Millisecond)
	if _, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{}); !errors.Is(err, client.ErrConflict) || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("a busy sandbox: want a busy conflict, got %v", err)
	}
	if _, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{Force: true}); err != nil {
		t.Fatalf("forced: %v", err)
	}
	if rec, _ := e.c.Get(ctx, sb.ID); rec.State != api.Paused {
		t.Fatalf("after a forced checkpoint: %+v", rec)
	}
}

func TestFailedCheckpointReturnsToRunning(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "ckfail"})
	fake := e.b.get(sb.ID)
	fake.mu.Lock()
	fake.failCheckpoint = errors.New("runsc checkpoint: something inside can't be saved")
	fake.mu.Unlock()
	if _, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{}); err == nil {
		t.Fatal("the checkpoint should fail")
	}
	if rec, _ := e.c.Get(ctx, sb.ID); rec.State != api.Running {
		t.Fatalf("a failed checkpoint must leave it running: %+v", rec)
	}
	if ev := lastEventTo(t, e, sb.ID, api.Running); !strings.Contains(ev.Detail, "checkpoint failed") {
		t.Fatalf("history: %+v", ev)
	}
	if entries, _ := os.ReadDir(filepath.Join(e.m.cfg.CheckpointDir, sb.ID)); len(entries) != 0 {
		t.Fatalf("a failed checkpoint left %d image directories behind", len(entries))
	}
	if _, err := e.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"true"}}); err != nil {
		t.Fatalf("still usable? %v", err)
	}
}

func TestDestroyingAPausedSandboxDeletesItsImages(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "gone"})
	ck, _ := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{})
	rec, err := e.c.Destroy(ctx, sb.ID)
	if err != nil || rec.State != api.Stopped {
		t.Fatalf("destroy a paused sandbox: %+v %v", rec, err)
	}
	if _, err := os.Stat(ck.Path); !os.IsNotExist(err) {
		t.Fatal("its image is still on disk")
	}
	if list, _ := e.c.Checkpoints(ctx, sb.ID); len(list) != 0 {
		t.Fatalf("still listed: %+v", list)
	}
}

// A paused sandbox's state is on disk, not in a process: a daemon restart
// must leave it paused (Day 11 restores it), not reap and fail it.
func TestPausedSurvivesADaemonRestart(t *testing.T) {
	dir, _ := os.MkdirTemp("", "sbxd")
	t.Cleanup(func() { os.RemoveAll(dir) })
	db := filepath.Join(dir, "registry.db")
	e := startWith(t, newFakeBackend(), db, filepath.Join(dir, "a.sock"))
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "sleeper"})
	if _, err := e.c.Checkpoint(tctx(t), sb.ID, api.CheckpointRequest{}); err != nil {
		t.Fatal(err)
	}
	e.reg.Close() // the daemon dies

	b2 := newFakeBackend()
	e2 := startWith(t, b2, db, filepath.Join(dir, "b.sock"))
	rec, err := e2.c.Get(tctx(t), sb.ID)
	if err != nil || rec.State != api.Paused {
		t.Fatalf("after a restart: %+v %v", rec, err)
	}
	b2.mu.Lock()
	reaped := len(b2.reaped)
	b2.mu.Unlock()
	if reaped != 0 {
		t.Fatal("a paused sandbox has nothing running to reap")
	}
}

// Paused sandboxes hold disk: their deadline still applies.
func TestAPausedSandboxStillExpires(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "expiring", TTLSeconds: 1})
	ck, _ := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{})
	waitState(t, e, sb.ID, api.Stopped, 3*time.Second)
	if ev := lastEvent(t, e, sb.ID); !strings.HasPrefix(ev.Detail, "lifetime expired") {
		t.Fatalf("history: %+v", ev)
	}
	if _, err := os.Stat(ck.Path); !os.IsNotExist(err) {
		t.Fatal("the expired sandbox's image is still on disk")
	}
}
