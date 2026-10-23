package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
	"github.com/Crpedeim/sbx/internal/registry"
)

func TestPauseResumeCycles(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "cycle"})
	for round := 1; round <= 2; round++ {
		ck, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{})
		if err != nil {
			t.Fatalf("round %d checkpoint: %v", round, err)
		}
		rec, err := e.c.Resume(ctx, sb.ID, "")
		if err != nil || rec.State != api.Running {
			t.Fatalf("round %d resume: %+v %v", round, rec, err)
		}
		if ev := lastEventTo(t, e, sb.ID, api.Running); ev.Detail != "restored from "+ck.ID {
			t.Fatalf("round %d history: %+v", round, ev)
		}
		if _, err := e.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"true"}}); err != nil {
			t.Fatalf("round %d exec after resume: %v", round, err)
		}
	}
	if a, ok := auditActions(t, e, sb.ID)["sandbox.resume"]; !ok || !strings.HasPrefix(a.Detail, "from ck-") {
		t.Fatalf("audit: %+v", a)
	}
}

// Resuming from an earlier snapshot rolls the sandbox back to that moment.
func TestResumeFromAnEarlierSnapshot(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "rollback"})
	early, _ := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{LeaveRunning: true})
	if _, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.Resume(ctx, sb.ID, early.ID); err != nil {
		t.Fatal(err)
	}
	if ev := lastEventTo(t, e, sb.ID, api.Running); ev.Detail != "restored from "+early.ID {
		t.Fatalf("should have resumed from the snapshot: %+v", ev)
	}
}

func TestResumeRefusals(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	a, _ := e.c.Create(ctx, api.CreateRequest{ID: "ra"})
	if _, err := e.c.Resume(ctx, a.ID, ""); !errors.Is(err, client.ErrConflict) {
		t.Fatalf("resuming a running sandbox: want ErrConflict, got %v", err)
	}
	b, _ := e.c.Create(ctx, api.CreateRequest{ID: "rb"})
	bck, _ := e.c.Checkpoint(ctx, b.ID, api.CheckpointRequest{})
	_, _ = e.c.Checkpoint(ctx, a.ID, api.CheckpointRequest{})
	if _, err := e.c.Resume(ctx, a.ID, "ck-nope"); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("unknown checkpoint: want ErrNotFound, got %v", err)
	}
	// One sandbox may never be restored from another's image.
	if _, err := e.c.Resume(ctx, a.ID, bck.ID); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("another sandbox's checkpoint: want ErrNotFound, got %v", err)
	}
	// An image gone from disk: refused, and still paused.
	_ = os.RemoveAll(bck.Path)
	if _, err := e.c.Resume(ctx, b.ID, ""); !errors.Is(err, client.ErrNotFound) || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing image: want ErrNotFound, got %v", err)
	}
	if rec, _ := e.c.Get(ctx, b.ID); rec.State != api.Paused {
		t.Fatalf("still paused? %+v", rec)
	}
}

func TestFailedRestoreStaysPaused(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "rf"})
	_, _ = e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{})
	e.b.mu.Lock()
	e.b.failRestore = errors.New("runsc restore: the image doesn't match this runsc")
	e.b.mu.Unlock()
	if _, err := e.c.Resume(ctx, sb.ID, ""); err == nil {
		t.Fatal("the restore should fail")
	}
	if rec, _ := e.c.Get(ctx, sb.ID); rec.State != api.Paused {
		t.Fatalf("a failed restore must leave it paused: %+v", rec)
	}
	if ev := lastEventTo(t, e, sb.ID, api.Paused); !strings.HasPrefix(ev.Detail, "restore failed") {
		t.Fatalf("history: %+v", ev)
	}
	e.b.mu.Lock()
	e.b.failRestore = nil
	e.b.mu.Unlock()
	if rec, err := e.c.Resume(ctx, sb.ID, ""); err != nil || rec.State != api.Running {
		t.Fatalf("a retry should work: %+v %v", rec, err)
	}
}

// Paused by one daemon, resumed by the next: the path Day 12 builds on.
func TestResumeAfterADaemonRestart(t *testing.T) {
	dir, _ := os.MkdirTemp("", "sbxd")
	t.Cleanup(func() { os.RemoveAll(dir) })
	db := filepath.Join(dir, "registry.db")
	e := startWith(t, newFakeBackend(), db, filepath.Join(dir, "a.sock"))
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "phoenix"})
	if _, err := e.c.Checkpoint(tctx(t), sb.ID, api.CheckpointRequest{}); err != nil {
		t.Fatal(err)
	}
	e.reg.Close()

	e2 := startWith(t, newFakeBackend(), db, filepath.Join(dir, "b.sock"))
	if rec, err := e2.c.Resume(tctx(t), sb.ID, ""); err != nil || rec.State != api.Running {
		t.Fatalf("resume after a restart: %+v %v", rec, err)
	}
}

// A daemon that dies mid-restore: the next one puts the sandbox back to
// paused (its image is untouched), rather than failing it.
func TestInterruptedRestoreGoesBackToPaused(t *testing.T) {
	dir, _ := os.MkdirTemp("", "sbxd")
	t.Cleanup(func() { os.RemoveAll(dir) })
	db := filepath.Join(dir, "registry.db")
	e := startWith(t, newFakeBackend(), db, filepath.Join(dir, "a.sock"))
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "midway"})
	_, _ = e.c.Checkpoint(tctx(t), sb.ID, api.CheckpointRequest{})
	if _, err := e.reg.Transition(context.Background(), sb.ID, registry.Paused, registry.Restoring, ""); err != nil {
		t.Fatal(err)
	}
	e.reg.Close() // the daemon dies, mid-restore

	e2 := startWith(t, newFakeBackend(), db, filepath.Join(dir, "b.sock"))
	rec, _ := e2.c.Get(tctx(t), sb.ID)
	if rec.State != api.Paused {
		t.Fatalf("want paused, got %+v", rec)
	}
	if ev := lastEventTo(t, e2, sb.ID, api.Paused); !strings.Contains(ev.Detail, "during a restore") {
		t.Fatalf("history: %+v", ev)
	}
}
