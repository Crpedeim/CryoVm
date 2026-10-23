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
	"github.com/Crpedeim/sbx/internal/registry"
)

// twoDaemons gives a fresh database path, for a first daemon and a second
// one started on the same registry.
func twoDaemons(t *testing.T) (db, dir string) {
	t.Helper()
	dir, _ = os.MkdirTemp("", "sbxd")
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "registry.db"), dir
}

func lastNote(t *testing.T, e *env, id string) string {
	t.Helper()
	evs, _ := e.c.Events(tctx(t), id)
	if len(evs) == 0 {
		t.Fatalf("%s: no history", id)
	}
	return evs[len(evs)-1].Detail
}

// A daemon crash doesn't stop gVisor sandboxes: the next daemon adopts
// them, and nothing inside ever stopped.
func TestCrashedDaemonAdoptsRunningSandboxes(t *testing.T) {
	db, dir := twoDaemons(t)
	b := newFakeBackend()
	e1 := startWith(t, b, db, filepath.Join(dir, "a.sock"))
	sb, _ := e1.c.Create(tctx(t), api.CreateRequest{ID: "survivor"})
	e1.reg.Close() // kill -9: no Close, the sandbox keeps running

	e2 := startWith(t, b, db, filepath.Join(dir, "b.sock"))
	rec, _ := e2.c.Get(tctx(t), sb.ID)
	if rec.State != api.Running {
		t.Fatalf("want running, got %+v", rec)
	}
	if n := lastNote(t, e2, sb.ID); !strings.HasPrefix(n, "adopted after a daemon restart") {
		t.Fatalf("history: %q", n)
	}
	if _, err := e2.c.Exec(tctx(t), sb.ID, client.ExecRequest{Args: []string{"true"}}); err != nil {
		t.Fatalf("exec through the new daemon: %v", err)
	}
	if a, ok := auditActions(t, e2, sb.ID)["sandbox.adopt"]; !ok || a.Actor != "sbxd" {
		t.Fatalf("audit: %+v", a)
	}
}

// The host rebooted while the daemon was down: the sandbox is gone, and the
// record says so.
func TestGoneWhileTheDaemonWasDownIsFailed(t *testing.T) {
	db, dir := twoDaemons(t)
	b := newFakeBackend()
	e1 := startWith(t, b, db, filepath.Join(dir, "a.sock"))
	sb, _ := e1.c.Create(tctx(t), api.CreateRequest{ID: "lost"})
	e1.reg.Close()
	b.get(sb.ID).end()

	e2 := startWith(t, b, db, filepath.Join(dir, "b.sock"))
	rec, _ := e2.c.Get(tctx(t), sb.ID)
	if rec.State != api.Failed || !strings.Contains(rec.Error, "no longer running") {
		t.Fatalf("want failed, no longer running: %+v", rec)
	}
}

// Stop policy "pause": running sandboxes are checkpointed (busy ones too)
// and resumed by the next daemon; one you paused yourself stays paused.
func TestShutdownPausesAndStartResumes(t *testing.T) {
	db, dir := twoDaemons(t)
	pause := func(c *Config) { c.OnStop = OnStopPause }
	e1 := startWith(t, newFakeBackend(), db, filepath.Join(dir, "a.sock"), pause)
	ctx := tctx(t)
	for _, id := range []string{"idle", "busy", "mine"} {
		if _, err := e1.c.Create(ctx, api.CreateRequest{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e1.c.Checkpoint(ctx, "mine", api.CheckpointRequest{}); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = e1.c.Exec(context.Background(), "busy", client.ExecRequest{Args: []string{"sleep", "5"}})
	}()
	time.Sleep(200 * time.Millisecond)

	e1.m.Close(ctx) // a clean stop
	for _, id := range []string{"idle", "busy"} {
		rec, _ := e1.reg.Get(ctx, id)
		if rec.State != api.Paused || !rec.ResumeOnStart {
			t.Fatalf("%s after the shutdown: %+v", id, rec)
		}
	}
	if rec, _ := e1.reg.Get(ctx, "mine"); rec.ResumeOnStart {
		t.Fatal("a sandbox you paused isn't marked to resume")
	}
	e1.reg.Close()

	e2 := startWith(t, newFakeBackend(), db, filepath.Join(dir, "b.sock"), pause)
	for _, id := range []string{"idle", "busy"} {
		rec, _ := e2.c.Get(ctx, id)
		if rec.State != api.Running || rec.ResumeOnStart {
			t.Fatalf("%s after the restart: %+v", id, rec)
		}
		if ev := lastEventTo(t, e2, id, api.Running); !strings.HasPrefix(ev.Detail, "restored from ck-") {
			t.Fatalf("%s history: %+v", id, ev)
		}
	}
	if rec, _ := e2.c.Get(ctx, "mine"); rec.State != api.Paused {
		t.Fatalf("your paused sandbox should stay paused: %+v", rec)
	}
}

// Stop policy "leave": nothing is touched, and the next daemon adopts.
func TestLeavePolicyAdoptsOnStart(t *testing.T) {
	db, dir := twoDaemons(t)
	b := newFakeBackend()
	e1 := startWith(t, b, db, filepath.Join(dir, "a.sock"), func(c *Config) { c.OnStop = OnStopLeave })
	sb, _ := e1.c.Create(tctx(t), api.CreateRequest{ID: "left"})
	e1.m.Close(tctx(t))
	if n := lastNote(t, e1, sb.ID); !strings.Contains(n, "left running") {
		t.Fatalf("history at stop: %q", n)
	}
	e1.reg.Close()
	e2 := startWith(t, b, db, filepath.Join(dir, "b.sock"))
	if rec, _ := e2.c.Get(tctx(t), sb.ID); rec.State != api.Running {
		t.Fatalf("want adopted, got %+v", rec)
	}
}

// A destroy interrupted by a restart is finished, not failed: someone
// wanted that sandbox gone.
func TestInterruptedDestroyIsFinished(t *testing.T) {
	db, dir := twoDaemons(t)
	e1 := startWith(t, newFakeBackend(), db, filepath.Join(dir, "a.sock"))
	sb, _ := e1.c.Create(tctx(t), api.CreateRequest{ID: "doomed"})
	ck, _ := e1.c.Checkpoint(tctx(t), sb.ID, api.CheckpointRequest{LeaveRunning: true})
	if _, err := e1.reg.Transition(context.Background(), sb.ID, registry.Running, registry.Stopping, "destroy requested"); err != nil {
		t.Fatal(err)
	}
	e1.reg.Close()
	e2 := startWith(t, newFakeBackend(), db, filepath.Join(dir, "b.sock"))
	rec, _ := e2.c.Get(tctx(t), sb.ID)
	if rec.State != api.Stopped || lastNote(t, e2, sb.ID) != "destroy finished after a daemon restart" {
		t.Fatalf("want stopped: %+v", rec)
	}
	if _, err := os.Stat(ck.Path); !os.IsNotExist(err) {
		t.Fatal("its images should be gone too")
	}
}

// A checkpoint interrupted by a restart: the sandbox still runs, so it's
// adopted back to running.
func TestInterruptedCheckpointIsAdopted(t *testing.T) {
	db, dir := twoDaemons(t)
	b := newFakeBackend()
	e1 := startWith(t, b, db, filepath.Join(dir, "a.sock"))
	sb, _ := e1.c.Create(tctx(t), api.CreateRequest{ID: "midck"})
	if _, err := e1.reg.Transition(context.Background(), sb.ID, registry.Running, registry.Checkpointing, ""); err != nil {
		t.Fatal(err)
	}
	e1.reg.Close()
	e2 := startWith(t, b, db, filepath.Join(dir, "b.sock"))
	rec, _ := e2.c.Get(tctx(t), sb.ID)
	if rec.State != api.Running || !strings.Contains(lastNote(t, e2, sb.ID), "checkpoint interrupted") {
		t.Fatalf("want adopted to running: %+v", rec)
	}
}

// A resume on start that fails leaves the sandbox paused and unmarked:
// someone should look, rather than every start retrying.
func TestFailedResumeOnStartStaysPaused(t *testing.T) {
	db, dir := twoDaemons(t)
	pause := func(c *Config) { c.OnStop = OnStopPause }
	e1 := startWith(t, newFakeBackend(), db, filepath.Join(dir, "a.sock"), pause)
	sb, _ := e1.c.Create(tctx(t), api.CreateRequest{ID: "stuck"})
	e1.m.Close(tctx(t))
	e1.reg.Close()
	b2 := newFakeBackend()
	b2.failRestore = errors.New("runsc restore: the image doesn't match this runsc")
	e2 := startWith(t, b2, db, filepath.Join(dir, "b.sock"), pause)
	rec, _ := e2.c.Get(tctx(t), sb.ID)
	if rec.State != api.Paused || rec.ResumeOnStart {
		t.Fatalf("want paused and unmarked: %+v", rec)
	}
}

func TestUnknownStopPolicyIsRefused(t *testing.T) {
	db, _ := twoDaemons(t)
	reg, err := registry.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	_, err = New(context.Background(), Config{Backend: newFakeBackend(), Registry: reg, OnStop: "explode", Logf: t.Logf})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}
