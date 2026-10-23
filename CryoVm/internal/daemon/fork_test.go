package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

func TestForkMakesANewSandbox(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	src, _ := e.c.Create(ctx, api.CreateRequest{ID: "origin"})
	forks, err := e.c.Fork(ctx, src.ID, api.ForkRequest{})
	if err != nil || len(forks) != 1 {
		t.Fatalf("fork: %+v %v", forks, err)
	}
	f := forks[0]
	if f.ID == src.ID || f.ForkedFrom != src.ID || f.State != api.Running {
		t.Fatalf("the fork: %+v", f)
	}
	if ev := lastEventTo(t, e, f.ID, api.Running); !strings.HasPrefix(ev.Detail, "forked from origin at ck-") {
		t.Fatalf("history: %+v", ev)
	}
	if _, err := e.c.Exec(ctx, f.ID, client.ExecRequest{Args: []string{"true"}}); err != nil {
		t.Fatalf("exec in the fork: %v", err)
	}
	if rec, _ := e.c.Get(ctx, src.ID); rec.State != api.Running {
		t.Fatalf("the source should keep running: %+v", rec)
	}
	if cks, _ := e.c.Checkpoints(ctx, src.ID); len(cks) != 1 || !cks[0].LeftRunning {
		t.Fatalf("the snapshot belongs to the source: %+v", cks)
	}
	if a, ok := auditActions(t, e, f.ID)["sandbox.fork"]; !ok || !strings.HasPrefix(a.Detail, "from origin at ck-") {
		t.Fatalf("audit: %+v", a)
	}
}

// One snapshot, many forks.
func TestForkMany(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	src, _ := e.c.Create(ctx, api.CreateRequest{ID: "fan"})
	forks, err := e.c.Fork(ctx, src.ID, api.ForkRequest{Count: 3})
	if err != nil || len(forks) != 3 {
		t.Fatalf("fork x3: %+v %v", forks, err)
	}
	seen := map[string]bool{}
	for _, f := range forks {
		seen[f.ID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("three distinct sandboxes: %+v", forks)
	}
	if cks, _ := e.c.Checkpoints(ctx, src.ID); len(cks) != 1 {
		t.Fatalf("three forks from one snapshot, not %d", len(cks))
	}
}

// A sleeping source is forked from its latest pause, and stays asleep.
func TestForkASleepingSandboxWithoutWakingIt(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	src := napper(t, e, "dreamer")
	waitState(t, e, src.ID, api.Paused, 4*time.Second)
	forks, err := e.c.Fork(ctx, src.ID, api.ForkRequest{})
	if err != nil || len(forks) != 1 {
		t.Fatalf("fork: %+v %v", forks, err)
	}
	if rec, _ := e.c.Get(ctx, src.ID); rec.State != api.Paused {
		t.Fatalf("forking woke the source: %+v", rec)
	}
	if cks, _ := e.c.Checkpoints(ctx, src.ID); len(cks) != 1 {
		t.Fatalf("no new snapshot should be taken: %d checkpoints", len(cks))
	}
}

func TestForkFromANamedCheckpoint(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	src, _ := e.c.Create(ctx, api.CreateRequest{ID: "history"})
	early, _ := e.c.Checkpoint(ctx, src.ID, api.CheckpointRequest{LeaveRunning: true})
	forks, err := e.c.Fork(ctx, src.ID, api.ForkRequest{Checkpoint: early.ID, ID: "from-the-past"})
	if err != nil || len(forks) != 1 || forks[0].ID != "from-the-past" {
		t.Fatalf("fork: %+v %v", forks, err)
	}
	if ev := lastEventTo(t, e, "from-the-past", api.Running); ev.Detail != "forked from history at "+early.ID {
		t.Fatalf("history: %+v", ev)
	}
}

func TestForkRefusals(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	src, _ := e.c.Create(ctx, api.CreateRequest{ID: "picky"})
	for _, tc := range []struct {
		req  api.ForkRequest
		want error
	}{
		{api.ForkRequest{Count: 17}, client.ErrInvalid},
		{api.ForkRequest{Count: -1}, client.ErrInvalid},
		{api.ForkRequest{Count: 2, ID: "twins"}, client.ErrInvalid},
		{api.ForkRequest{ID: "picky"}, client.ErrConflict}, // that ID is taken
		{api.ForkRequest{Checkpoint: "ck-nope"}, client.ErrNotFound},
	} {
		if _, err := e.c.Fork(ctx, src.ID, tc.req); !errors.Is(err, tc.want) {
			t.Errorf("%+v: want %v, got %v", tc.req, tc.want, err)
		}
	}
	if _, err := e.c.Fork(ctx, "nobody", api.ForkRequest{}); !errors.Is(err, client.ErrNotFound) {
		t.Errorf("unknown source: %v", err)
	}
	_, _ = e.c.Destroy(ctx, src.ID)
	if _, err := e.c.Fork(ctx, src.ID, api.ForkRequest{}); !errors.Is(err, client.ErrConflict) {
		t.Errorf("stopped source: %v", err)
	}
}

// A fork that fails is recorded as a failed fork; the source is untouched.
func TestFailedForkLeavesTheSourceAlone(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	src, _ := e.c.Create(ctx, api.CreateRequest{ID: "steady"})
	e.b.mu.Lock()
	e.b.failRestore = errors.New("runsc restore: the image doesn't match this runsc")
	e.b.mu.Unlock()
	if _, err := e.c.Fork(ctx, src.ID, api.ForkRequest{ID: "doomed-fork"}); err == nil {
		t.Fatal("the fork should fail")
	}
	if rec, _ := e.c.Get(ctx, "doomed-fork"); rec.State != api.Failed || !strings.HasPrefix(rec.Error, "fork failed") {
		t.Fatalf("the failed fork's record: %+v", rec)
	}
	if rec, _ := e.c.Get(ctx, src.ID); rec.State != api.Running {
		t.Fatalf("the source: %+v", rec)
	}
}

// A snapshot quiesces the source (Day 14 v2: without it, real gVisor left
// the source unreachable), which cuts off its execs. So a busy sandbox's
// snapshot, and fork, are refused unless forced, like a pause.
func TestBusySnapshotAndForkNeedForce(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "working"})
	go func() { _, _ = e.c.Exec(context.Background(), sb.ID, client.ExecRequest{Args: []string{"sleep", "3"}}) }()
	time.Sleep(300 * time.Millisecond)
	if _, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{LeaveRunning: true}); !errors.Is(err, client.ErrConflict) {
		t.Fatalf("a snapshot of a busy sandbox: want a busy conflict, got %v", err)
	}
	if _, err := e.c.Fork(ctx, sb.ID, api.ForkRequest{}); !errors.Is(err, client.ErrConflict) {
		t.Fatalf("a fork of a busy sandbox: want a busy conflict, got %v", err)
	}
	if forks, err := e.c.Fork(ctx, sb.ID, api.ForkRequest{Force: true}); err != nil || len(forks) != 1 {
		t.Fatalf("a forced fork: %+v %v", forks, err)
	}
}

// Day 14's race: a pause must not say "paused" until its cleanup is done,
// or a wake in between restores into a bundle the cleanup then deletes.
// The cleanup is made slow, so the old order fails every time.
func TestPausedOnlyAfterCleanup(t *testing.T) {
	e := start(t)
	sb := napper(t, e, "tidy")
	fake := e.b.get(sb.ID)
	fake.mu.Lock()
	fake.cleanupDelay = 300 * time.Millisecond
	fake.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rec, _ := e.c.Get(tctx(t), sb.ID); rec.State == api.Paused {
			if !fake.wasCleanedUp() {
				t.Fatal("the state said paused while the old sandbox's cleanup was still running")
			}
			// And a wake right now works.
			if _, err := e.c.Exec(tctx(t), sb.ID, client.ExecRequest{Args: []string{"true"}}); err != nil {
				t.Fatalf("a wake right after the pause: %v", err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("never paused")
}

// Day 23: clones are made in parallel. With every restore taking 100 ms,
// eight clones finish in well under 8 x 100 ms, each its own sandbox with
// its own files, returned in order.
func TestForkClonesInParallel(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	src, _ := e.c.Create(ctx, api.CreateRequest{ID: "src"})
	e.b.mu.Lock()
	e.b.restoreTook = 100 * time.Millisecond
	e.b.mu.Unlock()
	t0 := time.Now()
	forks, err := e.c.Fork(ctx, src.ID, api.ForkRequest{Count: 8})
	took := time.Since(t0)
	if err != nil || len(forks) != 8 {
		t.Fatalf("fork 8: %d %v", len(forks), err)
	}
	if took >= 600*time.Millisecond {
		t.Fatalf("8 clones at 100 ms each took %s: they should overlap", took)
	}
	seen := map[string]bool{}
	for _, f := range forks {
		if seen[f.ID] || f.State != api.Running || f.ForkedFrom != src.ID {
			t.Fatalf("clone %+v", f)
		}
		seen[f.ID] = true
		echoOK(t, e, f.ID)
	}
	t.Logf("8 clones with 100 ms restores in %s", took.Round(time.Millisecond))
}

// A failing clone doesn't stop the others: the successes come back, with
// the error.
func TestForkPartialFailure(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	src, _ := e.c.Create(ctx, api.CreateRequest{ID: "src"})
	if _, err := e.c.Checkpoint(ctx, src.ID, api.CheckpointRequest{LeaveRunning: true}); err != nil {
		t.Fatal(err)
	}
	e.b.mu.Lock()
	e.b.failRestore = errors.New("no room")
	e.b.mu.Unlock()
	forks, err := e.m.Fork(ctx, src.ID, api.ForkRequest{Count: 3})
	if err == nil || len(forks) != 0 {
		t.Fatalf("all failing: %d forks, %v", len(forks), err)
	}
	for _, s := range mustList(t, e) {
		if s.ForkedFrom == src.ID && s.State != api.Failed {
			t.Fatalf("a failed clone should be marked failed: %+v", s)
		}
	}
}

func mustList(t *testing.T, e *env) []api.Sandbox {
	t.Helper()
	all, err := e.c.List(tctx(t), true)
	if err != nil {
		t.Fatal(err)
	}
	return all
}
