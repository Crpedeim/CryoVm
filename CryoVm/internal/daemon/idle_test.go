package daemon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

func napper(t *testing.T, e *env, id string) api.Sandbox {
	t.Helper()
	sb, err := e.c.Create(tctx(t), api.CreateRequest{ID: id, IdleTimeoutS: 1, IdleAction: api.IdlePause})
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

func TestIdleSandboxIsPausedNotDestroyed(t *testing.T) {
	e := start(t)
	sb := napper(t, e, "nap")
	rec := waitState(t, e, sb.ID, api.Paused, 4*time.Second)
	if !rec.WakeOnUse {
		t.Fatalf("an idle pause wakes on use: %+v", rec)
	}
	if ev := lastEventTo(t, e, sb.ID, api.Paused); !strings.HasPrefix(ev.Detail, "paused while idle") {
		t.Fatalf("history: %+v", ev)
	}
	if a, ok := auditActions(t, e, sb.ID)["idle.pause"]; !ok || a.Actor != "sbxd" {
		t.Fatalf("audit: %+v", a)
	}
}

// Using a sleeping sandbox wakes it, transparently: the exec just works.
func TestUseWakesAnIdlePausedSandbox(t *testing.T) {
	e := start(t)
	sb := napper(t, e, "wakeme")
	waitState(t, e, sb.ID, api.Paused, 4*time.Second)
	var out strings.Builder
	if _, err := e.c.Exec(tctx(t), sb.ID, client.ExecRequest{Args: []string{"echo", "awake"}, Stdout: &out}); err != nil {
		t.Fatalf("an exec on a sleeping sandbox should wake it, not fail: %v", err)
	}
	rec, _ := e.c.Get(tctx(t), sb.ID)
	if rec.State != api.Running || rec.WakeOnUse {
		t.Fatalf("after the wake: %+v", rec)
	}
	if a, ok := auditActions(t, e, sb.ID)["sandbox.wake"]; !ok || !strings.HasPrefix(a.Detail, "woken by use") {
		t.Fatalf("audit: %+v", a)
	}
}

// Ten requests at once wake it once.
func TestConcurrentUseWakesOnce(t *testing.T) {
	e := start(t)
	sb := napper(t, e, "crowd")
	waitState(t, e, sb.ID, api.Paused, 4*time.Second)
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.c.Exec(context.Background(), sb.ID, client.ExecRequest{Args: []string{"true"}})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent request failed: %v", err)
		}
	}
	e.b.mu.Lock()
	restores := e.b.restores
	e.b.mu.Unlock()
	if restores != 1 {
		t.Fatalf("ten concurrent requests restored it %d times, want once", restores)
	}
}

// A pause you asked for is a decision, not an optimization: no waking.
func TestYourPauseDoesNotWake(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "deliberate"})
	if _, err := e.c.Checkpoint(tctx(t), sb.ID, api.CheckpointRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.Exec(tctx(t), sb.ID, client.ExecRequest{Args: []string{"true"}}); !errors.Is(err, client.ErrConflict) {
		t.Fatalf("exec on a sandbox you paused: want ErrConflict, got %v", err)
	}
}

// Watching isn't using (Day 9's rule): stats and info leave it asleep.
func TestWatchingDoesNotWake(t *testing.T) {
	e := start(t)
	sb := napper(t, e, "watched")
	waitState(t, e, sb.ID, api.Paused, 4*time.Second)
	_, _ = e.c.Stats(tctx(t), sb.ID)
	_, _ = e.c.Get(tctx(t), sb.ID)
	_, _ = e.c.Events(tctx(t), sb.ID)
	if rec, _ := e.c.Get(tctx(t), sb.ID); rec.State != api.Paused {
		t.Fatalf("watching woke it: %+v", rec)
	}
}

// CPU use is activity: a build with nobody calling the API isn't idle.
func TestBusyCPUIsNotIdle(t *testing.T) {
	e := start(t)
	sb := napper(t, e, "builder")
	fake := e.b.get(sb.ID)
	stop := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(stop) { // half a core, for 2.5 s: more than twice the timeout
		fake.burnCPU(50 * time.Millisecond)
		time.Sleep(100 * time.Millisecond)
	}
	if rec, _ := e.c.Get(tctx(t), sb.ID); rec.State != api.Running {
		t.Fatalf("paused mid-build: %+v", rec)
	}
	waitState(t, e, sb.ID, api.Paused, 4*time.Second) // the build ends: now it's idle
}

// The idle action is per sandbox; "destroy" is Day 9's behavior.
func TestIdleActionDestroyStillDestroys(t *testing.T) {
	e := start(t, func(c *Config) { c.DefaultIdleAction = api.IdlePause })
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "gone", IdleTimeoutS: 1, IdleAction: api.IdleDestroy})
	waitState(t, e, sb.ID, api.Stopped, 4*time.Second)
	def, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "def", IdleTimeoutS: 1})
	if def.IdleAction != api.IdlePause {
		t.Fatalf("the daemon's default should apply: %+v", def)
	}
	if _, err := e.c.Create(tctx(t), api.CreateRequest{ID: "bad", IdleAction: "hibernate"}); !errors.Is(err, client.ErrInvalid) {
		t.Fatalf("unknown idle action: want ErrInvalid, got %v", err)
	}
}

// Asleep across a daemon restart, and still wakes on use.
func TestSleepingSandboxWakesAfterARestart(t *testing.T) {
	db, dir := twoDaemons(t)
	e1 := startWith(t, newFakeBackend(), db, dir+"/a.sock")
	sb := napper(t, e1, "longnap")
	waitState(t, e1, sb.ID, api.Paused, 4*time.Second)
	e1.m.Close(tctx(t))
	e1.reg.Close()
	e2 := startWith(t, newFakeBackend(), db, dir+"/b.sock")
	if rec, _ := e2.c.Get(tctx(t), sb.ID); rec.State != api.Paused {
		t.Fatalf("still asleep after the restart: %+v", rec)
	}
	if _, err := e2.c.Exec(tctx(t), sb.ID, client.ExecRequest{Args: []string{"true"}}); err != nil {
		t.Fatalf("waking after a restart: %v", err)
	}
}
