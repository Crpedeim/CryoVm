package daemon

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

// waitState polls until the sandbox reaches want or the deadline passes.
func waitState(t *testing.T, e *env, id string, want api.State, within time.Duration) api.Sandbox {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		rec, err := e.c.Get(tctx(t), id)
		if err == nil && rec.State == want {
			return rec
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: want %s within %s, got %+v %v", id, want, within, rec, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func lastEvent(t *testing.T, e *env, id string) api.Event {
	t.Helper()
	evs, _ := e.c.Events(tctx(t), id)
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].To == api.Stopping {
			return evs[i]
		}
	}
	t.Fatalf("%s: no stopping event in %+v", id, evs)
	return api.Event{}
}

func auditActions(t *testing.T, e *env, id string) map[string]api.AuditEntry {
	t.Helper()
	entries, err := e.c.Audit(tctx(t), id, 100)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]api.AuditEntry{}
	for _, en := range entries {
		if _, seen := out[en.Action]; !seen { // newest first: keep the latest of each
			out[en.Action] = en
		}
	}
	return out
}

func TestLifetimeExpires(t *testing.T) {
	e := start(t)
	sb, err := e.c.Create(tctx(t), api.CreateRequest{ID: "brief", TTLSeconds: 1})
	if err != nil || sb.ExpiresAt == nil {
		t.Fatalf("create: %+v %v", sb, err)
	}
	waitState(t, e, sb.ID, api.Stopped, 3*time.Second)
	if ev := lastEvent(t, e, sb.ID); !strings.HasPrefix(ev.Detail, "lifetime expired") {
		t.Fatalf("history should say why: %q", ev.Detail)
	}
	if a, ok := auditActions(t, e, sb.ID)["lifetime.expire"]; !ok || a.Actor != "sbxd" {
		t.Fatalf("audit: %+v", a)
	}
}

func TestDefaultAndNoTTL(t *testing.T) {
	e := start(t, func(c *Config) { c.DefaultTTL = time.Hour })
	def, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "def"})
	if def.ExpiresAt == nil || time.Until(*def.ExpiresAt) < 59*time.Minute {
		t.Fatalf("the daemon's default ttl should apply: %+v", def.ExpiresAt)
	}
	none, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "none", TTLSeconds: -1})
	if none.ExpiresAt != nil {
		t.Fatalf("-1 means no deadline: %+v", none.ExpiresAt)
	}
	if _, err := e.c.Create(tctx(t), api.CreateRequest{ID: "bad", TTLSeconds: -5}); !errors.Is(err, client.ErrInvalid) {
		t.Fatalf("ttl -5: want ErrInvalid, got %v", err)
	}
}

func TestUseKeepsAnIdleTimeoutAtBay(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "busy", IdleTimeoutS: 1})
	for i := 0; i < 8; i++ { // 2.4 s of steady use, more than twice the timeout
		if _, err := e.c.Exec(tctx(t), sb.ID, client.ExecRequest{Args: []string{"true"}}); err != nil {
			t.Fatalf("exec %d: %v", i, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if rec, _ := e.c.Get(tctx(t), sb.ID); rec.State != api.Running {
		t.Fatalf("used every 300 ms, yet: %+v", rec)
	}
	waitState(t, e, sb.ID, api.Stopped, 3*time.Second) // left alone, it goes
	if ev := lastEvent(t, e, sb.ID); !strings.HasPrefix(ev.Detail, "idle for") {
		t.Fatalf("history: %q", ev.Detail)
	}
}

// A command running longer than the idle timeout is use, not idleness.
func TestALongOperationIsNotIdle(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "long", IdleTimeoutS: 1})
	if _, err := e.c.Exec(tctx(t), sb.ID, client.ExecRequest{Args: []string{"sleep", "2.5"}}); err != nil {
		t.Fatalf("a 2.5 s command in a sandbox with a 1 s idle timeout was cut short: %v", err)
	}
	if rec, _ := e.c.Get(tctx(t), sb.ID); rec.State != api.Running {
		t.Fatalf("destroyed during its own command: %+v", rec)
	}
}

// Watching isn't using: stats and info must not keep a sandbox alive.
func TestMonitoringDoesNotKeepASandboxAlive(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "watched", IdleTimeoutS: 1})
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		rec, _ := e.c.Get(tctx(t), sb.ID)
		if rec.State == api.Stopped {
			return
		}
		_, _ = e.c.Stats(tctx(t), sb.ID)
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("polled with stats and info every 100 ms, the sandbox never went idle")
}

func TestExtend(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "ext", TTLSeconds: 1})
	ext, err := e.c.Extend(tctx(t), sb.ID, time.Hour)
	if err != nil || ext.ExpiresAt == nil || time.Until(*ext.ExpiresAt) < 59*time.Minute {
		t.Fatalf("extend: %+v %v", ext, err)
	}
	time.Sleep(1500 * time.Millisecond)
	if rec, _ := e.c.Get(tctx(t), sb.ID); rec.State != api.Running {
		t.Fatalf("extended, yet: %+v", rec)
	}
	if _, err := e.c.Extend(tctx(t), sb.ID, -time.Second); !errors.Is(err, client.ErrInvalid) {
		t.Fatalf("negative extension: want ErrInvalid, got %v", err)
	}
	_, _ = e.c.Destroy(tctx(t), sb.ID)
	if _, err := e.c.Extend(tctx(t), sb.ID, time.Hour); !errors.Is(err, client.ErrConflict) {
		t.Fatalf("extending a stopped sandbox: want ErrConflict, got %v", err)
	}
}

// The audit log records who did what: the actor comes from the kernel's
// peer credentials, so it names this test's own user and process.
func TestAuditRecordsWhoAndWhat(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "audited"})
	_, _ = e.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "echo hi; exit 3"}})
	dir := t.TempDir()
	_, _ = e.c.Put(ctx, sb.ID, dir+"/f.txt", strings.NewReader("hello"), client.PutOptions{})
	p, _ := e.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"sleep", "30"}})
	_ = e.c.Signal(ctx, sb.ID, p.ID, 9)
	_, _ = e.c.Exec(ctx, "no-such-sandbox", client.ExecRequest{Args: []string{"true"}})
	_, _ = e.c.Destroy(ctx, sb.ID)

	got := auditActions(t, e, sb.ID)
	for _, action := range []string{"sandbox.create", "exec", "file.write", "process.start", "process.signal", "sandbox.destroy"} {
		if _, ok := got[action]; !ok {
			t.Errorf("no %s entry", action)
		}
	}
	ex := got["exec"]
	if ex.Detail != `sh -c "echo hi; exit 3" → exit 3` {
		t.Errorf("exec detail %q", ex.Detail)
	}
	if want := fmt.Sprintf("(uid %d) via", os.Getuid()); !strings.Contains(ex.Actor, want) && !strings.HasPrefix(ex.Actor, fmt.Sprintf("uid %d via", os.Getuid())) {
		t.Errorf("actor %q should name this user and process", ex.Actor)
	}
	if fw := got["file.write"]; !strings.Contains(fw.Detail, "f.txt (5 bytes, sha256 2cf24dba5fb0") {
		t.Errorf("file.write detail %q", fw.Detail)
	}
	// Failures are recorded too, with the error.
	fails, _ := e.c.Audit(ctx, "no-such-sandbox", 10)
	if len(fails) != 1 || fails[0].Outcome != "error" || fails[0].Error == "" {
		t.Errorf("a failed exec should be recorded as an error: %+v", fails)
	}
	if v, err := e.c.VerifyAudit(ctx); err != nil || !v.OK || v.Entries < 7 {
		t.Fatalf("verify: %+v %v", v, err)
	}
}

func TestShellAttachmentsAreAudited(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "shaudit"})
	a := attach(t, e.c, sb.ID, client.ShellOptions{})
	_ = a.conn.Detach()
	a.end(t)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got := auditActions(t, e, sb.ID)
		if end, ok := got["shell.end"]; ok {
			if open := got["shell.open"]; !strings.Contains(open.Detail, a.conn.SessionID) || !strings.Contains(end.Detail, "detached") {
				t.Fatalf("open %q / end %q", open.Detail, end.Detail)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no shell.end entry")
}
