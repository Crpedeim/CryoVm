package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func open(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.db")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, path
}

var ctx = context.Background()

func TestLifecycleAndHistory(t *testing.T) {
	r, _ := open(t)
	s, err := r.Create(ctx, Sandbox{ID: "a", Backend: "gvisor", Rootfs: "/r", VCPUs: 1, MemMiB: 256})
	if err != nil || s.State != Creating {
		t.Fatalf("create: %+v %v", s, err)
	}
	steps := []State{Running, Stopping, Stopped}
	from := Creating
	for _, to := range steps {
		if _, err := r.Transition(ctx, "a", from, to, "step"); err != nil {
			t.Fatalf("%s → %s: %v", from, to, err)
		}
		from = to
	}
	evs, err := r.Events(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	want := []State{Creating, Running, Stopping, Stopped}
	if len(evs) != len(want) {
		t.Fatalf("%d events, want %d", len(evs), len(want))
	}
	for i, e := range evs {
		if e.To != want[i] || (i > 0 && e.From != want[i-1]) {
			t.Errorf("event %d: %s → %s", i, e.From, e.To)
		}
	}
}

func TestIllegalTransitionsAreRefused(t *testing.T) {
	r, _ := open(t)
	_, _ = r.Create(ctx, Sandbox{ID: "b", Backend: "gvisor"})
	for _, tc := range []struct{ from, to State }{
		{Creating, Stopped}, // skipping steps
		{Creating, Paused},  // never ran
		{Stopped, Running},  // resurrecting a terminal state
		{Failed, Running},
	} {
		if CanTransition(tc.from, tc.to) {
			t.Errorf("%s → %s should be illegal", tc.from, tc.to)
		}
	}
	if _, err := r.Transition(ctx, "b", Creating, Stopped, ""); err == nil {
		t.Error("registry accepted creating → stopped")
	}
}

func TestStaleStateIsAConflict(t *testing.T) {
	r, _ := open(t)
	_, _ = r.Create(ctx, Sandbox{ID: "c", Backend: "gvisor"})
	_, _ = r.Transition(ctx, "c", Creating, Running, "")
	// A caller who still believes it's creating must be refused.
	if _, err := r.Transition(ctx, "c", Creating, Failed, "late"); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if _, err := r.Transition(ctx, "nope", Creating, Running, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestOnlyOneConcurrentTransitionWins: twenty destroy requests race for the
// same sandbox. The compare-and-set lets exactly one through; the rest get
// ErrConflict, and the history records the move once.
func TestOnlyOneConcurrentTransitionWins(t *testing.T) {
	r, _ := open(t)
	_, _ = r.Create(ctx, Sandbox{ID: "d", Backend: "gvisor"})
	_, _ = r.Transition(ctx, "d", Creating, Running, "")

	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Transition(ctx, "d", Running, Stopping, "destroy")
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrConflict):
				conflicts.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || conflicts.Load() != 19 {
		t.Fatalf("wins=%d conflicts=%d, want 1 and 19", wins.Load(), conflicts.Load())
	}
	evs, _ := r.Events(ctx, "d")
	if len(evs) != 3 {
		t.Fatalf("history has %d events, want 3 (created, running, stopping once)", len(evs))
	}
}

func TestDuplicateIDAndPersistence(t *testing.T) {
	r, path := open(t)
	if _, err := r.Create(ctx, Sandbox{ID: "e", Backend: "gvisor"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(ctx, Sandbox{ID: "e", Backend: "gvisor"}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate id: want ErrExists, got %v", err)
	}
	_, _ = r.Transition(ctx, "e", Creating, Failed, "boom")
	r.Close()

	// Reopen: everything must still be there. That's the point of a registry.
	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	s, err := r2.Get(ctx, "e")
	if err != nil || s.State != Failed || s.Error != "boom" {
		t.Fatalf("after reopen: %+v %v", s, err)
	}
	all, _ := r2.List(ctx, false)
	live, _ := r2.List(ctx, true)
	if len(all) != 1 || len(live) != 0 {
		t.Fatalf("list all=%d live=%d", len(all), len(live))
	}
}

// A database exactly as Day 5's sbxd left it: the old schema, no recorded
// version, and a sandbox in it. Opening it with today's code must add the
// new column and keep the row: this is what happens to the registry on
// your machine the first time Day 8's sbxd starts.
func TestMigratesADay5Database(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(schemaV1); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO sandboxes (id, backend, state, rootfs, vcpus, mem_mib, created_at, updated_at)
		VALUES ('veteran', 'gvisor', 'stopped', '/r', 1, 256, '2026-10-15T00:00:00Z', '2026-10-15T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	old.Close()

	r, err := Open(path)
	if err != nil {
		t.Fatalf("open an old database: %v", err)
	}
	defer r.Close()
	if v, _ := r.SchemaVersion(); v != len(migrations) {
		t.Fatalf("schema version %d, want %d", v, len(migrations))
	}
	got, err := r.Get(ctx, "veteran")
	if err != nil || got.MemMiB != 256 || got.PidsMax != 0 || got.State != Stopped {
		t.Fatalf("the old row after migration: %+v %v", got, err)
	}
	fresh, err := r.Create(ctx, Sandbox{ID: "rookie", Backend: "gvisor", VCPUs: 2, MemMiB: 512, PidsMax: 128})
	if err != nil || fresh.PidsMax != 128 {
		t.Fatalf("new row: %+v %v", fresh, err)
	}
}

func TestMigrationsRunOnceAndRefuseTheFuture(t *testing.T) {
	r, path := open(t)
	if v, _ := r.SchemaVersion(); v != len(migrations) {
		t.Fatalf("fresh database at version %d", v)
	}
	r.Close()
	// Reopening must not run anything again (ALTER TABLE ADD COLUMN would
	// fail if it did: the column exists).
	r2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := r2.db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	r2.Close()
	// A database from a newer sbxd: refuse, rather than misread it.
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "newer sbxd") {
		t.Fatalf("want a refusal for a newer schema, got %v", err)
	}
}

func TestCheckpointStatesAndRecords(t *testing.T) {
	r, _ := open(t)
	_, _ = r.Create(ctx, Sandbox{ID: "ck", Backend: "gvisor"})
	_, _ = r.Transition(ctx, "ck", Creating, Running, "")
	// running → checkpointing → paused; paused → running is Day 11's restore.
	for _, step := range [][2]State{{Running, Checkpointing}, {Checkpointing, Paused}, {Paused, Restoring}, {Restoring, Running},
		{Running, Checkpointing}, {Checkpointing, Running}, {Running, Checkpointing}, {Checkpointing, Paused}, {Paused, Restoring}, {Restoring, Paused}} {
		if _, err := r.Transition(ctx, "ck", step[0], step[1], ""); err != nil {
			t.Fatalf("%s → %s: %v", step[0], step[1], err)
		}
	}
	if CanTransition(Creating, Checkpointing) || CanTransition(Checkpointing, Stopping) || CanTransition(Paused, Running) || CanTransition(Restoring, Stopping) {
		t.Fatal("only a running sandbox can be checkpointed, and a checkpoint must finish before a destroy")
	}
	now := time.Now()
	for i, id := range []string{"ck-1", "ck-2"} {
		if err := r.AddCheckpoint(ctx, Checkpoint{ID: id, SandboxID: "ck", CreatedAt: now.Add(time.Duration(i) * time.Second),
			Path: "/x/" + id, ImageBytes: int64(1000 * (i + 1)), DurationMs: 50, LeftRunning: i == 0}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := r.Checkpoints(ctx, "ck")
	if err != nil || len(list) != 2 || list[0].ID != "ck-2" || !list[1].LeftRunning || list[0].ImageBytes != 2000 {
		t.Fatalf("checkpoints (newest first): %+v %v", list, err)
	}
	if _, err := r.Checkpoints(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown sandbox: %v", err)
	}
	_ = r.DeleteCheckpoints(ctx, "ck")
	if list, _ := r.Checkpoints(ctx, "ck"); len(list) != 0 {
		t.Fatalf("after delete: %+v", list)
	}
}

func TestResumeOnStartFlag(t *testing.T) {
	r, _ := open(t)
	_, _ = r.Create(ctx, Sandbox{ID: "flag", Backend: "gvisor"})
	if s, _ := r.Get(ctx, "flag"); s.ResumeOnStart {
		t.Fatal("a new sandbox isn't marked")
	}
	if err := r.SetResumeOnStart(ctx, "flag", true); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.Get(ctx, "flag"); !s.ResumeOnStart {
		t.Fatal("not marked")
	}
	_ = r.SetResumeOnStart(ctx, "flag", false)
	if s, _ := r.Get(ctx, "flag"); s.ResumeOnStart {
		t.Fatal("still marked")
	}
	if err := r.SetResumeOnStart(ctx, "nope", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown sandbox: %v", err)
	}
}

func TestIdleActionAndWakeFlag(t *testing.T) {
	r, _ := open(t)
	_, _ = r.Create(ctx, Sandbox{ID: "napper", Backend: "gvisor", IdleTimeoutS: 60, IdleAction: "pause"})
	s, _ := r.Get(ctx, "napper")
	if s.IdleAction != "pause" || s.WakeOnUse {
		t.Fatalf("created: %+v", s)
	}
	_ = r.SetWakeOnUse(ctx, "napper", true)
	if s, _ := r.Get(ctx, "napper"); !s.WakeOnUse || s.ResumeOnStart {
		t.Fatalf("the two flags are independent: %+v", s)
	}
	if err := r.SetWakeOnUse(ctx, "nope", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown sandbox: %v", err)
	}
}

// Network slots: the lowest free one, gaps reused, held while paused,
// released when stopped or failed; zero (the default) means none.
func TestNetworkSlots(t *testing.T) {
	r, _ := open(t)
	mk := func(id string, slot int) Sandbox {
		t.Helper()
		s, err := r.Create(ctx, Sandbox{ID: id, Backend: "gvisor", NetSlot: slot})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if s := mk("plain", 0); s.NetSlot != 0 {
		t.Fatalf("no network asked for, yet slot %d", s.NetSlot)
	}
	a, b, c := mk("a", AllocateSlot), mk("b", AllocateSlot), mk("c", AllocateSlot)
	if a.NetSlot != 1 || b.NetSlot != 2 || c.NetSlot != 3 {
		t.Fatalf("slots %d %d %d, want 1 2 3", a.NetSlot, b.NetSlot, c.NetSlot)
	}
	_, _ = r.Transition(ctx, "b", Creating, Failed, "")
	if d := mk("d", AllocateSlot); d.NetSlot != 2 {
		t.Fatalf("a failed sandbox's slot should be reused: got %d", d.NetSlot)
	}
	_, _ = r.Transition(ctx, "a", Creating, Running, "")
	_, _ = r.Transition(ctx, "a", Running, Checkpointing, "")
	_, _ = r.Transition(ctx, "a", Checkpointing, Paused, "")
	if e := mk("e", AllocateSlot); e.NetSlot != 4 {
		t.Fatalf("a paused sandbox keeps its slot; want 4, got %d", e.NetSlot)
	}
	if got, _ := r.Get(ctx, "a"); got.NetSlot != 1 {
		t.Fatalf("stored slot %d", got.NetSlot)
	}
	if got, err := r.BySlot(ctx, 1); err != nil || got.ID != "a" {
		t.Fatalf("slot 1 belongs to the paused a: %+v %v", got, err)
	}
	if _, err := r.BySlot(ctx, 9); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an empty slot: %v", err)
	}
	if got, err := r.BySlot(ctx, 2); err != nil || got.ID != "d" {
		t.Fatalf("slot 2 went from the failed b to d: %+v %v", got, err)
	}
}

// Where a checkpoint is: local on creation; both flags set together; and
// the lookups the sweep needs.
func TestCheckpointWhere(t *testing.T) {
	r, _ := open(t)
	if _, err := r.Create(ctx, Sandbox{ID: "s", Backend: "gvisor"}); err != nil {
		t.Fatal(err)
	}
	_ = r.AddCheckpoint(ctx, Checkpoint{ID: "ck-a", SandboxID: "s", Path: "/x/ck-a"})
	_ = r.AddCheckpoint(ctx, Checkpoint{ID: "ck-b", SandboxID: "s", Path: "/x/ck-b"})
	cks, _ := r.Checkpoints(ctx, "s")
	if len(cks) != 2 || !cks[0].Local || cks[0].Remote {
		t.Fatalf("new checkpoints are local only: %+v", cks)
	}
	if err := r.SetWhere(ctx, "ck-a", false, true); err != nil {
		t.Fatal(err)
	}
	if err := r.SetWhere(ctx, "ck-nope", true, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown checkpoint: %v", err)
	}
	all, _ := r.AllCheckpoints(ctx)
	where := map[string]string{}
	for _, c := range all {
		where[c.ID] = fmt.Sprintf("local=%v remote=%v", c.Local, c.Remote)
	}
	if where["ck-a"] != "local=false remote=true" || where["ck-b"] != "local=true remote=false" {
		t.Fatalf("where: %v", where)
	}
	_ = r.DeleteCheckpoint(ctx, "ck-a")
	if all, _ := r.AllCheckpoints(ctx); len(all) != 1 || all[0].ID != "ck-b" {
		t.Fatalf("after deleting one: %+v", all)
	}
}

// The registry runs with synchronous=NORMAL (see Open): checked, since a
// misspelled DSN parameter is silently ignored.
func TestRegistryDurabilitySetting(t *testing.T) {
	r, _ := open(t)
	var got int
	if err := r.db.QueryRow("PRAGMA synchronous").Scan(&got); err != nil || got != 1 {
		t.Fatalf("PRAGMA synchronous = %d (%v), want 1 (NORMAL)", got, err)
	}
	var mode string
	if err := r.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode %q (%v), want wal", mode, err)
	}
}
