package registry

import (
	"strings"
	"testing"
)

func fillAudit(t *testing.T, r *Registry, n int) []AuditEntry {
	t.Helper()
	var out []AuditEntry
	for i := 0; i < n; i++ {
		e, err := r.Audit(ctx, AuditEntry{SandboxID: "s1", Actor: "root (uid 0)", Action: "exec", Detail: "echo " + strings.Repeat("x", i), Outcome: "ok"})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestAuditChainLinksAndVerifies(t *testing.T) {
	r, _ := open(t)
	es := fillAudit(t, r, 4)
	if es[0].PrevHash != genesis || es[1].PrevHash != es[0].Hash || es[3].Seq != 4 {
		t.Fatalf("chain not linked: %+v", es)
	}
	log, err := r.AuditLog(ctx, "s1", 10)
	if err != nil || len(log) != 4 || log[0].Seq != 4 {
		t.Fatalf("log (newest first): %+v %v", log, err)
	}
	v, err := r.VerifyAudit(ctx)
	if err != nil || !v.OK || v.Entries != 4 || v.Head != es[3].Hash {
		t.Fatalf("verify: %+v %v", v, err)
	}
}

func TestAuditDetectsAnEditedEntry(t *testing.T) {
	r, _ := open(t)
	fillAudit(t, r, 5)
	// Someone with database access rewrites what happened.
	if _, err := r.db.Exec(`UPDATE audit SET detail = 'echo nothing to see here' WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	v, _ := r.VerifyAudit(ctx)
	if v.OK || v.BrokenAt != 3 || !strings.Contains(v.Problem, "edited") {
		t.Fatalf("an edit should be caught at 3: %+v", v)
	}
}

func TestAuditDetectsADeletedEntry(t *testing.T) {
	r, _ := open(t)
	fillAudit(t, r, 5)
	if _, err := r.db.Exec(`DELETE FROM audit WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	v, _ := r.VerifyAudit(ctx)
	if v.OK || v.BrokenAt != 3 || !strings.Contains(v.Problem, "missing") {
		t.Fatalf("a deletion should be caught: %+v", v)
	}
}

// The chain's honest limit: cutting entries off the *end* leaves a shorter
// chain that is still internally valid. Only a head recorded elsewhere
// reveals it, which is why verify reports the head.
func TestAuditTruncationNeedsAnOutsideHead(t *testing.T) {
	r, _ := open(t)
	fillAudit(t, r, 5)
	before, _ := r.VerifyAudit(ctx)
	if _, err := r.db.Exec(`DELETE FROM audit WHERE seq >= 4`); err != nil {
		t.Fatal(err)
	}
	after, _ := r.VerifyAudit(ctx)
	if !after.OK {
		t.Fatalf("a truncated chain is still internally consistent: %+v", after)
	}
	if after.Head == before.Head || after.Entries != 3 {
		t.Fatalf("the head must change, which is how an outside copy catches it: %+v vs %+v", after, before)
	}
}

func TestMigratesADay8Database(t *testing.T) {
	r, path := open(t)
	if _, err := r.db.Exec(`PRAGMA user_version = 2`); err != nil {
		t.Fatal(err)
	}
	// Undo migrations 3 and up by hand, as if this database came from Day 8.
	for _, q := range []string{`ALTER TABLE checkpoints DROP COLUMN remote`, `ALTER TABLE checkpoints DROP COLUMN local`, `ALTER TABLE sandboxes DROP COLUMN egress_policy`, `ALTER TABLE sandboxes DROP COLUMN net_slot`, `ALTER TABLE sandboxes DROP COLUMN forked_from`, `ALTER TABLE sandboxes DROP COLUMN idle_action`, `ALTER TABLE sandboxes DROP COLUMN wake_on_use`, `ALTER TABLE sandboxes DROP COLUMN resume_on_start`, `DROP TABLE checkpoints`, `DROP TABLE audit`, `ALTER TABLE sandboxes DROP COLUMN expires_at`, `ALTER TABLE sandboxes DROP COLUMN idle_timeout_s`} {
		if _, err := r.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := r.db.Exec(`INSERT INTO sandboxes (id, backend, state, rootfs, vcpus, mem_mib, pids_max, created_at, updated_at)
		VALUES ('day8', 'gvisor', 'stopped', '/r', 1, 256, 1024, '2026-10-16T00:00:00Z', '2026-10-16T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	r.Close()
	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	got, err := r2.Get(ctx, "day8")
	if err != nil || got.PidsMax != 1024 || got.ExpiresAt != nil || got.IdleTimeoutS != 0 {
		t.Fatalf("the Day 8 row after migration: %+v %v", got, err)
	}
	if _, err := r2.Audit(ctx, AuditEntry{Actor: "sbxd", Action: "test", Outcome: "ok"}); err != nil {
		t.Fatalf("the audit table should exist now: %v", err)
	}
}
