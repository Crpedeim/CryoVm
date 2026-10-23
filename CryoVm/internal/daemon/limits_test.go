package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

func TestLimitsAreRecordedAndDefaulted(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	def, err := e.c.Create(ctx, api.CreateRequest{ID: "defaults"})
	if err != nil || def.VCPUs != 1 || def.MemMiB != 256 || def.PidsMax != 512 {
		t.Fatalf("defaults: %+v %v", def, err)
	}
	custom, err := e.c.Create(ctx, api.CreateRequest{ID: "custom", VCPUs: 2, MemMiB: 1024, PidsMax: 64})
	if err != nil || custom.VCPUs != 2 || custom.MemMiB != 1024 || custom.PidsMax != 64 {
		t.Fatalf("custom: %+v %v", custom, err)
	}
	if _, err := e.c.Create(ctx, api.CreateRequest{ID: "negative", MemMiB: -1}); !errors.Is(err, client.ErrInvalid) {
		t.Fatalf("negative limit: want ErrInvalid, got %v", err)
	}
}

func TestStatsOverHTTP(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "st"})
	st, err := e.c.Stats(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Cgroup != "/sbx/st" || st.MemoryBytes != 64<<20 || st.MemoryLimit != 256<<20 ||
		st.CPUUsageMicros != 1_500_000 || st.CPUQuota != 1 || st.Pids != 7 || st.PidsLimit != 512 {
		t.Fatalf("stats: %+v", st)
	}
	_, _ = e.c.Destroy(ctx, sb.ID)
	if _, err := e.c.Stats(ctx, sb.ID); !errors.Is(err, client.ErrConflict) {
		t.Fatalf("stats of a stopped sandbox: want ErrConflict, got %v", err)
	}
}

// When the backend knows why a sandbox died, the registry records it, so
// `sbx ls -a` and `sbx info` explain the failure instead of shrugging.
func TestOOMDeathIsExplained(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "hog"})
	e.b.get(sb.ID).crashWith("killed by the kernel's out-of-memory killer (memory limit 256 MiB reached)")

	deadline := time.Now().Add(3 * time.Second)
	var rec api.Sandbox
	for time.Now().Before(deadline) {
		if rec, _ = e.c.Get(ctx, sb.ID); rec.State == api.Failed {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rec.State != api.Failed || !strings.Contains(rec.Error, "out-of-memory") || !strings.Contains(rec.Error, "256 MiB") {
		t.Fatalf("record: %+v", rec)
	}
	// And any later use of it says so too (Day 6's clearer message).
	_, err := e.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "out-of-memory") {
		t.Fatalf("exec on the dead sandbox: %v", err)
	}
}

// The memory guard: near the limit, the daemon has the agent kill the
// biggest process, records it in the history, and the sandbox lives on.
// Below the threshold, it does nothing.
func TestMemoryGuardActsBeforeTheKernelDoes(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "guarded"})
	fake := e.b.get(sb.ID)

	fake.setMemory(200 << 20) // 78% of 256 MiB: below the 85% threshold
	time.Sleep(200 * time.Millisecond)
	if n := fake.reclaimCount(); n != 0 {
		t.Fatalf("the guard acted at 78%%: %d reclaims", n)
	}

	fake.setMemory(240 << 20) // 94%: the guard must act
	deadline := time.Now().Add(3 * time.Second)
	for fake.reclaimCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fake.reclaimCount() == 0 {
		t.Fatal("the guard never acted at 94% of the limit")
	}
	var note string
	for time.Now().Before(deadline) && note == "" {
		evs, _ := e.c.Events(ctx, sb.ID)
		for _, ev := range evs {
			if strings.HasPrefix(ev.Detail, "memory guard:") {
				note = ev.Detail
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(note, "killed tail (pid 42, 200 MiB) at 240 of 256 MiB") {
		t.Fatalf("history note: %q", note)
	}
	if rec, _ := e.c.Get(ctx, sb.ID); rec.State != api.Running {
		t.Fatalf("the sandbox should still be running: %+v", rec)
	}
	// Reclaiming brought memory back down: no further kills.
	n := fake.reclaimCount()
	time.Sleep(200 * time.Millisecond)
	if fake.reclaimCount() != n {
		t.Fatal("the guard kept killing after memory recovered")
	}
}
