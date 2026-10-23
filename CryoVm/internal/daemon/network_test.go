package daemon

import (
	"context"
	"errors"
	"fmt"
	"github.com/Crpedeim/sbx/internal/registry"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
)

func withNet(n *fakeNet) func(*Config) { return func(c *Config) { c.Net = n } }

func TestNetworkedSandboxGetsItsOwnNetwork(t *testing.T) {
	n := newFakeNet()
	e := start(t, withNet(n))
	ctx := tctx(t)
	a, err := e.c.Create(ctx, api.CreateRequest{ID: "neta", Network: true})
	if err != nil || a.NetSlot != 1 || a.NetAddr != "10.200.0.6" {
		t.Fatalf("first networked sandbox: %+v %v", a, err)
	}
	b, _ := e.c.Create(ctx, api.CreateRequest{ID: "netb", Network: true})
	plain, _ := e.c.Create(ctx, api.CreateRequest{ID: "plain"})
	if b.NetSlot != 2 || plain.NetSlot != 0 || plain.NetAddr != "" {
		t.Fatalf("second: %+v; plain: %+v", b, plain)
	}
	e.b.mu.Lock()
	specA, specPlain := e.b.specs["neta"], e.b.specs["plain"]
	e.b.mu.Unlock()
	if specA.NetNS != "/fake/netns/sbx-neta" || specPlain.NetNS != "" {
		t.Fatalf("the specs: %q / %q", specA.NetNS, specPlain.NetNS)
	}
	if n.prepared != 1 {
		t.Fatalf("the host should be prepared once, not %d times", n.prepared)
	}
}

// Destroy tears down while the sandbox is still "stopping": the state change
// to "stopped" frees the slot, and must come after the network is gone.
func TestDestroyTearsDownBeforeFreeingTheSlot(t *testing.T) {
	n := newFakeNet()
	e := start(t, withNet(n))
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "goner", Network: true})
	var seen api.State
	n.onTeardown = func(id string) {
		rec, _ := e.reg.Get(context.Background(), id)
		seen = rec.State
	}
	if _, err := e.c.Destroy(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if !n.tornDown(sb.ID) || seen != api.Stopping {
		t.Fatalf("torn down %v, in state %q (want still stopping)", n.tornDown(sb.ID), seen)
	}
	if next, _ := e.c.Create(ctx, api.CreateRequest{ID: "heir", Network: true}); next.NetSlot != 1 {
		t.Fatalf("the slot should be free again: %+v", next)
	}
}

func TestFailedNetworkSetupFailsTheCreate(t *testing.T) {
	n := newFakeNet()
	n.failSetup = errors.New("ip link add: RTNETLINK answers: File exists")
	e := start(t, withNet(n))
	ctx := tctx(t)
	if _, err := e.c.Create(ctx, api.CreateRequest{ID: "unlucky", Network: true}); err == nil {
		t.Fatal("the create should fail")
	}
	if rec, _ := e.c.Get(ctx, "unlucky"); rec.State != api.Failed || !strings.HasPrefix(rec.Error, "network:") {
		t.Fatalf("record: %+v", rec)
	}
	if !n.tornDown("unlucky") {
		t.Fatal("a half-made network must be cleaned up")
	}
	n.mu.Lock()
	n.failSetup = nil
	n.mu.Unlock()
	if next, _ := e.c.Create(ctx, api.CreateRequest{ID: "lucky", Network: true}); next.NetSlot != 1 {
		t.Fatalf("the failed sandbox's slot should be free: %+v", next)
	}
}

// A pause keeps the network (and the slot: same address after). A reboot
// wipes /run/netns, so a resume rebuilds it, in the same slot.
func TestPausedKeepsItsNetworkAndResumeRebuildsIt(t *testing.T) {
	n := newFakeNet()
	e := start(t, withNet(n))
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "sleeper", Network: true})
	if _, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{}); err != nil {
		t.Fatal(err)
	}
	if n.tornDown(sb.ID) || !n.Exists(sb.ID) {
		t.Fatal("a pause should keep the network")
	}
	// A resume with the namespaces still there refreshes eth0 (runsc
	// took its address into gVisor at boot, Day 16 v2).
	if _, err := e.c.Resume(ctx, sb.ID, ""); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	refreshed := strings.Join(n.refreshes, " ")
	n.mu.Unlock()
	if refreshed != "sleeper" {
		t.Fatalf("a resume should refresh the network: %q", refreshed)
	}
	if _, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{}); err != nil {
		t.Fatal(err)
	}
	_ = n.Teardown(ctx, sb.ID, sb.NetSlot) // the reboot
	if _, err := e.c.Resume(ctx, sb.ID, ""); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	setups := strings.Join(n.setups, " ")
	n.mu.Unlock()
	if setups != "sleeper@1 sleeper@1" {
		t.Fatalf("setups: %q (want the same slot rebuilt)", setups)
	}
}

// Day 19: a networked source's clones each get their own slot and network,
// built before the restore, under their own IDs.
func TestNetworkedClonesGetTheirOwnNetworks(t *testing.T) {
	n := newFakeNet()
	e := start(t, withNet(n))
	ctx := tctx(t)
	src, _ := e.c.Create(ctx, api.CreateRequest{ID: "src", Network: true})
	forks, err := e.c.Fork(ctx, src.ID, api.ForkRequest{Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{src.NetAddr: true}
	for _, f := range forks {
		if f.NetSlot <= 0 || seen[f.NetAddr] {
			t.Fatalf("fork %s: slot %d, address %q (must be its own)", f.ID, f.NetSlot, f.NetAddr)
		}
		seen[f.NetAddr] = true
		if !n.Exists(f.ID) {
			t.Fatalf("fork %s has no network built", f.ID)
		}
	}
	// Clones are made in parallel (Day 23), so which one reaches the
	// registry first, and gets the lower slot, is up to the scheduler. What
	// matters: each clone's network was built once, on exactly the slot its
	// row records, and no slot is shared.
	n.mu.Lock()
	setups := append([]string(nil), n.setups...)
	n.mu.Unlock()
	want := []string{"src@1"}
	for _, f := range forks {
		want = append(want, fmt.Sprintf("%s@%d", f.ID, f.NetSlot))
	}
	sort.Strings(setups)
	sort.Strings(want)
	if strings.Join(setups, " ") != strings.Join(want, " ") {
		t.Fatalf("setups %v, want %v (each clone once, on its own recorded slot)", setups, want)
	}
	if forks[0].NetSlot == forks[1].NetSlot || forks[0].NetSlot == 1 || forks[1].NetSlot == 1 {
		t.Fatalf("slots %d and %d: each clone needs its own, not the source's", forks[0].NetSlot, forks[1].NetSlot)
	}

	plain, _ := e.c.Create(ctx, api.CreateRequest{ID: "plain"})
	pf, err := e.c.Fork(ctx, plain.ID, api.ForkRequest{})
	if err != nil || pf[0].NetSlot != 0 || n.Exists(pf[0].ID) {
		t.Fatalf("a plain source's fork should have no network: %+v %v", pf, err)
	}
}

// A clone whose network can't be built fails cleanly; its source runs on,
// network intact.
func TestCloneWithoutANetworkFailsAlone(t *testing.T) {
	n := newFakeNet()
	e := start(t, withNet(n))
	ctx := tctx(t)
	src, _ := e.c.Create(ctx, api.CreateRequest{ID: "src", Network: true})
	n.mu.Lock()
	n.failSetup = errors.New("RTNETLINK answers: File exists")
	n.mu.Unlock()
	if _, err := e.c.Fork(ctx, src.ID, api.ForkRequest{ID: "doomed"}); err == nil {
		t.Fatal("the fork should fail")
	}
	if rec, _ := e.c.Get(ctx, "doomed"); rec.State != api.Failed || !strings.Contains(rec.Error, "network") {
		t.Fatalf("the fork: %+v", rec)
	}
	if !n.tornDown("doomed") {
		t.Fatal("the failed fork's half-built network must be cleaned up")
	}
	if rec, _ := e.c.Get(ctx, src.ID); rec.State != api.Running || !n.Exists(src.ID) || n.tornDown(src.ID) {
		t.Fatalf("the source should run on with its network: %+v", rec)
	}
}

// At startup: networks no live sandbox claims are swept; a sandbox adopted
// after a crash keeps its network.
func TestStartupSweepsUnclaimedNetworks(t *testing.T) {
	db, dir := twoDaemons(t)
	n := newFakeNet()
	b := newFakeBackend()
	e1 := startWith(t, b, db, filepath.Join(dir, "a.sock"), withNet(n))
	sb, _ := e1.c.Create(tctx(t), api.CreateRequest{ID: "survivor", Network: true})
	_ = n.Setup(context.Background(), "ghost", 77) // left by something long gone
	e1.reg.Close()                                 // the daemon crashes

	e2 := startWith(t, b, db, filepath.Join(dir, "b.sock"), withNet(n))
	if !n.tornDown("ghost") {
		t.Fatal("an unclaimed network should be swept")
	}
	if n.tornDown(sb.ID) || !n.Exists(sb.ID) {
		t.Fatal("the adopted sandbox's network must survive the sweep")
	}
	if rec, _ := e2.c.Get(tctx(t), sb.ID); rec.State != api.Running || rec.NetAddr != "10.200.0.6" {
		t.Fatalf("adopted: %+v", rec)
	}
}

func TestCrashedSandboxReleasesItsNetwork(t *testing.T) {
	n := newFakeNet()
	e := start(t, withNet(n))
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "fragile", Network: true})
	e.b.get(sb.ID).end()
	rec := waitState(t, e, sb.ID, api.Failed, 3*time.Second)
	if !n.tornDown(sb.ID) {
		t.Fatalf("a crashed sandbox's network should go: %+v", rec)
	}
}

func TestUnknownEgressModeIsRefused(t *testing.T) {
	db, _ := twoDaemons(t)
	reg, err := registry.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	if _, err := New(context.Background(), Config{Backend: newFakeBackend(), Registry: reg, Egress: "wide-open", Logf: t.Logf}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}
