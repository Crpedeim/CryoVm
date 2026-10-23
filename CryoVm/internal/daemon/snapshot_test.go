package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
	"github.com/Crpedeim/sbx/internal/s3"
	"github.com/Crpedeim/sbx/internal/s3/s3test"
	"github.com/Crpedeim/sbx/internal/store"
)

func withStore(srv *s3test.Server, evict bool) func(*Config) {
	return func(c *Config) {
		c.Store = &store.S3{Client: &s3.Client{Endpoint: srv.URL}, Bucket: "b"}
		c.StoreEvict = evict
	}
}

func ckOf(t *testing.T, e *env, id string) api.Checkpoint {
	t.Helper()
	cks, err := e.c.Checkpoints(tctx(t), id)
	if err != nil || len(cks) == 0 {
		t.Fatalf("checkpoints of %s: %v %v", id, cks, err)
	}
	return cks[0]
}

func echoOK(t *testing.T, e *env, id string) {
	t.Helper()
	var out strings.Builder
	if _, err := e.c.Exec(tctx(t), id, client.ExecRequest{Args: []string{"echo", "ok"}, Stdout: &out}); err != nil || out.String() != "ok\n" {
		t.Fatalf("exec in %s: %q %v", id, out.String(), err)
	}
}

// The plan's done-when: checkpoint → upload → delete local files →
// download → restore → exec.
func TestStoreRoundTrip(t *testing.T) {
	srv := s3test.New()
	defer srv.Close()
	e := start(t, withStore(srv, true))
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "away"})
	if _, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{}); err != nil {
		t.Fatal(err)
	}
	ck := ckOf(t, e, sb.ID)
	if ck.Local || !ck.Remote {
		t.Fatalf("after the pause: %+v (want in the store only)", ck)
	}
	if _, err := os.Stat(ck.Path); !os.IsNotExist(err) {
		t.Fatalf("the local copy should be gone: %v", err)
	}
	if _, ok := srv.Objects()["b/checkpoints/"+ck.ID+"/manifest.json"]; !ok {
		t.Fatal("the store should have the manifest")
	}
	if _, err := e.c.Resume(ctx, sb.ID, ""); err != nil {
		t.Fatalf("resume from the store: %v", err)
	}
	echoOK(t, e, sb.ID)
	if ck := ckOf(t, e, sb.ID); !ck.Local || !ck.Remote {
		t.Fatalf("after the fetch: %+v (want both)", ck)
	}
	evs, _ := e.c.Events(ctx, sb.ID)
	var notes []string
	for _, ev := range evs {
		if strings.HasPrefix(ev.Detail, "uploaded ") || strings.HasPrefix(ev.Detail, "fetched ") {
			notes = append(notes, strings.Fields(ev.Detail)[0])
		}
	}
	if strings.Join(notes, " ") != "uploaded fetched" {
		t.Fatalf("the history should show the upload and the fetch: %v", notes)
	}
}

// A store that's down costs the upload, nothing else: the checkpoint stays
// local, and the history says so.
func TestStoreDownKeepsTheCheckpointLocal(t *testing.T) {
	srv := s3test.New()
	defer srv.Close()
	srv.Fail(true)
	e := start(t, withStore(srv, true))
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "local"})
	if _, err := e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{}); err != nil {
		t.Fatal(err)
	}
	if ck := ckOf(t, e, sb.ID); !ck.Local || ck.Remote {
		t.Fatalf("with the store down: %+v (want local only)", ck)
	}
	if _, err := e.c.Resume(ctx, sb.ID, ""); err != nil {
		t.Fatal(err)
	}
	echoOK(t, e, sb.ID)
}

// A corrupted object is caught by the manifest's SHA-256: the restore is
// refused, and the sandbox stays paused for another try.
func TestCorruptStoreIsRefused(t *testing.T) {
	srv := s3test.New()
	defer srv.Close()
	e := start(t, withStore(srv, true))
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "rot"})
	_, _ = e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{})
	ck := ckOf(t, e, sb.ID)
	srv.Set("b/checkpoints/"+ck.ID+"/files/checkpoint.img", []byte("not what was uploaded, same length?"))
	_, err := e.c.Resume(ctx, sb.ID, "")
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("resume from a corrupt store: %v", err)
	}
	if rec, _ := e.c.Get(ctx, sb.ID); rec.State != api.Paused {
		t.Fatalf("it should stay paused: %s", rec.State)
	}
	if _, err := os.Stat(ck.Path); !os.IsNotExist(err) {
		t.Fatal("a corrupt image must not appear on disk")
	}
}

// Destroying a sandbox removes its checkpoints everywhere.
func TestDestroyRemovesFromTheStore(t *testing.T) {
	srv := s3test.New()
	defer srv.Close()
	e := start(t, withStore(srv, false))
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "gone"})
	_, _ = e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{LeaveRunning: true})
	_, _ = e.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{})
	if n := len(srv.Objects()); n != 4 {
		t.Fatalf("two checkpoints in the store: %d objects", n)
	}
	if _, err := e.c.Destroy(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if n := len(srv.Objects()); n != 0 {
		t.Fatalf("after destroy, the store holds %d objects", n)
	}
}

type crashed struct{ point string }

// claimsTrue: every claim in the registry is true right now. It must hold
// at every moment, crash or not, with no sweep's help: that's what writing
// data before claims (and removing claims before data) buys.
func claimsTrue(t *testing.T, reg interface {
	AllCheckpoints(context.Context) ([]api.Checkpoint, error)
}, srv *s3test.Server, when string) {
	t.Helper()
	all, err := reg.AllCheckpoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	objects := srv.Objects()
	for _, c := range all {
		if _, err := os.Stat(filepath.Join(c.Path, "checkpoint.img")); c.Local && err != nil {
			t.Errorf("%s: %s is claimed local, but its image isn't on disk", when, c.ID)
		}
		if _, ok := objects["b/checkpoints/"+c.ID+"/manifest.json"]; c.Remote && !ok {
			t.Errorf("%s: %s is claimed in the store, but its manifest isn't there", when, c.ID)
		}
	}
}

// invariants: every claim is true, and nothing is unclaimed.
func invariants(t *testing.T, e *env, srv *s3test.Server, ckDir string) {
	t.Helper()
	all, err := e.reg.AllCheckpoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claimed := map[string]bool{}
	objects := srv.Objects()
	for _, c := range all {
		if c.Local {
			if _, err := os.Stat(filepath.Join(c.Path, "checkpoint.img")); err != nil {
				t.Errorf("%s is claimed local, but its image isn't on disk", c.ID)
			}
			claimed[c.Path] = true
		}
		if c.Remote {
			if _, ok := objects["b/checkpoints/"+c.ID+"/manifest.json"]; !ok {
				t.Errorf("%s is claimed in the store, but its manifest isn't there", c.ID)
			}
		}
		if !c.Local && !c.Remote {
			t.Errorf("%s is claimed nowhere, yet kept", c.ID)
		}
	}
	_ = filepath.Walk(ckDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || !fi.IsDir() || p == ckDir || filepath.Dir(p) == ckDir {
			return nil
		}
		if filepath.Dir(filepath.Dir(p)) == ckDir && !claimed[p] {
			t.Errorf("an unclaimed image directory was left: %s", p)
		}
		return nil
	})
	byID := map[string]bool{}
	for _, c := range all {
		if c.Remote {
			byID[c.ID] = true
		}
	}
	for key := range objects {
		id := strings.SplitN(strings.TrimPrefix(key, "b/checkpoints/"), "/", 2)[0]
		if !byID[id] {
			t.Errorf("an unclaimed object was left in the store: %s", key)
		}
	}
}

// The done-when's second half: a kill -9 at any point leaves nothing marked
// valid and nothing leaked. Each case runs a daemon to a point, stops it
// there (its registry closed, as if the process died), starts a fresh one
// on the same registry, disk and store, and checks the invariants, and
// that the sandbox can still be used.
func TestCrashAtEveryPoint(t *testing.T) {
	type step func(e *env, id string) error
	pause := func(e *env, id string) error {
		_, err := e.m.Checkpoint(context.Background(), id, api.CheckpointRequest{})
		return err
	}
	cases := []struct {
		point   string
		setup   step // before the crash point is armed
		do      step // runs into the crash
		midPuts int  // > 0: instead of a crash point, the store drops after this many uploads
		want    api.State
	}{
		// Before the image is claimed, the pause didn't happen: the sandbox
		// is lost (it was stopped by the checkpoint), its image swept.
		{point: "checkpoint:after-image", do: pause, want: api.Failed},
		// After the claim, the pause completed in all but its state change.
		{point: "offload:after-upload", do: pause, want: api.Paused},
		{point: "offload:after-claim", do: pause, want: api.Paused},
		{point: "offload:after-unclaim-local", do: pause, want: api.Paused},
		{point: "mid-upload", do: pause, midPuts: 1, want: api.Paused},
		{point: "fetch:after-download", setup: pause, want: api.Paused, do: func(e *env, id string) error {
			_, err := e.m.Resume(context.Background(), id, "")
			return err
		}},
		{point: "drop:after-unclaim", setup: pause, want: api.Stopped, do: func(e *env, id string) error {
			_, err := e.m.Destroy(context.Background(), id)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.point, func(t *testing.T) {
			db, dir := twoDaemons(t)
			srv := s3test.New()
			defer srv.Close()
			b := newFakeBackend()
			e1 := startWith(t, b, db, filepath.Join(dir, "a.sock"), withStore(srv, true))
			sb, _ := e1.c.Create(tctx(t), api.CreateRequest{ID: "victim"})
			if tc.setup != nil {
				if err := tc.setup(e1, sb.ID); err != nil {
					t.Fatal(err)
				}
			}
			if tc.midPuts > 0 {
				srv.FailAfterPuts(tc.midPuts)
			} else {
				e1.m.crashHook = func(p string) {
					if p == tc.point {
						panic(crashed{p})
					}
				}
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						if _, ok := r.(crashed); !ok {
							panic(r)
						}
					}
				}()
				_ = tc.do(e1, sb.ID)
			}()
			// At the moment of the crash, before any sweep: no false claims.
			claimsTrue(t, e1.reg, srv, "at the crash")
			e1.reg.Close() // the process is gone: nothing it left running can write again
			srv.Fail(false)

			e2 := startWith(t, b, db, filepath.Join(dir, "b.sock"), withStore(srv, true))
			invariants(t, e2, srv, filepath.Join(dir, "checkpoints"))
			rec, err := e2.c.Get(tctx(t), sb.ID)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("after the crash at %s and a restart: %s", tc.point, rec.State)
			if rec.State != tc.want {
				t.Fatalf("after the crash at %s: %s, want %s", tc.point, rec.State, tc.want)
			}
			switch rec.State {
			case api.Paused:
				if _, err := e2.c.Resume(tctx(t), sb.ID, ""); err != nil {
					t.Fatalf("a paused sandbox must be resumable: %v", err)
				}
				echoOK(t, e2, sb.ID)
			case api.Running:
				echoOK(t, e2, sb.ID)
			case api.Stopped, api.Failed:
				if cks, _ := e2.reg.Checkpoints(tctx(t), sb.ID); len(cks) != 0 && rec.State == api.Stopped {
					t.Fatalf("a destroyed sandbox keeps checkpoints: %+v", cks)
				}
			}
			invariants(t, e2, srv, filepath.Join(dir, "checkpoints"))
		})
	}
}
