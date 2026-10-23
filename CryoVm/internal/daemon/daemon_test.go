package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
	"github.com/Crpedeim/sbx/internal/registry"
)

type env struct {
	b    *fakeBackend
	reg  *registry.Registry
	m    *Manager
	c    *client.Client
	db   string
	sock string
}

// start runs the real HTTP handler on a real Unix socket, with the real
// client in front: everything but the backend is production code.
func start(t *testing.T, adjust ...func(*Config)) *env {
	t.Helper()
	dir, err := os.MkdirTemp("", "sbxd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	db := filepath.Join(dir, "registry.db")
	return startWith(t, newFakeBackend(), db, filepath.Join(dir, "sbxd.sock"), adjust...)
}

func startWith(t *testing.T, b *fakeBackend, db, sock string, adjust ...func(*Config)) *env {
	t.Helper()
	reg, err := registry.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Backend: b, Registry: reg, Rootfs: "/fake-rootfs", PidsMax: 512, GuardInterval: 20 * time.Millisecond,
		LifetimeEvery: 20 * time.Millisecond, CheckpointDir: filepath.Join(filepath.Dir(db), "checkpoints"),
		AgentWait: 5 * time.Second, Logf: t.Logf}
	if cfg.Net == nil {
		cfg.Net = newFakeNet() // the real one needs root
	}
	for _, f := range adjust {
		f(&cfg)
	}
	m, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: NewHandler(m), ConnContext: ConnContext}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		m.Close(context.Background())
		reg.Close()
	})
	return &env{b: b, reg: reg, m: m, c: client.New(sock), db: db, sock: sock}
}

func tctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func states(evs []api.Event) string {
	var s []string
	for _, e := range evs {
		s = append(s, string(e.To))
	}
	return strings.Join(s, " → ")
}

func TestLifecycleOverHTTP(t *testing.T) {
	e := start(t)
	ctx := tctx(t)

	sb, err := e.c.Create(ctx, api.CreateRequest{})
	if err != nil || sb.State != api.Running || !strings.HasPrefix(sb.ID, "sbx-") {
		t.Fatalf("create: %+v %v", sb, err)
	}
	if got, err := e.c.Get(ctx, sb.ID); err != nil || got.Rootfs != "/fake-rootfs" || got.VCPUs != 1 {
		t.Fatalf("get (defaults applied?): %+v %v", got, err)
	}

	var out, errb bytes.Buffer
	st, err := e.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "echo out; echo err >&2; exit 3"}, Stdout: &out, Stderr: &errb})
	if err != nil || st.Code != 3 || out.String() != "out\n" || errb.String() != "err\n" {
		t.Fatalf("exec: %+v %v stdout=%q stderr=%q", st, err, out.String(), errb.String())
	}

	dir := t.TempDir()
	data := make([]byte, 3<<20)
	rand.New(rand.NewSource(1)).Read(data)
	put, err := e.c.Put(ctx, sb.ID, filepath.Join(dir, "f.bin"), bytes.NewReader(data), client.PutOptions{Mode: 0o600})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	var back bytes.Buffer
	got, err := e.c.Fetch(ctx, sb.ID, filepath.Join(dir, "f.bin"), &back)
	if err != nil || got.SHA256 != put.SHA256 || !bytes.Equal(back.Bytes(), data) {
		t.Fatalf("fetch: %+v %v", got, err)
	}
	if ls, err := e.c.ListDir(ctx, sb.ID, dir); err != nil || len(ls.Entries) != 1 || ls.Entries[0].Mode != 0o600 {
		t.Fatalf("ls: %+v %v", ls, err)
	}

	live, _ := e.c.List(ctx, false)
	if len(live) != 1 {
		t.Fatalf("live list: %d", len(live))
	}
	done, err := e.c.Destroy(ctx, sb.ID)
	if err != nil || done.State != api.Stopped {
		t.Fatalf("destroy: %+v %v", done, err)
	}
	if again, err := e.c.Destroy(ctx, sb.ID); err != nil || again.State != api.Stopped {
		t.Fatalf("second destroy should be a no-op: %+v %v", again, err)
	}
	evs, _ := e.c.Events(ctx, sb.ID)
	if got := states(evs); got != "creating → running → stopping → stopped" {
		t.Fatalf("history: %s", got)
	}
	live, _ = e.c.List(ctx, false)
	all, _ := e.c.List(ctx, true)
	if len(live) != 0 || len(all) != 1 {
		t.Fatalf("after destroy: live=%d all=%d", len(live), len(all))
	}
}

// firstWriteWriter records when the first byte arrived.
type firstWriteWriter struct {
	mu    sync.Mutex
	first time.Time
	buf   bytes.Buffer
}

func (w *firstWriteWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.first.IsZero() {
		w.first = time.Now()
	}
	return w.buf.Write(p)
}

func TestExecStreamsThroughHTTP(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "stream"})
	w := &firstWriteWriter{}
	start := time.Now()
	if _, err := e.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sh", "-c", "echo a; sleep 1; echo b"}, Stdout: w}); err != nil {
		t.Fatal(err)
	}
	total := time.Since(start)
	if w.first.IsZero() || w.first.Sub(start) > total-500*time.Millisecond {
		t.Fatalf("first byte after %s of %s: buffered somewhere between agent and client", w.first.Sub(start), total)
	}
}

func sleepers(d string) int {
	n := 0
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range dirs {
		if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil && string(b) == "sleep\x00"+d+"\x00" {
			n++
		}
	}
	return n
}

// Ctrl+C on the CLI cancels the client's context, which closes the HTTP
// connection; the daemon sees its request context cancelled and the agent
// kills the command. The test follows that whole chain.
func TestClientCancelKillsRemoteCommand(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "cancel"})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	_, err := e.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"sleep", "33.5"}})
	if err == nil {
		t.Fatal("exec survived its context")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("cancel took %s", took)
	}
	deadline := time.Now().Add(3 * time.Second)
	for sleepers("33.5") > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := sleepers("33.5"); n > 0 {
		t.Fatal("the command kept running after the client went away")
	}
}

func TestErrorsKeepTheirMeaning(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "errs"})
	dir := t.TempDir()

	check := func(name string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: want %v, got %v", name, want, err)
		}
	}
	_, err := e.c.Get(ctx, "nope")
	check("unknown sandbox", err, client.ErrNotFound)
	_, err = e.c.Exec(ctx, "nope", client.ExecRequest{Args: []string{"true"}})
	check("exec on unknown sandbox", err, client.ErrNotFound)
	_, err = e.c.Create(ctx, api.CreateRequest{ID: "Bad ID"})
	check("invalid id", err, client.ErrInvalid)
	_, err = e.c.Create(ctx, api.CreateRequest{ID: "errs"})
	check("duplicate id", err, client.ErrConflict)
	_, err = e.c.Fetch(ctx, sb.ID, filepath.Join(dir, "missing"), &bytes.Buffer{})
	check("missing file", err, client.ErrNotFound)
	_, err = e.c.Fetch(ctx, sb.ID, dir, &bytes.Buffer{})
	check("download a directory", err, client.ErrInvalid)
	_, err = e.c.Put(ctx, sb.ID, "relative/path", strings.NewReader("x"), client.PutOptions{})
	check("relative path", err, client.ErrInvalid)

	_, _ = e.c.Destroy(ctx, sb.ID)
	_, err = e.c.Exec(ctx, sb.ID, client.ExecRequest{Args: []string{"true"}})
	check("exec on a stopped sandbox", err, client.ErrConflict)
}

func TestFailedCreateIsRecorded(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	e.b.mu.Lock()
	e.b.failCreate = errors.New("rootfs is corrupt")
	e.b.mu.Unlock()
	if _, err := e.c.Create(ctx, api.CreateRequest{ID: "broken"}); err == nil {
		t.Fatal("create should fail")
	}
	rec, err := e.c.Get(ctx, "broken")
	if err != nil || rec.State != api.Failed || !strings.Contains(rec.Error, "rootfs is corrupt") {
		t.Fatalf("record: %+v %v", rec, err)
	}
	evs, _ := e.c.Events(ctx, "broken")
	if got := states(evs); got != "creating → failed" {
		t.Fatalf("history: %s", got)
	}
}

func TestUnexpectedExitIsRecorded(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "crashy"})
	e.b.get(sb.ID).crash()

	deadline := time.Now().Add(3 * time.Second)
	var rec api.Sandbox
	for time.Now().Before(deadline) {
		rec, _ = e.c.Get(ctx, sb.ID)
		if rec.State == api.Failed {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rec.State != api.Failed || !strings.Contains(rec.Error, "unexpectedly") {
		t.Fatalf("a crashed sandbox should be failed: %+v", rec)
	}
	if again, err := e.c.Destroy(ctx, sb.ID); err != nil || again.State != api.Failed {
		t.Fatalf("destroying a failed sandbox should be a no-op: %+v %v", again, err)
	}
}

func TestConcurrentDestroysStopOnce(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "race"})
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.c.Destroy(ctx, sb.ID); err != nil && !errors.Is(err, client.ErrConflict) {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	evs, _ := e.c.Events(ctx, sb.ID)
	if got := states(evs); got != "creating → running → stopping → stopped" {
		t.Fatalf("ten destroys must stop it exactly once: %s", got)
	}
}

func TestRestartFailsAndReapsLeftovers(t *testing.T) {
	dir, _ := os.MkdirTemp("", "sbxd")
	t.Cleanup(func() { os.RemoveAll(dir) })
	db := filepath.Join(dir, "registry.db")

	// A daemon dies without cleaning up: simulate with a record left running.
	reg, err := registry.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = reg.Create(context.Background(), registry.Sandbox{ID: "left", Backend: "fake"})
	_, _ = reg.Transition(context.Background(), "left", registry.Creating, registry.Running, "")
	reg.Close()

	b := newFakeBackend()
	e := startWith(t, b, db, filepath.Join(dir, "sbxd.sock"))
	rec, err := e.c.Get(tctx(t), "left")
	if err != nil || rec.State != api.Failed || !strings.Contains(rec.Error, "daemon restarted") {
		t.Fatalf("leftover: %+v %v", rec, err)
	}
	b.mu.Lock()
	reaped := fmt.Sprint(b.reaped)
	b.mu.Unlock()
	if reaped != "[left]" {
		t.Fatalf("reaped %s, want [left]", reaped)
	}
}

func TestCloseStopsEverything(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	for i := 0; i < 3; i++ {
		if _, err := e.c.Create(ctx, api.CreateRequest{ID: fmt.Sprintf("c%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	e.m.Close(ctx)
	all, _ := e.m.List(ctx, true)
	for _, s := range all {
		if s.State != api.Stopped {
			t.Errorf("%s is %s after Close", s.ID, s.State)
		}
	}
}
