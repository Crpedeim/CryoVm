package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
	"github.com/Crpedeim/sbx/internal/guest"
)

func sockPath(t testing.TB) string {
	t.Helper()
	// Unix socket paths are limited to ~108 bytes; t.TempDir() can be long.
	dir, err := os.MkdirTemp("", "sbx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "agent.sock")
}

// startGuest runs the real guest agent loop in-process, dialing path.
func startGuest(t testing.TB, id, path string) context.CancelFunc {
	return startGuestWith(t, id, path, nil)
}

// startGuestWith lets a test adjust the agent's config. Background
// processes log to a temporary directory, never to the host's /var/log.
func startGuestWith(t testing.TB, id, path string, adjust func(*guest.Config)) context.CancelFunc {
	t.Helper()
	cfg := guest.Config{
		SandboxID: id, Dial: "unix:" + path,
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
		Logf: t.Logf, LogDir: t.TempDir(),
	}
	if adjust != nil {
		adjust(&cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = guest.Run(ctx, cfg)
	}()
	return func() { cancel(); <-done }
}

func wait(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// longWait is for operations that move a lot of data.
func longWait(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func TestHelloAndPing(t *testing.T) {
	path := sockPath(t)
	l, err := Listen(path, "demo")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stop := startGuest(t, "demo", path)
	defer stop()

	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	if conn.Hello.SandboxID != "demo" || conn.Hello.Version != guest.Version || conn.Hello.PID == 0 {
		t.Fatalf("hello: %+v", conn.Hello)
	}
	for i := 0; i < 50; i++ {
		if _, err := conn.Ping(wait(t)); err != nil {
			t.Fatalf("ping %d: %v", i, err)
		}
	}
}

func TestConcurrentPingsMatchByID(t *testing.T) {
	path := sockPath(t)
	l, _ := Listen(path, "demo")
	defer l.Close()
	defer startGuest(t, "demo", path)()
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := conn.Ping(wait(t)); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent ping: %v", err)
	}
}

func TestAgentReconnectsAfterConnectionDrops(t *testing.T) {
	path := sockPath(t)
	l, _ := Listen(path, "demo")
	defer l.Close()
	defer startGuest(t, "demo", path)()

	first, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	first.Close() // what a host-daemon restart or a checkpoint restore looks like to the agent

	second, err := l.Conn(wait(t))
	if err != nil {
		t.Fatalf("no reconnect: %v", err)
	}
	if second == first {
		t.Fatal("got the dead connection back")
	}
	if _, err := second.Ping(wait(t)); err != nil {
		t.Fatalf("ping after reconnect: %v", err)
	}
	if _, err := first.Ping(wait(t)); !errors.Is(err, ErrClosed) {
		t.Fatalf("old conn: want ErrClosed, got %v", err)
	}
}

func TestWrongSandboxIsRejected(t *testing.T) {
	path := sockPath(t)
	l, _ := Listen(path, "demo")
	defer l.Close()

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hello, _ := agentproto.New(agentproto.TypeHello, 0, agentproto.Hello{SandboxID: "intruder", PID: 7})
	_ = agentproto.Write(c, hello)
	reply, err := agentproto.Read(c)
	if err != nil || reply.Type != agentproto.TypeReject {
		t.Fatalf("want reject, got %+v %v", reply, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := l.Conn(ctx); err == nil {
		t.Fatal("a rejected agent became the sandbox's connection")
	}
}

func TestSilentClientDoesNotBlockRealAgent(t *testing.T) {
	path := sockPath(t)
	l, _ := Listen(path, "demo", WithHelloTimeout(300*time.Millisecond))
	defer l.Close()

	silent, err := net.Dial("unix", path) // connects, never says hello
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	defer startGuest(t, "demo", path)()

	if _, err := l.Conn(wait(t)); err != nil {
		t.Fatalf("real agent blocked by silent client: %v", err)
	}
	_ = silent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := silent.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent client was not disconnected")
	}
}

func TestCloseWakesWaitersAndRemovesSocket(t *testing.T) {
	path := sockPath(t)
	l, _ := Listen(path, "demo")
	errc := make(chan error, 1)
	go func() { _, err := l.Conn(context.Background()); errc <- err }()
	time.Sleep(50 * time.Millisecond)
	l.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("want ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wake the waiter")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("socket file left behind")
	}
}

func TestGuestRejectsUnknownDialScheme(t *testing.T) {
	for _, d := range []string{"tcp:1.2.3.4:80", "vsock:2:1024", "unix:", "nonsense"} {
		err := guest.Run(context.Background(), guest.Config{SandboxID: "x", Dial: d, LogDir: t.TempDir()})
		if !errors.Is(err, guest.ErrUnsupportedDial) {
			t.Errorf("%q: want ErrUnsupportedDial, got %v", d, err)
		}
	}
}
