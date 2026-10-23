package daemon

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

// webApp stands in for a server an agent started in its sandbox. The fake
// backend's agent runs on this machine, so the sandbox's loopback is the
// test's own, and a listener here is a server "inside".
func webApp(t *testing.T) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/big":
			n, _ := strconv.Atoi(r.URL.Query().Get("n"))
			data := make([]byte, n)
			rand.New(rand.NewSource(int64(n))).Read(data)
			w.Header().Set("X-Sha256", sum(data))
			_, _ = w.Write(data)
		case r.Method == http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, "%d bytes, sha256 %s", len(b), sum(b))
		default:
			fmt.Fprintf(w, "<h1>made by an agent</h1> %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// freePort is a port nothing listens on, a moment ago.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// get sends one HTTP request over a forwarded connection, and reads the
// answer.
func get(t *testing.T, conn net.Conn, path string) (*http.Response, string) {
	t.Helper()
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: preview\r\nConnection: close\r\n\r\n", path)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: reading the body: %v", path, err)
	}
	return resp, string(body)
}

// auditWith waits for the sandbox's latest audit entry of an action: some
// are written as a connection ends, just after the client sees it end.
func auditWith(t *testing.T, e *env, id, action string) api.AuditEntry {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if a, ok := auditActions(t, e, id)[action]; ok {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s in %s's audit log", action, id)
		}
	}
}

// What an agent made, seen from the host: a web server listening inside the
// sandbox, reached through the daemon, in a sandbox with no network at all.
func TestPortForwardingOverHTTP(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "web"})
	port := webApp(t)

	conn, err := e.c.DialPort(ctx, sb.ID, port)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := get(t, conn, "/index.html")
	conn.Close()
	if resp.StatusCode != http.StatusOK || body != "<h1>made by an agent</h1> GET /index.html" {
		t.Fatalf("through the tunnel: %d %q", resp.StatusCode, body)
	}

	list, err := e.c.Ports(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, p := range list.Ports {
		listed = listed || (p.Port == port && p.Addr == "127.0.0.1" && p.PID > 0)
	}
	if !listed {
		t.Fatalf("port %d isn't listed, with its process: %+v", port, list.Ports)
	}

	// The audit chain says who connected to what, and how it ended.
	if open := auditWith(t, e, sb.ID, "port.open"); open.Detail != fmt.Sprintf("port %d → 127.0.0.1:%d", port, port) || open.Outcome != "ok" {
		t.Fatalf("port.open: %+v", open)
	}
	if end := auditWith(t, e, sb.ID, "port.close"); !strings.HasPrefix(end.Detail, fmt.Sprintf("port %d: ", port)) ||
		!strings.Contains(end.Detail, " in, ") || !strings.HasSuffix(end.Detail, "; closed") {
		t.Fatalf("port.close: %+v", end)
	}
}

// Many windows' worth both ways, through the daemon's socket: an upload the
// server checks, and a download the client checks.
func TestPortForwardingCarriesLargeBodies(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "big"})
	port := webApp(t)

	conn, err := e.c.DialPort(tctx(t), sb.ID, port)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := get(t, conn, "/big?n=12345678")
	conn.Close()
	if resp.StatusCode != http.StatusOK || len(body) != 12345678 || sum([]byte(body)) != resp.Header.Get("X-Sha256") {
		t.Fatalf("download: %d, %d bytes, intact: %v", resp.StatusCode, len(body), sum([]byte(body)) == resp.Header.Get("X-Sha256"))
	}

	up := make([]byte, 9<<20)
	rand.New(rand.NewSource(9)).Read(up)
	conn, err = e.c.DialPort(tctx(t), sb.ID, port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: preview\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(up))
		_, _ = conn.Write(up)
	}()
	resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if want := fmt.Sprintf("%d bytes, sha256 %s", len(up), sum(up)); string(got) != want {
		t.Fatalf("upload: %q, want %q", got, want)
	}
}

// TCP's half-close survives the whole chain (client, daemon socket, agent):
// the server reads the request to its end, and only then answers.
func TestPortForwardingHalfCloses(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "half"})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, _ := io.ReadAll(c)
		for i, j := 0, len(req)-1; i < j; i, j = i+1, j-1 {
			req[i], req[j] = req[j], req[i]
		}
		fmt.Fprintf(c, "%d bytes, reversed: %s", len(req), req)
	}()
	conn, err := e.c.DialPort(tctx(t), sb.ID, ln.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Without the half-close passed on, the server would wait forever for
	// the rest of the request: fail in seconds instead.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "stressed"); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(conn); err != nil || string(got) != "8 bytes, reversed: desserts" {
		t.Fatalf("got %q, %v (did the half-close reach the server?)", got, err)
	}
}

func TestPortForwardingErrors(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "errs"})
	free := freePort(t)

	_, err := e.c.DialPort(ctx, sb.ID, free)
	var apiErr *client.APIError
	if !errors.Is(err, client.ErrRefused) || !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadGateway ||
		!strings.Contains(err.Error(), fmt.Sprintf("nothing is listening on port %d", free)) {
		t.Fatalf("nothing listening: want a 502 saying so, got %v", err)
	}
	if open := auditWith(t, e, sb.ID, "port.open"); open.Outcome != "error" || !strings.Contains(open.Error, "nothing is listening") {
		t.Fatalf("a refused connection is recorded too: %+v", open)
	}
	for _, bad := range []int{0, 70000} {
		if _, err := e.c.DialPort(ctx, sb.ID, bad); !errors.Is(err, client.ErrInvalid) {
			t.Errorf("port %d: want ErrInvalid, got %v", bad, err)
		}
	}
	if _, err := e.c.DialPort(ctx, "nope", 80); !errors.Is(err, client.ErrNotFound) {
		t.Errorf("unknown sandbox: want ErrNotFound, got %v", err)
	}

	raw := func(path, upgrade string) int {
		t.Helper()
		conn, err := net.Dial("unix", e.sock)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		hdr := ""
		if upgrade != "" {
			hdr = "Connection: Upgrade\r\nUpgrade: " + upgrade + "\r\n"
		}
		fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: sbxd\r\n%sContent-Length: 0\r\n\r\n", path, hdr)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}
	if code := raw("/v1/sandboxes/errs/ports/http/connect", api.PortProtocol); code != http.StatusBadRequest {
		t.Errorf("a port that isn't a number: want 400, got %d", code)
	}
	if code := raw("/v1/sandboxes/errs/ports/80/connect", ""); code != http.StatusUpgradeRequired {
		t.Errorf("no Upgrade header: want 426, got %d", code)
	}
	if code := raw("/v1/sandboxes/errs/ports/80/connect", api.ShellProtocol); code != http.StatusUpgradeRequired {
		t.Errorf("the shell's protocol: want 426, got %d", code)
	}

	_, _ = e.c.Destroy(ctx, sb.ID)
	if _, err := e.c.DialPort(ctx, sb.ID, free); !errors.Is(err, client.ErrConflict) {
		t.Errorf("a destroyed sandbox: want ErrConflict, got %v", err)
	}
	if _, err := e.c.Ports(ctx, sb.ID); !errors.Is(err, client.ErrConflict) {
		t.Errorf("ports of a destroyed sandbox: want ErrConflict, got %v", err)
	}
}

// An open forwarded connection is activity, as an attached shell is: the
// sandbox doesn't idle-pause under someone looking at what's in it, and a
// checkpoint that isn't forced says it's busy. Once it's closed, the
// sandbox naps.
func TestForwardedConnectionKeepsTheSandboxAwake(t *testing.T) {
	e := start(t)
	sb := napper(t, e, "awake")
	conn, err := e.c.DialPort(tctx(t), sb.ID, webApp(t))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond) // past its 1 s idle timeout
	if rec, _ := e.c.Get(tctx(t), sb.ID); rec.State != api.Running {
		t.Fatalf("paused under an open connection: %s", rec.State)
	}
	if _, err := e.c.Checkpoint(tctx(t), sb.ID, api.CheckpointRequest{}); !errors.Is(err, client.ErrConflict) || !strings.Contains(err.Error(), "forwarded connection") {
		t.Fatalf("checkpoint while a connection is open: %v", err)
	}
	conn.Close()
	waitState(t, e, sb.ID, api.Paused, 5*time.Second)
}

// A connection to a sleeping sandbox wakes it, as any use does: a preview
// left open in a browser works again after the sandbox has napped.
func TestForwardWakesASleepingSandbox(t *testing.T) {
	e := start(t)
	sb := napper(t, e, "sleepy")
	port := webApp(t)
	waitState(t, e, sb.ID, api.Paused, 5*time.Second)
	conn, err := e.c.DialPort(tctx(t), sb.ID, port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if resp, body := get(t, conn, "/after-a-nap"); resp.StatusCode != http.StatusOK || !strings.HasSuffix(body, "GET /after-a-nap") {
		t.Fatalf("after waking: %d %q", resp.StatusCode, body)
	}
	if rec, _ := e.c.Get(tctx(t), sb.ID); rec.State != api.Running {
		t.Fatalf("not woken: %s", rec.State)
	}
	auditWith(t, e, sb.ID, "sandbox.wake")
}

// What sbx forward and the MCP tool run: the sandbox's port served on this
// machine, for a browser. Requests at once each get their own connection.
func TestServePortForwardsABrowser(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "fwd"})
	port := webApp(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- e.c.ServePort(ln, sb.ID, port, nil) }()

	browser := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := browser.Get(fmt.Sprintf("http://%s/page/%d", ln.Addr(), i))
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if want := fmt.Sprintf("<h1>made by an agent</h1> GET /page/%d", i); string(body) != want {
				errs <- fmt.Errorf("page %d: %q", i, body)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// A server that speaks first (a greeting, as SMTP's or SSH's) is
	// reached at once: the forwarder doesn't wait for the client's bytes.
	greeter, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer greeter.Close()
	go func() {
		if c, err := greeter.Accept(); err == nil {
			io.WriteString(c, "220 sandbox ready\r\n")
			c.Close()
		}
	}()
	ln2, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer ln2.Close()
	go e.c.ServePort(ln2, sb.ID, greeter.Addr().(*net.TCPAddr).Port, nil)
	c, err := net.Dial("tcp4", ln2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, err := bufio.NewReader(c).ReadString('\n'); err != nil || line != "220 sandbox ready\r\n" {
		t.Fatalf("the greeting: %q, %v", line, err)
	}

	ln.Close()
	if err := <-served; err != nil {
		t.Fatalf("ServePort after its listener closed: %v", err)
	}
}

// A browser opening the address before the server inside is up gets a
// page saying why, not an empty response; a client that doesn't speak
// HTTP is just closed.
func TestServePortExplainsARefusal(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "early"})
	port := freePort(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var refusals []error
	go e.c.ServePort(ln, sb.ID, port, func(err error) {
		mu.Lock()
		refusals = append(refusals, err)
		mu.Unlock()
	})

	browser := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}
	resp, err := browser.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), fmt.Sprintf("nothing is listening on port %d", port)) ||
		!strings.Contains(string(body), "sandbox early") {
		t.Fatalf("the page: %d %q", resp.StatusCode, body)
	}

	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(c); len(got) != 0 || err != nil {
		t.Fatalf("a client that never spoke: %q, %v; want closed without a word", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(refusals) != 2 || !errors.Is(refusals[0], client.ErrRefused) {
		t.Fatalf("refusals reported: %v", refusals)
	}
	if !bytes.Contains([]byte(refusals[1].Error()), []byte("nothing is listening")) {
		t.Fatalf("the second refusal: %v", refusals[1])
	}
}
