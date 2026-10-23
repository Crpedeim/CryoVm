package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

// serve runs handle for every connection to a fresh listener, and returns
// its port. The in-process agent's "sandbox" is this machine, so the
// sandbox's loopback is the test's own.
func serve(t testing.TB, network, addr string, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// echo writes back everything it reads, until the client's end of file.
func echo(conn net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// readAll reads r to its end, or gives up after 10 s with an error rather
// than hang a test whose end of file never comes (a tunnel has no deadlines
// of its own). Safe to call from any goroutine.
func readAll(r io.Reader) ([]byte, error) {
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(r)
		done <- result{b, err}
	}()
	select {
	case res := <-done:
		return res.b, res.err
	case <-time.After(10 * time.Second):
		return nil, errors.New("no end of file within 10 s")
	}
}

func ended(t *testing.T, tun *Tunnel) {
	t.Helper()
	select {
	case <-tun.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel never ended")
	}
}

// The basic contract: bytes both ways, and TCP's half-close. The server
// reads the whole request, to end of file, before it answers: that works
// only if CloseWrite reaches it while the answer's direction stays open.
func TestTunnelCarriesBytesAndHalfCloses(t *testing.T) {
	c := connected(t)
	port := serve(t, "tcp4", "127.0.0.1:0", func(conn net.Conn) {
		req, _ := io.ReadAll(conn)
		fmt.Fprintf(conn, "got %d bytes: %s", len(req), bytes.ToUpper(req))
	})
	tun, err := c.DialPort(wait(t), port)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if want := "127.0.0.1:" + strconv.Itoa(port); tun.Addr != want {
		t.Fatalf("answered from %q, want %q", tun.Addr, want)
	}
	for _, part := range []string{"hello, ", "sandbox"} {
		if _, err := io.WriteString(tun, part); err != nil {
			t.Fatal(err)
		}
	}
	if err := tun.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := readAll(tun)
	if err != nil || string(got) != "got 14 bytes: HELLO, SANDBOX" {
		t.Fatalf("answer: %q %v", got, err)
	}
	ended(t, tun)
	if err := tun.Err(); err != nil {
		t.Fatalf("both sides closed: a clean end, not %v", err)
	}
	if _, err := tun.Write([]byte("x")); err == nil {
		t.Fatal("a write after CloseWrite went through")
	}
}

// Both directions at once, many windows' worth each way, with the server
// reading and writing concurrently: every byte arrives, in order.
func TestTunnelFullDuplex(t *testing.T) {
	c := connected(t)
	const size = 8 << 20
	up, down := randomBytes(size, 1), randomBytes(size, 2)
	received := make(chan string, 1)
	port := serve(t, "tcp4", "127.0.0.1:0", func(conn net.Conn) {
		wrote := make(chan struct{})
		go func() {
			defer close(wrote)
			_, _ = conn.Write(down)
			_ = conn.(*net.TCPConn).CloseWrite()
		}()
		b, _ := io.ReadAll(conn)
		received <- sha(b)
		<-wrote
	})
	tun, err := c.DialPort(longWait(t), port)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	go func() {
		_, _ = tun.Write(up)
		_ = tun.CloseWrite()
	}()
	got, err := readAll(tun)
	if err != nil || len(got) != size || sha(got) != sha(down) {
		t.Fatalf("down: %d bytes, %v; intact: %v", len(got), err, sha(got) == sha(down))
	}
	if s := <-received; s != sha(up) {
		t.Fatal("up: the server received different bytes")
	}
	ended(t, tun)
	if err := tun.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelToAPortNobodyListensOn(t *testing.T) {
	c := connected(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // free a moment ago: nothing listens there now
	_, err = c.DialPort(wait(t), port)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "nothing is listening on port "+strconv.Itoa(port)) {
		t.Fatalf("want ErrRefused saying nothing listens, got %v", err)
	}
	for _, bad := range []int{0, -1, 65536} {
		if _, err := c.DialPort(wait(t), bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("port %d: want ErrInvalid, got %v", bad, err)
		}
	}
	if _, err := c.Ping(wait(t)); err != nil {
		t.Fatalf("the connection after refused tunnels: %v", err)
	}
}

// A server on IPv6's loopback alone (Node's dev servers can be) is still
// reached: the agent tries ::1 after 127.0.0.1.
func TestTunnelReachesAServerOnIPv6LoopbackOnly(t *testing.T) {
	c := connected(t)
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback on this machine")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if probe, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port)); err != nil {
		t.Skipf("port %d is taken on 127.0.0.1 too", port)
	} else {
		probe.Close()
	}
	port6 := serve(t, "tcp6", "[::1]:"+strconv.Itoa(port), func(conn net.Conn) { io.WriteString(conn, "from ::1") })
	tun, err := c.DialPort(wait(t), port6)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	got, err := readAll(tun)
	if err != nil || string(got) != "from ::1" || tun.Addr != "[::1]:"+strconv.Itoa(port6) {
		t.Fatalf("got %q from %s, %v", got, tun.Addr, err)
	}
}

// A server bound to one of the sandbox's own addresses only, not loopback
// (told to listen on eth0's address, say): it's listed, so it's reached,
// at the address its socket is bound to.
func TestTunnelReachesAServerBoundToItsOwnAddress(t *testing.T) {
	c := connected(t)
	var own string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
			own = ipn.IP.String()
			break
		}
	}
	if own == "" {
		t.Skip("this machine has no address but loopback")
	}
	ln, err := net.Listen("tcp4", own+":0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if probe, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port)); err != nil {
		t.Skipf("port %d is taken on 127.0.0.1", port)
	} else {
		probe.Close()
	}
	serve(t, "tcp4", net.JoinHostPort(own, strconv.Itoa(port)), func(conn net.Conn) { io.WriteString(conn, "on "+own) })
	tun, err := c.DialPort(wait(t), port)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	got, err := readAll(tun)
	if err != nil || string(got) != "on "+own || tun.Addr != net.JoinHostPort(own, strconv.Itoa(port)) {
		t.Fatalf("got %q from %s, %v", got, tun.Addr, err)
	}
}

// The server answers and hangs up without reading (a greeting, say): the
// client still gets every byte, then end of file, and once it's done too,
// the tunnel ends cleanly.
func TestTunnelServerHangsUpFirst(t *testing.T) {
	c := connected(t)
	port := serve(t, "tcp4", "127.0.0.1:0", func(conn net.Conn) { io.WriteString(conn, "220 ready\r\n") })
	tun, err := c.DialPort(wait(t), port)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	got, err := readAll(tun)
	if err != nil || string(got) != "220 ready\r\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	select {
	case <-tun.Done():
		t.Fatal("the tunnel ended while the client's side was still open")
	case <-time.After(100 * time.Millisecond):
	}
	if err := tun.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	ended(t, tun)
	if err := tun.Err(); err != nil {
		t.Fatalf("a clean end, not %v", err)
	}
}

func TestTunnelCloseDropsTheConnection(t *testing.T) {
	c := connected(t)
	serverDone := make(chan struct{})
	port := serve(t, "tcp4", "127.0.0.1:0", func(conn net.Conn) {
		_, _ = io.Copy(io.Discard, conn) // until the end, or a reset
		close(serverDone)
	})
	tun, err := c.DialPort(wait(t), port)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tun, "partial"); err != nil {
		t.Fatal(err)
	}
	tun.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent kept its connection to the server after Close")
	}
	if _, err := tun.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after Close: want net.ErrClosed, got %v", err)
	}
	if _, err := tun.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after Close: want net.ErrClosed, got %v", err)
	}
	if _, err := c.Ping(wait(t)); err != nil {
		t.Fatal(err)
	}
}

// A tunnel nobody reads holds up only itself: the server's flood stops at
// the window, and everything else on the connection goes on.
func TestUnreadTunnelDoesNotBlockTheConnection(t *testing.T) {
	c := connected(t)
	port := serve(t, "tcp4", "127.0.0.1:0", func(conn net.Conn) { _, _ = conn.Write(make([]byte, 64<<20)) })
	tun, err := c.DialPort(wait(t), port)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	time.Sleep(200 * time.Millisecond) // the window fills; the rest waits in the sockets
	for i := 0; i < 20; i++ {
		if _, err := c.Ping(wait(t)); err != nil {
			t.Fatalf("ping %d beside an unread tunnel: %v", i, err)
		}
	}
	var out bytes.Buffer
	if res, err := c.Exec(wait(t), ExecRequest{Args: []string{"echo", "still here"}, Stdout: &out}); err != nil || res.ExitCode != 0 || out.String() != "still here\n" {
		t.Fatalf("exec beside an unread tunnel: %+v %v %q", res, err, out.String())
	}
	if n, err := io.CopyN(io.Discard, tun, 4<<20); err != nil || n != 4<<20 {
		t.Fatalf("the tunnel, read at last: %d bytes, %v", n, err)
	}
}

// When the connection to the agent drops (a daemon restart, or a
// checkpoint's quiesce), its tunnels end, on both sides.
func TestTunnelEndsWhenTheAgentConnectionDrops(t *testing.T) {
	c := connected(t)
	serverDone := make(chan struct{})
	port := serve(t, "tcp4", "127.0.0.1:0", func(conn net.Conn) {
		_, _ = io.Copy(io.Discard, conn)
		close(serverDone)
	})
	tun, err := c.DialPort(wait(t), port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := tun.Read(make([]byte, 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("read: want ErrClosed, got %v", err)
	}
	if _, err := tun.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write: want ErrClosed, got %v", err)
	}
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent kept its connection to the server after losing the host")
	}
}

func TestManyTunnelsAtOnce(t *testing.T) {
	c := connected(t)
	port := serve(t, "tcp4", "127.0.0.1:0", echo)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tun, err := c.DialPort(longWait(t), port)
			if err != nil {
				errs <- err
				return
			}
			defer tun.Close()
			msg := bytes.Repeat([]byte(fmt.Sprintf("tunnel %d;", i)), 20000) // several windows' worth
			go func() {
				_, _ = tun.Write(msg)
				_ = tun.CloseWrite()
			}()
			got, err := readAll(tun)
			if err != nil || !bytes.Equal(got, msg) {
				errs <- fmt.Errorf("tunnel %d: %d of %d bytes back, %v", i, len(got), len(msg), err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestPortsListsWhatListens(t *testing.T) {
	c := connected(t)
	port := serve(t, "tcp4", "127.0.0.1:0", func(net.Conn) {})
	list, err := c.Ports(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range list.Ports {
		if p.Port == port && p.Addr == "127.0.0.1" {
			if p.PID != os.Getpid() {
				t.Fatalf("port %d: held by %d %q, want this process (%d)", port, p.PID, p.Command, os.Getpid())
			}
			return
		}
	}
	t.Fatalf("port %d isn't in %+v", port, list.Ports)
}

// A sandbox keeps the agent it was created with, and an agent from before
// port forwarding skips requests it doesn't know: asking it anyway would
// wait until the caller gave up. The hello's version settles it at once.
func TestOldAgentIsRefusedUpFront(t *testing.T) {
	path := sockPath(t)
	l, err := Listen(path, "old")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	raw, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	hello, _ := agentproto.New(agentproto.TypeHello, 0, agentproto.Hello{SandboxID: "old", Version: "0.15.0", PID: 1})
	_ = agentproto.Write(raw, hello)
	if m, err := agentproto.Read(raw); err != nil || m.Type != agentproto.TypeWelcome {
		t.Fatalf("welcome: %+v %v", m, err)
	}
	go func() { // an old agent: everything it doesn't know, it ignores
		for {
			if _, err := agentproto.Read(raw); err != nil {
				return
			}
		}
	}()
	c, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.DialPort(wait(t), 8000); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "0.15.0") {
		t.Fatalf("dial: want ErrUnsupported naming the agent's version, got %v", err)
	}
	if _, err := c.Ports(wait(t)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ports: want ErrUnsupported, got %v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("waited %s for answers that were never coming", took)
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, tc := range []struct {
		have, want string
		ok         bool
	}{
		{"0.16.0", "0.16.0", true}, {"0.16.1", "0.16.0", true}, {"0.17.0", "0.16.0", true}, {"1.0.0", "0.16.0", true},
		{"0.16", "0.16.0", true}, {"0.16.0.1", "0.16.0", true}, {"0.100.0", "0.16.0", true},
		{"0.15.9", "0.16.0", false}, {"0.15.0", "0.16.0", false}, {"0.9.0", "0.16.0", false},
		{"", "0.16.0", false}, {"dev", "0.16.0", false}, {"0.x.0", "0.16.0", false},
	} {
		if got := versionAtLeast(tc.have, tc.want); got != tc.ok {
			t.Errorf("versionAtLeast(%q, %q) = %v, want %v", tc.have, tc.want, got, tc.ok)
		}
	}
}

// go test -bench Tunnel ./internal/agent: the server's bytes to the host
// through one tunnel.
func BenchmarkTunnel(b *testing.B) {
	const size = 64 << 20
	path := sockPath(b)
	l, err := Listen(path, "x")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	defer startGuest(b, "x", path)()
	c, err := l.Conn(longWait(b))
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	port := serve(b, "tcp4", "127.0.0.1:0", func(conn net.Conn) {
		for sent := 0; sent < size; sent += len(chunk) {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	})
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tun, err := c.DialPort(longWait(b), port)
		if err != nil {
			b.Fatal(err)
		}
		if n, err := io.Copy(io.Discard, tun); err != nil || n != size {
			b.Fatalf("%d bytes, %v", n, err)
		}
		tun.Close()
	}
}
