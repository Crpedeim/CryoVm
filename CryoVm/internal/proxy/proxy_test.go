package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	p, err := New(Config{Allow: []string{"pypi.org", "*.pythonhosted.org"},
		Identify: func(netip.Addr) (Client, bool) { return Client{}, false }, Record: func(Decision) {}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host string
		port int
		ok   bool
		why  string
	}{
		{"pypi.org", 443, true, ""},
		{"PyPI.org.", 443, true, ""}, // case and a trailing dot don't matter
		{"files.pythonhosted.org", 443, true, ""},
		{"pythonhosted.org", 443, false, "not on the allowlist"}, // "*." means a subdomain
		{"evilpythonhosted.org", 443, false, "not on the allowlist"},
		{"pypi.org.evil.com", 443, false, "not on the allowlist"},
		{"pypi.org", 22, false, "port 22 is not allowed"},
		{"151.101.0.223", 443, false, "an IP address, not a name: the allowlist is names"},
		{"[2a04:4e42::223]", 443, false, "an IP address, not a name: the allowlist is names"},
	} {
		ok, why := p.Check(c.host, c.port, PolicyAllowlist)
		if ok != c.ok || why != c.why {
			t.Errorf("%s:%d: %v %q, want %v %q", c.host, c.port, ok, why, c.ok, c.why)
		}
	}
	// Browse: any valid name, any address (checked after resolution), still
	// only web ports.
	for _, c := range []struct {
		host string
		port int
		ok   bool
	}{{"anything.example", 443, true}, {"151.101.0.223", 443, true}, {"[2a04:4e42::223]", 80, true},
		{"anything.example", 22, false}, {"bad_name!", 443, false}} {
		if ok, why := p.Check(c.host, c.port, PolicyBrowse); ok != c.ok {
			t.Errorf("browse %s:%d: %v %q, want %v", c.host, c.port, ok, why, c.ok)
		}
	}
	for _, bad := range []string{"py*.org", "pypi.org/simple", ""} {
		if _, err := New(Config{Allow: []string{bad}, Identify: func(netip.Addr) (Client, bool) { return Client{}, false }, Record: func(Decision) {}}); err == nil {
			t.Errorf("allowlist entry %q should be refused", bad)
		}
	}
}

// rig is a proxy on loopback, a sandbox at 127.0.0.1, and an "internet":
// an echo server whose names resolve through a fake resolver.
type rig struct {
	t        *testing.T
	p        *Proxy
	addr     string // the proxy
	echo     net.Listener
	mu       sync.Mutex
	recorded []Decision
	held     map[string]int
}

func newRig(t *testing.T) *rig {
	t.Helper()
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	r := &rig{t: t, echo: echo, held: map[string]int{}}
	echoPort := echo.Addr().(*net.TCPAddr).Port
	p, err := New(Config{
		Allow: []string{"allowed.test", "*.cdn.test", "nowhere.test"},
		Ports: []int{echoPort, 443},
		Identify: func(a netip.Addr) (Client, bool) {
			if a == netip.MustParseAddr("127.0.0.1") {
				return Client{Sandbox: "sbx-a"}, true
			}
			return Client{}, false
		},
		AddrOK: func(netip.Addr) bool { return true }, // this test's "internet" is loopback
		Record: func(d Decision) { r.mu.Lock(); r.recorded = append(r.recorded, d); r.mu.Unlock() },
		Hold: func(id string) func() {
			r.mu.Lock()
			r.held[id]++
			r.mu.Unlock()
			return func() { r.mu.Lock(); r.held[id]--; r.mu.Unlock() }
		},
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "nowhere.test" {
				return nil, errors.New("no such host")
			}
			return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, nil
		},
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve(ln)
	t.Cleanup(func() { p.Close() })
	r.p, r.addr = p, ln.Addr().String()
	return r
}

func (r *rig) echoPort() int { return r.echo.Addr().(*net.TCPAddr).Port }

func (r *rig) last() Decision {
	r.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := len(r.recorded)
		var d Decision
		if n > 0 {
			d = r.recorded[n-1]
		}
		r.mu.Unlock()
		if n > 0 {
			return d
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatal("nothing recorded")
	return Decision{}
}

// connect sends a CONNECT from the given local address and returns the
// connection and the status line.
func (r *rig) connect(from, target string) (net.Conn, *bufio.Reader, string) {
	r.t.Helper()
	d := net.Dialer{Timeout: 2 * time.Second}
	if from != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
	}
	c, err := d.Dial("tcp4", r.addr)
	if err != nil {
		r.t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	return c, br, strings.TrimSpace(status)
}

func TestAllowedConnectTunnels(t *testing.T) {
	r := newRig(t)
	c, br, status := r.connect("", fmt.Sprintf("allowed.test:%d", r.echoPort()))
	defer c.Close()
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("status %q", status)
	}
	br.ReadString('\n') // the blank line ending the reply
	fmt.Fprint(c, "ping\n")
	if got, _ := br.ReadString('\n'); got != "ping\n" {
		t.Fatalf("through the tunnel: %q", got)
	}
	d := r.last()
	if !d.Allowed || d.Sandbox != "sbx-a" || d.Host != "allowed.test" || d.Addr != "127.0.0.1" || d.Method != "CONNECT" {
		t.Fatalf("recorded %+v (want allowed, sbx-a, IPv4 preferred)", d)
	}
	r.mu.Lock()
	busy := r.held["sbx-a"]
	r.mu.Unlock()
	if busy != 1 {
		t.Fatalf("an open tunnel should hold the sandbox busy: %d", busy)
	}
	c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		busy = r.held["sbx-a"]
		r.mu.Unlock()
		if busy == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a closed tunnel should release the sandbox")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRefusalsAreRecorded(t *testing.T) {
	r := newRig(t)
	for target, why := range map[string]string{
		fmt.Sprintf("denied.test:%d", r.echoPort()): "not on the allowlist",
		"allowed.test:22":                         "port 22 is not allowed",
		fmt.Sprintf("127.0.0.1:%d", r.echoPort()): "an IP address, not a name: the allowlist is names",
	} {
		c, br, status := r.connect("", target)
		body, _ := io.ReadAll(br)
		c.Close()
		if status != "HTTP/1.1 403 Forbidden" || !strings.Contains(string(body), why) {
			t.Errorf("%s: %q %q", target, status, body)
		}
		if d := r.last(); d.Allowed || d.Reason != why || d.Sandbox != "sbx-a" {
			t.Errorf("%s: recorded %+v", target, d)
		}
	}
}

// Only the source address identifies a sandbox; anyone else is refused, so
// the proxy is never an open proxy.
func TestNotFromASandboxIsRefused(t *testing.T) {
	r := newRig(t)
	c, br, status := r.connect("127.0.0.2", fmt.Sprintf("allowed.test:%d", r.echoPort()))
	body, _ := io.ReadAll(br)
	c.Close()
	if status != "HTTP/1.1 403 Forbidden" || !strings.Contains(string(body), "not from a sandbox") {
		t.Fatalf("%q %q", status, body)
	}
	if d := r.last(); d.Allowed || d.Sandbox != "" || d.Source != netip.MustParseAddr("127.0.0.2") {
		t.Fatalf("recorded %+v", d)
	}
}

// A client may send its first bytes (a TLS hello) right behind the CONNECT,
// before reading the reply; they must reach upstream, not be lost in the
// proxy's read buffer.
func TestBytesRightBehindTheConnect(t *testing.T) {
	r := newRig(t)
	c, err := net.Dial("tcp4", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target := fmt.Sprintf("allowed.test:%d", r.echoPort())
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nearly bird\n", target, target)
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if got, _ := br.ReadString('\n'); got != "early bird\n" {
		t.Fatalf("the bytes behind the CONNECT: %q", got)
	}
}

func TestPlainHTTPIsForwarded(t *testing.T) {
	r := newRig(t)
	web := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "host %s path %s proxy-header %q", req.Host, req.URL.Path, req.Header.Get("Proxy-Connection"))
	})}
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	go web.Serve(ln)
	defer web.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	r.p.ports[port] = true
	proxyURL, _ := url.Parse("http://" + r.addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 3 * time.Second}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://x.cdn.test:%d/simple/", port), nil)
	req.Header.Set("Proxy-Connection", "keep-alive")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := fmt.Sprintf("host x.cdn.test:%d path /simple/ proxy-header \"\"", port); string(body) != want {
		t.Fatalf("got %q, want %q", body, want)
	}
	if d := r.last(); !d.Allowed || d.Method != "GET" || d.Host != "x.cdn.test" {
		t.Fatalf("recorded %+v", d)
	}
}

func TestFailedLookupIsRecorded(t *testing.T) {
	r := newRig(t)
	c, _, status := r.connect("", "nowhere.test:443")
	c.Close()
	if status != "HTTP/1.1 502 Bad Gateway" {
		t.Fatalf("status %q", status)
	}
	if d := r.last(); !d.Allowed || !strings.Contains(d.Reason, "resolving nowhere.test failed") {
		t.Fatalf("recorded %+v", d)
	}
}

func TestCloseCutsOpenTunnels(t *testing.T) {
	r := newRig(t)
	c, br, status := r.connect("", fmt.Sprintf("allowed.test:%d", r.echoPort()))
	defer c.Close()
	if !strings.Contains(status, "200") {
		t.Fatal(status)
	}
	br.ReadString('\n')
	done := make(chan struct{})
	go func() { r.p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close didn't return with a tunnel open")
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("the tunnel should be cut")
	}
}

func TestPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "151.101.0.223": true, "172.32.0.1": true, "2606:4700::1111": true,
		"10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "100.64.1.1": false, "127.0.0.1": false,
		"169.254.169.254": false, "0.0.0.0": false, "255.255.255.255": false, "224.0.0.1": false, "198.18.0.1": false,
		"::1": false, "fe80::1": false, "fd00::1": false, "::ffff:10.0.0.1": false, "64:ff9b::a00:1": false,
		"2002:a00:1::": false, "2001:db8::1": false,
		"10.200.0.6": false, "10.89.0.1": false, // the sandboxes' own networks
	} {
		if got := Public(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Public(%s) = %v, want %v", addr, got, want)
		}
	}
}

// browseRig: the real public-address check, a fake resolver, and a dialer
// that records where the proxy connected and hands it to a local echo
// server (so "public" addresses are never really dialed).
type browseRig struct {
	*rig
	mu      sync.Mutex
	dialed  []string
	lookups map[string]int
}

func newBrowseRig(t *testing.T, policy string, answers func(host string, n int) []netip.Addr) *browseRig {
	t.Helper()
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	b := &browseRig{rig: &rig{t: t, echo: echo, held: map[string]int{}}, lookups: map[string]int{}}
	p, err := New(Config{
		Allow: []string{"allowed.test"},
		Identify: func(a netip.Addr) (Client, bool) {
			return Client{Sandbox: "sbx-b", Policy: policy}, a == netip.MustParseAddr("127.0.0.1")
		},
		Record: func(d Decision) { b.rig.mu.Lock(); b.recorded = append(b.recorded, d); b.rig.mu.Unlock() },
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			b.mu.Lock()
			b.lookups[host]++
			n := b.lookups[host]
			b.mu.Unlock()
			return answers(host, n), nil
		},
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			b.mu.Lock()
			b.dialed = append(b.dialed, addr)
			b.mu.Unlock()
			return net.Dial("tcp4", echo.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	go p.Serve(ln)
	t.Cleanup(func() { p.Close() })
	b.p, b.addr = p, ln.Addr().String()
	return b
}

func addrs(list ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range list {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// Day 20: the browse policy. The public internet, by name or address; never
// a private, link-local or metadata address, however it's reached.
func TestBrowsePolicy(t *testing.T) {
	b := newBrowseRig(t, PolicyBrowse, func(host string, _ int) []netip.Addr {
		return map[string][]netip.Addr{
			"example.test":  addrs("93.184.215.14"),
			"metadata.test": addrs("169.254.169.254"),
			"mixed.test":    addrs("93.184.215.14", "10.0.0.5"), // one public answer, one private
		}[host]
	})
	for target, want := range map[string]string{
		"example.test:443":   "200",
		"1.1.1.1:443":        "200",
		"169.254.169.254:80": "169.254.169.254 is not a public address",
		"metadata.test:80":   "metadata.test resolves to 169.254.169.254, which is not a public address",
		"mixed.test:443":     "mixed.test resolves to 10.0.0.5, which is not a public address",
		"10.0.0.1:443":       "10.0.0.1 is not a public address",
		"example.test:22":    "port 22 is not allowed",
	} {
		c, br, status := b.connect("", target)
		body := ""
		if !strings.Contains(status, "200") {
			// A refusal ends the connection, so its body can be read to the
			// end; an open tunnel never ends, and reading it would hang.
			body, _ = br.ReadString(0)
		}
		c.Close()
		d := b.last()
		switch {
		case want == "200":
			if !strings.Contains(status, "200") || !d.Allowed || d.Policy != PolicyBrowse {
				t.Errorf("%s: %q, recorded %+v", target, status, d)
			}
		case !strings.Contains(status, "403") || !strings.Contains(body, want) || d.Allowed || d.Reason != want:
			t.Errorf("%s: %q %q; recorded %+v; want %q", target, status, body, d, want)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if strings.Join(b.dialed, " ") != "93.184.215.14:443 1.1.1.1:443" && strings.Join(b.dialed, " ") != "1.1.1.1:443 93.184.215.14:443" {
		t.Fatalf("connected to %v: only the two public destinations, by the addresses checked", b.dialed)
	}
}

// DNS rebinding: a name answers with a public address, then a private one.
// The proxy looks up once and connects to the address it checked, so the
// second answer never matters.
func TestRebindingCannotSlipPast(t *testing.T) {
	b := newBrowseRig(t, PolicyBrowse, func(host string, n int) []netip.Addr {
		if n == 1 {
			return addrs("93.184.215.14")
		}
		return addrs("169.254.169.254")
	})
	c, _, status := b.connect("", "rebind.test:80")
	c.Close()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !strings.Contains(status, "200") || b.lookups["rebind.test"] != 1 || len(b.dialed) != 1 || b.dialed[0] != "93.184.215.14:80" {
		t.Fatalf("status %q, lookups %d, dialed %v: want one lookup and the checked address", status, b.lookups["rebind.test"], b.dialed)
	}
}

// The address check applies to the allowlist too: an allowlisted name that
// resolves somewhere private (a hijacked record, say) is refused.
func TestAllowlistedNameResolvingPrivateIsRefused(t *testing.T) {
	b := newBrowseRig(t, PolicyAllowlist, func(string, int) []netip.Addr { return addrs("127.0.0.1") })
	c, br, status := b.connect("", "allowed.test:443")
	body, _ := br.ReadString(0)
	c.Close()
	if !strings.Contains(status, "403") || !strings.Contains(body, "allowed.test resolves to 127.0.0.1, which is not a public address") {
		t.Fatalf("%q %q", status, body)
	}
}
