// Package proxy is the sandboxes' one way out (Day 18): an HTTP proxy on the
// host. Sandboxes reach it at 10.89.0.1:3128 (Day 17's routers send that
// one destination here), with HTTPS_PROXY pointing at it.
//
// For each connection it:
//   - identifies the sandbox by the source address it sees (each sandbox's
//     router gives it a unique one, Day 16), never by anything the sandbox
//     sends; a connection that isn't from a sandbox is refused outright, so
//     this is never an open proxy;
//   - checks the destination by the sandbox's policy, always on an allowed
//     port (80 or 443):
//     allowlist (the default): a name on the allowlist; raw IP addresses
//     refused, since the allowlist is names;
//     browse (Day 20, browser sandboxes): any name, or a public address;
//   - resolves the name itself (sandboxes have no DNS), checks EVERY address
//     it resolves to, refuses if any isn't public (private ranges, loopback,
//     link-local, the cloud metadata address…), and connects to an address
//     it checked. Checking one answer and connecting by name would let DNS
//     rebinding slip past: a second lookup can answer differently.
//   - records the decision, allowed or not, through Record.
//
// HTTPS goes through CONNECT: the proxy joins two connections and never sees
// inside the encryption. Plain HTTP requests are forwarded one at a time.
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
	"strconv"
	"strings"
	"sync"
	"time"
)

// Policies a sandbox's egress can follow.
const (
	PolicyAllowlist = "allowlist" // names on the allowlist (the default)
	PolicyBrowse    = "browse"    // the public internet (Day 20)
)

// Client is who a connection is from, as Identify finds it.
type Client struct {
	Sandbox string
	Policy  string // PolicyAllowlist ("" too) or PolicyBrowse
}

// Decision is one attempt, as recorded.
type Decision struct {
	Sandbox string     // "" when the source isn't a sandbox
	Policy  string     // the policy it was judged by
	Source  netip.Addr // the address the connection came from
	Method  string     // CONNECT, GET, …
	Host    string
	Port    int
	Allowed bool
	Reason  string // why it was refused, or what went wrong after it was allowed
	Addr    string // the address the name resolved to, when it got that far
}

type Config struct {
	Allow []string // names: "pypi.org" exactly, "*.pythonhosted.org" for any subdomain
	Ports []int    // allowed destination ports; default 80 and 443

	// Identify maps a source address to a sandbox and its policy.
	Identify func(netip.Addr) (Client, bool)
	// AddrOK says whether an address may be connected to. Default: Public.
	// Tests that run "the internet" on loopback replace it.
	AddrOK func(netip.Addr) bool
	// Record is called once per attempt, after it's decided (and, if
	// allowed, after the upstream connection succeeded or failed).
	Record func(Decision)
	// Hold marks a sandbox busy while a connection lasts (Day 13: traffic
	// is activity), until the returned function is called. Optional.
	Hold func(sandbox string) func()

	Resolve func(ctx context.Context, host string) ([]netip.Addr, error) // default: the host's resolver
	Dial    func(ctx context.Context, addr string) (net.Conn, error)     // default: TCP
	Logf    func(string, ...any)
}

type Proxy struct {
	cfg     Config
	exact   map[string]bool
	suffix  []string // ".pythonhosted.org" for "*.pythonhosted.org"
	ports   map[int]bool
	mu      sync.Mutex
	ln      net.Listener
	conns   map[net.Conn]bool
	closed  bool
	running sync.WaitGroup
}

func New(cfg Config) (*Proxy, error) {
	if cfg.Identify == nil || cfg.Record == nil {
		return nil, errors.New("proxy: Identify and Record are required")
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []int{80, 443}
	}
	if cfg.Resolve == nil {
		cfg.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if cfg.Dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		cfg.Dial = func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.AddrOK == nil {
		cfg.AddrOK = Public
	}
	p := &Proxy{cfg: cfg, exact: map[string]bool{}, ports: map[int]bool{}, conns: map[net.Conn]bool{}}
	for _, raw := range cfg.Allow {
		pat := normalize(raw)
		switch {
		case pat == "" || strings.ContainsAny(pat, " /:"):
			return nil, fmt.Errorf("proxy: bad allowlist entry %q", raw)
		case strings.HasPrefix(pat, "*."):
			p.suffix = append(p.suffix, pat[1:])
		case strings.Contains(pat, "*"):
			return nil, fmt.Errorf("proxy: %q: a wildcard may only be a leading \"*.\"", raw)
		default:
			p.exact[pat] = true
		}
	}
	for _, port := range cfg.Ports {
		p.ports[port] = true
	}
	return p, nil
}

// normalize lowercases a name and drops a trailing dot ("PyPI.org." and
// "pypi.org" are the same name).
func normalize(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// Check says whether a destination's name and port are allowed under a
// policy, and if not, why. The addresses it resolves to are checked after
// resolution, under every policy.
func (p *Proxy) Check(host string, port int, policy string) (bool, string) {
	h := normalize(host)
	_, ipErr := netip.ParseAddr(strings.Trim(h, "[]"))
	if !p.ports[port] {
		return false, fmt.Sprintf("port %d is not allowed", port)
	}
	if policy == PolicyBrowse {
		if ipErr != nil && !validName(h) {
			return false, "not a valid host name"
		}
		return true, "" // any name, or an address: what it resolves to is checked next
	}
	if ipErr == nil {
		return false, "an IP address, not a name: the allowlist is names"
	}
	if p.exact[h] {
		return true, ""
	}
	for _, s := range p.suffix {
		if strings.HasSuffix(h, s) && len(h) > len(s) {
			return true, ""
		}
	}
	return false, "not on the allowlist"
}

// Serve accepts connections until Close.
func (p *Proxy) Serve(ln net.Listener) error {
	p.mu.Lock()
	p.ln = ln
	closed := p.closed
	p.mu.Unlock()
	if closed {
		ln.Close()
		return net.ErrClosed
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		if !p.track(c) {
			c.Close()
			return nil
		}
		p.running.Add(1)
		go func() {
			defer p.running.Done()
			defer p.untrack(c)
			p.handle(c)
		}()
	}
}

// Close stops accepting and cuts every open connection.
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	if p.ln != nil {
		p.ln.Close()
	}
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	p.running.Wait()
	return nil
}

func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = true
	return true
}

func (p *Proxy) untrack(c net.Conn) {
	c.Close()
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func refuse(c net.Conn, code int, why string) {
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s\n",
		code, http.StatusText(code), len(why)+1, why)
}

func (p *Proxy) handle(c net.Conn) {
	src := netip.Addr{}
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		src, _ = netip.AddrFromSlice(ta.IP)
		src = src.Unmap()
	}
	d := Decision{Source: src}

	// Who is this? Only the address decides.
	client, ok := p.cfg.Identify(src)
	if !ok {
		d.Reason = "not from a sandbox"
		p.cfg.Record(d)
		refuse(c, http.StatusForbidden, "sbx proxy: "+d.Reason)
		return
	}
	id := client.Sandbox
	d.Sandbox, d.Policy = id, client.Policy
	if d.Policy == "" {
		d.Policy = PolicyAllowlist
	}
	if p.cfg.Hold != nil {
		defer p.cfg.Hold(id)()
	}

	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return // not HTTP, or nothing sent: nothing to record
	}
	_ = c.SetReadDeadline(time.Time{})
	d.Method = req.Method

	var hostport string
	switch {
	case req.Method == http.MethodConnect:
		hostport = req.Host
	case req.URL.IsAbs() && req.URL.Scheme == "http":
		hostport = req.URL.Host
		if req.URL.Port() == "" {
			hostport = net.JoinHostPort(req.URL.Hostname(), "80")
		}
	default:
		d.Reason = "not a proxy request (use CONNECT, or an absolute http:// URL)"
		p.cfg.Record(d)
		refuse(c, http.StatusBadRequest, "sbx proxy: "+d.Reason)
		return
	}
	host, portStr, err := net.SplitHostPort(hostport)
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil {
		d.Host, d.Reason = hostport, "bad destination"
		p.cfg.Record(d)
		refuse(c, http.StatusBadRequest, "sbx proxy: "+d.Reason)
		return
	}
	d.Host, d.Port = normalize(host), port

	if ok, why := p.Check(host, port, d.Policy); !ok {
		d.Reason = why
		p.cfg.Record(d)
		refuse(c, http.StatusForbidden, fmt.Sprintf("sbx proxy: %s:%d %s", d.Host, port, why))
		return
	}

	// Allowed. Resolve here (sandboxes have no DNS), then connect to the
	// address resolved.
	d.Allowed = true
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(strings.Trim(d.Host, "[]")); err == nil {
		addrs = []netip.Addr{a} // an address (browse): checked like any answer
	} else if addrs, err = p.cfg.Resolve(ctx, d.Host); err != nil || len(addrs) == 0 {
		d.Reason = fmt.Sprintf("resolving %s failed: %v", d.Host, err)
		p.cfg.Record(d)
		refuse(c, http.StatusBadGateway, "sbx proxy: "+d.Reason)
		return
	}
	// Every answer must be public: a name answering with a public address
	// and a private one is an attack, not a choice.
	for _, a := range addrs {
		if a = a.Unmap(); !p.cfg.AddrOK(a) {
			d.Allowed, d.Addr = false, a.String()
			d.Reason = fmt.Sprintf("%s resolves to %s, which is not a public address", d.Host, a)
			if d.Host == a.String() {
				d.Reason = fmt.Sprintf("%s is not a public address", a)
			}
			p.cfg.Record(d)
			refuse(c, http.StatusForbidden, "sbx proxy: "+d.Reason)
			return
		}
	}
	// Connect to an address that was checked, never to the name: a second
	// lookup could answer differently (DNS rebinding).
	addr := pick(addrs)
	d.Addr = addr.String()
	up, err := p.cfg.Dial(ctx, net.JoinHostPort(addr.String(), strconv.Itoa(port)))
	if err != nil {
		d.Reason = "connecting failed: " + err.Error()
		p.cfg.Record(d)
		refuse(c, http.StatusBadGateway, "sbx proxy: "+d.Reason)
		return
	}
	defer up.Close()
	p.cfg.Record(d)

	if req.Method == http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		// A client may send its first bytes (a TLS hello) without waiting for
		// the reply: whatever the reader already took goes first.
		if n := br.Buffered(); n > 0 {
			buf, _ := br.Peek(n)
			if _, err := up.Write(buf); err != nil {
				return
			}
		}
		splice(c, up)
		return
	}
	// Plain HTTP: one request, forwarded to the address we connected to,
	// with the proxy's own headers removed.
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Close = true
	if err := req.Write(up); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(up), req)
	if err != nil {
		refuse(c, http.StatusBadGateway, "sbx proxy: bad response from upstream")
		return
	}
	defer resp.Body.Close()
	resp.Close = true
	_ = resp.Write(c)
}

// pick prefers an IPv4 address: the sandboxes' network is IPv4.
func pick(addrs []netip.Addr) netip.Addr {
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap()
		}
	}
	return addrs[0]
}

// splice copies both ways until either side is done, then closes both.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite() // pass the end of one direction along
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// validName is a loose check that a host name is a name: letters, digits,
// hyphens and dots, under the DNS length limit.
func validName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		if !(r == '-' || r == '.' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// notPublic is every range a sandbox must never reach, from IANA's
// special-purpose address registries: private and shared ranges, loopback,
// link-local (which holds the cloud metadata address, 169.254.169.254),
// documentation, benchmarking, multicast and reserved space, and their IPv6
// counterparts, plus the IPv6 prefixes that embed an IPv4 address (NAT64,
// 6to4) and could smuggle a private one in.
var notPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32",
		"2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// Public says whether an address is on the public internet.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
