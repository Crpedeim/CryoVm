package daemon

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/proxy"
)

func TestProxySettingsInNetworkedSandboxes(t *testing.T) {
	envOf := func(egress string, network bool) string {
		e := start(t, func(c *Config) { c.Egress = egress })
		sb, err := e.c.Create(tctx(t), api.CreateRequest{Network: network})
		if err != nil {
			t.Fatal(err)
		}
		e.b.mu.Lock()
		defer e.b.mu.Unlock()
		return strings.Join(e.b.specs[sb.ID].Env, " ")
	}
	if env := envOf("deny", true); !strings.Contains(env, "HTTPS_PROXY=http://10.89.0.1:3128") || !strings.Contains(env, "https_proxy=") {
		t.Fatalf("a networked sandbox, egress denied: %q", env)
	}
	if env := envOf("open", true); env != "" {
		t.Fatalf("egress open needs no proxy: %q", env)
	}
	if env := envOf("deny", false); env != "" {
		t.Fatalf("no network, no proxy: %q", env)
	}
}

func TestProxyIdentifiesALiveSandboxByItsAddress(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "who", Network: true})
	addr := netip.MustParseAddr(sb.NetAddr)
	if c, ok := e.m.identify(addr); !ok || c.Sandbox != "who" || c.Policy != "" {
		t.Fatalf("identify(%s) = %+v %v", addr, c, ok)
	}
	if _, ok := e.m.identify(netip.MustParseAddr("10.200.0.10")); ok {
		t.Fatal("an empty slot identifies nobody")
	}
	if _, err := e.c.Destroy(tctx(t), sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.m.identify(addr); ok {
		t.Fatal("a destroyed sandbox's address identifies nobody")
	}
}

// The real proxy, started by the daemon: a connection from the host itself
// is not a sandbox, so it's refused, and the refusal is in the audit chain.
// A sandbox's decisions are recorded with the sandbox as the actor.
func TestProxyDecisionsGoToTheAuditChain(t *testing.T) {
	e := start(t)
	addr, err := e.m.StartProxy("127.0.0.1:0", []string{"pypi.org"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n")
	status, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if !strings.Contains(status, "403") {
		t.Fatalf("a connection from the host itself: %q", status)
	}

	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "talker", Network: true})
	e.m.recordNet(proxy.Decision{Sandbox: sb.ID, Method: "CONNECT", Host: "pypi.org", Port: 443, Allowed: true, Addr: "151.101.0.223"})
	e.m.recordNet(proxy.Decision{Sandbox: sb.ID, Method: "CONNECT", Host: "example.com", Port: 443, Reason: "not on the allowlist"})

	all, err := e.c.Audit(tctx(t), "", 100)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, a := range all {
		if a.Action == "net.connect" {
			lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s", a.SandboxID, a.Actor, a.Detail, a.Outcome, a.Error))
		}
	}
	want := []string{ // newest first
		"talker|sandbox|CONNECT example.com:443|denied|not on the allowlist",
		"talker|sandbox|CONNECT pypi.org:443 → 151.101.0.223|allowed|",
		"|unknown 127.0.0.1|a connection from 127.0.0.1, refused before reading its request|denied|not from a sandbox",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if v, err := e.c.VerifyAudit(tctx(t)); err != nil || !v.OK {
		t.Fatalf("the chain should still verify: %+v %v", v, err)
	}
	e.m.Close(tctx(t)) // closes the proxy too
	if c, err := net.Dial("tcp4", addr); err == nil {
		c.Close()
		t.Fatal("the proxy should be closed with the daemon")
	}
}

// Day 20: the browser image picks its rootfs, memory, network and policy in
// one word, and the proxy learns the policy with the identity.
func TestBrowserImage(t *testing.T) {
	e := start(t, func(c *Config) {
		c.Images = map[string]Image{"browser": {Rootfs: "/fake/browser", MemMiB: 2048, Network: true, Policy: proxy.PolicyBrowse}}
	})
	sb, err := e.c.Create(tctx(t), api.CreateRequest{ID: "web", Image: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	e.b.mu.Lock()
	spec := e.b.specs["web"]
	e.b.mu.Unlock()
	if spec.Rootfs != "/fake/browser" || spec.MemMiB != 2048 || sb.NetSlot == 0 || sb.EgressPolicy != proxy.PolicyBrowse {
		t.Fatalf("spec %+v, record %+v", spec, sb)
	}
	if c, ok := e.m.identify(netip.MustParseAddr(sb.NetAddr)); !ok || c.Policy != proxy.PolicyBrowse {
		t.Fatalf("the proxy should learn the browse policy: %+v %v", c, ok)
	}
	forks, err := e.c.Fork(tctx(t), sb.ID, api.ForkRequest{})
	if err != nil || forks[0].EgressPolicy != proxy.PolicyBrowse {
		t.Fatalf("a clone keeps its source's policy: %+v %v", forks, err)
	}
	e.m.recordNet(proxy.Decision{Sandbox: "web", Policy: proxy.PolicyBrowse, Method: "CONNECT", Host: "example.com", Port: 443, Allowed: true, Addr: "93.184.215.14"})
	all, _ := e.c.Audit(tctx(t), "web", 5)
	if len(all) == 0 || all[0].Detail != "CONNECT example.com:443 → 93.184.215.14 (browse)" {
		t.Fatalf("the audit detail should say browse: %+v", all)
	}
}

func TestPolicyAndImageValidation(t *testing.T) {
	e := start(t, func(c *Config) { c.Images = map[string]Image{"browser": {Rootfs: "/fake/browser"}} })
	for req, want := range map[*api.CreateRequest]string{
		{Image: "gpu"}:                       `unknown image "gpu" (this daemon has: browser)`,
		{Policy: "wide-open", Network: true}: `unknown egress policy "wide-open"`,
		{Policy: proxy.PolicyBrowse}:         "a browse policy needs a network",
	} {
		if _, err := e.c.Create(tctx(t), *req); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", *req, err, want)
		}
	}
	sb, err := e.c.Create(tctx(t), api.CreateRequest{Policy: proxy.PolicyAllowlist, Network: true})
	if err != nil || sb.EgressPolicy != "" {
		t.Fatalf("an explicit allowlist is the default, stored as such: %+v %v", sb, err)
	}
}

// Day 21: with the socket opened to a group, choosing a rootfs (a host
// directory the sandbox will see) stays the daemon user's alone. Another
// user asking for one is refused; a named image is fine.
func TestOnlyTheDaemonUserChoosesARootfs(t *testing.T) {
	e := start(t, func(c *Config) { c.Images = map[string]Image{"browser": {Rootfs: t.TempDir()}} })
	other := context.WithValue(tctx(t), uidKey{}, uint32(os.Getuid()+1))
	if _, err := e.m.Create(other, api.CreateRequest{ID: "peek", Rootfs: "/"}); err == nil || !strings.Contains(err.Error(), "only the user running sbxd may choose a rootfs") {
		t.Fatalf("another user choosing / as a rootfs: %v", err)
	}
	if _, err := e.m.Create(other, api.CreateRequest{ID: "fine", Image: "browser"}); err != nil {
		t.Fatalf("another user using an image: %v", err)
	}
	self := context.WithValue(tctx(t), uidKey{}, uint32(os.Getuid()))
	if _, err := e.m.Create(self, api.CreateRequest{ID: "mine", Rootfs: t.TempDir()}); err != nil {
		t.Fatalf("the daemon's own user choosing a rootfs: %v", err)
	}
}

// Day 21: versioned images. A sandbox keeps the version it was made with,
// however the -current link moves; Images reports which versions are in
// use, paused sandboxes included.
func TestVersionedImages(t *testing.T) {
	dir := t.TempDir()
	v1, v2 := filepath.Join(dir, "browser-20261020-171500"), filepath.Join(dir, "browser-20261021-101500")
	_ = os.Mkdir(v1, 0o755)
	_ = os.Mkdir(v2, 0o755)
	link := filepath.Join(dir, "browser-current")
	point := func(at string) {
		_ = os.Remove(link)
		if err := os.Symlink(filepath.Base(at), link); err != nil {
			t.Fatal(err)
		}
	}
	point(v1)
	e := start(t, func(c *Config) {
		c.Images = map[string]Image{"browser": {Rootfs: link, MemMiB: 2048, Network: true, Policy: proxy.PolicyBrowse}}
	})
	ctx := tctx(t)
	a, err := e.c.Create(ctx, api.CreateRequest{ID: "old", Image: "browser"})
	if err != nil || a.Rootfs != v1 {
		t.Fatalf("made on version 1: %q %v", a.Rootfs, err)
	}
	point(v2)
	b, _ := e.c.Create(ctx, api.CreateRequest{ID: "new", Image: "browser"})
	if b.Rootfs != v2 {
		t.Fatalf("made after the switch: %q, want version 2", b.Rootfs)
	}
	if _, err := e.c.Checkpoint(ctx, a.ID, api.CheckpointRequest{}); err != nil {
		t.Fatal(err)
	}
	show := func() string {
		imgs, err := e.c.Images(ctx)
		if err != nil || len(imgs) != 1 {
			t.Fatalf("images: %+v %v", imgs, err)
		}
		var parts []string
		for _, v := range imgs[0].Versions {
			parts = append(parts, fmt.Sprintf("%s current=%v sandboxes=%d paused=%d", filepath.Base(v.Path), v.Current, v.Sandboxes, v.Paused))
		}
		return strings.Join(parts, "; ")
	}
	if got, want := show(), "browser-20261020-171500 current=false sandboxes=1 paused=1; browser-20261021-101500 current=true sandboxes=1 paused=0"; got != want {
		t.Fatalf("images:\n got %s\nwant %s", got, want)
	}
	if r, err := e.c.Resume(ctx, a.ID, ""); err != nil || r.Rootfs != v1 {
		t.Fatalf("the paused sandbox resumes on its own version: %q %v", r.Rootfs, err)
	}
	_, _ = e.c.Destroy(ctx, a.ID)
	_, _ = e.c.Destroy(ctx, b.ID)
	if got, want := show(), "browser-20261020-171500 current=false sandboxes=0 paused=0; browser-20261021-101500 current=true sandboxes=0 paused=0"; got != want {
		t.Fatalf("after both are gone:\n got %s\nwant %s", got, want)
	}
}
