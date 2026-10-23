package daemon

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/netns"
)

// Identity across the whole path, for real (root only): the daemon builds a
// real sandbox network and starts the real proxy; a process in the
// sandbox's namespace (standing in for gVisor) sends CONNECTs to
// 10.89.0.1. Its router translates and forwards; the proxy sees the unique
// address, maps it back to a slot, the slot to the sandbox, and the audit
// chain names that sandbox, for an allowed and a refused destination.
func TestProxyIdentityThroughRealNamespaces(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network namespaces")
	}
	for _, tool := range []string{"ip", "nft", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("needs %s", tool)
		}
	}
	free, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	policy := netns.Policy{Egress: netns.EgressDeny, ProxyPort: port}
	e := start(t, func(c *Config) { c.Net = hostNetwork{policy}; c.ProxyPort = port })
	if _, err := e.m.StartProxy(fmt.Sprintf("0.0.0.0:%d", port), []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	sb, err := e.c.Create(tctx(t), api.CreateRequest{ID: fmt.Sprintf("pid%d", port), Network: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.c.Destroy(tctx(t), sb.ID)

	connect := func(target string) string {
		code := fmt.Sprintf("import socket; s=socket.create_connection(('%s', %d), 5); "+
			"s.sendall(b'CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n'); print(s.recv(200).decode().split()[1])",
			netns.ProxyAddr, port, target, target)
		out, err := exec.Command("ip", "netns", "exec", "sbx-"+sb.ID, "python3", "-c", code).CombinedOutput()
		if err != nil {
			t.Fatalf("CONNECT %s from inside: %v: %s", target, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	// localhost is on the list, but resolves to 127.0.0.1, not a public
	// address (Day 20): refused. example.com: not on the list, refused.
	if got := connect("localhost:443"); got != "403" {
		t.Fatalf("an allowed name resolving to loopback: %q, want 403", got)
	}
	if got := connect("example.com:443"); got != "403" {
		t.Fatalf("a name not on the list: %q, want 403", got)
	}
	entries, err := e.c.Audit(tctx(t), sb.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range entries {
		if a.Action == "net.connect" {
			got = append(got, fmt.Sprintf("%s %s %s", a.Actor, strings.Fields(a.Detail)[1], a.Outcome))
		}
	}
	want := "sandbox example.com:443 denied|sandbox localhost:443 denied"
	if strings.Join(got, "|") != want {
		t.Fatalf("the audit chain for %s: %q, want %q", sb.ID, strings.Join(got, "|"), want)
	}
	t.Logf("the proxy saw %s as %s, and recorded: %s", sb.ID, sb.NetAddr, strings.Join(got, "; "))
}
