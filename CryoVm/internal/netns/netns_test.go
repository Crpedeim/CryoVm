package netns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSlotAddresses(t *testing.T) {
	for slot, want := range map[int][2]string{
		1: {"10.200.0.5", "10.200.0.6"}, 64: {"10.200.1.1", "10.200.1.2"}, MaxSlots - 1: {"10.200.255.253", "10.200.255.254"},
	} {
		if h, r := HostAddr(slot).String(), RouterAddr(slot).String(); h != want[0] || r != want[1] {
			t.Errorf("slot %d: host %s router %s, want %v", slot, h, r, want)
		}
	}
}

// needNet skips unless real namespaces can be made: root, with ip and nft.
func needNet(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network namespaces")
	}
	for _, tool := range []string{"ip", "nft", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("needs %s", tool)
		}
	}
}

func uniqueID(tag string) string { return fmt.Sprintf("t%s%d", tag, time.Now().UnixNano()%1e6) }

// world is a test's network: a stand-in proxy on the host, and a fake
// internet beyond it (a namespace reached only through the host's
// forwarding, as real internet traffic is), with a TCP listener and a
// UDP echo on port 53, standing in for a web server and a DNS server.
type world struct {
	proxy    net.Listener
	policy   Policy
	internet string // the fake internet's address
}

func newWorld(t *testing.T, egress string) *world {
	t.Helper()
	ctx := context.Background()
	proxy, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.Close() })
	go func() {
		for {
			c, err := proxy.Accept()
			if err != nil {
				return
			}
			fmt.Fprintf(c, "%s\n", c.RemoteAddr().(*net.TCPAddr).IP)
			c.Close()
		}
	}()
	w := &world{proxy: proxy, policy: Policy{Egress: egress, ProxyPort: proxy.Addr().(*net.TCPAddr).Port}, internet: "10.201.0.2"}
	if err := PrepareHost(ctx, w.policy); err != nil {
		t.Fatal(err)
	}
	// A run that was killed (Ctrl-C, a timeout) never ran its cleanup: clear
	// this fixture's own leftovers first, or every later run collides.
	if out, err := exec.Command("ip", "netns", "list").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) > 0 && strings.HasPrefix(f[0], "tinet") {
				_ = exec.Command("ip", "netns", "del", f[0]).Run()
			}
		}
	}
	_ = exec.Command("ip", "link", "del", "sbxti0").Run()
	for i := 0; i < 500 && linkExists("sbxti0"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	ns := uniqueID("inet")
	// Cleanup is registered before anything that can fail, so a failure
	// can't leak the namespace. And it waits for the kernel to finish:
	// deleting a namespace is asynchronous, so the link pair lingers a
	// moment, and the next test's link of the same name would collide (it
	// did, the first time this ran).
	t.Cleanup(func() {
		exec.Command("ip", "netns", "del", ns).Run()
		for i := 0; i < 500 && linkExists("sbxti0"); i++ {
			time.Sleep(10 * time.Millisecond)
		}
	})
	for _, s := range [][]string{
		{"ip", "netns", "add", ns},
		{"ip", "link", "add", "sbxti0", "type", "veth", "peer", "name", "sbxto0"},
		{"ip", "link", "set", "sbxto0", "netns", ns},
		{"ip", "addr", "add", "10.201.0.1/30", "dev", "sbxti0"},
		{"ip", "link", "set", "sbxti0", "up"},
		{"ip", "netns", "exec", ns, "ip", "addr", "add", w.internet + "/30", "dev", "sbxto0"},
		{"ip", "netns", "exec", ns, "ip", "link", "set", "sbxto0", "up"},
		{"ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"},
		{"ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", "10.201.0.1"},
	} {
		if out, err := exec.Command(s[0], s[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", s, err, out)
		}
	}
	for _, server := range []string{
		"import socket\ns=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', 8080)); s.listen()\nwhile True:\n    c,_=s.accept(); c.sendall(b'web\\n'); c.close()",
		"import socket\ns=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', 53))\nwhile True:\n    d,a=s.recvfrom(512); s.sendto(d,a)",
	} {
		cmd := exec.Command("ip", "netns", "exec", ns, "python3", "-c", server)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}
	time.Sleep(300 * time.Millisecond) // let the servers bind
	return w
}

// sandbox makes a sandbox's network for the test.
func (w *world) sandbox(t *testing.T, tag string, slot int) string {
	t.Helper()
	id := uniqueID(tag)
	if err := Setup(context.Background(), id, slot, w.policy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Teardown(context.Background(), id, slot) })
	return id
}

// inside runs Python in a sandbox's namespace (a plain process stands in
// for gVisor there) and returns its output, or an error if it failed.
func inside(id, code string) (string, error) {
	out, err := exec.Command("ip", "netns", "exec", "sbx-"+id, "python3", "-c", code).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func tcpProbe(host string, port int) string {
	return fmt.Sprintf("import socket; s=socket.create_connection(('%s', %d), 2); print(s.recv(64).decode().strip())", host, port)
}

const udpProbe = "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'dns?', ('10.201.0.2', 53)); print(s.recv(64).decode())"

// The design, with real packets: two sandboxes, the same address inside,
// and through the proxy path the host sees each by its own address.
func TestSameInsideAddressUniqueOutside(t *testing.T) {
	needNet(t)
	w := newWorld(t, EgressDeny)
	for _, slot := range []int{101, 102} {
		id := w.sandbox(t, "s", slot)
		self, err := inside(id, "import socket; s=socket.create_connection(('"+ProxyAddr+"', "+fmt.Sprint(w.policy.ProxyPort)+"), 2); print(s.getsockname()[0], s.recv(64).decode().strip())")
		t.Logf("sandbox in slot %d, through the proxy path: %s (its own address, then what the proxy saw)", slot, self)
		if err != nil || self != InsideAddr+" "+RouterAddr(slot).String() {
			t.Errorf("slot %d: %q %v; want %s %s", slot, self, err, InsideAddr, RouterAddr(slot))
		}
	}
}

// Day 17: with egress denied, the proxy path is all there is.
func TestDefaultDeny(t *testing.T) {
	needNet(t)
	w := newWorld(t, EgressDeny)
	a, b := w.sandbox(t, "a", 106), w.sandbox(t, "b", 107)

	if out, err := inside(a, tcpProbe(ProxyAddr, w.policy.ProxyPort)); err != nil || out != RouterAddr(106).String() {
		t.Fatalf("the proxy path must work: %q %v", out, err)
	}
	// A listener in the router itself, which nothing from the sandbox may reach.
	rl := exec.Command("ip", "netns", "exec", "sbxr-"+a, "python3", "-c",
		"import socket\ns=socket.socket(); s.bind(('0.0.0.0', 22)); s.listen()\nwhile True: s.accept()[0].close()")
	if err := rl.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { rl.Process.Kill(); rl.Wait() }()
	// A service on the host, on a port other than the proxy's.
	hostSvc, _ := net.Listen("tcp4", "0.0.0.0:0")
	defer hostSvc.Close()
	time.Sleep(200 * time.Millisecond)

	for name, code := range map[string]string{
		"the internet (TCP)":           tcpProbe(w.internet, 8080),
		"DNS (UDP to port 53)":         udpProbe,
		"the router itself":            tcpProbe(ProxyAddr, 22),
		"a host service":               tcpProbe(HostAddr(106).String(), hostSvc.Addr().(*net.TCPAddr).Port),
		"another sandbox's router":     tcpProbe(RouterAddr(107).String(), 22),
		"the host's address, past NAT": tcpProbe("10.201.0.1", 8080),
	} {
		if out, err := inside(a, code); err == nil {
			t.Errorf("%s: reachable with egress denied: %q", name, out)
		}
	}
	_ = b
}

// Egress open (Day 16's behavior, for debugging): the same probes succeed,
// which is what shows the deny test's failures are the rules and not broken
// probes. Host services stay closed either way.
func TestOpenEgress(t *testing.T) {
	needNet(t)
	w := newWorld(t, EgressOpen)
	a := w.sandbox(t, "o", 108)
	if out, err := inside(a, tcpProbe(w.internet, 8080)); err != nil || out != "web" {
		t.Errorf("open: the internet over TCP: %q %v", out, err)
	}
	if out, err := inside(a, udpProbe); err != nil || out != "dns?" {
		t.Errorf("open: UDP to port 53: %q %v", out, err)
	}
	hostSvc, _ := net.Listen("tcp4", "0.0.0.0:0")
	defer hostSvc.Close()
	if out, err := inside(a, tcpProbe(HostAddr(108).String(), hostSvc.Addr().(*net.TCPAddr).Port)); err == nil {
		t.Errorf("open egress must still not reach host services: %q", out)
	}
}

// A setup that fails partway (here: the slot's host link is taken) must
// remove what it built, and leave the slot's real owner alone.
func TestFailedSetupCleansUp(t *testing.T) {
	needNet(t)
	w := newWorld(t, EgressDeny)
	owner := w.sandbox(t, "own", 103)
	intruder := uniqueID("int")
	if err := Setup(context.Background(), intruder, 103, w.policy); err == nil {
		_ = Teardown(context.Background(), intruder, 103)
		t.Fatal("a second setup on a taken slot should fail")
	}
	if Exists(intruder) {
		t.Fatal("the failed setup left its namespaces behind")
	}
	if !Exists(owner) || exec.Command("ip", "link", "show", NamesFor(owner, 103).Host).Run() != nil {
		t.Fatal("cleaning up the failed setup damaged the slot's real owner")
	}
}

// Teardown removes everything, and waits for the kernel to finish: deleting
// a namespace is asynchronous, and before Teardown waited, this immediate
// check found the host link still there in every run.
func TestTeardownLeavesNothing(t *testing.T) {
	needNet(t)
	w := newWorld(t, EgressDeny)
	id := uniqueID("td")
	if err := Setup(context.Background(), id, 109, w.policy); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := Teardown(context.Background(), id, 109); err != nil {
		t.Fatal(err)
	}
	t.Logf("teardown, host link gone: %s", time.Since(start).Round(time.Millisecond))
	if Exists(id) || exec.Command("ip", "link", "show", NamesFor(id, 109).Host).Run() == nil {
		t.Fatal("left behind after teardown")
	}
	for _, o := range Owners() {
		if o == id {
			t.Fatal("still listed as an owner")
		}
	}
}

// What runsc does at boot (moves eth0's address into gVisor, leaving eth0
// bare; your Day 16 run confirmed it), done by hand: Refresh puts things
// back so a restore finds them, and the proxy path works again.
func TestRefreshRestoresAStrippedInterface(t *testing.T) {
	needNet(t)
	w := newWorld(t, EgressDeny)
	id := w.sandbox(t, "rf", 105)
	if err := exec.Command("ip", "netns", "exec", "sbx-"+id, "ip", "addr", "flush", "dev", "eth0").Run(); err != nil {
		t.Fatal(err)
	}
	if got := InsideState(context.Background(), id); got != "no IPv4 address" {
		t.Fatalf("after stripping: %q", got)
	}
	probe := tcpProbe(ProxyAddr, w.policy.ProxyPort)
	if out, err := inside(id, probe); err == nil {
		t.Fatalf("a stripped interface shouldn't reach anything: %s", out)
	}
	for i := 0; i < 2; i++ { // twice: Refresh must be idempotent
		if err := Refresh(context.Background(), id); err != nil {
			t.Fatalf("refresh %d: %v", i+1, err)
		}
	}
	if out, err := inside(id, probe); err != nil || out != RouterAddr(105).String() {
		t.Fatalf("after refresh, the proxy path should work: %q %v", out, err)
	}
}

func TestSlotOfReversesRouterAddr(t *testing.T) {
	for _, slot := range []int{1, 2, 63, 64, 1000, MaxSlots - 1} {
		if got, ok := SlotOf(RouterAddr(slot)); !ok || got != slot {
			t.Errorf("slot %d: SlotOf(%s) = %d %v", slot, RouterAddr(slot), got, ok)
		}
		if _, ok := SlotOf(HostAddr(slot)); ok {
			t.Errorf("slot %d: the host's end %s is not a sandbox", slot, HostAddr(slot))
		}
	}
	for _, a := range []string{"10.200.0.2", "10.201.0.6", "127.0.0.1", "10.89.0.2", "::1"} {
		if s, ok := SlotOf(netip.MustParseAddr(a)); ok {
			t.Errorf("%s: slot %d, want none", a, s)
		}
	}
}

// Day 19: the same MAC addresses in every sandbox, so a clone's restored
// neighbor cache (its gateway at GatewayMAC) is right in its own network.
func TestEverySandboxHasTheSameMACs(t *testing.T) {
	needNet(t)
	w := newWorld(t, EgressDeny)
	for _, slot := range []int{111, 112} {
		id := w.sandbox(t, "mac", slot)
		read := func(ns, dev string) string {
			out, err := exec.Command("ip", "netns", "exec", ns, "cat", "/sys/class/net/"+dev+"/address").Output()
			if err != nil {
				t.Fatal(err)
			}
			return strings.TrimSpace(string(out))
		}
		if got := read("sbx-"+id, "eth0"); got != InsideMAC {
			t.Errorf("slot %d: eth0 at %s, want %s", slot, got, InsideMAC)
		}
		if got := read("sbxr-"+id, NamesFor(id, slot).Inside); got != GatewayMAC {
			t.Errorf("slot %d: the gateway at %s, want %s", slot, got, GatewayMAC)
		}
		// And traffic still flows with them.
		if out, err := inside(id, tcpProbe(ProxyAddr, w.policy.ProxyPort)); err != nil || out != RouterAddr(slot).String() {
			t.Errorf("slot %d: the proxy path with fixed MACs: %q %v", slot, out, err)
		}
	}
}
