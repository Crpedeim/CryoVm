// Package netns gives each sandbox its own network (Day 16): a network
// namespace for the sandbox, and a small router namespace between it and
// the host.
//
//	sandbox ns sbx-<id>        router ns sbxr-<id>              host
//	eth0 10.89.0.2  ─veth─  sbg<n> 10.89.0.1                       (root namespace)
//	(the same in every          SNAT 10.89.0.2 → 10.200.x.2
//	 sandbox)                   sbr<n> 10.200.x.2  ─veth─  sbh<n> 10.200.x.1 ─► NAT ─► out
//
// Every sandbox has the same address inside, 10.89.0.2, so a restored or
// forked network stack works unchanged. Its router translates that to an
// address unique to the sandbox, 10.200.x.2, before traffic reaches the
// host: that's the source address the host, and Day 18's proxy, see. And
// when the router namespace goes, its NAT rules go with it: nothing about a
// sandbox is left in the host's own rules.
//
// Everything is done with the ip and nft commands, so every step is one a
// person can type to inspect or debug the result.
package netns

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	InsideAddr    = "10.89.0.2" // every sandbox's address, inside
	InsideGateway = "10.89.0.1" // its router

	// And the same MAC addresses in every sandbox (Day 19). The worry: a
	// restored network stack remembers which MAC its gateway was at, and a
	// clone's new router, with a random MAC, would be somewhere else. Day
	// 19's control run measured it on gVisor, and the worry didn't hold:
	// with random MACs, each clone reported its own new interface's MAC
	// (gVisor takes it from the namespace at restore) and reached its
	// gateway as fast as with fixed ones. So on gVisor these are a
	// precaution, not a necessity. They stay: harmless, they make every
	// sandbox's network identical, and a backend whose guest kernel keeps
	// its neighbor cache in restored memory would likely need them.
	// Each pair lives in its own namespaces, so identical addresses never
	// meet. "02:" marks them locally administered: no real hardware uses
	// them.
	InsideMAC    = "02:00:0a:59:00:02"
	GatewayMAC   = "02:00:0a:59:00:01"
	insidePrefix = 30

	// Host side: one /30 per sandbox, by slot, in 10.200.0.0/16.
	MaxSlots = 1 << 14

	// The host's own nftables table: NAT for every sandbox's router, and the
	// host's half of the egress rules (Day 17).
	hostTable = "sbx"

	// The egress proxy (Day 18), as every sandbox sees it: its own gateway,
	// the same in every sandbox. Its router forwards this one destination to
	// the host's end of its link, where the proxy listens.
	ProxyAddr        = InsideGateway
	DefaultProxyPort = 3128

	EgressDeny = "deny" // only the proxy (Day 17): the default
	EgressOpen = "open" // anything (Day 16's behavior), for debugging

	nsDir = "/run/netns" // where `ip netns` keeps named namespaces
)

var hostPool = netip.MustParsePrefix("10.200.0.0/16")

// Names are a sandbox's namespaces and the interfaces of its slot.
type Names struct {
	Sandbox, Router string // namespace names
	Inside          string // in the router, toward the sandbox
	Uplink          string // in the router, toward the host
	Host            string // in the host
}

func NamesFor(id string, slot int) Names {
	return Names{
		Sandbox: "sbx-" + id, Router: "sbxr-" + id,
		Inside: fmt.Sprintf("sbg%d", slot), Uplink: fmt.Sprintf("sbr%d", slot), Host: fmt.Sprintf("sbh%d", slot),
	}
}

// Path is the namespace file the sandbox's OCI spec points at.
func Path(id string) string { return filepath.Join(nsDir, "sbx-"+id) }

// HostAddr is the host's end of a slot's link; RouterAddr is the address
// the host sees the sandbox's traffic come from.
func HostAddr(slot int) netip.Addr   { return slotAddr(slot, 1) }
func RouterAddr(slot int) netip.Addr { return slotAddr(slot, 2) }

func slotAddr(slot, host int) netip.Addr {
	b := hostPool.Addr().As4()
	n := uint32(slot)*4 + uint32(host)
	b[2] += byte(n >> 8)
	b[3] = byte(n)
	return netip.AddrFrom4(b)
}

// run runs a command, returning its output in any error.
func run(ctx context.Context, name string, args ...string) error {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

// in runs a command inside a namespace.
func in(ctx context.Context, ns string, args ...string) error {
	return run(ctx, "ip", append([]string{"netns", "exec", ns}, args...)...)
}

// Policy is how sandboxes may reach the outside.
type Policy struct {
	Egress    string // EgressDeny (default) or EgressOpen
	ProxyPort int    // where the proxy listens on the host (default 3128)
}

func (p Policy) withDefaults() Policy {
	if p.Egress == "" {
		p.Egress = EgressDeny
	}
	if p.ProxyPort == 0 {
		p.ProxyPort = DefaultProxyPort
	}
	return p
}

// PrepareHost does the host-wide part: let the kernel forward packets, NAT
// what the routers send out, and the host's half of the egress rules. It's
// idempotent: the table is rebuilt from scratch, so its contents are
// exactly this. Enabling forwarding is a host-wide setting (Docker sets it
// too).
//
// The host's rules are the second layer under each router's (Setup): from
// any sandbox link, the host accepts only the proxy port (no SSH, no other
// host service), and with egress denied, forwards nothing onward. A mistake
// in one layer isn't a breach.
func PrepareHost(ctx context.Context, p Policy) error {
	p = p.withDefaults()
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("netns: enable forwarding: %w", err)
	}
	forward := `iifname "sbh*" drop`
	if p.Egress == EgressOpen {
		forward = `# egress open: forwarding allowed`
	}
	_ = run(ctx, "nft", "delete", "table", "ip", hostTable)
	rules := fmt.Sprintf(`table ip %s {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr %s oifname != "sbh*" masquerade
	}
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "sbh*" ct state established,related accept
		iifname "sbh*" tcp dport %d accept
		iifname "sbh*" drop
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		%s
	}
}
`, hostTable, hostPool, p.ProxyPort, forward)
	return nftApply(ctx, "", rules)
}

// nftApply loads a ruleset, in a namespace or (ns "") on the host.
func nftApply(ctx context.Context, ns, rules string) error {
	args := []string{"nft", "-f", "-"}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(rules)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("netns: nft rules: %w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

// Setup builds a sandbox's network: its namespace, its router namespace,
// the two links, addresses, routes and the router's NAT. On any failure it
// tears down what it built.
func Setup(ctx context.Context, id string, slot int, p Policy) (err error) {
	p = p.withDefaults()
	if slot < 0 || slot >= MaxSlots {
		return fmt.Errorf("netns: slot %d out of range", slot)
	}
	n := NamesFor(id, slot)
	// On failure, remove only what this call made. A link pair still in the
	// host's namespace (made, not yet moved) is ours only if we made it: its
	// name comes from the slot, and if the slot is taken, an identically
	// named link belongs to the sandbox that owns it. Deleting by name there
	// would cut another sandbox off (a test found exactly that).
	var madeNS []string
	var looseInHost []string // pairs we made that are still in the host namespace
	defer func() {
		if err == nil {
			return
		}
		bg := context.WithoutCancel(ctx)
		for _, link := range looseInHost {
			_ = run(bg, "ip", "link", "del", link)
		}
		for _, ns := range madeNS {
			_ = run(bg, "ip", "netns", "del", ns)
		}
	}()
	host, router := HostAddr(slot), RouterAddr(slot)
	steps := [][]string{
		{"ip", "netns", "add", n.Sandbox},
		{"ip", "netns", "add", n.Router},
		// Sandbox ↔ router. The sandbox's end is created under a unique
		// name, moved in, then renamed eth0: every sandbox's is eth0.
		{"ip", "link", "add", n.Inside + "s", "type", "veth", "peer", "name", n.Inside},
		{"ip", "link", "set", n.Inside + "s", "netns", n.Sandbox},
		{"ip", "link", "set", n.Inside, "netns", n.Router},
		{"ip", "netns", "exec", n.Sandbox, "ip", "link", "set", n.Inside + "s", "name", "eth0"},
		{"ip", "netns", "exec", n.Sandbox, "ip", "link", "set", "eth0", "address", InsideMAC},
		{"ip", "netns", "exec", n.Router, "ip", "link", "set", n.Inside, "address", GatewayMAC},
		{"ip", "netns", "exec", n.Sandbox, "ip", "addr", "add", fmt.Sprintf("%s/%d", InsideAddr, insidePrefix), "dev", "eth0"},
		{"ip", "netns", "exec", n.Sandbox, "ip", "link", "set", "eth0", "up"},
		{"ip", "netns", "exec", n.Sandbox, "ip", "link", "set", "lo", "up"},
		{"ip", "netns", "exec", n.Sandbox, "ip", "route", "add", "default", "via", InsideGateway},
		{"ip", "netns", "exec", n.Router, "ip", "addr", "add", fmt.Sprintf("%s/%d", InsideGateway, insidePrefix), "dev", n.Inside},
		{"ip", "netns", "exec", n.Router, "ip", "link", "set", n.Inside, "up"},
		{"ip", "netns", "exec", n.Router, "ip", "link", "set", "lo", "up"},
		// Router ↔ host.
		{"ip", "link", "add", n.Uplink, "type", "veth", "peer", "name", n.Host},
		{"ip", "link", "set", n.Uplink, "netns", n.Router},
		{"ip", "addr", "add", host.String() + "/30", "dev", n.Host},
		{"ip", "link", "set", n.Host, "up"},
		{"ip", "netns", "exec", n.Router, "ip", "addr", "add", router.String() + "/30", "dev", n.Uplink},
		{"ip", "netns", "exec", n.Router, "ip", "link", "set", n.Uplink, "up"},
		{"ip", "netns", "exec", n.Router, "ip", "route", "add", "default", "via", host.String()},
		{"ip", "netns", "exec", n.Router, "sysctl", "-qw", "net.ipv4.ip_forward=1"},
	}
	for _, s := range steps {
		if err := run(ctx, s[0], s[1:]...); err != nil {
			return fmt.Errorf("netns: %w", err)
		}
		switch {
		case s[1] == "netns" && s[2] == "add":
			madeNS = append(madeNS, s[3])
		case s[1] == "link" && s[2] == "add":
			looseInHost = append(looseInHost, s[3]) // made in the host namespace
		case s[1] == "link" && s[2] == "set" && len(s) > 4 && s[4] == "netns":
			// Moved into a namespace of its own: that namespace's deletion
			// now takes the pair. No longer loose.
			for i, l := range looseInHost {
				if l == s[3] || (s[3] == n.Inside && l == n.Inside+"s") {
					looseInHost = append(looseInHost[:i], looseInHost[i+1:]...)
					break
				}
			}
		}
	}
	// The router's rules, in its namespace, so they disappear with it.
	//   prerouting: the proxy's address inside (10.89.0.1:port) leads to the
	//     host's end of the link, where the proxy listens.
	//   postrouting: the shared inside address becomes this slot's unique
	//     one on the way out: the address the proxy identifies it by.
	//   forward (Day 17): with egress denied, only that proxy connection
	//     passes (and its replies); everything else, DNS included, drops.
	//   input: nothing from the sandbox may talk to the router itself.
	forward := "policy accept;"
	if p.Egress == EgressDeny {
		forward = fmt.Sprintf(`policy drop;
		ct state established,related accept
		iifname "%s" ip daddr %s tcp dport %d accept`, n.Inside, host, p.ProxyPort)
	}
	return nftApply(ctx, n.Router, fmt.Sprintf(`table ip sbx {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "%s" ip daddr %s tcp dport %d dnat to %s:%d
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "%s" ip saddr %s masquerade
	}
	chain forward {
		type filter hook forward priority filter; %s
	}
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "%s" drop
	}
}
`, n.Inside, ProxyAddr, p.ProxyPort, host, p.ProxyPort, n.Uplink, InsideAddr, forward, n.Inside))
}

// Teardown removes a sandbox's network. Deleting a namespace deletes the
// interfaces in it, and deleting one end of a veth pair deletes the other,
// so the two namespace deletions take everything, host-side link included.
// Nothing is deleted by its slot-derived name: that name might belong to
// another sandbox. It's idempotent: missing pieces are fine.
//
// The sandbox's own namespace is freed by the kernel only once nothing runs
// in it, so tear down after the sandbox has stopped.
//
// And the kernel dismantles a deleted namespace in the background: its
// interfaces vanish a moment after `ip netns del` returns (a test caught
// the host link still there). So Teardown waits until the slot's host link
// is really gone. Until it returns, the slot isn't free, so a sandbox given
// the same slot next can't collide with a link that hasn't vanished yet.
func Teardown(ctx context.Context, id string, slot int) error {
	n := NamesFor(id, slot)
	_ = run(ctx, "ip", "netns", "del", n.Sandbox)
	_ = run(ctx, "ip", "netns", "del", n.Router)
	deadline := time.Now().Add(5 * time.Second)
	for linkExists(n.Host) {
		if time.Now().After(deadline) {
			return fmt.Errorf("netns: %s's host link %s is still there 5 s after its namespaces were deleted", id, n.Host)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func linkExists(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", name))
	return err == nil
}

// Exists reports whether both of a sandbox's namespaces exist.
func Exists(id string) bool {
	for _, name := range []string{"sbx-" + id, "sbxr-" + id} {
		if _, err := os.Stat(filepath.Join(nsDir, name)); err != nil {
			return false
		}
	}
	return true
}

// Owners lists the sandbox IDs that have a namespace here, for sweeping
// ones no sandbox claims.
func Owners() []string {
	entries, _ := os.ReadDir(nsDir)
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		var id string
		switch name := e.Name(); {
		case strings.HasPrefix(name, "sbxr-"):
			id = strings.TrimPrefix(name, "sbxr-")
		case strings.HasPrefix(name, "sbx-"):
			id = strings.TrimPrefix(name, "sbx-")
		default:
			continue
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// Refresh leaves MAC addresses alone on purpose: a sandbox paused before
// Day 19 remembers its gateway at its old, random MAC, and changing it
// underneath would break exactly what fixed MACs fix. Only Setup sets them.
//
// Refresh puts the sandbox's address and default route back on its eth0,
// for a restore (Day 16 v2). At first boot, runsc with --network=sandbox
// transfers the interface's address and routes into gVisor's own network
// stack, leaving eth0 bare in the namespace. A restore sets the network up
// again by reading the namespace, so without this it finds no address and
// no route, and the restored sandbox's network is unreachable (your Day 16
// run). Idempotent: "replace" sets what's missing and leaves what's there.
func Refresh(ctx context.Context, id string) error {
	ns := "sbx-" + id
	for _, s := range [][]string{
		{"ip", "addr", "replace", fmt.Sprintf("%s/%d", InsideAddr, insidePrefix), "dev", "eth0"},
		{"ip", "link", "set", "eth0", "up"},
		{"ip", "route", "replace", "default", "via", InsideGateway},
	} {
		if err := in(ctx, ns, s...); err != nil {
			return fmt.Errorf("netns: refresh %s: %w", id, err)
		}
	}
	return nil
}

// InsideState describes what's on the sandbox's eth0 now, as the host sees
// it: for diagnosis (did runsc take the address into gVisor?).
func InsideState(ctx context.Context, id string) string {
	out, err := exec.CommandContext(ctx, "ip", "netns", "exec", "sbx-"+id, "ip", "-4", "-o", "addr", "show", "dev", "eth0").CombinedOutput()
	if err != nil {
		return "unreadable: " + strings.TrimSpace(string(out))
	}
	if s := strings.TrimSpace(string(out)); s != "" {
		return s
	}
	return "no IPv4 address"
}

// SlotOf is the reverse of RouterAddr: which slot a host-side source address
// belongs to, if any. The proxy identifies a sandbox this way (Day 18).
func SlotOf(a netip.Addr) (int, bool) {
	a = a.Unmap()
	if !a.Is4() || !hostPool.Contains(a) {
		return 0, false
	}
	b, base := a.As4(), hostPool.Addr().As4()
	off := (int(b[2])-int(base[2]))<<8 | int(b[3])
	if off%4 != 2 {
		return 0, false // a host end, or not a router address at all
	}
	slot := off / 4
	if slot < 1 || slot >= MaxSlots {
		return 0, false
	}
	return slot, true
}

// ProxyEnv is what a networked sandbox's programs need to use the proxy
// (Day 18): the same in every sandbox, so clones keep it.
func ProxyEnv(port int) []string {
	u := fmt.Sprintf("http://%s:%d", ProxyAddr, port)
	return []string{
		"HTTP_PROXY=" + u, "HTTPS_PROXY=" + u, "http_proxy=" + u, "https_proxy=" + u,
		"NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1",
	}
}
