package daemon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/netns"
	"github.com/Crpedeim/sbx/internal/proxy"
)

// StartProxy starts the egress proxy (Day 18) on addr, allowing the names
// in allow, and returns the address it listens on. Close stops it.
//
// It listens on the host, so it must never serve anyone but a sandbox: the
// proxy refuses any connection whose source address isn't a live sandbox's
// (identify), and records that refusal too.
func (m *Manager) StartProxy(addr string, allow []string) (string, error) {
	p, err := proxy.New(proxy.Config{
		Allow: allow, Identify: m.identify, Record: m.recordNet, Hold: m.Hold, Logf: m.cfg.Logf,
	})
	if err != nil {
		return "", err
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return "", fmt.Errorf("egress proxy: %w", err)
	}
	m.mu.Lock()
	m.proxy = p
	m.mu.Unlock()
	go func() {
		if err := p.Serve(ln); err != nil {
			m.cfg.Logf("egress proxy stopped: %v", err)
		}
	}()
	return ln.Addr().String(), nil
}

// identify maps a source address to the sandbox in that slot: the only way
// the proxy learns who is asking. Nothing the sandbox sends is consulted.
func (m *Manager) identify(a netip.Addr) (proxy.Client, bool) {
	slot, ok := netns.SlotOf(a)
	if !ok {
		return proxy.Client{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec, err := m.reg.BySlot(ctx, slot)
	if err != nil {
		return proxy.Client{}, false
	}
	return proxy.Client{Sandbox: rec.ID, Policy: rec.EgressPolicy}, true
}

// recordNet writes one proxy decision to the audit chain (Day 9): the
// sandbox is the actor, so network activity is as tamper-evident as
// everything else it does.
func (m *Manager) recordNet(d proxy.Decision) {
	target := fmt.Sprintf("%s %s:%d", d.Method, d.Host, d.Port)
	if d.Addr != "" {
		target += " → " + d.Addr
	}
	if d.Policy == proxy.PolicyBrowse {
		target += " (browse)"
	}
	if d.Host == "" {
		// Refused before its request was read: an outsider's input is never
		// parsed, so there's no destination to record, only who it was.
		target = "a connection from " + d.Source.String() + ", refused before reading its request"
	}
	e := api.AuditEntry{
		At: time.Now(), SandboxID: d.Sandbox, Actor: "sandbox", Action: "net.connect",
		Detail: truncate(target, 512), Outcome: "allowed", Error: truncate(d.Reason, 512),
	}
	if !d.Allowed {
		e.Outcome = "denied"
		m.cfg.Logf("%s: egress denied: %s (%s)", orUnknown(d.Sandbox), target, d.Reason)
	}
	if d.Sandbox == "" {
		e.Actor = "unknown " + d.Source.String()
	}
	if _, err := m.reg.Audit(context.Background(), e); err != nil {
		m.cfg.Logf("audit net.connect: %v", err)
	}
}

func orUnknown(id string) string {
	if id == "" {
		return "(not a sandbox)"
	}
	return id
}
