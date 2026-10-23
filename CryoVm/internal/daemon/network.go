package daemon

import (
	"context"
	"fmt"

	"github.com/Crpedeim/sbx/internal/netns"
	"github.com/Crpedeim/sbx/internal/registry"
)

// Networker builds and removes sandboxes' networks (Day 16). The real one
// is the netns package; tests, which run without root, use a stand-in.
type Networker interface {
	PrepareHost(ctx context.Context) error
	Setup(ctx context.Context, id string, slot int) error
	Teardown(ctx context.Context, id string, slot int) error
	Exists(id string) bool
	Owners() []string
	Path(id string) string
	Refresh(ctx context.Context, id string) error
	InsideState(ctx context.Context, id string) string
}

// hostNetwork is the real thing, with the daemon's egress policy (Day 17).
type hostNetwork struct{ policy netns.Policy }

func (h hostNetwork) PrepareHost(ctx context.Context) error { return netns.PrepareHost(ctx, h.policy) }
func (h hostNetwork) Setup(ctx context.Context, id string, slot int) error {
	return netns.Setup(ctx, id, slot, h.policy)
}
func (hostNetwork) Teardown(ctx context.Context, id string, slot int) error {
	return netns.Teardown(ctx, id, slot)
}
func (hostNetwork) Exists(id string) bool { return netns.Exists(id) }
func (hostNetwork) Owners() []string      { return netns.Owners() }
func (hostNetwork) Path(id string) string { return netns.Path(id) }
func (hostNetwork) Refresh(ctx context.Context, id string) error {
	return netns.Refresh(ctx, id)
}
func (hostNetwork) InsideState(ctx context.Context, id string) string {
	return netns.InsideState(ctx, id)
}

// setupNetwork prepares the host the first time any sandbox asks for a
// network (forwarding, the host's NAT), then the sandbox's own namespaces.
func (m *Manager) setupNetwork(ctx context.Context, id string, slot int) error {
	m.netOnce.Do(func() { m.netErr = m.cfg.Net.PrepareHost(ctx) })
	if m.netErr != nil {
		return fmt.Errorf("preparing the host for sandbox networks: %w", m.netErr)
	}
	return m.cfg.Net.Setup(ctx, id, slot)
}

// teardownNetwork removes a sandbox's network, if it has one. Called before
// a sandbox is marked stopped or failed: that's what frees its slot, and the
// slot must not be handed out while its host link is still disappearing.
func (m *Manager) teardownNetwork(ctx context.Context, rec registry.Sandbox) {
	if rec.NetSlot <= 0 {
		return
	}
	if err := m.cfg.Net.Teardown(context.WithoutCancel(ctx), rec.ID, rec.NetSlot); err != nil {
		m.cfg.Logf("%s: network teardown: %v", rec.ID, err)
	}
}

// sweepNetworks removes namespaces that no live, networked sandbox claims:
// left by a crash between a teardown's steps, or by a sandbox the registry
// has since forgotten. Run at startup, after reconciliation.
func (m *Manager) sweepNetworks(ctx context.Context) {
	for _, id := range m.cfg.Net.Owners() {
		rec, err := m.reg.Get(ctx, id)
		if err == nil && !rec.State.Terminal() && rec.NetSlot > 0 {
			continue
		}
		slot := 0
		if err == nil {
			slot = rec.NetSlot
		}
		_ = m.cfg.Net.Teardown(ctx, id, slot)
		m.cfg.Logf("%s: swept a network no live sandbox claims", id)
	}
}

// netAddr is the address the host sees a networked sandbox's traffic come
// from, or "" for none.
func netAddr(slot int) string {
	if slot <= 0 {
		return ""
	}
	return netns.RouterAddr(slot).String()
}
