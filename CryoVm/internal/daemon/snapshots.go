package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Crpedeim/sbx/internal/registry"
	"github.com/Crpedeim/sbx/internal/store"
)

// The S3 snapshot store, from the daemon's side.
//
// The registry is the truth about which checkpoint images exist and where.
// Every step follows one rule: write the data first, then the claim;
// remove the claim first, then the data. A crash between any two steps can
// then leave only data no claim covers (which the startup sweep removes),
// never a claim pointing at missing or half-written data.

// SnapshotStore keeps checkpoint images off this machine (internal/store's
// S3 is the real one).
type SnapshotStore interface {
	Upload(ctx context.Context, id, sandboxID, dir string) (store.Manifest, error)
	Download(ctx context.Context, id, dir string) (store.Manifest, error)
	Delete(ctx context.Context, id string) error
	Contents(ctx context.Context) (map[string]bool, error)
}

// crash marks a point between two writes. Tests set crashHook to stop the
// daemon right there, as a kill -9 would; in production it does nothing.
func (m *Manager) crash(point string) {
	if m.crashHook != nil {
		m.crashHook(point)
	}
}

// offload uploads a new checkpoint to the store, then claims it there; with
// StoreEvict, it then gives up the local copy: claim first, files second.
// Called while the sandbox is still checkpointing, so no wake can race the
// eviction. A failed upload costs nothing but the upload: the checkpoint
// stays local, and the history says so.
func (m *Manager) offload(ctx context.Context, ck registry.Checkpoint) {
	if m.cfg.Store == nil {
		return
	}
	start := time.Now()
	man, err := m.cfg.Store.Upload(ctx, ck.ID, ck.SandboxID, ck.Path)
	if err != nil {
		_ = m.reg.Note(ctx, ck.SandboxID, fmt.Sprintf("upload of %s to the store failed; it stays local: %v", ck.ID, err))
		return
	}
	m.crash("offload:after-upload")
	if err := m.reg.SetWhere(ctx, ck.ID, true, true); err != nil {
		return
	}
	m.crash("offload:after-claim")
	took := time.Since(start)
	_ = m.reg.Note(ctx, ck.SandboxID, fmt.Sprintf("uploaded %s to the store: %.1f MiB in %dms", ck.ID, float64(man.Bytes)/(1<<20), took.Milliseconds()))
	if !m.cfg.StoreEvict {
		return
	}
	if err := m.reg.SetWhere(ctx, ck.ID, false, true); err != nil {
		return
	}
	m.crash("offload:after-unclaim-local")
	_ = os.RemoveAll(ck.Path)
}

// ensureLocal makes sure a checkpoint's image is on this machine, fetching
// it from the store if not (verified, via a .partial directory), then
// claiming it locally.
func (m *Manager) ensureLocal(ctx context.Context, ck registry.Checkpoint) (registry.Checkpoint, error) {
	if ck.Local {
		if _, err := os.Stat(ck.Path); err == nil {
			return ck, nil
		}
	}
	if !ck.Remote || m.cfg.Store == nil {
		return ck, fmt.Errorf("%w: checkpoint %s's image is missing from %s", registry.ErrNotFound, ck.ID, ck.Path)
	}
	start := time.Now()
	_ = os.RemoveAll(ck.Path) // a leftover no claim covers
	man, err := m.cfg.Store.Download(ctx, ck.ID, ck.Path)
	if err != nil {
		return ck, fmt.Errorf("fetching checkpoint %s from the store: %w", ck.ID, err)
	}
	m.crash("fetch:after-download")
	if err := m.reg.SetWhere(ctx, ck.ID, true, true); err != nil {
		return ck, err
	}
	ck.Local = true
	_ = m.reg.Note(ctx, ck.SandboxID, fmt.Sprintf("fetched %s from the store: %.1f MiB in %dms", ck.ID, float64(man.Bytes)/(1<<20), time.Since(start).Milliseconds()))
	return ck, nil
}

// dropCheckpoints forgets all of a sandbox's checkpoints: the claims first,
// then the data, here and in the store.
func (m *Manager) dropCheckpoints(ctx context.Context, sandboxID string) {
	cks, _ := m.reg.Checkpoints(ctx, sandboxID)
	if err := m.reg.DeleteCheckpoints(ctx, sandboxID); err != nil {
		return // the claims stand, so the data must too
	}
	m.crash("drop:after-unclaim")
	_ = os.RemoveAll(filepath.Join(m.cfg.CheckpointDir, sandboxID))
	if m.cfg.Store != nil {
		for _, ck := range cks {
			if ck.Remote {
				_ = m.cfg.Store.Delete(ctx, ck.ID)
			}
		}
	}
}

// sweepCheckpoints runs at startup, after reconciliation. It removes data no
// claim covers (left by a crash between a write and its claim, or a claim's
// removal and its data's), and corrects claims whose data is gone, so that
// nothing is ever marked valid that isn't.
func (m *Manager) sweepCheckpoints(ctx context.Context) {
	all, err := m.reg.AllCheckpoints(ctx)
	if err != nil {
		return
	}
	byID := map[string]registry.Checkpoint{}
	for _, c := range all {
		byID[c.ID] = c
	}
	swept := 0

	// Local: every image directory must be claimed as local.
	sandboxes, _ := os.ReadDir(m.cfg.CheckpointDir)
	for _, sd := range sandboxes {
		if !sd.IsDir() {
			continue
		}
		dir := filepath.Join(m.cfg.CheckpointDir, sd.Name())
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			c, claimed := byID[e.Name()]
			if strings.HasSuffix(e.Name(), ".partial") || !claimed || !c.Local || c.SandboxID != sd.Name() {
				_ = os.RemoveAll(filepath.Join(dir, e.Name()))
				swept++
			}
		}
		if rest, _ := os.ReadDir(dir); len(rest) == 0 {
			_ = os.Remove(dir)
		}
	}

	// The store: every checkpoint there must be complete and claimed.
	var contents map[string]bool
	if m.cfg.Store != nil {
		if contents, err = m.cfg.Store.Contents(ctx); err != nil {
			m.cfg.Logf("checkpoint sweep: the store can't be listed (%v); its leftovers wait for the next start", err)
			contents = nil
		}
		for id, complete := range contents {
			if c, claimed := byID[id]; !claimed || !c.Remote || !complete {
				if err := m.cfg.Store.Delete(ctx, id); err == nil {
					swept++
				}
			}
		}
	}

	// Claims whose data is gone: correct them, and forget a checkpoint
	// that's nowhere at all.
	for _, c := range all {
		local := c.Local
		if local {
			if _, err := os.Stat(c.Path); err != nil {
				local = false
			}
		}
		remote := c.Remote
		if remote && contents != nil && !contents[c.ID] {
			remote = false
		}
		switch {
		case local == c.Local && remote == c.Remote:
		case !local && !remote:
			_ = m.reg.DeleteCheckpoint(ctx, c.ID)
			_ = m.reg.Note(ctx, c.SandboxID, fmt.Sprintf("checkpoint %s's image is gone from disk and store: forgotten", c.ID))
			m.cfg.Logf("%s: checkpoint %s is nowhere: forgotten", c.SandboxID, c.ID)
		default:
			_ = m.reg.SetWhere(ctx, c.ID, local, remote)
		}
	}
	if swept > 0 {
		m.cfg.Logf("checkpoint sweep: removed %d image(s) no claim covers", swept)
	}
}
