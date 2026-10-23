package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Crpedeim/sbx/internal/sandbox"
)

func newGeneration() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// renew gives a restored sandbox's agent its identity (Day 15): the
// sandbox's own ID (a fork's agent still thinks it's its source) and a new
// generation (any restore may be a duplicate, or a jump in time). It never
// fails the restore: an image from before agent 0.15 carries an agent that
// ignores the message (Day 11: images keep their own agent), so the call
// times out, the history says so, and the sandbox carries on as it was.
func (m *Manager) renew(ctx context.Context, id string, sb sandbox.Sandbox) {
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	gen := newGeneration()
	prev, err := sb.SetIdentity(rctx, id, gen)
	switch {
	case errors.Is(err, sandbox.ErrUnsupported):
	case err != nil:
		_ = m.reg.Note(ctx, id, fmt.Sprintf("identity not renewed (an agent older than 0.15?): %v", err))
		m.cfg.Logf("%s: identity not renewed: %v", id, err)
	case prev != id:
		_ = m.reg.Note(ctx, id, fmt.Sprintf("identity: now %s (its agent was started as %s); generation %.12s", id, prev, gen))
	default:
		_ = m.reg.Note(ctx, id, fmt.Sprintf("identity: new generation %.12s", gen))
	}
}
