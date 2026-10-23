package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/registry"
)

// ---- who is calling ----

type actorKey struct{}

// uidKey carries the caller's user ID, from the kernel (Day 21): for
// authorization, a number to compare, not a description to parse.
type uidKey struct{}

// ConnContext records who is on the other end of each API connection. On a
// Unix socket the kernel knows the connecting process's credentials
// (SO_PEERCRED): its user and PID, as of when it connected. A client can't
// forge them, unlike anything it might say about itself in a request. Set
// it as http.Server.ConnContext.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ctx
	}
	var cred *syscall.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if cred == nil {
		return ctx
	}
	ctx = context.WithValue(ctx, uidKey{}, cred.Uid)
	return context.WithValue(ctx, actorKey{}, describePeer(cred))
}

// callerUID is the connecting process's user ID, if the kernel told us.
func callerUID(ctx context.Context) (uint32, bool) {
	uid, ok := ctx.Value(uidKey{}).(uint32)
	return uid, ok
}

// describePeer turns credentials into "root (uid 0) via sbx[4242]".
func describePeer(c *syscall.Ucred) string {
	who := fmt.Sprintf("uid %d", c.Uid)
	if u, err := user.LookupId(strconv.Itoa(int(c.Uid))); err == nil {
		who = fmt.Sprintf("%s (uid %d)", u.Username, c.Uid)
	}
	comm := "?"
	if b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(c.Pid)), "comm")); err == nil {
		comm = strings.TrimSpace(string(b))
	}
	return fmt.Sprintf("%s via %s[%d]", who, comm, c.Pid)
}

// The daemon's own actions (the memory guard, expiries) are by "sbxd".
const selfActor = "sbxd"

func actorOf(ctx context.Context) string {
	if a, ok := ctx.Value(actorKey{}).(string); ok {
		return a
	}
	return "unknown"
}

func withActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

// ---- recording ----

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// quoteArgs renders a command readably: words with spaces or quotes are
// quoted, so `sh -c "rm -rf /tmp/x"` reads as what it was.
func quoteArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n\"'\\$") {
			out[i] = strconv.Quote(a)
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}

// Record writes an audit entry. Arguments are recorded, never stdin, output
// or file contents: commands can carry secrets, and the log keeps what was
// done, not the data. A failure to write the audit log is logged, not
// returned: the operation itself already happened.
func (m *Manager) Record(ctx context.Context, sandboxID, action, detail string, start time.Time, err error) {
	e := api.AuditEntry{
		At: start, SandboxID: sandboxID, Actor: actorOf(ctx), Action: action,
		Detail: truncate(detail, 1024), Outcome: "ok", DurationMs: time.Since(start).Milliseconds(),
	}
	if err != nil {
		e.Outcome, e.Error = "error", truncate(err.Error(), 512)
	}
	if _, aerr := m.reg.Audit(context.WithoutCancel(ctx), e); aerr != nil {
		m.cfg.Logf("audit %s %s: %v", sandboxID, action, aerr)
	}
}

func (m *Manager) AuditLog(ctx context.Context, sandboxID string, limit int) ([]api.AuditEntry, error) {
	return m.reg.AuditLog(ctx, sandboxID, limit)
}

func (m *Manager) VerifyAudit(ctx context.Context) (api.AuditVerify, error) {
	return m.reg.VerifyAudit(ctx)
}

// ---- activity ----

// activity is a live sandbox's use, kept in memory: writing every request
// to the database would cost more than it's worth.
type activity struct {
	last     time.Time
	inflight int // operations in progress: an attached shell, a followed log

	// The last CPU sample (Day 13): used CPU counts as activity.
	cpuAt    time.Time
	cpuUsage time.Duration
}

// Hold marks a sandbox busy until the returned function is called. Quick
// operations hold it for their duration; an attached shell or a followed
// log holds it for as long as it lasts, so a long session never counts as
// idle.
func (m *Manager) Hold(id string) func() {
	m.actMu.Lock()
	a := m.act[id]
	if a == nil {
		a = &activity{}
		m.act[id] = a
	}
	a.last = time.Now()
	a.inflight++
	m.actMu.Unlock()
	return func() {
		m.actMu.Lock()
		a.inflight--
		a.last = time.Now()
		m.actMu.Unlock()
	}
}

// idleFor says how long a sandbox has been idle, or 0 while it's busy.
func (m *Manager) idleFor(id string, now time.Time) time.Duration {
	m.actMu.Lock()
	defer m.actMu.Unlock()
	a := m.act[id]
	if a == nil || a.inflight > 0 {
		return 0
	}
	return now.Sub(a.last)
}

func (m *Manager) lastActive(id string) *time.Time {
	m.actMu.Lock()
	defer m.actMu.Unlock()
	if a := m.act[id]; a != nil {
		t := a.last
		return &t
	}
	return nil
}

// ---- lifetimes ----

// lifetimes checks every live sandbox each tick: past its deadline, or idle
// for longer than its idle timeout, it's destroyed, with the reason in its
// history and the audit log.
func (m *Manager) lifetimes(stop <-chan struct{}) {
	t := time.NewTicker(m.cfg.LifetimeEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			m.checkLifetimes(now)
		}
	}
}

func (m *Manager) checkLifetimes(now time.Time) {
	ctx := withActor(context.Background(), selfActor)
	// From the registry, not just the live ones: a paused sandbox holds a
	// checkpoint image on disk, and its deadline still applies.
	recs, err := m.reg.List(ctx, true)
	if err != nil {
		return
	}
	for _, rec := range recs {
		if rec.State != registry.Running && rec.State != registry.Paused {
			continue
		}
		id := rec.ID
		var why, action string
		if rec.State == registry.Running && rec.IdleTimeoutS > 0 {
			m.sampleCPU(ctx, id, now)
		}
		switch {
		case rec.ExpiresAt != nil && !now.Before(*rec.ExpiresAt):
			why, action = "lifetime expired (deadline "+rec.ExpiresAt.Local().Format(time.DateTime)+")", "lifetime.expire"
		// Idle timeouts apply to running sandboxes only: a paused one is
		// already idle, by definition.
		case rec.State == registry.Running && rec.IdleTimeoutS > 0 && m.idleFor(id, now) >= time.Duration(rec.IdleTimeoutS)*time.Second:
			m.idleAct(ctx, rec, m.idleFor(id, now))
			continue
		default:
			continue
		}
		start := time.Now()
		_, err = m.destroy(ctx, id, why)
		m.Record(ctx, id, action, why, start, err)
		if err == nil {
			m.cfg.Logf("%s: %s", id, why)
		}
	}
}

// Extend moves a running sandbox's deadline to ttl from now.
func (m *Manager) Extend(ctx context.Context, id string, ttl time.Duration) (registry.Sandbox, error) {
	start := time.Now()
	if ttl <= 0 {
		return registry.Sandbox{}, fmt.Errorf("%w: ttl must be positive", ErrInvalid)
	}
	rec, err := m.reg.Get(ctx, id)
	if err == nil && rec.State.Terminal() {
		err = fmt.Errorf("%w: sandbox %s is %s", registry.ErrConflict, id, rec.State)
	}
	if err == nil {
		rec, err = m.reg.SetExpiry(ctx, id, time.Now().Add(ttl))
	}
	m.Record(ctx, id, "sandbox.extend", "ttl "+ttl.String(), start, err)
	return m.withActivity(rec), err
}

// withActivity adds the in-memory last-active time to a record.
func (m *Manager) withActivity(rec registry.Sandbox) registry.Sandbox {
	if !rec.State.Terminal() {
		rec.LastActive = m.lastActive(rec.ID)
	}
	rec.NetAddr = netAddr(rec.NetSlot)
	return rec
}
