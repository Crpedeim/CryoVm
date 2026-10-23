// Package registry records every sandbox and its lifecycle in SQLite. Each
// state change is a compare-and-set on the current state plus an event row,
// written in one transaction: the state and its history can never disagree.
package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mattn/go-sqlite3" // also registers the "sqlite3" driver

	"github.com/Crpedeim/sbx/internal/api"
)

// The types are api's, so clients can use them without importing SQLite.
type (
	State   = api.State
	Sandbox = api.Sandbox
	Event   = api.Event
)

const (
	Creating = api.Creating
	Running  = api.Running
	Paused   = api.Paused
	Stopping = api.Stopping
	Stopped  = api.Stopped
	Failed   = api.Failed

	Checkpointing = api.Checkpointing
	Restoring     = api.Restoring
)

// transitions lists every legal move. Anything else is a bug or a race,
// and is refused.
var transitions = map[State][]State{
	Creating: {Running, Failed},
	Running:  {Checkpointing, Stopping, Failed},
	// A checkpoint ends in one of three ways: the sandbox stops and is
	// paused (the usual case), keeps running (a snapshot, or a checkpoint
	// that failed while the sandbox lived on), or is lost.
	Checkpointing: {Paused, Running, Failed},
	// A restore ends running, or back at paused if it fails: the image is
	// still there to retry from.
	Paused:    {Restoring, Stopping, Failed},
	Restoring: {Running, Paused, Failed},
	Stopping:  {Stopped, Failed},
}

// CanTransition reports whether from → to is legal.
func CanTransition(from, to State) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

var (
	ErrNotFound = errors.New("registry: sandbox not found")
	ErrExists   = errors.New("registry: sandbox already exists")
	// ErrConflict: the sandbox wasn't in the expected state, usually
	// because another request changed it first.
	ErrConflict = errors.New("registry: state conflict")
)

type Registry struct {
	db *sql.DB
}

// migrations brings a database up to date, one numbered step at a time.
// The database records how many have run in SQLite's built-in user_version
// field, so each step runs exactly once, in order, on every database,
// whether it was created today or by an older sbxd. Steps are append-only:
// never edit one that has shipped, add a new one instead.
var migrations = []string{
	// 1: the Day 5 schema. IF NOT EXISTS lets it run harmlessly on a
	// database Day 5 created before migrations existed (user_version 0).
	schemaV1,
	// 2 (Day 8): a process limit per sandbox. Existing rows get 0, meaning
	// "no limit recorded", which is true of every sandbox made before.
	`ALTER TABLE sandboxes ADD COLUMN pids_max INTEGER NOT NULL DEFAULT 0`,
	// 3 (Day 9): lifetimes, and the audit log.
	`ALTER TABLE sandboxes ADD COLUMN expires_at TEXT NOT NULL DEFAULT '';
	 ALTER TABLE sandboxes ADD COLUMN idle_timeout_s INTEGER NOT NULL DEFAULT 0;
	 CREATE TABLE audit (
		seq         INTEGER PRIMARY KEY,
		at          TEXT NOT NULL,
		sandbox_id  TEXT NOT NULL DEFAULT '',
		actor       TEXT NOT NULL,
		action      TEXT NOT NULL,
		detail      TEXT NOT NULL DEFAULT '',
		outcome     TEXT NOT NULL,
		error       TEXT NOT NULL DEFAULT '',
		duration_ms INTEGER NOT NULL DEFAULT 0,
		prev_hash   TEXT NOT NULL,
		hash        TEXT NOT NULL
	 );
	 CREATE INDEX audit_by_sandbox ON audit(sandbox_id, seq);`,
	// 4 (Day 10): checkpoint images.
	`CREATE TABLE checkpoints (
		id           TEXT PRIMARY KEY,
		sandbox_id   TEXT NOT NULL REFERENCES sandboxes(id),
		created_at   TEXT NOT NULL,
		path         TEXT NOT NULL,
		image_bytes  INTEGER NOT NULL,
		duration_ms  INTEGER NOT NULL,
		left_running INTEGER NOT NULL
	 );
	 CREATE INDEX checkpoints_by_sandbox ON checkpoints(sandbox_id, created_at);`,
	// 5 (Day 12): sandboxes paused by a daemon shutdown, to resume on start.
	`ALTER TABLE sandboxes ADD COLUMN resume_on_start INTEGER NOT NULL DEFAULT 0`,
	// 6 (Day 13): what idleness does, and sandboxes paused by it.
	`ALTER TABLE sandboxes ADD COLUMN idle_action TEXT NOT NULL DEFAULT '';
	 ALTER TABLE sandboxes ADD COLUMN wake_on_use INTEGER NOT NULL DEFAULT 0;`,
	// 7 (Day 14): where a forked sandbox came from.
	`ALTER TABLE sandboxes ADD COLUMN forked_from TEXT NOT NULL DEFAULT ''`,
	// 8 (Day 16): the network slot, from 1; 0 for none.
	`ALTER TABLE sandboxes ADD COLUMN net_slot INTEGER NOT NULL DEFAULT 0`,
	// 9 (Day 20): the egress policy: '' (the allowlist) or 'browse'.
	`ALTER TABLE sandboxes ADD COLUMN egress_policy TEXT NOT NULL DEFAULT ''`,
	// 10 (the S3 snapshot store): where each checkpoint's image is.
	`ALTER TABLE checkpoints ADD COLUMN local INTEGER NOT NULL DEFAULT 1;
	 ALTER TABLE checkpoints ADD COLUMN remote INTEGER NOT NULL DEFAULT 0;`,
}

const schemaV1 = `
CREATE TABLE IF NOT EXISTS sandboxes (
	id         TEXT PRIMARY KEY,
	backend    TEXT NOT NULL,
	state      TEXT NOT NULL,
	rootfs     TEXT NOT NULL,
	vcpus      INTEGER NOT NULL,
	mem_mib    INTEGER NOT NULL,
	error      TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
	seq        INTEGER PRIMARY KEY AUTOINCREMENT,
	sandbox_id TEXT NOT NULL REFERENCES sandboxes(id),
	from_state TEXT NOT NULL,
	to_state   TEXT NOT NULL,
	at         TEXT NOT NULL,
	detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_by_sandbox ON events(sandbox_id, seq);
`

// Open opens (creating if needed) the registry database at path.
//
// WAL journal mode lets readers proceed while a write is in progress, and
// busy_timeout makes a writer wait briefly for the lock instead of failing
// at once. One open connection keeps SQLite's single writer simple.
func Open(path string) (*Registry, error) {
	// synchronous=NORMAL (Day 23): in WAL mode a commit then survives any
	// process crash, kill -9 included, which is what sbx's crash safety is
	// about (Day 12, the snapshot store); only a power loss or OS crash can
	// drop the last commits, and the database can't be corrupted either way.
	// FULL would fsync every commit for durability across power loss, which
	// sbx doesn't offer anyway: runsc doesn't fsync checkpoint images, and a
	// power loss kills every sandbox, which reconciliation already handles.
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on&_synchronous=NORMAL", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Registry{db: db}, nil
}

// migrate runs every migration the database hasn't seen yet. Each one, and
// the version bump that records it, commit together: a crash midway leaves
// the database at the last complete step, never between.
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("registry: read schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("registry: database is at schema version %d, but this sbxd only knows %d: it was written by a newer sbxd", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("registry: migration %d: %w", i+1, err)
		}
		// PRAGMA doesn't take parameters; the value is our own integer.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("registry: migration %d: %w", i+1, err)
		}
	}
	return nil
}

// SchemaVersion reports how many migrations the database has run.
func (r *Registry) SchemaVersion() (int, error) {
	var v int
	err := r.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	return v, err
}

func (r *Registry) Close() error { return r.db.Close() }

// Times are stored as RFC 3339 text with nanoseconds, in UTC: readable in
// the sqlite3 shell, and they sort correctly as strings.
const timeFormat = time.RFC3339Nano

func now() string { return time.Now().UTC().Format(timeFormat) }

// Create records a new sandbox in state creating.
func (r *Registry) Create(ctx context.Context, s Sandbox) (Sandbox, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Sandbox{}, err
	}
	defer tx.Rollback() // a no-op after Commit
	if s.NetSlot == AllocateSlot {
		if s.NetSlot, err = freeSlot(ctx, tx); err != nil {
			return Sandbox{}, err
		}
	}
	t := now()
	_, err = tx.ExecContext(ctx,
		`INSERT INTO sandboxes (id, backend, state, rootfs, vcpus, mem_mib, pids_max, expires_at, idle_timeout_s, idle_action, forked_from, net_slot, egress_policy, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.Backend, Creating, s.Rootfs, s.VCPUs, s.MemMiB, s.PidsMax, timeText(s.ExpiresAt), s.IdleTimeoutS, s.IdleAction, s.ForkedFrom, s.NetSlot, s.EgressPolicy, t, t)
	if err != nil {
		if isConstraint(err) {
			return Sandbox{}, fmt.Errorf("%w: %s", ErrExists, s.ID)
		}
		return Sandbox{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO events (sandbox_id, from_state, to_state, at) VALUES (?, '', ?, ?)`,
		s.ID, Creating, t); err != nil {
		return Sandbox{}, err
	}
	if err := tx.Commit(); err != nil {
		return Sandbox{}, err
	}
	return r.Get(ctx, s.ID)
}

// Transition moves a sandbox from → to, only if it is currently in from.
// The UPDATE's WHERE clause is the compare-and-set: if another request
// changed the state first, no row matches and the move is refused.
func (r *Registry) Transition(ctx context.Context, id string, from, to State, detail string) (Sandbox, error) {
	if !CanTransition(from, to) {
		return Sandbox{}, fmt.Errorf("registry: illegal transition %s → %s", from, to)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Sandbox{}, err
	}
	defer tx.Rollback()
	t := now()
	errText := ""
	if to == Failed {
		errText = detail
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE sandboxes SET state = ?, updated_at = ?, error = CASE WHEN ? != '' THEN ? ELSE error END
		 WHERE id = ? AND state = ?`,
		to, t, errText, errText, id, from)
	if err != nil {
		return Sandbox{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var cur State
		err := tx.QueryRowContext(ctx, `SELECT state FROM sandboxes WHERE id = ?`, id).Scan(&cur)
		if errors.Is(err, sql.ErrNoRows) {
			return Sandbox{}, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return Sandbox{}, fmt.Errorf("%w: %s is %s, not %s", ErrConflict, id, cur, from)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO events (sandbox_id, from_state, to_state, at, detail) VALUES (?, ?, ?, ?, ?)`,
		id, from, to, t, detail); err != nil {
		return Sandbox{}, err
	}
	if err := tx.Commit(); err != nil {
		return Sandbox{}, err
	}
	return r.Get(ctx, id)
}

// Note records something that happened to a sandbox without changing its
// state, such as the memory guard killing a process inside it. It appears
// in the history with the same state on both sides.
func (r *Registry) Note(ctx context.Context, id, detail string) error {
	s, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		`INSERT INTO events (sandbox_id, from_state, to_state, at, detail) VALUES (?, ?, ?, ?, ?)`,
		id, s.State, s.State, now(), detail)
	return err
}

func scanSandbox(row interface{ Scan(...any) error }) (Sandbox, error) {
	var s Sandbox
	var created, updated string
	var expires string
	var resume, wake int
	err := row.Scan(&s.ID, &s.Backend, &s.State, &s.Rootfs, &s.VCPUs, &s.MemMiB, &s.PidsMax, &s.Error, &created, &updated, &expires, &s.IdleTimeoutS, &resume, &s.IdleAction, &wake, &s.ForkedFrom, &s.NetSlot, &s.EgressPolicy)
	if err != nil {
		return Sandbox{}, err
	}
	if expires != "" {
		if t, err := time.Parse(timeFormat, expires); err == nil {
			s.ExpiresAt = &t
		}
	}
	s.ResumeOnStart = resume == 1
	s.WakeOnUse = wake == 1
	s.CreatedAt, _ = time.Parse(timeFormat, created)
	s.UpdatedAt, _ = time.Parse(timeFormat, updated)
	return s, nil
}

const sandboxCols = `id, backend, state, rootfs, vcpus, mem_mib, pids_max, error, created_at, updated_at, expires_at, idle_timeout_s, resume_on_start, idle_action, wake_on_use, forked_from, net_slot, egress_policy`

// SetWakeOnUse marks (or unmarks) a sandbox as paused by idleness: using it
// resumes it.
func (r *Registry) SetWakeOnUse(ctx context.Context, id string, on bool) error {
	return r.setFlag(ctx, id, "wake_on_use", on)
}

// setFlag sets one of the boolean columns. The column name is never user
// input: only the two callers here choose it.
func (r *Registry) setFlag(ctx context.Context, id, column string, on bool) error {
	v := 0
	if on {
		v = 1
	}
	res, err := r.db.ExecContext(ctx, `UPDATE sandboxes SET `+column+` = ?, updated_at = ? WHERE id = ?`, v, now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

// SetResumeOnStart marks (or unmarks) a sandbox for the next daemon to
// resume.
func (r *Registry) SetResumeOnStart(ctx context.Context, id string, on bool) error {
	return r.setFlag(ctx, id, "resume_on_start", on)
}

// timeText stores an optional time: "" for none, RFC 3339 otherwise.
func timeText(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(timeFormat)
}

// SetExpiry moves a sandbox's deadline.
func (r *Registry) SetExpiry(ctx context.Context, id string, at time.Time) (Sandbox, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE sandboxes SET expires_at = ?, updated_at = ? WHERE id = ?`, timeText(&at), now(), id)
	if err != nil {
		return Sandbox{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Sandbox{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return r.Get(ctx, id)
}

func (r *Registry) Get(ctx context.Context, id string) (Sandbox, error) {
	s, err := scanSandbox(r.db.QueryRowContext(ctx, `SELECT `+sandboxCols+` FROM sandboxes WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Sandbox{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return s, err
}

// List returns sandboxes, newest first. With live set, terminal ones are
// left out.
func (r *Registry) List(ctx context.Context, live bool) ([]Sandbox, error) {
	q := `SELECT ` + sandboxCols + ` FROM sandboxes`
	if live {
		q += ` WHERE state NOT IN ('stopped', 'failed')`
	}
	q += ` ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Sandbox{}
	for rows.Next() {
		s, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Events returns a sandbox's state history, oldest first.
func (r *Registry) Events(ctx context.Context, id string) ([]Event, error) {
	if _, err := r.Get(ctx, id); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT seq, sandbox_id, from_state, to_state, at, detail FROM events WHERE sandbox_id = ? ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var at string
		if err := rows.Scan(&e.Seq, &e.SandboxID, &e.From, &e.To, &at, &e.Detail); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(timeFormat, at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// isConstraint reports a uniqueness violation, by the driver's error code
// rather than by matching error text, which can change between versions.
func isConstraint(err error) bool {
	var se sqlite3.Error
	return errors.As(err, &se) && se.Code == sqlite3.ErrConstraint
}

// AllocateSlot, as a new sandbox's NetSlot, asks Create for a free network
// slot. NetSlots is how many there are: slots run from 1 to NetSlots-1.
const (
	AllocateSlot = -1
	NetSlots     = 1 << 14
)

// freeSlot finds the lowest slot no live sandbox holds, inside Create's
// transaction. The registry has one connection, so two creates can't both
// find the same slot free. A paused sandbox keeps its slot, so its address
// stays the same across a pause; only stopped and failed ones give it up.
func freeSlot(ctx context.Context, tx *sql.Tx) (int, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT net_slot FROM sandboxes WHERE net_slot > 0 AND state NOT IN (?, ?) ORDER BY net_slot`, Stopped, Failed)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	want := 1
	for rows.Next() {
		var used int
		if err := rows.Scan(&used); err != nil {
			return 0, err
		}
		if used > want {
			break // a gap: want is free
		}
		want = used + 1
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if want >= NetSlots {
		return 0, fmt.Errorf("%w: all %d network slots are in use", ErrConflict, NetSlots-1)
	}
	return want, nil
}

// BySlot finds the live sandbox holding a network slot (Day 18: the proxy's
// identity lookup). Stopped and failed sandboxes have given theirs up.
func (r *Registry) BySlot(ctx context.Context, slot int) (Sandbox, error) {
	var id string
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM sandboxes WHERE net_slot = ? AND state NOT IN (?, ?)`, slot, Stopped, Failed).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Sandbox{}, fmt.Errorf("%w: no live sandbox in slot %d", ErrNotFound, slot)
	}
	if err != nil {
		return Sandbox{}, err
	}
	return r.Get(ctx, id)
}
