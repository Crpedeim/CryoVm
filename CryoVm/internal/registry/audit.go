package registry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
)

type AuditEntry = api.AuditEntry

// genesis is the "previous hash" of the first entry.
var genesis = strings.Repeat("0", 64)

// auditHash is the hash of an entry: every field that matters, plus the
// previous entry's hash. Fields are length-prefixed, so no choice of
// content can make two different entries serialize the same way (with a
// plain separator, "a|b" + "c" and "a" + "b|c" would collide).
func auditHash(e AuditEntry, at string) string {
	h := sha256.New()
	for _, f := range []string{
		e.PrevHash, strconv.FormatInt(e.Seq, 10), at, e.SandboxID, e.Actor, e.Action,
		e.Detail, e.Outcome, e.Error, strconv.FormatInt(e.DurationMs, 10),
	} {
		fmt.Fprintf(h, "%d:%s,", len(f), f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Audit appends an entry to the log and returns it with its seq and hashes.
// Seq and PrevHash come from the last entry, read in the same transaction
// as the insert; with one database connection, appends are strictly
// sequential, so the chain can't fork.
func (r *Registry) Audit(ctx context.Context, e AuditEntry) (AuditEntry, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return e, err
	}
	defer tx.Rollback()
	var last int64
	prev := genesis
	err = tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&last, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return e, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		prev = genesis
	}
	e.Seq, e.PrevHash = last+1, prev
	if e.At.IsZero() {
		e.At = time.Now()
	}
	at := e.At.UTC().Format(timeFormat)
	e.Hash = auditHash(e, at)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit (seq, at, sandbox_id, actor, action, detail, outcome, error, duration_ms, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Seq, at, e.SandboxID, e.Actor, e.Action, e.Detail, e.Outcome, e.Error, e.DurationMs, e.PrevHash, e.Hash); err != nil {
		return e, err
	}
	return e, tx.Commit()
}

// AuditLog lists entries, newest first: all of them, or one sandbox's.
func (r *Registry) AuditLog(ctx context.Context, sandboxID string, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT seq, at, sandbox_id, actor, action, detail, outcome, error, duration_ms, prev_hash, hash FROM audit`
	args := []any{}
	if sandboxID != "" {
		q += ` WHERE sandbox_id = ?`
		args = append(args, sandboxID)
	}
	q += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.Seq, &at, &e.SandboxID, &e.Actor, &e.Action, &e.Detail, &e.Outcome, &e.Error, &e.DurationMs, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(timeFormat, at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyAudit walks the whole chain, oldest first, and reports the first
// entry that doesn't check out: a gap in seq (an entry deleted), a
// PrevHash that isn't the previous Hash (an entry removed or reordered), or
// a Hash that doesn't match the entry's content (an entry edited).
//
// What it can't detect: someone with write access to the database who
// rewrites the entire chain from the edit onwards, recomputing every hash.
// That's why it reports Head: copy it somewhere outside this machine, and a
// later Head that doesn't extend it proves the history was rewritten.
func (r *Registry) VerifyAudit(ctx context.Context) (api.AuditVerify, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT seq, at, sandbox_id, actor, action, detail, outcome, error, duration_ms, prev_hash, hash FROM audit ORDER BY seq`)
	if err != nil {
		return api.AuditVerify{}, err
	}
	defer rows.Close()
	res := api.AuditVerify{OK: true, Head: genesis}
	var want int64 = 1
	prev := genesis
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.Seq, &at, &e.SandboxID, &e.Actor, &e.Action, &e.Detail, &e.Outcome, &e.Error, &e.DurationMs, &e.PrevHash, &e.Hash); err != nil {
			return res, err
		}
		fail := func(problem string) (api.AuditVerify, error) {
			res.OK, res.BrokenAt, res.Problem = false, e.Seq, problem
			return res, nil
		}
		switch {
		case e.Seq != want:
			return fail(fmt.Sprintf("entry %d is missing: the chain jumps from %d to %d", want, want-1, e.Seq))
		case e.PrevHash != prev:
			return fail("its previous-hash doesn't match the entry before it")
		case auditHash(e, at) != e.Hash:
			return fail("its content doesn't match its hash: it was edited")
		}
		prev, res.Head = e.Hash, e.Hash
		res.Entries++
		want++
	}
	return res, rows.Err()
}
