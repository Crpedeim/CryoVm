package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
)

type Checkpoint = api.Checkpoint

// AddCheckpoint records a checkpoint image.
func (r *Registry) AddCheckpoint(ctx context.Context, c Checkpoint) error {
	left := 0
	if c.LeftRunning {
		left = 1
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO checkpoints (id, sandbox_id, created_at, path, image_bytes, duration_ms, left_running, local, remote)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0)`,
		c.ID, c.SandboxID, c.CreatedAt.UTC().Format(timeFormat), c.Path, c.ImageBytes, c.DurationMs, left)
	return err
}

const checkpointCols = `id, sandbox_id, created_at, path, image_bytes, duration_ms, left_running, local, remote`

func scanCheckpoint(rows interface{ Scan(...any) error }) (Checkpoint, error) {
	var c Checkpoint
	var at string
	var left, local, remote int
	if err := rows.Scan(&c.ID, &c.SandboxID, &at, &c.Path, &c.ImageBytes, &c.DurationMs, &left, &local, &remote); err != nil {
		return c, err
	}
	c.CreatedAt, _ = time.Parse(timeFormat, at)
	c.LeftRunning, c.Local, c.Remote = left == 1, local == 1, remote == 1
	return c, nil
}

// SetWhere records where a checkpoint's image is: on local disk, in the
// object store, or both. Both flags change together, in one statement: an
// eviction moves a checkpoint from "both" to "the store only" atomically.
func (r *Registry) SetWhere(ctx context.Context, id string, local, remote bool) error {
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	res, err := r.db.ExecContext(ctx, `UPDATE checkpoints SET local = ?, remote = ? WHERE id = ?`, b(local), b(remote), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: checkpoint %s", ErrNotFound, id)
	}
	return nil
}

// DeleteCheckpoint forgets one checkpoint.
func (r *Registry) DeleteCheckpoint(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM checkpoints WHERE id = ?`, id)
	return err
}

// AllCheckpoints lists every checkpoint of every sandbox (for the sweep).
func (r *Registry) AllCheckpoints(ctx context.Context) ([]Checkpoint, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+checkpointCols+` FROM checkpoints`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		c, err := scanCheckpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Checkpoints lists a sandbox's checkpoints, newest first.
func (r *Registry) Checkpoints(ctx context.Context, sandboxID string) ([]Checkpoint, error) {
	if _, err := r.Get(ctx, sandboxID); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+checkpointCols+` FROM checkpoints WHERE sandbox_id = ? ORDER BY created_at DESC`, sandboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Checkpoint{}
	for rows.Next() {
		c, err := scanCheckpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCheckpoints forgets a sandbox's checkpoints (their images are
// removed from disk by the caller).
func (r *Registry) DeleteCheckpoints(ctx context.Context, sandboxID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM checkpoints WHERE sandbox_id = ?`, sandboxID)
	return err
}
