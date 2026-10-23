// Package store keeps checkpoint images in an S3-compatible object store
// (the S3 snapshot store), so a sandbox's image can live off this machine.
//
// One checkpoint is a set of objects:
//
//	checkpoints/<id>/files/<name>    each file of the image
//	checkpoints/<id>/manifest.json   names, sizes and SHA-256s, written LAST
//
// "Is this checkpoint in the store?" means exactly "does its manifest
// exist". The manifest goes up only after every file has, and is deleted
// before any file is; so a crash at any point leaves either a complete,
// valid checkpoint or files no manifest claims (which a sweep removes),
// never a manifest pointing at missing or half-written files.
//
// Downloads are verified against the manifest's SHA-256s here, by sbx.
// Not every server checks a body against its signed hash (SeaweedFS
// doesn't), so the store isn't trusted to return what it was given.
package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Crpedeim/sbx/internal/s3"
)

// ErrNotFound is a checkpoint the store doesn't have (no manifest).
var ErrNotFound = errors.New("store: not in the store")

type File struct {
	Name   string `json:"name"` // relative, with '/'
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Checkpoint string    `json:"checkpoint"`
	Sandbox    string    `json:"sandbox"`
	Created    time.Time `json:"created"`
	Bytes      int64     `json:"bytes"`
	Files      []File    `json:"files"`
}

// S3 is the store on an S3-compatible server.
type S3 struct {
	Client *s3.Client
	Bucket string
	Prefix string // default "checkpoints/"

	// afterPut, if set, runs after each object is stored (tests use it to
	// stop an upload partway, as a crash would).
	afterPut func(key string) error
}

func (s *S3) prefix() string {
	if s.Prefix == "" {
		return "checkpoints/"
	}
	return s.Prefix
}

func (s *S3) manifestKey(id string) string { return s.prefix() + id + "/manifest.json" }
func (s *S3) fileKey(id, name string) string {
	return s.prefix() + id + "/files/" + name
}

func validID(id string) error {
	if id == "" || strings.ContainsAny(id, "/\\") || id == "." || id == ".." {
		return fmt.Errorf("store: bad checkpoint id %q", id)
	}
	return nil
}

// safeName refuses a file name that would land outside the checkpoint's
// directory: the manifest comes from the store, and a tampered one could
// name ../../etc/cron.d/x.
func safeName(name string) error {
	if name == "" || path.IsAbs(name) || strings.Contains(name, "\\") {
		return fmt.Errorf("store: unsafe file name %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == "." || part == "" {
			return fmt.Errorf("store: unsafe file name %q", name)
		}
	}
	return nil
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// Upload stores every file under dir, then the manifest.
func (s *S3) Upload(ctx context.Context, id, sandboxID, dir string) (Manifest, error) {
	if err := validID(id); err != nil {
		return Manifest{}, err
	}
	m := Manifest{Checkpoint: id, Sandbox: sandboxID, Created: time.Now().UTC()}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("store: %s is not a regular file", p)
		}
		rel, _ := filepath.Rel(dir, p)
		name := filepath.ToSlash(rel)
		sum, size, err := hashFile(p)
		if err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		key := s.fileKey(id, name)
		if err := s.Client.Put(ctx, s.Bucket, key, f, size, sum); err != nil {
			return err
		}
		m.Files = append(m.Files, File{Name: name, Size: size, SHA256: sum})
		m.Bytes += size
		if s.afterPut != nil {
			return s.afterPut(key)
		}
		return nil
	})
	if err != nil {
		return Manifest{}, fmt.Errorf("store: uploading %s: %w", id, err)
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Name < m.Files[j].Name })
	body, _ := json.MarshalIndent(m, "", "  ")
	sum := sha256.Sum256(body)
	key := s.manifestKey(id)
	if err := s.Client.Put(ctx, s.Bucket, key, bytes.NewReader(body), int64(len(body)), hex.EncodeToString(sum[:])); err != nil {
		return Manifest{}, fmt.Errorf("store: committing %s: %w", id, err)
	}
	if s.afterPut != nil {
		if err := s.afterPut(key); err != nil {
			return Manifest{}, err
		}
	}
	return m, nil
}

// Manifest reads a checkpoint's manifest: ErrNotFound if it isn't there.
func (s *S3) Manifest(ctx context.Context, id string) (Manifest, error) {
	if err := validID(id); err != nil {
		return Manifest{}, err
	}
	rc, _, err := s.Client.Get(ctx, s.Bucket, s.manifestKey(id))
	if errors.Is(err, s3.ErrNotFound) {
		return Manifest{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return Manifest{}, err
	}
	defer rc.Close()
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(rc, 16<<20)).Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("store: %s's manifest: %w", id, err)
	}
	return m, nil
}

// Download fetches a checkpoint into dir (which must not exist yet), via
// dir.partial, verifying every file's size and SHA-256 against the manifest,
// then renaming into place: dir appears complete and verified, or not at
// all.
func (s *S3) Download(ctx context.Context, id, dir string) (Manifest, error) {
	m, err := s.Manifest(ctx, id)
	if err != nil {
		return Manifest{}, err
	}
	partial := dir + ".partial"
	_ = os.RemoveAll(partial)
	fail := func(err error) (Manifest, error) {
		_ = os.RemoveAll(partial)
		return Manifest{}, fmt.Errorf("store: downloading %s: %w", id, err)
	}
	if err := os.MkdirAll(partial, 0o700); err != nil {
		return fail(err)
	}
	for _, f := range m.Files {
		if err := safeName(f.Name); err != nil {
			return fail(err)
		}
		target := filepath.Join(partial, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fail(err)
		}
		rc, _, err := s.Client.Get(ctx, s.Bucket, s.fileKey(id, f.Name))
		if err != nil {
			return fail(err)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			rc.Close()
			return fail(err)
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(rc, f.Size+1))
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fail(err)
		}
		if got := hex.EncodeToString(h.Sum(nil)); n != f.Size || got != f.SHA256 {
			return fail(fmt.Errorf("%s is corrupt: %d bytes with SHA-256 %.12s, the manifest says %d bytes with %.12s",
				f.Name, n, got, f.Size, f.SHA256))
		}
		if strings.HasSuffix(f.Name, "sbx-agent") {
			_ = os.Chmod(target, 0o755) // the image carries its own agent (Day 11)
		}
	}
	if err := os.Rename(partial, dir); err != nil {
		return fail(err)
	}
	return m, nil
}

// Delete removes a checkpoint: the manifest first (from then on it isn't
// in the store), then its files.
func (s *S3) Delete(ctx context.Context, id string) error {
	if err := validID(id); err != nil {
		return err
	}
	if err := s.Client.Delete(ctx, s.Bucket, s.manifestKey(id)); err != nil {
		return err
	}
	objs, err := s.Client.List(ctx, s.Bucket, s.prefix()+id+"/")
	if err != nil {
		return err
	}
	for _, o := range objs {
		if err := s.Client.Delete(ctx, s.Bucket, o.Key); err != nil {
			return err
		}
	}
	return nil
}

// Contents lists the checkpoints the store holds anything for, and whether
// each has its manifest (complete) or only files (an interrupted upload or
// delete, for the sweep).
func (s *S3) Contents(ctx context.Context) (map[string]bool, error) {
	objs, err := s.Client.List(ctx, s.Bucket, s.prefix())
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, o := range objs {
		rest := strings.TrimPrefix(o.Key, s.prefix())
		id, tail, ok := strings.Cut(rest, "/")
		if !ok || id == "" {
			continue
		}
		if tail == "manifest.json" {
			out[id] = true
		} else if _, seen := out[id]; !seen {
			out[id] = false
		}
	}
	return out, nil
}
