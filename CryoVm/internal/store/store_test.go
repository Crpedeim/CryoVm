package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/s3"
	"github.com/Crpedeim/sbx/internal/s3/s3test"
)

// stores returns the store tests run against: the in-memory server always,
// and a real one when SBX_S3_ENDPOINT is set.
func stores(t *testing.T) map[string]*S3 {
	t.Helper()
	fake := s3test.New()
	t.Cleanup(fake.Close)
	out := map[string]*S3{"in-memory": {Client: &s3.Client{Endpoint: fake.URL}, Bucket: "b"}}
	if ep := os.Getenv("SBX_S3_ENDPOINT"); ep != "" {
		// One bucket, a fresh prefix per test: a bucket per run exhausts a
		// small server's volumes (SeaweedFS gives each bucket its own).
		c := &s3.Client{Endpoint: ep, AccessKey: os.Getenv("SBX_S3_ACCESS_KEY"), SecretKey: os.Getenv("SBX_S3_SECRET_KEY")}
		bucket := os.Getenv("SBX_S3_BUCKET")
		if bucket == "" {
			bucket = "sbx-test"
		}
		if err := c.MakeBucket(context.Background(), bucket); err != nil {
			t.Fatal(err)
		}
		out["real"] = &S3{Client: c, Bucket: bucket, Prefix: fmt.Sprintf("test-%d/", time.Now().UnixNano())}
	}
	return out
}

// image makes a directory shaped like a checkpoint image.
func image(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{
		"checkpoint.img": bytes.Repeat([]byte("state "), 50000),
		"pages.img":      bytes.Repeat([]byte{0, 1, 2, 3}, 100000),
		"config.json":    []byte(`{"ociVersion":"1.0.2"}`),
		"sbx-agent":      []byte("#!/bin/sh\necho agent\n"),
		"extra/meta.img": []byte("nested"),
	}
	for name, b := range files {
		p := filepath.Join(dir, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func sameTree(t *testing.T, a, b string) {
	t.Helper()
	_ = filepath.Walk(a, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(a, p)
		x, _ := os.ReadFile(p)
		y, err := os.ReadFile(filepath.Join(b, rel))
		if err != nil || !bytes.Equal(x, y) {
			t.Errorf("%s differs after the round trip (%v)", rel, err)
		}
		return nil
	})
}

func TestRoundTrip(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			src := image(t)
			m, err := s.Upload(ctx, "ck-round", "sbx-a", src)
			if err != nil || len(m.Files) != 5 || m.Sandbox != "sbx-a" {
				t.Fatalf("upload: %+v %v", m, err)
			}
			if c, _ := s.Contents(ctx); !c["ck-round"] {
				t.Fatalf("contents: %v", c)
			}
			dst := filepath.Join(t.TempDir(), "ck-round")
			if _, err := s.Download(ctx, "ck-round", dst); err != nil {
				t.Fatalf("download: %v", err)
			}
			sameTree(t, src, dst)
			if fi, _ := os.Stat(filepath.Join(dst, "sbx-agent")); fi.Mode().Perm()&0o100 == 0 {
				t.Fatal("the image's agent should be executable")
			}
			if _, err := os.Stat(dst + ".partial"); !os.IsNotExist(err) {
				t.Fatal("a .partial directory was left behind")
			}
			if err := s.Delete(ctx, "ck-round"); err != nil {
				t.Fatal(err)
			}
			if c, _ := s.Contents(ctx); len(c) != 0 {
				t.Fatalf("after delete: %v", c)
			}
		})
	}
}

// The manifest is the claim, so it goes up last: no moment exists in which
// it names a file that isn't there.
func TestManifestIsWrittenLast(t *testing.T) {
	s := stores(t)["in-memory"]
	var order []string
	s.afterPut = func(key string) error { order = append(order, key); return nil }
	if _, err := s.Upload(context.Background(), "ck-order", "sbx-a", image(t)); err != nil {
		t.Fatal(err)
	}
	if len(order) != 6 || order[5] != "checkpoints/ck-order/manifest.json" {
		t.Fatalf("upload order: %v", order)
	}
}

// An upload stopped partway (a crash, a store going away) leaves files but
// no manifest: the checkpoint isn't in the store, and the sweep sees why.
func TestInterruptedUploadLeavesNoManifest(t *testing.T) {
	s := stores(t)["in-memory"]
	puts := 0
	s.afterPut = func(string) error {
		if puts++; puts == 2 {
			return errors.New("crash")
		}
		return nil
	}
	ctx := context.Background()
	if _, err := s.Upload(ctx, "ck-cut", "sbx-a", image(t)); err == nil {
		t.Fatal("the upload should fail")
	}
	if c, _ := s.Contents(ctx); c["ck-cut"] || len(c) != 1 {
		t.Fatalf("contents: %v (want ck-cut present, without a manifest)", c)
	}
	if _, err := s.Download(ctx, "ck-cut", filepath.Join(t.TempDir(), "x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("downloading an incomplete checkpoint: %v", err)
	}
}

// The store isn't trusted: a file changed or cut short is caught by the
// manifest's SHA-256, and nothing is left behind. (SeaweedFS doesn't check
// bodies against their signed hash, so this check is sbx's own.)
func TestDownloadRefusesCorruption(t *testing.T) {
	fake := s3test.New()
	defer fake.Close()
	s := &S3{Client: &s3.Client{Endpoint: fake.URL}, Bucket: "b"}
	ctx := context.Background()
	if _, err := s.Upload(ctx, "ck-bad", "sbx-a", image(t)); err != nil {
		t.Fatal(err)
	}
	key := "b/checkpoints/ck-bad/files/pages.img"
	good := fake.Objects()[key]
	for name, b := range map[string][]byte{
		"a flipped byte": append([]byte{good[0] ^ 1}, good[1:]...),
		"cut short":      good[:len(good)/2],
	} {
		fake.Set(key, b)
		dst := filepath.Join(t.TempDir(), "ck-bad")
		_, err := s.Download(ctx, "ck-bad", dst)
		if err == nil || !strings.Contains(err.Error(), "pages.img is corrupt") {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			t.Fatalf("%s: a corrupt checkpoint must not appear", name)
		}
		if _, err := os.Stat(dst + ".partial"); !os.IsNotExist(err) {
			t.Fatalf("%s: the .partial directory was left behind", name)
		}
	}
}

// A manifest is read from the store, so a tampered one could name a file
// outside the checkpoint's directory. It's refused, and nothing is written.
func TestDownloadRefusesUnsafeNames(t *testing.T) {
	fake := s3test.New()
	defer fake.Close()
	s := &S3{Client: &s3.Client{Endpoint: fake.URL}, Bucket: "b"}
	root := t.TempDir()
	for _, evil := range []string{"../escape.txt", "/etc/cron.d/x", "a/../../escape.txt", "./x"} {
		m, _ := json.Marshal(Manifest{Checkpoint: "ck-evil", Files: []File{{Name: evil, Size: 1, SHA256: "x"}}})
		fake.Set("b/checkpoints/ck-evil/manifest.json", m)
		fake.Set("b/checkpoints/ck-evil/files/"+evil, []byte("x"))
		_, err := s.Download(context.Background(), "ck-evil", filepath.Join(root, "inner", "ck-evil"))
		if err == nil || !strings.Contains(err.Error(), "unsafe file name") {
			t.Fatalf("%q: %v", evil, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "escape.txt")); !os.IsNotExist(err) {
		t.Fatal("a file was written outside the checkpoint's directory")
	}
}
