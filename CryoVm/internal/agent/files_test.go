package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

func randomBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// leftovers lists upload temp files in dir: there must never be any after
// a transfer ends, successful or not.
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, ".sbx-upload-*"))
	return m
}

func TestRoundTripAcrossChunkBoundaries(t *testing.T) {
	c := connected(t)
	dir := t.TempDir()
	cs := agentproto.ChunkSize
	for i, size := range []int{0, 1, cs - 1, cs, cs + 1, 3*cs + 7, 5 << 20} {
		data := randomBytes(size, int64(i))
		path := filepath.Join(dir, fmt.Sprintf("f%d", i))

		wres, err := c.WriteFile(wait(t), path, bytes.NewReader(data), WriteOptions{})
		if err != nil {
			t.Fatalf("size %d: write: %v", size, err)
		}
		if wres.Size != int64(size) || wres.SHA256 != sha(data) {
			t.Fatalf("size %d: write result %+v", size, wres)
		}
		var back bytes.Buffer
		rres, err := c.ReadFile(wait(t), path, &back)
		if err != nil {
			t.Fatalf("size %d: read: %v", size, err)
		}
		if !bytes.Equal(back.Bytes(), data) || rres.SHA256 != wres.SHA256 {
			t.Fatalf("size %d: round trip changed the data", size)
		}
	}
	if l := leftovers(t, dir); len(l) > 0 {
		t.Fatalf("temp files left: %v", l)
	}
}

func TestModeMkdirsAndOverwrite(t *testing.T) {
	c := connected(t)
	path := filepath.Join(t.TempDir(), "a", "b", "run.sh")

	if _, err := c.WriteFile(wait(t), path, strings.NewReader("x"), WriteOptions{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing parent without Mkdirs: want ErrNotFound, got %v", err)
	}
	if _, err := c.WriteFile(wait(t), path, strings.NewReader("v1"), WriteOptions{Mode: 0o755, Mkdirs: true}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode: %v %v", fi.Mode(), err)
	}
	if _, err := c.WriteFile(wait(t), path, strings.NewReader("v2"), WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "v2" {
		t.Fatalf("overwrite: %q", got)
	}
}

// sendRawUpload drives the protocol by hand so a test can lie about the
// checksum, which WriteFile never does.
func sendRawUpload(t *testing.T, c *Conn, path string, data []byte, claimedSHA string) agentproto.Message {
	t.Helper()
	id, p, err := c.register(16)
	if err != nil {
		t.Fatal(err)
	}
	defer c.unregister(id, p)
	open, _ := agentproto.New(agentproto.TypeWriteOpen, id, agentproto.WriteOpen{Path: path})
	chunk, _ := agentproto.New(agentproto.TypeWriteChunk, id, agentproto.Chunk{Data: data})
	closeMsg, _ := agentproto.New(agentproto.TypeWriteClose, id, agentproto.WriteClose{Size: int64(len(data)), SHA256: claimedSHA})
	for _, m := range []agentproto.Message{open, chunk, closeMsg} {
		if err := c.send(m); err != nil {
			t.Fatal(err)
		}
	}
	for {
		select {
		case f := <-p.ch:
			if f.Type == agentproto.TypeDone || f.Type == agentproto.TypeError {
				return f
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no final frame")
		}
	}
}

func TestChecksumMismatchCommitsNothing(t *testing.T) {
	c := connected(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "important.txt")
	if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := sendRawUpload(t, c, path, []byte("corrupted in transit"), sha([]byte("something else")))
	err := fileErr("write", path, f)
	if f.Type != agentproto.TypeError || !errors.Is(err, ErrChecksum) {
		t.Fatalf("want a checksum error, got %s %v", f.Type, err)
	}
	if got, _ := os.ReadFile(path); string(got) != "original" {
		t.Fatalf("a failed upload replaced the file: %q", got)
	}
	if l := leftovers(t, dir); len(l) > 0 {
		t.Fatalf("temp files left: %v", l)
	}
}

func TestCancelledUploadLeavesNothing(t *testing.T) {
	c := connected(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.bin")

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(randomBytes(3*agentproto.ChunkSize, 1)) // then stall forever
	}()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	_, err := c.WriteFile(ctx, path, pr, WriteOptions{})
	pw.Close()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a cancelled upload created the file")
	}
	if l := leftovers(t, dir); len(l) > 0 {
		t.Fatalf("temp files left: %v", l)
	}
}

func TestErrorsAreTyped(t *testing.T) {
	c := connected(t)
	dir := t.TempDir()
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"read missing", func() error { _, e := c.ReadFile(wait(t), filepath.Join(dir, "nope"), io.Discard); return e }(), ErrNotFound},
		{"read a directory", func() error { _, e := c.ReadFile(wait(t), dir, io.Discard); return e }(), ErrIsDir},
		{"relative path", func() error { _, e := c.ReadFile(wait(t), "relative/x", io.Discard); return e }(), ErrInvalid},
		{"stat missing", func() error { _, e := c.Stat(wait(t), filepath.Join(dir, "nope")); return e }(), ErrNotFound},
		{"list a file", func() error {
			f := filepath.Join(dir, "file")
			_ = os.WriteFile(f, nil, 0o644)
			_, e := c.ListDir(wait(t), f)
			return e
		}(), ErrNotDir},
	}
	for _, tc := range cases {
		if !errors.Is(tc.err, tc.want) {
			t.Errorf("%s: want %v, got %v", tc.name, tc.want, tc.err)
		}
		var fe *FileError
		if !errors.As(tc.err, &fe) {
			t.Errorf("%s: not a *FileError: %T", tc.name, tc.err)
		}
	}
}

func TestListAndStat(t *testing.T) {
	c := connected(t)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "data.txt"), []byte("12345"), 0o640)
	_ = os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	_ = os.Symlink("data.txt", filepath.Join(dir, "link"))

	res, err := c.ListDir(wait(t), dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]agentproto.FileInfo{}
	for _, e := range res.Entries {
		got[e.Name] = e
	}
	if e := got["data.txt"]; e.Size != 5 || e.Mode != 0o640 || e.IsDir {
		t.Errorf("data.txt: %+v", e)
	}
	if e := got["sub"]; !e.IsDir {
		t.Errorf("sub: %+v", e)
	}
	if e := got["link"]; !e.IsSymlink {
		t.Errorf("link should be reported as a symlink, not followed: %+v", e)
	}
	if res.Truncated || len(res.Entries) != 3 {
		t.Errorf("entries=%d truncated=%v", len(res.Entries), res.Truncated)
	}

	fi, err := c.Stat(wait(t), filepath.Join(dir, "data.txt"))
	if err != nil || fi.Name != "data.txt" || fi.Size != 5 {
		t.Errorf("stat: %+v %v", fi, err)
	}
}

func TestListTruncatesHugeDirectories(t *testing.T) {
	c := connected(t)
	dir := t.TempDir()
	for i := 0; i < agentproto.MaxListEntries+10; i++ {
		f, err := os.Create(filepath.Join(dir, fmt.Sprintf("f%05d", i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	res, err := c.ListDir(wait(t), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Entries) != agentproto.MaxListEntries {
		t.Fatalf("entries=%d truncated=%v", len(res.Entries), res.Truncated)
	}
}

func TestConcurrentTransfers(t *testing.T) {
	c := connected(t)
	dir := t.TempDir()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := randomBytes(1<<20+i*1000, int64(100+i))
			path := filepath.Join(dir, fmt.Sprintf("c%d", i))
			if _, err := c.WriteFile(wait(t), path, bytes.NewReader(data), WriteOptions{}); err != nil {
				errs <- err
				return
			}
			var back bytes.Buffer
			if _, err := c.ReadFile(wait(t), path, &back); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(back.Bytes(), data) {
				errs <- fmt.Errorf("transfer %d: data differs", i)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
