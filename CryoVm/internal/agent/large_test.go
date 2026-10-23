//go:build !race

// Moving 100 MB through race-instrumented code takes minutes, so this runs
// in plain `go test` only. Its logic is shared with the smaller transfer
// tests, which do run under -race.
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestHundredMegabyteRoundTrip is Day 4's done-when: 100 MB up and back
// down through the shipped agent binary, with matching SHA-256 on both
// sides and an independent check of the file on disk.
func TestHundredMegabyteRoundTrip(t *testing.T) {
	bin := buildAgent(t)
	l, _, _ := runAgent(t, bin)
	conn, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	const size = 100 << 20
	src := io.LimitReader(rand.New(rand.NewSource(42)), size)
	srcHash := sha256.New()
	path := filepath.Join(t.TempDir(), "big.bin")

	start := time.Now()
	up, err := conn.WriteFile(longWait(t), path, io.TeeReader(src, srcHash), WriteOptions{})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	upTook := time.Since(start)
	want := hex.EncodeToString(srcHash.Sum(nil))
	if up.Size != size || up.SHA256 != want {
		t.Fatalf("upload result %+v, want sha %s", up, want)
	}

	// Independent check: hash the file on disk ourselves.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	disk := sha256.New()
	_, _ = io.Copy(disk, f)
	f.Close()
	if got := hex.EncodeToString(disk.Sum(nil)); got != want {
		t.Fatalf("file on disk hashes to %s, want %s", got, want)
	}

	start = time.Now()
	back := sha256.New()
	down, err := conn.ReadFile(longWait(t), path, back)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	downTook := time.Since(start)
	if hex.EncodeToString(back.Sum(nil)) != want || down.SHA256 != want {
		t.Fatal("download hash differs")
	}
	mb := float64(size) / (1 << 20)
	t.Logf("100 MB: upload %s (%.0f MB/s), download %s (%.0f MB/s)",
		upTook.Round(time.Millisecond), mb/upTook.Seconds(), downTook.Round(time.Millisecond), mb/downTook.Seconds())
}
