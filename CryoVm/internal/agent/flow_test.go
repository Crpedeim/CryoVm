//go:build !race

// This test measures timing, so it doesn't run under the race detector,
// which slows everything roughly tenfold and, on a small machine, turns
// CPU starvation into noise that swamps the effect being measured. The
// transfer code is still race-checked: every other test in files_test.go,
// including the concurrent ones, runs under -race.
package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

// slowWriter accepts data slowly, like a congested disk or network.
type slowWriter struct {
	delay time.Duration
	n     int64
}

func (w *slowWriter) Write(p []byte) (int, error) {
	time.Sleep(w.delay)
	w.n += int64(len(p))
	return len(p), nil
}

type countWriter struct{ n int64 }

func (w *countWriter) Write(p []byte) (int, error) { w.n += int64(len(p)); return len(p), nil }

// TestSlowDownloadDoesNotSlowOtherStreams is the point of flow control.
//
// The kernel's socket buffer already stops a sender from racing far ahead:
// once it fills, write blocks. But that backpressure is per connection, not
// per stream. Without a window, the slow download's sender sits blocked in
// write while holding the connection's write lock, so every other stream
// (exec output, other downloads, pongs) moves at the slow consumer's pace.
//
// With the window, the slow transfer never has more than 8 chunks out, the
// host always has room to buffer them, the socket never fills, and other
// streams keep their speed. Measured while building Day 4: a 4 MB exec ran
// about 1.3x slower beside a slow download with flow control, and about 13x
// slower without it. The test allows 5x.
func TestSlowDownloadDoesNotSlowOtherStreams(t *testing.T) {
	c := connected(t)

	fastExec := func() time.Duration {
		var out countWriter
		start := time.Now()
		res, err := c.Exec(wait(t), ExecRequest{Args: []string{"head", "-c", "4000000", "/dev/zero"}, Stdout: &out})
		if err != nil || res.ExitCode != 0 || out.n != 4_000_000 {
			t.Fatalf("fast exec: %+v %v, %d bytes", res, err, out.n)
		}
		return time.Since(start)
	}
	baseline := fastExec()

	const chunks = 40
	path := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(path, randomBytes(chunks*agentproto.ChunkSize, 9), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	slow := &slowWriter{delay: 100 * time.Millisecond}
	go func() {
		_, err := c.ReadFile(context.Background(), path, slow)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond) // let the slow download get going

	beside := fastExec()
	t.Logf("4 MB exec: %s alone, %s beside a slow download (%.1fx)",
		baseline.Round(time.Millisecond), beside.Round(time.Millisecond), float64(beside)/float64(baseline))
	if beside > 5*baseline+200*time.Millisecond {
		t.Fatalf("a fast stream slowed from %s to %s: it was held to the slow download's pace", baseline, beside)
	}
	if err := <-done; err != nil || slow.n != chunks*int64(agentproto.ChunkSize) {
		t.Fatalf("slow download: %v, %d bytes", err, slow.n)
	}
}
