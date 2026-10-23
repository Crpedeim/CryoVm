package guest

import (
	"bytes"
	"fmt"
	"testing"
)

// readAll reads from off to the end, the way a client paging through
// chunks would.
func readAll(t *testing.T, l *logStore, off int64) (data []byte, next, skipped int64) {
	t.Helper()
	next = off
	for {
		d, n, s, err := l.read(next, 7) // small chunks: exercise boundaries
		if err != nil {
			t.Fatal(err)
		}
		skipped += s
		data = append(data, d...)
		if n == next && len(d) == 0 {
			return data, n, skipped
		}
		next = n
	}
}

func TestLogStoreOffsetsSurviveRotation(t *testing.T) {
	l, err := newLogStore(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var all bytes.Buffer
	for i := 0; i < 50; i++ {
		line := []byte(fmt.Sprintf("line %02d\n", i)) // 8 bytes each: 400 in all
		all.Write(line)
		if _, err := l.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if l.total() != 400 {
		t.Fatalf("total %d, want 400", l.total())
	}

	// Two files of at most 100 bytes are kept: the oldest 200 or so have
	// rotated away. Reading from 0 must say exactly how much was lost and
	// return exactly the bytes that follow it.
	data, next, skipped := readAll(t, l, 0)
	if next != 400 {
		t.Fatalf("next %d, want 400", next)
	}
	if skipped == 0 || int(skipped)+len(data) != 400 {
		t.Fatalf("skipped %d + read %d != 400", skipped, len(data))
	}
	if !bytes.Equal(data, all.Bytes()[skipped:]) {
		t.Fatal("bytes after the skipped region are not the bytes written there")
	}

	// An offset inside the kept window means the same byte as always.
	mid := int64(380)
	data, _, skipped = readAll(t, l, mid)
	if skipped != 0 || !bytes.Equal(data, all.Bytes()[mid:]) {
		t.Fatalf("from %d: skipped %d, %q", mid, skipped, data)
	}

	// Reading at the end returns nothing, and next stays put.
	if d, n, s, _ := l.read(400, 10); len(d) != 0 || n != 400 || s != 0 {
		t.Fatalf("at the end: %q next=%d skipped=%d", d, n, s)
	}
}

func TestLogStoreWakesWaiters(t *testing.T) {
	l, err := newLogStore(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	ch := l.wait()
	go l.Write([]byte("x"))
	<-ch // must be woken by the append
	ch = l.wait()
	go l.finish()
	<-ch // and by finish
	if !l.isFinished() {
		t.Fatal("not finished")
	}
}

// One write far larger than the cap must still respect it: the burst is
// split across rotations, and only the newest two files' worth survives.
func TestLogStoreCapIsStrictForBigWrites(t *testing.T) {
	l, err := newLogStore(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("0123456789"), 100) // 1000 bytes in one write
	if n, err := l.Write(big); err != nil || n != 1000 {
		t.Fatalf("write: %d %v", n, err)
	}
	data, next, skipped := readAll(t, l, 0)
	if next != 1000 || skipped != 800 || !bytes.Equal(data, big[800:]) {
		t.Fatalf("next=%d skipped=%d kept=%d bytes", next, skipped, len(data))
	}
}
