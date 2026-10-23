package guest

import (
	"os"
	"path/filepath"
	"sync"
)

// logStore keeps a process's output on disk with a bounded size.
//
// Offsets are absolute: byte 0 is the first byte the process ever wrote,
// and an offset keeps meaning the same byte forever, even after rotation.
// When the current file would grow past fileCap, it's renamed to
// output.1.log (replacing the previous one) and a new output.log begins.
// So at most two files exist, covering a sliding window of the most
// recent history:
//
//	offset:  0 ............ prevStart ........ curStart ........ total
//	         [ rotated away ][   output.1.log   ][   output.log    ]
//
// Reading below prevStart skips to the oldest byte still kept, and says
// how many bytes were skipped.
type logStore struct {
	mu      sync.Mutex
	dir     string
	fileCap int64

	cur       *os.File
	curStart  int64 // absolute offset of output.log's first byte
	curSize   int64
	hasPrev   bool
	prevStart int64 // absolute offset of output.1.log's first byte

	finished bool          // the writer is done: no more output, ever
	changed  chan struct{} // closed (and replaced) on every append and on finish
}

func newLogStore(dir string, fileCap int64) (*logStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "output.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &logStore{dir: dir, fileCap: fileCap, cur: f, changed: make(chan struct{})}, nil
}

func (l *logStore) curPath() string  { return filepath.Join(l.dir, "output.log") }
func (l *logStore) prevPath() string { return filepath.Join(l.dir, "output.1.log") }

// broadcast wakes everyone waiting for new output. Closing a channel wakes
// every receiver at once; a fresh channel is ready for the next round.
// Callers hold l.mu.
func (l *logStore) broadcast() {
	close(l.changed)
	l.changed = make(chan struct{})
}

// Write appends output. A file never holds more than fileCap bytes: a
// write that would cross the cap fills the current file, rotates, and
// continues in the new one. (The cap is strict on purpose: the pump reads
// up to 32 KiB at a time, and a burst that size must not slip past a cap.)
func (l *logStore) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	written := 0
	defer func() {
		if written > 0 {
			l.broadcast()
		}
	}()
	for len(p) > 0 {
		if l.curSize >= l.fileCap {
			if err := l.rotate(); err != nil {
				return written, err
			}
		}
		room := l.fileCap - l.curSize
		chunk := p[:min(int64(len(p)), room)]
		n, err := l.cur.Write(chunk)
		l.curSize += int64(n)
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (l *logStore) rotate() error {
	if err := l.cur.Close(); err != nil {
		return err
	}
	if err := os.Rename(l.curPath(), l.prevPath()); err != nil {
		return err
	}
	f, err := os.OpenFile(l.curPath(), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	l.prevStart, l.hasPrev = l.curStart, true
	l.curStart += l.curSize
	l.cur, l.curSize = f, 0
	return nil
}

// total is the absolute offset one past the last byte written.
func (l *logStore) total() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.curStart + l.curSize
}

// read returns up to max bytes from absolute offset off. If off has
// rotated away, reading starts at the oldest byte kept and skipped says how
// many bytes were lost. next is the offset to continue from.
func (l *logStore) read(off int64, max int) (data []byte, next, skipped int64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	oldest := l.curStart
	if l.hasPrev {
		oldest = l.prevStart
	}
	if off < oldest {
		skipped, off = oldest-off, oldest
	}
	end := l.curStart + l.curSize
	if off >= end {
		return nil, end, skipped, nil
	}
	// Read from whichever file holds off, without crossing into the other:
	// the caller simply asks again from next.
	path, start, limit := l.curPath(), l.curStart, end
	if off < l.curStart {
		path, start, limit = l.prevPath(), l.prevStart, l.curStart
	}
	n := min(int64(max), limit-off)
	f, err := os.Open(path)
	if err != nil {
		return nil, off, skipped, err
	}
	defer f.Close()
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, off-start)
	if err != nil && got == 0 {
		return nil, off, skipped, err
	}
	return buf[:got], off + int64(got), skipped, nil
}

// wait returns a channel that's closed at the next append or at finish.
// Take it *before* reading, so an append between the read and the wait
// can't be missed.
func (l *logStore) wait() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.changed
}

func (l *logStore) finish() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.finished {
		l.finished = true
		l.cur.Close()
		l.broadcast()
	}
}

func (l *logStore) isFinished() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.finished
}

// remove deletes the log files.
func (l *logStore) remove() error {
	l.finish()
	return os.RemoveAll(l.dir)
}
