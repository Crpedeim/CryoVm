package guest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

// job is a background process. Like a shell session, it belongs to the
// agent rather than to any connection.
type job struct {
	id      string
	args    []string
	pid     int
	started time.Time
	logs    *logStore

	mu     sync.Mutex
	exited bool
	ended  time.Time
	exit   agentproto.Exit
	done   chan struct{} // closed when the process has exited
}

func (j *job) info() agentproto.ProcInfo {
	j.mu.Lock()
	defer j.mu.Unlock()
	pi := agentproto.ProcInfo{
		ID: j.id, Args: j.args, PID: j.pid, Running: !j.exited, ExitCode: -1,
		Started: j.started, LogBytes: j.logs.total(),
	}
	if j.exited {
		pi.ExitCode, pi.Signal, pi.Ended = j.exit.Code, j.exit.Signal, j.ended
	}
	return pi
}

func (j *job) isExited() (bool, time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.exited, j.ended
}

type jobTable struct {
	mu      sync.Mutex
	m       map[string]*job
	procs   *procTable
	dir     string
	fileCap int64
}

func newJobTable(procs *procTable, dir string, fileCap int64) *jobTable {
	if dir == "" {
		dir = "/var/log/sbx"
	}
	if fileCap <= 0 {
		fileCap = 8 << 20
	}
	return &jobTable{m: map[string]*job{}, procs: procs, dir: dir, fileCap: fileCap}
}

var (
	errNoCommand  = errors.New("no command given")
	errBadSignal  = errors.New("signal must be between 1 and 64")
	errNoJob      = errors.New("no such process")
	errJobRunning = errors.New("process is still running")
	errJobExited  = errors.New("process has already exited")
)

func newJobID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "p-" + hex.EncodeToString(b)
}

// start launches a background process. stdout and stderr share one pipe,
// so the log keeps their relative order exactly as the program wrote them.
// It gets its own process group, so a signal reaches everything it starts.
func (t *jobTable) start(req agentproto.ProcStart) (*job, error) {
	if len(req.Args) == 0 {
		return nil, errNoCommand
	}
	path, err := exec.LookPath(req.Args[0])
	if err != nil {
		return nil, err
	}
	id := newJobID()
	logs, err := newLogStore(filepath.Join(t.dir, id), t.fileCap)
	if err != nil {
		return nil, err
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		logs.remove()
		return nil, err
	}
	defer devnull.Close()
	r, w, err := os.Pipe()
	if err != nil {
		logs.remove()
		return nil, err
	}
	attr := &os.ProcAttr{
		Dir:   req.Dir,
		Env:   mergeEnv(os.Environ(), req.Env),
		Files: []*os.File{devnull, w, w},
		Sys:   &syscall.SysProcAttr{Setpgid: true},
	}
	pid, status, err := t.procs.start(path, req.Args, attr)
	w.Close() // only the process holds the write end now (Day 3's EOF rule)
	if err != nil {
		r.Close()
		logs.remove()
		return nil, err
	}
	j := &job{id: id, args: req.Args, pid: pid, started: time.Now(), logs: logs, done: make(chan struct{})}

	// The pump copies output to the log until every writer has closed the
	// pipe: the process, and anything it started that kept the pipe open.
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				_, _ = logs.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		r.Close()
		logs.finish()
	}()
	go func() {
		ws := <-status
		ended := time.Now()
		// The exit status and the last output travel separate paths: the
		// status arrives here, while the pump may still be copying the
		// final bytes. Declare the process exited only once its output has
		// drained, so its exit info (LogBytes above all) is final. A child
		// that keeps the pipe open can't hold this up for more than
		// drainDelay (Day 3).
		select {
		case <-pumpDone:
		case <-time.After(drainDelay):
		}
		e := agentproto.Exit{Code: -1}
		switch {
		case ws.Exited():
			e.Code = ws.ExitStatus()
		case ws.Signaled():
			e.Signal = ws.Signal().String()
		}
		j.mu.Lock()
		j.exited, j.ended, j.exit = true, ended, e
		j.mu.Unlock()
		close(j.done)
	}()

	t.mu.Lock()
	t.m[id] = j
	t.mu.Unlock()
	return j, nil
}

func (t *jobTable) get(id string) (*job, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if j := t.m[id]; j != nil {
		return j, nil
	}
	return nil, errNoJob
}

func (t *jobTable) list() agentproto.ProcList {
	t.mu.Lock()
	all := make([]*job, 0, len(t.m))
	for _, j := range t.m {
		all = append(all, j)
	}
	t.mu.Unlock()
	sort.Slice(all, func(a, b int) bool { return all[a].started.Before(all[b].started) })
	out := agentproto.ProcList{Processes: []agentproto.ProcInfo{}}
	for _, j := range all {
		out.Processes = append(out.Processes, j.info())
	}
	return out
}

// signal sends sig to the process's whole group (Day 3).
func (t *jobTable) signal(id string, sig int) error {
	j, err := t.get(id)
	if err != nil {
		return err
	}
	if sig < 1 || sig > 64 {
		return errBadSignal
	}
	if exited, _ := j.isExited(); exited {
		return errJobExited
	}
	if j.pid <= 1 {
		return errors.New("refusing to signal pid <= 1")
	}
	return syscall.Kill(-j.pid, syscall.Signal(sig))
}

// remove forgets an exited process and deletes its logs.
func (t *jobTable) remove(id string) error {
	t.mu.Lock()
	j := t.m[id]
	if j == nil {
		t.mu.Unlock()
		return errNoJob
	}
	if exited, _ := j.isExited(); !exited {
		t.mu.Unlock()
		return errJobRunning
	}
	delete(t.m, id)
	t.mu.Unlock()
	return j.logs.remove()
}

// closeAll stops every running process when the agent shuts down: SIGTERM
// to each group, then SIGKILL for whatever is left after two seconds.
func (t *jobTable) closeAll() {
	t.mu.Lock()
	var running []*job
	for _, j := range t.m {
		if exited, _ := j.isExited(); !exited {
			running = append(running, j)
		}
	}
	t.mu.Unlock()
	for _, j := range running {
		if j.pid > 1 {
			_ = syscall.Kill(-j.pid, syscall.SIGTERM)
		}
	}
	deadline := time.After(2 * time.Second)
	for _, j := range running {
		select {
		case <-j.done:
		case <-deadline:
			if j.pid > 1 {
				_ = syscall.Kill(-j.pid, syscall.SIGKILL)
			}
			<-j.done
		}
	}
}

// jobErr turns a job error into an error frame.
func jobErr(w *frameWriter, id uint64, err error) {
	switch {
	case errors.Is(err, errNoJob), errors.Is(err, exec.ErrNotFound):
		sendErr(w, id, agentproto.CodeNotFound, err.Error())
	case errors.Is(err, errNoCommand), errors.Is(err, errBadSignal):
		sendErr(w, id, agentproto.CodeInvalid, err.Error())
	case errors.Is(err, errJobRunning), errors.Is(err, errJobExited):
		sendErr(w, id, agentproto.CodeConflict, err.Error())
	default:
		sendErrFrom(w, id, err)
	}
}

// runLogs streams a process's log from req.Offset, under the same credit
// window as a download. With Follow, it waits for new output and ends only
// once the process has exited and its output has drained: either the pipe
// closed, or drainDelay passed (a leftover child can hold the pipe open,
// as in Day 3).
func runLogs(ctx context.Context, id uint64, req agentproto.ProcLogs, acks <-chan agentproto.Message, w *frameWriter, t *jobTable) {
	j, err := t.get(req.ID)
	if err != nil {
		jobErr(w, id, err)
		return
	}
	off := req.Offset
	if off < 0 {
		off = 0
	}
	var skippedTotal int64
	inflight := 0
	for {
		for inflight >= agentproto.Window {
			select {
			case <-acks:
				inflight--
			case <-ctx.Done():
				sendErr(w, id, agentproto.CodeCanceled, "logs cancelled")
				return
			}
		}
		changed := j.logs.wait() // before reading: no append can slip between
		data, next, skipped, err := j.logs.read(off, agentproto.ChunkSize)
		if err != nil {
			sendErrFrom(w, id, err)
			return
		}
		skippedTotal += skipped
		if len(data) > 0 {
			m, _ := agentproto.New(agentproto.TypeChunk, id, agentproto.Chunk{Data: data})
			if w.send(m) != nil {
				return
			}
			inflight++
			off = next
			continue
		}
		off = next
		if !req.Follow {
			break
		}
		exited, ended := j.isExited()
		if exited && (j.logs.isFinished() || time.Since(ended) >= drainDelay) {
			break
		}
		var drain <-chan time.Time
		if exited {
			drain = time.After(drainDelay - time.Since(ended))
		}
		select {
		case <-changed:
		case <-j.done:
		case <-drain:
		case <-acks:
			inflight--
		case <-ctx.Done():
			sendErr(w, id, agentproto.CodeCanceled, "logs cancelled")
			return
		}
	}
	exited, _ := j.isExited()
	end, _ := agentproto.New(agentproto.TypeLogsEnd, id, agentproto.LogsEnd{Next: off, Skipped: skippedTotal, Exited: exited})
	_ = w.send(end)
}
