package guest

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

// drainDelay is how long output may keep flowing after the command itself
// exits. A command that starts a background job (`server &`) hands it the
// same output pipes; without a limit, exec would wait for that job forever.
const drainDelay = time.Second

// frameWriter serializes frames from many goroutines onto one connection.
type frameWriter struct {
	mu   sync.Mutex
	conn interface{ Write([]byte) (int, error) }
}

func (w *frameWriter) send(m agentproto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return agentproto.Write(w.conn, m)
}

// runExec runs one command and streams its output as frames tagged with id.
// It always ends by sending exactly one exit frame. ctx is cancelled when the
// host sends cancel or the connection drops.
func runExec(ctx context.Context, id uint64, req agentproto.Exec, w *frameWriter, procs *procTable) {
	exit := func(e agentproto.Exit) {
		m, _ := agentproto.New(agentproto.TypeExit, id, e)
		_ = w.send(m)
	}
	if len(req.Args) == 0 {
		exit(agentproto.Exit{Code: -1, Error: "empty command"})
		return
	}
	path, err := exec.LookPath(req.Args[0])
	if err != nil {
		exit(agentproto.Exit{Code: -1, Error: err.Error()})
		return
	}

	runCtx := ctx
	if req.TimeoutMs > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	stdinR, err := stdinFile(req.Stdin)
	if err != nil {
		exit(agentproto.Exit{Code: -1, Error: "stdin: " + err.Error()})
		return
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		exit(agentproto.Exit{Code: -1, Error: err.Error()})
		return
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		outR.Close()
		outW.Close()
		exit(agentproto.Exit{Code: -1, Error: err.Error()})
		return
	}
	defer outR.Close()
	defer errR.Close()

	attr := &os.ProcAttr{
		Dir:   req.Dir,
		Env:   mergeEnv(os.Environ(), req.Env),
		Files: []*os.File{stdinR, outW, errW},
		// Its own process group, so a kill reaches everything it started.
		Sys: &syscall.SysProcAttr{Setpgid: true},
	}
	pid, status, err := procs.start(path, req.Args, attr)
	// The child has its own copies now. Ours must close, or the pipes would
	// never report end-of-file.
	stdinR.Close()
	outW.Close()
	errW.Close()
	if err != nil {
		exit(agentproto.Exit{Code: -1, Error: err.Error()})
		return
	}

	var pumps sync.WaitGroup
	pump := func(r *os.File, stream string) {
		defer pumps.Done()
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				m, _ := agentproto.New(agentproto.TypeOutput, id, agentproto.Output{Stream: stream, Data: buf[:n]})
				_ = w.send(m) // New copied the bytes, so buf can be reused
			}
			if err != nil {
				return
			}
		}
	}
	pumps.Add(2)
	go pump(outR, agentproto.StreamStdout)
	go pump(errR, agentproto.StreamStderr)

	killed := false
	var ws syscall.WaitStatus
	select {
	case ws = <-status:
	case <-runCtx.Done():
		// Negative PID: the whole process group. Never with pid <= 1:
		// kill(-1) signals every process we're allowed to, and as PID 1
		// that's the entire sandbox.
		if pid > 1 {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
		killed = true
		ws = <-status
	}

	drained := make(chan struct{})
	go func() { pumps.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(drainDelay):
		outR.Close() // unblocks the pumps' reads
		errR.Close()
		<-drained
	}

	e := agentproto.Exit{Code: -1}
	switch {
	case ws.Exited():
		e.Code = ws.ExitStatus()
	case ws.Signaled():
		e.Signal = ws.Signal().String()
	}
	if killed {
		if ctx.Err() != nil {
			e.Canceled = true
		} else {
			e.TimedOut = true
		}
	}
	exit(e)
}

func stdinFile(data []byte) (*os.File, error) {
	if len(data) == 0 {
		return os.Open(os.DevNull)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() {
		_, _ = w.Write(data) // fails harmlessly if the command exits without reading
		w.Close()
	}()
	return r, nil
}

// mergeEnv returns base with extra applied on top. Duplicated keys are a
// trap: C's getenv returns the FIRST match, so appending FOO=new after
// FOO=old would silently keep the old value.
func mergeEnv(base, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	override := map[string]bool{}
	for _, kv := range extra {
		k, _, _ := strings.Cut(kv, "=")
		override[k] = true
	}
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if !override[k] {
			out = append(out, kv)
		}
	}
	return append(out, extra...)
}
