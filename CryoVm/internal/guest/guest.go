// Package guest is the agent that runs inside a sandbox. It dials out to the
// host, introduces itself, then serves requests. If the connection drops (the
// host daemon restarts, or the sandbox is restored from a checkpoint), it
// dials again with backoff, forever, until its context is cancelled.
package guest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

const Version = "0.15.0"

// TrampolineFlag, as the agent binary's first argument, makes it set
// RLIMIT_NPROC and exec a program instead of running as the agent:
//
//	sbx-agent -exec-nproc N -- /path/to/program argv0 argv1 ...
const TrampolineFlag = "-exec-nproc"

// Trampoline is that mode. It never returns on success: the process
// becomes the program, with the limit in force from its first instruction.
func Trampoline(args []string) error {
	if len(args) < 4 || args[1] != "--" {
		return fmt.Errorf("usage: sbx-agent %s N -- path argv0 [args...]", TrampolineFlag)
	}
	n, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil || n == 0 {
		return fmt.Errorf("bad process limit %q", args[0])
	}
	if err := syscall.Setrlimit(rlimitNproc, &syscall.Rlimit{Cur: n, Max: n}); err != nil {
		return fmt.Errorf("set RLIMIT_NPROC: %w", err)
	}
	return syscall.Exec(args[2], args[3:], os.Environ())
}

const rlimitNproc = 6 // RLIMIT_NPROC, from <sys/resource.h>

var ErrUnsupportedDial = errors.New("guest: unsupported dial address")

type Config struct {
	SandboxID string
	// Dial is where the host listens: "unix:/sbx/agent.sock" on gVisor.
	// "vsock:2:<port>" is reserved for the Firecracker backend.
	Dial string

	MinBackoff, MaxBackoff time.Duration
	Logf                   func(format string, args ...any)

	// ReapAll makes the agent collect every exited child, orphans included.
	// Required as PID 1; see procTable.
	ReapAll bool

	// LogDir holds background processes' logs, one directory each.
	// Default /var/log/sbx. LogFileCap bounds each log file (two are kept
	// per process); default 8 MiB.
	LogDir     string
	LogFileCap int64

	// ChildNproc, if positive, limits the processes everything the agent
	// starts may create (RLIMIT_NPROC), while the agent itself stays
	// unlimited. The limit counts threads too, so if the agent had it, a
	// fork bomb filling the limit would leave the agent unable to create
	// an OS thread, which kills a Go program, and as PID 1, the sandbox.
	// Needs TrampolinePath: the agent binary, which sets the limit and then
	// execs the real program (Go can't set a child's rlimit itself).
	ChildNproc     int
	TrampolinePath string

	// IdentityDir is where the agent publishes its sandbox ID and
	// generation as files (sbx-agent: /run/sbx). Empty: not published.
	IdentityDir string
}

// Run dials, serves, and redials until ctx is cancelled. It returns ctx.Err()
// on cancellation, or an error that retrying can't fix (a bad address).
func Run(ctx context.Context, cfg Config) error {
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = 50 * time.Millisecond
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 2 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	network, addr, err := parseDial(cfg.Dial)
	if err != nil {
		return err
	}
	procs := newProcTable(cfg.ReapAll)
	defer procs.close()
	procs.ident = newIdentity(cfg.SandboxID, cfg.IdentityDir)
	if cfg.ChildNproc > 0 && cfg.TrampolinePath != "" {
		n := strconv.Itoa(cfg.ChildNproc)
		procs.wrap = func(path string, args []string) (string, []string) {
			return cfg.TrampolinePath, append([]string{"sbx-agent", TrampolineFlag, n, "--", path}, args...)
		}
	}
	// Shell sessions belong to the agent, not to any one connection: they
	// survive the host disconnecting, and end only when the agent does.
	shells := newSessionTable(procs)
	defer shells.closeAll()
	// Background processes, the same way: owned by the agent, stopped when
	// it stops.
	jobs := newJobTable(procs, cfg.LogDir, cfg.LogFileCap)
	defer jobs.closeAll()

	backoff := cfg.MinBackoff
	for {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, addr)
		if err == nil {
			served := session(ctx, conn, cfg, procs, shells, jobs)
			conn.Close()
			if served {
				backoff = cfg.MinBackoff // a session that got going resets the backoff
			}
		} else if ctx.Err() == nil {
			cfg.Logf("agent: dial %s: %v (retrying in %s)", cfg.Dial, err, backoff)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, cfg.MaxBackoff)
	}
}

// session runs one connection: hello, then serve requests until it breaks.
// It reports whether the host accepted the hello. Requests are handled
// concurrently; when the connection ends, commands still running are killed
// and waited for, so nothing from this session outlives it.
func session(ctx context.Context, conn net.Conn, cfg Config, procs *procTable, shells *sessionTable, jobs *jobTable) (accepted bool) {
	stop := context.AfterFunc(ctx, func() { conn.Close() }) // unblock reads on cancel
	defer stop()

	hello, _ := agentproto.New(agentproto.TypeHello, 0, agentproto.Hello{
		SandboxID: idOf(procs), Version: Version, PID: os.Getpid(),
	})
	if err := agentproto.Write(conn, hello); err != nil {
		return false
	}
	reply, err := agentproto.Read(conn)
	if err != nil {
		return false
	}
	switch reply.Type {
	case agentproto.TypeWelcome:
	case agentproto.TypeReject:
		var r agentproto.Reject
		_ = reply.Decode(&r)
		cfg.Logf("agent: host rejected hello: %s", r.Reason)
		return false
	default:
		cfg.Logf("agent: expected welcome, got %q", reply.Type)
		return false
	}

	sctx, cancelAll := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancelAll(); wg.Wait() }()
	w := &frameWriter{conn: conn}

	// Every long-running request gets an entry: a cancel function, and for
	// transfers an inbox for the frames that follow (chunks, close, acks).
	type task struct {
		cancel context.CancelFunc
		inbox  chan agentproto.Message
	}
	var mu sync.Mutex
	tasks := map[uint64]*task{}

	// start runs fn in a goroutine as request id, with its own context.
	// inbox is the size of its inbox, 0 for none: room for a full window
	// plus control frames, so a host that respects the window can never
	// make the loop's send block.
	start := func(id uint64, inbox int, fn func(ctx context.Context, inbox <-chan agentproto.Message)) {
		ctx, cancel := context.WithCancel(sctx)
		t := &task{cancel: cancel}
		if inbox > 0 {
			t.inbox = make(chan agentproto.Message, inbox)
		}
		mu.Lock()
		if _, dup := tasks[id]; dup {
			mu.Unlock()
			cancel()
			sendErr(w, id, agentproto.CodeInvalid, "request id already in use")
			return
		}
		tasks[id] = t
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				mu.Lock()
				delete(tasks, id)
				mu.Unlock()
				cancel()
			}()
			fn(ctx, t.inbox)
		}()
	}

	for {
		m, err := agentproto.Read(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				cfg.Logf("agent: connection lost: %v", err)
			}
			return true
		}
		switch m.Type {
		case agentproto.TypePing:
			pong, _ := agentproto.New(agentproto.TypePong, m.ID, nil)
			if err := w.send(pong); err != nil {
				return true
			}

		case agentproto.TypeExec:
			var req agentproto.Exec
			if err := m.Decode(&req); err != nil {
				bad, _ := agentproto.New(agentproto.TypeExit, m.ID, agentproto.Exit{Code: -1, Error: "bad exec request: " + err.Error()})
				_ = w.send(bad)
				continue
			}
			id := m.ID
			start(id, 0, func(ctx context.Context, _ <-chan agentproto.Message) {
				runExec(ctx, id, req, w, procs)
			})

		case agentproto.TypeWriteOpen:
			var req agentproto.WriteOpen
			if err := m.Decode(&req); err != nil {
				sendErr(w, m.ID, agentproto.CodeInvalid, "bad write_open: "+err.Error())
				continue
			}
			id := m.ID
			start(id, agentproto.Window+4, func(ctx context.Context, in <-chan agentproto.Message) {
				runWrite(ctx, id, req, in, w)
			})

		case agentproto.TypeRead:
			var req agentproto.ReadReq
			if err := m.Decode(&req); err != nil {
				sendErr(w, m.ID, agentproto.CodeInvalid, "bad read: "+err.Error())
				continue
			}
			id := m.ID
			start(id, agentproto.Window+4, func(ctx context.Context, acks <-chan agentproto.Message) {
				runRead(ctx, id, req, acks, w)
			})

		case agentproto.TypeList, agentproto.TypeStat:
			var req agentproto.PathReq
			if err := m.Decode(&req); err != nil {
				sendErr(w, m.ID, agentproto.CodeInvalid, "bad request: "+err.Error())
				continue
			}
			id, typ := m.ID, m.Type
			start(id, 0, func(context.Context, <-chan agentproto.Message) {
				if typ == agentproto.TypeList {
					runList(id, req, w)
				} else {
					runStat(id, req, w)
				}
			})

		case agentproto.TypeShellOpen:
			var req agentproto.ShellOpen
			if err := m.Decode(&req); err != nil {
				sendErr(w, m.ID, agentproto.CodeInvalid, "bad shell_open: "+err.Error())
				continue
			}
			id := m.ID
			// Input frames under the window, acks for output under the
			// window, and a few control frames.
			start(id, 2*agentproto.Window+8, func(ctx context.Context, in <-chan agentproto.Message) {
				runShell(ctx, id, req, in, w, shells)
			})

		case agentproto.TypeShellList:
			list, _ := agentproto.New(agentproto.TypeShellListed, m.ID, shells.list())
			_ = w.send(list)

		case agentproto.TypeShellKill:
			var req agentproto.ShellKill
			if err := m.Decode(&req); err != nil {
				sendErr(w, m.ID, agentproto.CodeInvalid, "bad shell_kill: "+err.Error())
				continue
			}
			id := m.ID
			start(id, 0, func(context.Context, <-chan agentproto.Message) {
				s, err := shells.get(req.SessionID)
				if err != nil {
					sendErr(w, id, agentproto.CodeNotFound, err.Error())
					return
				}
				s.kill()
				done, _ := agentproto.New(agentproto.TypeShellKilled, id, nil)
				_ = w.send(done)
			})

		case agentproto.TypeProcStart:
			var req agentproto.ProcStart
			if err := m.Decode(&req); err != nil {
				sendErr(w, m.ID, agentproto.CodeInvalid, "bad proc_start: "+err.Error())
				continue
			}
			id := m.ID
			start(id, 0, func(context.Context, <-chan agentproto.Message) {
				j, err := jobs.start(req)
				if err != nil {
					jobErr(w, id, err)
					return
				}
				ok, _ := agentproto.New(agentproto.TypeProcStarted, id, agentproto.ProcStarted{ID: j.id, PID: j.pid})
				_ = w.send(ok)
			})

		case agentproto.TypeProcList:
			list, _ := agentproto.New(agentproto.TypeProcListed, m.ID, jobs.list())
			_ = w.send(list)

		case agentproto.TypeProcSignal:
			var req agentproto.ProcSignal
			if err := m.Decode(&req); err != nil {
				sendErr(w, m.ID, agentproto.CodeInvalid, "bad proc_signal: "+err.Error())
				continue
			}
			if err := jobs.signal(req.ID, req.Signal); err != nil {
				jobErr(w, m.ID, err)
				continue
			}
			ok, _ := agentproto.New(agentproto.TypeProcSignaled, m.ID, nil)
			_ = w.send(ok)

		case agentproto.TypeProcWait:
			var req agentproto.ProcRef
			if err := m.Decode(&req); err != nil {
				sendErr(w, m.ID, agentproto.CodeInvalid, "bad proc_wait: "+err.Error())
				continue
			}
			id := m.ID
			// Waiting can take forever; a dropped connection ends the wait,
			// never the process.
			start(id, 0, func(ctx context.Context, _ <-chan agentproto.Message) {
				j, err := jobs.get(req.ID)
				if err != nil {
					jobErr(w, id, err)
					return
				}
				select {
				case <-j.done:
					done, _ := agentproto.New(agentproto.TypeProcExited, id, j.info())
					_ = w.send(done)
				case <-ctx.Done():
					sendErr(w, id, agentproto.CodeCanceled, "wait cancelled")
				}
			})

		case agentproto.TypeProcLogs:
			var req agentproto.ProcLogs
			if err := m.Decode(&req); err != nil {
				sendErr(w, m.ID, agentproto.CodeInvalid, "bad proc_logs: "+err.Error())
				continue
			}
			id := m.ID
			start(id, agentproto.Window+4, func(ctx context.Context, acks <-chan agentproto.Message) {
				runLogs(ctx, id, req, acks, w, jobs)
			})

		case agentproto.TypeProcRemove:
			var req agentproto.ProcRef
			if err := m.Decode(&req); err != nil {
				sendErr(w, m.ID, agentproto.CodeInvalid, "bad proc_remove: "+err.Error())
				continue
			}
			if err := jobs.remove(req.ID); err != nil {
				jobErr(w, m.ID, err)
				continue
			}
			ok, _ := agentproto.New(agentproto.TypeProcRemoved, m.ID, nil)
			_ = w.send(ok)

		case agentproto.TypeIdentity:
			var id agentproto.Identity
			if err := m.Decode(&id); err != nil || id.SandboxID == "" {
				sendErr(w, m.ID, agentproto.CodeInvalid, "identity needs a sandbox_id")
				continue
			}
			prev := procs.ident.set(id.SandboxID, id.Generation)
			now, gen := procs.ident.get()
			ack, _ := agentproto.New(agentproto.TypeIdentityAck, m.ID, agentproto.IdentityAck{
				Previous: prev, Identity: agentproto.Identity{SandboxID: now, Generation: gen},
			})
			_ = w.send(ack)
			cfg.Logf("agent: now sandbox %s (was %s), generation %s", now, prev, gen)

		case agentproto.TypeQuiesce:
			// A checkpoint is coming. Acknowledge, then end this session:
			// returning closes the connection. Sessions and background
			// processes live on inside the sandbox; execs on this
			// connection end with it (the host only quiesces an idle
			// sandbox unless told to force it). The redial loop takes
			// over: dials fail until the host listens again, and none of
			// them leaves a connection open.
			ack, _ := agentproto.New(agentproto.TypeQuiesced, m.ID, nil)
			_ = w.send(ack)
			cfg.Logf("agent: quiescing for a checkpoint")
			return true

		case agentproto.TypeReclaim:
			// Inline, not in a task: when memory is nearly gone, the kill
			// should happen now, not after a goroutine is scheduled.
			res, _ := agentproto.New(agentproto.TypeReclaimed, m.ID, reclaim("/proc"))
			_ = w.send(res)

		case agentproto.TypeWriteChunk, agentproto.TypeWriteClose, agentproto.TypeAck,
			agentproto.TypePtyIn, agentproto.TypeResize, agentproto.TypeDetach:
			mu.Lock()
			t := tasks[m.ID]
			mu.Unlock()
			if t == nil || t.inbox == nil {
				continue // the transfer already ended (failed or cancelled)
			}
			select {
			case t.inbox <- m:
			default:
				// The sender ignored the window. Fail that transfer rather
				// than block this loop, which serves every other request.
				t.cancel()
			}

		case agentproto.TypeCancel:
			mu.Lock()
			t := tasks[m.ID]
			mu.Unlock()
			if t != nil {
				t.cancel()
			}
			// Unknown request types are ignored, not fatal: an older agent
			// keeps working with a newer host for what it does understand.
		}
	}
}

func parseDial(s string) (network, addr string, err error) {
	scheme, rest, ok := strings.Cut(s, ":")
	switch {
	case ok && scheme == "unix" && rest != "":
		return "unix", rest, nil
	case ok && scheme == "vsock":
		return "", "", fmt.Errorf("%w: vsock is the Firecracker transport, not built yet: %q", ErrUnsupportedDial, s)
	default:
		return "", "", fmt.Errorf("%w: %q (want unix:/path)", ErrUnsupportedDial, s)
	}
}

// idOf is the ID the agent introduces itself with: its current identity, or
// (for a session started outside Run, in tests) none.
func idOf(procs *procTable) string {
	if procs.ident == nil {
		return ""
	}
	id, _ := procs.ident.get()
	return id
}
