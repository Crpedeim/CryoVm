package guest

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// procTable starts processes and delivers each one's exit status exactly
// once, to whoever started it.
//
// When the agent is PID 1 (reapAll), it must also reap orphans: every
// process in the sandbox whose parent died becomes its child. Reaping means
// wait4(-1), which collects ANY child, including the ones exec is waiting
// for. So one reaper owns all waiting, and hands tracked statuses over.
//
// The race to beat: a command can exit before its PID is registered, and
// the reaper would throw its status away as an orphan's. Starting and
// registering happen under the same lock the reaper holds while it waits,
// so the reaper can't run in between.
type procTable struct {
	reapAll bool
	mu      sync.Mutex
	waiting map[int]chan syscall.WaitStatus
	stop    chan struct{}

	// wrap, if set, rewrites every child's command so it starts with a
	// process limit (see guest.Config.ChildNproc and the trampoline in
	// cmd/sbx-agent). Every way the agent starts a program (exec, shells,
	// background processes) goes through start, so nothing escapes it.
	wrap func(path string, args []string) (string, []string)

	// ident gives every child the agent's identity in its environment
	// (Day 15), through the one function all children are started by.
	ident *identity
}

func newProcTable(reapAll bool) *procTable {
	t := &procTable{reapAll: reapAll, waiting: map[int]chan syscall.WaitStatus{}, stop: make(chan struct{})}
	if reapAll {
		go t.reapLoop()
	}
	return t
}

func (t *procTable) close() { close(t.stop) }

func (t *procTable) reapLoop() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGCHLD)
	defer signal.Stop(sigs)
	// SIGCHLDs can merge into one delivery, so each wakeup reaps until
	// nothing is left. The ticker is insurance against a lost wakeup.
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-sigs:
		case <-tick.C:
		}
		t.reap()
	}
}

func (t *procTable) reap() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if pid <= 0 || err != nil {
			return
		}
		if ch, ok := t.waiting[pid]; ok {
			ch <- ws // buffered: never blocks while holding the lock
			delete(t.waiting, pid)
		}
		// Unregistered: an orphan. Its status is discarded, and the zombie is gone.
	}
}

// start launches a process and returns its PID and a channel that receives
// its exit status once.
func (t *procTable) start(path string, args []string, attr *os.ProcAttr) (int, <-chan syscall.WaitStatus, error) {
	if t.wrap != nil {
		path, args = t.wrap(path, args)
	}
	if t.ident != nil {
		a := *attr // the caller's attr is left as it was
		a.Env = t.ident.env(attr.Env)
		attr = &a
	}
	ch := make(chan syscall.WaitStatus, 1)
	if !t.reapAll {
		p, err := os.StartProcess(path, args, attr)
		if err != nil {
			return 0, nil, err
		}
		go func() {
			ps, err := p.Wait() // waits for this PID only: safe alongside other code
			if err == nil {
				ch <- ps.Sys().(syscall.WaitStatus)
			} else {
				ch <- syscall.WaitStatus(0xff00) // unknown status: report exit code 255
			}
		}()
		return p.Pid, ch, nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	p, err := os.StartProcess(path, args, attr)
	if err != nil {
		return 0, nil, err
	}
	// Read the PID before Release: Release sets p.Pid to -1.
	pid := p.Pid
	t.waiting[pid] = ch
	_ = p.Release() // the reaper waits for it, never os.Process.Wait
	return pid, ch, nil
}
