package guest

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

// procEntry is one process as /proc describes it.
type procEntry struct {
	pid, ppid int
	command   string
	rss       int64 // bytes of memory actually in use (resident set size)
}

// readProc reads one process's parent, name and resident memory from
// /proc/<pid>/status. Processes can vanish while we read: that's not an
// error, just a skipped entry.
func readProc(procRoot string, pid int) (procEntry, bool) {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return procEntry{}, false
	}
	e := procEntry{pid: pid}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			e.command = v
		case "PPid":
			e.ppid, _ = strconv.Atoi(v)
		case "VmRSS": // "123456 kB"
			if f := strings.Fields(v); len(f) > 0 {
				kb, _ := strconv.ParseInt(f[0], 10, 64)
				e.rss = kb << 10
			}
		}
	}
	return e, true
}

// largestDescendant finds the process using the most memory among root's
// descendants. Only descendants are candidates: inside a sandbox that's
// every process but the agent, and in tests (where the agent runs inside
// `go test`) it can never pick anything else on the machine.
func largestDescendant(procRoot string, root int) (procEntry, bool) {
	dirs, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	all := map[int]procEntry{}
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil {
			continue
		}
		if e, ok := readProc(procRoot, pid); ok {
			all[pid] = e
		}
	}
	isDescendant := func(pid int) bool {
		for seen := 0; pid > 1 && seen < len(all)+1; seen++ {
			e, ok := all[pid]
			if !ok {
				return false
			}
			if e.ppid == root {
				return true
			}
			pid = e.ppid
		}
		return false
	}
	var best procEntry
	found := false
	for pid, e := range all {
		if pid == root || pid <= 1 || !isDescendant(pid) {
			continue
		}
		if !found || e.rss > best.rss {
			best, found = e, true
		}
	}
	return best, found
}

// reclaim kills the agent's descendant using the most memory. SIGKILL,
// not SIGTERM: memory is about to run out, and there's no time to ask.
func reclaim(procRoot string) agentproto.Reclaimed {
	victim, ok := largestDescendant(procRoot, os.Getpid())
	if !ok || victim.pid <= 1 {
		return agentproto.Reclaimed{}
	}
	if err := syscall.Kill(victim.pid, syscall.SIGKILL); err != nil {
		return agentproto.Reclaimed{}
	}
	return agentproto.Reclaimed{Killed: true, PID: victim.pid, Command: victim.command, RSS: victim.rss}
}
