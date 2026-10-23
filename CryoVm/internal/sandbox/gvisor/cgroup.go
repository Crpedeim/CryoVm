package gvisor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Crpedeim/sbx/internal/sandbox"
)

// cgroupFS reads cgroup v2, the unified hierarchy that modern Linux
// (including Ubuntu 24.04) uses. Both roots are configurable so tests can
// point them at a fake tree.
type cgroupFS struct {
	procRoot string // normally /proc
	cgRoot   string // normally /sys/fs/cgroup
}

// pathOf returns the cgroup a process is in, relative to the cgroup root.
// It asks the kernel rather than assuming: on cgroup v2, /proc/<pid>/cgroup
// holds one line of the form "0::<path>".
func (c cgroupFS) pathOf(pid int) (string, error) {
	raw, err := os.ReadFile(filepath.Join(c.procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p, nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry for pid %d (is the host on cgroup v1?): %q", pid, raw)
}

func (c cgroupFS) dir(path string) string { return filepath.Join(c.cgRoot, path) }

// readStat reads a single-number file; "max" means no limit and reads as 0.
// A missing file is not an error: some files exist only on newer kernels
// (memory.peak) or only when a controller is enabled.
func readStat(dir, name string) (int64, bool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	s := strings.TrimSpace(string(raw))
	if s == "max" {
		return 0, true, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("%s: %q is not a number", name, s)
	}
	return n, true, nil
}

// readKeyed reads a "key value" per line file, like memory.events or cpu.stat.
func readKeyed(dir, name string) (map[string]int64, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]int64{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 {
			if n, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				out[f[0]] = n
			}
		}
	}
	return out, sc.Err()
}

// readStats reads a cgroup's usage and limits.
func readStats(dir, path string) (sandbox.Stats, error) {
	if _, err := os.Stat(dir); err != nil {
		return sandbox.Stats{}, fmt.Errorf("cgroup %s: %w", path, err)
	}
	st := sandbox.Stats{Cgroup: path}
	var err error
	if st.MemoryBytes, _, err = readStat(dir, "memory.current"); err != nil {
		return st, err
	}
	if st.MemoryPeak, _, err = readStat(dir, "memory.peak"); err != nil {
		return st, err
	}
	if st.MemoryLimit, _, err = readStat(dir, "memory.max"); err != nil {
		return st, err
	}
	if st.Pids, _, err = readStat(dir, "pids.current"); err != nil {
		return st, err
	}
	if st.PidsLimit, _, err = readStat(dir, "pids.max"); err != nil {
		return st, err
	}
	events, err := readKeyed(dir, "memory.events")
	if err != nil {
		return st, err
	}
	st.OOMKills = events["oom_kill"]

	cpu, err := readKeyed(dir, "cpu.stat")
	if err != nil {
		return st, err
	}
	st.CPUUsage = time.Duration(cpu["usage_usec"]) * time.Microsecond
	st.CPUThrottled = time.Duration(cpu["throttled_usec"]) * time.Microsecond
	st.ThrottledPeriods = cpu["nr_throttled"]

	// cpu.max is "<quota> <period>" in microseconds, or "max <period>".
	if raw, err := os.ReadFile(filepath.Join(dir, "cpu.max")); err == nil {
		f := strings.Fields(string(raw))
		if len(f) == 2 && f[0] != "max" {
			q, _ := strconv.ParseFloat(f[0], 64)
			per, _ := strconv.ParseFloat(f[1], 64)
			if per > 0 {
				st.CPUQuota = q / per
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "cpuset.cpus.effective")); err == nil {
		st.CPUs = strings.TrimSpace(string(raw))
	}
	return st, nil
}

// exitReason explains an unexpected stop from the cgroup's event counters,
// or returns "". From the host, the sandbox is one process: whichever limit
// the kernel enforced, it was enforced on all of it.
func exitReason(dir string) string {
	if mem, err := readKeyed(dir, "memory.events"); err == nil && mem["oom_kill"] > 0 {
		limit, _, _ := readStat(dir, "memory.max")
		if limit > 0 {
			return fmt.Sprintf("killed by the kernel's out-of-memory killer (memory limit %d MiB reached)", limit>>20)
		}
		return "killed by the kernel's out-of-memory killer"
	}
	// The host thread limit. gVisor needs host threads to run the processes
	// inside, so when it can't create one, the whole sandbox fails. Two
	// pieces of evidence, either enough: pids.events counted a refused
	// fork, or pids.peak (newer kernels) reached pids.max. Day 8 saw a
	// death here with pids.events silent, hence the second check, and the
	// watcher's own samples (hostThreadReason) as a third.
	limit, _, _ := readStat(dir, "pids.max")
	if pids, err := readKeyed(dir, "pids.events"); err == nil && pids["max"] > 0 {
		return hostThreadReason(limit)
	}
	if peak, ok, _ := readStat(dir, "pids.peak"); ok && limit > 0 && peak >= limit {
		return hostThreadReason(limit)
	}
	return ""
}

func hostThreadReason(limit int64) string {
	return fmt.Sprintf("hit its host thread limit (pids.max %d): gVisor couldn't create the threads it needed", limit)
}

// setMemoryHigh sets the cgroup's throttling point. Above memory.high the
// kernel doesn't kill: it makes allocations slow, reclaiming hard. That
// buys the memory guard time to act before memory.max, where the OOM
// killer would end the whole sandbox.
func setMemoryHigh(dir string, bytes int64) error {
	return os.WriteFile(filepath.Join(dir, "memory.high"), []byte(strconv.FormatInt(bytes, 10)), 0o644)
}
