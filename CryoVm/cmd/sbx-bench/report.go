package main

import (
	"fmt"
	"strings"
)

func f0(v float64) string { return fmt.Sprintf("%.0f", v) }
func f1(v float64) string { return fmt.Sprintf("%.1f", v) }

func statsRow(name string, s Stats) string {
	return fmt.Sprintf("| %s | %d | **%s** | %s | %s | %s | %s |\n", name, s.N, f1(s.P50), f1(s.P99), f1(s.Min), f1(s.Max), f1(s.Mean))
}

const statsHead = "| | n | p50 ms | p99 ms | min | max | mean |\n| --- | --- | --- | --- | --- | --- | --- |\n"

// pause finds the pause result for a place and a workload size.
func (r *Results) pause(where string, mib int) (PauseResult, bool) {
	for _, p := range r.Pauses {
		if p.Where == where && p.TouchedMiB == mib {
			return p, true
		}
	}
	return PauseResult{}, false
}

func (r *Results) touchedRange() (lo, hi int) {
	lo, hi = -1, -1
	for _, p := range r.Pauses {
		if lo < 0 || p.TouchedMiB < lo {
			lo = p.TouchedMiB
		}
		if p.TouchedMiB > hi {
			hi = p.TouchedMiB
		}
	}
	return
}

// report renders the results: the resume entry's numbers first, each with
// where it came from, then the machine, then every measurement.
func report(r *Results) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("# sbx benchmarks\n\nRun %s, %s long. Every number is measured through the daemon's API, on the machine described below.\n\n",
		r.Started.Format("2006-01-02 15:04 MST"), r.Finished.Sub(r.Started).Round(1e9))

	w("## The resume entry\n\n")
	lo, hi := r.touchedRange()
	small, okSmall := r.pause("object store", lo)
	where := "from S3-compatible storage"
	if !okSmall {
		small, okSmall = r.pause("local disk", lo)
		where = "from local disk (the store wasn't measured)"
	}
	if okSmall && r.ColdStart != nil {
		x, y := small.Resume.Stats.P50, r.ColdStart.Stats.P50
		closeness := fmt.Sprintf("within **%s ms** of starting an empty one (**%s ms**)", f0(x-y), f0(y))
		if x < y {
			closeness = fmt.Sprintf("faster than starting an empty one (**%s ms**)", f0(y))
		}
		big := ""
		if p, ok := r.pause(small.Where, hi); ok && hi > lo {
			big = fmt.Sprintf("; **%s ms** for one holding %d MiB of memory", f0(p.Resume.Stats.P50), hi)
		}
		w("- …resuming sandboxes with running processes and terminals intact %s in **%s ms** (p50), %s%s.\n", where, f0(x), closeness, big)
		w("  - The resume is p50 from the resume call to the first exec returning, the image downloaded and SHA-256-verified first; the cold start is p50 from the create call to the first exec of an empty sandbox. On gVisor there is no guest kernel to boot, so an empty sandbox starts fast: resume's value is that everything comes back, not that it's quicker.\n")
	}
	if n := len(r.Fork); n > 0 {
		top := r.Fork[n-1]
		if top.MemoryAvailable {
			w("- …cloning an environment into **%d** copies in **%s ms** at **%s MiB** per sandbox.\n", top.N, f0(top.Series.Stats.P50), f1(top.PSSPerCloneMiB))
			w("  - p50 from the fork call until all %d clones answer an exec; per sandbox is each clone's PSS with all %d running, which shares runsc's code pages among them. One more clone's own memory (its cgroup's count) is %s MiB.\n", top.N, top.N, f1(top.CgroupPerClone))
		} else {
			// A missing number must never look like a measured zero.
			w("- …cloning an environment into **%d** copies in **%s ms** at **[K] not measured** per sandbox (see the notes).\n", top.N, f0(top.Series.Stats.P50))
		}
	}

	w("\n## The machine\n\n| | at the start | at the end |\n| --- | --- | --- |\n")
	row := func(k, a, c string) { w("| %s | %s | %s |\n", k, a, c) }
	e, a := r.Env, r.EnvAfter
	row("CPU", fmt.Sprintf("%s (%d CPUs)", e.CPU, e.CPUs), "")
	row("Memory", fmt.Sprintf("%.0f MiB total, %.0f available", e.MemTotalMiB, e.MemAvailMiB), fmt.Sprintf("%.0f available", a.MemAvailMiB))
	row("Virtualized", e.Virtualized, "")
	row("Kernel", e.Kernel, "")
	row("CPU governor", e.Governor, a.Governor)
	row("Load average", e.LoadAvg, a.LoadAvg)
	row("Busiest processes (%CPU)", strings.Join(e.TopCPU, "; "), strings.Join(a.TopCPU, "; "))
	row("gVisor", e.Runsc, "")
	row("Platform", e.Platform, "")
	row("Object store", e.Store, "")
	row("Checkpoint filesystem", e.DirFilesystem, "")
	row("Checkpoint image I/O", e.CheckpointIO, "")
	row("fsync on that filesystem (4 KiB, p50)", f1(e.FsyncMs)+" ms", "")
	row("Go, sbx commit", e.Go+", "+e.Commit, "")

	if r.ColdStart != nil {
		w("\n## Cold start: create call → first exec returns\n\nLoad at the start: %s. One warm-up run first, not counted: %s ms.\n\n%s%s",
			r.ColdLoad, f1(r.ColdWarmupMs), statsHead, statsRow("base image, empty", r.ColdStart.Stats))
	}
	if len(r.Pauses) > 0 {
		w("\n## Snapshot and resume, by memory in use\n\n")
		w("Each sandbox holds a workload: a counting shell loop (0 MiB), or a Python process that has written to every page of a buffer. Snapshot is the checkpoint call until the image is saved (local disk) or its manifest is committed (object store); the sandbox is paused. Resume is the resume call until the first exec returns; from the object store the local copy was deleted after each upload, so every resume downloads and verifies the image first. Each row: one warm-up round, then the timed ones.\n\n")
		w("| memory in use | where | image MiB | uploaded MiB | snapshot p50 ms | p99 | resume p50 ms | p99 | n | load at the start |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
		for _, p := range r.Pauses {
			up := "—"
			if p.Where == "object store" {
				up = f1(p.UploadedMiB)
				if p.UploadedMiB == 0 {
					up = "not measured" // never a missing number shown as zero
				}
			}
			w("| %d MiB | %s | %s | %s | **%s** | %s | **%s** | %s | %d | %s |\n", p.TouchedMiB, p.Where, f1(p.ImageMiB), up,
				f1(p.Snapshot.Stats.P50), f1(p.Snapshot.Stats.P99), f1(p.Resume.Stats.P50), f1(p.Resume.Stats.P99), p.Resume.Stats.N, p.Load)
		}
		w("\nWhat goes to the store is the image plus the agent binary every image carries (Day 11).\n")
	}
	if len(r.IOCompare) > 0 {
		w("\n## Checkpoint I/O: buffered vs O_DIRECT\n\nLocal disk, at sizes where buffered I/O is safe. A buffered image's page cache is charged to the sandbox's own memory limit, which killed a sandbox holding 128 of 256 MiB; O_DIRECT avoids that, at a cost measured here. The default, auto, uses O_DIRECT only above 40%% of a sandbox's limit.\n\n| memory in use | snapshot p50, buffered | snapshot p50, O_DIRECT | resume p50, buffered | resume p50, O_DIRECT |\n| --- | --- | --- | --- | --- |\n")
		for _, c := range r.IOCompare {
			w("| %d MiB | %s ms | %s ms | %s ms | %s ms |\n", c.TouchedMiB, f1(c.Buffered.Stats.P50), f1(c.Direct.Stats.P50), f1(c.BufferedRs.Stats.P50), f1(c.DirectRs.Stats.P50))
		}
	}
	if len(r.Fork) > 0 {
		w("\n## Fork: fork call → every clone answers an exec\n\nFrom a running sandbox (so each fork includes a snapshot of the source); the clones are made in parallel, at most one per CPU, and queried in parallel. Load at the start: %s.\n\n| N | runs | p50 ms | p99 ms | per clone (p50 / N) |\n| --- | --- | --- | --- | --- |\n", r.ForkLoad)
		for _, f := range r.Fork {
			w("| %d | %d | **%s** | %s | %s |\n", f.N, f.Series.Stats.N, f1(f.Series.Stats.P50), f1(f.Series.Stats.P99), f1(f.Series.Stats.P50/float64(f.N)))
		}
		if len(r.Fork[0].PhaseP50) > 0 {
			w("\nWhere each clone's time goes: the p50 of each phase, per clone, as the daemon logged it. A phase that grows with N is where the clones wait on each other.\n\n| N | registry ms | network ms | restore ms | agent ms | finish ms |\n| --- | --- | --- | --- | --- | --- |\n")
			for _, f := range r.Fork {
				p := f.PhaseP50
				w("| %d | %s | %s | %s | %s | %s |\n", f.N, f0(p["registry"]), f0(p["network"]), f0(p["restore"]), f0(p["agent"]), f0(p["finish"]))
			}
		}
		w("\n## Memory per sandbox, as clone count grows\n\nPSS of every process in each clone's cgroup, with all N clones running, and the cgroup's own count. A flat cgroup count means the clones share none of their sandbox memory (as Day 14 found); PSS falls as N grows because runsc's own code pages are shared, and PSS divides them among more processes.\n\n| N | PSS per clone, MiB | cgroup memory per clone, MiB | the source's PSS, MiB |\n| --- | --- | --- | --- |\n")
		for _, f := range r.Fork {
			if f.MemoryAvailable {
				w("| %d | **%s** | %s | %s |\n", f.N, f1(f.PSSPerCloneMiB), f1(f.CgroupPerClone), f1(f.PSSSourceMiB))
			} else {
				w("| %d | not measured | | |\n", f.N)
			}
		}
	}
	if len(r.Terminal) > 0 {
		w("\n## Terminal round trip: keystroke sent → echoed byte received\n\n\"Just resumed\" is the first keystroke after the sandbox was paused, resumed and its shell session reattached. Load at the start: %s.\n\n%s", r.TerminalLoad, statsHead)
		for _, k := range []string{"running", "just resumed"} {
			if s, ok := r.Terminal[k]; ok {
				w("%s", statsRow(k, s.Stats))
			}
		}
	}
	if len(r.Density) > 0 {
		w("\n## Density: sandboxes running at once\n\nMeasured last, since it loads the machine most. Sandboxes were created, each answering an exec (and, for the browser image, running Chromium with a page open), until a share of the memory available at the start was used: filling the host for real could take everything else on it down. The last column extrapolates, from the memory each one actually took, to all of the memory that was available: an estimate, by memory alone.\n\n| sandboxes | running (measured) | stopped at | PSS each, MiB | available memory used each, MiB | create → ready p50 ms | load at the start | extrapolated to the host's limit |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
		for _, d := range r.Density {
			pss := f1(d.PSSPerSandboxMiB)
			if d.PSSPerSandboxMiB == 0 {
				pss = "not measured"
			}
			extra := fmt.Sprintf("~%d", d.Extrapolated)
			if d.Extrapolated == 0 {
				extra = "not measurable (too little memory used to see)"
			}
			w("| %s | **%d** | %s | %s | %s | %s | %s | %s |\n", d.Image, d.Running, d.StoppedBecause, pss, f1(d.UsedPerSandboxMiB), f1(d.CreateSeries.Stats.P50), d.Load, extra)
		}
	}
	w("\n## Method\n\n")
	w("- p50 and p99 use the nearest rank: with n samples, p99 is the ceil(0.99 n)-th smallest, so **for n ≤ 100 it is the largest sample**: a worst case seen, not a stable tail.\n")
	w("- Cold start, snapshot and resume each run one warm-up round first, reported but not counted.\n")
	w("- Each measurement runs on private daemons, separate from any sbxd service, with that service's defaults (1 vCPU, 256 MiB, browser image 2048 MiB). Sandboxes never idle-pause during the run. Density runs last, and the load average at the start of each measurement is shown with it.\n")
	w("- Compare these numbers only with others from the same setup: Day 14 saw file transfers swing between 30 and 130 MB/s from one day to the next on this machine with no code change.\n")
	for _, n := range r.Notes {
		w("- Note: %s\n", n)
	}
	return b.String()
}
