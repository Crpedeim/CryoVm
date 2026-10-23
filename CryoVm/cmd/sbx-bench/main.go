// sbx-bench runs the plan's benchmark suite (Day 23) and writes every
// sample, the machine's conditions, and a report with the resume entry's
// numbers filled in:
//
//	sudo bin/sbx-bench -out bench-results
//
// It starts its own private daemons (one on local disk, one on the object
// store), separate from any sbxd service, and talks to them through the
// API, so every number includes the path a real client takes. Root is
// needed: gVisor, and reading each sandbox's memory from /proc.
//
// The seven measurements (plan, section 6):
//
//	cold start           create call → first exec returns
//	snapshot             checkpoint call → image saved (local) / manifest committed (store)
//	resume               resume call → first exec returns (local disk vs object store),
//	                     each for sandboxes holding ~0, 64 and 128 MiB of touched memory
//	fork                 fork call → every clone answers an exec (N = 1, 2, 4, 8, 16)
//	memory per sandbox   PSS of the processes in each sandbox's cgroup, as clones grow
//	density              sandboxes running at once: idle base image vs Chromium running
//	terminal round trip  keystroke sent → echoed byte received (running vs just resumed)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
	"github.com/Crpedeim/sbx/internal/daemon"
	"github.com/Crpedeim/sbx/internal/registry"
	"github.com/Crpedeim/sbx/internal/s3"
	"github.com/Crpedeim/sbx/internal/sandbox/gvisor"
	"github.com/Crpedeim/sbx/internal/store"
)

type opts struct {
	rootfs, browserRootfs, agent, runsc, dir, out string
	storeURL, storeBucket                         string
	runs, forkRuns, keys, resumedKeys             int
	forkNs, memSizes                              []int
	budget                                        float64
	densityMax                                    int
	only                                          map[string]bool
	cgroupParent, cgroupRoot                      string
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("sbx-bench: ")
	var o opts
	var forkNs, only, memSizes string
	flag.StringVar(&o.rootfs, "rootfs", "/mnt/sbx/rootfs/ubuntu-24.04", "the base image")
	flag.StringVar(&o.browserRootfs, "browser-rootfs", "", "the browser image (default: browser-current, else browser, under /mnt/sbx/rootfs)")
	flag.StringVar(&o.agent, "agent", "/usr/local/bin/sbx-agent", "the guest agent binary")
	flag.StringVar(&o.runsc, "runsc", "", "runsc (default: from PATH)")
	flag.StringVar(&o.dir, "dir", "/var/lib/sbx-bench", "working directory for the private daemons (removed afterwards)")
	flag.StringVar(&o.out, "out", "bench-results", "where results.json and report.md go")
	flag.StringVar(&o.storeURL, "store", "http://127.0.0.1:8333", "the object store; credentials from SBX_S3_ACCESS_KEY/SBX_S3_SECRET_KEY or /etc/sbx/sbxd.env; empty skips the store variants")
	flag.StringVar(&o.storeBucket, "store-bucket", "sbx-bench", "the object store bucket")
	flag.IntVar(&o.runs, "runs", 20, "repetitions for cold start, snapshot and resume")
	flag.IntVar(&o.forkRuns, "fork-runs", 5, "repetitions per fork size")
	flag.StringVar(&forkNs, "fork-n", "1,2,4,8,16", "fork sizes")
	flag.StringVar(&memSizes, "mem", "0,64,128", "snapshot and resume for sandboxes holding this much touched memory, MiB")
	flag.IntVar(&o.keys, "keys", 200, "keystrokes for the running terminal round trip")
	flag.IntVar(&o.resumedKeys, "resumed", 20, "pause-resume cycles for the just-resumed terminal round trip")
	flag.Float64Var(&o.budget, "density-budget", 0.5, "density stops after using this fraction of the memory available at its start")
	flag.IntVar(&o.densityMax, "density-max", 500, "density stops at this many sandboxes at most")
	flag.StringVar(&only, "only", "", "run only these, comma-separated: cold,snapshot,io,fork,density,terminal")
	flag.StringVar(&o.cgroupParent, "cgroup-parent", "/sbx", "sandboxes' cgroup parent (as the backend's)")
	flag.StringVar(&o.cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "the cgroup v2 mount")
	flag.Parse()
	for _, s := range strings.Split(forkNs, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			o.forkNs = append(o.forkNs, n)
		}
	}
	for _, s := range strings.Split(memSizes, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 0 {
			o.memSizes = append(o.memSizes, n)
		}
	}
	o.only = map[string]bool{}
	for _, s := range strings.Split(only, ",") {
		if s = strings.TrimSpace(s); s != "" {
			o.only[s] = true
		}
	}
	if o.runsc == "" {
		o.runsc, _ = exec.LookPath("runsc")
	}
	if o.browserRootfs == "" {
		for _, p := range []string{"/mnt/sbx/rootfs/browser-current", "/mnt/sbx/rootfs/browser"} {
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				o.browserRootfs = p
				break
			}
		}
	}
	if err := run(o); err != nil {
		log.Fatal(err)
	}
}

func (o opts) want(name string) bool { return len(o.only) == 0 || o.only[name] }

// Series is one measurement's samples, in milliseconds, and their summary.
type Series struct {
	Samples []float64 `json:"samples_ms"`
	Stats   Stats     `json:"stats"`
}

type Stats struct {
	N    int     `json:"n"`
	P50  float64 `json:"p50_ms"`
	P99  float64 `json:"p99_ms"`
	Min  float64 `json:"min_ms"`
	Max  float64 `json:"max_ms"`
	Mean float64 `json:"mean_ms"`
}

// summarize uses the nearest-rank percentile: with n samples, p99 is the
// ceil(0.99 n)-th smallest, which for n <= 100 is the largest.
func summarize(ms []float64) Stats {
	if len(ms) == 0 {
		return Stats{}
	}
	s := append([]float64(nil), ms...)
	sort.Float64s(s)
	rank := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		if i < 0 {
			i = 0
		}
		return s[i]
	}
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	return Stats{N: len(s), P50: rank(0.50), P99: rank(0.99), Min: s[0], Max: s[len(s)-1], Mean: sum / float64(len(s))}
}

func series(ms []float64) Series { return Series{Samples: ms, Stats: summarize(ms)} }

type ForkResult struct {
	N               int                `json:"n"`
	PhaseP50        map[string]float64 `json:"phase_p50_ms_per_clone,omitempty"`
	Series          Series             `json:"fork"`
	PSSPerCloneMiB  float64            `json:"pss_per_clone_mib"`
	PSSSourceMiB    float64            `json:"pss_source_mib"`
	CgroupPerClone  float64            `json:"cgroup_memory_per_clone_mib"`
	MemoryAvailable bool               `json:"memory_measured"`
}

type DensityResult struct {
	Load              string  `json:"load_at_start"`
	Image             string  `json:"image"`
	Running           int     `json:"running"`
	StoppedBecause    string  `json:"stopped_because"`
	PSSPerSandboxMiB  float64 `json:"pss_per_sandbox_mib"`
	AvailableStartMiB float64 `json:"mem_available_start_mib"`
	AvailableEndMiB   float64 `json:"mem_available_end_mib"`
	UsedPerSandboxMiB float64 `json:"mem_available_drop_per_sandbox_mib"`
	Extrapolated      int     `json:"extrapolated_to_host_limit"`
	CreateSeries      Series  `json:"create_and_first_exec"`
}

// PauseResult is snapshot and resume for one workload in one place.
type PauseResult struct {
	Where       string  `json:"where"`        // "local disk" or "object store"
	TouchedMiB  int     `json:"touched_mib"`  // memory the workload touched
	ImageMiB    float64 `json:"image_mib"`    // as runsc reports it
	UploadedMiB float64 `json:"uploaded_mib"` // to the store, per pause
	Snapshot    Series  `json:"snapshot"`
	Resume      Series  `json:"resume"`
	WarmupMs    float64 `json:"warmup_pause_resume_ms"` // the discarded first round
	Load        string  `json:"load_at_start"`
}

// IOResult compares buffered and O_DIRECT checkpoint images for one size,
// on local disk (only sizes where buffered is safe).
type IOResult struct {
	TouchedMiB int    `json:"touched_mib"`
	Buffered   Series `json:"buffered_snapshot"`
	Direct     Series `json:"direct_snapshot"`
	BufferedRs Series `json:"buffered_resume"`
	DirectRs   Series `json:"direct_resume"`
}

type Results struct {
	IOCompare    []IOResult        `json:"io_compare,omitempty"`
	Started      time.Time         `json:"started"`
	Finished     time.Time         `json:"finished"`
	Env          Env               `json:"env"`
	EnvAfter     Env               `json:"env_after"`
	ColdStart    *Series           `json:"cold_start,omitempty"`
	ColdWarmupMs float64           `json:"cold_start_warmup_ms,omitempty"`
	ColdLoad     string            `json:"cold_start_load_at_start,omitempty"`
	Pauses       []PauseResult     `json:"pauses,omitempty"`
	Fork         []ForkResult      `json:"fork,omitempty"`
	ForkLoad     string            `json:"fork_load_at_start,omitempty"`
	Density      []DensityResult   `json:"density,omitempty"`
	Terminal     map[string]Series `json:"terminal,omitempty"`
	TerminalLoad string            `json:"terminal_load_at_start,omitempty"`
	Notes        []string          `json:"notes,omitempty"`
}

func (r *Results) note(f string, a ...any) {
	msg := fmt.Sprintf(f, a...)
	r.Notes = append(r.Notes, msg)
	log.Print("note: " + msg)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// ---- the private daemons ----

type benchDaemon struct {
	name string
	m    *daemon.Manager
	c    *client.Client
	srv  *http.Server
	reg  *registry.Registry
}

// ioMode records how checkpoint images are written and read.
var ioMode string

// daemonLog collects the private daemons' logs in the output directory, so
// a failure can be diagnosed afterwards (v1 discarded them).
var daemonLog struct {
	sync.Mutex
	f *os.File
}

func logTo(name string) func(string, ...any) {
	return func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		collectPhases(msg)
		daemonLog.Lock()
		defer daemonLog.Unlock()
		if daemonLog.f != nil {
			fmt.Fprintf(daemonLog.f, "%s %s: %s\n", time.Now().Format("15:04:05.000"), name, msg)
		}
	}
}

// Fork phases: the daemon logs each clone's, "(registry 3ms, network 0ms,
// restore 80ms, agent 12ms, finish 4ms)"; they're gathered per fork size.
var phaseSink struct {
	sync.Mutex
	n       int // the fork size being measured; 0: not collecting
	samples map[int]map[string][]float64
}

var phaseLine = regexp.MustCompile(`\(registry (\d+)ms, network (\d+)ms, restore (\d+)ms, agent (\d+)ms, finish (\d+)ms\)$`)

var phaseNames = []string{"registry", "network", "restore", "agent", "finish"}

func collectPhases(msg string) {
	m := phaseLine.FindStringSubmatch(msg)
	if m == nil {
		return
	}
	phaseSink.Lock()
	defer phaseSink.Unlock()
	if phaseSink.n == 0 {
		return
	}
	if phaseSink.samples == nil {
		phaseSink.samples = map[int]map[string][]float64{}
	}
	if phaseSink.samples[phaseSink.n] == nil {
		phaseSink.samples[phaseSink.n] = map[string][]float64{}
	}
	for i, name := range phaseNames {
		v, _ := strconv.ParseFloat(m[i+1], 64)
		phaseSink.samples[phaseSink.n][name] = append(phaseSink.samples[phaseSink.n][name], v)
	}
}

func collectingPhases(n int) {
	phaseSink.Lock()
	phaseSink.n = n
	phaseSink.Unlock()
}

func phaseP50s(n int) map[string]float64 {
	phaseSink.Lock()
	defer phaseSink.Unlock()
	out := map[string]float64{}
	for name, v := range phaseSink.samples[n] {
		out[name] = summarize(v).P50
	}
	return out
}

func startDaemon(o opts, name string, st daemon.SnapshotStore, images map[string]daemon.Image) (*benchDaemon, error) {
	return startDaemonIO(o, name, "auto", st, images)
}

func startDaemonIO(o opts, name, io string, st daemon.SnapshotStore, images map[string]daemon.Image) (*benchDaemon, error) {
	dir := filepath.Join(o.dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b, err := gvisor.New(gvisor.Config{RunscPath: o.runsc, StateDir: filepath.Join(dir, "state"), AgentPath: o.agent, CgroupParent: o.cgroupParent, CheckpointIO: io})
	if err != nil {
		return nil, err
	}
	if ck, rs := b.DirectIO(); name == "local" {
		ioMode = fmt.Sprintf("auto: O_DIRECT for a sandbox holding more than 40%% of its memory limit (this runsc offers it: checkpoint %v, restore %v)", ck, rs)
	}
	reg, err := registry.Open(filepath.Join(dir, "registry.db"))
	if err != nil {
		return nil, err
	}
	m, err := daemon.New(context.Background(), daemon.Config{
		Backend: b, Registry: reg, Rootfs: o.rootfs, VCPUs: 1, MemMiB: 256, PidsMax: 1024,
		CheckpointDir: filepath.Join(dir, "checkpoints"), Images: images,
		Store: st, StoreEvict: st != nil, OnStop: daemon.OnStopDestroy,
		Logf: logTo(name),
	})
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "api.sock")
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: daemon.NewHandler(m), ConnContext: daemon.ConnContext}
	go srv.Serve(ln)
	return &benchDaemon{name: name, m: m, c: client.New(sock), srv: srv, reg: reg}, nil
}

func (d *benchDaemon) stop() {
	d.srv.Close()
	d.m.Close(context.Background()) // OnStopDestroy: nothing is left running
	d.reg.Close()
}

func (d *benchDaemon) exec(ctx context.Context, id string, args ...string) error {
	res, err := d.c.Exec(ctx, id, client.ExecRequest{Args: args, Timeout: 30 * time.Second})
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("exit %d", res.Code)
	}
	return err
}

// ---- measurements ----

func coldStart(ctx context.Context, d *benchDaemon, n int) (Series, float64, error) {
	var out []float64
	warm := -1.0
	for i := -1; i < n; i++ { // round -1 is a warm-up, reported but not counted
		t0 := time.Now()
		sb, err := d.c.Create(ctx, api.CreateRequest{})
		if err != nil {
			return Series{}, 0, err
		}
		if err := d.exec(ctx, sb.ID, "true"); err != nil {
			return Series{}, 0, err
		}
		if took := ms(time.Since(t0)); i < 0 {
			warm = took
		} else {
			out = append(out, took)
		}
		_, _ = d.c.Destroy(ctx, sb.ID)
	}
	return series(out), warm, nil
}

// workload is what the paused sandbox holds: a counting shell loop, or a
// Python process that has written to every page of a buffer of the given
// size (so the memory is really in use, and in the image).
func workload(mib int) []string {
	if mib == 0 {
		return []string{"sh", "-c", "i=0; while :; do i=$((i+1)); echo $i; sleep 0.5; done"}
	}
	return []string{"python3", "-c", fmt.Sprintf(
		"import time\nb = bytearray(%d << 20)\nfor i in range(0, len(b), 4096): b[i] = 1\nprint('ready', flush=True)\ntime.sleep(1e9)", mib)}
}

// waitReady waits until a process's output contains "ready".
func waitReady(ctx context.Context, d *benchDaemon, id, proc string, within time.Duration) error {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		var out strings.Builder
		_, _ = d.c.Logs(ctx, id, proc, 0, false, &out)
		if strings.Contains(out.String(), "ready") {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("process %s in %s never said ready", proc, id)
}

// snapshotResume pauses and resumes one sandbox, holding the workload, n
// times after one discarded warm-up round.
func snapshotResume(ctx context.Context, d *benchDaemon, n, mib int) (pr PauseResult, err error) {
	pr.TouchedMiB, pr.Load = mib, loadAvg()
	sb, err := d.c.Create(ctx, api.CreateRequest{})
	if err != nil {
		return
	}
	defer d.c.Destroy(ctx, sb.ID)
	defer func() { // a failure: keep the sandbox's own history for diagnosis
		if err != nil {
			logHistory(ctx, d, sb.ID)
		}
	}()
	proc, err := d.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: workload(mib)})
	if err != nil {
		return
	}
	if mib > 0 {
		if err = waitReady(ctx, d, sb.ID, proc.ID, 60*time.Second); err != nil {
			return
		}
	}
	// What actually went to the store: the history records each upload's
	// size (the image plus the agent binary it carries, Day 11).
	defer func() {
		evs, _ := d.c.Events(ctx, sb.ID)
		for _, ev := range evs {
			if mib, ok := uploadedMiB(ev.Detail); ok {
				pr.UploadedMiB = mib
			}
		}
	}()
	var snaps, resumes []float64
	for i := -1; i < n; i++ { // round -1 is a warm-up
		t0 := time.Now()
		ck, err2 := d.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{})
		if err2 != nil {
			return pr, fmt.Errorf("checkpoint %d: %w", i, err2)
		}
		snap := ms(time.Since(t0))
		pr.ImageMiB = float64(ck.ImageBytes) / (1 << 20)
		t1 := time.Now()
		if _, err2 := d.c.Resume(ctx, sb.ID, ""); err2 != nil {
			return pr, fmt.Errorf("resume %d: %w", i, err2)
		}
		if err2 := d.exec(ctx, sb.ID, "true"); err2 != nil {
			return pr, err2
		}
		res := ms(time.Since(t1))
		if i < 0 {
			pr.WarmupMs = snap + res
			continue
		}
		snaps, resumes = append(snaps, snap), append(resumes, res)
	}
	pr.Snapshot, pr.Resume = series(snaps), series(resumes)
	return pr, nil
}

// uploadedMiB reads the size from the daemon's history note for an upload,
// "uploaded ck-… to the store: 4.9 MiB in 247ms".
func uploadedMiB(detail string) (float64, bool) {
	rest, ok := strings.CutPrefix(detail, "uploaded ")
	if !ok {
		return 0, false
	}
	_, after, ok := strings.Cut(rest, " to the store: ")
	if !ok {
		return 0, false
	}
	num, unit, ok := strings.Cut(after, " ")
	if !ok || !strings.HasPrefix(unit, "MiB") {
		return 0, false
	}
	v, err := strconv.ParseFloat(num, 64)
	return v, err == nil
}

// logHistory copies a sandbox's history (states, notes, failures) into the
// daemons' log: a failure's details live there, not in the daemon's own log.
func logHistory(ctx context.Context, d *benchDaemon, id string) {
	evs, err := d.c.Events(ctx, id)
	logf := logTo(d.name)
	if err != nil {
		logf("%s: history unavailable: %v", id, err)
		return
	}
	logf("%s: its history, after a failure:", id)
	for _, ev := range evs {
		logf("  %s  %s -> %s  %s", ev.At.Format("15:04:05.000"), ev.From, ev.To, ev.Detail)
	}
}

func loadAvg() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(b))[:3], " ")
}

// cgroupDir is where a sandbox's processes are on the host.
func (o opts) cgroupDir(id string) string {
	return filepath.Join(o.cgroupRoot, o.cgroupParent, id)
}

// pssMiB sums the PSS of every process in a sandbox's cgroup (and below).
// PSS divides shared pages among their sharers: the honest per-sandbox cost.
func (o opts) pssMiB(id string) (float64, error) {
	var pids []string
	err := filepath.Walk(o.cgroupDir(id), func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Name() == "cgroup.procs" {
			b, err := os.ReadFile(p)
			if err == nil {
				pids = append(pids, strings.Fields(string(b))...)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if len(pids) == 0 {
		return 0, fmt.Errorf("no processes in %s", o.cgroupDir(id))
	}
	total := 0.0
	for _, pid := range pids {
		kb, err := pssOfPID(filepath.Join("/proc", pid, "smaps_rollup"))
		if err == nil {
			total += kb
		}
	}
	return total / 1024, nil
}

func pssOfPID(path string) (float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return parsePss(f)
}

// parsePss reads the "Pss:" line of smaps_rollup, in kB.
func parsePss(r interface{ Read([]byte) (int, error) }) (float64, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "Pss:" {
			return strconv.ParseFloat(f[1], 64)
		}
	}
	return 0, fmt.Errorf("no Pss line")
}

func (o opts) cgroupMemMiB(id string) (float64, error) {
	b, err := os.ReadFile(filepath.Join(o.cgroupDir(id), "memory.current"))
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	return v / (1 << 20), err
}

// fork measures the fork call through every clone answering an exec, with
// the clones queried in parallel, and each clone's memory.
func fork(ctx context.Context, o opts, d *benchDaemon, ns []int, runs int, r *Results) error {
	src, err := d.c.Create(ctx, api.CreateRequest{})
	if err != nil {
		return err
	}
	defer d.c.Destroy(ctx, src.ID)
	if _, err := d.c.StartProcess(ctx, src.ID, api.ProcStartRequest{Args: []string{"sh", "-c", "i=0; while :; do i=$((i+1)); echo $i; sleep 0.5; done"}}); err != nil {
		return err
	}
	for _, n := range ns {
		var samples []float64
		res := ForkResult{N: n}
		collectingPhases(n)
		for run := 0; run < runs; run++ {
			t0 := time.Now()
			clones, err := d.c.Fork(ctx, src.ID, api.ForkRequest{Count: n, Force: true})
			if err != nil {
				return fmt.Errorf("fork %d: %w", n, err)
			}
			var wg sync.WaitGroup
			errs := make(chan error, len(clones))
			for _, cl := range clones {
				wg.Add(1)
				go func(id string) {
					defer wg.Done()
					if err := d.exec(ctx, id, "true"); err != nil {
						errs <- err
					}
				}(cl.ID)
			}
			wg.Wait()
			samples = append(samples, ms(time.Since(t0)))
			select {
			case err := <-errs:
				return fmt.Errorf("a clone of a %d-fork didn't answer: %w", n, err)
			default:
			}
			if run == runs-1 { // memory on the last run, all clones still up
				time.Sleep(time.Second) // let restores settle
				var pss, cg float64
				ok := true
				for _, cl := range clones {
					p, err := o.pssMiB(cl.ID)
					c, err2 := o.cgroupMemMiB(cl.ID)
					if err != nil || err2 != nil {
						ok = false
						break
					}
					pss += p
					cg += c
				}
				if ok {
					res.PSSPerCloneMiB, res.CgroupPerClone = pss/float64(len(clones)), cg/float64(len(clones))
					res.PSSSourceMiB, _ = o.pssMiB(src.ID)
					res.MemoryAvailable = true
				}
			}
			for _, cl := range clones {
				_, _ = d.c.Destroy(ctx, cl.ID)
			}
		}
		res.Series = series(samples)
		collectingPhases(0)
		res.PhaseP50 = phaseP50s(n)
		r.Fork = append(r.Fork, res)
		log.Printf("fork %2d: p50 %.0f ms, %.1f MiB PSS per clone", n, res.Series.Stats.P50, res.PSSPerCloneMiB)
	}
	return nil
}

func memAvailableMiB() float64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemAvailable:" {
			kb, _ := strconv.ParseFloat(f[1], 64)
			return kb / 1024
		}
	}
	return 0
}

// chromium keeps a headless Chromium open on a page, then says ready: a
// browser sandbox's real cost is the browser running, not its files.
const chromium = `import time
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(args=["--disable-dev-shm-usage"])
    page = b.new_page()
    page.set_content("<h1>sbx density</h1><p>" + "text " * 2000 + "</p>")
    print("ready", flush=True)
    time.sleep(1e9)`

// density creates sandboxes, each answering an exec (and, for the browser
// image, running Chromium with a page open), until a share of the memory
// available at the start is used (or a cap): filling the host for real
// could take everything else on it down. It reports the count reached and,
// separately labeled, the extrapolation to the host's limit.
func density(ctx context.Context, o opts, d *benchDaemon, image string, r *Results) (DensityResult, error) {
	res := DensityResult{Image: "base, idle", Load: loadAvg()}
	if image != "" {
		res.Image = image + ", Chromium running a page"
	}
	res.AvailableStartMiB = memAvailableMiB()
	budget := res.AvailableStartMiB * o.budget
	var ids []string
	var creates []float64
	defer func() {
		for _, id := range ids {
			_, _ = d.c.Destroy(ctx, id)
		}
	}()
	for {
		if len(ids) >= o.densityMax {
			res.StoppedBecause = fmt.Sprintf("the cap of %d sandboxes", o.densityMax)
			break
		}
		if used := res.AvailableStartMiB - memAvailableMiB(); used > budget {
			res.StoppedBecause = fmt.Sprintf("the budget: %.0f%% of the memory available at the start", o.budget*100)
			break
		}
		t0 := time.Now()
		sb, err := d.c.Create(ctx, api.CreateRequest{Image: image})
		if err != nil {
			res.StoppedBecause = "a create failed: " + err.Error()
			break
		}
		ids = append(ids, sb.ID)
		if err := d.exec(ctx, sb.ID, "true"); err != nil {
			res.StoppedBecause = "an exec failed: " + err.Error()
			break
		}
		if image != "" {
			p, err := d.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"python3", "-c", chromium}})
			if err == nil {
				err = waitReady(ctx, d, sb.ID, p.ID, 90*time.Second)
			}
			if err != nil {
				res.StoppedBecause = "Chromium didn't start: " + err.Error()
				break
			}
		}
		creates = append(creates, ms(time.Since(t0)))
	}
	time.Sleep(2 * time.Second) // let the last ones settle
	res.Running = len(creates)
	res.AvailableEndMiB = memAvailableMiB()
	res.CreateSeries = series(creates)
	var pss float64
	measured := 0
	for _, id := range ids {
		if p, err := o.pssMiB(id); err == nil {
			pss += p
			measured++
		}
	}
	if measured > 0 {
		res.PSSPerSandboxMiB = pss / float64(measured)
	}
	if res.Running > 0 {
		res.UsedPerSandboxMiB = (res.AvailableStartMiB - res.AvailableEndMiB) / float64(res.Running)
	}
	if res.UsedPerSandboxMiB > 0 {
		res.Extrapolated = int(res.AvailableStartMiB / res.UsedPerSandboxMiB)
	}
	log.Printf("density %s: %d running (stopped at %s), %.1f MiB PSS each, extrapolated %d", res.Image, res.Running, res.StoppedBecause, res.PSSPerSandboxMiB, res.Extrapolated)
	return res, nil
}

// chanWriter delivers a session's output as it arrives.
type chanWriter chan []byte

func (c chanWriter) Write(p []byte) (int, error) {
	c <- append([]byte(nil), p...)
	return len(p), nil
}

// settle drains output until none has arrived for quiet.
func settle(ch chanWriter, quiet time.Duration) {
	for {
		select {
		case <-ch:
		case <-time.After(quiet):
			return
		}
	}
}

// keystrokes types n characters into a shell session (reattaching to
// session if given) and times each from sending it to its echo arriving.
// It returns the session's ID, detached, for the next reattach.
func keystrokes(ctx context.Context, d *benchDaemon, id, session string, n int) ([]float64, string, error) {
	conn, err := d.c.Shell(ctx, id, client.ShellOptions{Cols: 80, Rows: 24, SessionID: session})
	if err != nil {
		return nil, "", err
	}
	ch := make(chanWriter, 4096)
	done := make(chan struct{})
	go func() { _, _ = conn.Run(ch); close(done) }()
	settle(ch, 300*time.Millisecond) // the prompt, or a reattach's replay
	var out []float64
	for i := 0; i < n; i++ {
		t0 := time.Now()
		if _, err := conn.Write([]byte("x")); err != nil {
			return nil, "", err
		}
		deadline := time.After(5 * time.Second)
	wait:
		for {
			select {
			case b := <-ch:
				if strings.Contains(string(b), "x") {
					out = append(out, ms(time.Since(t0)))
					break wait
				}
			case <-deadline:
				return nil, "", fmt.Errorf("keystroke %d never echoed", i)
			}
		}
	}
	_, _ = conn.Write([]byte{0x15}) // Ctrl-U: clear the typed line
	settle(ch, 100*time.Millisecond)
	sid := conn.SessionID
	_ = conn.Detach()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = conn.Close()
	}
	return out, sid, nil
}

func terminal(ctx context.Context, d *benchDaemon, keys, cycles int, r *Results) (running, resumed Series, err error) {
	sb, err := d.c.Create(ctx, api.CreateRequest{})
	if err != nil {
		return
	}
	defer d.c.Destroy(ctx, sb.ID)
	run, session, err := keystrokes(ctx, d, sb.ID, "", keys)
	if err != nil {
		return
	}
	var first []float64
	for i := 0; i < cycles; i++ {
		if _, err = d.c.Checkpoint(ctx, sb.ID, api.CheckpointRequest{}); err != nil {
			return
		}
		if _, err = d.c.Resume(ctx, sb.ID, ""); err != nil {
			return
		}
		var one []float64
		one, next, kerr := keystrokes(ctx, d, sb.ID, session, 1)
		if kerr != nil {
			// The session should survive a resume (it does on gVisor, Day
			// 11). If it didn't, measure on a fresh one, and say so: a
			// number must never quietly mean something else.
			r.note("cycle %d: the shell session didn't survive the resume (%v); measured on a new session", i+1, kerr)
			if one, next, err = keystrokes(ctx, d, sb.ID, "", 1); err != nil {
				return
			}
		}
		session = next
		first = append(first, one...)
	}
	return series(run), series(first), nil
}

// ---- the object store ----

func storeCredentials() (key, secret string) {
	key, secret = os.Getenv("SBX_S3_ACCESS_KEY"), os.Getenv("SBX_S3_SECRET_KEY")
	if key != "" {
		return
	}
	b, err := os.ReadFile("/etc/sbx/sbxd.env")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "SBX_S3_ACCESS_KEY="); ok {
			key = strings.Trim(v, `"`)
		}
		if v, ok := strings.CutPrefix(line, "SBX_S3_SECRET_KEY="); ok {
			secret = strings.Trim(v, `"`)
		}
	}
	return
}

func run(o opts) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root (gVisor, and reading each sandbox's memory from /proc)")
	}
	if o.runsc == "" {
		return fmt.Errorf("runsc not found: install gVisor, or pass -runsc")
	}
	ctx := context.Background()
	r := &Results{Started: time.Now(), Terminal: map[string]Series{}}
	r.Env = environment(o)
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}
	if f, err := os.Create(filepath.Join(o.out, "daemons.log")); err == nil {
		daemonLog.f = f
		defer f.Close()
	}
	// A run that stops early still writes what it measured, and why it stopped.
	err := measure(ctx, o, r)
	if err != nil {
		r.note("the run stopped early: %v (see daemons.log)", err)
	}
	r.Finished = time.Now()
	r.EnvAfter = environment(o)
	r.Env.CheckpointIO = ioMode
	if werr := write(o, r); werr != nil {
		return werr
	}
	return err
}

func measure(ctx context.Context, o opts, r *Results) error {
	_ = os.RemoveAll(o.dir)
	defer os.RemoveAll(o.dir)
	images := map[string]daemon.Image{}
	if o.browserRootfs != "" {
		images["browser"] = daemon.Image{Rootfs: o.browserRootfs, MemMiB: 2048}
	}
	local, err := startDaemon(o, "local", nil, images)
	if err != nil {
		return fmt.Errorf("starting the local daemon: %w", err)
	}
	defer local.stop()

	if o.want("cold") {
		log.Printf("cold start: %d runs (+1 warm-up)", o.runs)
		r.ColdLoad = loadAvg()
		s, warm, err := coldStart(ctx, local, o.runs)
		if err != nil {
			return fmt.Errorf("cold start: %w", err)
		}
		r.ColdStart, r.ColdWarmupMs = &s, warm
	}
	if o.want("snapshot") {
		var remote *benchDaemon
		key, secret := storeCredentials()
		switch {
		case o.storeURL == "":
			r.note("the object store variants were skipped (-store is empty)")
		case key == "":
			r.note("the object store variants were skipped: no credentials (SBX_S3_* or /etc/sbx/sbxd.env)")
		default:
			c := &s3.Client{Endpoint: o.storeURL, AccessKey: key, SecretKey: secret}
			if err := c.MakeBucket(ctx, o.storeBucket); err != nil {
				return fmt.Errorf("the object store: %w", err)
			}
			st := &store.S3{Client: c, Bucket: o.storeBucket, Prefix: fmt.Sprintf("bench-%d/", time.Now().Unix())}
			if remote, err = startDaemon(o, "store", st, nil); err != nil {
				return err
			}
			defer remote.stop()
		}
		for _, mib := range o.memSizes {
			for _, d := range []*benchDaemon{local, remote} {
				if d == nil {
					continue
				}
				where := map[string]string{"local": "local disk", "store": "object store"}[d.name]
				log.Printf("snapshot and resume, %s, %d MiB touched: %d runs (+1 warm-up)", where, mib, o.runs)
				pr, err := snapshotResume(ctx, d, o.runs, mib)
				if err != nil {
					return fmt.Errorf("%s, %d MiB: %w", where, mib, err)
				}
				pr.Where = where
				r.Pauses = append(r.Pauses, pr)
			}
		}
	}
	if o.want("io") {
		for _, mib := range []int{0, 64} {
			res := IOResult{TouchedMiB: mib}
			for _, io := range []string{"buffered", "direct"} {
				d, err := startDaemonIO(o, "io-"+io, io, nil, nil)
				if err != nil {
					return err
				}
				log.Printf("checkpoint I/O, %s, %d MiB touched: %d runs (+1 warm-up)", io, mib, o.runs)
				pr, err := snapshotResume(ctx, d, o.runs, mib)
				d.stop()
				if err != nil {
					return fmt.Errorf("%s I/O, %d MiB: %w", io, mib, err)
				}
				if io == "buffered" {
					res.Buffered, res.BufferedRs = pr.Snapshot, pr.Resume
				} else {
					res.Direct, res.DirectRs = pr.Snapshot, pr.Resume
				}
			}
			r.IOCompare = append(r.IOCompare, res)
		}
	}
	if o.want("fork") {
		log.Printf("fork: N = %v, %d runs each", o.forkNs, o.forkRuns)
		r.ForkLoad = loadAvg()
		if err := fork(ctx, o, local, o.forkNs, o.forkRuns, r); err != nil {
			return err
		}
		if len(r.Fork) > 0 && !r.Fork[0].MemoryAvailable {
			r.note("memory per sandbox wasn't measured: no processes found under %s", o.cgroupDir("<id>"))
		}
	}
	if o.want("terminal") {
		log.Printf("terminal round trip: %d keystrokes running, %d just resumed", o.keys, o.resumedKeys)
		r.TerminalLoad = loadAvg()
		run, resumed, err := terminal(ctx, local, o.keys, o.resumedKeys, r)
		if err != nil {
			return fmt.Errorf("terminal: %w", err)
		}
		r.Terminal["running"], r.Terminal["just resumed"] = run, resumed
	}
	// Density last: it loads the machine more than anything else, and what
	// runs after it would be measured under that load.
	if o.want("density") {
		res, err := density(ctx, o, local, "", r)
		if err != nil {
			return err
		}
		r.Density = append(r.Density, res)
		if o.browserRootfs != "" {
			time.Sleep(10 * time.Second) // let the first round's teardown settle
			res, err := density(ctx, o, local, "browser", r)
			if err != nil {
				return err
			}
			r.Density = append(r.Density, res)
		} else {
			r.note("no browser image: density was measured for the base image only")
		}
	}
	return nil
}

// ---- the machine's conditions ----

type Env struct {
	Time          time.Time `json:"time"`
	CPU           string    `json:"cpu"`
	CPUs          int       `json:"cpus"`
	MemTotalMiB   float64   `json:"mem_total_mib"`
	MemAvailMiB   float64   `json:"mem_available_mib"`
	Kernel        string    `json:"kernel"`
	Virtualized   string    `json:"virtualized"`
	Governor      string    `json:"cpu_governor"`
	LoadAvg       string    `json:"loadavg"`
	TopCPU        []string  `json:"top_cpu"`
	Runsc         string    `json:"runsc"`
	Platform      string    `json:"platform"`
	Go            string    `json:"go"`
	Commit        string    `json:"sbx_commit"`
	Store         string    `json:"store"`
	DirFilesystem string    `json:"bench_dir_filesystem"`
	CheckpointIO  string    `json:"checkpoint_io"`
	FsyncMs       float64   `json:"fsync_p50_ms"`
	Rootfs        string    `json:"rootfs"`
	BrowserRootfs string    `json:"browser_rootfs,omitempty"`
}

func firstLine(b []byte) string { return strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0]) }

func environment(o opts) Env {
	e := Env{Time: time.Now(), CPUs: runtime.NumCPU(), Go: runtime.Version(), Rootfs: o.rootfs, BrowserRootfs: o.browserRootfs}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "model name" && e.CPU == "" {
				e.CPU = strings.TrimSpace(v)
			}
		}
		e.Virtualized = "no hypervisor flag in /proc/cpuinfo"
		if strings.Contains(string(b), " hypervisor") {
			e.Virtualized = "yes: this host is itself a VM (hypervisor flag)"
		}
	}
	if out, err := exec.Command("systemd-detect-virt").Output(); err == nil {
		e.Virtualized += "; systemd-detect-virt: " + firstLine(out)
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "MemTotal:" {
				kb, _ := strconv.ParseFloat(f[1], 64)
				e.MemTotalMiB = kb / 1024
			}
		}
	}
	e.MemAvailMiB = memAvailableMiB()
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		e.Kernel = firstLine(out)
	}
	if b, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"); err == nil {
		e.Governor = firstLine(b)
	} else {
		e.Governor = "not exposed (no cpufreq: typical of a VM)"
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		e.LoadAvg = firstLine(b)
	}
	if out, err := exec.Command("ps", "-eo", "pcpu,comm", "--sort=-pcpu", "--no-headers").Output(); err == nil {
		for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if i == 5 {
				break
			}
			e.TopCPU = append(e.TopCPU, strings.Join(strings.Fields(line), " "))
		}
	}
	if out, err := exec.Command(o.runsc, "--version").Output(); err == nil {
		e.Runsc = strings.Join(strings.Fields(firstLine(out)), " ")
	}
	e.Platform = "systrap (runsc's default; sbx passes no --platform)"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				e.Commit = s.Value
			}
			if s.Key == "vcs.modified" && s.Value == "true" {
				e.Commit += " (with uncommitted changes)"
			}
		}
	}
	if out, err := exec.Command("weed", "version").Output(); err == nil {
		e.Store = "SeaweedFS: " + firstLine(out) + " at " + o.storeURL
	} else if o.storeURL != "" {
		e.Store = o.storeURL
	}
	if e.Commit == "" { // a build without version-control stamping
		// safe.directory: run as root in a user's repository, git refuses
		// to read it otherwise (it did, on Day 23: "unknown").
		if out, err := exec.Command("git", "-c", "safe.directory=*", "rev-parse", "--short", "HEAD").Output(); err == nil {
			e.Commit = firstLine(out) + " (from git in the current directory)"
			if out, err := exec.Command("git", "-c", "safe.directory=*", "status", "--porcelain").Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
				e.Commit += ", with uncommitted changes"
			}
		} else {
			e.Commit = "unknown"
		}
	}
	e.FsyncMs = fsyncP50(filepath.Dir(o.dir))
	// findmnt names the filesystem as mounted (stat -f calls ext4 "ext2/ext3").
	if out, err := exec.Command("findmnt", "-n", "-o", "FSTYPE,TARGET", "--target", filepath.Dir(o.dir)).Output(); err == nil {
		if f := strings.Fields(firstLine(out)); len(f) == 2 {
			e.DirFilesystem = f[0] + " (mounted at " + f[1] + ")"
		}
	}
	return e
}

// fsyncP50 times writing 4 KiB and fsyncing it, 50 times, in dir: what a
// durable write costs on this filesystem (a VM's disk can make it slow).
func fsyncP50(dir string) float64 {
	f, err := os.CreateTemp(dir, ".sbx-bench-fsync-")
	if err != nil {
		return 0
	}
	defer os.Remove(f.Name())
	defer f.Close()
	buf := make([]byte, 4096)
	var samples []float64
	for i := 0; i < 50; i++ {
		t0 := time.Now()
		if _, err := f.WriteAt(buf, int64(i)*4096); err != nil {
			return 0
		}
		if err := f.Sync(); err != nil {
			return 0
		}
		samples = append(samples, ms(time.Since(t0)))
	}
	return summarize(samples).P50
}

// ---- output ----

func write(o opts, r *Results) error {
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(o.out, "results.json"), b, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(o.out, "report.md"), []byte(report(r)), 0o644); err != nil {
		return err
	}
	log.Printf("wrote %s and %s", filepath.Join(o.out, "results.json"), filepath.Join(o.out, "report.md"))
	return nil
}
