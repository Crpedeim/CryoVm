package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Nearest-rank percentiles: with 20 samples p99 is the largest; with 200,
// the 198th smallest. p50 is the ceil(n/2)-th smallest.
func TestSummarize(t *testing.T) {
	var twenty, twoHundred []float64
	for i := 20; i >= 1; i-- {
		twenty = append(twenty, float64(i))
	}
	for i := 1; i <= 200; i++ {
		twoHundred = append(twoHundred, float64(i))
	}
	if s := summarize(twenty); s.P50 != 10 || s.P99 != 20 || s.Min != 1 || s.Max != 20 || s.Mean != 10.5 || s.N != 20 {
		t.Fatalf("20 samples: %+v", s)
	}
	if s := summarize(twoHundred); s.P50 != 100 || s.P99 != 198 {
		t.Fatalf("200 samples: %+v", s)
	}
	if s := summarize(nil); s.N != 0 {
		t.Fatalf("no samples: %+v", s)
	}
}

func TestParsePss(t *testing.T) {
	rollup := `55c1c3a00000-7ffd5a5f6000 ---p 00000000 00:00 0                          [rollup]
Rss:               42116 kB
Pss:               19873 kB
Pss_Anon:          18000 kB
Shared_Clean:       3000 kB
`
	kb, err := parsePss(strings.NewReader(rollup))
	if err != nil || kb != 19873 {
		t.Fatalf("Pss: %v %v (Pss_Anon must not be mistaken for it)", kb, err)
	}
}

// The report fills the resume entry from the right measurements, says what
// resume offers honestly, and never prints an empty or impossible value.
func TestReport(t *testing.T) {
	r := &Results{Started: time.Now(), Finished: time.Now().Add(5 * time.Minute)}
	cold := series([]float64{48, 49, 50})
	r.ColdStart = &cold
	r.Pauses = []PauseResult{
		{Where: "local disk", TouchedMiB: 0, ImageMiB: 1.4, Snapshot: series([]float64{42}), Resume: series([]float64{66})},
		{Where: "object store", TouchedMiB: 0, ImageMiB: 1.4, UploadedMiB: 5.2, Snapshot: series([]float64{82}), Resume: series([]float64{88})},
		{Where: "object store", TouchedMiB: 128, ImageMiB: 130, UploadedMiB: 134, Snapshot: series([]float64{900}), Resume: series([]float64{700})},
	}
	r.Fork = []ForkResult{
		{N: 1, Series: series([]float64{120}), PSSPerCloneMiB: 35, CgroupPerClone: 18.8, MemoryAvailable: true},
		{N: 16, Series: series([]float64{400, 420}), PSSPerCloneMiB: 22.0, CgroupPerClone: 18.8, MemoryAvailable: true},
	}
	r.Density = []DensityResult{{Image: "base, idle", Running: 400, StoppedBecause: "the cap", PSSPerSandboxMiB: 16, UsedPerSandboxMiB: 17, Extrapolated: 1100}}
	r.Terminal = map[string]Series{"running": series([]float64{1, 2}), "just resumed": series([]float64{1})}
	out := report(r)
	for _, want := range []string{
		"from S3-compatible storage in **88 ms** (p50), within **39 ms** of starting an empty one (**49 ms**); **700 ms** for one holding 128 MiB",
		"resume's value is that everything comes back, not that it's quicker",
		"into **16** copies in **400 ms** at **22.0 MiB**",
		"One more clone's own memory (its cgroup's count) is 18.8 MiB",
		"| 128 MiB | object store | 130.0 | 134.0 |",
		"for n ≤ 100 it is the largest sample",
		"| base, idle | **400** |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report should contain %q", want)
		}
	}
	for _, bad := range []string{"NaN", "Inf", "%!"} {
		if strings.Contains(out, bad) {
			t.Errorf("the report contains %q", bad)
		}
	}
	if strings.Index(out, "## Terminal") > strings.Index(out, "## Density") {
		t.Error("density should come last, as it runs last")
	}
}

// A memory figure that wasn't measured must say so, never show as zero.
func TestReportNeverShowsAMissingNumberAsZero(t *testing.T) {
	r := &Results{Started: time.Now(), Finished: time.Now()}
	r.Fork = []ForkResult{{N: 4, Series: series([]float64{76})}}
	r.Density = []DensityResult{{Image: "base", Running: 8}}
	out := report(r)
	if strings.Contains(out, "0.0 MiB") || !strings.Contains(out, "[K] not measured") || !strings.Contains(out, "| not measured |") {
		t.Fatalf("missing memory numbers:\n%s", out)
	}
}

// The upload size comes from the daemon's history note, in its exact format.
// (v1 read the wrong word and got zero, which the report then silently left
// out: a test against the real format would have caught it.)
func TestUploadedMiB(t *testing.T) {
	note := fmt.Sprintf("uploaded %s to the store: %.1f MiB in %dms", "ck-42b71021", 4.9, 247) // as internal/daemon/snapshots.go writes it
	if v, ok := uploadedMiB(note); !ok || v != 4.9 {
		t.Fatalf("%q: %v %v", note, v, ok)
	}
	for _, other := range []string{"fetched ck-1 from the store: 4.9 MiB in 14ms", "uploaded", "upload of ck-1 to the store failed; it stays local: boom"} {
		if _, ok := uploadedMiB(other); ok {
			t.Errorf("%q isn't an upload note", other)
		}
	}
}

func TestReportSaysWhatWasntMeasured(t *testing.T) {
	r := &Results{Started: time.Now(), Finished: time.Now()}
	r.Pauses = []PauseResult{{Where: "object store", Resume: series([]float64{1}), Snapshot: series([]float64{1})}}
	r.Density = []DensityResult{{Image: "base, idle", Running: 3}}
	out := report(r)
	if !strings.Contains(out, "| not measured | **") || !strings.Contains(out, "not measurable (too little memory used to see)") || strings.Contains(out, "~0") {
		t.Fatalf("unmeasured values:\n%s", out)
	}
}

// Fork phases are parsed from the daemon's log line, in its exact format
// (internal/daemon/fork.go: "%s: forked from %s at %s in %s (%s)", with the
// phases' String). Only while a fork size is being measured.
func TestCollectPhases(t *testing.T) {
	line := fmt.Sprintf("%s: forked from %s at %s in %s (%s)", "sbx-1", "sbx-src", "ck-1", "160ms",
		"registry 3ms, network 0ms, restore 120ms, agent 30ms, finish 7ms")
	collectPhases(line) // not collecting: ignored
	collectingPhases(4)
	collectPhases(line)
	collectPhases("sbx-2: something else entirely")
	collectingPhases(0)
	got := phaseP50s(4)
	if got["registry"] != 3 || got["restore"] != 120 || got["agent"] != 30 || got["finish"] != 7 || len(got) != 5 {
		t.Fatalf("phases: %v", got)
	}
	if len(phaseP50s(1)) != 0 {
		t.Fatal("a line logged while not collecting must not count")
	}
}
