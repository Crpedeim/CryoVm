package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// connected starts a listener and the real in-process agent, and returns a
// live connection.
func connected(t *testing.T) *Conn {
	t.Helper()
	path := sockPath(t)
	l, err := Listen(path, "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	t.Cleanup(startGuest(t, "x", path))
	c, err := l.Conn(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// stampWriter records when each write arrived.
type stampWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	times []time.Time
}

func (w *stampWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.times = append(w.times, time.Now())
	return w.buf.Write(p)
}

func (w *stampWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// sleepers counts live `sleep <duration>` processes, matching the exact
// argument list. (A loose text match would also count any shell whose
// command line merely mentions the same text.)
func sleepers(duration string) int {
	want := "sleep\x00" + duration + "\x00"
	n := 0
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		cmd, err := os.ReadFile(filepath.Join(d, "cmdline"))
		if err == nil && string(cmd) == want {
			n++
		}
	}
	return n
}

func TestExecOutputAndExitCode(t *testing.T) {
	c := connected(t)
	var out, errb bytes.Buffer
	res, err := c.Exec(wait(t), ExecRequest{
		Args:   []string{"sh", "-c", "echo out; echo err >&2; exit 4"},
		Stdout: &out, Stderr: &errb,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 4 || out.String() != "out\n" || errb.String() != "err\n" {
		t.Fatalf("res=%+v stdout=%q stderr=%q", res, out.String(), errb.String())
	}
}

func TestExecStreamsWhileRunning(t *testing.T) {
	c := connected(t)
	var out stampWriter
	start := time.Now()
	res, err := c.Exec(wait(t), ExecRequest{
		Args: []string{"sh", "-c", "echo first; sleep 1; echo second"}, Stdout: &out,
	})
	total := time.Since(start)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if out.String() != "first\nsecond\n" || len(out.times) < 2 {
		t.Fatalf("output %q in %d writes", out.String(), len(out.times))
	}
	if first := out.times[0].Sub(start); first > total-500*time.Millisecond {
		t.Fatalf("first line arrived after %s of %s: output is buffered, not streamed", first, total)
	}
}

func TestConcurrentExecsKeepStreamsSeparate(t *testing.T) {
	c := connected(t)
	const n, lines = 10, 20
	var wg sync.WaitGroup
	outs := make([]bytes.Buffer, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			script := fmt.Sprintf("for k in $(seq %d); do echo tag%d; sleep 0.01; done", lines, i)
			res, err := c.Exec(wait(t), ExecRequest{Args: []string{"sh", "-c", script}, Stdout: &outs[i]})
			if err != nil || res.ExitCode != 0 {
				errs <- fmt.Errorf("exec %d: %+v %v", i, res, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for i := range outs {
		want := strings.Repeat(fmt.Sprintf("tag%d\n", i), lines)
		if outs[i].String() != want {
			t.Fatalf("exec %d got someone else's output:\n%s", i, outs[i].String())
		}
	}
}

func TestPingWhileExecStreams(t *testing.T) {
	c := connected(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.Exec(context.Background(), ExecRequest{Args: []string{"sh", "-c", "for k in $(seq 20); do echo x; sleep 0.05; done"}})
	}()
	for i := 0; i < 10; i++ {
		if d, err := c.Ping(wait(t)); err != nil || d > 200*time.Millisecond {
			t.Fatalf("ping during exec: %v %v", d, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	<-done
}

func TestExecTimeoutKillsWholeProcessGroup(t *testing.T) {
	c := connected(t)
	start := time.Now()
	res, err := c.Exec(wait(t), ExecRequest{
		Args:    []string{"sh", "-c", "sleep 37.5 & sleep 37.5; wait"},
		Timeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Signal == "" {
		t.Fatalf("want timed-out and signalled, got %+v", res)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("timeout took %s", took)
	}
	time.Sleep(100 * time.Millisecond)
	if n := sleepers("37.5"); n != 0 {
		t.Fatalf("%d sleep processes survived the kill: the background one escaped", n)
	}
}

func TestExecCancelViaContext(t *testing.T) {
	c := connected(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err := c.Exec(ctx, ExecRequest{Args: []string{"sleep", "38.5"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("cancel took %s", took)
	}
	time.Sleep(100 * time.Millisecond)
	if n := sleepers("38.5"); n != 0 {
		t.Fatal("cancelled command still running")
	}
}

func TestExecKilledWhenConnectionDrops(t *testing.T) {
	c := connected(t)
	go func() { _, _ = c.Exec(context.Background(), ExecRequest{Args: []string{"sleep", "39.5"}}) }()
	deadline := time.Now().Add(2 * time.Second)
	for sleepers("39.5") == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	c.Close()
	time.Sleep(300 * time.Millisecond)
	if n := sleepers("39.5"); n != 0 {
		t.Fatal("command outlived the connection that started it")
	}
}

func TestExecSignalNotFoundStdinEnvDir(t *testing.T) {
	c := connected(t)

	res, err := c.Exec(wait(t), ExecRequest{Args: []string{"sh", "-c", "kill -9 $$"}})
	if err != nil || res.ExitCode != -1 || res.Signal != "killed" {
		t.Errorf("killed by signal: %+v %v", res, err)
	}

	if _, err := c.Exec(wait(t), ExecRequest{Args: []string{"/no/such/program"}}); err == nil {
		t.Error("a missing program should be an error, not a result")
	}

	var out bytes.Buffer
	_, _ = c.Exec(wait(t), ExecRequest{Args: []string{"cat"}, Stdin: []byte("from stdin"), Stdout: &out})
	if out.String() != "from stdin" {
		t.Errorf("stdin: got %q", out.String())
	}

	out.Reset()
	_, _ = c.Exec(wait(t), ExecRequest{Args: []string{"sh", "-c", "echo $SBX_TEST_VAR; pwd"}, Env: []string{"SBX_TEST_VAR=hello", "PATH=" + os.Getenv("PATH")}, Dir: "/tmp", Stdout: &out})
	if out.String() != "hello\n/tmp\n" {
		t.Errorf("env and dir: got %q", out.String())
	}

	if _, err := c.Exec(wait(t), ExecRequest{Args: []string{"cat"}, Stdin: make([]byte, 1<<20)}); err == nil {
		t.Error("oversized stdin accepted")
	}
}

func TestExecLargeOutput(t *testing.T) {
	c := connected(t)
	var out bytes.Buffer
	res, err := c.Exec(wait(t), ExecRequest{Args: []string{"head", "-c", "3000000", "/dev/zero"}, Stdout: &out})
	if err != nil || res.ExitCode != 0 || out.Len() != 3_000_000 {
		t.Fatalf("got %d bytes, res=%+v err=%v", out.Len(), res, err)
	}
}

func TestExecReturnsDespiteBackgroundChild(t *testing.T) {
	c := connected(t)
	start := time.Now()
	res, err := c.Exec(wait(t), ExecRequest{Args: []string{"sh", "-c", "sleep 36.5 & echo started"}})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("exec waited %s for a background job holding its output open", took)
	}
}
