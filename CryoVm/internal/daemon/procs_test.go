package daemon

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

func TestProcessesOverHTTP(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "procs"})

	p, err := e.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"sh", "-c", "echo hello; echo oops >&2; exit 4"}})
	if err != nil || !strings.HasPrefix(p.ID, "p-") {
		t.Fatalf("start: %+v %v", p, err)
	}
	info, err := e.c.Wait(ctx, sb.ID, p.ID)
	if err != nil || info.Running || info.ExitCode != 4 {
		t.Fatalf("wait: %+v %v", info, err)
	}
	var out bytes.Buffer
	end, err := e.c.Logs(ctx, sb.ID, p.ID, 0, false, &out)
	if err != nil || out.String() != "hello\noops\n" || end.Next != 11 || !end.Exited {
		t.Fatalf("logs: %q %+v %v", out.String(), end, err)
	}
	out.Reset()
	if end, err := e.c.Logs(ctx, sb.ID, p.ID, 6, false, &out); err != nil || out.String() != "oops\n" || end.Next != 11 {
		t.Fatalf("logs from 6: %q %+v %v", out.String(), end, err)
	}

	list, err := e.c.Processes(ctx, sb.ID)
	if err != nil || len(list) != 1 || list[0].LogBytes != 11 {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := e.c.RemoveProcess(ctx, sb.ID, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.Process(ctx, sb.ID, p.ID); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("after remove: want ErrNotFound, got %v", err)
	}
}

// Follow streams through the HTTP layer as the process writes: the first
// line must arrive long before the process ends.
func TestFollowStreamsOverHTTP(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "follow"})
	p, _ := e.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"sh", "-c", "for i in 1 2 3; do echo tick$i; sleep 0.4; done"}})
	w := &firstWriteWriter{}
	start := time.Now()
	end, err := e.c.Logs(ctx, sb.ID, p.ID, 0, true, w)
	took := time.Since(start)
	if err != nil || !end.Exited || w.buf.String() != "tick1\ntick2\ntick3\n" {
		t.Fatalf("follow: %q %+v %v", w.buf.String(), end, err)
	}
	if w.first.Sub(start) > took-600*time.Millisecond {
		t.Fatalf("first line after %s of %s: buffered between agent and client", w.first.Sub(start), took)
	}
}

func TestProcessSignalsAndConflictsOverHTTP(t *testing.T) {
	e := start(t)
	ctx := tctx(t)
	sb, _ := e.c.Create(ctx, api.CreateRequest{ID: "sig"})
	p, _ := e.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"sleep", "30"}})
	if err := e.c.RemoveProcess(ctx, sb.ID, p.ID); !errors.Is(err, client.ErrConflict) {
		t.Fatalf("remove while running: want ErrConflict, got %v", err)
	}
	if err := e.c.Signal(ctx, sb.ID, p.ID, int(syscall.SIGTERM)); err != nil {
		t.Fatal(err)
	}
	info, err := e.c.Wait(ctx, sb.ID, p.ID)
	if err != nil || info.Signal != "terminated" {
		t.Fatalf("wait: %+v %v", info, err)
	}
	if err := e.c.Signal(ctx, sb.ID, p.ID, int(syscall.SIGTERM)); !errors.Is(err, client.ErrConflict) {
		t.Fatalf("signal after exit: want ErrConflict, got %v", err)
	}
	if _, err := e.c.StartProcess(ctx, sb.ID, api.ProcStartRequest{Args: []string{"no-such-program-xyz"}}); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("missing program: want ErrNotFound, got %v", err)
	}
	var out bytes.Buffer
	if _, err := e.c.Logs(ctx, sb.ID, "p-nope", 0, false, &out); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("logs of unknown process: want ErrNotFound (a real 404), got %v", err)
	}
}

// A client that stops waiting must not affect the process.
func TestAbandonedWaitLeavesTheProcessAlone(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "abandon"})
	p, _ := e.c.StartProcess(tctx(t), sb.ID, api.ProcStartRequest{Args: []string{"sh", "-c", "sleep 0.8; echo finished"}})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := e.c.Wait(ctx, sb.ID, p.ID); err == nil {
		t.Fatal("wait should have timed out")
	}
	info, err := e.c.Wait(tctx(t), sb.ID, p.ID)
	if err != nil || info.ExitCode != 0 {
		t.Fatalf("the process should finish normally: %+v %v", info, err)
	}
	var out bytes.Buffer
	if _, err := e.c.Logs(tctx(t), sb.ID, p.ID, 0, false, &out); err != nil || out.String() != "finished\n" {
		t.Fatalf("logs: %q %v", out.String(), err)
	}
}
