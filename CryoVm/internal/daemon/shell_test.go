package daemon

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

type screen struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *screen) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		ok := strings.Contains(s.buf.String(), want)
		s.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Fatalf("never saw %q; screen:\n%s", want, s.buf.String())
}

type attached struct {
	conn *client.ShellConn
	scr  *screen
	done chan client.ShellEnd
}

func attach(t *testing.T, c *client.Client, id string, opts client.ShellOptions) *attached {
	t.Helper()
	if opts.SessionID == "" && len(opts.Command) == 0 {
		opts.Command = []string{"sh"}
	}
	conn, err := c.Shell(tctx(t), id, opts)
	if err != nil {
		t.Fatalf("shell: %v", err)
	}
	a := &attached{conn: conn, scr: &screen{}, done: make(chan client.ShellEnd, 1)}
	go func() {
		end, _ := conn.Run(a.scr)
		a.done <- end
	}()
	return a
}

func (a *attached) typ(t *testing.T, s string) {
	t.Helper()
	if _, err := a.conn.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
}

func (a *attached) end(t *testing.T) client.ShellEnd {
	t.Helper()
	select {
	case e := <-a.done:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("attachment did not end")
		return client.ShellEnd{}
	}
}

// A computed marker: the terminal echoes "$((n+1))", only output shows the sum.
func marker(n int) (typed, shown string) {
	return fmt.Sprintf("echo M-$((%d+1))\n", n), fmt.Sprintf("M-%d", n+1)
}

func TestShellOverHTTP(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "sh"})

	a := attach(t, e.c, sb.ID, client.ShellOptions{Cols: 90, Rows: 33})
	if !a.conn.Created || !strings.HasPrefix(a.conn.SessionID, "s-") {
		t.Fatalf("new session: %+v", a.conn)
	}
	a.typ(t, "test -t 1 && echo TTY-$((1+1)); stty size\n")
	a.scr.waitFor(t, "TTY-2")
	a.scr.waitFor(t, "33 90")
	a.typ(t, "cd /tmp\n")
	typed, shown := marker(10)
	a.typ(t, typed)
	a.scr.waitFor(t, shown)
	if err := a.conn.Detach(); err != nil {
		t.Fatal(err)
	}
	if end := a.end(t); !end.Detached {
		t.Fatalf("want detached: %+v", end)
	}

	b := attach(t, e.c, sb.ID, client.ShellOptions{SessionID: a.conn.SessionID})
	if b.conn.Created {
		t.Fatal("reattach created a new session")
	}
	b.scr.waitFor(t, "TTY-2") // the scrollback came back
	b.typ(t, "echo cwd=$(pwd)\n")
	b.scr.waitFor(t, "cwd=/tmp")

	list, err := e.c.Sessions(tctx(t), sb.ID)
	if err != nil || len(list) != 1 || !list[0].Attached {
		t.Fatalf("sessions: %+v %v", list, err)
	}
	if err := e.c.KillSession(tctx(t), sb.ID, b.conn.SessionID); err != nil {
		t.Fatal(err)
	}
	if end := b.end(t); !end.Exited {
		t.Fatalf("killed session should end as exited: %+v", end)
	}
	if list, _ := e.c.Sessions(tctx(t), sb.ID); len(list) != 0 {
		t.Fatalf("still listed: %+v", list)
	}
}

// The client crashes: no detach, the connection just closes. The daemon
// must detach on its behalf so the session survives.
func TestShellSurvivesAVanishingClient(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "vanish"})
	a := attach(t, e.c, sb.ID, client.ShellOptions{})
	a.typ(t, "export KEPT=yes\n")
	typed, shown := marker(20)
	a.typ(t, typed)
	a.scr.waitFor(t, shown)
	a.conn.Close()

	// The daemon must notice and detach on the client's behalf. (Without
	// this check, the reattach below would simply displace a stale
	// attachment, and the test would pass even if the daemon never noticed.)
	detached := false
	deadline := time.Now().Add(3 * time.Second)
	for !detached && time.Now().Before(deadline) {
		list, _ := e.c.Sessions(tctx(t), sb.ID)
		detached = len(list) == 1 && !list[0].Attached
		time.Sleep(20 * time.Millisecond)
	}
	if !detached {
		t.Fatal("the daemon never detached the vanished client")
	}
	b := attach(t, e.c, sb.ID, client.ShellOptions{SessionID: a.conn.SessionID})
	b.typ(t, "echo kept=$KEPT\n")
	b.scr.waitFor(t, "kept=yes")
}

func TestShellExitCodeOverHTTP(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "exit"})
	a := attach(t, e.c, sb.ID, client.ShellOptions{})
	a.typ(t, "exit 6\n")
	if end := a.end(t); !end.Exited || end.Code != 6 {
		t.Fatalf("want exit 6: %+v", end)
	}
}

func TestShellErrorsBeforeTheUpgrade(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "err"})
	if _, err := e.c.Shell(tctx(t), "nope", client.ShellOptions{}); !errors.Is(err, client.ErrNotFound) {
		t.Errorf("unknown sandbox: want ErrNotFound, got %v", err)
	}
	if _, err := e.c.Shell(tctx(t), sb.ID, client.ShellOptions{SessionID: "s-nope"}); !errors.Is(err, client.ErrNotFound) {
		t.Errorf("unknown session: want ErrNotFound, got %v", err)
	}

	// A plain POST that doesn't ask to upgrade gets 426 Upgrade Required.
	conn, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /v1/sandboxes/%s/shell HTTP/1.1\r\nHost: sbxd\r\nContent-Length: 0\r\n\r\n", sb.ID)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Errorf("no Upgrade header: want 426, got %d", resp.StatusCode)
	}
}
