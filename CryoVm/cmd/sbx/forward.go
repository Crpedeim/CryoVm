package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

// ports shows what listens inside a sandbox: what forward can reach.
func ports(ctx context.Context, c *client.Client, args []string) error {
	if err := need(args, 1, "ports <id>"); err != nil {
		return err
	}
	list, err := c.Ports(ctx, args[0])
	if err != nil {
		return err
	}
	if len(list.Ports) == 0 {
		fmt.Fprintf(os.Stderr, "nothing in %s listens on a TCP port\n", args[0])
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PORT\tADDRESS\tPID\tCOMMAND")
	for _, p := range list.Ports {
		pid := "-"
		if p.PID > 0 {
			pid = strconv.Itoa(p.PID)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", p.Port, p.Addr, pid, p.Command)
	}
	if list.Truncated {
		fmt.Fprintln(tw, "...\t\t\t(more not shown)")
	}
	return tw.Flush()
}

// forwardSpec is one [LOCAL:]PORT argument: the port on this machine (0:
// any free one) and the port inside the sandbox.
type forwardSpec struct{ local, remote int }

func parseForward(s string) (forwardSpec, error) {
	bad := fmt.Errorf("%q: want PORT, LOCAL:PORT, or :PORT for any free local port", s)
	localStr, remoteStr, both := strings.Cut(s, ":")
	if !both {
		remoteStr = localStr // the same number on both sides
	}
	remote, err := strconv.Atoi(remoteStr)
	if err != nil || remote < 1 || remote > 65535 {
		return forwardSpec{}, bad
	}
	local := 0
	if localStr != "" {
		if local, err = strconv.Atoi(localStr); err != nil || local < 0 || local > 65535 {
			return forwardSpec{}, bad
		}
	}
	return forwardSpec{local: local, remote: remote}, nil
}

// forward serves ports inside a sandbox on this machine until Ctrl+C, the
// way ssh -L does: each connection to a local port becomes a connection to
// the port inside, through sbxd, which wakes the sandbox if it's asleep.
// The sandbox needs no network for it: the server inside may listen on its
// localhost alone.
//
//	sbx forward sbx-1a2b3c4d 8000        127.0.0.1:8000 → port 8000 inside
//	sbx forward sbx-1a2b3c4d 9000:8000   127.0.0.1:9000 → port 8000 inside
//	sbx forward sbx-1a2b3c4d :8000       any free local port → port 8000 inside
func forward(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1", "the local address to listen on; 0.0.0.0 lets other machines in too")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		return errors.New("want forward [-addr IP] <id> [LOCAL:]PORT...")
	}
	id := fs.Arg(0)
	var specs []forwardSpec
	for _, a := range fs.Args()[1:] {
		s, err := parseForward(a)
		if err != nil {
			return err
		}
		specs = append(specs, s)
	}
	sb, err := c.Get(ctx, id)
	if err != nil {
		return err
	}
	if sb.State.Terminal() {
		return fmt.Errorf("sandbox %s is %s", id, sb.State)
	}

	var lns []net.Listener
	defer func() {
		for _, ln := range lns {
			ln.Close()
		}
	}()
	for _, s := range specs {
		ln, err := net.Listen("tcp", net.JoinHostPort(*addr, strconv.Itoa(s.local)))
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("%w: give it another local port (LOCAL:%d), or :%d for any free one", err, s.remote, s.remote)
		}
		if err != nil {
			return err
		}
		lns = append(lns, ln)
	}

	// What listens inside now, to point out a port nothing serves yet. A
	// sleeping sandbox isn't woken just to look: its first connection will.
	listening, looked := map[int]bool{}, false
	if sb.State == api.Running {
		if list, err := c.Ports(ctx, id); err == nil {
			looked = true
			for _, p := range list.Ports {
				listening[p.Port] = true
			}
		}
	}
	// A browser retries at once and asks for many files: each reason a
	// connection was refused is said once in a while, not every time.
	var mu sync.Mutex
	said := map[string]time.Time{}
	refused := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if msg := err.Error(); time.Since(said[msg]) >= 10*time.Second {
			said[msg] = time.Now()
			fmt.Fprintf(os.Stderr, "sbx: %s\n", msg)
		}
	}
	for i, ln := range lns {
		note := ""
		if looked && !listening[specs[i].remote] {
			note = "  (nothing listens there yet)"
		}
		fmt.Printf("http://%s → port %d in %s%s\n", urlHost(ln.Addr()), specs[i].remote, id, note)
		go func(ln net.Listener, port int) { _ = c.ServePort(ln, id, port, refused) }(ln, specs[i].remote)
	}
	fmt.Fprintln(os.Stderr, "forwarding until Ctrl+C; the sandbox and its servers keep running after")
	<-ctx.Done()
	return nil
}

// urlHost is a listener's address as a browser should be pointed at it:
// one listening on every address is reached as localhost.
func urlHost(a net.Addr) string {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return a.String()
	}
	host := ta.IP.String()
	if ta.IP.IsUnspecified() {
		host = "localhost"
	}
	return net.JoinHostPort(host, strconv.Itoa(ta.Port))
}
