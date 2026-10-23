// sbx-mcp is sbx's MCP server (Day 21): it gives an AI agent tools to work
// in one sandbox. An MCP client starts it and talks over stdin and stdout:
//
//	claude mcp add sbx -- /path/to/sbx-mcp -sandbox agent -create -net
//
// -sandbox NAME binds the session to that sandbox; with -create, it's made
// the first time and reused after, so the agent's machine persists across
// sessions (sleeping when idle, waking on use). The binding is fixed for the
// whole session: no tool takes a sandbox ID, so none can reach another.
//
// The daemon's socket must be reachable by whoever runs this: start sbxd
// with -sock-group and add yourself to that group.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
	"github.com/Crpedeim/sbx/internal/mcp"
)

const version = "0.22.0"

func main() {
	// Stdout is the protocol: every log goes to stderr.
	log.SetOutput(os.Stderr)
	log.SetPrefix("sbx-mcp: ")
	sock := flag.String("sock", defaultSock(), "the daemon's socket")
	id := flag.String("sandbox", "", "the sandbox to bind to")
	create := flag.Bool("create", false, "create it if it doesn't exist (with no -sandbox: a new one each time)")
	image := flag.String("image", "", "when creating: a named image, e.g. browser")
	network := flag.Bool("net", false, "when creating: give it a network")
	mem := flag.Int("mem", 0, "when creating: memory in MiB (default: the daemon's or the image's)")
	flag.Parse()
	if *id == "" && !*create {
		log.Fatal("need -sandbox ID, or -create")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c := client.New(*sock)
	sb, err := bind(ctx, c, *id, *create, api.CreateRequest{Image: *image, Network: *network, MemMiB: *mem})
	if err != nil {
		log.Fatal(daemonHint(*sock, err))
	}
	log.Printf("bound to sandbox %s (%s)", sb.ID, sb.State)
	tools := mcp.NewSandbox(c, sb.ID)
	defer tools.Close()
	if err := mcp.Serve(ctx, tools, os.Stdin, os.Stdout, version); err != nil {
		log.Fatal(err)
	}
}

func bind(ctx context.Context, c *client.Client, id string, create bool, req api.CreateRequest) (api.Sandbox, error) {
	if id != "" {
		sb, err := c.Get(ctx, id)
		switch {
		case err == nil && !sb.State.Terminal():
			return sb, nil
		case err == nil:
			return sb, fmt.Errorf("sandbox %s is %s", id, sb.State)
		case !create || !errors.Is(err, client.ErrNotFound):
			return sb, fmt.Errorf("sandbox %s: %w", id, err)
		}
	}
	req.ID = id
	sb, err := c.Create(ctx, req)
	if err != nil {
		return sb, fmt.Errorf("creating a sandbox: %w", err)
	}
	log.Printf("created sandbox %s", sb.ID)
	return sb, nil
}

func defaultSock() string {
	if s := os.Getenv("SBX_SOCK"); s != "" {
		return s
	}
	return "/run/sbx/sbxd.sock"
}

// daemonHint turns "can't reach the daemon" into what to do about it: the
// three ways it happens each have their own fix.
func daemonHint(sock string, err error) error {
	switch msg := err.Error(); {
	case strings.Contains(msg, "no such file or directory"):
		return fmt.Errorf("sbxd isn't running: there's no socket at %s. Start it with: sudo systemctl start sbxd "+
			"(install it once with: sudo scripts/install.sh)", sock)
	case strings.Contains(msg, "connection refused"):
		return fmt.Errorf("sbxd isn't running (its socket %s is left over from an earlier run). Start it with: sudo systemctl start sbxd", sock)
	case strings.Contains(msg, "permission denied"):
		return fmt.Errorf("you can't use sbxd's socket %s: you're not in the sbx group yet (log out and back in after the install, "+
			"or run: newgrp sbx), or sbxd was started without -sock-group sbx", sock)
	}
	return err
}
