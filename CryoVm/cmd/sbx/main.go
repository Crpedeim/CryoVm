// sbx is the command-line client for sbxd.
//
//	sudo sbx create
//	sudo sbx exec sbx-1a2b3c4d -- python3 -c 'print(6*7)'
//	sudo sbx put sbx-1a2b3c4d ./data.csv /work/data.csv
//	sudo sbx rm sbx-1a2b3c4d
//
// `sbx exec` exits with the remote command's exit code, as ssh does, so it
// fits in scripts. Ctrl+C stops the remote command, not just the client.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

const usage = `usage: sbx [-sock PATH] <command> [arguments]

commands:
  create [-id ID] [-rootfs DIR] [-vcpus N] [-mem MiB] [-pids N] [-ttl D] [-idle D] [-idle-action pause|destroy] [-net] [-image NAME] [-policy allowlist|browse]
                                                        create a sandbox, print its id
  ls [-a]                                               list sandboxes (-a: include stopped)
  info <id>                                             show one sandbox
  stats [-watch] <id>                                   resource use and limits (-watch: every second)
  events <id>                                           show its state history
  exec [-timeout D] [-env K=V]... [-dir D] <id> -- cmd  run a command, stream its output
  put [-mode 0644] <id> <local> <remote>                upload a file
  get <id> <remote> <local>                             download a file
  files <id> <dir>                                      list a directory in the sandbox
  shell [-attach S] <id> [-- command]                   interactive shell; Ctrl+] detaches
  sessions <id>                                         list shell sessions
  kill-session <id> <session>                           end a shell session
  start [-dir D] [-env K=V]... <id> -- command          start a background process, print its id
  ps <id>                                               list background processes
  logs [-f] [-offset N] <id> <proc>                     print a process's output (-f: follow)
  signal <id> <proc> [SIGNAL]                           signal its process group (default TERM)
  wait <id> <proc>                                      wait for it to exit; exits with its code
  rmproc <id> <proc>                                    forget an exited process, delete its logs
  extend <id> <duration>                                set its deadline to duration from now
  checkpoint [-leave-running] [-force] <id>             save its whole state; without -leave-running it's paused
  checkpoints <id>                                      list its checkpoints
  resume [-checkpoint CK] <id>                          bring a paused sandbox back (from CK: roll back to it)
  images                                                each image's versions: current, in use, or safe to delete
  fork [-id NEW] [-checkpoint CK] [-count N] [-force] <id>  new sandboxes from one snapshot of this one; prints their ids
  audit [-sandbox ID] [-n N] [-verify]                  the audit log, newest first (-verify: check the chain)
  rm <id>...                                            destroy sandboxes
  run [create flags] [-timeout D] -- cmd                create, run one command, destroy

The socket defaults to $SBX_SOCK, or /run/sbx/sbxd.sock.
`

func main() {
	fs := flag.NewFlagSet("sbx", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	def := os.Getenv("SBX_SOCK")
	if def == "" {
		def = "/run/sbx/sbxd.sock"
	}
	sock := fs.String("sock", def, "daemon socket")
	_ = fs.Parse(os.Args[1:])
	if fs.NArg() == 0 {
		fs.Usage()
		os.Exit(2)
	}

	// Ctrl+C cancels the context. For exec, that closes the connection, and
	// the daemon kills the remote command.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c := client.New(*sock)
	cmd, args := fs.Arg(0), fs.Args()[1:]
	code, err := dispatch(ctx, c, cmd, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbx:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func dispatch(ctx context.Context, c *client.Client, cmd string, args []string) (int, error) {
	switch cmd {
	case "create":
		return 0, create(ctx, c, args)
	case "ls":
		return 0, list(ctx, c, args)
	case "info":
		return 0, info(ctx, c, args)
	case "stats":
		return 0, stats(ctx, c, args)
	case "extend":
		return 0, extend(ctx, c, args)
	case "checkpoint":
		return 0, checkpoint(ctx, c, args)
	case "checkpoints":
		return 0, checkpoints(ctx, c, args)
	case "resume":
		return 0, resume(ctx, c, args)
	case "images":
		return 0, images(ctx, c)
	case "fork":
		return 0, fork(ctx, c, args)
	case "audit":
		return audit(ctx, c, args)
	case "events":
		return 0, events(ctx, c, args)
	case "exec":
		return execCmd(ctx, c, args)
	case "put":
		return 0, put(ctx, c, args)
	case "get":
		return 0, get(ctx, c, args)
	case "files":
		return 0, files(ctx, c, args)
	case "shell":
		return shellCmd(c, args)
	case "sessions":
		return 0, sessions(ctx, c, args)
	case "kill-session":
		if err := need(args, 2, "kill-session <id> <session>"); err != nil {
			return 2, err
		}
		return 0, c.KillSession(ctx, args[0], args[1])
	case "start":
		return startProc(ctx, c, args)
	case "ps":
		return 0, ps(ctx, c, args)
	case "logs":
		return 0, logs(ctx, c, args)
	case "signal":
		return 0, signalProc(ctx, c, args)
	case "wait":
		return waitProc(ctx, c, args)
	case "rmproc":
		if err := need(args, 2, "rmproc <id> <proc>"); err != nil {
			return 2, err
		}
		return 0, c.RemoveProcess(ctx, args[0], args[1])
	case "rm":
		return 0, remove(ctx, c, args)
	case "run":
		return run(ctx, c, args)
	default:
		return 2, fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
	}
}

func need(args []string, n int, what string) error {
	if len(args) != n {
		return fmt.Errorf("want %s", what)
	}
	return nil
}

func createFlags(fs *flag.FlagSet) func() api.CreateRequest {
	id := fs.String("id", "", "sandbox id (default: generated)")
	rootfs := fs.String("rootfs", "", "rootfs directory (default: the daemon's)")
	vcpus := fs.Int("vcpus", 0, "vCPUs (default: the daemon's)")
	mem := fs.Int("mem", 0, "memory in MiB (default: the daemon's)")
	pids := fs.Int("pids", 0, "limit on processes inside (default: the daemon's)")
	ttl := fs.String("ttl", "", `maximum lifetime, e.g. 2h; "none" for no deadline (default: the daemon's)`)
	idle := fs.String("idle", "", `act after this long without use, e.g. 15m; "none" to never (default: the daemon's)`)
	idleAction := fs.String("idle-action", "", "what idleness does: pause (wakes on use) or destroy (default: the daemon's)")
	network := fs.Bool("net", false, "give it a network: its own namespace, NAT to the outside")
	image := fs.String("image", "", "a named image, e.g. browser: its rootfs, memory, network and egress policy")
	policy := fs.String("policy", "", "egress policy: allowlist (default) or browse (the public internet)")
	return func() api.CreateRequest {
		return api.CreateRequest{ID: *id, Rootfs: *rootfs, VCPUs: *vcpus, MemMiB: *mem, PidsMax: *pids,
			TTLSeconds: lifetimeFlag(*ttl), IdleTimeoutS: lifetimeFlag(*idle), IdleAction: *idleAction, Network: *network, Image: *image, Policy: *policy}
	}
}

func create(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	req := createFlags(fs)
	_ = fs.Parse(args)
	start := time.Now()
	sb, err := c.Create(ctx, req())
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "created in %s\n", time.Since(start).Round(time.Millisecond))
	fmt.Println(sb.ID)
	return nil
}

func age(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func list(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	all := fs.Bool("a", false, "include stopped and failed sandboxes")
	_ = fs.Parse(args)
	sbs, err := c.List(ctx, *all)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tBACKEND\tVCPUS\tMEM\tPIDS\tAGE\tERROR")
	for _, s := range sbs {
		e := s.Error
		if len(e) > 40 {
			e = e[:37] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%dMiB\t%s\t%s\t%s\n", s.ID, s.State, s.Backend, s.VCPUs, s.MemMiB, limitStr(int64(s.PidsMax)), age(s.CreatedAt), e)
	}
	return tw.Flush()
}

func info(ctx context.Context, c *client.Client, args []string) error {
	if err := need(args, 1, "info <id>"); err != nil {
		return err
	}
	s, err := c.Get(ctx, args[0])
	if err != nil {
		return err
	}
	fmt.Printf("id:       %s\nstate:    %s\nbackend:  %s\nrootfs:   %s\nvcpus:    %d\nmemory:   %d MiB\nprocesses: %s (inside)\ncreated:  %s\nupdated:  %s\n",
		s.ID, s.State, s.Backend, s.Rootfs, s.VCPUs, s.MemMiB, limitStr(int64(s.PidsMax)), s.CreatedAt.Local().Format(time.DateTime), s.UpdatedAt.Local().Format(time.DateTime))
	expires := "never"
	if s.ExpiresAt != nil {
		expires = fmt.Sprintf("%s (in %s)", s.ExpiresAt.Local().Format(time.DateTime), time.Until(*s.ExpiresAt).Round(time.Second))
	}
	idle := "never"
	if s.IdleTimeoutS > 0 {
		idle = s.IdleAction + " after " + (time.Duration(s.IdleTimeoutS) * time.Second).String() + " without use"
	}
	fmt.Printf("expires:  %s\nidle:     %s\n", expires, idle)
	if s.ResumeOnStart {
		fmt.Println("resume:   paused by sbxd's shutdown; resumes when sbxd starts")
	}
	if s.WakeOnUse {
		fmt.Println("asleep:   paused while idle; wakes when used")
	}
	if s.ForkedFrom != "" {
		fmt.Printf("forked:   from %s\n", s.ForkedFrom)
	}
	if s.NetSlot > 0 {
		fmt.Printf("network:  10.89.0.2 inside; the host sees %s (slot %d)\n", s.NetAddr, s.NetSlot)
		if s.EgressPolicy == "browse" {
			fmt.Println("egress:   browse: the public internet; private, link-local and metadata addresses refused")
		} else {
			fmt.Println("egress:   allowlist: only the proxy's allowed names")
		}
	} else {
		fmt.Println("network:  none")
	}
	if s.LastActive != nil {
		fmt.Printf("active:   %s ago\n", time.Since(*s.LastActive).Round(time.Second))
	}
	if s.Error != "" {
		fmt.Printf("error:    %s\n", s.Error)
	}
	return nil
}

func events(ctx context.Context, c *client.Client, args []string) error {
	if err := need(args, 1, "events <id>"); err != nil {
		return err
	}
	evs, err := c.Events(ctx, args[0])
	if err != nil {
		return err
	}
	for _, e := range evs {
		from := string(e.From)
		if from == "" {
			from = "∅"
		}
		line := fmt.Sprintf("%s  %-8s → %s", e.At.Local().Format("15:04:05.000"), from, e.To)
		if e.Detail != "" {
			line += "  (" + e.Detail + ")"
		}
		fmt.Println(line)
	}
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// signalNumbers maps the names Go prints for common signals back to their
// numbers, for shell-style exit codes (128 + signal number).
var signalNumbers = map[string]int{"hangup": 1, "interrupt": 2, "aborted": 6, "killed": 9, "segmentation fault": 11, "terminated": 15}

// exitCode turns a remote result into this process's exit code: the remote
// code itself, 124 for a timeout (as GNU timeout(1) does), and 128 + N for
// death by signal N (as shells do).
func exitCode(st api.ExitStatus) int {
	switch {
	case st.TimedOut:
		return 124
	case st.Signal != "":
		if n, ok := signalNumbers[st.Signal]; ok {
			return 128 + n
		}
		return 255
	default:
		return st.Code
	}
}

func execCmd(ctx context.Context, c *client.Client, args []string) (int, error) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	timeout := fs.Duration("timeout", 0, "kill the command after this long")
	dir := fs.String("dir", "", "working directory in the sandbox")
	var env multiFlag
	fs.Var(&env, "env", "KEY=value (repeatable)")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		return 2, errors.New("want exec <id> -- <command>")
	}
	id, command := fs.Arg(0), fs.Args()[1:]
	// Flag parsing stops at the id, so the "--" after it is still here.
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		return 2, errors.New("want exec <id> -- <command>")
	}
	st, err := c.Exec(ctx, id, client.ExecRequest{
		Args: command, Env: env, Dir: *dir, Timeout: *timeout, Stdout: os.Stdout, Stderr: os.Stderr,
	})
	if err != nil {
		if ctx.Err() != nil {
			return 130, errors.New("interrupted: the remote command was stopped")
		}
		return 255, err
	}
	return exitCode(st), nil
}

func put(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	modeStr := fs.String("mode", "", "permission bits, e.g. 0755 (default: the local file's)")
	_ = fs.Parse(args)
	if err := need(fs.Args(), 3, "put <id> <local> <remote>"); err != nil {
		return err
	}
	id, local, remote := fs.Arg(0), fs.Arg(1), fs.Arg(2)
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	mode := fi.Mode().Perm()
	if *modeStr != "" {
		var m uint32
		if _, err := fmt.Sscanf(*modeStr, "%o", &m); err != nil {
			return fmt.Errorf("mode must be octal, like 0644")
		}
		mode = os.FileMode(m)
	}
	start := time.Now()
	res, err := c.Put(ctx, id, remote, f, client.PutOptions{Mode: mode, Mkdirs: true})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s -> %s: %s, sha256 %s...\n", local, remote, rate(res.Size, time.Since(start)), res.SHA256[:12])
	return nil
}

func rate(n int64, d time.Duration) string {
	mb := float64(n) / (1 << 20)
	return fmt.Sprintf("%.1f MB in %s (%.1f MB/s)", mb, d.Round(time.Millisecond), mb/max(d.Seconds(), 1e-9))
}

// get writes to a temp file next to the destination and renames it into
// place only after the checksum verifies: the same pattern the agent uses
// inside the sandbox, so a failed download never leaves a half file.
func get(ctx context.Context, c *client.Client, args []string) error {
	if err := need(args, 3, "get <id> <remote> <local>"); err != nil {
		return err
	}
	id, remote, local := args[0], args[1], args[2]
	tmp, err := os.CreateTemp(dirOf(local), ".sbx-get-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op after a successful rename
	start := time.Now()
	res, err := c.Fetch(ctx, id, remote, tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), local); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s -> %s: %s, sha256 %s...\n", remote, local, rate(res.Size, time.Since(start)), res.SHA256[:12])
	return nil
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		if i == 0 {
			return "/"
		}
		return p[:i]
	}
	return "."
}

func files(ctx context.Context, c *client.Client, args []string) error {
	if err := need(args, 2, "files <id> <dir>"); err != nil {
		return err
	}
	res, err := c.ListDir(ctx, args[0], args[1])
	if err != nil {
		return err
	}
	for _, e := range res.Entries {
		kind := "-"
		switch {
		case e.IsDir:
			kind = "d"
		case e.IsSymlink:
			kind = "l"
		}
		perm := os.FileMode(e.Mode).Perm().String()[1:]
		fmt.Printf("%s%s %10d  %s  %s\n", kind, perm, e.Size, e.ModTime.Local().Format("2006-01-02 15:04"), e.Name)
	}
	if res.Truncated {
		fmt.Println("(listing truncated)")
	}
	return nil
}

func remove(ctx context.Context, c *client.Client, args []string) error {
	if len(args) == 0 {
		return errors.New("want rm <id>...")
	}
	var failed error
	for _, id := range args {
		s, err := c.Destroy(ctx, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", id, err)
			failed = errors.New("some sandboxes were not removed")
			continue
		}
		fmt.Printf("%s %s\n", id, s.State)
	}
	return failed
}

// run is create + exec + rm. The sandbox is destroyed even if the command
// fails or you press Ctrl+C.
func run(ctx context.Context, c *client.Client, args []string) (int, error) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	req := createFlags(fs)
	timeout := fs.Duration("timeout", 0, "kill the command after this long")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		return 2, errors.New("want run [flags] -- <command>")
	}
	sb, err := c.Create(ctx, req())
	if err != nil {
		return 255, err
	}
	defer func() {
		if _, err := c.Destroy(context.Background(), sb.ID); err != nil {
			fmt.Fprintf(os.Stderr, "sbx: destroy %s: %v\n", sb.ID, err)
		}
	}()
	st, err := c.Exec(ctx, sb.ID, client.ExecRequest{Args: fs.Args(), Timeout: *timeout, Stdout: os.Stdout, Stderr: os.Stderr})
	if err != nil {
		if ctx.Err() != nil {
			return 130, errors.New("interrupted: the remote command was stopped")
		}
		return 255, err
	}
	return exitCode(st), nil
}

const detachKey = 0x1d // Ctrl+]

// shellCmd attaches this terminal to a shell session in the sandbox. Ctrl+]
// detaches and leaves the session running; reattach with -attach.
func shellCmd(c *client.Client, args []string) (int, error) {
	fs := flag.NewFlagSet("shell", flag.ExitOnError)
	attachID := fs.String("attach", "", "attach to this existing session instead of starting one")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		return 2, errors.New("want shell [-attach S] <id> [-- command]")
	}
	id, command := fs.Arg(0), fs.Args()[1:]
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}

	in, out := int(os.Stdin.Fd()), int(os.Stdout.Fd())
	tty := isTerminal(in)
	cols, rows, err := termSize(out)
	if err != nil {
		cols, rows = 80, 24
	}
	sh, err := c.Shell(context.Background(), id, client.ShellOptions{SessionID: *attachID, Cols: cols, Rows: rows, Command: command})
	if err != nil {
		return 255, err
	}
	defer sh.Close()

	restore := func() {}
	if tty {
		if r, err := makeRaw(in); err == nil {
			restore = r
		}
	}
	verb := "attached to"
	if sh.Created {
		verb = "started"
	}
	// In raw mode the terminal no longer turns \n into \r\n for us.
	fmt.Fprintf(os.Stderr, "[sbx: %s session %s; Ctrl+] detaches]\r\n", verb, sh.SessionID)

	// The window changed size: tell the remote terminal, so vim and less
	// redraw to fit.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for range winch {
			if c, r, err := termSize(out); err == nil {
				_ = sh.Resize(c, r)
			}
		}
	}()

	// Keystrokes go to the remote shell, except the detach key.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				data := buf[:n]
				if i := bytes.IndexByte(data, detachKey); i >= 0 {
					_, _ = sh.Write(data[:i])
					_ = sh.Detach()
					return
				}
				if _, err := sh.Write(data); err != nil {
					return
				}
			}
			if err != nil {
				// Input ended (a pipe, not a keyboard): leave the session
				// running, as Ctrl+] would.
				_ = sh.Detach()
				return
			}
		}
	}()

	end, err := sh.Run(os.Stdout)
	restore() // before printing, so the message lands on a normal terminal
	if err != nil {
		return 255, err
	}
	if end.Exited {
		st := api.ExitStatus{Code: end.Code, Signal: end.Signal}
		fmt.Fprintf(os.Stderr, "[sbx: session %s ended]\n", sh.SessionID)
		return exitCode(st), nil
	}
	fmt.Fprintf(os.Stderr, "[sbx: detached (%s). It keeps running; reattach with: sbx shell -attach %s %s]\n",
		end.Reason, sh.SessionID, id)
	return 0, nil
}

func sessions(ctx context.Context, c *client.Client, args []string) error {
	if err := need(args, 1, "sessions <id>"); err != nil {
		return err
	}
	list, err := c.Sessions(ctx, args[0])
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION\tATTACHED\tCOMMAND")
	for _, s := range list {
		fmt.Fprintf(tw, "%s\t%v\t%s\n", s.ID, s.Attached, strings.Join(s.Command, " "))
	}
	return tw.Flush()
}

func startProc(ctx context.Context, c *client.Client, args []string) (int, error) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	dir := fs.String("dir", "", "working directory in the sandbox")
	var env multiFlag
	fs.Var(&env, "env", "KEY=value (repeatable)")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		return 2, errors.New("want start <id> -- <command>")
	}
	id, command := fs.Arg(0), fs.Args()[1:]
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		return 2, errors.New("want start <id> -- <command>")
	}
	p, err := c.StartProcess(ctx, id, api.ProcStartRequest{Args: command, Env: env, Dir: *dir})
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(os.Stderr, "started pid %d in %s\n", p.PID, id)
	fmt.Println(p.ID)
	return 0, nil
}

func ps(ctx context.Context, c *client.Client, args []string) error {
	if err := need(args, 1, "ps <id>"); err != nil {
		return err
	}
	list, err := c.Processes(ctx, args[0])
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PROC\tPID\tSTATE\tAGE\tLOG\tCOMMAND")
	for _, p := range list {
		state := "running"
		if !p.Running {
			state = fmt.Sprintf("exited %d", p.ExitCode)
			if p.Signal != "" {
				state = "killed: " + p.Signal
			}
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", p.ID, p.PID, state, age(p.Started), human(p.LogBytes), strings.Join(p.Args, " "))
	}
	return tw.Flush()
}

func human(n int64) string {
	switch {
	case n < 1<<10:
		return fmt.Sprintf("%dB", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	}
}

// logs prints output from -offset. With -f it follows until the process
// exits; Ctrl+C stops following and leaves the process running. With an
// explicit -offset, the next offset is printed at the end, for paging.
func logs(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	follow := fs.Bool("f", false, "follow: keep printing new output until the process exits")
	offset := fs.Int64("offset", 0, "start from this byte offset")
	_ = fs.Parse(args)
	if err := need(fs.Args(), 2, "logs [-f] [-offset N] <id> <proc>"); err != nil {
		return err
	}
	paging := false
	fs.Visit(func(f *flag.Flag) { paging = paging || f.Name == "offset" })
	end, err := c.Logs(ctx, fs.Arg(0), fs.Arg(1), *offset, *follow, os.Stdout)
	if err != nil {
		if ctx.Err() != nil {
			return nil // Ctrl+C while following: the process is untouched
		}
		return err
	}
	if end.Skipped > 0 {
		fmt.Fprintf(os.Stderr, "[sbx: %d earlier bytes were rotated away and are gone]\n", end.Skipped)
	}
	if paging {
		fmt.Fprintf(os.Stderr, "[sbx: next offset %d]\n", end.Next)
	}
	return nil
}

var signalNames = map[string]int{
	"HUP": 1, "INT": 2, "QUIT": 3, "KILL": 9, "USR1": 10, "USR2": 12, "TERM": 15, "CONT": 18, "STOP": 19,
}

func signalProc(ctx context.Context, c *client.Client, args []string) error {
	if len(args) != 2 && len(args) != 3 {
		return errors.New("want signal <id> <proc> [SIGNAL]")
	}
	sig := 15
	if len(args) == 3 {
		name := strings.TrimPrefix(strings.ToUpper(args[2]), "SIG")
		if n, ok := signalNames[name]; ok {
			sig = n
		} else if n, err := strconv.Atoi(args[2]); err == nil {
			sig = n
		} else {
			return fmt.Errorf("unknown signal %q: use a name like TERM or KILL, or a number", args[2])
		}
	}
	return c.Signal(ctx, args[0], args[1], sig)
}

// waitProc exits with the process's own exit code, like `sbx exec`.
func waitProc(ctx context.Context, c *client.Client, args []string) (int, error) {
	if err := need(args, 2, "wait <id> <proc>"); err != nil {
		return 2, err
	}
	p, err := c.Wait(ctx, args[0], args[1])
	if err != nil {
		if ctx.Err() != nil {
			return 130, errors.New("stopped waiting; the process keeps running")
		}
		return 255, err
	}
	return exitCode(api.ExitStatus{Code: p.ExitCode, Signal: p.Signal}), nil
}

func limitStr(n int64) string {
	if n <= 0 {
		return "unlimited"
	}
	return strconv.FormatInt(n, 10)
}

func mib(n int64) string { return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20)) }

// stats prints resource use against limits. With -watch, it prints a line
// every second, with CPU use as a percentage of one core, computed from
// the change in CPU time over the change in wall-clock time.
func stats(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	watch := fs.Bool("watch", false, "print a line every second until Ctrl+C")
	_ = fs.Parse(args)
	if err := need(fs.Args(), 1, "stats [-watch] <id>"); err != nil {
		return err
	}
	id := fs.Arg(0)
	st, err := c.Stats(ctx, id)
	if err != nil {
		return err
	}
	if !*watch {
		memLimit := "unlimited"
		if st.MemoryLimit > 0 {
			memLimit = mib(st.MemoryLimit)
		}
		peak := ""
		if st.MemoryPeak > 0 {
			peak = ", peak " + mib(st.MemoryPeak)
		}
		cpuLimit := "unlimited"
		if st.CPUQuota > 0 {
			cpuLimit = fmt.Sprintf("%.2f cores", st.CPUQuota)
		}
		cpus := st.CPUs
		if cpus == "" {
			cpus = "any"
		}
		fmt.Printf("cgroup:     %s\n", st.Cgroup)
		fmt.Printf("memory:     %s of %s%s\n", mib(st.MemoryBytes), memLimit, peak)
		fmt.Printf("oom kills:  %d\n", st.OOMKills)
		fmt.Printf("cpu time:   %s (limit %s, on CPUs %s)\n", time.Duration(st.CPUUsageMicros)*time.Microsecond, cpuLimit, cpus)
		fmt.Printf("throttled:  %s across %d periods\n", time.Duration(st.CPUThrottledMicros)*time.Microsecond, st.ThrottledPeriods)
		// The host counts gVisor's threads, about 2 per process inside: the
		// limit on processes inside is in `sbx info`.
		fmt.Printf("host threads: %d of %s\n", st.Pids, limitStr(st.PidsLimit))
		return nil
	}
	fmt.Println("TIME      CPU%    MEMORY        THREADS  THROTTLED")
	prev, prevAt := st, time.Now()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		st, err := c.Stats(ctx, id)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		now := time.Now()
		cpu := float64(st.CPUUsageMicros-prev.CPUUsageMicros) / float64(now.Sub(prevAt).Microseconds()) * 100
		fmt.Printf("%s  %5.1f  %12s  %7d  %d\n", now.Format("15:04:05"), cpu, mib(st.MemoryBytes), st.Pids, st.ThrottledPeriods-prev.ThrottledPeriods)
		prev, prevAt = st, now
	}
}

// lifetimeFlag turns "2h" into seconds, "none" into -1 (no limit), and ""
// into 0 (the daemon's default). A bad value exits with a usage error.
func lifetimeFlag(v string) int {
	switch v {
	case "":
		return 0
	case "none", "never", "off":
		return -1
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Second {
		fmt.Fprintf(os.Stderr, "sbx: %q is not a duration like 30m or 2h, or none\n", v)
		os.Exit(2)
	}
	return int(d / time.Second)
}

func extend(ctx context.Context, c *client.Client, args []string) error {
	if err := need(args, 2, "extend <id> <duration>"); err != nil {
		return err
	}
	d, err := time.ParseDuration(args[1])
	if err != nil || d <= 0 {
		return fmt.Errorf("%q is not a duration like 30m or 2h", args[1])
	}
	s, err := c.Extend(ctx, args[0], d)
	if err != nil {
		return err
	}
	fmt.Printf("%s now expires at %s\n", s.ID, s.ExpiresAt.Local().Format(time.DateTime))
	return nil
}

// audit prints the log, oldest of the selection first, so it reads like a
// story. With -verify it checks the hash chain instead, and exits 1 if
// it's broken.
func audit(ctx context.Context, c *client.Client, args []string) (int, error) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	sandboxID := fs.String("sandbox", "", "only this sandbox's entries")
	n := fs.Int("n", 30, "how many entries")
	verify := fs.Bool("verify", false, "check the whole chain instead of listing")
	_ = fs.Parse(args)
	if *verify {
		v, err := c.VerifyAudit(ctx)
		if err != nil {
			return 1, err
		}
		if !v.OK {
			fmt.Printf("BROKEN at entry %d: %s\n(%d entries verified before it)\n", v.BrokenAt, v.Problem, v.Entries)
			return 1, nil
		}
		fmt.Printf("ok: %d entries, chain intact\nhead: %s\n", v.Entries, v.Head)
		fmt.Println("(keep a copy of the head somewhere else: a later head that doesn't extend it means history was rewritten)")
		return 0, nil
	}
	entries, err := c.Audit(ctx, *sandboxID, *n)
	if err != nil {
		return 1, err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		mark := auditMark(e.Outcome)
		line := fmt.Sprintf("%5d %s %s %-14s %-14s %s", e.Seq, mark, e.At.Local().Format("01-02 15:04:05"), e.SandboxID, e.Action, e.Detail)
		if e.Error != "" {
			line += "  [" + e.Error + "]"
		}
		fmt.Printf("%s\n      by %s, %dms\n", line, e.Actor, e.DurationMs)
	}
	return 0, nil
}

func checkpoint(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("checkpoint", flag.ExitOnError)
	leave := fs.Bool("leave-running", false, "take a snapshot and keep the sandbox running")
	force := fs.Bool("force", false, "checkpoint even if busy, cutting off execs and detaching shells")
	_ = fs.Parse(args)
	if err := need(fs.Args(), 1, "checkpoint [-leave-running] [-force] <id>"); err != nil {
		return err
	}
	ck, err := c.Checkpoint(ctx, fs.Arg(0), api.CheckpointRequest{LeaveRunning: *leave, Force: *force})
	if err != nil {
		return err
	}
	after := "paused: its state is on disk, nothing runs"
	switch where(ck) { // the snapshot store: say where the state really is
	case "store":
		after = "paused: its state is in the snapshot store, nothing runs"
	case "disk+store":
		after = "paused: its state is on disk and in the snapshot store, nothing runs"
	}
	if ck.LeftRunning {
		after = "still running"
	}
	fmt.Printf("%s: checkpoint %s, %s in %s; %s\n", ck.SandboxID, ck.ID, human(ck.ImageBytes),
		(time.Duration(ck.DurationMs) * time.Millisecond).String(), after)
	return nil
}

func checkpoints(ctx context.Context, c *client.Client, args []string) error {
	if err := need(args, 1, "checkpoints <id>"); err != nil {
		return err
	}
	list, err := c.Checkpoints(ctx, args[0])
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECKPOINT\tAGE\tSIZE\tTOOK\tKIND\tWHERE")
	for _, ck := range list {
		kind := "pause"
		if ck.LeftRunning {
			kind = "snapshot"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%dms\t%s\t%s\n", ck.ID, age(ck.CreatedAt), human(ck.ImageBytes), ck.DurationMs, kind, where(ck))
	}
	return tw.Flush()
}

func resume(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("resume", flag.ExitOnError)
	ck := fs.String("checkpoint", "", "resume from this checkpoint instead of the one that paused it")
	_ = fs.Parse(args)
	if err := need(fs.Args(), 1, "resume [-checkpoint CK] <id>"); err != nil {
		return err
	}
	start := time.Now()
	s, err := c.Resume(ctx, fs.Arg(0), *ck)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s again (%s)\n", s.ID, s.State, time.Since(start).Round(time.Millisecond))
	return nil
}

// fork prints the new sandboxes' IDs, one per line, so scripts can capture
// them; the timing goes to stderr.
func fork(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("fork", flag.ExitOnError)
	id := fs.String("id", "", "the new sandbox's ID (a single fork only)")
	ck := fs.String("checkpoint", "", "fork from this checkpoint (default: a snapshot taken now, or a sleeping sandbox's latest)")
	count := fs.Int("count", 1, "how many forks, from the same snapshot (at most 16)")
	force := fs.Bool("force", false, "fork a busy sandbox anyway, cutting off its execs")
	_ = fs.Parse(args)
	if err := need(fs.Args(), 1, "fork [-id NEW] [-checkpoint CK] [-count N] <id>"); err != nil {
		return err
	}
	start := time.Now()
	forks, err := c.Fork(ctx, fs.Arg(0), api.ForkRequest{ID: *id, Checkpoint: *ck, Count: *count, Force: *force})
	for _, f := range forks {
		fmt.Println(f.ID)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d fork(s) of %s in %s\n", len(forks), fs.Arg(0), time.Since(start).Round(time.Millisecond))
	return nil
}

// auditMark flags the entries worth a look: errors, and (Day 18) egress the
// proxy denied. An allowed connection is normal, not a problem: before this,
// every one was flagged, burying the denials among them.
func auditMark(outcome string) string {
	if outcome == "error" || outcome == "denied" {
		return "!"
	}
	return " "
}

// images shows each image's versions (Day 21).
func images(ctx context.Context, c *client.Client) error {
	imgs, err := c.Images(ctx)
	if err != nil {
		return err
	}
	if len(imgs) == 0 {
		fmt.Println("no images (build one: sudo scripts/build-browser-rootfs.sh)")
	}
	for _, im := range imgs {
		fmt.Printf("%s: %s (%d MiB, %s)\n", im.Name, im.Path, im.MemMiB, orDefault(im.Policy, "allowlist"))
		for _, v := range im.Versions {
			state := "unused: safe to delete"
			switch {
			case v.Current && v.Sandboxes > 0:
				state = fmt.Sprintf("current; %d sandbox(es)", v.Sandboxes)
			case v.Current:
				state = "current"
			case v.Sandboxes > 0:
				state = fmt.Sprintf("%d sandbox(es), %d paused: keep", v.Sandboxes, v.Paused)
			}
			fmt.Printf("  %-50s %s\n", v.Path, state)
		}
	}
	return nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// where says where a checkpoint's image is (the S3 snapshot store).
func where(ck api.Checkpoint) string {
	switch {
	case ck.Local && ck.Remote:
		return "disk+store"
	case ck.Remote:
		return "store"
	default:
		return "disk"
	}
}
