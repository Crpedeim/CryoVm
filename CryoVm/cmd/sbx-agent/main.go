// sbx-agent runs inside a sandbox, usually as its init process (PID 1). It
// dials the host, says hello, and serves requests. Build it static so it runs
// in any rootfs:
//
//	CGO_ENABLED=0 go build -o bin/sbx-agent ./cmd/sbx-agent
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Crpedeim/sbx/internal/guest"
)

const prSetChildSubreaper = 36 // from <linux/prctl.h>

func main() {
	// Trampoline mode, before anything else: set the process limit, then
	// become the program. See guest.Trampoline.
	if len(os.Args) > 1 && os.Args[1] == guest.TrampolineFlag {
		err := guest.Trampoline(os.Args[2:])
		fmt.Fprintln(os.Stderr, "sbx-agent:", err) // reached only if exec failed
		os.Exit(127)
	}
	id := flag.String("id", "", "sandbox id (checked by the host)")
	dial := flag.String("dial", "unix:/sbx/agent.sock", "where the host listens")
	reapAll := flag.Bool("reap-all", false, "reap every exited child, orphans included (automatic as PID 1)")
	logDir := flag.String("log-dir", "/var/log/sbx", "where background processes' logs are kept")
	identityDir := flag.String("identity-dir", "/run/sbx", "where to publish the sandbox ID and generation for programs")
	childNproc := flag.Int("child-nproc", 0, "limit on processes for everything the agent starts (0: none); the agent itself stays unlimited")
	flag.Parse()
	log.SetPrefix("sbx-agent: ")
	if *id == "" {
		log.Fatal("-id is required")
	}

	// SIGTERM is how the host asks the sandbox to stop. As PID 1, a process
	// gets no default signal handling from the kernel, so without this the
	// signal would be ignored and every shutdown would end in SIGKILL.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// SIGHUP must not kill PID 1, and Go's default for it is to exit. The
	// kernel sends one when a terminal hangs up to the process that owns it,
	// and if PID 1 exits, the whole sandbox stops. Catch it rather than
	// ignore it: an ignored signal stays ignored in every program the agent
	// starts (so shells would no longer exit when their session is killed),
	// while a caught one resets to the default in each child.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Print("SIGHUP received and ignored")
		}
	}()

	reap := *reapAll || os.Getpid() == 1
	if reap && os.Getpid() != 1 {
		// Outside a sandbox (tests, debugging): become a "child subreaper",
		// so orphans of commands we start are reparented to us, exactly as
		// they would be to PID 1.
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); errno != 0 {
			log.Fatalf("prctl(PR_SET_CHILD_SUBREAPER): %v", errno)
		}
	}

	self, _ := os.Executable()
	err := guest.Run(ctx, guest.Config{SandboxID: *id, Dial: *dial, ReapAll: reap, LogDir: *logDir,
		ChildNproc: *childNproc, TrampolinePath: self, IdentityDir: *identityDir})
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
