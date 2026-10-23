// sbxd is the sandbox daemon. It owns the backend and the registry, and
// serves the HTTP API on a Unix socket that only root can open.
//
//	sudo sbxd -rootfs /mnt/sbx/rootfs/ubuntu-24.04 -agent /home/garvit/sbx/bin/sbx-agent
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/Crpedeim/sbx/internal/s3"
	"github.com/Crpedeim/sbx/internal/store"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Crpedeim/sbx/internal/daemon"
	"github.com/Crpedeim/sbx/internal/registry"
	"github.com/Crpedeim/sbx/internal/sandbox"
	"github.com/Crpedeim/sbx/internal/sandbox/firecracker"
	"github.com/Crpedeim/sbx/internal/sandbox/gvisor"
)

// The daemon finds Reap with a runtime type check, so a signature change
// would silently turn reaping off. This line turns that into a build error.
var _ daemon.Reaper = (*gvisor.Backend)(nil)

// checkpointIOMode is -checkpoint-io (Day 23); a package variable rather
// than another parameter of run's long list.
var checkpointIOMode string

func main() {
	sock := flag.String("sock", "/run/sbx/sbxd.sock", "Unix socket to serve the API on")
	db := flag.String("db", "/var/lib/sbx/registry.db", "SQLite registry path")
	backendName := flag.String("backend", "gvisor", "gvisor or firecracker")
	rootfs := flag.String("rootfs", "", "default rootfs for new sandboxes")
	agentPath := flag.String("agent", "", "gvisor: static sbx-agent binary (recommended)")
	runsc := flag.String("runsc", "runsc", "gvisor: path to runsc")
	state := flag.String("state", "/var/lib/sbx", "gvisor: state directory")
	platform := flag.String("platform", "", "gvisor: systrap or kvm (empty = runsc default)")
	vcpus := flag.Int("vcpus", 1, "default vCPUs")
	mem := flag.Int("mem", 256, "default memory in MiB")
	ckDir := flag.String("checkpoints", "/var/lib/sbx/checkpoints", "where checkpoint images are kept")
	egress := flag.String("egress", "deny", "what networked sandboxes may reach: deny (only the egress proxy) or open (anything; for debugging)")
	storeURL := flag.String("store", "", "an S3-compatible snapshot store for checkpoint images, e.g. http://127.0.0.1:8333 (credentials from SBX_S3_ACCESS_KEY and SBX_S3_SECRET_KEY)")
	storeBucket := flag.String("store-bucket", "sbx", "the snapshot store's bucket")
	storeEvict := flag.Bool("store-evict", false, "delete a checkpoint's local copy once the store has it (fetched again when needed)")
	checkpointIO := flag.String("checkpoint-io", "auto", "how checkpoint images are written and read: auto (O_DIRECT for a sandbox holding more than 40% of its memory limit, where a buffered image could push it over), direct, or buffered (for filesystems without O_DIRECT, such as tmpfs)")
	sockGroup := flag.String("sock-group", "", "a group whose members may use the API socket too (e.g. for sbx-mcp run as yourself); default: owner only")
	browserRootfs := flag.String("browser-rootfs", "/mnt/sbx/rootfs/browser-current", "the browser image: a versioned image's -current link (Day 21), or a plain rootfs (build it with scripts/build-browser-rootfs.sh)")
	allow := flag.String("allow", "pypi.org,files.pythonhosted.org", "names sandboxes may reach through the egress proxy, comma-separated; *.example.com allows subdomains")
	proxyPort := flag.Int("proxy-port", 3128, "the port the egress proxy listens on, on the host; sandboxes reach it at 10.89.0.1")
	onStop := flag.String("on-stop", daemon.OnStopPause, "what a clean stop does with running sandboxes: pause (checkpoint them, resume on start; survives a reboot), leave (keep them running for the next daemon to adopt), or destroy")
	ttl := flag.Duration("ttl", 0, "default maximum lifetime of a sandbox, e.g. 24h (0: none, the plan's default)")
	idle := flag.Duration("idle", 0, "default idle timeout: act after this long without use (0: never)")
	idleAction := flag.String("idle-action", "pause", "what the idle timeout does by default: pause (cheap, wakes on use) or destroy")
	pids := flag.Int("pids", 1024, "default limit on processes inside each sandbox (0: none); the host thread limit is set above it")
	kernel := flag.String("kernel", "", "firecracker: guest kernel")
	fcBin := flag.String("firecracker", "firecracker", "firecracker: binary")
	flag.Parse()
	checkpointIOMode = *checkpointIO
	switch checkpointIOMode {
	case "auto", "direct", "buffered":
	default:
		log.Fatalf("-checkpoint-io: %q isn't auto, direct or buffered", checkpointIOMode)
	}
	log.SetPrefix("sbxd: ")

	if err := run(*sock, *db, *backendName, *rootfs, *agentPath, *runsc, *state, *platform, *vcpus, *mem, *pids, *ttl, *idle, *idleAction, *ckDir, *onStop, *egress, *proxyPort, *allow, *browserRootfs, *sockGroup, *storeURL, *storeBucket, *storeEvict, *kernel, *fcBin); err != nil {
		log.Fatal(err)
	}
}

func run(sock, db, backendName, rootfs, agentPath, runsc, state, platform string, vcpus, mem, pids int, ttl, idle time.Duration, idleAction, ckDir, onStop, egress string, proxyPort int, allow, browserRootfs, sockGroup, storeURL, storeBucket string, storeEvict bool, kernel, fcBin string) error {
	for _, d := range []string{filepath.Dir(sock), filepath.Dir(db)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// One sbxd per registry and per state directory (Day 21). Two daemons
	// sharing them would each reconcile the other's live sandboxes, fail to
	// adopt them (their agents are connected elsewhere) and destroy them.
	for _, l := range []string{db + ".lock", filepath.Join(state, "sbxd.lock")} {
		release, err := lockExclusive(l)
		if err != nil {
			return err
		}
		defer release()
	}

	var b sandbox.Backend
	var err error
	switch backendName {
	case "gvisor":
		b, err = gvisor.New(gvisor.Config{CheckpointIO: checkpointIOMode, RunscPath: runsc, StateDir: state, Platform: platform, AgentPath: agentPath})
	case "firecracker":
		b, err = firecracker.New(firecracker.Config{FirecrackerBin: fcBin})
	default:
		err = fmt.Errorf("unknown backend %q", backendName)
	}
	if err != nil {
		return err
	}

	reg, err := registry.Open(db)
	if err != nil {
		return err
	}
	defer reg.Close()

	ctx := context.Background()
	m, err := daemon.New(ctx, daemon.Config{
		Backend: b, Registry: reg, Rootfs: rootfs, Kernel: kernel, VCPUs: vcpus, MemMiB: mem, PidsMax: pids,
		DefaultTTL: ttl, DefaultIdle: idle, DefaultIdleAction: idleAction, CheckpointDir: ckDir, OnStop: onStop,
		Egress: egress, ProxyPort: proxyPort, Images: images(browserRootfs),
		Store: snapshotStore(ctx, storeURL, storeBucket), StoreEvict: storeEvict,
	})
	if err != nil {
		return err
	}
	// The egress proxy (Day 18): sandboxes' one way out. If its port is
	// taken, say so and stop, rather than run with sandboxes cut off.
	var names []string
	for _, n := range strings.Split(allow, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	paddr, err := m.StartProxy(fmt.Sprintf("0.0.0.0:%d", proxyPort), names)
	if err != nil {
		m.Close(ctx)
		return fmt.Errorf("%w (is another program using port %d? see -proxy-port)", err, proxyPort)
	}
	log.Printf("egress proxy on %s; allowed: %s", paddr, strings.Join(names, ", "))

	ln, err := listen(sock, sockGroup)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           daemon.NewHandler(m),
		ConnContext:       daemon.ConnContext, // who's calling, from the kernel (audit log)
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: exec output and downloads stream for as long as
		// they take. Each request's own context bounds it instead.
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	log.Printf("serving on %s (backend %s, registry %s)", sock, b.Name(), db)

	select {
	case sig := <-stop:
		log.Printf("%s: shutting down", sig)
	case err := <-serveErr:
		return err
	}
	// Stop accepting, give in-flight requests a moment, then stop every
	// sandbox. A clean daemon stop never leaves a sandbox running.
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	m.Close(context.Background())
	_ = os.Remove(sock)
	log.Print("stopped")
	return nil
}

// listen opens the API socket so that only root can connect: anyone who can
// reach this API controls sandboxes as root. The umask is tightened before
// the socket is created, so it never exists, even briefly, with looser
// permissions.
// listen serves the API on a Unix socket, owner-only by default. With a
// group (-sock-group, Day 21), members may connect too: what that grants is
// the API, which acts inside sandboxes; the one parameter that reaches the
// host (a create's rootfs) stays the daemon user's alone. Never anyone else.
func listen(sock, group string) (net.Listener, error) {
	if c, err := net.Dial("unix", sock); err == nil {
		c.Close()
		return nil, fmt.Errorf("another sbxd is already serving on %s", sock)
	}
	_ = os.Remove(sock) // a stale socket from a daemon that crashed
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", sock)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	allowed := os.FileMode(0o600)
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("-sock-group: %w", err)
		}
		gid, _ := strconv.Atoi(g.Gid)
		if err := os.Chown(sock, -1, gid); err != nil {
			ln.Close()
			return nil, err
		}
		if err := os.Chmod(sock, 0o660); err != nil {
			ln.Close()
			return nil, err
		}
		allowed = 0o660
	}
	if fi, err := os.Stat(sock); err == nil && fi.Mode().Perm()&^allowed != 0 {
		ln.Close()
		return nil, errors.New("API socket is accessible to others; refusing to serve")
	}
	return ln, nil
}

// images are the named sandbox kinds this daemon offers (Day 20). The
// browser image exists only if its rootfs has been built: say so either way.
func images(browserRootfs string) map[string]daemon.Image {
	// Until the first versioned build, the Day 20 image is where it was.
	if _, err := os.Stat(browserRootfs); err != nil && browserRootfs == "/mnt/sbx/rootfs/browser-current" {
		if fi, err := os.Stat("/mnt/sbx/rootfs/browser"); err == nil && fi.IsDir() {
			browserRootfs = "/mnt/sbx/rootfs/browser"
		}
	}
	if fi, err := os.Stat(browserRootfs); err != nil || !fi.IsDir() {
		log.Printf("no browser image: %s doesn't exist (build it with scripts/build-browser-rootfs.sh)", browserRootfs)
		return nil
	}
	log.Printf("browser image: %s (2048 MiB, network, browse policy)", browserRootfs)
	return map[string]daemon.Image{
		"browser": {Rootfs: browserRootfs, MemMiB: 2048, Network: true, Policy: "browse"},
	}
}

// lockExclusive takes an exclusive flock on path, holding it until release
// (or until this process dies: the kernel drops flocks with their owner, so
// a crash, even kill -9, never leaves a stale lock behind).
func lockExclusive(path string) (release func(), err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder, _ := os.ReadFile(path)
		f.Close()
		return nil, fmt.Errorf("another sbxd (pid %s) is already using %s: two daemons sharing a registry or state directory would destroy each other's sandboxes",
			strings.TrimSpace(string(holder)), path)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(fmt.Sprintf("%d\n", os.Getpid())), 0)
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// snapshotStore connects the S3 snapshot store, if one is configured. The
// credentials come from the environment, never from flags: a flag's value
// is visible in ps to every user on the machine.
func snapshotStore(ctx context.Context, url, bucket string) daemon.SnapshotStore {
	if url == "" {
		return nil
	}
	c := &s3.Client{Endpoint: url, AccessKey: os.Getenv("SBX_S3_ACCESS_KEY"), SecretKey: os.Getenv("SBX_S3_SECRET_KEY")}
	// A store started at the same time may answer before it can store
	// anything (SeaweedFS does): retry making the bucket for a while.
	deadline := time.Now().Add(60 * time.Second)
	for {
		err := c.MakeBucket(ctx, bucket)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			log.Fatalf("snapshot store %s: %v", url, err)
		}
		time.Sleep(time.Second)
	}
	log.Printf("snapshot store: %s, bucket %s", url, bucket)
	return &store.S3{Client: c, Bucket: bucket}
}
