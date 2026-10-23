// sbx-boot boots one Firecracker microVM with its serial console attached to
// this terminal. Day 1 of the sandbox build.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Crpedeim/sbx/internal/vm"
)

func main() {
	fcBin := flag.String("firecracker", "firecracker", "path to the firecracker binary")
	kernel := flag.String("kernel", "", "uncompressed guest kernel (vmlinux)")
	rootfs := flag.String("rootfs", "", "ext4 root filesystem image")
	sock := flag.String("sock", "/tmp/sbx-fc.sock", "Firecracker API socket path")
	vcpus := flag.Int("vcpus", 1, "number of vCPUs")
	mem := flag.Int("mem", 256, "guest memory in MiB")
	auto := flag.Duration("auto-shutdown", 0, "shut the guest down after this long; 0 waits for `reboot` in the guest")
	flag.Parse()
	if *kernel == "" || *rootfs == "" {
		flag.Usage()
		os.Exit(2)
	}
	k, err := filepath.Abs(*kernel)
	if err != nil {
		log.Fatal(err)
	}
	r, err := filepath.Abs(*rootfs)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	t0 := time.Now()
	v, err := vm.Start(ctx, vm.Config{
		FirecrackerBin: *fcBin,
		SocketPath:     *sock,
		KernelPath:     k,
		RootfsPath:     r,
		VCPUs:          *vcpus,
		MemMiB:         *mem,
		Stdin:          os.Stdin,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
	})
	if err != nil {
		log.Fatalf("boot: %v", err)
	}
	log.Printf("InstanceStart accepted %s after launching firecracker", time.Since(t0).Round(time.Millisecond))

	if *auto > 0 {
		select {
		case <-v.Exited():
			// the guest rebooted on its own before the timer fired
		case <-time.After(*auto):
			log.Printf("auto-shutdown: sending Ctrl+Alt+Del")
		}
		if err := v.Shutdown(ctx, 10*time.Second); err != nil {
			log.Fatalf("shutdown: %v", err)
		}
		log.Printf("firecracker exited cleanly")
		return
	}
	if err := v.Wait(); err != nil {
		log.Fatalf("firecracker: %v", err)
	}
	log.Printf("guest rebooted; firecracker exited cleanly")
}
