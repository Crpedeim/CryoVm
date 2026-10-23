// Package vm owns the lifecycle of one Firecracker process: start it, wait
// for its API socket, configure and boot the guest, and shut it down.
package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/Crpedeim/sbx/internal/fc"
)

const DefaultBootArgs = "console=ttyS0 reboot=k panic=1"

type Config struct {
	FirecrackerBin string
	SocketPath     string
	KernelPath     string // must be absolute: Firecracker resolves paths from its own cwd
	RootfsPath     string // must be absolute
	VCPUs          int
	MemMiB         int
	BootArgs       string

	// The guest's serial console is wired to Firecracker's stdio.
	Stdin          io.Reader
	Stdout, Stderr io.Writer

	// BinArgs go before --api-sock. Empty for the real binary; tests use it
	// to run a fake Firecracker.
	BinArgs []string
}

type VM struct {
	cfg     Config
	cmd     *exec.Cmd
	client  *fc.Client
	exited  chan struct{}
	waitErr error
}

// Start launches Firecracker, configures the guest and boots it. On any
// failure the process is killed, so a failed Start never leaks a VM.
func Start(ctx context.Context, cfg Config) (*VM, error) {
	if cfg.BootArgs == "" {
		cfg.BootArgs = DefaultBootArgs
	}
	_ = os.Remove(cfg.SocketPath) // a stale socket makes Firecracker refuse to start

	args := append(append([]string{}, cfg.BinArgs...), "--api-sock", cfg.SocketPath)
	// exec.Command, not CommandContext: cancelling ctx must not kill a running VM.
	cmd := exec.Command(cfg.FirecrackerBin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = cfg.Stdin, cfg.Stdout, cfg.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start firecracker: %w", err)
	}

	v := &VM{cfg: cfg, cmd: cmd, client: fc.NewClient(cfg.SocketPath), exited: make(chan struct{})}
	go func() {
		v.waitErr = cmd.Wait()
		close(v.exited)
	}()

	if err := v.waitForSocket(ctx, 2*time.Second); err != nil {
		v.kill()
		return nil, err
	}
	if err := v.boot(ctx); err != nil {
		v.kill()
		return nil, err
	}
	return v, nil
}

func (v *VM) boot(ctx context.Context) error {
	c := v.client
	if err := c.SetMachineConfig(ctx, fc.MachineConfig{VcpuCount: v.cfg.VCPUs, MemSizeMib: v.cfg.MemMiB}); err != nil {
		return err
	}
	if err := c.SetBootSource(ctx, fc.BootSource{KernelImagePath: v.cfg.KernelPath, BootArgs: v.cfg.BootArgs}); err != nil {
		return err
	}
	if err := c.SetDrive(ctx, fc.Drive{DriveID: "rootfs", PathOnHost: v.cfg.RootfsPath, IsRootDevice: true}); err != nil {
		return err
	}
	return c.Start(ctx)
}

// waitForSocket polls until the API socket accepts connections, the process
// dies, or the timeout passes.
func (v *VM) waitForSocket(ctx context.Context, timeout time.Duration) error {
	deadline := time.After(timeout)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if conn, err := net.Dial("unix", v.cfg.SocketPath); err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-v.exited:
			return fmt.Errorf("firecracker exited before its API socket was ready: %v", v.waitErr)
		case <-deadline:
			return fmt.Errorf("API socket %s not ready after %s", v.cfg.SocketPath, timeout)
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// Shutdown asks the guest to shut down and waits up to grace for Firecracker
// to exit. If the guest ignores the request, the process is killed and an
// error says so.
func (v *VM) Shutdown(ctx context.Context, grace time.Duration) error {
	select {
	case <-v.exited:
		return v.finish()
	default:
	}
	if err := v.client.SendCtrlAltDel(ctx); err != nil {
		v.kill()
		return fmt.Errorf("send ctrl-alt-del: %w (process killed)", err)
	}
	select {
	case <-v.exited:
		return v.finish()
	case <-time.After(grace):
		v.kill()
		return fmt.Errorf("guest did not shut down within %s (process killed)", grace)
	}
}

// Wait blocks until Firecracker exits on its own, e.g. after `reboot` in the guest.
func (v *VM) Wait() error {
	<-v.exited
	return v.finish()
}

// Exited is closed once the Firecracker process has exited.
func (v *VM) Exited() <-chan struct{} { return v.exited }

func (v *VM) finish() error {
	_ = os.Remove(v.cfg.SocketPath)
	var exitErr *exec.ExitError
	if errors.As(v.waitErr, &exitErr) {
		return fmt.Errorf("firecracker exited with code %d", exitErr.ExitCode())
	}
	return v.waitErr
}

func (v *VM) kill() {
	_ = v.cmd.Process.Kill()
	<-v.exited
	_ = os.Remove(v.cfg.SocketPath)
}
