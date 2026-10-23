// Package firecracker adapts the Firecracker microVM code in internal/vm to
// the sandbox.Backend interface. It needs /dev/kvm. Exec arrives with the
// guest agent; until then a Firecracker sandbox only has its serial console.
package firecracker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Crpedeim/sbx/internal/agent"
	"github.com/Crpedeim/sbx/internal/sandbox"
	"github.com/Crpedeim/sbx/internal/vm"
)

type Config struct {
	FirecrackerBin string // default "firecracker"
	SocketDir      string // where each VM's API socket lives
}

type Backend struct {
	cfg Config
}

var _ sandbox.Backend = (*Backend)(nil)

func New(cfg Config) (*Backend, error) {
	if cfg.FirecrackerBin == "" {
		cfg.FirecrackerBin = "firecracker"
	}
	if cfg.SocketDir == "" {
		cfg.SocketDir = os.TempDir()
	}
	if err := os.MkdirAll(cfg.SocketDir, 0o755); err != nil {
		return nil, err
	}
	return &Backend{cfg: cfg}, nil
}

func (b *Backend) Name() string { return "firecracker" }

func (b *Backend) Create(ctx context.Context, s sandbox.Spec) (sandbox.Sandbox, error) {
	if err := sandbox.ValidateID(s.ID); err != nil {
		return nil, err
	}
	if s.Kernel == "" {
		return nil, fmt.Errorf("firecracker: a kernel image is required")
	}
	kernel, err := filepath.Abs(s.Kernel)
	if err != nil {
		return nil, err
	}
	rootfs, err := filepath.Abs(s.Rootfs)
	if err != nil {
		return nil, err
	}
	cfg := vm.Config{
		FirecrackerBin: b.cfg.FirecrackerBin,
		SocketPath:     filepath.Join(b.cfg.SocketDir, "sbx-"+s.ID+".sock"),
		KernelPath:     kernel,
		RootfsPath:     rootfs,
		VCPUs:          orDefault(s.VCPUs, 1),
		MemMiB:         orDefault(s.MemMiB, 256),
	}
	if s.Console != nil {
		cfg.Stdin, cfg.Stdout, cfg.Stderr = s.Console.Stdin, s.Console.Stdout, s.Console.Stderr
	}
	v, err := vm.Start(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Sandbox{id: s.ID, vm: v}, nil
}

type Sandbox struct {
	id string
	vm *vm.VM
}

var _ sandbox.Sandbox = (*Sandbox)(nil)

func (s *Sandbox) ID() string { return s.id }

func (s *Sandbox) Exec(context.Context, sandbox.ExecRequest) (sandbox.ExecResult, error) {
	return sandbox.ExecResult{}, fmt.Errorf("firecracker exec needs the guest agent: %w", sandbox.ErrUnsupported)
}

func (s *Sandbox) Shutdown(ctx context.Context, grace time.Duration) error {
	return s.vm.Shutdown(ctx, grace)
}

func (s *Sandbox) Exited() <-chan struct{} { return s.vm.Exited() }

func (s *Sandbox) Agent(context.Context) (*agent.Conn, error) {
	return nil, fmt.Errorf("firecracker agent transport (vsock) not built yet: %w", sandbox.ErrUnsupported)
}

var errNoFiles = fmt.Errorf("firecracker file operations need the vsock agent: %w", sandbox.ErrUnsupported)

func (s *Sandbox) WriteFile(context.Context, string, io.Reader, sandbox.WriteOptions) (sandbox.TransferResult, error) {
	return sandbox.TransferResult{}, errNoFiles
}

func (s *Sandbox) ReadFile(context.Context, string, io.Writer) (sandbox.TransferResult, error) {
	return sandbox.TransferResult{}, errNoFiles
}

func (s *Sandbox) ListDir(context.Context, string) (sandbox.ListResult, error) {
	return sandbox.ListResult{}, errNoFiles
}

func (s *Sandbox) Stat(context.Context, string) (sandbox.FileInfo, error) {
	return sandbox.FileInfo{}, errNoFiles
}

var errNoShell = fmt.Errorf("firecracker shells need the vsock agent: %w", sandbox.ErrUnsupported)

func (s *Sandbox) OpenShell(context.Context, sandbox.ShellOptions) (*agent.Shell, error) {
	return nil, errNoShell
}

func (s *Sandbox) Sessions(context.Context) (sandbox.SessionList, error) {
	return sandbox.SessionList{}, errNoShell
}

func (s *Sandbox) KillSession(context.Context, string) error { return errNoShell }

func orDefault(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

var errNoProcs = fmt.Errorf("firecracker background processes need the vsock agent: %w", sandbox.ErrUnsupported)

func (s *Sandbox) StartProcess(context.Context, sandbox.ProcStart) (sandbox.ProcStarted, error) {
	return sandbox.ProcStarted{}, errNoProcs
}

func (s *Sandbox) Processes(context.Context) ([]sandbox.ProcInfo, error) { return nil, errNoProcs }
func (s *Sandbox) Signal(context.Context, string, int) error             { return errNoProcs }
func (s *Sandbox) Wait(context.Context, string) (sandbox.ProcInfo, error) {
	return sandbox.ProcInfo{}, errNoProcs
}

func (s *Sandbox) Logs(context.Context, string, int64, bool, io.Writer) (sandbox.LogsEnd, error) {
	return sandbox.LogsEnd{}, errNoProcs
}

func (s *Sandbox) RemoveProcess(context.Context, string) error { return errNoProcs }

func (s *Sandbox) Stats(context.Context) (sandbox.Stats, error) {
	return sandbox.Stats{}, fmt.Errorf("firecracker stats come with the jailer's cgroups: %w", sandbox.ErrUnsupported)
}

func (s *Sandbox) Reclaim(context.Context) (sandbox.Reclaimed, error) {
	return sandbox.Reclaimed{}, fmt.Errorf("firecracker reclaim needs the vsock agent: %w", sandbox.ErrUnsupported)
}

func (s *Sandbox) Checkpoint(context.Context, sandbox.CheckpointOptions) (sandbox.CheckpointResult, error) {
	return sandbox.CheckpointResult{}, fmt.Errorf("firecracker snapshots are designed but not built: %w", sandbox.ErrUnsupported)
}

func (b *Backend) Restore(context.Context, string, string) (sandbox.Sandbox, error) {
	return nil, fmt.Errorf("firecracker snapshots are designed but not built: %w", sandbox.ErrUnsupported)
}

func (s *Sandbox) SetIdentity(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("firecracker identity needs the vsock agent: %w", sandbox.ErrUnsupported)
}
