// Package sandbox defines what every isolation backend must provide. The
// daemon, CLI and MCP server talk only to these interfaces, so the backend
// (gVisor, Firecracker, ...) can be swapped without touching them.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/Crpedeim/sbx/internal/agent"
	"github.com/Crpedeim/sbx/internal/agentproto"
)

var (
	// ErrUnsupported means the backend can't do this yet (or ever).
	ErrUnsupported = errors.New("not supported by this backend")
	// ErrExited means the sandbox has already stopped.
	ErrExited = errors.New("sandbox has exited")
)

// Console wires a sandbox's console, where a backend has one.
type Console struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// Spec describes a sandbox to create. Fields a backend doesn't use are ignored.
type Spec struct {
	ID     string
	Rootfs string // gVisor: a directory; Firecracker: an ext4 image file
	Kernel string // Firecracker only
	VCPUs  int
	MemMiB int
	// PidsMax caps the number of processes and threads (0: no cap). How
	// gVisor applies it is measured by Day 8's integration test.
	PidsMax int

	// NetNS, if set, is a network namespace prepared by the daemon (Day
	// 16): the sandbox joins it and gVisor runs its own network stack on
	// the interface it finds there. Empty: no network at all.
	NetNS string

	// Env is added to the agent's environment, and so inherited by every
	// process it starts: the proxy settings of a networked sandbox (Day 18).
	Env []string

	Console *Console // optional
}

// Stats is a sandbox's resource use, read from its cgroup on the host. It
// covers everything the sandbox costs the host, including gVisor's own
// kernel, not just the programs inside.
type Stats struct {
	Cgroup string // the cgroup path, relative to the cgroup root

	MemoryBytes int64 // in use now
	MemoryPeak  int64 // highest seen (0 if the kernel doesn't report it)
	MemoryLimit int64 // 0: unlimited
	OOMKills    int64 // processes the kernel's out-of-memory killer ended

	CPUUsage         time.Duration // total CPU time used
	CPUThrottled     time.Duration // time spent held back by the CPU quota
	ThrottledPeriods int64
	CPUQuota         float64 // cores; 0: unlimited
	CPUs             string  // the CPUs it may run on, e.g. "0-1"

	Pids      int64
	PidsLimit int64 // 0: unlimited
}

// ExitReasoner is implemented by sandboxes that can say why they stopped
// on their own (for example, the out-of-memory killer).
type ExitReasoner interface {
	ExitReason() string
}

type ExecRequest struct {
	Args           []string
	Env            []string // KEY=value, added to the sandbox's environment
	Dir            string   // working directory inside the sandbox
	Timeout        time.Duration
	Stdin          io.Reader
	Stdout, Stderr io.Writer // receive output as it arrives
}

type ExecResult struct {
	ExitCode int    // -1 when a signal ended the command
	Signal   string // e.g. "killed"
	TimedOut bool
}

// Backend creates sandboxes of one isolation technology.
type Backend interface {
	Name() string
	Create(ctx context.Context, spec Spec) (Sandbox, error)
	// Restore brings a sandbox back from a checkpoint image (Day 11),
	// under the ID it had. There's no Sandbox to call it on: there's only
	// an image.
	Restore(ctx context.Context, id, imageDir string) (Sandbox, error)
}

// Sandbox is one running, isolated environment.
type Sandbox interface {
	ID() string
	// Exec runs a command to completion inside the sandbox. A non-zero exit
	// code is a result, not an error; err is for failures to run at all.
	Exec(ctx context.Context, req ExecRequest) (ExecResult, error)
	// Shutdown stops the sandbox politely, then by force after grace, and
	// releases its resources. It says so in the error if force was needed.
	Shutdown(ctx context.Context, grace time.Duration) error
	// Exited is closed once the sandbox has stopped.
	Exited() <-chan struct{}
	// Agent waits for the guest agent inside the sandbox to connect and
	// returns that connection. Backends without an agent return ErrUnsupported.
	Agent(ctx context.Context) (*agent.Conn, error)

	// File operations, on absolute paths inside the sandbox. Errors match
	// agent.ErrNotFound, agent.ErrReadOnly and friends with errors.Is.
	WriteFile(ctx context.Context, path string, r io.Reader, opts WriteOptions) (TransferResult, error)
	ReadFile(ctx context.Context, path string, w io.Writer) (TransferResult, error)
	ListDir(ctx context.Context, path string) (ListResult, error)
	Stat(ctx context.Context, path string) (FileInfo, error)

	// Terminal sessions. A session lives in the sandbox and outlives any
	// one attachment: detach, and it keeps running until it exits or is
	// killed.
	OpenShell(ctx context.Context, opts ShellOptions) (*agent.Shell, error)
	Sessions(ctx context.Context) (SessionList, error)
	KillSession(ctx context.Context, sessionID string) error

	// Background processes. Like sessions, they belong to the sandbox and
	// outlive connections; their output is logged inside the sandbox.
	StartProcess(ctx context.Context, req ProcStart) (ProcStarted, error)
	Processes(ctx context.Context) ([]ProcInfo, error)
	Signal(ctx context.Context, procID string, sig int) error
	Wait(ctx context.Context, procID string) (ProcInfo, error)
	Logs(ctx context.Context, procID string, offset int64, follow bool, w io.Writer) (LogsEnd, error)
	RemoveProcess(ctx context.Context, procID string) error

	// Ports. DialPort connects to a port on the sandbox's own loopback,
	// through the agent: a server inside is reached whether it listens on
	// every address or on localhost alone, with or without a network.
	// Ports lists the TCP sockets listening inside.
	DialPort(ctx context.Context, port int) (*agent.Tunnel, error)
	Ports(ctx context.Context) (PortList, error)

	// Stats reports resource use and limits, from the host's side.
	Stats(ctx context.Context) (Stats, error)

	// Reclaim kills the process inside using the most memory: the memory
	// guard's move before the kernel's OOM killer ends the whole sandbox.
	Reclaim(ctx context.Context) (Reclaimed, error)

	// Checkpoint saves the sandbox's whole state as an image in opts.Dir.
	// Without opts.LeaveRunning, the sandbox stops afterwards.
	Checkpoint(ctx context.Context, opts CheckpointOptions) (CheckpointResult, error)

	// SetIdentity tells the sandbox's agent who it is now (Day 15): after a
	// fork, a new ID; after any restore, a new generation. It returns the ID
	// the agent had before.
	SetIdentity(ctx context.Context, id, generation string) (previous string, err error)
}

type CheckpointOptions struct {
	Dir          string // where the image goes; created if needed
	LeaveRunning bool   // a snapshot: the sandbox keeps running
}

type CheckpointResult struct {
	ImageBytes int64
	Duration   time.Duration
}

// Releaser is implemented by sandboxes that can be let go of without being
// stopped: the host-side resources (the agent's listener) are closed, and
// the sandbox runs on, for another daemon to adopt (Day 12).
type Releaser interface {
	Release()
}

// File types are the agent's, re-exported so callers need one import.
type (
	WriteOptions   = agent.WriteOptions
	TransferResult = agent.TransferResult
	FileInfo       = agentproto.FileInfo
	ListResult     = agentproto.ListResult
	ShellOptions   = agent.ShellOptions
	ShellEnd       = agent.ShellEnd
	SessionList    = agentproto.SessionList
	SessionInfo    = agentproto.SessionInfo
	ProcStart      = agentproto.ProcStart
	ProcStarted    = agentproto.ProcStarted
	ProcInfo       = agentproto.ProcInfo
	LogsEnd        = agentproto.LogsEnd
	Reclaimed      = agentproto.Reclaimed
	PortInfo       = agentproto.PortInfo
	PortList       = agentproto.PortList
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidateID keeps IDs safe to use in file paths and command lines.
func ValidateID(id string) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("invalid sandbox id %q: use 1-63 lowercase letters, digits or '-'", id)
	}
	return nil
}
