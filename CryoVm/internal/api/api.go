// Package api holds the types the daemon and its clients exchange. It has no
// dependencies on purpose: the CLI imports it without pulling in SQLite
// (which needs cgo) or any backend.
package api

import "time"

// State is a sandbox's lifecycle state.
type State string

const (
	Creating State = "creating"
	Running  State = "running"
	// Paused: checkpointed to disk and stopped (Day 10). Its memory,
	// processes and files are in a checkpoint image; nothing runs.
	Paused State = "paused"
	// Checkpointing: being saved. Briefly, nothing else may touch it.
	Checkpointing State = "checkpointing"
	// Restoring: coming back from a checkpoint (Day 11). Same rule.
	Restoring State = "restoring"
	Stopping  State = "stopping"
	Stopped   State = "stopped"
	Failed    State = "failed"
)

// Terminal states never change again.
func (s State) Terminal() bool { return s == Stopped || s == Failed }

type Sandbox struct {
	ID        string    `json:"id"`
	Backend   string    `json:"backend"`
	State     State     `json:"state"`
	Rootfs    string    `json:"rootfs"`
	VCPUs     int       `json:"vcpus"`
	MemMiB    int       `json:"mem_mib"`
	PidsMax   int       `json:"pids_max"`
	Error     string    `json:"error,omitempty"` // why it failed, if it did
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Lifetime. ExpiresAt is nil for no deadline; IdleTimeoutS is 0 for no
	// idle limit. LastActive is the daemon's in-memory view of the last API
	// activity, set only while the sandbox is live.
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	IdleTimeoutS int        `json:"idle_timeout_s,omitempty"`
	LastActive   *time.Time `json:"last_active,omitempty"`

	// ResumeOnStart marks a sandbox the daemon paused when it shut down
	// (Day 12): the next daemon resumes it. A sandbox you paused yourself
	// stays paused.
	ResumeOnStart bool `json:"resume_on_start,omitempty"`

	// IdleAction is what the idle timeout does: "pause" (Day 13) or
	// "destroy" (Day 9). WakeOnUse marks a sandbox paused because it was
	// idle: using it resumes it. A sandbox you paused yourself stays paused.
	IdleAction string `json:"idle_action,omitempty"`
	WakeOnUse  bool   `json:"wake_on_use,omitempty"`

	// ForkedFrom is the sandbox this one was forked from (Day 14).
	ForkedFrom string `json:"forked_from,omitempty"`

	// Network (Day 16): NetSlot is the sandbox's network slot, from 1; 0 is
	// no network, so the zero value can never mean "networked" by accident.
	// Inside, every networked sandbox is 10.89.0.2; NetAddr is the address
	// the host sees its traffic come from, unique to it.
	NetSlot int    `json:"net_slot,omitempty"`
	NetAddr string `json:"net_addr,omitempty"`

	// EgressPolicy is how the proxy judges its traffic (Day 20): "" or
	// "allowlist" (names on the allowlist), or "browse" (the public internet).
	EgressPolicy string `json:"egress_policy,omitempty"`
}

const (
	IdlePause   = "pause"
	IdleDestroy = "destroy"
)

type Event struct {
	Seq       int64     `json:"seq"`
	SandboxID string    `json:"sandbox_id"`
	From      State     `json:"from"` // empty for the first event
	To        State     `json:"to"`
	At        time.Time `json:"at"`
	Detail    string    `json:"detail,omitempty"`
}

type CreateRequest struct {
	ID      string `json:"id,omitempty"`
	Rootfs  string `json:"rootfs,omitempty"`
	VCPUs   int    `json:"vcpus,omitempty"`
	MemMiB  int    `json:"mem_mib,omitempty"`
	PidsMax int    `json:"pids_max,omitempty"`

	TTLSeconds   int    `json:"ttl_seconds,omitempty"`    // max lifetime; 0: the daemon's default
	IdleTimeoutS int    `json:"idle_timeout_s,omitempty"` // act after this long idle; 0: the daemon's default; -1: never
	IdleAction   string `json:"idle_action,omitempty"`    // "pause" or "destroy"; "": the daemon's default
	Network      bool   `json:"network,omitempty"`        // its own network namespace, NAT to the outside (Day 16)
	Image        string `json:"image,omitempty"`          // a named image (Day 20), e.g. "browser": rootfs, memory and policy
	Policy       string `json:"policy,omitempty"`         // egress policy: "allowlist" (default) or "browse"
}

// ExtendRequest sets a sandbox's deadline to TTLSeconds from now.
type ExtendRequest struct {
	TTLSeconds int `json:"ttl_seconds"`
}

type ExecRequest struct {
	Args      []string `json:"args"`
	Env       []string `json:"env,omitempty"`
	Dir       string   `json:"dir,omitempty"`
	TimeoutMs int64    `json:"timeout_ms,omitempty"`
	Stdin     []byte   `json:"stdin,omitempty"`
}

// ExecLine is one line of an exec response, which streams as NDJSON: any
// number of output lines, then exactly one line with Exit or Error.
type ExecLine struct {
	Stream string      `json:"stream,omitempty"` // "stdout" or "stderr"
	Data   []byte      `json:"data,omitempty"`
	Exit   *ExitStatus `json:"exit,omitempty"`
	Error  *Error      `json:"error,omitempty"`
}

type ExitStatus struct {
	Code     int    `json:"code"`
	Signal   string `json:"signal,omitempty"`
	TimedOut bool   `json:"timed_out,omitempty"`
}

type TransferResult struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Error is the body of every failed response.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes.
const (
	CodeNotFound    = "not_found"
	CodeExists      = "exists"
	CodeConflict    = "conflict"
	CodeInvalid     = "invalid"
	CodeForbidden   = "forbidden"
	CodeUnsupported = "unsupported"
	CodeChecksum    = "checksum"
	CodeTimeout     = "timeout"
	CodeInternal    = "internal"
)

// A file download's checksum is only known once the body has been sent, so
// it travels in HTTP trailers, after the body.
const (
	TrailerSHA256 = "Sbx-Sha256"
	TrailerSize   = "Sbx-Size"
	TrailerError  = "Sbx-Error"
)

// ShellProtocol is the protocol name in the Upgrade header for an
// interactive shell. After the 101 response, both directions carry the
// agent's framing (length-prefixed JSON): pty_in, resize and detach from
// the client; shell_ready, pty_out, detached, shell_exit and error from the
// daemon.
const ShellProtocol = "sbx-shell"

type ProcStartRequest struct {
	Args []string `json:"args"`
	Env  []string `json:"env,omitempty"`
	Dir  string   `json:"dir,omitempty"`
}

type ProcStarted struct {
	ID  string `json:"id"`
	PID int    `json:"pid"`
}

type ProcInfo struct {
	ID       string    `json:"id"`
	Args     []string  `json:"args"`
	PID      int       `json:"pid"`
	Running  bool      `json:"running"`
	ExitCode int       `json:"exit_code"`
	Signal   string    `json:"signal,omitempty"`
	Started  time.Time `json:"started"`
	Ended    time.Time `json:"ended,omitempty"`
	LogBytes int64     `json:"log_bytes"`
}

type SignalRequest struct {
	Signal int `json:"signal"`
}

// LogsEnd is how a logs response ended, from its trailers.
type LogsEnd struct {
	Next    int64
	Skipped int64
	Exited  bool
}

// A logs response streams the raw output; where it ended is only known
// afterwards, so it travels in trailers.
const (
	TrailerNextOffset = "Sbx-Next-Offset"
	TrailerSkipped    = "Sbx-Skipped"
	TrailerExited     = "Sbx-Exited"
)

// Stats is a sandbox's resource use and limits, as the host sees them.
type Stats struct {
	Cgroup             string  `json:"cgroup"`
	MemoryBytes        int64   `json:"memory_bytes"`
	MemoryPeak         int64   `json:"memory_peak"`
	MemoryLimit        int64   `json:"memory_limit"` // 0: unlimited
	OOMKills           int64   `json:"oom_kills"`
	CPUUsageMicros     int64   `json:"cpu_usage_us"`
	CPUThrottledMicros int64   `json:"cpu_throttled_us"`
	ThrottledPeriods   int64   `json:"throttled_periods"`
	CPUQuota           float64 `json:"cpu_quota"` // cores; 0: unlimited
	CPUs               string  `json:"cpus"`
	Pids               int64   `json:"pids"`
	PidsLimit          int64   `json:"pids_limit"` // 0: unlimited
}

// AuditEntry is one recorded action. Entries form a hash chain: Hash covers
// this entry's fields and PrevHash, the previous entry's Hash, so editing or
// deleting any entry breaks every hash after it.
type AuditEntry struct {
	Seq        int64     `json:"seq"`
	At         time.Time `json:"at"`
	SandboxID  string    `json:"sandbox_id,omitempty"`
	Actor      string    `json:"actor"` // who: from the socket's peer credentials, or "sbxd"
	Action     string    `json:"action"`
	Detail     string    `json:"detail,omitempty"`
	Outcome    string    `json:"outcome"` // "ok" or "error"
	Error      string    `json:"error,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	PrevHash   string    `json:"prev_hash"`
	Hash       string    `json:"hash"`
}

// AuditVerify is the result of checking the whole chain.
type AuditVerify struct {
	OK       bool   `json:"ok"`
	Entries  int64  `json:"entries"`
	Head     string `json:"head"`                // the last entry's hash: write it down elsewhere
	BrokenAt int64  `json:"broken_at,omitempty"` // first bad entry's seq
	Problem  string `json:"problem,omitempty"`
}

type CheckpointRequest struct {
	// LeaveRunning takes a snapshot and keeps the sandbox running.
	// Otherwise the sandbox stops and is paused, its state on disk.
	LeaveRunning bool `json:"leave_running,omitempty"`
	// Force checkpoints even while operations are in progress (an exec,
	// an attached shell): they are cut off. Without it, a busy sandbox is
	// refused.
	Force bool `json:"force,omitempty"`
}

// Checkpoint is one saved image of a sandbox.
type Checkpoint struct {
	ID          string    `json:"id"`
	SandboxID   string    `json:"sandbox_id"`
	CreatedAt   time.Time `json:"created_at"`
	ImageBytes  int64     `json:"image_bytes"`
	DurationMs  int64     `json:"duration_ms"`
	LeftRunning bool      `json:"left_running"`
	Path        string    `json:"path"`

	// Where the image is (the S3 snapshot store): on this machine's disk,
	// in the object store, or both. A checkpoint with neither is never kept.
	Local  bool `json:"local"`
	Remote bool `json:"remote,omitempty"`
}

// ResumeRequest picks which checkpoint to resume a paused sandbox from:
// empty means the one that paused it; an earlier snapshot's ID rolls the
// sandbox back to that moment.
type ResumeRequest struct {
	Checkpoint string `json:"checkpoint,omitempty"`
}

// ForkRequest makes new sandboxes from one snapshot of another. Without
// Checkpoint, a running sandbox is snapshotted now (without disturbing it)
// and a sleeping one is forked from its latest pause, without waking it.
type ForkRequest struct {
	ID         string `json:"id,omitempty"`         // the new sandbox's ID; only with Count 1
	Checkpoint string `json:"checkpoint,omitempty"` // fork from this checkpoint of the source
	Count      int    `json:"count,omitempty"`      // how many forks (default 1, at most 16)
	// Force snapshots a busy source anyway: the snapshot quiesces it,
	// cutting off its execs and detaching its shells.
	Force bool `json:"force,omitempty"`
}

// ImageInfo is a named image and its versions (Day 21).
type ImageInfo struct {
	Name     string         `json:"name"`
	Path     string         `json:"path"` // what the daemon was given: for a versioned image, its -current link
	MemMiB   int            `json:"mem_mib,omitempty"`
	Policy   string         `json:"policy,omitempty"`
	Versions []ImageVersion `json:"versions"`
}

// ImageVersion is one version of an image: current or not, and how many
// live sandboxes use it (paused ones too: they'll resume on it).
type ImageVersion struct {
	Path      string `json:"path"`
	Current   bool   `json:"current,omitempty"`
	Sandboxes int    `json:"sandboxes"`
	Paused    int    `json:"paused,omitempty"`
}
