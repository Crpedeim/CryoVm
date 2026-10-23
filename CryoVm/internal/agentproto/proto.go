// Package agentproto is the wire format between the host and the guest agent
// inside a sandbox: length-prefixed JSON frames. A 4-byte big-endian length,
// then one JSON-encoded Message. JSON keeps every frame readable while
// debugging; the length prefix makes message boundaries unambiguous on a
// byte stream.
package agentproto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// MaxFrame bounds a single frame so a buggy or hostile peer can't make the
// other side allocate unbounded memory. Large file transfers (Day 4) are
// chunked into many frames.
const MaxFrame = 1 << 20 // 1 MiB

// Message types.
const (
	TypeHello   = "hello"   // agent → host, first frame on every connection
	TypeWelcome = "welcome" // host → agent, accepts the hello
	TypeReject  = "reject"  // host → agent, refuses the hello; host then closes
	TypePing    = "ping"    // host → agent
	TypePong    = "pong"    // agent → host, same ID as the ping

	// An exec is one request ID carrying a stream: the host sends exec, the
	// agent answers with any number of output frames and exactly one exit
	// frame, always last. The host may send cancel with the same ID.
	TypeExec   = "exec"   // host → agent: start a command
	TypeOutput = "output" // agent → host: a chunk of stdout or stderr
	TypeExit   = "exit"   // agent → host: the command finished
	TypeCancel = "cancel" // host → agent: kill the command's process group, or abort a transfer

	// File transfers stream like execs, with flow control: the sender may
	// have at most Window chunks unacknowledged, and the receiver acks each
	// chunk only after consuming it. Either way, the transfer ends with
	// exactly one done or error frame from the agent.
	TypeWriteOpen  = "write_open"  // host → agent: start an upload
	TypeWriteChunk = "write_chunk" // host → agent: upload data
	TypeWriteClose = "write_close" // host → agent: no more data; size and checksum
	TypeRead       = "read"        // host → agent: start a download
	TypeChunk      = "chunk"       // agent → host: download data
	TypeAck        = "ack"         // either way: one chunk consumed
	TypeDone       = "done"        // agent → host: transfer committed
	TypeError      = "error"       // agent → host: a request failed

	TypeList       = "list"        // host → agent: list a directory
	TypeListResult = "list_result" // agent → host
	TypeStat       = "stat"        // host → agent: describe one path
	TypeStatResult = "stat_result" // agent → host

	// A shell attachment is one request ID carrying a two-way stream. The
	// session behind it lives in the agent and outlives the attachment:
	// detaching (or losing the connection) leaves the shell running.
	TypeShellOpen   = "shell_open"   // host → agent: start a session, or attach to one
	TypeShellReady  = "shell_ready"  // agent → host: attached; which session
	TypePtyIn       = "pty_in"       // host → agent: keystrokes (acked like chunks)
	TypePtyOut      = "pty_out"      // agent → host: terminal output (acked like chunks)
	TypeResize      = "resize"       // host → agent: the window changed size
	TypeDetach      = "detach"       // host → agent: leave; the session keeps running
	TypeDetached    = "detached"     // agent → host: the attachment ended, session alive
	TypeShellExit   = "shell_exit"   // agent → host: the shell itself exited
	TypeShellList   = "shell_list"   // host → agent: list sessions
	TypeShellListed = "shell_listed" // agent → host
	TypeShellKill   = "shell_kill"   // host → agent: end a session
	TypeShellKilled = "shell_killed" // agent → host

	// Background processes belong to the agent, like shell sessions: they
	// run detached, outlive connections, and log to files in the sandbox.
	TypeProcStart    = "proc_start"    // host → agent: start one
	TypeProcStarted  = "proc_started"  // agent → host: its id and pid
	TypeProcList     = "proc_list"     // host → agent
	TypeProcListed   = "proc_listed"   // agent → host
	TypeProcSignal   = "proc_signal"   // host → agent: signal its process group
	TypeProcSignaled = "proc_signaled" // agent → host
	TypeProcWait     = "proc_wait"     // host → agent: reply when it exits
	TypeProcExited   = "proc_exited"   // agent → host: its final state
	TypeProcLogs     = "proc_logs"     // host → agent: read or follow its log
	TypeLogsEnd      = "logs_end"      // agent → host: after the chunks
	TypeProcRemove   = "proc_remove"   // host → agent: forget an exited one
	TypeProcRemoved  = "proc_removed"  // agent → host

	// The memory guard: the host sees the sandbox nearing its memory limit
	// and asks the agent to kill the process using the most memory, before
	// the kernel's OOM killer takes the whole sandbox down.
	TypeReclaim   = "reclaim"   // host → agent
	TypeReclaimed = "reclaimed" // agent → host: who was killed, if anyone

	// Before a checkpoint, the host asks the agent to let go of its
	// connection: a live connection to the host can't be saved in an image.
	// The agent acknowledges, closes its end, and redials as usual.
	TypeQuiesce  = "quiesce"  // host → agent
	TypeQuiesced = "quiesced" // agent → host: closing now

	// After a fork or a restore, the host tells the agent who it is now: a
	// fork's agent was started as its source, and any restore may have
	// produced a duplicate or a jump in time. The agent takes the ID,
	// publishes the new generation to programs, and acknowledges.
	TypeIdentity    = "identity"     // host → agent
	TypeIdentityAck = "identity_ack" // agent → host

	// A port tunnel is one request ID carrying a TCP connection that the
	// agent opens to a port on the sandbox's own loopback: how a server
	// started inside is reached from the host, with or without a network.
	// Bytes flow both ways under the same credit window as a shell (each
	// port_data is acked once delivered). Either side ends its direction
	// with port_eof, TCP's half-close, and the agent ends the tunnel with
	// exactly one final frame: port_closed once both directions have ended,
	// or error. The host may send cancel to drop the connection at once.
	TypePortOpen   = "port_open"   // host → agent: connect to a port inside
	TypePortReady  = "port_ready"  // agent → host: connected; which address answered
	TypePortData   = "port_data"   // either way: bytes (acked like chunks)
	TypePortEOF    = "port_eof"    // either way: no more bytes this way
	TypePortClosed = "port_closed" // agent → host: both ways have ended
	TypePortList   = "port_list"   // host → agent: which TCP ports something listens on
	TypePortListed = "port_listed" // agent → host
)

const (
	// ChunkSize is the payload of one transfer frame. After JSON's base64
	// (a third larger) it is still far below MaxFrame.
	ChunkSize = 256 << 10
	// Window is how many chunks may be in flight unacknowledged: 2 MiB.
	Window = 8
	// MaxListEntries keeps a listing inside one frame.
	MaxListEntries = 5000
)

// Error codes carried by error frames.
const (
	CodeNotFound   = "not_found"
	CodePermission = "permission"
	CodeReadOnly   = "read_only"
	CodeExists     = "exists"
	CodeIsDir      = "is_dir"
	CodeNotDir     = "not_dir"
	CodeChecksum   = "checksum"
	CodeInvalid    = "invalid"
	CodeCanceled   = "canceled"
	CodeConflict   = "conflict" // right request, wrong state (e.g. removing a running process)
	CodeRefused    = "refused"  // nothing listens on the port a tunnel asked for
	CodeIO         = "io"
)

// Output streams.
const (
	StreamStdout = "stdout"
	StreamStderr = "stderr"
)

// Message is one frame. ID pairs a request with its response, so many
// requests can be in flight on one connection.
type Message struct {
	Type string          `json:"type"`
	ID   uint64          `json:"id,omitempty"`
	Body json.RawMessage `json:"body,omitempty"`
}

type Hello struct {
	SandboxID string `json:"sandbox_id"`
	Version   string `json:"version"`
	PID       int    `json:"pid"`
}

type Welcome struct {
	HostTime time.Time `json:"host_time"`
}

type Reject struct {
	Reason string `json:"reason"`
}

// Exec starts a command. Stdin is sent whole, up to MaxStdin; streaming
// stdin arrives with terminals on Day 6.
type Exec struct {
	Args      []string `json:"args"`
	Env       []string `json:"env,omitempty"` // KEY=value, added to the agent's environment
	Dir       string   `json:"dir,omitempty"`
	Stdin     []byte   `json:"stdin,omitempty"`
	TimeoutMs int64    `json:"timeout_ms,omitempty"`
}

// MaxStdin keeps an Exec frame comfortably under MaxFrame after JSON's
// base64 encoding of []byte (which grows data by a third).
const MaxStdin = 512 << 10

type Output struct {
	Stream string `json:"stream"`
	Data   []byte `json:"data"`
}

// WriteOpen starts an upload to Path, an absolute path in the sandbox.
// Mode 0 means 0644. With Mkdirs, missing parent directories are created.
type WriteOpen struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode,omitempty"`
	Mkdirs bool   `json:"mkdirs,omitempty"`
}

type Chunk struct {
	Data []byte `json:"data"`
}

// WriteClose ends an upload. The agent commits the file only if what it
// received matches both Size and SHA256.
type WriteClose struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type ReadReq struct {
	Path string `json:"path"`
}

// Done ends a transfer successfully, with what the agent wrote or sent.
type Done struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type PathReq struct {
	Path string `json:"path"`
}

type FileInfo struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Mode      uint32    `json:"mode"` // permission bits
	ModTime   time.Time `json:"mod_time"`
	IsDir     bool      `json:"is_dir,omitempty"`
	IsSymlink bool      `json:"is_symlink,omitempty"`
}

type ListResult struct {
	Entries   []FileInfo `json:"entries"`
	Truncated bool       `json:"truncated,omitempty"`
}

// ShellOpen starts a new session (SessionID empty) or attaches to an
// existing one. Cols and Rows are the client's terminal size.
type ShellOpen struct {
	SessionID string   `json:"session_id,omitempty"`
	Cols      uint16   `json:"cols"`
	Rows      uint16   `json:"rows"`
	Command   []string `json:"command,omitempty"` // default: bash if present, else sh
	Env       []string `json:"env,omitempty"`
	Dir       string   `json:"dir,omitempty"`
}

type ShellReady struct {
	SessionID string `json:"session_id"`
	Created   bool   `json:"created"` // false: attached to an existing session
}

type Resize struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// Detached says why an attachment ended while the session lives on.
type Detached struct {
	Reason string `json:"reason"`
}

type SessionInfo struct {
	ID       string    `json:"id"`
	Command  []string  `json:"command"`
	Started  time.Time `json:"started"`
	Attached bool      `json:"attached"`
	Exited   bool      `json:"exited"`
}

type SessionList struct {
	Sessions []SessionInfo `json:"sessions"`
}

type ShellKill struct {
	SessionID string `json:"session_id"`
}

// ScrollbackSize is how much recent output each session keeps, replayed to
// whoever attaches next.
const ScrollbackSize = 256 << 10

type ProcStart struct {
	Args []string `json:"args"`
	Env  []string `json:"env,omitempty"`
	Dir  string   `json:"dir,omitempty"`
}

type ProcStarted struct {
	ID  string `json:"id"`
	PID int    `json:"pid"`
}

// ProcInfo describes a background process, running or exited.
type ProcInfo struct {
	ID       string    `json:"id"`
	Args     []string  `json:"args"`
	PID      int       `json:"pid"`
	Running  bool      `json:"running"`
	ExitCode int       `json:"exit_code"` // -1 while running or if a signal ended it
	Signal   string    `json:"signal,omitempty"`
	Started  time.Time `json:"started"`
	Ended    time.Time `json:"ended,omitempty"`
	LogBytes int64     `json:"log_bytes"` // total ever written; the next offset to read
}

type ProcRef struct {
	ID string `json:"id"`
}

type ProcSignal struct {
	ID     string `json:"id"`
	Signal int    `json:"signal"`
}

type ProcList struct {
	Processes []ProcInfo `json:"processes"`
}

// ProcLogs asks for a process's output from Offset, an absolute byte
// position in everything it has ever written. With Follow, the stream
// stays open and delivers new output until the process has exited.
type ProcLogs struct {
	ID     string `json:"id"`
	Offset int64  `json:"offset"`
	Follow bool   `json:"follow,omitempty"`
}

// LogsEnd follows the chunks. Next is the offset to ask for next time.
// Skipped counts bytes before Offset that had rotated away and were lost.
type LogsEnd struct {
	Next    int64 `json:"next"`
	Skipped int64 `json:"skipped,omitempty"`
	Exited  bool  `json:"exited"`
}

// Reclaimed reports the memory guard's victim. Killed is false when there
// was nothing to kill (no process but the agent).
type Reclaimed struct {
	Killed  bool   `json:"killed"`
	PID     int    `json:"pid,omitempty"`
	Command string `json:"command,omitempty"`
	RSS     int64  `json:"rss,omitempty"` // bytes
}

// Exit ends an exec. Error is set when the command never started (not
// found, not executable); then Code is -1. Signal is set when a signal
// killed the command; then Code is -1 too.
type Exit struct {
	Code     int    `json:"code"`
	Signal   string `json:"signal,omitempty"`
	TimedOut bool   `json:"timed_out,omitempty"`
	Canceled bool   `json:"canceled,omitempty"`
	Error    string `json:"error,omitempty"`
}

var ErrFrameTooLarge = errors.New("agentproto: frame exceeds MaxFrame")

// New builds a Message, encoding body as JSON (nil body → no body).
func New(typ string, id uint64, body any) (Message, error) {
	m := Message{Type: typ, ID: id}
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return Message{}, fmt.Errorf("agentproto: encode %s body: %w", typ, err)
		}
		m.Body = b
	}
	return m, nil
}

// Decode unmarshals m's body into v.
func (m Message) Decode(v any) error {
	if len(m.Body) == 0 {
		return fmt.Errorf("agentproto: %s frame has no body", m.Type)
	}
	return json.Unmarshal(m.Body, v)
}

// Write sends one frame. It is not safe for concurrent use on the same
// writer; callers serialize writes.
func Write(w io.Writer, m Message) error {
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrame {
		return ErrFrameTooLarge
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	_, err = w.Write(frame) // one Write: header and payload never interleave with another frame
	return err
}

// Read receives one frame. A clean close between frames returns io.EOF; a
// close in the middle of a frame returns io.ErrUnexpectedEOF.
func Read(r io.Reader) (Message, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Message{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return Message{}, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return Message{}, err
	}
	var m Message
	if err := json.Unmarshal(payload, &m); err != nil {
		return Message{}, fmt.Errorf("agentproto: bad frame: %w", err)
	}
	if m.Type == "" {
		return Message{}, errors.New("agentproto: frame without a type")
	}
	return m, nil
}

// Identity is who the agent is now. Generation is a fresh random token that
// changes whenever the sandbox might have been duplicated (a fork) or moved
// in time (a restore): programs that keep random state or secrets should
// renew them when it changes.
type Identity struct {
	SandboxID  string `json:"sandbox_id"`
	Generation string `json:"generation"`
}

// IdentityAck confirms the change, saying who the agent was before.
type IdentityAck struct {
	Previous string `json:"previous"`
	Identity
}

// PortOpen asks for a connection to Port inside the sandbox, on its
// loopback: a server listening on every address and one listening on
// localhost alone are reached the same way. Failing that, the agent tries
// the address a listening socket on Port is bound to.
type PortOpen struct {
	Port int `json:"port"`
}

// PortReady says which address answered: 127.0.0.1; ::1, for a server
// listening on IPv6's loopback alone; or the one address a server is bound
// to.
type PortReady struct {
	Addr string `json:"addr"`
}

// PortChunk is the most data one port_data frame carries.
const PortChunk = 32 << 10

// PortInfo is one TCP socket listening inside the sandbox, and the process
// holding it, when the agent can tell.
type PortInfo struct {
	Port    int    `json:"port"`
	Addr    string `json:"addr"` // what it's bound to; 0.0.0.0 and :: mean every address
	PID     int    `json:"pid,omitempty"`
	Command string `json:"command,omitempty"`
}

type PortList struct {
	Ports     []PortInfo `json:"ports"`
	Truncated bool       `json:"truncated,omitempty"`
}
