// Package client talks to sbxd over its Unix socket. It imports only the
// api package, so programs using it (the CLI, later the MCP server) stay
// free of SQLite and backends.
package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
)

// Sentinel errors; an *APIError unwraps to the one matching its code.
var (
	ErrNotFound    = errors.New("not found")
	ErrConflict    = errors.New("conflict")
	ErrInvalid     = errors.New("invalid request")
	ErrForbidden   = errors.New("forbidden")
	ErrUnsupported = errors.New("unsupported")
)

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string { return e.Message }

func (e *APIError) Unwrap() error {
	switch e.Code {
	case api.CodeNotFound:
		return ErrNotFound
	case api.CodeConflict, api.CodeExists:
		return ErrConflict
	case api.CodeInvalid:
		return ErrInvalid
	case api.CodeForbidden:
		return ErrForbidden
	case api.CodeUnsupported:
		return ErrUnsupported
	}
	return nil
}

type Client struct {
	http *http.Client
	base string
}

// New returns a client for the daemon listening on the Unix socket sock.
// There is no overall timeout: exec and file transfers can legitimately
// run for a long time. Use the context to bound a call.
func New(sock string) *Client {
	return &Client{
		base: "http://sbxd", // the host is a placeholder; every request goes to sock
		http: &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		}},
	}
}

func decodeErr(resp *http.Response) error {
	var e api.Error
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e); err != nil || e.Code == "" {
		return &APIError{Status: resp.StatusCode, Code: api.CodeInternal, Message: resp.Status}
	}
	return &APIError{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sbxd unreachable (is it running?): %w", err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, decodeErr(resp)
	}
	return resp, nil
}

func (c *Client) json(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	resp, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func sbPath(id string, rest ...string) string {
	p := "/v1/sandboxes/" + url.PathEscape(id)
	for _, r := range rest {
		p += r
	}
	return p
}

func (c *Client) Health(ctx context.Context) error {
	var out map[string]string
	return c.json(ctx, http.MethodGet, "/v1/health", nil, &out)
}

func (c *Client) Create(ctx context.Context, req api.CreateRequest) (api.Sandbox, error) {
	var s api.Sandbox
	err := c.json(ctx, http.MethodPost, "/v1/sandboxes", req, &s)
	return s, err
}

func (c *Client) List(ctx context.Context, all bool) ([]api.Sandbox, error) {
	q := ""
	if all {
		q = "?all=1"
	}
	var out []api.Sandbox
	err := c.json(ctx, http.MethodGet, "/v1/sandboxes"+q, nil, &out)
	return out, err
}

func (c *Client) Get(ctx context.Context, id string) (api.Sandbox, error) {
	var s api.Sandbox
	err := c.json(ctx, http.MethodGet, sbPath(id), nil, &s)
	return s, err
}

func (c *Client) Destroy(ctx context.Context, id string) (api.Sandbox, error) {
	var s api.Sandbox
	err := c.json(ctx, http.MethodDelete, sbPath(id), nil, &s)
	return s, err
}

func (c *Client) Events(ctx context.Context, id string) ([]api.Event, error) {
	var out []api.Event
	err := c.json(ctx, http.MethodGet, sbPath(id, "/events"), nil, &out)
	return out, err
}

type ExecRequest struct {
	Args           []string
	Env            []string
	Dir            string
	Timeout        time.Duration
	Stdin          []byte
	Stdout, Stderr io.Writer
}

// Exec runs a command and streams its output to the request's writers as
// the NDJSON lines arrive. Cancelling ctx closes the connection, which the
// daemon turns into killing the command.
func (c *Client) Exec(ctx context.Context, id string, req ExecRequest) (api.ExitStatus, error) {
	b, err := json.Marshal(api.ExecRequest{
		Args: req.Args, Env: req.Env, Dir: req.Dir, TimeoutMs: req.Timeout.Milliseconds(), Stdin: req.Stdin,
	})
	if err != nil {
		return api.ExitStatus{}, err
	}
	resp, err := c.do(ctx, http.MethodPost, sbPath(id, "/exec"), bytes.NewReader(b))
	if err != nil {
		return api.ExitStatus{Code: -1}, err
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20) // a line holds at most one 32 KiB chunk, base64-encoded
	for sc.Scan() {
		var l api.ExecLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return api.ExitStatus{Code: -1}, fmt.Errorf("bad exec stream line: %w", err)
		}
		switch {
		case l.Exit != nil:
			return *l.Exit, nil
		case l.Error != nil:
			return api.ExitStatus{Code: -1}, &APIError{Status: http.StatusOK, Code: l.Error.Code, Message: l.Error.Message}
		case l.Stream == "stderr" && req.Stderr != nil:
			_, _ = req.Stderr.Write(l.Data)
		case l.Stream == "stdout" && req.Stdout != nil:
			_, _ = req.Stdout.Write(l.Data)
		}
	}
	if err := sc.Err(); err != nil {
		return api.ExitStatus{Code: -1}, err
	}
	if ctx.Err() != nil {
		return api.ExitStatus{Code: -1}, ctx.Err()
	}
	return api.ExitStatus{Code: -1}, errors.New("exec stream ended without an exit status")
}

type PutOptions struct {
	Mode   os.FileMode
	Mkdirs bool
}

// Put uploads r to path inside the sandbox, and checks the daemon's SHA-256
// against one computed here as the bytes left.
func (c *Client) Put(ctx context.Context, id, path string, r io.Reader, opts PutOptions) (api.TransferResult, error) {
	q := url.Values{"path": {path}}
	if opts.Mode != 0 {
		q.Set("mode", fmt.Sprintf("%o", opts.Mode.Perm()))
	}
	if opts.Mkdirs {
		q.Set("mkdirs", "1")
	}
	h := sha256.New()
	resp, err := c.do(ctx, http.MethodPut, sbPath(id, "/files?"+q.Encode()), io.TeeReader(r, h))
	if err != nil {
		return api.TransferResult{}, err
	}
	defer resp.Body.Close()
	var res api.TransferResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return res, err
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != res.SHA256 {
		return res, fmt.Errorf("checksum mismatch: sent %s, daemon stored %s", sum, res.SHA256)
	}
	return res, nil
}

// Fetch downloads path from the sandbox into w. The daemon sends the
// checksum in HTTP trailers, which only exist once the body has been read
// to the end; Fetch compares it with its own hash of what arrived.
func (c *Client) Fetch(ctx context.Context, id, path string, w io.Writer) (api.TransferResult, error) {
	q := url.Values{"path": {path}}
	resp, err := c.do(ctx, http.MethodGet, sbPath(id, "/files?"+q.Encode()), nil)
	if err != nil {
		return api.TransferResult{}, err
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), resp.Body)
	if err != nil {
		return api.TransferResult{}, err
	}
	if msg := resp.Trailer.Get(api.TrailerError); msg != "" {
		return api.TransferResult{}, fmt.Errorf("download failed midway: %s", msg)
	}
	want := resp.Trailer.Get(api.TrailerSHA256)
	got := hex.EncodeToString(h.Sum(nil))
	if want == "" {
		return api.TransferResult{}, errors.New("download ended without a checksum trailer")
	}
	if got != want {
		return api.TransferResult{}, fmt.Errorf("checksum mismatch: daemon sent %s, received %s", want, got)
	}
	if size, _ := strconv.ParseInt(resp.Trailer.Get(api.TrailerSize), 10, 64); size != n {
		return api.TransferResult{}, fmt.Errorf("size mismatch: daemon sent %d bytes, received %d", size, n)
	}
	return api.TransferResult{Size: n, SHA256: got}, nil
}

// FileInfo and ListResult mirror the agent's, decoded from JSON.
type FileInfo struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Mode      uint32    `json:"mode"`
	ModTime   time.Time `json:"mod_time"`
	IsDir     bool      `json:"is_dir,omitempty"`
	IsSymlink bool      `json:"is_symlink,omitempty"`
}

type ListResult struct {
	Entries   []FileInfo `json:"entries"`
	Truncated bool       `json:"truncated,omitempty"`
}

func (c *Client) ListDir(ctx context.Context, id, path string) (ListResult, error) {
	var res ListResult
	err := c.json(ctx, http.MethodGet, sbPath(id, "/ls?"+url.Values{"path": {path}}.Encode()), nil, &res)
	return res, err
}

func (c *Client) Stat(ctx context.Context, id, path string) (FileInfo, error) {
	var fi FileInfo
	err := c.json(ctx, http.MethodGet, sbPath(id, "/stat?"+url.Values{"path": {path}}.Encode()), nil, &fi)
	return fi, err
}

// Stats reports a sandbox's resource use and limits, as the host sees them.
func (c *Client) Stats(ctx context.Context, id string) (api.Stats, error) {
	var st api.Stats
	err := c.json(ctx, http.MethodGet, sbPath(id, "/stats"), nil, &st)
	return st, err
}

// Extend sets a sandbox's deadline to ttl from now.
func (c *Client) Extend(ctx context.Context, id string, ttl time.Duration) (api.Sandbox, error) {
	var s api.Sandbox
	err := c.json(ctx, http.MethodPatch, sbPath(id), api.ExtendRequest{TTLSeconds: int(ttl / time.Second)}, &s)
	return s, err
}

// Audit lists audit entries, newest first; sandboxID "" for all.
func (c *Client) Audit(ctx context.Context, sandboxID string, limit int) ([]api.AuditEntry, error) {
	q := url.Values{}
	if sandboxID != "" {
		q.Set("sandbox", sandboxID)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out []api.AuditEntry
	err := c.json(ctx, http.MethodGet, "/v1/audit?"+q.Encode(), nil, &out)
	return out, err
}

// VerifyAudit checks the audit log's hash chain end to end.
func (c *Client) VerifyAudit(ctx context.Context) (api.AuditVerify, error) {
	var v api.AuditVerify
	err := c.json(ctx, http.MethodGet, "/v1/audit/verify", nil, &v)
	return v, err
}

// Checkpoint saves a sandbox's state; without LeaveRunning it's paused.
func (c *Client) Checkpoint(ctx context.Context, id string, req api.CheckpointRequest) (api.Checkpoint, error) {
	var ck api.Checkpoint
	err := c.json(ctx, http.MethodPost, sbPath(id, "/checkpoints"), req, &ck)
	return ck, err
}

func (c *Client) Checkpoints(ctx context.Context, id string) ([]api.Checkpoint, error) {
	var out []api.Checkpoint
	err := c.json(ctx, http.MethodGet, sbPath(id, "/checkpoints"), nil, &out)
	return out, err
}

// Resume brings a paused sandbox back: from the checkpoint that paused it,
// or from the named one.
func (c *Client) Resume(ctx context.Context, id, checkpoint string) (api.Sandbox, error) {
	var s api.Sandbox
	err := c.json(ctx, http.MethodPost, sbPath(id, "/resume"), api.ResumeRequest{Checkpoint: checkpoint}, &s)
	return s, err
}

// Fork makes new sandboxes from one snapshot of the given one.
func (c *Client) Fork(ctx context.Context, id string, req api.ForkRequest) ([]api.Sandbox, error) {
	var out []api.Sandbox
	err := c.json(ctx, http.MethodPost, sbPath(id, "/fork"), req, &out)
	return out, err
}

// Images lists the daemon's images and their versions (Day 21).
func (c *Client) Images(ctx context.Context) ([]api.ImageInfo, error) {
	var out []api.ImageInfo
	err := c.json(ctx, http.MethodGet, "/v1/images", nil, &out)
	return out, err
}
