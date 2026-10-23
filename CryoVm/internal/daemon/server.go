package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/Crpedeim/sbx/internal/agent"
	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/registry"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

// NewHandler returns the daemon's HTTP API. Routes use Go 1.22's pattern
// syntax: a method, then a path whose {id} segment r.PathValue reads.
func NewHandler(m *Manager) http.Handler {
	h := &handler{m: m}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/sandboxes", h.create)
	mux.HandleFunc("GET /v1/sandboxes", h.list)
	mux.HandleFunc("GET /v1/images", h.images)
	mux.HandleFunc("GET /v1/sandboxes/{id}", h.get)
	mux.HandleFunc("DELETE /v1/sandboxes/{id}", h.destroy)
	mux.HandleFunc("PATCH /v1/sandboxes/{id}", h.extend)
	mux.HandleFunc("POST /v1/sandboxes/{id}/checkpoints", h.checkpoint)
	mux.HandleFunc("GET /v1/sandboxes/{id}/checkpoints", h.listCheckpoints)
	mux.HandleFunc("POST /v1/sandboxes/{id}/resume", h.resume)
	mux.HandleFunc("POST /v1/sandboxes/{id}/fork", h.fork)
	mux.HandleFunc("GET /v1/audit", h.audit)
	mux.HandleFunc("GET /v1/audit/verify", h.verifyAudit)
	mux.HandleFunc("GET /v1/sandboxes/{id}/events", h.events)
	mux.HandleFunc("POST /v1/sandboxes/{id}/exec", h.exec)
	mux.HandleFunc("PUT /v1/sandboxes/{id}/files", h.putFile)
	mux.HandleFunc("GET /v1/sandboxes/{id}/files", h.getFile)
	mux.HandleFunc("GET /v1/sandboxes/{id}/ls", h.listDir)
	mux.HandleFunc("GET /v1/sandboxes/{id}/stat", h.stat)
	mux.HandleFunc("POST /v1/sandboxes/{id}/shell", h.shell)
	mux.HandleFunc("GET /v1/sandboxes/{id}/sessions", h.sessions)
	mux.HandleFunc("DELETE /v1/sandboxes/{id}/sessions/{sid}", h.killSession)
	mux.HandleFunc("GET /v1/sandboxes/{id}/stats", h.stats)
	mux.HandleFunc("POST /v1/sandboxes/{id}/processes", h.startProcess)
	mux.HandleFunc("GET /v1/sandboxes/{id}/processes", h.listProcesses)
	mux.HandleFunc("GET /v1/sandboxes/{id}/processes/{proc}", h.getProcess)
	mux.HandleFunc("POST /v1/sandboxes/{id}/processes/{proc}/signal", h.signalProcess)
	mux.HandleFunc("GET /v1/sandboxes/{id}/processes/{proc}/wait", h.waitProcess)
	mux.HandleFunc("GET /v1/sandboxes/{id}/processes/{proc}/logs", h.processLogs)
	mux.HandleFunc("DELETE /v1/sandboxes/{id}/processes/{proc}", h.removeProcess)
	return mux
}

type handler struct{ m *Manager }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// classify maps an internal error to an HTTP status and an API code, so a
// client can react to "not found" without parsing English.
func classify(err error) (int, string) {
	switch {
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, agent.ErrNotFound):
		return http.StatusNotFound, api.CodeNotFound
	case errors.Is(err, registry.ErrExists), errors.Is(err, agent.ErrExists):
		return http.StatusConflict, api.CodeExists
	case errors.Is(err, registry.ErrConflict), errors.Is(err, agent.ErrConflict):
		return http.StatusConflict, api.CodeConflict
	case errors.Is(err, ErrInvalid), errors.Is(err, agent.ErrInvalid),
		errors.Is(err, agent.ErrIsDir), errors.Is(err, agent.ErrNotDir):
		return http.StatusBadRequest, api.CodeInvalid
	case errors.Is(err, agent.ErrReadOnly), errors.Is(err, agent.ErrPermission):
		return http.StatusForbidden, api.CodeForbidden
	case errors.Is(err, sandbox.ErrUnsupported):
		return http.StatusNotImplemented, api.CodeUnsupported
	case errors.Is(err, agent.ErrChecksum):
		return http.StatusBadGateway, api.CodeChecksum
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, api.CodeTimeout
	default:
		return http.StatusInternalServerError, api.CodeInternal
	}
}

func writeErr(w http.ResponseWriter, err error) {
	status, code := classify(err)
	writeJSON(w, status, api.Error{Code: code, Message: err.Error()})
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var req api.CreateRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, fmt.Errorf("%w: bad JSON: %v", ErrInvalid, err))
			return
		}
	}
	rec, err := h.m.Create(r.Context(), req)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, rec)
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "1"
	recs, err := h.m.List(r.Context(), all)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, recs)
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	rec, err := h.m.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (h *handler) destroy(w http.ResponseWriter, r *http.Request) {
	rec, err := h.m.Destroy(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (h *handler) events(w http.ResponseWriter, r *http.Request) {
	evs, err := h.m.Events(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evs)
}

// lineWriter streams NDJSON: each Write becomes one output line, flushed at
// once so the client sees output as it happens. Stdout and stderr share it,
// so a mutex keeps lines whole.
type lineWriter struct {
	mu  *sync.Mutex
	enc *json.Encoder
	fl  http.Flusher
}

func (lw *lineWriter) line(l api.ExecLine) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	_ = lw.enc.Encode(l)
	if lw.fl != nil {
		lw.fl.Flush()
	}
}

type streamWriter struct {
	lw     *lineWriter
	stream string
}

func (s streamWriter) Write(p []byte) (int, error) {
	s.lw.line(api.ExecLine{Stream: s.stream, Data: p})
	return len(p), nil
}

// exec streams a command's output as NDJSON. Errors found before the
// command starts get a normal HTTP status; once the 200 has been sent, the
// status can't change, so later errors arrive as a final error line.
// If the client disconnects, r.Context() is cancelled and the agent kills
// the command: Ctrl+C on the CLI reaches the process in the sandbox.
func (h *handler) exec(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req api.ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Args) == 0 {
		writeErr(w, fmt.Errorf("%w: need a JSON body with args", ErrInvalid))
		return
	}
	if err := h.m.Ready(r.Context(), id); err != nil {
		// Refused before the command could start: still audited. A log of
		// only successful actions would hide exactly the probing an
		// investigator wants to see.
		h.m.Record(r.Context(), id, "exec", quoteArgs(req.Args), time.Now(), err)
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	lw := &lineWriter{mu: &sync.Mutex{}, enc: json.NewEncoder(w), fl: fl}
	if fl != nil {
		fl.Flush() // the client learns the command started
	}

	sreq := sandbox.ExecRequest{
		Args: req.Args, Env: req.Env, Dir: req.Dir,
		Timeout: time.Duration(req.TimeoutMs) * time.Millisecond,
		Stdout:  streamWriter{lw, "stdout"}, Stderr: streamWriter{lw, "stderr"},
	}
	if len(req.Stdin) > 0 {
		sreq.Stdin = bytes.NewReader(req.Stdin)
	}
	res, err := h.m.Exec(r.Context(), id, sreq)
	if err != nil {
		_, code := classify(err)
		lw.line(api.ExecLine{Error: &api.Error{Code: code, Message: err.Error()}})
		return
	}
	lw.line(api.ExecLine{Exit: &api.ExitStatus{Code: res.ExitCode, Signal: res.Signal, TimedOut: res.TimedOut}})
}

// filePath reads and checks the ?path= parameter.
func filePath(r *http.Request) (string, error) {
	p := r.URL.Query().Get("path")
	if p == "" || !path.IsAbs(p) {
		return "", fmt.Errorf("%w: ?path= must be an absolute path", ErrInvalid)
	}
	return p, nil
}

// putFile streams the request body into the sandbox: the body is never
// held in memory, so a 10 GB upload costs the daemon a few chunks of RAM.
func (h *handler) putFile(w http.ResponseWriter, r *http.Request) {
	p, err := filePath(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	opts := sandbox.WriteOptions{Mkdirs: r.URL.Query().Get("mkdirs") == "1"}
	if m := r.URL.Query().Get("mode"); m != "" {
		mode, err := strconv.ParseUint(m, 8, 32)
		if err != nil {
			writeErr(w, fmt.Errorf("%w: mode must be octal, like 0644", ErrInvalid))
			return
		}
		opts.Mode = os.FileMode(mode).Perm()
	}
	res, err := h.m.WriteFile(r.Context(), r.PathValue("id"), p, r.Body, opts)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.TransferResult{Size: res.Size, SHA256: res.SHA256})
}

// getFile streams a file out of the sandbox. A stat first turns the common
// failures (missing, a directory) into proper status codes. After that the
// 200 is committed, so the checksum and any late error travel in trailers,
// which HTTP sends after the body.
func (h *handler) getFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := filePath(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	fi, err := h.m.Stat(r.Context(), id, p)
	if err == nil && fi.IsDir {
		err = fmt.Errorf("%w: %s is a directory", ErrInvalid, p)
	}
	if err != nil {
		h.m.Record(r.Context(), id, "file.read", p, time.Now(), err) // refused, but recorded
		writeErr(w, err)
		return
	}
	w.Header().Set("Trailer", api.TrailerSHA256+", "+api.TrailerSize+", "+api.TrailerError)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	res, err := h.m.ReadFile(r.Context(), id, p, w)
	if err != nil {
		w.Header().Set(api.TrailerError, err.Error())
		return
	}
	w.Header().Set(api.TrailerSHA256, res.SHA256)
	w.Header().Set(api.TrailerSize, strconv.FormatInt(res.Size, 10))
}

func (h *handler) listDir(w http.ResponseWriter, r *http.Request) {
	p, err := filePath(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := h.m.ListDir(r.Context(), r.PathValue("id"), p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *handler) stat(w http.ResponseWriter, r *http.Request) {
	p, err := filePath(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	fi, err := h.m.Stat(r.Context(), r.PathValue("id"), p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, fi)
}

func (h *handler) stats(w http.ResponseWriter, r *http.Request) {
	st, err := h.m.Stats(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.Stats{
		Cgroup: st.Cgroup, MemoryBytes: st.MemoryBytes, MemoryPeak: st.MemoryPeak, MemoryLimit: st.MemoryLimit,
		OOMKills: st.OOMKills, CPUUsageMicros: st.CPUUsage.Microseconds(), CPUThrottledMicros: st.CPUThrottled.Microseconds(),
		ThrottledPeriods: st.ThrottledPeriods, CPUQuota: st.CPUQuota, CPUs: st.CPUs, Pids: st.Pids, PidsLimit: st.PidsLimit,
	})
}

// extend moves a sandbox's deadline: {"ttl_seconds": N} from now.
func (h *handler) extend(w http.ResponseWriter, r *http.Request) {
	var req api.ExtendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, fmt.Errorf("%w: need a JSON body with ttl_seconds", ErrInvalid))
		return
	}
	rec, err := h.m.Extend(r.Context(), r.PathValue("id"), time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// audit lists entries, newest first: ?sandbox=ID to filter, ?limit=N.
func (h *handler) audit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := h.m.AuditLog(r.Context(), r.URL.Query().Get("sandbox"), limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *handler) verifyAudit(w http.ResponseWriter, r *http.Request) {
	v, err := h.m.VerifyAudit(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *handler) checkpoint(w http.ResponseWriter, r *http.Request) {
	var req api.CheckpointRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, fmt.Errorf("%w: bad JSON: %v", ErrInvalid, err))
			return
		}
	}
	ck, err := h.m.Checkpoint(r.Context(), r.PathValue("id"), req)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, ck)
}

func (h *handler) listCheckpoints(w http.ResponseWriter, r *http.Request) {
	list, err := h.m.Checkpoints(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *handler) resume(w http.ResponseWriter, r *http.Request) {
	var req api.ResumeRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, fmt.Errorf("%w: bad JSON: %v", ErrInvalid, err))
			return
		}
	}
	rec, err := h.m.Resume(r.Context(), r.PathValue("id"), req.Checkpoint)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (h *handler) fork(w http.ResponseWriter, r *http.Request) {
	var req api.ForkRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, fmt.Errorf("%w: bad JSON: %v", ErrInvalid, err))
			return
		}
	}
	forks, err := h.m.Fork(r.Context(), r.PathValue("id"), req)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, forks)
}

func (h *handler) images(w http.ResponseWriter, r *http.Request) {
	imgs, err := h.m.Images(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, imgs)
}
