package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

func toAPI(p sandbox.ProcInfo) api.ProcInfo {
	return api.ProcInfo{ID: p.ID, Args: p.Args, PID: p.PID, Running: p.Running, ExitCode: p.ExitCode,
		Signal: p.Signal, Started: p.Started, Ended: p.Ended, LogBytes: p.LogBytes}
}

func (h *handler) startProcess(w http.ResponseWriter, r *http.Request) {
	var req api.ProcStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Args) == 0 {
		writeErr(w, fmt.Errorf("%w: need a JSON body with args", ErrInvalid))
		return
	}
	res, err := h.m.StartProcess(r.Context(), r.PathValue("id"), sandbox.ProcStart{Args: req.Args, Env: req.Env, Dir: req.Dir})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, api.ProcStarted{ID: res.ID, PID: res.PID})
}

func (h *handler) listProcesses(w http.ResponseWriter, r *http.Request) {
	list, err := h.m.Processes(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]api.ProcInfo, 0, len(list))
	for _, p := range list {
		out = append(out, toAPI(p))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) getProcess(w http.ResponseWriter, r *http.Request) {
	p, err := h.m.Process(r.Context(), r.PathValue("id"), r.PathValue("proc"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAPI(p))
}

func (h *handler) signalProcess(w http.ResponseWriter, r *http.Request) {
	var req api.SignalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, fmt.Errorf("%w: need a JSON body with signal", ErrInvalid))
		return
	}
	if err := h.m.Signal(r.Context(), r.PathValue("id"), r.PathValue("proc"), req.Signal); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"signal": req.Signal})
}

// waitProcess is a long poll: the response comes when the process exits.
// If the client gives up, the request's context ends the wait, never the
// process.
func (h *handler) waitProcess(w http.ResponseWriter, r *http.Request) {
	p, err := h.m.Wait(r.Context(), r.PathValue("id"), r.PathValue("proc"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAPI(p))
}

func (h *handler) removeProcess(w http.ResponseWriter, r *http.Request) {
	if err := h.m.RemoveProcess(r.Context(), r.PathValue("id"), r.PathValue("proc")); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"removed": r.PathValue("proc")})
}

// flushWriter pushes each write onto the wire at once, so a followed log
// arrives line by line rather than when a buffer fills.
type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

// processLogs streams raw output from ?offset (default 0). With ?follow=1
// it keeps going until the process has exited. Checking that the process
// exists first gives a missing one a real 404; after the 200, the stream's
// outcome travels in trailers (Day 5).
func (h *handler) processLogs(w http.ResponseWriter, r *http.Request) {
	id, proc := r.PathValue("id"), r.PathValue("proc")
	var offset int64
	if s := r.URL.Query().Get("offset"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			writeErr(w, fmt.Errorf("%w: offset must be a byte position, 0 or more", ErrInvalid))
			return
		}
		offset = n
	}
	follow := r.URL.Query().Get("follow") == "1"
	if _, err := h.m.Process(r.Context(), id, proc); err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Trailer", api.TrailerNextOffset+", "+api.TrailerSkipped+", "+api.TrailerExited+", "+api.TrailerError)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}
	end, err := h.m.Logs(r.Context(), id, proc, offset, follow, flushWriter{w, fl})
	if err != nil {
		w.Header().Set(api.TrailerError, err.Error())
		return
	}
	w.Header().Set(api.TrailerNextOffset, strconv.FormatInt(end.Next, 10))
	w.Header().Set(api.TrailerSkipped, strconv.FormatInt(end.Skipped, 10))
	w.Header().Set(api.TrailerExited, strconv.FormatBool(end.Exited))
}
