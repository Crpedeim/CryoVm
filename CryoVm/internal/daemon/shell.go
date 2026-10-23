package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

// frameConn serializes frame writes to the client's connection.
type frameConn struct {
	mu sync.Mutex
	w  interface{ Write([]byte) (int, error) }
}

func (f *frameConn) send(typ string, body any) error {
	m, err := agentproto.New(typ, 0, body)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return agentproto.Write(f.w, m)
}

// ptyWriter turns the shell's output into pty_out frames. A slow client
// makes these writes block, which stops Run acknowledging output to the
// agent, which pauses the shell: backpressure all the way down.
type ptyWriter struct{ f *frameConn }

func (p ptyWriter) Write(b []byte) (int, error) {
	if err := p.f.send(agentproto.TypePtyOut, agentproto.Chunk{Data: b}); err != nil {
		return 0, err
	}
	return len(b), nil
}

func hasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func parseSize(q string) uint16 {
	n, err := strconv.ParseUint(q, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// shell upgrades the HTTP connection to a two-way stream, the way WebSockets
// and `docker attach` do: the client asks to switch protocols, we answer
// 101, take over the raw connection, and from then on both sides exchange
// frames. Everything that can fail does so before the 101, so those errors
// still get proper HTTP statuses.
func (h *handler) shell(w http.ResponseWriter, r *http.Request) {
	if !hasToken(r.Header, "Connection", "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), api.ShellProtocol) {
		writeJSON(w, http.StatusUpgradeRequired, api.Error{Code: api.CodeInvalid,
			Message: "this endpoint needs Connection: Upgrade and Upgrade: " + api.ShellProtocol})
		return
	}
	q := r.URL.Query()
	opts := sandbox.ShellOptions{
		SessionID: q.Get("session"), Cols: parseSize(q.Get("cols")), Rows: parseSize(q.Get("rows")),
		Command: q["cmd"], Env: q["env"], Dir: q.Get("dir"),
	}
	id := r.PathValue("id")
	sh, err := h.m.OpenShell(r.Context(), id, opts)
	if err != nil {
		writeErr(w, err)
		return
	}
	// An attached shell keeps the sandbox busy for as long as it lasts,
	// and how the attachment ended goes in the audit log.
	attached := time.Now()
	defer h.m.Hold(id)()
	var how string
	defer func() { h.m.Record(r.Context(), id, "shell.end", sh.SessionID+": "+how, attached, nil) }()
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = sh.Detach()
		writeErr(w, errors.New("connection can't be upgraded"))
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		_ = sh.Detach()
		return
	}
	defer conn.Close()
	// The 101 is written by hand: after Hijack, net/http no longer writes
	// anything for us.
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + api.ShellProtocol + "\r\n\r\n")
	if brw.Flush() != nil {
		_ = sh.Detach()
		return
	}

	out := &frameConn{w: conn}
	_ = out.send(agentproto.TypeShellReady, agentproto.ShellReady{SessionID: sh.SessionID, Created: sh.Created})

	// The request's context ends with this handler, which is the wrong
	// lifetime now: this context lasts exactly as long as the bridge.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		end, err := sh.Run(ctx, ptyWriter{out})
		switch {
		case err != nil:
			how = "connection lost"
		case end.Exited:
			how = fmt.Sprintf("shell exited %d", end.Code)
		default:
			how = "detached: " + end.Reason
		}
		switch {
		case err != nil && ctx.Err() == nil:
			_, code := classify(err)
			_ = out.send(agentproto.TypeError, agentproto.ErrorBody{Code: code, Message: err.Error()})
		case end.Exited:
			_ = out.send(agentproto.TypeShellExit, agentproto.Exit{Code: end.Code, Signal: end.Signal})
		case end.Detached:
			_ = out.send(agentproto.TypeDetached, agentproto.Detached{Reason: end.Reason})
		}
		conn.Close() // ends the read loop below
	}()

	// Read the client's frames. brw.Reader, not conn: it may already hold
	// bytes the client sent right after its request.
	for {
		m, err := agentproto.Read(brw.Reader)
		if err != nil {
			break // the client went away, or Run finished and closed conn
		}
		switch m.Type {
		case agentproto.TypePtyIn:
			var c agentproto.Chunk
			if m.Decode(&c) == nil {
				_, _ = sh.Write(c.Data)
			}
		case agentproto.TypeResize:
			var rs agentproto.Resize
			if m.Decode(&rs) == nil {
				_ = sh.Resize(rs.Cols, rs.Rows)
			}
		case agentproto.TypeDetach:
			_ = sh.Detach()
		}
	}
	// If the client vanished without detaching, cancelling makes Run
	// detach: the session survives for the next client.
	cancel()
	<-runDone
}

func (h *handler) sessions(w http.ResponseWriter, r *http.Request) {
	list, err := h.m.Sessions(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *handler) killSession(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if err := h.m.KillSession(r.Context(), r.PathValue("id"), sid); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"killed": sid})
}
