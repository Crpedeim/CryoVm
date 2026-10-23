package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Crpedeim/sbx/internal/agent"
	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/sandbox"
)

// DialPort opens a connection to a port inside a sandbox, through its agent,
// waking the sandbox if it's asleep: how a server an agent started there is
// reached from the host. It goes through no network, so it reaches a server
// listening on the sandbox's localhost alone, in a sandbox with no network
// at all, and the sandbox's default-deny rules stay as they are. The caller
// holds the sandbox busy for as long as the connection lasts (Hold), and
// records its end, as for a shell.
func (m *Manager) DialPort(ctx context.Context, id string, port int) (t *agent.Tunnel, err error) {
	start := time.Now()
	defer func() {
		detail := fmt.Sprintf("port %d", port)
		if t != nil {
			detail += " → " + t.Addr
		}
		m.Record(ctx, id, "port.open", detail, start, err)
	}()
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: a port is between 1 and 65535, not %d", ErrInvalid, port)
	}
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return nil, err
	}
	defer done()
	return sb.DialPort(ctx, port)
}

// Ports lists the TCP sockets listening inside a sandbox. Like listing its
// processes, it asks the agent, so a sleeping sandbox is woken.
func (m *Manager) Ports(ctx context.Context, id string) (sandbox.PortList, error) {
	sb, done, err := m.use(ctx, id)
	if err != nil {
		return sandbox.PortList{}, err
	}
	defer done()
	return sb.Ports(ctx)
}

func (h *handler) listPorts(w http.ResponseWriter, r *http.Request) {
	list, err := h.m.Ports(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	out := api.PortList{Ports: make([]api.PortInfo, 0, len(list.Ports)), Truncated: list.Truncated}
	for _, p := range list.Ports {
		out.Ports = append(out.Ports, api.PortInfo{Port: p.Port, Addr: p.Addr, PID: p.PID, Command: p.Command})
	}
	writeJSON(w, http.StatusOK, out)
}

// connectPort joins the client's connection to a port inside the sandbox,
// the way a CONNECT proxy joins two connections: the client asks to switch
// protocols, and after the 101 its bytes go to the server inside and the
// server's come back, untouched, until both sides are done. Everything that
// can fail before then (no such sandbox, nothing listening on the port)
// fails before the 101, with a proper status.
func (h *handler) connectPort(w http.ResponseWriter, r *http.Request) {
	if !hasToken(r.Header, "Connection", "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), api.PortProtocol) {
		writeJSON(w, http.StatusUpgradeRequired, api.Error{Code: api.CodeInvalid,
			Message: "this endpoint needs Connection: Upgrade and Upgrade: " + api.PortProtocol})
		return
	}
	id := r.PathValue("id")
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		writeErr(w, fmt.Errorf("%w: %q is not a port number", ErrInvalid, r.PathValue("port")))
		return
	}
	tun, err := h.m.DialPort(r.Context(), id, port)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer tun.Close()
	// An open connection keeps the sandbox busy for as long as it lasts,
	// as an attached shell does, and how it ended goes in the audit log.
	opened := time.Now()
	defer h.m.Hold(id)()
	var in, out int64
	how := "the client went away before the upgrade"
	defer func() {
		h.m.Record(r.Context(), id, "port.close", fmt.Sprintf("port %d: %s in, %s out; %s", port, byteCount(in), byteCount(out), how), opened, nil)
	}()
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeErr(w, errors.New("connection can't be upgraded"))
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	// The 101 is written by hand: after Hijack, net/http writes nothing more.
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + api.PortProtocol + "\r\n\r\n")
	if brw.Flush() != nil {
		return
	}
	// brw.Reader, not conn: it may already hold bytes the client sent right
	// behind its request.
	in, out, how = splice(conn, brw.Reader, tun)
}

// drainTimeout bounds how long a client gets to take a tunnel's last bytes
// once the tunnel has ended.
const drainTimeout = 10 * time.Second

// splice copies both ways between a client's connection and a tunnel until
// both directions are done, passing each one's end along as a half-close,
// as a TCP proxy does. If either side breaks, both are cut off. It says how
// many bytes went in (to the server) and out, and how it ended.
func splice(conn net.Conn, client io.Reader, tun *agent.Tunnel) (in, out int64, how string) {
	type end struct {
		n                 int64
		readErr, writeErr error
	}
	up, down := make(chan end, 1), make(chan end, 1)
	go func() {
		n, r, w := pipe(tun, client, tun.CloseWrite)
		up <- end{n, r, w}
	}()
	go func() {
		n, r, w := pipe(conn, tun, func() error { return closeWrite(conn) })
		down <- end{n, r, w}
	}()
	var u, d end
	for pending := 2; pending > 0; pending-- {
		select {
		case u = <-up:
			switch {
			case u.readErr != nil: // the client broke
				tun.Close()
				conn.Close()
			case u.writeErr != nil:
				// The tunnel has ended. The other way may still have its last
				// bytes to deliver: a while for them, not forever, since a
				// client that stops reading must not keep the sandbox busy.
				_ = conn.SetWriteDeadline(time.Now().Add(drainTimeout))
			}
		case d = <-down:
			if d.readErr != nil || d.writeErr != nil {
				tun.Close()
				conn.Close()
			}
		}
	}
	switch tunErr := tun.Err(); {
	case tunErr != nil && !errors.Is(tunErr, net.ErrClosed):
		how = "ended in the sandbox: " + tunErr.Error()
	case u.readErr != nil:
		how = "the client's side broke: " + u.readErr.Error()
	case d.writeErr != nil:
		how = "the client stopped taking bytes: " + d.writeErr.Error()
	default:
		how = "closed"
	}
	return u.n, d.n, how
}

// pipe copies src to dst until src's end of file, then ends dst's direction
// with done. It says how many bytes went, and which side failed, if one did.
func pipe(dst io.Writer, src io.Reader, done func() error) (n int64, readErr, writeErr error) {
	buf := make([]byte, 32<<10)
	for {
		k, err := src.Read(buf)
		if k > 0 {
			if _, werr := dst.Write(buf[:k]); werr != nil {
				return n, nil, werr
			}
			n += int64(k)
		}
		if errors.Is(err, io.EOF) {
			return n, nil, done()
		}
		if err != nil {
			return n, err, nil
		}
	}
}

// closeWrite half-closes a connection: the peer reads end of file, and can
// still send.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func byteCount(n int64) string {
	switch {
	case n < 1<<10:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
}
