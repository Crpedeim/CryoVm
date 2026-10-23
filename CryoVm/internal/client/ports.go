package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
)

// Ports lists the TCP sockets listening inside a sandbox, lowest port
// first, with the process holding each when the daemon could tell.
func (c *Client) Ports(ctx context.Context, id string) (api.PortList, error) {
	var out api.PortList
	err := c.json(ctx, http.MethodGet, sbPath(id, "/ports"), nil, &out)
	return out, err
}

// PortConn is a connection to a port inside a sandbox, through the daemon:
// its bytes are those of a TCP connection to the port. CloseWrite
// half-closes it.
type PortConn struct {
	net.Conn
	r *bufio.Reader // bytes the daemon sent right behind its 101 come first
}

func (p *PortConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// CloseWrite ends this direction: the server inside reads end of file, and
// can still answer.
func (p *PortConn) CloseWrite() error { return closeWrite(p.Conn) }

// DialPort connects to a port inside a sandbox, through the daemon, which
// wakes the sandbox first if it's asleep. It returns once the daemon has
// connected to the port, so a port nothing listens on fails here, with
// ErrRefused. ctx bounds the dial, not the connection.
//
// The connection is the daemon socket itself, upgraded, rather than
// net/http's: net/http's can't half-close.
func (c *Client) DialPort(ctx context.Context, id string, port int) (*PortConn, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("sbxd unreachable (is it running?): %w", err)
	}
	// Until the daemon answers, ctx's end ends the wait.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	req, err := http.NewRequest(http.MethodPost, c.base+sbPath(id, fmt.Sprintf("/ports/%d/connect", port)), nil)
	if err != nil {
		stop()
		conn.Close()
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", api.PortProtocol)
	br := bufio.NewReader(conn)
	var resp *http.Response
	if err = req.Write(conn); err == nil {
		resp, err = http.ReadResponse(br, req)
	}
	if !stop() || err != nil { // stop is false once the deadline was set: ctx ended
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("connecting to port %d through sbxd: %w", port, err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer conn.Close()
		return nil, decodeErr(resp)
	}
	return &PortConn{Conn: conn, r: br}, nil
}

// dialPortWait bounds how long a forwarded connection waits for the daemon
// to reach the port: waking a sandbox from the snapshot store takes a
// moment, a stuck one shouldn't take forever.
const dialPortWait = time.Minute

// ServePort serves a port inside a sandbox on ln, as ssh -L does: every
// connection ln accepts is joined to a new connection to the port, through
// the daemon, until ln is closed. Each one wakes the sandbox if it's asleep
// and keeps it busy while it lasts.
//
// A connection that can't be made (nothing listens on the port yet, say)
// is reported to refused, which may be nil, and closed; a client that spoke
// HTTP first gets the reason as an HTTP answer, so a browser shows it
// rather than an empty page.
func (c *Client) ServePort(ln net.Listener, id string, port int, refused func(error)) error {
	backoff := 5 * time.Millisecond
	for {
		local, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Out of file descriptors, say: wait, and try again, as
			// net/http's server does.
			time.Sleep(backoff)
			backoff = min(2*backoff, time.Second)
			continue
		}
		backoff = 5 * time.Millisecond
		go c.forward(local, id, port, refused)
	}
}

func (c *Client) forward(local net.Conn, id string, port int, refused func(error)) {
	defer local.Close()
	ctx, cancel := context.WithTimeout(context.Background(), dialPortWait)
	remote, err := c.DialPort(ctx, id, port)
	cancel()
	if err != nil {
		if refused != nil {
			refused(err)
		}
		explain(local, fmt.Sprintf("sbx: %v\n\n(this address forwards to port %d in sandbox %s)\n", err, port, id))
		return
	}
	defer remote.Close()
	join(local, remote)
}

var httpMethods = [][]byte{[]byte("GET "), []byte("HEAD "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "), []byte("TRACE ")}

// explain answers a client whose connection went nowhere with why, if it
// spoke HTTP; anything else is just closed. It reads only after the dial
// failed, so a protocol where the server speaks first never waits on it.
func explain(local net.Conn, why string) {
	_ = local.SetReadDeadline(time.Now().Add(time.Second))
	head := make([]byte, 8)
	n, _ := io.ReadFull(local, head)
	isHTTP := false
	for _, m := range httpMethods {
		isHTTP = isHTTP || bytes.HasPrefix(head[:n], m) || (n < len(m) && n > 0 && bytes.HasPrefix(m, head[:n]))
	}
	if !isHTTP {
		return
	}
	_ = local.SetWriteDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(local, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n"+
		"Cache-Control: no-store\r\nConnection: close\r\n\r\n%s", len(why), why)
	// Closing with the rest of the request unread would reset the
	// connection, and the client could lose the answer: say we're done,
	// then take what it still sends, briefly.
	_ = closeWrite(local)
	_ = local.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.Copy(io.Discard, local)
}

// drainTimeout bounds how long one direction gets to deliver its last
// bytes once the other side has gone.
const drainTimeout = 10 * time.Second

// join copies both ways between a local connection and one to a port in a
// sandbox until both directions are done, passing each one's end along as
// a half-close, as a TCP proxy does. When the local client breaks, or
// either side stops taking bytes for good, both are cut off.
func join(local net.Conn, remote *PortConn) {
	type end struct{ readErr, writeErr error }
	up, down := make(chan end, 1), make(chan end, 1)
	go func() { r, w := pipe(remote, local); up <- end{r, w} }()
	go func() { r, w := pipe(local, remote); down <- end{r, w} }()
	for pending := 2; pending > 0; pending-- {
		select {
		case e := <-up:
			switch {
			case e.readErr != nil: // the local client broke
				local.Close()
				remote.Close()
			case e.writeErr != nil:
				// The sandbox's side is ending. The other way may still have
				// its last bytes to deliver: a while for them, not forever.
				_ = local.SetWriteDeadline(time.Now().Add(drainTimeout))
			}
		case e := <-down:
			if e.readErr != nil || e.writeErr != nil {
				local.Close()
				remote.Close()
			}
		}
	}
}

// pipe copies src to dst until src's end of file, then half-closes dst. It
// says which side failed, if one did.
func pipe(dst, src net.Conn) (readErr, writeErr error) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return nil, werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil, closeWrite(dst)
		}
		if err != nil {
			return err, nil
		}
	}
}

// closeWrite half-closes a connection, or closes one that can't.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}
