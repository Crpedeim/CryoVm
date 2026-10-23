package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

type PortInfo = agentproto.PortInfo
type PortList = agentproto.PortList

// portsSince is the first agent version that serves port tunnels and
// listings.
const portsSince = "0.16.0"

// needs checks that the agent is at least version min before it's asked
// for what. An older agent skips requests it doesn't know, so the caller
// would only wait out its deadline; the hello's version says so at once.
func (c *Conn) needs(min, what string) error {
	if versionAtLeast(c.Hello.Version, min) {
		return nil
	}
	have := c.Hello.Version
	if have == "" {
		have = "unknown"
	}
	return fmt.Errorf("%w: %s needs a sandbox agent %s or newer; this sandbox's agent is %s, from the sbx that created it, and a new sandbox gets the current one",
		ErrUnsupported, what, min, have)
}

// versionAtLeast compares dotted version numbers: "0.16.0" is at least
// "0.15.2". A missing part counts as 0; one that isn't a number, as less
// than any.
func versionAtLeast(have, want string) bool {
	h, w := strings.Split(have, "."), strings.Split(want, ".")
	for i := range w {
		hv := 0
		if i < len(h) {
			n, err := strconv.Atoi(h[i])
			if err != nil {
				n = -1
			}
			hv = n
		}
		wv, _ := strconv.Atoi(w[i])
		if hv != wv {
			return hv > wv
		}
	}
	return true
}

// Ports lists the TCP sockets listening inside the sandbox, with the
// process holding each when the agent can tell.
func (c *Conn) Ports(ctx context.Context) (PortList, error) {
	if err := c.needs(portsSince, "listing ports"); err != nil {
		return PortList{}, err
	}
	var out PortList
	err := c.call(ctx, "list ports", agentproto.TypePortList, agentproto.TypePortListed, "", nil, &out)
	return out, err
}

// Tunnel is a TCP connection to a port inside the sandbox, carried over the
// agent's connection: the agent connected to the port and relays bytes both
// ways. It reads and writes like a net.Conn, and half-closes like a TCP one
// (CloseWrite).
//
// The two directions are independent. A dispatcher takes every frame the
// agent sends as it arrives, so a Write waiting for the agent's acks never
// waits behind bytes nobody has read yet, and the connection's other
// requests never wait on this one: the agent sends at most Window frames
// unread, and they fit in data.
type Tunnel struct {
	Addr string // the address inside the sandbox that answered, e.g. 127.0.0.1:8000

	c    *Conn
	id   uint64
	p    *pendingReq
	port int

	credits chan struct{} // the agent's acks: room to Write
	data    chan []byte   // received, not yet read; closed at the server's end of file
	eof     bool          // dispatch's own: data is closed

	readMu sync.Mutex
	rest   []byte // what's left of the frame being read

	writeMu  sync.Mutex
	wroteEOF bool

	done chan struct{} // closed when the tunnel is over, for whatever reason
	once sync.Once
	err  error // why it's over, when not cleanly; set before done closes
}

// DialPort connects to port inside the sandbox, through the agent: a
// server is reached whether it listens on every address or on localhost
// alone, with or without a network. A port nothing listens on is
// ErrRefused.
func (c *Conn) DialPort(ctx context.Context, port int) (*Tunnel, error) {
	if err := c.needs(portsSince, "port forwarding"); err != nil {
		return nil, err
	}
	id, p, err := c.register(2*agentproto.Window + 8)
	if err != nil {
		return nil, err
	}
	open, _ := agentproto.New(agentproto.TypePortOpen, id, agentproto.PortOpen{Port: port})
	if err := c.send(open); err != nil {
		c.unregister(id, p)
		return nil, err
	}
	label := "port " + strconv.Itoa(port)
	select {
	case f := <-p.ch:
		switch f.Type {
		case agentproto.TypePortReady:
			var r agentproto.PortReady
			if err := f.Decode(&r); err != nil {
				c.abandon(id, p)
				return nil, fmt.Errorf("connect to %s: bad port_ready frame: %w", label, err)
			}
			t := &Tunnel{Addr: r.Addr, c: c, id: id, p: p, port: port,
				credits: make(chan struct{}, agentproto.Window), data: make(chan []byte, agentproto.Window),
				done: make(chan struct{})}
			for i := 0; i < agentproto.Window; i++ {
				t.credits <- struct{}{}
			}
			go t.dispatch()
			return t, nil
		case agentproto.TypeError:
			c.unregister(id, p)
			return nil, fileErr("connect to", label, f)
		default:
			c.abandon(id, p)
			return nil, fmt.Errorf("connect to %s: unexpected %q frame", label, f.Type)
		}
	case <-ctx.Done():
		// The agent may connect after all: cancel, so it doesn't keep a
		// connection to the server open that nobody will use.
		c.abandon(id, p)
		return nil, ctx.Err()
	case <-c.done:
		c.unregister(id, p)
		return nil, ErrClosed
	}
}

// abandon gives up on request id: the agent is told to stop, and whatever
// it still sends for it is dropped.
func (c *Conn) abandon(id uint64, p *pendingReq) {
	m, _ := agentproto.New(agentproto.TypeCancel, id, nil)
	_ = c.send(m)
	c.unregister(id, p)
}

func (t *Tunnel) label() string { return "port " + strconv.Itoa(t.port) }

// dispatch takes every frame the agent sends for the tunnel as it arrives:
// bytes for Read, acks for Write, and the end.
func (t *Tunnel) dispatch() {
	for {
		select {
		case f := <-t.p.ch:
			if t.handle(f) {
				return
			}
		case <-t.done: // Close
			return
		case <-t.c.done:
			// Frames that came in before the connection broke are already
			// here (the reader delivers every frame before it signals the
			// close): take them, so Read still gets the bytes and the end
			// they carry.
			for drained := false; !drained; {
				select {
				case f := <-t.p.ch:
					if t.handle(f) {
						return
					}
				default:
					drained = true
				}
			}
			t.finish(fmt.Errorf("%s: %w", t.label(), ErrClosed))
			return
		}
	}
}

// handle acts on one frame, and says whether it ended the tunnel.
func (t *Tunnel) handle(f agentproto.Message) bool {
	switch f.Type {
	case agentproto.TypePortData:
		var ch agentproto.Chunk
		if err := f.Decode(&ch); err != nil || t.eof {
			t.abort(fmt.Errorf("%s: a port_data frame that's malformed, or after the end", t.label()))
			return true
		}
		select {
		case t.data <- ch.Data:
		default:
			// More unread than the window allows: give up on this tunnel
			// rather than hold up every other request on the connection.
			t.abort(fmt.Errorf("%s: the agent sent beyond the window", t.label()))
			return true
		}
	case agentproto.TypePortEOF:
		if !t.eof {
			t.eof = true
			close(t.data)
		}
	case agentproto.TypeAck:
		select {
		case t.credits <- struct{}{}:
		default: // more acks than frames sent: ignore rather than overflow
		}
	case agentproto.TypePortClosed:
		t.finish(nil)
		return true
	case agentproto.TypeError:
		t.finish(fileErr("tunnel to", t.label(), f))
		return true
	}
	return false
}

// finish ends the tunnel, once: err is why, nil for a clean end.
func (t *Tunnel) finish(err error) {
	t.once.Do(func() {
		t.err = err
		close(t.done)
		t.c.unregister(t.id, t.p)
	})
}

// abort ends the tunnel and has the agent drop its connection to the server.
func (t *Tunnel) abort(err error) {
	m, _ := agentproto.New(agentproto.TypeCancel, t.id, nil)
	_ = t.c.send(m)
	t.finish(err)
}

// Done is closed when the tunnel is over: both ways ended, it broke, or it
// was closed.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Err says why the tunnel ended: nil while it's open, or after a clean end.
func (t *Tunnel) Err() error {
	select {
	case <-t.done:
		return t.err
	default:
		return nil
	}
}

// Read reads the server's bytes. It returns io.EOF once the server has
// closed its side and everything before has been read; if the tunnel broke
// instead, the reason, after the bytes that came before it.
func (t *Tunnel) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	t.readMu.Lock()
	defer t.readMu.Unlock()
	for len(t.rest) == 0 {
		d, err := t.next()
		if err != nil {
			return 0, err
		}
		t.rest = d
		if len(d) == 0 {
			t.ack() // an empty frame: consumed already
		}
	}
	n := copy(b, t.rest)
	t.rest = t.rest[n:]
	if len(t.rest) == 0 {
		t.ack() // the whole frame is consumed: only now may the agent send another
	}
	return n, nil
}

// next waits for the next frame's bytes, or the end.
func (t *Tunnel) next() ([]byte, error) {
	select {
	case d, ok := <-t.data:
		if !ok {
			return nil, io.EOF
		}
		return d, nil
	case <-t.done:
		select { // bytes that arrived before the end come first
		case d, ok := <-t.data:
			if !ok {
				return nil, io.EOF
			}
			return d, nil
		default:
		}
		if t.err != nil {
			return nil, t.err
		}
		return nil, io.EOF
	}
}

func (t *Tunnel) ack() {
	m, _ := agentproto.New(agentproto.TypeAck, t.id, nil)
	_ = t.c.send(m)
}

// Write sends bytes to the server. It blocks while Window frames wait for
// the agent's acks, which come as the server takes them: a server that stops
// reading slows the writer down, as it would over TCP.
func (t *Tunnel) Write(b []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if t.wroteEOF {
		return 0, fmt.Errorf("%s: write after CloseWrite: %w", t.label(), io.ErrClosedPipe)
	}
	sent := 0
	for len(b) > 0 {
		chunk := b[:min(len(b), agentproto.PortChunk)]
		// The end first: with credits to spare, a select would pick either.
		select {
		case <-t.done:
			return sent, t.writeErr()
		default:
		}
		select {
		case <-t.credits:
		case <-t.done:
			return sent, t.writeErr()
		}
		m, _ := agentproto.New(agentproto.TypePortData, t.id, agentproto.Chunk{Data: chunk})
		if err := t.c.send(m); err != nil {
			return sent, err
		}
		sent += len(chunk)
		b = b[len(chunk):]
	}
	return sent, nil
}

// writeErr is why a Write can't go on, once the tunnel is over.
func (t *Tunnel) writeErr() error {
	if t.err != nil {
		return t.err
	}
	return fmt.Errorf("%s: %w", t.label(), io.ErrClosedPipe)
}

// CloseWrite ends this direction, as TCP's half-close does: the server
// reads end-of-file, and can still answer.
func (t *Tunnel) CloseWrite() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if t.wroteEOF {
		return nil
	}
	t.wroteEOF = true
	m, _ := agentproto.New(agentproto.TypePortEOF, t.id, nil)
	return t.c.send(m)
}

// Close drops the connection at once, both ways, without waiting for the
// agent: it closes its end, and bytes still in flight are lost, as when a
// TCP connection is closed with data unread. Read and Write then return
// net.ErrClosed.
func (t *Tunnel) Close() error {
	select {
	case <-t.done:
	default:
		t.abort(net.ErrClosed)
	}
	return nil
}
