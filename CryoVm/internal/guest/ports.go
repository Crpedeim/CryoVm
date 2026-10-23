package guest

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

// dialTimeout bounds a connection to a port inside. On loopback it's
// answered at once, unless the server's accept queue is full: then TCP
// tries again after 1, 3, 7 and 15 s. (Python's http.server queues 5: a
// burst of 20 connections, run on gVisor, saw two of them take 3 s.)
const dialTimeout = 20 * time.Second

// dialLoopback connects to port on the sandbox's own loopback: 127.0.0.1
// first, then ::1, for a server listening on IPv6's loopback alone (Node,
// for one, may resolve "localhost" to ::1 and listen only there).
func dialLoopback(ctx context.Context, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	p := strconv.Itoa(port)
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", p))
	if err == nil {
		return c, nil
	}
	if c6, err6 := d.DialContext(ctx, "tcp", net.JoinHostPort("::1", p)); err6 == nil {
		return c6, nil
	}
	return nil, err // IPv4's error says it best: ::1 may not even exist
}

// dialInside connects to port inside the sandbox: on its loopback, where
// nearly every server can be reached (one listening on every address, or on
// localhost alone), and failing that on the address a listening socket is
// bound to (a server told to listen on the sandbox's eth0 address only).
// Every address tried is the sandbox's own.
func dialInside(ctx context.Context, procRoot string, port int) (net.Conn, error) {
	c, err := dialLoopback(ctx, port)
	if err == nil || !errors.Is(err, syscall.ECONNREFUSED) {
		return c, err
	}
	for _, p := range listPorts(procRoot).Ports {
		a, perr := netip.ParseAddr(p.Addr)
		if p.Port != port || perr != nil || a.IsUnspecified() || a.IsLoopback() {
			continue
		}
		d := net.Dialer{Timeout: dialTimeout}
		if c, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(p.Addr, strconv.Itoa(port))); derr == nil {
			return c, nil
		}
	}
	return nil, err
}

// runPort serves one tunnel: a connection to a port on the sandbox's
// loopback, relayed both ways until both directions have ended, either side
// fails, or the host cancels or goes away. It always ends with exactly one
// final frame (port_closed or error), unless the connection is gone.
//
// The two directions run apart, so neither waits on the other: a server
// that writes a long answer while it still reads is never stalled by its own
// output. The server's bytes are read only with a credit in hand, so a host
// that stops acknowledging leaves them in the socket, where TCP itself makes
// the server wait. The host's bytes are written by a goroutine of their own
// and acknowledged once written: a server that doesn't read holds up only
// its own direction.
func runPort(ctx context.Context, id uint64, req agentproto.PortOpen, in <-chan agentproto.Message, w *frameWriter, procRoot string) {
	if req.Port < 1 || req.Port > 65535 {
		sendErr(w, id, agentproto.CodeInvalid, fmt.Sprintf("port %d is not between 1 and 65535", req.Port))
		return
	}
	conn, err := dialInside(ctx, procRoot, req.Port)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			sendErr(w, id, agentproto.CodeRefused, fmt.Sprintf("nothing is listening on port %d inside the sandbox", req.Port))
		} else {
			sendErr(w, id, agentproto.CodeIO, fmt.Sprintf("connecting to port %d: %v", req.Port, err))
		}
		return
	}
	// Deferred in this order, stop is closed first, then conn: closing conn
	// releases a read or write that would block, and stop the waits for a
	// credit or for the next bytes to write.
	defer conn.Close()
	stop := make(chan struct{})
	defer close(stop)

	ready, _ := agentproto.New(agentproto.TypePortReady, id, agentproto.PortReady{Addr: conn.RemoteAddr().String()})
	if w.send(ready) != nil {
		return
	}

	credits := make(chan struct{}, agentproto.Window)
	for i := 0; i < agentproto.Window; i++ {
		credits <- struct{}{}
	}
	fromServer := make(chan error, 1) // how reading ended: io.EOF when the server closed its side
	go func() {
		buf := make([]byte, agentproto.PortChunk)
		for {
			select {
			case <-credits:
			case <-stop:
				return
			}
			n, err := conn.Read(buf)
			if n > 0 {
				m, _ := agentproto.New(agentproto.TypePortData, id, agentproto.Chunk{Data: buf[:n]})
				if serr := w.send(m); serr != nil {
					fromServer <- serr
					return
				}
			} else {
				credits <- struct{}{} // nothing was sent: the credit is still ours
			}
			if err != nil {
				fromServer <- err
				return
			}
		}
	}()

	toServer := make(chan []byte, agentproto.Window) // never full while the host keeps to the window
	wrote := make(chan error, 1)                     // how writing ended: nil once the host's end was passed on
	go func() {
		for {
			select {
			case data, ok := <-toServer:
				if !ok {
					// The host's port_eof: the server reads end-of-file, and
					// can still answer.
					wrote <- closeWrite(conn)
					return
				}
				if _, err := conn.Write(data); err != nil {
					wrote <- err
					return
				}
				ack, _ := agentproto.New(agentproto.TypeAck, id, nil)
				_ = w.send(ack)
			case <-stop:
				return
			}
		}
	}()

	hostEOF := false
	hostDone, serverDone := false, false
	for !hostDone || !serverDone {
		select {
		case m := <-in:
			switch m.Type {
			case agentproto.TypePortData:
				var c agentproto.Chunk
				if err := m.Decode(&c); err != nil || hostEOF {
					sendErr(w, id, agentproto.CodeInvalid, "port_data that's malformed, or after port_eof")
					return
				}
				select {
				case toServer <- c.Data:
				default:
					sendErr(w, id, agentproto.CodeInvalid, "port_data beyond the window")
					return
				}
			case agentproto.TypePortEOF:
				if !hostEOF {
					hostEOF = true
					close(toServer)
				}
			case agentproto.TypeAck:
				select {
				case credits <- struct{}{}:
				default: // more acks than frames sent: ignore rather than overflow
				}
			}
		case err := <-wrote:
			if err != nil {
				sendErr(w, id, agentproto.CodeIO, "writing to the server: "+err.Error())
				return
			}
			hostDone = true
		case err := <-fromServer:
			if !errors.Is(err, io.EOF) {
				sendErr(w, id, agentproto.CodeIO, "reading from the server: "+err.Error())
				return
			}
			eof, _ := agentproto.New(agentproto.TypePortEOF, id, nil)
			if w.send(eof) != nil {
				return
			}
			serverDone = true
		case <-ctx.Done():
			// The host cancelled, or its connection dropped: either way the
			// connection to the server ends here.
			sendErr(w, id, agentproto.CodeCanceled, "connection closed by the host")
			return
		}
	}
	closed, _ := agentproto.New(agentproto.TypePortClosed, id, nil)
	_ = w.send(closed)
}

// closeWrite half-closes a connection: TCP's FIN, with reading still open.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("%T can't half-close", c)
}

// The kernel's name for a listening TCP socket in /proc/net/tcp.
const tcpListen = "0A"

// maxPorts keeps a listing well inside one frame, even with long commands.
const maxPorts = 2000

// listPorts lists the TCP sockets listening inside the sandbox, from the
// kernel's socket tables (gVisor keeps Linux's format), each with the
// process holding it, when one can be found.
func listPorts(procRoot string) agentproto.PortList {
	type key struct {
		addr string
		port int
	}
	out := agentproto.PortList{Ports: []agentproto.PortInfo{}}
	seen := map[key]bool{}
	byInode := map[uint64]int{} // socket inode → its entry
	for _, table := range []string{"tcp", "tcp6"} {
		raw, err := os.ReadFile(filepath.Join(procRoot, "net", table))
		if err != nil {
			continue // no IPv6, say
		}
		for _, line := range strings.Split(string(raw), "\n")[1:] { // after the header
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != tcpListen {
				continue
			}
			addr, port, ok := parseSockAddr(f[1])
			if !ok {
				continue
			}
			k := key{addr.String(), port}
			if seen[k] {
				continue // several sockets on one address and port (SO_REUSEPORT): one entry
			}
			if len(out.Ports) == maxPorts {
				out.Truncated = true
				break
			}
			seen[k] = true
			if inode, err := strconv.ParseUint(f[9], 10, 64); err == nil && inode != 0 {
				byInode[inode] = len(out.Ports)
			}
			out.Ports = append(out.Ports, agentproto.PortInfo{Port: port, Addr: k.addr})
		}
	}
	if len(byInode) > 0 {
		findOwners(procRoot, byInode, out.Ports)
	}
	sort.Slice(out.Ports, func(i, j int) bool {
		a, b := out.Ports[i], out.Ports[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Addr < b.Addr
	})
	return out
}

// parseSockAddr decodes an address as /proc/net/tcp prints it: the IP in
// hex, as 32-bit words each printed in the machine's byte order, then the
// port.
func parseSockAddr(s string) (netip.Addr, int, bool) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(hexIP)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, false
	}
	ip := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(ip[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap(), int(port), true // an IPv4 address in IPv6's table reads as itself
}

// findOwners names the process holding each socket: one of its open files
// links to "socket:[inode]". Lowest PID first, so a server that shares its
// socket with workers it started is named by its first process. Processes
// that vanish, or can't be read, are skipped.
func findOwners(procRoot string, byInode map[uint64]int, ports []agentproto.PortInfo) {
	dirs, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	pids := make([]int, 0, len(dirs))
	for _, d := range dirs {
		if pid, err := strconv.Atoi(filepath.Base(d)); err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	for _, pid := range pids {
		dir := filepath.Join(procRoot, strconv.Itoa(pid))
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(link[len("socket:["):], "]"), 10, 64)
			if err != nil {
				continue
			}
			if i, ok := byInode[inode]; ok && ports[i].PID == 0 {
				ports[i].PID, ports[i].Command = pid, commandOf(dir)
			}
		}
	}
}

// commandOf is a process's command line, as ps shows it, or failing that
// its name.
func commandOf(dir string) string {
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		if s := strings.TrimSpace(strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " ")); s != "" {
			if len(s) > 200 {
				s = s[:200] + "…"
			}
			return s
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}
