package guest

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNetProc writes a /proc with socket tables and processes whose open
// files link to sockets: pid → (cmdline, comm, fd links).
func fakeNetProc(t *testing.T, tcp, tcp6 string, procs map[int]fakeProcess) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "net"), 0o755))
	must(os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(tcp), 0o644))
	if tcp6 != "" {
		must(os.WriteFile(filepath.Join(root, "net", "tcp6"), []byte(tcp6), 0o644))
	}
	for pid, p := range procs {
		dir := filepath.Join(root, fmt.Sprint(pid))
		must(os.MkdirAll(filepath.Join(dir, "fd"), 0o755))
		must(os.WriteFile(filepath.Join(dir, "cmdline"), []byte(p.cmdline), 0o644))
		must(os.WriteFile(filepath.Join(dir, "comm"), []byte(p.comm+"\n"), 0o644))
		for fd, target := range p.fds {
			must(os.Symlink(target, filepath.Join(dir, "fd", fmt.Sprint(fd))))
		}
	}
	return root
}

type fakeProcess struct {
	cmdline, comm string
	fds           map[int]string
}

// The tables are as Linux prints them on a little-endian machine (x86,
// arm64): each 32-bit word of an address in the machine's byte order.
const (
	fakeTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1F40 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0000000000000000 20 4 30 10 -1
   3: 0200590A:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1007 1 0000000000000000 100 0 0 10 0
`
	fakeTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1004 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1005 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:2328 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1006 1 0000000000000000 100 0 0 10 0
`
)

func TestListPortsReadsTheSocketTables(t *testing.T) {
	var probe [4]byte
	binary.NativeEndian.PutUint32(probe[:], 1)
	if probe[0] != 1 {
		t.Skip("the fixture's tables are a little-endian machine's")
	}
	root := fakeNetProc(t, fakeTCP, fakeTCP6, map[int]fakeProcess{
		// A server bound to localhost alone; its other files aren't sockets.
		42: {cmdline: "python3\x00-m\x00http.server\x008000\x00--bind\x00127.0.0.1\x00", comm: "python3",
			fds: map[int]string{0: "/dev/null", 3: "socket:[1001]", 4: "pipe:[77]"}},
		// Node, on IPv6's loopback only; and a connection that isn't listening.
		7: {cmdline: "node\x00vite\x00", comm: "node", fds: map[int]string{20: "socket:[1004]", 21: "socket:[1003]"}},
		// No command line (a zombie, say): its name instead.
		9: {comm: "nginx", fds: map[int]string{6: "socket:[1005]"}},
		// A worker sharing its parent's socket: the parent, lower PID, names it.
		43: {cmdline: "python3\x00worker\x00", comm: "python3", fds: map[int]string{3: "socket:[1001]"}},
	})
	got := listPorts(root)
	var lines []string
	for _, p := range got.Ports {
		lines = append(lines, fmt.Sprintf("%d %s %d %s", p.Port, p.Addr, p.PID, p.Command))
	}
	want := []string{
		"80 0.0.0.0 0 ", // nobody here holds 1002
		"80 :: 9 nginx", // the same port on IPv6: its own entry
		"3000 10.89.0.2 0 ",
		"5432 ::1 7 node vite",
		"8000 127.0.0.1 42 python3 -m http.server 8000 --bind 127.0.0.1",
		"9000 127.0.0.1 0 ", // an IPv4 address in IPv6's table reads as itself
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") || got.Truncated {
		t.Fatalf("ports:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}

	// No IPv6 table (a kernel without IPv6): IPv4's ports still come back.
	if got := listPorts(fakeNetProc(t, fakeTCP, "", nil)); len(got.Ports) != 3 {
		t.Fatalf("without tcp6: %+v", got.Ports)
	}
	// No tables at all: an empty list, not an error.
	if got := listPorts(t.TempDir()); got.Ports == nil || len(got.Ports) != 0 {
		t.Fatalf("without /proc/net: %+v", got)
	}
}

func TestParseSockAddrRefusesGarbage(t *testing.T) {
	for _, s := range []string{"", "0100007F", "0100007F:", "0100007F:XYZW", "01007F:1F40", "zz00007F:1F40", "0100007F:10000"} {
		if a, p, ok := parseSockAddr(s); ok {
			t.Errorf("%q parsed as %s port %d", s, a, p)
		}
	}
}

// Against this machine's real kernel: a listener this test opens is found,
// at its address and port, as held by this very process. That checks the
// byte order and the inode matching for real, not just against a fixture.
func TestListPortsFindsARealListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	want := []struct {
		addr string
		port int
	}{{"127.0.0.1", port}}
	if ln6, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		defer ln6.Close()
		want = append(want, struct {
			addr string
			port int
		}{"::1", ln6.Addr().(*net.TCPAddr).Port})
	}
	got := listPorts("/proc")
	for _, w := range want {
		found := false
		for _, p := range got.Ports {
			if p.Port == w.port && p.Addr == w.addr {
				found = true
				if p.PID != os.Getpid() || p.Command == "" {
					t.Errorf("%s:%d is held by this process (%d), not %d %q", w.addr, w.port, os.Getpid(), p.PID, p.Command)
				}
			}
		}
		if !found {
			t.Errorf("listener %s:%d not listed in %+v", w.addr, w.port, got.Ports)
		}
	}
}
