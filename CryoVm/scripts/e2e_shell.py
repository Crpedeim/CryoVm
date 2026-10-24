#!/usr/bin/env python3
"""Drives `sbx shell` through a real terminal (a PTY), the way a person would.

Run it against a running sbxd, as root (the API socket is root-only):

    sudo ./bin/sbx create                      # note the id
    sudo python3 scripts/e2e_shell.py <id>

Optional: SBX_BIN (default ./bin/sbx), SBX_SOCK (default /run/sbx/sbxd.sock).
It checks raw mode, resize, Ctrl+C, Ctrl+] detach, terminal restore,
reattach with scrollback, and exit codes. It uses only Python's standard
library.
"""
import os, select, subprocess, sys, time, fcntl, termios, struct

SBX = os.environ.get("SBX_BIN", "./bin/sbx")
env = dict(os.environ)
env.setdefault("SBX_SOCK", "/run/sbx/sbxd.sock")
results = []

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (("  " + detail) if detail and not ok else ""))

class Term:
    """sbx running on a real PTY, as if a person were typing at it."""
    def __init__(self, args):
        self.master, self.slave = os.openpty()
        self.set_size(100, 30)
        def child_setup():
            os.setsid()                                    # own session...
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)           # ...with this PTY as its terminal
        self.p = subprocess.Popen([SBX] + args, stdin=self.slave, stdout=self.slave,
                                  stderr=self.slave, preexec_fn=child_setup, env=env, close_fds=True)
        self.out = b""
    def set_size(self, cols, rows):
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    def termios_now(self):
        return termios.tcgetattr(self.slave)
    def send(self, s):
        os.write(self.master, s.encode() if isinstance(s, str) else s)
    def expect(self, text, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if text.encode() in self.out:
                return True
            r, _, _ = select.select([self.master], [], [], 0.05)
            if r:
                try:
                    self.out += os.read(self.master, 65536)
                except OSError:
                    break
        return text.encode() in self.out
    def wait(self, timeout=5):
        try:
            return self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return None

if len(sys.argv) != 2:
    sys.exit("usage: e2e_shell.py <sandbox-id>")
sid_box = sys.argv[1]

# 1. A new session on a real terminal.
t = Term(["shell", sid_box, "--", "sh"])
before = t.termios_now()
if not t.expect("[sbx: started session s-"):
    # Nothing else can work without a session: show what sbx said instead.
    t.wait(timeout=2)
    t.expect("\n", timeout=0.5)
    print("FAIL banner shows a new session")
    print("sbx printed:\n  " + t.out.decode(errors="replace").strip().replace("\n", "\n  "))
    print(f"sbx exit status: {t.p.returncode}")
    sys.exit(1)
check("banner shows a new session", True)
time.sleep(0.2)
check("terminal switched to raw mode while attached", t.termios_now() != before)
t.send("test -t 0 && echo TTY-$((1+1))\r")         # Enter is \r in raw mode
check("the remote shell is on a terminal", t.expect("TTY-2"))

# 2. Resize the local window: the kernel signals sbx (SIGWINCH), sbx tells the sandbox.
t.set_size(132, 43)
time.sleep(0.3)
t.send("stty size\r")
check("a local resize reaches the remote terminal", t.expect("43 132"))

# 3. Ctrl+C is a byte now; it must interrupt the *remote* foreground job.
t.send("sleep 30\r"); time.sleep(0.4)
start = time.time()
t.send(b"\x03")
t.send("echo AFTER-$((3+4))\r")
check("Ctrl+C interrupts the remote sleep, not sbx", t.expect("AFTER-7") and time.time() - start < 3,
      f"took {time.time()-start:.1f}s")
check("sbx itself is still running after Ctrl+C", t.p.poll() is None)

# 4. Ctrl+] detaches, sbx exits 0, and the terminal is restored.
t.send("cd /tmp\r"); t.send("echo MARK-$((5+5))\r"); t.expect("MARK-10")
t.send(b"\x1d")
code = t.wait()
check("Ctrl+] detaches and sbx exits 0", code == 0, f"exit {code}")
t.expect("reattach with", timeout=1)
check("detach message says how to reattach", b"reattach with: sbx shell -attach" in t.out)
check("local terminal restored after detach", t.termios_now() == before)
sid = t.out.split(b"started session ")[1].split(b";")[0].decode()

# 5. Reattach: same session, scrollback replayed, state intact, then exit 4.
u = Term(["shell", "-attach", sid, sid_box])
check("reattach reports attaching, not starting", u.expect(f"[sbx: attached to session {sid}"))
check("scrollback replayed on reattach", u.expect("TTY-2"))
u.send("echo cwd=$(pwd)\r")
check("shell state (cwd) survived the detach", u.expect("cwd=/tmp"))
u.send("exit 4\r")
code = u.wait()
check("remote exit code becomes sbx's exit code", code == 4, f"exit {code}")
check("end message printed", u.expect("ended]", timeout=1))

print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
