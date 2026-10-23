#!/usr/bin/env python3
"""Tries N forks and reports how many succeeded, and why the first one failed.

Run it inside a sandbox to see its process limit at work:

    sudo ./bin/sbx put "$ID" scripts/fork_probe.py /tmp/fork_probe.py
    sudo ./bin/sbx exec "$ID" -- python3 /tmp/fork_probe.py 100

Why Python and not a shell loop: in dash (Ubuntu's /bin/sh), a failed fork
ends the whole script, so a shell can't count past the first refusal.
Each child immediately becomes a tiny `sleep`: a forked Python child that
stays Python slowly copies the whole interpreter (reference counting
writes to every page it touches), and 64 of them can exhaust memory before
any process limit is reached.
"""
import os
import sys

tries = int(sys.argv[1]) if len(sys.argv) > 1 else 100
started, pids, refused = 0, [], ""
for _ in range(tries):
    try:
        pid = os.fork()
    except OSError as e:
        refused = os.strerror(e.errno)
        break
    if pid == 0:
        try:
            os.execv("/bin/sleep", ["sleep", "60"])
        finally:
            os._exit(127)
    pids.append(pid)
    started += 1
print("started=%d refused=%s" % (started, refused or "none"))
for p in pids:
    os.kill(p, 9)
    os.waitpid(p, 0)
