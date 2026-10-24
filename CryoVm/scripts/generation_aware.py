#!/usr/bin/env python3
"""Prints random numbers, renewing its random state whenever the sandbox's
generation changes: the pattern clone identity (Day 15) exists for.

A fork copies a running program's memory exactly, including its random
generator's internal state, so every clone of a naive program draws the same
"random" numbers. No outside agent can reach into a running program to fix
that. So sbx publishes a generation marker, /run/sbx/generation, which
changes whenever the sandbox may have been duplicated (a fork) or moved in
time (a restore); a program that checks it before using random state can
renew that state itself. Secrets made before a fork (session keys, tokens)
deserve the same treatment.

    sbx start <id> -- python3 /tmp/generation_aware.py
"""
import os
import random
import sys
import time

GENERATION = os.path.join(os.environ.get("SBX_IDENTITY_DIR", "/run/sbx"), "generation")


def generation():
    try:
        with open(GENERATION) as f:
            return f.read().strip()
    except OSError:
        return ""


seen = generation()
interval = float(sys.argv[1]) if len(sys.argv) > 1 else 0.2
while True:
    now = generation()
    if now != seen:
        random.seed(os.urandom(32))  # fresh entropy from the kernel, drawn now
        print("# generation changed: random state renewed", flush=True)
        seen = now
    print(random.random(), flush=True)
    time.sleep(interval)
