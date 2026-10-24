#!/usr/bin/env python3
"""Speak MCP to sbx-mcp by hand: see exactly what an agent sees.

    scripts/mcp-try.py [-sandbox NAME] [-image browser] STEP...

Starts sbx-mcp (bound to NAME, default "try", created if missing),
initializes, runs the steps in order, and prints each result. A step is:

    shell 'COMMAND'          run a command in the persistent shell
    TOOL '{"json": "args"}'  any tool with JSON arguments
    sleep SECONDS            wait (to let the sandbox fall asleep, say)
    tools                    list the tools and their descriptions

Images in a result are saved as /tmp/mcp-try-N.png. Timings are shown.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import time

args = sys.argv[1:]
sandbox, extra = "try", []
while args and args[0].startswith("-"):
    flag = args.pop(0)
    if flag == "-sandbox":
        sandbox = args.pop(0)
    else:
        extra += [flag, args.pop(0)]
if not args:
    sys.exit(__doc__)

mcp = shutil.which("sbx-mcp") or os.path.join(os.path.dirname(__file__), "..", "bin", "sbx-mcp")
proc = subprocess.Popen([mcp, "-sandbox", sandbox, "-create", *extra],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
next_id = 0


def call(method, params=None):
    global next_id
    next_id += 1
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": next_id, "method": method, "params": params or {}}) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        sys.exit("sbx-mcp ended (its error is above)")
    reply = json.loads(line)
    if "error" in reply:
        sys.exit(f"protocol error: {reply['error']}")
    return reply["result"]


init = call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-try"}})
proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
print(f"# {init['serverInfo']['name']} {init['serverInfo']['version']}, protocol {init['protocolVersion']}, sandbox {sandbox}")
images = 0
while args:
    step = args.pop(0)
    if step == "sleep":
        seconds = float(args.pop(0))
        print(f"\n$ sleep {seconds:g}")
        time.sleep(seconds)
        continue
    if step == "tools":
        for t in call("tools/list")["tools"]:
            print(f"\n## {t['name']}\n{t['description']}")
        continue
    arg = args.pop(0)
    arguments = json.loads(arg) if arg.lstrip().startswith("{") else {"command": arg}
    print(f"\n$ {step} {arg}")
    start = time.time()
    result = call("tools/call", {"name": step, "arguments": arguments})
    for c in result["content"]:
        if c["type"] == "text":
            print(c["text"])
        elif c["type"] == "image":
            images += 1
            path = f"/tmp/mcp-try-{images}.png"
            with open(path, "wb") as f:
                f.write(base64.b64decode(c["data"]))
            print(f"[image: {path}]")
    print(f"({'error, ' if result.get('isError') else ''}{(time.time() - start) * 1000:.0f} ms)")
proc.stdin.close()
proc.wait()
