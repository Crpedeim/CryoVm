#!/bin/bash
# Background processes end to end, against a running sbxd. From ~/sbx:
#
#   sudo bash scripts/e2e_processes.sh
#
# It creates its own sandbox, starts a Python web server detached, makes a
# request from inside the sandbox, checks the server logged it, stops it
# with SIGTERM, and destroys the sandbox. Optional: SBX_BIN (default
# ./bin/sbx), SBX_SOCK (default /run/sbx/sbxd.sock).
S=${SBX_BIN:-./bin/sbx}
pass=0; fail=0
check() { if [ "$1" = "$2" ]; then echo "PASS $3"; pass=$((pass+1)); else echo "FAIL $3 (got '$1', want '$2')"; fail=$((fail+1)); fi; }

ID=$($S create 2>/dev/null) || { echo "FAIL create: is sbxd running?"; exit 1; }
trap '$S rm "$ID" >/dev/null 2>&1' EXIT
if ! $S exec "$ID" -- sh -c 'command -v python3' >/dev/null; then echo "no python3 in this rootfs"; exit 1; fi

P=$($S start -env PYTHONUNBUFFERED=1 "$ID" -- python3 -m http.server 8765 --bind 127.0.0.1 2>/dev/null)
check "${P:0:2}" "p-" "start returns a process id"
for _ in $(seq 50); do $S logs "$ID" "$P" | grep -q "Serving HTTP" && break; sleep 0.1; done
check "$($S logs "$ID" "$P" | grep -c 'Serving HTTP')" "1" "the server's banner is in its log"
check "$($S ps "$ID" | grep "$P" | awk '{print $3}')" "running" "ps shows it running"

STATUS=$($S exec "$ID" -- python3 -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8765/').status)")
check "$STATUS" "200" "a request from inside the sandbox gets 200"
for _ in $(seq 50); do $S logs "$ID" "$P" | grep -q '"GET / HTTP/1.1" 200' && break; sleep 0.1; done
check "$($S logs "$ID" "$P" | grep -c '"GET / HTTP/1.1" 200')" "1" "the request is in the server's log"

TOTAL=$($S logs -offset 0 "$ID" "$P" 2>&1 >/dev/null | sed -n 's/.*next offset \([0-9]*\).*/\1/p')
check "$($S logs -offset "$TOTAL" "$ID" "$P" 2>/dev/null | wc -c | tr -d ' ')" "0" "reading from the next offset returns nothing new"

$S rmproc "$ID" "$P" >/dev/null 2>&1; check "$?" "1" "removing a running process is refused"
$S signal "$ID" "$P" TERM
$S wait "$ID" "$P"; check "$?" "143" "SIGTERM: wait exits 143 (128 + 15)"

C=$($S start "$ID" -- sh -c 'for i in 1 2 3; do echo count $i; sleep 0.3; done; exit 3' 2>/dev/null)
check "$($S logs -f "$ID" "$C" | tr '\n' ' ')" "count 1 count 2 count 3 " "follow streams until the process exits"
$S wait "$ID" "$C"; check "$?" "3" "wait passes the exit code through"
$S rmproc "$ID" "$C"; check "$?" "0" "an exited process can be removed"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
