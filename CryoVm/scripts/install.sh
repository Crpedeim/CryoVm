#!/usr/bin/env bash
# Installs sbx once (Day 22), so an MCP client needs a single command:
#
#   sudo scripts/install.sh            # from the repo, after building bin/
#   claude mcp add sbx -- sbx-mcp -sandbox agent -create -image browser
#
# It installs the binaries, creates the sbx group (adding you to it), and
# runs sbxd as a systemd service: started now, restarted if it crashes,
# started at boot. sbxd must run as root (gVisor, cgroups, network
# namespaces); sbx-mcp runs as you and reaches it through the group socket.
#
# Overridable, for testing: PREFIX, UNIT_DIR, SBX_ROOTFS, RUNSC.
set -euo pipefail

PREFIX=${PREFIX:-/usr/local}
UNIT_DIR=${UNIT_DIR:-/etc/systemd/system}
SBX_ROOTFS=${SBX_ROOTFS:-/mnt/sbx/rootfs/ubuntu-24.04}
repo=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "install: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"
for b in sbxd sbx sbx-agent sbx-mcp; do
	[ -x "$repo/bin/$b" ] || die "bin/$b is missing: build first (see the README)"
done
RUNSC=${RUNSC:-$(command -v runsc || true)}
if [ -z "$RUNSC" ] || [ ! -x "$RUNSC" ]; then
	die "runsc not found: install gVisor first"
fi
[ -d "$SBX_ROOTFS" ] || die "no base rootfs at $SBX_ROOTFS (set SBX_ROOTFS)"

echo "installing sbxd, sbx, sbx-agent, sbx-mcp into $PREFIX/bin"
install -d "$PREFIX/bin"
for b in sbxd sbx sbx-agent sbx-mcp; do
	install -m 0755 "$repo/bin/$b" "$PREFIX/bin/$b"
done

groupadd -f sbx
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
	usermod -aG sbx "$SUDO_USER"
	echo "added $SUDO_USER to the sbx group"
fi

echo "writing $UNIT_DIR/sbxd.service"
install -d "$UNIT_DIR"
cat > "$UNIT_DIR/sbxd.service" <<UNIT
[Unit]
Description=sbx: sandboxes for AI agents (gVisor)
After=network-online.target
Wants=network-online.target
RequiresMountsFor=$SBX_ROOTFS

[Service]
# Optional settings (the snapshot store: SBXD_FLAGS and its credentials),
# kept out of this file and out of ps: see scripts/s3-local.sh.
EnvironmentFile=-/etc/sbx/sbxd.env
ExecStart=$PREFIX/bin/sbxd -rootfs $SBX_ROOTFS -agent $PREFIX/bin/sbx-agent -runsc $RUNSC -sock-group sbx \$SBXD_FLAGS
Restart=on-failure
RestartSec=2
# Signal only sbxd. By default systemd kills every process a service
# started; that would take every sandbox down with the daemon. sbxd pauses
# its sandboxes on a clean stop (Day 12), and after a crash the restarted
# sbxd adopts the ones still running.
KillMode=process
# Pausing every sandbox at stop takes a moment each.
TimeoutStopSec=180

[Install]
WantedBy=multi-user.target
UNIT

if [ -d /run/systemd/system ] && [ "$UNIT_DIR" = /etc/systemd/system ]; then
	systemctl daemon-reload
	# enable --now wouldn't restart a running sbxd, leaving the old binary
	# running after a reinstall: restart explicitly. (Its sandboxes are
	# paused for the restart and resumed after, Day 12.)
	systemctl enable sbxd
	systemctl restart sbxd
	for _ in $(seq 50); do [ -S /run/sbx/sbxd.sock ] && break; sleep 0.1; done
	systemctl --no-pager --lines=3 status sbxd || true
else
	echo "systemd isn't managing this system (or UNIT_DIR was overridden): start sbxd yourself"
fi

cat <<NEXT

Done. Next:
  1. Log out and back in (or run: newgrp sbx) so your new group membership applies.
  2. Give Claude Code the sandbox:
       claude mcp add sbx -- $PREFIX/bin/sbx-mcp -sandbox agent -create -image browser
     (without a browser image: replace -image browser with -net)
NEXT
