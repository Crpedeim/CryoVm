#!/usr/bin/env bash
# Runs a local S3-compatible snapshot store for sbx (SeaweedFS), once:
#
#   sudo scripts/s3-local.sh
#
# It installs SeaweedFS (a pinned release), generates credentials, runs it
# as the sbx-s3 service on 127.0.0.1 only, waits until it can really store
# things, and restarts sbxd with the store (pausing to it, -store-evict).
# The credentials live in /etc/sbx, readable by root only, and reach sbxd
# through its environment file, never its command line.
#
# Overridable, for testing: PREFIX, UNIT_DIR, SBX_ETC, SBX_S3_DATA, SBX_S3_PORT.
set -euo pipefail

WEED_VERSION=${WEED_VERSION:-4.48}   # released 2026-09-28
PREFIX=${PREFIX:-/usr/local}
UNIT_DIR=${UNIT_DIR:-/etc/systemd/system}
ETC=${SBX_ETC:-/etc/sbx}
DATA=${SBX_S3_DATA:-/var/lib/sbx-s3}
PORT=${SBX_S3_PORT:-8333}

die() { echo "s3-local: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"
command -v curl >/dev/null || die "curl is needed"

# 1. SeaweedFS, pinned.
if ! "$PREFIX/bin/weed" version 2>/dev/null | grep -q " $WEED_VERSION "; then
	echo "installing SeaweedFS $WEED_VERSION into $PREFIX/bin"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	curl -fsSL -o "$tmp/weed.tgz" "https://github.com/seaweedfs/seaweedfs/releases/download/$WEED_VERSION/linux_amd64.tar.gz"
	tar -xzf "$tmp/weed.tgz" -C "$tmp" weed
	install -d "$PREFIX/bin"
	install -m 0755 "$tmp/weed" "$PREFIX/bin/weed"
fi

# 2. Credentials, made once and kept: root-readable only.
install -d -m 0700 "$ETC"
if [ ! -f "$ETC/sbxd.env" ]; then
	key=$(head -c 10 /dev/urandom | od -An -tx1 | tr -d ' \n')
	secret=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
	umask 077
	cat > "$ETC/s3.json" <<JSON
{"identities": [{"name": "sbx", "credentials": [{"accessKey": "$key", "secretKey": "$secret"}], "actions": ["Admin", "Read", "Write", "List", "Tagging"]}]}
JSON
	cat > "$ETC/sbxd.env" <<ENV
SBX_S3_ACCESS_KEY=$key
SBX_S3_SECRET_KEY=$secret
SBXD_FLAGS="-store http://127.0.0.1:$PORT -store-evict"
ENV
	echo "generated credentials in $ETC (root only)"
fi
key=$(sed -n 's/^SBX_S3_ACCESS_KEY=//p' "$ETC/sbxd.env")
secret=$(sed -n 's/^SBX_S3_SECRET_KEY=//p' "$ETC/sbxd.env")

# 3. The service: SeaweedFS on 127.0.0.1 only. -volume.max: each bucket
# gets its own volumes, and the default cap runs out quickly.
install -d -m 0700 "$DATA"
install -d "$UNIT_DIR" "$UNIT_DIR/sbxd.service.d"
cat > "$UNIT_DIR/sbx-s3.service" <<UNIT
[Unit]
Description=sbx: local S3 snapshot store (SeaweedFS $WEED_VERSION)
After=network-online.target

[Service]
ExecStart=$PREFIX/bin/weed server -ip=127.0.0.1 -ip.bind=127.0.0.1 -dir=$DATA -s3 -s3.port=$PORT -s3.config=$ETC/s3.json -master.volumeSizeLimitMB=256 -volume.max=64
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
cat > "$UNIT_DIR/sbxd.service.d/s3.conf" <<UNIT
[Unit]
Wants=sbx-s3.service
After=sbx-s3.service
UNIT

if [ ! -d /run/systemd/system ] || [ "$UNIT_DIR" != /etc/systemd/system ]; then
	echo "systemd isn't managing this system (or UNIT_DIR was overridden): start the store and sbxd yourself"
	exit 0
fi
systemctl daemon-reload
systemctl enable --now sbx-s3

# 4. Ready means it can store things, not that it answers: SeaweedFS answers
# HTTP before its storage is up. A signed bucket creation is the real test.
echo -n "waiting for the store"
for _ in $(seq 120); do
	code=$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$key:$secret" -X PUT "http://127.0.0.1:$PORT/sbx" || true)
	[ "$code" = 200 ] && break
	echo -n .
	sleep 0.5
done
echo
[ "$code" = 200 ] || die "the store didn't become ready (last answer: $code); see: journalctl -u sbx-s3"
systemctl restart sbxd
sleep 1
systemctl --no-pager --lines=4 status sbxd || true
echo
echo "Done: sbxd pauses sandboxes to the store (sbx checkpoints <id> shows where each image is)."
