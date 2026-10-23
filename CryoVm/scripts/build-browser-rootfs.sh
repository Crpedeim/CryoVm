#!/usr/bin/env bash
# Builds the browser image (Day 20): a copy of the base rootfs with Chromium
# and Playwright, for sandboxes made with `sbx create -image browser`.
#
#   sudo scripts/build-browser-rootfs.sh [BASE] [NAME]
#
# BASE defaults to /mnt/sbx/rootfs/ubuntu-24.04, NAME to
# /mnt/sbx/rootfs/browser. Each build is a new version, NAME-YYYYMMDD-HHMMSS,
# published as NAME-current once it's done (Day 21: versioned images; a
# paused sandbox must resume on exactly the files it was made with, so a
# version is never rebuilt in place). It copies BASE (reflinks on XFS:
# instant), then,
# in a chroot with the host's network and DNS: installs pip, a pinned
# Playwright, and Playwright's Chromium with the system libraries it needs.
# It ends by launching Chromium in the chroot and loading a page, so a
# broken image fails here rather than later in a sandbox.
#
# The version appears, and NAME-current moves to it, only if everything
# succeeded; a failed build leaves VERSION.partial for inspection.
set -euo pipefail

BASE=${1:-/mnt/sbx/rootfs/ubuntu-24.04}
NAME=${2:-/mnt/sbx/rootfs/browser}
TARGET="$NAME-$(date +%Y%m%d-%H%M%S)"
# Pinned: released 2026-09-15. Versions before ~1.50 download Chromium only
# from *.azureedge.net hosts; newer ones from cdn.playwright.dev and
# playwright.download.prss.microsoft.com (checked in the wheels themselves).
PLAYWRIGHT_VERSION=${PLAYWRIGHT_VERSION:-1.63.0}
WORK="$TARGET.partial"

die() { echo "build-browser-rootfs: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo): it uses chroot and mounts"
[ -d "$BASE" ] || die "no base rootfs at $BASE"
[ ! -e "$TARGET" ] || die "$TARGET already exists"
here=$(cd "$(dirname "$0")" && pwd)
[ -x "$here/publish-image.sh" ] || die "publish-image.sh missing next to this script"
echo "copying $BASE to $WORK (reflinks where the filesystem supports them)"
cp -a --reflink=auto "$BASE" "$WORK"
mkdir -p "$WORK/proc" "$WORK/sys" "$WORK/dev" "$WORK/tmp"
# The working directories apt expects. An image slimmed for running (caches
# and logs deleted to save space) may lack them; apt then can't download
# ("Archives directory /var/cache/apt/archives/partial is missing").
mkdir -p "$WORK/var/cache/apt/archives/partial" "$WORK/var/lib/apt/lists/partial" \
	"$WORK/var/log/apt" "$WORK/var/lib/dpkg/updates"

# Mounts the chroot needs, always undone, innermost first.
mounted=()
saved_resolv=""
cleanup() {
	local i
	for ((i = ${#mounted[@]} - 1; i >= 0; i--)); do
		umount -R "${mounted[$i]}" 2>/dev/null || umount -l "${mounted[$i]}" 2>/dev/null || true
	done
	mounted=()
	# Put the image's own resolv.conf back: the host's was only for the build.
	if [ -n "$saved_resolv" ]; then
		rm -f "$WORK/etc/resolv.conf"
		mv "$saved_resolv" "$WORK/etc/resolv.conf"
		saved_resolv=""
	fi
}
trap cleanup EXIT

mount -t proc proc "$WORK/proc" && mounted+=("$WORK/proc")
# A fresh /tmp for the build. apt writes temporary files there to verify
# repository signatures, and an image made for gVisor may have no usable
# /tmp of its own (gVisor mounts one at runtime). Whatever the build writes
# there vanishes with the mount instead of bloating the image.
mkdir -p "$WORK/tmp"
mount -t tmpfs -o mode=1777 tmpfs "$WORK/tmp" && mounted+=("$WORK/tmp")
mount --rbind /sys "$WORK/sys" && mount --make-rslave "$WORK/sys" && mounted+=("$WORK/sys")
mount --rbind /dev "$WORK/dev" && mount --make-rslave "$WORK/dev" && mounted+=("$WORK/dev")

# DNS for the build: the chroot shares the host's network, so the host's
# resolver configuration works there (including systemd-resolved's
# 127.0.0.53).
if [ -e "$WORK/etc/resolv.conf" ] || [ -L "$WORK/etc/resolv.conf" ]; then
	saved_resolv="$WORK/etc/.resolv.conf.sbx-saved"
	mv "$WORK/etc/resolv.conf" "$saved_resolv"
fi
cp -L /etc/resolv.conf "$WORK/etc/resolv.conf"

in_chroot() {
	chroot "$WORK" /usr/bin/env -i HOME=/root TERM=dumb \
		PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		DEBIAN_FRONTEND=noninteractive PLAYWRIGHT_VERSION="$PLAYWRIGHT_VERSION" \
		/bin/bash -euo pipefail -c "$1"
}

echo "installing pip, Playwright $PLAYWRIGHT_VERSION and Chromium (a few minutes)"
# Single quotes on purpose: $PLAYWRIGHT_VERSION expands inside the chroot,
# where in_chroot passes it as an environment variable.
# shellcheck disable=SC2016
in_chroot '
	# pip, and some of Chromium'"'"'s fonts, live in Ubuntu'"'"'s universe
	# component. Most Ubuntu images enable it; a minimal one (debootstrap'"'"'s)
	# has only main. Add it if no source mentions it.
	if ! grep -rqsw universe /etc/apt/sources.list /etc/apt/sources.list.d/; then
		. /etc/os-release
		echo "enabling the universe component for $VERSION_CODENAME"
		printf "deb http://archive.ubuntu.com/ubuntu %s main universe\ndeb http://archive.ubuntu.com/ubuntu %s-updates main universe\n" \
			"$VERSION_CODENAME" "$VERSION_CODENAME" > /etc/apt/sources.list.d/sbx-universe.list
	fi
	apt-get update -q
	apt-get install -y -q --no-install-recommends python3-pip ca-certificates
	python3 -m pip install -q --break-system-packages --no-cache-dir "playwright==$PLAYWRIGHT_VERSION"
	python3 -m playwright install --with-deps chromium
	apt-get clean
	rm -rf /var/lib/apt/lists/*
'

echo "smoke test: launching Chromium in the image"
in_chroot '
	python3 - <<PY
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(args=["--disable-dev-shm-usage"])
    page = b.new_page()
    page.goto("data:text/html,<title>sbx browser image ok</title>")
    print("smoke test:", page.title())
    b.close()
PY
'

cleanup
trap - EXIT
mv "$WORK" "$TARGET"
echo "built $TARGET ($(du -sh "$TARGET" | cut -f1))"
"$here/publish-image.sh" "$TARGET"
echo "new browser sandboxes get this version; existing ones keep theirs (sbx images)"
