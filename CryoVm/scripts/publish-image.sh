#!/usr/bin/env bash
# Points an image's -current link at a version, atomically (Day 21):
#
#   scripts/publish-image.sh /mnt/sbx/rootfs/browser-20261021-101500
#
# makes /mnt/sbx/rootfs/browser-current point at it. The new link is made
# under a temporary name and renamed over the old one: rename replaces in a
# single step, so anything reading the link sees the old version or the new
# one, never no link at all.
#
# Sandboxes are unaffected: the daemon stores the resolved path at create
# time, so each keeps the version it was made with through pauses and
# resumes. `sbx images` shows which versions are still in use.
set -euo pipefail
version=${1:?usage: publish-image.sh VERSION_DIR}
version=${version%/}
[ -d "$version" ] || { echo "publish-image: no directory $version" >&2; exit 1; }
base=$(basename "$version")
prefix=${version%-*-*}                      # /mnt/sbx/rootfs/browser-20261021-101500 → /mnt/sbx/rootfs/browser
[ "$prefix" != "$version" ] || { echo "publish-image: $base isn't NAME-YYYYMMDD-HHMMSS" >&2; exit 1; }
link="$prefix-current"
ln -sfn "$base" "$link.tmp.$$"              # relative: the link keeps working if the directory moves
mv -T "$link.tmp.$$" "$link"
echo "$(basename "$link") -> $base"
