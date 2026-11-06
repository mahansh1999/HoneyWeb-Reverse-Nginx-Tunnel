#!/usr/bin/env bash
# install.sh — one-line installer for HoneyWeb Reverse Nginx Tunnel. Run as root on either server:
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/mahansh1999/HoneyWeb-Reverse-Nginx-Tunnel/main/install.sh)
#
# GITHUB_TOKEN, if set, is sent with the GitHub downloads (a fork kept private, or GitHub's rate limit); it is never
# stored.
#
# It downloads the scripts (RNT_REF, default main) and the engine binary of the latest release (RNT_TAG to pin one),
# checks the binary against the release's SHA256SUMS, keeps everything in /opt/hwt-rnt/pkg, links hwt-rnt, and opens
# the menu (install entry / exit, status, speed test, certificate, stop, remove).
set -euo pipefail
REPO=${RNT_REPO:-mahansh1999/HoneyWeb-Reverse-Nginx-Tunnel}; REF=${RNT_REF:-main}; TAG=${RNT_TAG:-latest}
PKG=/opt/hwt-rnt/pkg
die() { echo "install: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
for c in curl tar python3 sha256sum; do command -v $c >/dev/null || die "$c is required (apt-get install $c)"; done
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) die "unsupported architecture $(uname -m)";; esac
auth=(); [ -z "${GITHUB_TOKEN:-}" ] || auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
api() { curl -fsSL "${auth[@]}" -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/$1"; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

echo "== downloading the scripts ($REPO@$REF)"
curl -fsSL "${auth[@]}" "https://api.github.com/repos/$REPO/tarball/$REF" -o "$tmp/src.tgz" \
  || die "cannot download $REPO (no network to GitHub, or a private fork without GITHUB_TOKEN)"
mkdir "$tmp/src"; tar -xzf "$tmp/src.tgz" -C "$tmp/src" --strip-components=1
[ -f "$tmp/src/hwt-rnt.sh" ] || die "the download has no hwt-rnt.sh"

echo "== downloading the engine (release $TAG, linux/$ARCH)"
if [ "$TAG" = latest ]; then rel=$(api releases/latest); else rel=$(api "releases/tags/$TAG"); fi \
  || die "no release found in $REPO"
ids=$(printf '%s' "$rel" | python3 -c '
import json, sys
r = json.load(sys.stdin); a = {x["name"]: x["id"] for x in r.get("assets", [])}
print(r.get("tag_name"), a.get("hwtunnel-linux-'"$ARCH"'", ""), a.get("SHA256SUMS", ""))')
read -r tag bin_id sums_id <<<"$ids"
[ -n "$bin_id" ] && [ -n "$sums_id" ] || die "release $tag has no hwtunnel-linux-$ARCH or SHA256SUMS"
asset() { curl -fsSL "${auth[@]}" -H "Accept: application/octet-stream" "https://api.github.com/repos/$REPO/releases/assets/$1" -o "$2"; }
asset "$bin_id" "$tmp/hwtunnel"; asset "$sums_id" "$tmp/SHA256SUMS"
want=$(awk -v f="hwtunnel-linux-$ARCH" '$2 == f || $2 == "*" f {print $1}' "$tmp/SHA256SUMS")
got=$(sha256sum "$tmp/hwtunnel" | awk '{print $1}')
[ -n "$want" ] && [ "$want" = "$got" ] || die "engine checksum mismatch (release $tag): want ${want:-none}, got $got"
echo "   engine $tag verified (${got:0:16})"

rm -rf "$PKG.new"; install -d -m 0755 /opt/hwt-rnt "$PKG.new"
cp -a "$tmp/src/hwt-rnt.sh" "$tmp/src/rnt.sh" "$tmp/src/nginx" "$tmp/src/site" "$PKG.new/"
install -m 0755 "$tmp/hwtunnel" "$PKG.new/hwtunnel"; echo "$got  hwtunnel" > "$PKG.new/hwtunnel.sha256"
# keep a token an earlier run left (a reinstall of the same tunnel)
[ -f "$PKG/token" ] && cp -a "$PKG/token" "$PKG.new/token"
rm -rf "$PKG"; mv "$PKG.new" "$PKG"; chmod 0755 "$PKG/hwt-rnt.sh" "$PKG/rnt.sh"
ln -sfn "$PKG/hwt-rnt.sh" /usr/local/bin/hwt-rnt
echo "== ready: hwt-rnt (menu), or hwt-rnt status|speedtest|start|stop|remove NAME"
exec bash "$PKG/hwt-rnt.sh" menu
