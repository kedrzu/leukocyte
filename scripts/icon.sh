#!/usr/bin/env bash
# Renders packaging/icon.svg into packaging/leukocyte.icns (16–512 pt at @1x and @2x).
#
#   scripts/icon.sh
#
# Rasterises with rsvg-convert when it is installed, else with Quick Look (qlmanage renders the SVG
# at 1024 px and sips scales it down), so it needs nothing beyond macOS. The .icns is committed: run
# this after changing the SVG, not on every build.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

svg="packaging/icon.svg"
icns="packaging/leukocyte.icns"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
iconset="$work/leukocyte.iconset"
mkdir "$iconset"

# render <pixels> <output.png>
if command -v rsvg-convert >/dev/null; then
  render() { rsvg-convert --width "$1" --height "$1" --output "$2" "$svg"; }
else
  qlmanage -t -s 1024 -o "$work" "$svg" >/dev/null
  master="$work/$(basename "$svg").png"
  [[ -f "$master" ]] || {
    echo "qlmanage did not render $svg" >&2
    exit 1
  }
  render() { sips -z "$1" "$1" "$master" --out "$2" >/dev/null; }
fi

for size in 16 32 128 256 512; do
  render "$size" "$iconset/icon_${size}x${size}.png"
  render "$((size * 2))" "$iconset/icon_${size}x${size}@2x.png"
done
iconutil -c icns -o "$icns" "$iconset"
echo "wrote $icns"
