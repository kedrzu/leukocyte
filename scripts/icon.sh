#!/usr/bin/env bash
# Renders packaging/icon.svg into packaging/leukocyte.icns (16–512 pt at @1x and @2x).
#
#   scripts/icon.sh
#
# Rasterises with AppKit (`scripts/lib/render-svg.swift`, compiled once per run), which keeps the
# transparent corners; it needs only macOS and the Command Line Tools. The .icns is committed: run this
# after changing the SVG, not on every build.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

svg="packaging/icon.svg"
icns="packaging/leukocyte.icns"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
iconset="$work/leukocyte.iconset"
mkdir "$iconset"

swiftc -O -o "$work/render-svg" scripts/lib/render-svg.swift
# render <pixels> <output.png>
render() { "$work/render-svg" "$svg" "$2" "$1"; }

for size in 16 32 128 256 512; do
  render "$size" "$iconset/icon_${size}x${size}.png"
  render "$((size * 2))" "$iconset/icon_${size}x${size}@2x.png"
done
iconutil -c icns -o "$icns" "$iconset"
echo "wrote $icns"
