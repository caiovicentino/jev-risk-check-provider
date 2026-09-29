#!/bin/bash
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
BUILD=/tmp/x402snap-build
rm -rf "$BUILD"
mkdir -p "$BUILD"
for f in index.tsx snap.manifest.json package.json snap.config.js tsconfig.json icon.svg; do
  [ -f "$SRC/$f" ] && cp "$SRC/$f" "$BUILD/"
done
cp -R "$SRC/node_modules" "$BUILD/node_modules"
cd "$BUILD"
npx mm-snap build > /tmp/x402snap-build.log 2>&1
grep -E "✖|Compiled|successfully|fixed" /tmp/x402snap-build.log | head -4
cd "$BUILD" && npx mm-snap manifest > /tmp/x402snap-manifest.log 2>&1
grep -E "✖|⚠|valid" /tmp/x402snap-manifest.log | head -4 || true
cp -R "$BUILD/dist" "$SRC/dist"
cp "$BUILD/snap.manifest.json" "$SRC/snap.manifest.json"
echo COPIED
