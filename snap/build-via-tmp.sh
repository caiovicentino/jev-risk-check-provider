#!/usr/bin/env bash
# Builds the Snap in a space-free directory and copies the result back.
#
# mm-snap (webpack + swc) breaks when the project path contains a space (this
# repo lives under "/Volumes/SSD Major/..."), so the sources are copied to
# $BUILD, built and validated there, then:
#   - dist/ in the snap folder is REPLACED as a whole (copying into an existing
#     dist/ would create dist/dist and leave a stale dist/bundle.js),
#   - snap.manifest.json is copied back with the recomputed shasum.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
BUILD="${X402SNAP_BUILD_DIR:-/tmp/x402snap-build}"
case "$BUILD" in
  *" "*) echo "build dir must not contain spaces: $BUILD" >&2; exit 1 ;;
esac
# The contents of $BUILD are deleted below: only ever operate on a dedicated
# x402snap-* directory, never on an arbitrary path such as $HOME or /.
case "$(basename "$BUILD")" in
  x402snap-*) ;;
  *) echo "refusing to clean $BUILD: the build dir name must start with x402snap-" >&2; exit 1 ;;
esac

mkdir -p "$BUILD"
# Clean everything except the node_modules mirror (kept to make rebuilds fast).
find "$BUILD" -mindepth 1 -maxdepth 1 ! -name node_modules -exec rm -rf {} +
for f in index.tsx snap.manifest.json package.json snap.config.js tsconfig.json icon.svg; do
  cp "$SRC/$f" "$BUILD/"
done
cp -R "$SRC/src" "$BUILD/src"
# A symlink would resolve back to the path with the space, so mirror a copy.
if command -v rsync > /dev/null 2>&1; then
  rsync -a --delete "$SRC/node_modules/" "$BUILD/node_modules/"
else
  rm -rf "$BUILD/node_modules"
  cp -R "$SRC/node_modules" "$BUILD/node_modules"
fi

cd "$BUILD"
if ! npx mm-snap build > "$BUILD/build.log" 2>&1; then
  cat "$BUILD/build.log" >&2
  echo "mm-snap build failed" >&2
  exit 1
fi
grep -E "✖|⚠|Compiled|fixed" "$BUILD/build.log" || true
if ! npx mm-snap manifest > "$BUILD/manifest.log" 2>&1; then
  cat "$BUILD/manifest.log" >&2
  echo "mm-snap manifest validation failed" >&2
  exit 1
fi
grep -E "✖|⚠|valid" "$BUILD/manifest.log" || true

rm -rf "$SRC/dist"
cp -R "$BUILD/dist" "$SRC/dist"
cp "$BUILD/snap.manifest.json" "$SRC/snap.manifest.json"
echo "Copied $(wc -c < "$SRC/dist/bundle.js" | tr -d ' ') bytes to dist/bundle.js; shasum $(node -p "require('$SRC/snap.manifest.json').source.shasum")"
