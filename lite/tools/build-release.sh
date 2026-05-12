#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${DIST:-"$ROOT/dist"}"
VERSION="${VERSION:-$(cd "$ROOT" && go run ./cmd/cloudrec-lite version)}"

if [[ -n "${LITE_RELEASE_TARGETS:-}" ]]; then
  read -r -a targets <<< "$LITE_RELEASE_TARGETS"
else
  targets=(
    "darwin/amd64"
    "darwin/arm64"
    "linux/amd64"
    "linux/arm64"
    "windows/amd64"
  )
fi

rm -rf "$DIST"
mkdir -p "$DIST"

for target in "${targets[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  name="cloudrec-lite_${VERSION}_${os}_${arch}"
  out_dir="$DIST/$name"
  mkdir -p "$out_dir"
  binary="$out_dir/cloudrec-lite"
  if [[ "$os" == "windows" ]]; then
    binary="$binary.exe"
  fi
  echo "building $name"
  ldflags="-s -w -X main.version=$VERSION"
  (
    cd "$ROOT"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$ldflags" -o "$binary" ./cmd/cloudrec-lite
  )
  cp "$ROOT/README.md" "$out_dir/README.md"
  cp -R "$ROOT/rules" "$out_dir/rules"
  if [[ -f "$ROOT/../LICENSE" ]]; then
    cp "$ROOT/../LICENSE" "$out_dir/LICENSE"
  fi
  if [[ -f "$ROOT/../SECURITY.md" ]]; then
    cp "$ROOT/../SECURITY.md" "$out_dir/SECURITY.md"
  fi
  (
    cd "$DIST"
    tar -czf "$name.tar.gz" "$name"
  )
  rm -rf "$out_dir"
done

(
  cd "$DIST"
  shasum -a 256 *.tar.gz > checksums.txt
)

echo "release artifacts written to $DIST"
