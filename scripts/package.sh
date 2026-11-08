#!/bin/sh
# 构建四个平台的单一程序；只向尚不存在的目录交付完整归档。
set -eu
umask 022
cd "$(dirname "$0")/.."
GO=${GO:-go}
output=${1:-dist}
case "$output" in /*) ;; *) output="$PWD/$output" ;; esac
if [ -e "$output" ]; then
  printf 'output already exists: %s\n' "$output" >&2
  exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
host_os=$("$GO" env GOHOSTOS)
host_arch=$("$GO" env GOHOSTARCH)
host="$host_os/$host_arch"
CGO_ENABLED=0 GOOS=$host_os GOARCH=$host_arch "$GO" build -mod=readonly -trimpath -o "$work/vxlan" ./cmd/vxlan
version=$("$work/vxlan" --version)
version=${version#vxlan }
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if [ "${GITHUB_REF_TYPE:-}" = tag ] && [ "${GITHUB_REF_NAME:-}" != "v$version" ]; then
  printf 'tag and CLI version differ: %s / %s\n' "$GITHUB_REF_NAME" "$version" >&2
  exit 1
fi
test -f "docs/releases/v$version.md"
mkdir -p "$work/common/docs/releases" "$work/common/licenses/go" "$work/archives"
cp README.md LICENSE "$work/common/"
cp docs/architecture.md docs/api-migration.md docs/compatibility.md docs/verification.md docs/RELEASING.md "$work/common/docs/"
cp "docs/releases/v$version.md" "$work/common/docs/releases/"
goroot=$("$GO" env GOROOT)
license="$goroot/LICENSE"
# Homebrew 将顶层 LICENSE 放在 libexec 的父目录。
if [ ! -f "$license" ] && [ "${goroot##*/}" = libexec ]; then
  license="$goroot/../LICENSE"
fi
cp "$license" "$goroot/PATENTS" "$work/common/licenses/go/"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${target%/*}
  arch=${target#*/}
  name="vxlan_${version}_${os}_${arch}"
  directory="$work/$name"
  mkdir "$directory"
  cp -R "$work/common/." "$directory/"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch GO="$GO" sh scripts/package-licenses.sh "$directory/licenses" ./cmd/vxlan
  for tool in vxlan; do
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch "$GO" build -mod=readonly -trimpath -o "$directory/$tool" "./cmd/$tool"
    (cd "$directory" && "$GO" version -m "$tool" > "$tool.BUILDINFO.txt")
  done
  COPYFILE_DISABLE=1 tar -czf "$work/archives/$name.tar.gz" -C "$work" "$name"
  if [ "$target" = "$host" ]; then
    mkdir "$work/installed"
    tar -xzf "$work/archives/$name.tar.gz" -C "$work/installed"
    for tool in vxlan; do
      test "$("$work/installed/$name/$tool" --version)" = "$version"
      "$work/installed/$name/$tool" --help > /dev/null
    done
  fi
done
(cd "$work/archives" && shasum -a 256 ./*.tar.gz > SHA256SUMS && shasum -a 256 -c SHA256SUMS)
mkdir "$output"
cp "$work/archives/"* "$output/"
printf 'release archives: %s\n' "$output"
