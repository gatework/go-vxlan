#!/bin/sh
# 检查精确的归档集合、摘要、平台与单一程序的源码提交身份。
set -eu
test "$#" = 3
output=$1
tag=$2
revision=$3
printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
printf '%s\n' "$revision" | grep -Eq '^[0-9a-f]{40}$'
version=${tag#v}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  printf './vxlan_%s_%s.tar.gz\n' "$version" "$target"
done | sort > "$work/expected"
(cd "$output" && find . -mindepth 1 -maxdepth 1 ! -name SHA256SUMS -print | sort) > "$work/actual"
cmp "$work/expected" "$work/actual"
test "$(wc -l < "$output/SHA256SUMS" | tr -d ' ')" = 4
awk 'length($1) != 64 || $1 ~ /[^0-9a-f]/ || NF != 2 {exit 1} {print $2}' "$output/SHA256SUMS" | sort > "$work/listed"
cmp "$work/expected" "$work/listed"
(cd "$output" && shasum -a 256 -c SHA256SUMS)
for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  name="vxlan_${version}_$target"
  archive="$output/$name.tar.gz"
  tar -tzf "$archive" > "$work/entries"
  awk -v root="$name/" 'index($0,root) != 1 || $0 ~ /(^|\/)\.\.(\/|$)/ {exit 1}' "$work/entries"
  grep -Fx "$name/docs/releases/$tag.md" "$work/entries" > /dev/null
  grep -Fx "$name/docs/api-migration.md" "$work/entries" > /dev/null
  grep -Fx "$name/LICENSE" "$work/entries" > /dev/null
  tar -xOf "$archive" "$name/LICENSE" > "$work/license"
  cmp LICENSE "$work/license"
  mkdir "$work/$target"
  tar -xzf "$archive" -C "$work/$target" "$name/licenses"
  licenses="$work/$target/$name/licenses"
  test -s "$licenses/go/LICENSE"
  test -s "$licenses/go/PATENTS"
  (cd "$licenses" && shasum -a 256 -c SHA256SUMS)
  : > "$work/dependencies"
  for tool in vxlan; do
    tar -xOf "$archive" "$name/$tool.BUILDINFO.txt" > "$work/buildinfo"
    tar -xOf "$archive" "$name/$tool" > "$work/binary"
    go version -m "$work/binary" > "$work/actual-buildinfo"
    sed '1d' "$work/buildinfo" > "$work/expected-metadata"
    sed '1d' "$work/actual-buildinfo" > "$work/actual-metadata"
    cmp "$work/expected-metadata" "$work/actual-metadata"
    grep -Fx "$(printf '\tbuild\tvcs.revision=%s' "$revision")" "$work/buildinfo" > /dev/null
    grep -Fx "$(printf '\tbuild\tvcs.modified=false')" "$work/buildinfo" > /dev/null
    grep -Fx "$(printf '\tbuild\tGOOS=%s' "${target%_*}")" "$work/buildinfo" > /dev/null
    grep -Fx "$(printf '\tbuild\tGOARCH=%s' "${target#*_}")" "$work/buildinfo" > /dev/null
    grep -Fx "$(printf '\tbuild\tCGO_ENABLED=0')" "$work/buildinfo" > /dev/null
    # 许可证清单必须对应归档中二进制的实际模块，而非整个 go.mod 图。
    awk '$1 == "=>" {exit 1} $1 == "dep" {printf "%s\t%s\t%s\n", $2, $3, $4}' "$work/buildinfo" >> "$work/dependencies"
  done
  LC_ALL=C sort -u "$work/dependencies" > "$work/actual-dependencies"
  cmp "$licenses/modules.tsv" "$work/actual-dependencies"
  while IFS="$(printf '\t')" read -r module module_version module_sum; do
    test -n "$module_sum"
    test -d "$licenses/modules/$module@$module_version"
    test -n "$(find "$licenses/modules/$module@$module_version" -type f -print)"
  done < "$licenses/modules.tsv"
done
host="$(go env GOHOSTOS)_$(go env GOHOSTARCH)"
name="vxlan_${version}_$host"
for tool in vxlan; do
  tar -xOf "$output/$name.tar.gz" "$name/$tool" > "$work/$tool"
  chmod +x "$work/$tool"
  test "$("$work/$tool" --version)" = "$version"
  "$work/$tool" --help > /dev/null
done
printf 'verified %s at %s\n' "$tag" "$revision"
