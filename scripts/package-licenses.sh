#!/bin/sh
# 按目标平台的实际生产依赖保留模块声明；调用方设置 GOOS、GOARCH、CGO_ENABLED。
set -eu
test "$#" -ge 2
destination=$1
shift
GO=${GO:-go}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$destination/modules"
template='{{with .Module}}{{if not .Main}}{{if .Replace}}REPLACED{{end}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{.Sum}}{{"\t"}}{{.Dir}}{{end}}{{end}}'
"$GO" list -mod=readonly -deps -f "$template" "$@" > "$work/packages"
sed '/^$/d' "$work/packages" | LC_ALL=C sort -u > "$work/modules"
: > "$destination/modules.tsv"
while IFS="$(printf '\t')" read -r module version sum directory; do
  case "$module" in REPLACED*) printf 'release dependency replacement is not supported: %s\n' "$module" >&2; exit 1 ;; esac
  test -n "$version" && test -n "$sum" && test -d "$directory"
  target="$destination/modules/$module@$version"
  # 模块中的嵌套第三方实现可能使用不同许可证，保留相对路径以免覆盖。
  (cd "$directory" && find . -type f -print) | LC_ALL=C sort | awk '
    {name=$0; sub(/^.*\//,"",name); name=tolower(name)}
    name ~ /^(licen[cs]e|notice|patents?|copying|copyright)([._-].*)?$/ || tolower($0) ~ /\/licenses\// {print}
  ' > "$work/notices"
  if [ ! -s "$work/notices" ]; then
    printf 'no license or notice found for dependency: %s\n' "$module" >&2
    exit 1
  fi
  while IFS= read -r notice; do
    mkdir -p "$target/$(dirname "$notice")"
    cp "$directory/$notice" "$target/$notice"
  done < "$work/notices"
  printf '%s\t%s\t%s\n' "$module" "$version" "$sum" >> "$destination/modules.tsv"
done < "$work/modules"
(cd "$destination" && find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort > "$work/files")
(cd "$destination" && while IFS= read -r file; do shasum -a 256 "$file"; done < "$work/files") > "$destination/SHA256SUMS"
