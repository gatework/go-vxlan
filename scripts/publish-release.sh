#!/bin/sh
# reuse-release.sh 已验证 dist；发布只上传缺失附件，不重建或覆盖已有文件。
set -eu
cd "$(dirname "$0")/.."
: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_REF_NAME:?}"
: "${GITHUB_SHA:?}"
test "${GITHUB_REF_TYPE:-}" = tag
tag=$GITHUB_REF_NAME
printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
version=${tag#v}
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
verify_tag() {
  refs=$(git ls-remote --exit-code origin "refs/tags/$tag" "refs/tags/$tag^{}")
  direct=$(printf '%s\n' "$refs" | awk -v ref="refs/tags/$tag" '$2 == ref {print $1}')
  peeled=$(printf '%s\n' "$refs" | awk -v ref="refs/tags/$tag^{}" '$2 == ref {print $1}')
  test -n "$direct"
  test "${peeled:-$direct}" = "$GITHUB_SHA"
}
verify_tag
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
printf 'SHA256SUMS\n' > "$work/expected"
for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  printf 'vxlan_%s_%s.tar.gz\n' "$version" "$target" >> "$work/expected"
done
sort "$work/expected" > "$work/sorted"
mv "$work/sorted" "$work/expected"
(cd dist && find . -mindepth 1 -maxdepth 1 -print | sed 's|^./||' | sort) > "$work/local"
cmp "$work/expected" "$work/local"

# API 失败直接停止，不能将认证、限流或网络错误误认为版本不存在。
release_id=$(gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate --jq ".[] | select(.tag_name == \"$tag\") | .id")
if [ -z "$release_id" ]; then
  gh release create "$tag" --repo "$GITHUB_REPOSITORY" --verify-tag --draft --title "$tag" --notes-file "docs/releases/$tag.md"
  # 按标签查询的端点不返回草稿；创建后仍从包含草稿的列表读取资源 ID。
  release_id=$(gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate --jq ".[] | select(.tag_name == \"$tag\") | .id")
fi
printf '%s\n' "$release_id" | grep -Eq '^[0-9]+$'
endpoint="repos/$GITHUB_REPOSITORY/releases/$release_id"
verify_metadata() {
  test "$(gh api "$endpoint" --jq .tag_name)" = "$tag"
  test "$(gh api "$endpoint" --jq .prerelease)" = false
}
verify_metadata
draft=$(gh api "$endpoint" --jq .draft)
gh api "$endpoint" --jq '.assets[].name' > "$work/remote-unsorted"
sort "$work/remote-unsorted" > "$work/remote"
comm -23 "$work/remote" "$work/expected" > "$work/extra"
test ! -s "$work/extra"
mkdir "$work/readback"
: > "$work/verified"
while IFS= read -r name; do
  if ! grep -Fxq "$name" "$work/remote"; then
    test "$draft" = true
    gh release upload "$tag" "dist/$name" --repo "$GITHUB_REPOSITORY"
  fi
  gh api "$endpoint" --jq ".assets[] | select(.name == \"$name\") | [.id,.name,.size] | @tsv" > "$work/asset"
  test "$(wc -l < "$work/asset" | tr -d ' ')" = 1
  cat "$work/asset" >> "$work/verified"
  # 重跑同样回读已有文件；不同内容直接失败，不能用 clobber 掩盖未知状态。
  gh release download "$tag" --repo "$GITHUB_REPOSITORY" --pattern "$name" --dir "$work/readback"
  cmp "dist/$name" "$work/readback/$name"
done < "$work/expected"
(cd "$work/readback" && shasum -a 256 -c SHA256SUMS)
# 每个附件只回读一次；公开草稿不会改变附件内容，核对资源 ID 防止并发替换。
sort "$work/verified" > "$work/before"
gh api "$endpoint" --jq '.assets[] | [.id,.name,.size] | @tsv' > "$work/current"
sort "$work/current" > "$work/after"
cmp "$work/before" "$work/after"
if [ "$draft" = true ]; then
  verify_tag
  gh release edit "$tag" --repo "$GITHUB_REPOSITORY" --draft=false
fi
test "$(gh api "$endpoint" --jq .draft)" = false
verify_metadata
gh api "$endpoint" --jq '.assets[] | [.id,.name,.size] | @tsv' > "$work/current"
sort "$work/current" > "$work/after"
cmp "$work/before" "$work/after"
verify_tag
printf 'published and verified %s\n' "$tag"
