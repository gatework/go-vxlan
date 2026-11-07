#!/bin/sh
# 只复用同一提交的成功主分支 CI 产物；缺失时失败，不重新构建。
set -eu
cd "$(dirname "$0")/.."
: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_SHA:?}"
: "${GITHUB_REF_NAME:?}"
test "${GITHUB_REF_TYPE:-}" = tag
revision=$(git rev-parse HEAD)
test "$revision" = "$GITHUB_SHA"
workflow_id=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml" --jq .id)
printf '%s\n' "$workflow_id" | grep -Eq '^[1-9][0-9]*$'
run_id=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/$workflow_id/runs?branch=main&head_sha=$revision&status=success&per_page=100" --jq ".workflow_runs | map(select(.head_sha == \"$revision\" and .head_branch == \"main\" and (.event == \"push\" or .event == \"workflow_dispatch\") and .workflow_id == $workflow_id and .status == \"completed\" and .conclusion == \"success\")) | sort_by(.id) | last | .id // empty")
if [ -z "$run_id" ]; then
  printf 'no successful main CI for %s; complete main CI and rerun this workflow\n' "$revision" >&2
  exit 1
fi
artifact="source-$revision"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id/artifacts" --jq ".artifacts[] | select(.name == \"$artifact\" and .expired == false) | [.id, .size_in_bytes] | @tsv" > "$work/artifact"
if [ "$(wc -l < "$work/artifact" | tr -d ' ')" != 1 ]; then
  printf 'verified artifact missing or expired in run %s; rerun main CI, then this workflow\n' "$run_id" >&2
  exit 1
fi
read -r artifact_id artifact_size < "$work/artifact"
test "$artifact_id" -gt 0
test "$artifact_size" -gt 0
test ! -e dist
gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact_id/zip" > "$work/artifact.zip"
mkdir dist
unzip -q "$work/artifact.zip" -d dist
sh scripts/verify-release.sh dist "$GITHUB_REF_NAME" "$revision"
printf 'reused main CI run %s, artifact %s, commit %s\n' "$run_id" "$artifact_id" "$revision"
