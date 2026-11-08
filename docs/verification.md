# 验证说明

## 当前检查入口

构建独立使用 go.mod/go.sum 固定的正式 Connector 与 Expect，不恢复本地依赖源码：

v0.3.0 固定 Connector v0.5.0、Expect v0.4.2，消费正式版本中的 `SingleAccepted`、`Body`、`ReadFile`、`ParseYAMLMapping`。此前任务级 workspace 与冻结本地 module proxy 的结果是候选验证；正式依赖更新后须重新通过下面的独立构建及精确版本门禁。发布还需同提交成功 CI、原制品复用和正式标签消费者，不以候选测试代替。

```sh
export GOWORK=off GOFLAGS=-mod=readonly
go mod verify
go mod tidy -diff
python3 scripts/check-architecture.py
python3 scripts/test_architecture.py
go test -race -shuffle=on -count=1 -timeout=180s ./...
go vet ./...
python3 scripts/check-delivery.py
python3 scripts/test-reuse-release.py
python3 scripts/test-publish-release.py
```

交付脚本在隔离源码目录运行全包测试、Linux/macOS × amd64/arm64 构建、公开业务包消费者和安装后 CLI。只有当前 VXLAN 候选源码在临时 consumer 中使用本地 replace；Connector/Expect 始终保持正式版本。该检查与发布后的无 replace 标签消费者分别证明不同阶段，不以候选源码检查冒充发布验收。隔离源码排除 bin、dist、workspace 和私有运行目录。

GitHub CI 在 Linux/macOS × Go 1.26/1.27 执行模块、架构、vet、race 检查；Go 1.27 作业运行 govulncheck。打包后在 Linux 和 macOS 实际执行下载的发行包。默认 golangci-lint 仍有此前记录的 errcheck/staticcheck 债务，未将其声明为已通过的项目门禁。

## 保留的回归依据

`testdata/` 中的 Ruby 金样覆盖 727 个运行态、431 个配置事实、431 个来源元数据及 311 个领域用例。`docs/ruby-baseline.json` 保留原始 Ruby 源码身份；`scripts/export-*.rb` 和 `verify-ruby-parsers.rb` 用于显式重生/对照，普通构建与 Go 测试不需要 Ruby。目录清理不修改金样、精确数值、来源顺序或配置指纹。

### Ruby 重生与来源验证

manifest 记录参考提交 `3c7b85529a6639c74c649f754c7feb09e7610621` 及 102 个文件的 SHA256；脚本按文件摘要验证来源，而非仅相信分支名。2026-11-07 只读检查发现当前 `/Users/crate/Works/ruby/vxlan` 有 34 个文件与该清单不同，因此本轮没有运行独立 Ruby oracle 或重生金样。应使用匹配清单的参考 checkout 和它自己的 bundle；不要为通过对照自动更新 manifest。

以下命令仅在单独更新基线任务时执行，不属于本轮验证。两段应在同一 shell 脚本中顺序执行，来源检查失败即停止。变量使用绝对路径，输出放独立临时目录，首先验证已提交的输入/预期：

```sh
set -eu
vxlan_go=/absolute/path/to/go-vxlan
vxlan_ruby=/absolute/path/to/matching-ruby-vxlan
vxlan_oracle=$(mktemp -d)
export VXLAN_CORPUS_DIR="$vxlan_oracle/raw"
export VXLAN_DOMAIN_DIR="$vxlan_oracle/testdata/domain"
mkdir -p "$VXLAN_CORPUS_DIR" "$VXLAN_DOMAIN_DIR" "$vxlan_oracle/testdata/configuration" "$vxlan_oracle/testdata/runtime"
cd "$vxlan_ruby"
bundle exec ruby -Ilib "$vxlan_go/scripts/verify-ruby-parsers.rb" "$vxlan_go" "$vxlan_ruby"

bundle exec rspec -Ilib -r "$vxlan_go/scripts/export-ruby-corpus.rb" \
  spec/runtime_parser_spec.rb spec/config_spec.rb spec/config spec/cisco_nxos
bundle exec rspec -Ilib -r "$vxlan_go/scripts/export-domain-corpus.rb" \
  spec/recommendations_spec.rb spec/change_plan_value_spec.rb \
  spec/service/catalog_spec.rb spec/fabric/scope_spec.rb spec/fabric/review_spec.rb \
  spec/prefix_list_references_spec.rb spec/change_plan_spec.rb spec/acl_policy_spec.rb
bundle exec ruby -Ilib "$vxlan_go/scripts/export-domain-extra.rb"
```

`export-ruby-corpus.rb` 记录真实 parser 调用，按内容 SHA256 命名；配置行保持 name/records/issues/evidence，去掉不稳定时间。将配置行与运行态行分开，运行态 ID 保持 `upstream/<文件摘要>`：

```sh
python3 - "$vxlan_oracle" <<'PY'
import json, pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
runtime = []
for path in sorted((root / "raw").glob("*.json")):
    row = json.loads(path.read_text())
    if row["name"] == "configuration":
        shutil.copy2(path, root / "testdata/configuration" / path.name)
    else:
        row["id"] = "upstream/" + path.stem
        runtime.append(row)
(root / "testdata/runtime/upstream-spec.json").write_text(
    json.dumps(runtime, ensure_ascii=False, indent=2) + "\n"
)
PY
bundle exec ruby -Ilib "$vxlan_go/scripts/export-source-corpus.rb" \
  "$vxlan_oracle" "$vxlan_oracle/testdata/configuration_sources.json"
cp "$vxlan_go/testdata/runtime/generate.rb" "$vxlan_oracle/testdata/runtime/generate.rb"
VXLAN_RUBY="$vxlan_ruby" bundle exec ruby -Ilib "$vxlan_oracle/testdata/runtime/generate.rb"
diff -qr "$vxlan_go/testdata" "$vxlan_oracle/testdata"
```

`export-source-corpus.rb` 基于配置输入保留来源状态、嵌套块与 capture 顺序；`generate.rb` 补充运行态对抗输入；领域脚本覆盖推荐、同角色 Fabric、ACL/网关/映射增量、子网及前缀引用。差异需按业务事实审核，不能排序或规范化数组来掩盖行为变化。确认有意更新后才替换相应金样，并重跑 Go 的配置、运行态、来源和领域 corpus 测试。

现有回归覆盖重复键和非法数字拒绝、已接受回执与后置错误共存、profile 所有权、父 context 取消、配置前后验证、发布/持久化失败，以及最终回调失败后返回摘要与磁盘摘要保持一致。业务边界与跨语言差异见 [兼容矩阵](compatibility.md)，Go 导入路径和生命周期迁移见 [API 迁移](api-migration.md)。

旧依赖 manifest、workspace 恢复步骤和初始实施草案从当前源码树移除；历史材料可在 v0.1.0/v0.2.0 标签查询。当前文档只保留有效操作步骤、接口契约、回归来源和实测边界。

## v0.2.0 已发布版本

[v0.2.0](https://github.com/gatework/go-vxlan/releases/tag/v0.2.0) 对应提交 `e6188e1d9a3cd6bccba85ff70b3fc4ad70d1981d`，[同提交 CI](https://github.com/gatework/go-vxlan/actions/runs/42433244944) 全部通过。

[发布工作流](https://github.com/gatework/go-vxlan/actions/runs/42433637138) 复用该提交的不可变制品，四个平台归档及 SHA256SUMS 经上传、下载字节核对。全新缓存、GOWORK=off、无 replace 的正式模块消费者和 go install 通过，下载的 macOS arm64 发行程序完成帮助、版本和离线解析检查。首次草稿读回步骤退出后，重跑同一提交的发布作业成功，没有重建或覆盖已发布附件。

这些结果只对应已发布的提交。后续工作区清理需要重新执行本节列出的本地检查；不修改既有标签或附件。

## 2026-10-26 实机只读历史

历史验证从 83 台 NX-OS 清单中抽取 6 台（3 Leaf、1 Border、2 Spine），覆盖六种 N9K 型号，并发 2。仅执行 SSH 只读查询，没有 apply 或保存配置。

- 6 台均完成传输及报告保存；78 次回执包含 12 次准备和 66 次维度查询。
- 共解析 8,835 条记录：4 台 complete、2 台 partial。两台 Spine 的 l2route 查询缺少空表完整性证据，保留 partial；未放宽规则伪造 complete。
- 对同一批传输正文与 Ruby Driver/Collector 回放比较，6 台共 78 个观测的 status、records、issues 一致；未排序或归一化诊断来掩盖差异。

原始采集、回放 JSON 与设备报告属于本地私有 `.work/live-validation-*` 数据，不进入源码或公开 fixture。它们来自旧依赖的一次现场验证，不能外推为全部 83 台、v0.2.0 新版实机、真实 PostgreSQL、生产写入、业务连通性或部署验收。apply 回归仍使用合成会话或本地 PTY。
