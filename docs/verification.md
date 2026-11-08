# 验证说明

## 当前检查入口

构建独立使用 go.mod/go.sum 固定的正式 Connector 与 Expect，不恢复本地依赖源码：

```sh
export GOWORK=off GOFLAGS=-mod=readonly
go mod verify
go mod tidy -diff
python3 scripts/check-architecture.py
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
