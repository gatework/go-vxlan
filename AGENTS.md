# go-vxlan 开发说明

遵循 [gatework Go 工程规范](https://github.com/gatework/go-standards/blob/v1.0.2/STANDARD.md)（go-standards/STANDARD.md）；提交前运行 `make check`。

本项目提供 Cisco NX-OS VXLAN/EVPN 的配置与运行态解析、采集、Fabric 审查和受控增量变更，同时提供 Go 库与 `cmd/vxlan` CLI。用法见 [README.md](README.md)。

## 工作入口

- 开始修改前检查 `git status --short --branch` 和 `git worktree list`，保留已有工作区、暂存区及其他 worktree 的改动；提交时只暂存本次任务涉及的文件。
- 调整包职责、导入关系或会话生命周期前，阅读 [docs/architecture.md](docs/architecture.md)，以 `scripts/check-architecture.py` 验证边界。
- 修改公共 Go API 时阅读并同步 [docs/api-migration.md](docs/api-migration.md)；修改 CLI、证据或跨语言行为时核对 [docs/compatibility.md](docs/compatibility.md)。
- Go 版本与依赖以 `go.mod` 为准。日常构建使用正式模块版本与 `GOWORK=off`；本地依赖副本、workspace 或持久化 `replace` 不属于默认构建流程。

## 构建与检查

在仓库根目录执行：

```sh
export GOWORK=off GOFLAGS=-mod=readonly
go test ./...
go vet ./...
python3 scripts/check-architecture.py
go build -o bin/vxlan ./cmd/vxlan
./bin/vxlan --help
```

Go 文件修改后运行 `gofmt`。开发时先运行相关包的现有测试；代码交付前按 [docs/verification.md](docs/verification.md) 执行 race、模块及独立交付检查。CI 的实际命令和平台矩阵见 [.github/workflows/ci.yml](.github/workflows/ci.yml)。

独立交付检查入口为 `python3 scripts/check-delivery.py`，覆盖隔离源码、四平台构建、库消费者与安装后的 CLI。发布脚本变更另运行 `scripts/test-reuse-release.py` 和 `scripts/test-publish-release.py`（均使用 `python3`）。

## 实现边界

- 根包只承载证据结构、严格 JSON 投影和指纹。`parser` 声明查询/profile；`vendors/nxos` 负责厂商语法和来源信息；内置 registry 由 `vendors` 显式构造。
- `configuration` 负责配置关系，`review` 负责诊断和建议，`change` 负责增量及执行计划。这些业务包保持独立于文件系统、终端和具体传输。
- `collect` 借用调用方选定 profile 的独占会话；`adapter/netconnector` 承担传输适配和连接生命周期。完整 Capture 与后置错误可以共存：保留已接受事实，同时记录错误。
- `internal/bootstrap` 组合配置、清单和依赖，`internal/workflow` 编排流程，`internal/cli` 适配参数、确认和输出；`cmd/vxlan` 保持信号与退出码入口职责。
- `report` 负责私有文件与原子持久化。保留目录 `0700`、文件 `0600`、同步写入和执行检查点的语义。

## 回归与变更安全

- `Complete` 表示证据完整性，不代表网络健康。未知、不完整或互相矛盾的证据不能授权配置变更。
- 保留严格 JSON 校验、精确整数、来源顺序、null 与空容器的区别，以及配置指纹语义；用现有回归与金样验证行为。
- 自动执行仅支持 `svi_acl`、`svi_gateway_add`、`vlan_vni_add`。`apply` 保留单项选择、真实终端确认、计划绑定、写前漂移检查、执行日志和回读验证；结果不明时保留 `uncertain`，不自动重放、重连、回滚或保存配置。
- `testdata/` 是 Ruby 基线金样，来源见 [docs/ruby-baseline.json](docs/ruby-baseline.json)。普通 Go 测试无需 Ruby；仅在明确更新基线时使用 `scripts/export-*.rb` 或 `scripts/verify-ruby-parsers.rb`，重生方法见验证说明。
- 凭据通过环境或 `.env` 提供。真实设备报告、`.work/`、`vxlans/`、`vxlan-executions/` 和本地构建产物保持在源码与发行包之外。

## 发布与验证范围

发布任务先阅读 [docs/RELEASING.md](docs/RELEASING.md)，复用精确提交的成功 CI 制品，并读回附件校验结果。版本常量位于 `internal/cli/app.go`。

汇报时区分本地测试、CI、发行包、真实设备与部署验证。合成会话或 PTY 回归不构成生产写入验收；历史实机记录的边界见验证说明。
