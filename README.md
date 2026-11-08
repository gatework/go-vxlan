# Go VXLAN

Cisco NX-OS VXLAN/EVPN 配置与运行态采集、证据解析、Fabric 审查和受控增量变更。参考 Ruby VXLAN `3c7b855` 实现，运行时不需要 Ruby。

支持 Go 1.26 及以上，Linux/macOS amd64/arm64。当前版本 `v0.2.0`，固定使用正式依赖 `go-net-connector v0.4.0` 与 `go-expect v0.4.1`，通过 `GOWORK=off` 独立构建。公开业务包路径有所调整，升级前阅读 [API 迁移](docs/api-migration.md)；版本与附件见 [Releases](https://github.com/gatework/go-vxlan/releases)。

```sh
GOWORK=off go test -mod=readonly ./...
GOWORK=off go build -mod=readonly -o bin/vxlan ./cmd/vxlan
./bin/vxlan --help
```

依赖由 `go.mod/go.sum` 管理，无需本地依赖副本或 workspace 重建步骤。接口迁移见 [迁移说明](docs/api-migration.md)。

## CLI

```sh
# 在启动目录生成 vxlan.yml 与 .env 模板，已有文件保持不变
/path/to/vxlan collect --init --non-interactive --config ./vxlan.yml --env-file ./.env

# 离线解析；只有确认采集完整时才声明 --complete
/path/to/vxlan parse --file running.cfg --complete --json
/path/to/vxlan parse --dimension nve_peers --file peers.txt --model N9K --complete --json

# 先查看所选清单，再采集；--host 仅筛选清单，不创建临时目标
/path/to/vxlan collect --name leaf --plan
/path/to/vxlan collect --dimensions configuration,nve_peers,nve_vnis --json

# 离线复核已有证据，按需生成候选命令
/path/to/vxlan review --batch vxlans/BATCH --scripts
/path/to/vxlan apply --plan OUTPUT_BATCH/plan.json --item ITEM_ID
```

`collect`、`parse`、`review`、`apply` 均提供 `--help`。采集含配置及 11 个运行维度；`parse --help` 列出名称。`--plan`/`--inventory-only` 只读清单，不连接设备。默认只输出事实和建议；`--scripts` 导出候选变更。

证据与计划 JSON 拒绝重复键、非法 UTF-8 和超过 128 层的嵌套。采集、持久化和离线审查保留大整数计数的精确值；ACL 序号须为 1～4294967295 的整数。

退出码：`0` 完整或预览成功，`1` 证据不完整、无目标或用户取消确认，`2` 参数/执行/报告错误，`130` 信号或上下文取消。证据完整不等于网络健康。

最小 `vxlan.yml`：

```yaml
devices:
  - host: 192.0.2.10
    name: leaf01
    model: N9K-C93180
parallel: 4
dimensions: [configuration, nve_peers, nve_vnis]
directory: ./vxlans
ssh:
  host_key_policy: strict
```

凭据放在环境或 `.env`：`NC_DEVICE_USERNAME`、`NC_DEVICE_PASSWORD`，也支持 `NC_CISCO_NXOS_USERNAME`/`NC_CISCO_NXOS_PASSWORD`。凭据不写入 YAML。主机密钥默认严格验证；正式使用前准备已核对的 known_hosts。

配置优先级为 CLI > 进程环境 > YAML > `.env` > 默认。支持系统、用户、程序目录、启动目录、显式文件分层；路径相对于定义它的配置文件，数组替换。`--show-config` 显示公开配置及来源。清单支持静态设备与 Netdisco HTTP/PostgreSQL/缓存，复用 Go connector 公共接口；详见 [兼容矩阵](docs/compatibility.md)。

报告目录为 `0700`，文件为 `0600`；证据、建议、计划和事件通过临时文件、同步和原子替换发布。先读 `summary.json` 的最终状态和 `report_saved`，再查看 `devices/`、`evidence/`；报告失败保留已有事实。

`apply` 仅接受计划中明确选择的一项，要求真实终端输入包含目标、计划摘要和条目 ID 的确认串。执行前重新校验计划、渲染命令、采集配置并检查漂移；写前记录执行日志，逐条执行后读回验收。结果不明时保留 `uncertain`，不自动重放、回滚或保存配置。成功发布前先持久化独立 `execution-checkpoint.json`；该文件存在时优先按结果不明处理，即使 `execution.json` 可见成功状态。只有执行返回成功、最终文件持久化且检查点删除持久化全部确认，才报告配置回读已验证。

## Go API

```go
observation, err := nxos.ParseConfigChecked(text, true)
// observation.Complete() 只表示证据完整性。

parser := new(nxos.ConfigurationParser)
observation, err = parser.Parse(text, true)
document := parser.Document()
captures := document.CapturesFor("interfaces", "Vlan10")
```

`vendors/nxos.ParseRuntime` 解析运行态；`vendors.NewBuiltinRegistry` 与 `nxos.ProfileSpec` 通过有序 QuerySpec 支持独立实例的型号覆盖。`collect.Collect` 显式接收已选 Profile，通过 opener 借用一段操作会话，opener 持有连接和关闭职责；回调收到与操作生命周期关联的 context。`collect.CollectSession` 借用已打开的独占会话。`Capture.Complete` 表示命令已接受且正文校验通过，完整 Capture 可能与后置错误同时返回；采集保留该维度事实并在 `collection` 记录错误。`adapter/netconnector.Open` 接入 Go connector。

`NewEvidenceDocument` 将原生 Snapshot 与离线 `DecodeDocument` 输出投影到相同的已校验证据；`ProjectRecord` 拒绝循环、非有限数值、不可投影类型，保留精确数字与 null/空容器区别。`Fingerprint` 现在返回 `(string, error)`；无效值没有摘要。`change.NewExecutionPlan` 持有选中条目的原始文件摘要、设备、预期配置摘要和重渲染命令，`ChangePlan` 仍表示独立业务增量。

`review.ReviewFabric`、`review.Recommendations`、`configuration.ServiceCatalog` 和 `change.NewChangePlan` 提供领域能力；变更包含 `svi_acl`、`svi_gateway_add`、`vlan_vni_add` 三类。公开观察对象由调用者持有，可修改；构造、解析和计划访问器复制输入或输出，避免跨调用共享。`ConfigurationParser` 实例不支持并发调用，使用独立实例。

包职责、导入方向和扩展方式见 [架构说明](docs/architecture.md)；公共 Go API 路径调整见 [迁移说明](docs/api-migration.md)。CLI 实现在 `internal/cli`，库消费者直接使用业务包。

## 验证

以下检查使用 `GOWORK=off` 和 `GOFLAGS=-mod=readonly`，Connector/Expect 均从正式版本解析。源码消费者与发行版本的检查范围见 [验证说明](docs/verification.md)。

```sh
GOWORK=off go test -mod=readonly -race ./...
GOWORK=off go vet -mod=readonly ./...
python3 scripts/check-architecture.py
GOWORK=off go mod verify
python3 scripts/check-delivery.py
```

已有 Ruby 金样覆盖 727 个运行态、431 个配置事实、431 个来源元数据及 311 个领域用例。重建方法、实际验证范围和差异见 [验证记录](docs/verification.md) 与 [兼容矩阵](docs/compatibility.md)。
