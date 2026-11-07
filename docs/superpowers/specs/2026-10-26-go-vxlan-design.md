# Go VXLAN 功能对齐设计

状态：用户于 2026-10-26 通过 “@Waza 执行方案” 批准实施；实现及验证结果见 ../../verification.md。

## 目标与基线

按用户要求，将 `/Users/wenwu.yan/Works/ruby/vxlan` 当前源码功能实现为独立 Go 库与 CLI。以本次读取的源码和 spec 为裁定依据，README 只辅助导航。参考仓库当前 HEAD 为 `3c7b85529a6639c74c649f754c7feb09e7610621`，读取时 `git status --short` 为空。实施开始时记录相关文件 SHA-256；如果源文件变化，明确更新基线与对齐测试，不静默混合版本。

工程决定（由实施者建议）：路径 `/Users/wenwu.yan/Works/go/go-vxlan`，模块 `github.com/gatework/go-vxlan`，包名 `vxlan`，入口 `cmd/vxlan`。最低 Go 版本建议与 go-net-connector 的 Go 1.26 对齐，Linux/macOS、amd64/arm64。运行时不调用 Ruby；Ruby 仅用于开发期间生成、核对测试预期。

## 对齐范围

| 领域 | 交付与判据 |
| --- | --- |
| 证据模型 | Observation、Snapshot；complete/partial/failed/unsupported/not_requested；诊断、来源与时间；外部数据复制和安全打印，空选择不算完整 |
| 配置解析 | NX-OS interfaces、VRF、VLAN/VNI、NVE、BGP/OSPF、vPC、ACL/地址组、route-map、prefix-list；语法、上下文、冲突排除与引用诊断按原版对齐 |
| 运行态解析 | CDP、NVE peers/VNI、BGP EVPN、OSPF、vPC、接口、port-channel、MAC、L2RIB MAC/MAC-IP，共 11 类，加配置为 12 个维度 |
| 派生与审查 | BGP 模板继承、prefix-list 消费关系、配置关联、业务目录、子网冲突、Fabric 角色与覆盖、ACL/网关/传输差异、建议与阻断条件 |
| 采集 | 固定命令注册表、型号覆盖机制、生命周期入口与借用会话入口；配置先采集、结果按请求顺序；部分事实和关闭失败独立保留 |
| CLI | collect、parse、review、apply；帮助/示例、初始化、配置来源、清单筛选与预览、并发/取消、文本与 JSON 输出、原版退出码 |
| 配置 | CLI > 进程环境 > YAML > .env > 默认；系统/用户/入口/启动目录及显式文件分层；共享与专用 YAML；相对路径按来源；数组替换、严格校验与来源记录 |
| 报告 | summary.txt/json、devices、evidence、可选 scripts、plan.json/校验文件、events.jsonl；私有权限、原子发布、持久化回执、pending 与 report_saved |
| 下发 | 原版 svi_acl、svi_gateway_add、vlan_vni_add 三种变更；计划完整性、单项选择、真实终端确认、配置漂移检查、顺序执行、读回验证及失败记录 |

JSON 字段、状态、诊断代码、null/空数组含义和事实排序尽量逐项兼容；Go API 使用类型化领域对象及小接口，不照搬 Ruby 类继承。任何必要的机器格式差异须在兼容矩阵逐条说明并有测试，不能默认把差异视为等价。运行时间、批次路径等不稳定值允许在差分测试中显式规范化；原始输入指纹须按 Ruby 的算法核对。

## 结构与依赖

核心库处理证据、解析和领域审查，不持有资产源、凭据、文件报告或连接生命周期策略。建议按 `cisco_nxos`、`fabric`、`service`、`changeplan` 职责组织；具体 Go 包边界由实施者根据依赖方向决定，避免循环依赖和转发层。

采集定义最小会话协议，通过适配包复用 `go-net-connector` 的 NX-OS 档案、连接、操作租约、命令回执与取消。借用会话不打开、关闭、提权或重连。CLI 管理静态/Netdisco HTTP/PostgreSQL/缓存清单、凭据、并发、报告与交互。优先复用可访问的公开 API；Ruby VXLAN 与 Go connector 的配置格式不同，不能直接把 connector CLI 配置当作 VXLAN 配置。

当前 Go connector 含本地未发布依赖。实施者负责核查可用版本与公开 API；本地开发可用隔离 go.work 或冻结依赖快照，并记录来源和验证方式。不得改写 sibling 工作区或把占位版本声称为可公共安装。最终验证包含隔离 consumer 构建，明确依赖发布状况。

## 关键语义

- 完整传输是完整解析的必要条件，未知语法、冲突、缺引用、分页和终端控制仍须保留 partial；不得以丢弃行获得 complete。
- 完整证据不等于网络健康；缺数据不当作一致，无部署范围不推测角色。
- 报告故障、输出故障、取消和关闭故障不得掩盖已得到的证据，也不得误报成功。
- apply 只接受原版允许的、有校验的聚合计划与单项 ID；不自动重放结果不明的写入，不新增自动回滚行为。
- 原始事实仅在显式 JSON/私有证据输出中导出；常规日志与对象格式化不泄露凭据或原始回显。

## 验证与交付

先建立 Ruby public API、命令参数、配置字段、报告 schema、诊断代码和 spec 场景的对应矩阵，再实施。移植合成或已脱敏 fixture；使用 Ruby 生成规范化金样，并对 Go 做语义差分。覆盖成功、空表证据、未知/畸形输入、重复身份、跨行记录、控制符、配置上下文、ACL 依赖、Fabric 缺证据和阻断条件。

采集、报告和 apply 用注入会话、本地假设备/PTY、临时目录以及 HTTP 服务测试，验证失败和取消清理、会话所有权、命令顺序、权限与持久化失败。Go 测试、race、vet、CLI 构建、最低工具链和隔离消费构建必须有可复查结果。跨平台编译与实际平台运行分开记录。

交付包含源码、测试、CLI、中文使用说明、兼容矩阵、可重复对齐脚本及验证记录。未对齐项必须标明，不能用占位实现或一律 unsupported 声称完成。功能按核心解析→领域审查→采集/CLI→报告/apply 顺序实施，但目标是完整范围，不把阶段一冒充最终交付。

本次实现与验证不自动连接生产设备或实际下发；真实 NX-OS 互通另记实测范围。保留现有工作区修改，不自动提交、推送或发布。
