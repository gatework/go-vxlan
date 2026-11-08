# Ruby / Go 兼容矩阵

基线为 Ruby VXLAN `3c7b85529a6639c74c649f754c7feb09e7610621`。102 个 lib/spec 文件的 SHA256 见 `ruby-baseline.json`。本实现按公开行为移植，Go API 不模拟 Ruby 常量、类继承或 Gem 加载方式。

| Ruby 能力 | Go 对应 | 验证 |
| --- | --- | --- |
| Observation / Snapshot | `NewObservation`、`Observation`、`Snapshot` | 状态、空集完整性、复制边界、安全格式化 |
| Config / ShowRunningConfig | `nxos.ParseConfigChecked`、`nxos.ConfigurationParser.Parse` | 431 条 Ruby 事实金样；原文 digest、冲突身份排除、未知语法和引用诊断 |
| cursor/source document | `ConfigurationDocument`、`SourceLine`、`SourceBlock`、`SourceCapture` | 431 条来源金样；原文、逐行状态、块范围、路径、捕获事实、CRLF/CR；1293 次独立变体差分 |
| RuntimeParser / NXOS profile | `nxos.ParseRuntime`、`Profile.Queries`、`parser.Registry` | 11 类、727 条金样；5816 次独立运行态变体差分；型号覆盖、注册表独立复制 |
| BGPNeighbors / PrefixListReferences / AclPolicy | `BGPNeighbors`、`PrefixListReferences`、`ACLRules`、`ResolveACLPolicy`、`ACLBindings` | 继承、引用、规则与依赖事实 |
| Service / SubnetIndex | `ServiceCatalog`、`EffectiveNVEMember`、`ServiceRouteTargets`、`ServiceTenant`、`InferServiceMapping`、`NewSubnetIndex` | 映射歧义、租户、路由目标、前缀重叠；增长测试 |
| Fabric scope/review | `ValidateFabricPolicy`、`ReviewFabric` | 明确部署范围、缺失事实、角色阻断、业务/ACL/网关/传输诊断 |
| Recommendations | `Recommendations`、`CombineRecommendations` | 分类、阻断、候选条件及修复关联 |
| ChangePlan | `NewChangePlan`、`CandidateChangePlan`；`Eligible`、`Satisfied` | 三种动作、命令/条件回退、漂移和读回条件；领域合计 311 金样 |
| Collector | `collect.Collect`、`collect.CollectSession`、`netconnector.Open` | 配置优先；明确传输回执；准备命令；空表证据；独立失败；关闭失败；不重连重放 |
| collect | `cmd/vxlan` / `internal/cli` | 静态/动态清单、过滤、预览、并发、取消、逐设备发布、摘要；本地 HTTP 测试 |
| parse | `vxlan parse` | file/stdin、维度、model、complete、JSON；非法维度先拒绝；中断 stdin |
| review | `vxlan review` | 离线 evidence 输入、Fabric policy、可选 scripts、schema 2 聚合计划、schema 3 review 摘要、事件 |
| apply | `vxlan apply` | checksum、单项、真实终端、确认、重新渲染、漂移、顺序写入、写前日志、读回、结果不明；假会话与真实 PTY 取消测试 |
| 配置 / Report | `internal/bootstrap.Load` / `report.Report` | 分层、来源路径、严格 YAML、私有权限、原子替换/持久化失败、未完成检查点与恢复 |

公共能力已按 [架构说明](architecture.md) 分包；完整路径映射见 [API 迁移](api-migration.md)。CLI wire schema 保持，Go 根包只保留证据与结构验证。

## 机器格式和必要差异

- 配置与运行事实的字段、诊断代码、状态、空值及数组，按金样语义比较；JSON 对象成员顺序和空白排版不作为协议。采集摘要保留 Ruby 的 `duration_ms`、去重诊断代码数组、按 host 排序的设备结果；成功结果省略 `error`。实时耗时、时间和批次目录自然不同。
- CLI 证据/计划读取比 Ruby 默认 JSON 读取更严格：重复键（包括转义后同名的键）、非法 UTF-8、非对象根值、多余 JSON 文档和超过 128 层的嵌套会被拒绝。不会用后出现的状态或版本字段覆盖前值。数字解码不经过 float64 中转；int64 范围的整数供领域逻辑使用，更大整数和非整数保留 `json.Number` 原始数值表示。可精确表示为 int64 的整数值小数/指数形式规范化为整数；大数计数不丢精度。
- Go 的 `map` 不记录插入顺序。直接消费外部 map 的派生接口按键排序，因此 `Recommendations` 的维度建议、`BGPNeighbors`、`PrefixListReferences` 的结果数组可能与 Ruby 的插入顺序不同。例如 Ruby 输入维度顺序 `vpc, configuration`，Go 建议顺序是 `configuration, vpc`。配置解析内部另存原文顺序，金样中的配置事实/诊断顺序保持一致。该差异有 `TestDocumentedGoContracts` 固定。
- `Fingerprint` 返回 `(string, error)`，无效值返回错误和空摘要；面向 JSON 配置事实，键排序、Unicode 和转义按当前配置金样核对。Go 将数学值相同的整数和整数值浮点数（`1` / `1.0`）规范化为同一 JSON 数值，保证 JSON 解码前后配置指纹稳定；Ruby 任意用户数据中的 `1.0` 与 `1` 可产生不同指纹。不要用它宣称任意 Ruby 对象的浮点类型身份兼容。设备配置中的语义数字为整数；对应指纹金样通过。
- Observation/Snapshot 是可修改的 Go 值，并非 Ruby 的冻结对象。构造器与解析结果拥有独立数据，调用方修改本对象会改变本对象；不保证并发修改安全。计划和来源文档的访问器返回独立副本或不可变值。来源文档默认格式化/JSON 只给元数据，原文须显式 `Content()`、`Raw()` 等访问。
- `nxos.ParseConfigChecked`、`nxos.ConfigurationParser.Parse` 和 CLI 拒绝非法 UTF-8/NUL，与 Ruby 严格入口一致。便利函数 `ParseConfig` 不返回 Go error，非法输入以 partial 诊断表达；需要严格校验时使用 Checked 入口。
- 时间为 Go `time.Time` 的 RFC3339 JSON；不会逐字复制 Ruby 时间精度。Go API 不提供 Ruby 的符号键：数字映射键用十进制字符串，源捕获数组下标为 int。
- 文本帮助、进度和 summary/device 可读报告采用简洁中文，排版不逐字复制 Ruby；自动化使用 JSON。错误保留安全代码，底层 Ruby 异常类名称不会跨语言复制。
- Netdisco 接入原生 Go connector。HTTP/PostgreSQL 与缓存模式均已接线；缓存是 Go connector 私有格式/身份，不读取 Ruby 缓存文件。复用配置中的公开 `netdisco`/`inventory` 字段和 `ND_*`/筛选环境变量，包括自定义 `device_rules`；Ruby YAML 中非当前 connector schema 的字段明确拒绝。不要跨实现共用缓存目录。
- 信号取消统一退出 130，确认输入期间同样有效。对于库中注入的任意 `io.Reader`，取消会立即返回，但调用者应在释放 App 时解除其阻塞读取；App 不关闭调用者持有的输入流。
- `go.mod` 固定正式 `go-net-connector v0.4.0` / `go-expect v0.4.1`，包含共享 Netdisco Fetch API。构建和独立交付检查使用 `GOWORK=off`；源码消费者与已发布标签消费者分别验证，见 [验证说明](verification.md)。
- 已接受且正文校验通过的命令，遇到后续回调、日志或取消错误仍保留维度解析结果；`collection` 单独记录错误并保持非成功。没有可验证正文时，该维度仍为 failed，仅保留回执元数据；设备拒绝或未完成原文不会作为配置事实解析。原始回执指纹来自 wire 字节，分页与编码转换不改变该指纹的输入；新增尝试进度字段不替换现有证据字段。具体 Go interface 变更见 [迁移说明](api-migration.md)。

## 验证边界

金样与差分是已覆盖输入的证据，不是 NX-OS 全语法证明。2026-10-26 曾对 6 台真实 NX-OS 完成 SSH 只读采集，并与 Ruby 驱动/Collector 回放比对；该历史结果不能外推为新版实机验收。v0.2.0 的远程 CI、公开发布与正式版本消费者已验证，记录见 [验证说明](verification.md)。真实 PostgreSQL、生产配置写入、业务连通性与部署不在本次证据内。apply 测试使用合成会话或本地 PTY，没有下发生产配置。
