# 公共 API 迁移

这是用户批准的公共 Go API 调整，不保留旧根包/公开 cli 的转发层。CLI 参数、默认值、JSON/schema、确认串与正常设备命令顺序保持不变；取消或输出失败发生在最终回调时，批次摘要会重新写为 interrupted/incomplete，修复原来返回状态与已发布摘要不一致的问题。包职责与依赖图见 [architecture.md](architecture.md)。

| 原入口 | 新入口 |
| --- | --- |
| 根包 `ParseConfigChecked` / `ConfigurationParser` / 来源文档类型 / `ParseRuntime` | `vendors/nxos` 同名入口 |
| 根包 `ParserRegistry` / `NewParserRegistry` | `parser.Registry` / `parser.NewRegistry` |
| 根包 `DefaultParserRegistry` / `NXOSProfileSpec` | `vendors.NewBuiltinRegistry` / `nxos.ProfileSpec` |
| 根包 `ProfileSpec.Commands/Parsers` | 有序 `ProfileSpec.Queries []parser.QuerySpec`；维度/命令/解析器在同一声明内 |
| `ModelParsers[model][command]` | `ModelParsers[model][dimension]`；只能覆盖已有维度 |
| 根包 `Collect` / `CollectSession` / Capture/Session/OpenSession/Request | `collect` 同名入口；Request 显式传入已选 `Profile` |
| `adapter.Open` | `adapter/netconnector.Open` |
| 根包 ACL/SubnetIndex/ServiceCatalog/BGP/PrefixList 关系 | `configuration` 同名入口；`ConfigReview` 改为 `configuration.Review` |
| 根包 Fabric review、recommendations、`InferServiceMapping` | `review`；ReviewFabric/Recommendations/Advice 显式接收 QueryCatalog（通常为选定 Profile） |
| 根包 ChangePlan/ExecutionPlan | `change` 同名入口 |
| 公开 `cli` | 已删除；终端入口是 `cmd/vxlan`，库消费者使用业务包 |
| CLI Report | 公共 `report`；Publish、PublishJSON、Finish、ReadSources 接收 ctx 首参 |
| `internal/apply` | `internal/workflow/apply`；不属于外部导入面 |

```go
profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", model)
if err != nil { return err }
snapshot, err := collect.Collect(ctx, netconnector.Open(connection), collect.Request{
    Target: device, Profile: profile, Dimensions: []string{"configuration", "nve_peers"},
})
// 同时检查 err 与 snapshot.Dimensions["collection"]；不要仅按传输完成推断网络健康。
```

自定义平台通过 `parser.ProfileSpec{Queries: []parser.QuerySpec{{Dimension: "...", Command: "...", Parse: fn}}}` 声明。Registry 不导入任何 vendor，构造时验证查询及型号覆盖并复制输入。准备命令的控制字符限制与查询一致。review 从所选 profile 取得验证命令，不再维护平行表。

## Fabric 验证查询

`ReviewFabric(documents, policy)` 改为 `ReviewFabric(documents, policy, queries)`。`QueryCatalog` 除 `Command(dimension) string` 外，新增 `VerificationCommands(scope string) []string`。直接传入已选 `parser.Profile` 即可；自定义目录需实现两项能力。

`ProfileSpec.Verification map[string][]string` 按业务用途声明核查序列，`fabric` 用于跨设备核查。NX-OS 保持 `show running-config`、`show nve vni`、`show ip interface brief vrf all` 的既有顺序与内容；最后一条不等同于采集维度 `interfaces` 的 `show interface brief`。这些命令仅进入建议和计划的 verify，不改变默认采集维度或执行许可。Registry 校验非空用途、序列和命令，拒绝控制字符；构造、选取和访问器都复制序列。

未传目录或所选 Profile 未声明 `fabric` 时，诊断与证据仍返回，相关建议保持 blocked 并说明缺少核查定义；不生成 commands、rollback 或 change。已满足其余前提的候选也不能越过该限制。工作流把同一选定 Profile 同时传入设备与 Fabric 审查。

CLI 的 bootstrap 复用 Connector `config.InventoryEnvironment(values, higher)` 与 `config.ValidateInventory(document)`，仅处理共享 netdisco/inventory 部分；高优先级的 false/null/空集合仍屏蔽低优先级环境变量。应用配置、分层及相对路径规则不变。

配置文件与 `.env` 现在经过共享 `config.ReadFile`，使用 caller context、16 MiB 上限和普通文件检查；可读符号链接仍允许，FIFO 无需等待写入方即拒绝。YAML 改用共享 `ParseYAMLMapping`，保留空/根 null 拒绝、显式 `{}` 允许的应用规则，同时增加共享解析预算。配置优先级、相对路径及显式缺失处理保持原样。内部 `bootstrap.Load`、`ReadYAML` 改为 ctx 首参；CLI 帮助路径仍不读取配置。

加载后的公开配置数据是诊断快照，运行设置不再从这些可变映射回读。要改变库存来源、筛选、凭据或 Fabric policy，应重新加载配置。静态库存的返回设备行也为独立副本。计划和报告证据 JSON 不采用配置文件的大小上限。

v0.3.0 采用正式 Connector v0.5.0、Expect v0.4.2，其中包含本轮使用的回执与配置读取 API。默认构建不使用 workspace 或 replace；固定版本交付门禁同步检查这两个版本。发布前的 workspace/本地模块代理结果仅是候选证据，正式验收还需独立构建、同提交 CI、发行附件和标签消费者。当前检查见 [验证说明](verification.md)。

## 证据、执行绑定与共享清单

最低版本保持 Go 1.26.0，CLI 参数、配置字段、确认串、计划/报告 schema 和设备命令顺序保持兼容。以下契约由公开业务包提供，共享 Netdisco 采集使用已发布 Connector API。

## Checked evidence 与 Fingerprint

原来 `Fingerprint(value) string` 改为 `Fingerprint(value) (string, error)`。每个调用者都必须处理错误；无效对象不再得到空字节摘要。循环、非有限浮点数、非法 UTF-8、非法 json.Number、任意不可投影 struct/pointer、函数、通道等均被拒绝。

```go
digest, err := vxlan.Fingerprint(configuration)
if err != nil {
    return err
}
// 只有成功的 digest 才可绑定计划。
```

`ProjectRecord(value) (Record, error)` 显式投影 Snapshot、Observation、time.Time、字符串键映射、数组和切片及 JSON 标量，返回独立数据；不调用自定义 JSON marshaler。`NewEvidenceDocument(value)` 在投影后验证设备身份、观测与配置结构。实时采集和离线审查都使用它；离线入口先经 `DecodeDocument`，拒绝重复键、非法 UTF-8、多文档和过深嵌套。

int64 范围整数保持精确，更大数字和小数保留 json.Number，不经 float64 中转。整数值的小数/指数形式规范化为 int64；有效配置的既有摘要金样保持通过。nil 容器和非 nil 空容器分别投影为 null、空数组/对象；NewObservation 的顶层 records/issues/evidence 仍按原有协议规范为数组，嵌套空值保留。原生观察值仍可修改，构造器复制输入；调用方不能并发修改参与投影的数据。

`NewSubnetIndex` 保留原有返回类型；不合法证据产生的构建错误由 `Conflicts` 返回，不能被当成无冲突。已有子网索引、VLAN/VNI 反向索引和业务增量逻辑继续使用。

## ExecutionPlan 与 apply

`ChangePlan` 继续表示 `svi_acl`、`svi_gateway_add` 或 `vlan_vni_add` 业务增量。新增 `NewExecutionPlan(rawPlanJSON, itemID)` 绑定精确文件字节的 SHA256、规范设备地址、预期配置 SHA256、选中条目和由 ChangePlan 重渲染的 commands/rollback；保存独立副本，访问器也返回副本。构造前验证独立 checksum，构造后使用 `ConfirmationToken()` 确认，再打开会话。零值或 nil ExecutionPlan 不能执行；读取访问器应先成功构造。

`CheckBefore` 同时验证完整结构、预期摘要和前提；公开 `CheckAfter(before, after)` 也重新验证 before 的绑定，再验证目标状态和其余配置保持不变。不能用另一份 before 绕过审批绑定。

CLI 只负责参数、文件、真实终端确认、凭据和展示。`internal/workflow/apply` 通过小型 Session、Opener 和 Journal 能力执行一项已确认计划：单次借用，写前持久化 intent，接受回执后记 ack，最后回读。opener 忽略 callback 错误、重复调用或提前返回都不能抹去失败或让已进入的 callback 越过最终发布。

内部执行状态改为私有类型化结构；Journal 每次收到独立 Record，Result.State 也不与日志数据共享可变容器。执行 JSON 字段、步骤顺序、pending/error/observed 摘要的省略规则保持不变；初始 steps 仍为 `[]`。日志的 `PublicationCommitted`、accepted 后错误和 finalization 失败处理保持原协议。

intent rename 已提交但目录同步失败时状态为 uncertain；不发送该命令。每次发送前后检查操作与父 context，取消后只进行必要的日志收尾。不会自动重放、重连、回退或保存配置。已接受正文与后置 error 的采集契约保留；apply 读取同时收到 error 时停止，不能用该正文授权下一条写入。

## 最终日志与存储失效

Report 发布错误现在保留 Unwrap 原因和 committed 属性，默认文本仍为安全诊断。最终 configuration_verified 发布前，先持久化独立 `execution-checkpoint.json`，状态为 uncertain。最终文件的写入、rename、目录同步以及检查点删除后的目录同步全部成功，才返回成功。任何失败都会尝试恢复 uncertain；恢复失败再撤销最终文件，并保留所有独立错误。

读取规则：`execution-checkpoint.json` 存在时优先视为 uncertain；不能只看可见 execution.json 的成功字段。若介质同时拒绝覆盖、撤销，或检查点删除同步失败后又拒绝重建，磁盘上的文件可能不足以证明结果，执行 API 的失败和终端警告仍为权威，不得宣称成功或重放。报告 schema 没有添加字段；独立检查点是恢复协议的新增文件。

## Netdisco 缓存迁移

清单改用 connector 的 `FetchHTTP`/`FetchPostgres` + `FetchOptions`/`CachePolicy`；完整 CacheResult 保留来源、时间、刷新错误和缓存写入错误，VXLAN 仅做本地配置映射及 NX-OS 设备筛选。`cache_namespace` / `ND_CACHE_NAMESPACE` 原来被忽略，现传给共享身份策略，这是单独的行为修复。

新身份包含有效来源、账号/namespace、查询形态和 page_size，不再由 CLI 拼装含原始 API key 的身份 JSON。显式 namespace 可支持同一账号的 key 轮换。新身份不静默重标或借用旧缓存：prefer/refresh 重新采集；only 无法验证条目时提示先刷新，不连接设备或静默联网。字段、配置优先级和 CLI 退出码不变。

## 原生连接器与采集回执

构建、测试和交付检查统一使用 `GOWORK=off`。旧依赖归档及恢复脚本已移除，历史实现可从 v0.1.0 标签查询。

## OpenSession 回调

旧回调 `func(Session) error` 改为 `func(context.Context, Session) error`，不提供旧签名兼容包装。opener 必须同步调用回调且最多调用一次；会话只能在回调期间独占使用。

```go
type OpenSession func(context.Context, func(context.Context, Session) error) error

snapshot, err := collect.Collect(ctx, netconnector.Open(config), request)
// 检查 err，同时检查 snapshot 的 collection 状态；解析事实与执行结果分别保留。
```

自定义 opener 应把其操作 context 传给回调，而非悄悄换成 Background。`netconnector.Open` 传递 connector 的 admitted context，设备 Close 可取消它；采集与 apply 内部使用该 context。没有额外生命周期的测试 opener 可以把传入的 ctx 原样传给回调。

`CollectSession(ctx, session, request)` 仍只借用会话，不打开、关闭、提权或重连。命令不会自动重放。opener 继续拥有连接和关闭职责。

## Capture 与 error 必须一起处理

`Session.Read` 的返回类型不变。`Capture.Complete` 表示命令已接受且可见正文校验通过，不代表所有回调、日志或清理都成功。

| 回执事实 | 采集行为 |
| --- | --- |
| 已接受，正文校验通过，无后置错误 | 使用正文解析；解析器仍可判 partial |
| 已接受，正文校验通过，但后置处理报错 | 保留维度解析事实；collection 记录错误，整体不为 complete |
| 超时、断流、设备拒绝或文本不可验证 | 不把原文当作配置；维度 failed，保留已收到的安全元数据 |
| 会话不可用或操作 context 已取消 | 后续维度标记跳过，不重放、不重连 |
| 关闭失败 | 追加独立关闭诊断，不覆盖之前的事实或错误 |

完整传输只是完整解析的必要条件。完整证据也不代表网络健康；CLI 的退出码约定不变。

adapter 从 `Response.Raw()` 计算 `sha256` 和 `bytes`，不使用已解码、可能去除分页标记的 `JoinedOutput()`。回执元数据保留命令、指纹、字节数、时间及尝试进度；不存储原文或敏感 hook 命令。未完成响应即便有 `Raw()`，也不能绕过 `Rendered()`/`Prompt()` 的验证重新解码为正文。

adapter 改用 Connector `Result.SingleAccepted(command)` 与 `StepResult.Body()`，执行 error 仍须独立检查。Body 只去掉已确认 prompt 和首行匹配 echo；VXLAN 在此基础上继续去掉 prompt 自带的前导换行，保持既有 Capture 正文及指纹输入。其余空行、缩进和正文中的重复命令行保留，不对正文整体 TrimSpace。hook 的原始 Attempts 证据与 accepted Capture、后置错误继续共存。

错误保留 `Unwrap` 链，调用者可用 `errors.Is` 识别取消、超时。默认格式化仅显示安全代码；底层错误须显式解包。除单一 `CodedError.FailureCode()` 外，采集也识别可选的 `FailureCodes() []string`，保留独立原因并按代码去重。adapter 从公开错误链提取各原因；已分类的 connector 错误作为语义叶处理，不重复分类它的底层原因。

没有公开分类的独立原因保留为 `command_failed`；只有 opener 明确捕获的关闭失败标为 `session_close_failed`。不通过错误文本或私有类型猜测。即使后续关闭重试成功，首次失败也不会消失。

采集复制回执中的时间值和证据，后续会话复用不改变已返回结果。

## 依赖消费与资源归属

解析 profile 由 VXLAN 的 `vendors.NewBuiltinRegistry().Fetch("cisco_nxos", model)` 获取；设备连接使用 Connector 内建 registry 的 NX-OS 方言，清单复用其 `fleet.NewRules`。VXLAN 自身的配置分层、字段、设备筛选和严格主机密钥规则保持不变，不套用上游 CLI 的站点配置迁移。

文件描述符预检由 VXLAN CLI 持有，维持 `128 + 16 × min(parallel, selected)` 的原预算。仅在现有硬限制内提高进程软限制；不足时在建立设备连接前失败。测试在子进程中调整限制，避免污染测试宿主。

交付脚本验证依赖的固定版本与无 replace 状态，隔离副本执行测试、四目标编译和临时安装。外部消费者仅对未发布的 go-vxlan 候选源码使用本地 replace；connector/expect 必须保持正式版本。这是候选源码消费检查，不是 go-vxlan 发布证明。

Ruby 金样与实测边界见 [兼容矩阵](compatibility.md) 和 [验证说明](verification.md)。

## v0.3.1 依赖更新

采用正式 Connector v0.6.0、Expect v0.5.0。Netdisco 缓存模式在内部调用边界转换为 `netdisco.CacheMode`；配置中的 prefer、refresh、only 取值不变。公开 VXLAN API 与设备命令不变。
