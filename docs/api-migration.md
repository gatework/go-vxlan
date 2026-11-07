# 2026-11-07：正式依赖与采集回执

本轮固定 `github.com/gatework/go-net-connector v0.2.0` 和 `github.com/gatework/go-expect v0.4.0`，最低版本保持 Go 1.26.0。旧依赖归档及恢复脚本已退役；构建、测试和交付检查统一使用 `GOWORK=off`。历史来源见 [dependencies/README.md](../dependencies/README.md)。

## OpenSession 回调

旧回调 `func(Session) error` 改为 `func(context.Context, Session) error`，不提供旧签名兼容包装。opener 必须同步调用回调且最多调用一次；会话只能在回调期间独占使用。

```go
type OpenSession func(context.Context, func(context.Context, Session) error) error

snapshot, err := vxlan.Collect(ctx, adapter.Open(config), request)
// 检查 err，同时检查 snapshot 的 collection 状态；解析事实与执行结果分别保留。
```

自定义 opener 应把其操作 context 传给回调，而非悄悄换成 Background。`adapter.Open` 传递 connector 的 admitted context，设备 Close 可取消它；采集与 apply 内部使用该 context。没有额外生命周期的测试 opener 可以把传入的 ctx 原样传给回调。

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

错误保留 `Unwrap` 链，调用者可用 `errors.Is` 识别取消、超时。默认格式化仅显示安全代码；底层错误须显式解包。除单一 `CodedError.FailureCode()` 外，采集也识别可选的 `FailureCodes() []string`，保留独立原因并按代码去重。adapter 从公开错误链提取各原因；已分类的 connector 错误作为语义叶处理，不重复分类它的底层原因。

上游 v0.2.0 内部清理错误没有公开分类，独立的未知原因保留为 `command_failed`；只有 opener 明确捕获的关闭失败标为 `session_close_failed`。不通过错误文本或私有类型猜测。即使后续关闭重试成功，首次失败也不会消失。

采集复制回执中的时间值和证据，后续会话复用不改变已返回结果。

## 依赖消费与资源归属

NX-OS profile 由 `vendors.NewBuiltinRegistry().Lookup("cisco_nxos")` 获取；清单使用 `fleet.NewRules` 与同一内置 registry。VXLAN 自身的配置分层、字段、设备筛选和严格主机密钥规则保持不变，不套用上游 CLI 的站点配置迁移。

文件描述符预检由 VXLAN CLI 持有，维持 `128 + 16 × min(parallel, selected)` 的原预算。仅在现有硬限制内提高进程软限制；不足时在建立设备连接前失败。测试在子进程中调整限制，避免污染测试宿主。

交付脚本验证依赖的固定版本与无 replace 状态，隔离副本执行测试、四目标编译和临时安装。外部消费者仅对未发布的 go-vxlan 候选源码使用本地 replace；connector/expect 必须保持正式版本。这是候选源码消费检查，不是 go-vxlan 发布证明。

## 本轮范围

本轮只处理正式依赖和采集链路，apply 仅适配操作 context。报告最终状态发布、apply 执行 module、实时与 JSON 证据结构的进一步整理未包含在本次改动中。Ruby 金样未重新生成；真实设备和历史现场记录不等同于新版实机验收。
