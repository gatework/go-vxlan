# 历史依赖来源

2026-10-26 从本机 `go-net-connector` 工作区冻结源码。其 HEAD 为 `4f3774de892f1907531e48117d2eba4a413f02fc`，含未提交修改，因而 HEAD **不能**独立复现本次依赖；以 `manifest.json` 的归档及逐文件 SHA256 为准。`go-expect` 来源为该工程 `.work/go-expect` 的现有源码快照。

原归档只包含构建/测试源码、go.mod/go.sum、许可证与合成测试资料，不包含 bin、备份报告、环境文件或设备凭据。原始工作区未修改。

2026-11-07 起，构建直接使用 `go-net-connector v0.2.0` 和 `go-expect v0.4.0`。旧源码归档、workspace 恢复脚本及其专用测试已退役；本目录的 `manifest.json` 仅保留历史归档和逐文件 SHA256，不参与构建，也不能单独恢复旧快照。已有本地 `.work/` 数据不删除。

| 历史归档 | SHA256 |
| --- | --- |
| go-net-connector-source.tar.gz | `86e6134eea6b9796fb5987690af93d8975a2a2281cf8a8d626759f317b89b26a` |
| go-expect-source.tar.gz | `ffce729a2b0dc33ad68d2330a7899ac2cf5409d41afb55e2328b261608937bac` |

当前职责深化候选的 go.mod 下限已升为 connector v0.3.0，新增共享 Fetch API 及 InventoryEnvironment/ValidateInventory 尚待正式发布；本轮在授权 go.work 联合验证。发布后更新正式版本，再执行下述独立交付门禁，详见 [迁移说明](../docs/api-migration.md)。

所有独立交付检查设置 `GOWORK=off`；connector/expect 不允许本地 replace。go-vxlan 本身尚未发布时，外部消费者只替换这份候选源码，该结果不等同于已发布模块的安装验证。见 `scripts/check-delivery.py`。

构建常规公开第三方模块时 Go 可能需要网络访问。Ruby 及其依赖只用于开发期金样生成，不参与构建和执行。

历史实机验证补丁曾在冻结快照的 `connector/terminal_text.go` 公开 `RenderTerminalText`，仅转调已有严格终端渲染器。当前通过正式版本的 `Response.Rendered()` 获取校验过的可见正文，不再依赖该快照补丁。
