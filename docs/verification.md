# 验证记录

## 2026-11-07 v0.2.0 正式依赖采纳

用户在组织重构验收后授权发布。Connector v0.4.0 和 Expect v0.4.1 已完成各自同提交 CI、发布附件核验及全新缓存、无替换的正式消费者检查；本模块已固定这两个版本。此前共享 API 未发布的阻塞已解除，下文候选状态保留为历史记录。

更新依赖后，在 `GOWORK=off` 下通过全包 race/shuffle、vet、govulncheck，以及完整 `scripts/check-delivery.py`（架构边界、模块 verify/tidy、隔离源码全包测试、四平台构建、公开业务包消费者及仓库外安装后 CLI）。本脚本的本模块消费者仍是源码候选检查；正式 v0.2.0 发布后另用全新缓存、无任何 replace 的消费者验证标签。

日志与后续 CI/artifact/release 账本保存于 sibling `release-20261107-164506/`。发行只能复用本提交成功 CI 的不可变制品；此准备记录不预先声明 VXLAN 已发布，也不代表新增真实设备验证或部署。

## 2026-11-07 组织重构：最终本地验证

本节对应 `organization-20261107-155459` 阶段；此前证据/生命周期修复已保留。日志根目录是任务 worktree 的同级 `organization-20261107-155459/`。未提交、推送或发布，没有真实设备、生产清单或远程 CI 验收。

| 检查 | 结果与日志 |
| --- | --- |
| 有序 QuerySpec、迁移后的所有包、Ruby 事实/来源/业务金样 | 全量 `go test ./...` 通过；金样未重新生成 |
| Go 1.27.3 全量 race + shuffle，`-count=1 -timeout=180s` | 通过；`vxlan-organization-race.log` |
| 最终回调取消/写入失败修复后的 workflow/apply/report/CLI race | 通过；`vxlan-organization-finalization-race.log`；四种模式核对返回和持久化摘要指纹相等、采集/输出各一次、证据保留 |
| Go 1.26.0 全量测试 | 通过；`vxlan-organization-go126.log`；后续最终回调变更另见 `vxlan-organization-go126-finalization.log` |
| typed Settings 抽取后的 bootstrap/CLI race 与 Go 1.26.0 | 通过；`vxlan-organization-settings-race.log` / `vxlan-organization-go126-settings.log`；gopls 无诊断，`vxlan-organization-settings-gopls.log` |
| 最终 `go vet ./...` | 通过；`vxlan-organization-vet.log` |
| gopls 关键边界检查 | 无诊断；`vxlan-organization-gopls.log` |
| 生产导入方向门禁 | 通过；`vxlan-organization-architecture.log`，已接入 CI 与 check-delivery |
| GOWORK=off mod verify / tidy -diff | 通过；`vxlan-organization-modules.log` / `vxlan-organization-tidy.log`；Cobra v1.10.2 固定依赖，无本地 replace |
| 离线 release/reuse 脚本 | 两组各 14 项通过；`vxlan-organization-release-tests.log` |
| 冻结重构前二进制的 40 个离线 CLI 场景 | 退出码和 JSON 比较通过；`cli-compare-vxlan.json`、空 `cli-mismatches-vxlan.json`；最终联合检查另由四模块集成流程记录 |
| 未配置项目规则的默认 golangci-lint | **未通过，继承的 lint 债务**；冻结基线默认 49 项，候选 48 项（相同 43 个 errcheck、5 个 staticcheck，移除 1 个未使用 helper）。展开数量限制后基线 74、候选 71；两处 help 源码仅改为 profile 维度查询，未增加诊断种类。日志 `vxlan-baseline-lint.log` / `vxlan-final-lint.log`，展开比较见 `vxlan-before-default-lint.log` / `vxlan-organization-default-lint.log` / `vxlan-lint-comparison.json`；没有新增 broad exclusion |
| GOWORK=off check-delivery | **发布前阻断继续保留**；`vxlan-organization-standalone-blocked.log`。正式 connector v0.3.0 缺少 InventoryEnvironment/ValidateInventory 与新增 Fetch/cache API，隔离副本编译失败；未改用 workspace 或弱化消费者门禁 |

公共 Go API 按 [迁移表](api-migration.md) 调整；机器 schema、精确整数/null/空容器、指纹、命令顺序和执行 no-replay/uncertain 检查保持。上下文回归另覆盖取消后已接受证据落盘，以及离线 review/读取/发布在已取消 context 下不产生成功报告。最终通知/结果输出之后的取消与错误现在会使持久化摘要和返回值一致，这是明确修复的生命周期行为。

独立发布、正式依赖归档和外部安装门禁需要先发布共享 Connector API 并更新版本；本节 workspace 成功不能替代那些证据。

## 前一阶段：2026-11-07 四仓库职责深化

在专属 `network-modules-20261107-075052/go-vxlan` worktree 实施，原工作树保持不变。没有提交、推送、发布或访问真实设备。当前依赖下限为 connector v0.3.0 / expect v0.4.0；新增共享 Fetch 接口来自明确授权的四仓库 go.work。除独立模块检查外，以下 Go 检查使用该 workspace、`GOFLAGS=-mod=readonly`，并非已发布依赖的消费者证明。

| 检查 | 本轮结果与任务日志 |
| --- | --- |
| Go 1.26.0 全量 `go test -race -count=1 -timeout=180s ./...` | 通过；root 25.374s、adapter 6.765s、cli 11.699s、internal/apply 6.457s；`TASK/logs/vxlan-go126-race.log` |
| Go 1.26.0 `go vet ./...` | 通过；`vxlan-go126-vet.log` |
| 最后将配置读取 capability 移入 adapter 后，Go 1.26.0 adapter/cli/internal/apply race | 通过；`vxlan-go126-final-adapter.log` |
| Go 1.27.3 gopls check | checked evidence、execution plan、executor、journal、inventory、review 及最终 adapter/CLI 装配无诊断；`vxlan-gopls.log` |
| Go 1.27.3 govulncheck | `No vulnerabilities found.`；`vxlan-govulncheck.log` |
| GOWORK=off `go mod verify` / `go mod tidy -diff` | 通过；`vxlan-module-check.log` |
| 离线 release/reuse 脚本测试 | 两组各 14 项通过；`vxlan-release-script-tests-retry.log`。首次并行工具链构建期间 reuse 一项触发自身 10 秒 timeout，原始失败保留在 `vxlan-release-script-tests.log`，串行复核通过 |
| Go 1.27.3 workspace Linux/macOS × amd64/arm64 CGO=0 编译，macOS arm64 CLI version/help/parse smoke | 通过；`vxlan-workspace-builds.log`，本地二进制位于 TASK/artifacts；这不是正式依赖归档验证 |
| `python3 scripts/check-delivery.py`，GOWORK=off | **未通过，预期的发布前阻断**：已发布 connector v0.3.0 尚无 FetchHTTP/FetchPostgres/FetchOptions/CachePolicy/ErrCacheRefreshRequired。隔离源码阶段编译失败；`vxlan-standalone-delivery-blocked.log`。脚本没有弱化，须在共享接口正式发布、更新依赖后重跑消费者、四目标正式打包与安装门禁 |

本轮回归覆盖精确大数/小数、null 与空容器、循环与共享 slice 视图、不可投影值、计划访问器所有权、原始文件与 before 配置绑定、命令重渲染、committed intent、取消前后的发送/ack 边界、被 opener 忽略的 callback 错误、重复/缺失/提前返回的 callback、独立清理失败、最终发布/恢复/撤销失败，以及检查点删除同步失败后的连锁存储故障。既有 Ruby 金样和索引分配增长断言全部保留。

adapter 的借用操作测试使用真实 connector 命令引擎加 net.Pipe；accepted Body 与后置 hook/清理 error 同时保留，配置 capability 不把带 error 的正文用于授权后续写入。共享缓存测试使用本地 httptest，覆盖 namespace 的 key 轮换、only 拒绝新身份和 prefer 重新采集。没有真设备、真实 PostgreSQL、生产配置变更、远程 CI 或发布证据。

新增接口、缓存迁移例外与检查点的判定优先级见 [迁移说明](api-migration.md)。下方先前验证与实机数据仅保留历史，不可用来替代当前候选的发布或设备验收。

## 先前验证：2026-11-07 正式依赖与采集回执

环境：macOS arm64。最低 Go 版本仍为 1.26.0；正式依赖为 `go-net-connector v0.2.0`、`go-expect v0.4.0`，无本地依赖 replace。源码在独立副本中修改和验证，未提交、推送或发布。

升级前的 adapter 与冻结 workspace API 已不一致，全包测试和 vet 无法编译；本轮迁移到正式版本后通过以下检查。所有 Go 检查使用 `GOWORK=off`、`GOFLAGS=-mod=readonly`，不会借用旧 `.work/` 或 sibling 工程。

| 检查 | 本轮结果 |
| --- | --- |
| Go 1.27.3 `go test -race -count=1 ./...` | 通过；root 17.491s、adapter 1.482s、cli 5.913s |
| Go 1.27.3 `go vet ./...` | 通过 |
| Go 1.26.0 / 1.26.10 `go test -count=1 ./...` | 两个版本全包通过 |
| Go 1.27.3 `govulncheck ./...`，工具 v1.9.0 | `No vulnerabilities found.` |
| `go mod verify`、`go mod tidy -diff` | 通过，固定依赖无 replace |
| `python3 scripts/check-delivery.py` | 隔离源码测试、Linux/macOS × amd64/arm64 四目标 CGO=0 编译、外部消费者、临时安装后 version/parse 全部通过 |
| Go 1.27.3 `go fix -diff ./adapter` | 无剩余修改建议；改动 Go 文件通过 gofmt 检查 |
| 独立源码审阅 | 已修复首次内部清理错误遗漏、内层 callback 错误覆盖 connector 分类两处发现，复查无阻断问题 |

回归通过真实 connector 引擎与本地 `net.Pipe` 传输，覆盖超时、断流、设备拒绝、非法编码、分页/GBK 原始指纹、后置 hook 与取消。已接受正文保留为维度事实，执行错误独立写入 collection；未验证原文不会进入解析器。首次清理失败、后续关闭重试成功仍保留独立诊断，且 `errors.Is` 身份未丢失。无法由公开 API 分类的内部原因保留为 `command_failed`，不猜测为 `session_close_failed`。

采集测试还覆盖准备命令证据、回调 context、时间指针复用和复制、会话失败后不重放、关闭错误不覆盖已有事实。文件描述符测试在子进程中验证预算、软限制提升及连接前拒绝。原有 Ruby 金样继续由 Go 全包测试读取，未重新生成，也未重新调用 Ruby oracle。

当前复现命令：

```sh
export GOWORK=off GOFLAGS=-mod=readonly
GOTOOLCHAIN=go1.27.3 go test -race -count=1 ./...
GOTOOLCHAIN=go1.27.3 go vet ./...
GOTOOLCHAIN=go1.26.0 go test -count=1 ./...
GOTOOLCHAIN=go1.26.10 go test -count=1 ./...
GOTOOLCHAIN=go1.27.3 go fix -diff ./adapter
GOTOOLCHAIN=go1.27.3 govulncheck ./...
GOTOOLCHAIN=go1.27.3 python3 scripts/check-delivery.py
```

`govulncheck` 本次安装到临时工具目录，没有更改用户全局工具。交付脚本只对尚未发布的 go-vxlan 候选源码使用本地 replace，connector/expect 仍从正式模块解析；这是候选源码消费证明，不是发布证明。临时安装的 CLI 现有版本字符串 `0.1.0` 不表示本次发布。

本轮没有连接设备、运行真实 PostgreSQL、执行配置写入、远程 CI、部署或发布。四平台构建不等于各平台原生运行，漏洞扫描结论对应本轮 Go 1.27.3 构建。下面六台设备的历史记录来自旧冻结依赖，不是 v0.2.0 升级后的实机验收。接口与诊断边界见 [迁移说明](api-migration.md)。

## 2026-10-26 历史记录

以下保留当时的验证结果和复现方式。旧依赖恢复脚本已退役，当前执行方式以上文为准。

日期：2026-10-26。环境：macOS arm64，Go 1.27.1 / 1.26.0，Homebrew Ruby 4.0.7。参考 Ruby HEAD `3c7b85529a6639c74c649f754c7feb09e7610621`；本次新建 Go 工程，无自动提交、推送或发布。

## 已执行

| 检查 | 结果 |
| --- | --- |
| `go test ./... -count=1` | 根包、adapter、cli 通过；cmd 编译通过 |
| `go test -race ./... -count=1` | 通过；最新完整运行 root 16.597s、adapter 1.854s、cli 2.492s |
| `go vet ./...` | 通过 |
| `python3 scripts/test-prepare-workspace.py` | 5 项通过，包含变更内容拒绝覆盖及符号链接边界 |
| `python3 scripts/check-delivery.py` | Linux/macOS × amd64/arm64 四目标 CGO=0 编译通过；隔离副本还原、测试、外部模块导入 root/adapter、安装后二进制 version/parse 通过 |
| Go 1.26.0 最低工具链 | 通过；Go 1.26.0 darwin/arm64 全包测试：root 1.562s、adapter 0.812s、cli 0.728s |
| Ruby baseline + parser replay | 当前 102 个文件哈希一致；1,158 个配置/运行观测重新调用 Ruby 后完全匹配 |
| 来源元数据 | 431 个输入的 states、roots、range、captures/data/complete 精确对比通过；独立额外 1,293 次变体差分无差异 |
| 运行态 | 727 金样通过；独立额外 5,816 次变体差分无差异 |
| 领域 | 原 Ruby 80 个相关 examples 通过；311 个 oracle JSON 在临时目录重新生成后逐字一致；Go 领域及 race 聚焦检查通过 |
| 复杂度 | Subnet 128/512 项分配数 1,024/4,096；Fabric 32/128 VNI 分配数 29,836/133,682；原小于 6 倍增长阈值通过 |
| 交互取消 | 真实本地 PTY 到达 apply 确认提示后 SIGINT，无需回车退出 130 |
| 连接适配 | `net.Pipe` + 真 Go connector/profile 验证含 `!comment#` 的分段回显不被提前截断；只读查询固定当前提示符 |
| 报告/apply | 临时目录失败注入、输出错误、权限、漂移、校验、逐步失败、读回失败、关闭失败和回调违约测试通过 |

测试金样不是测试函数数：运行态 515 个生成对抗场景 + 212 个原 spec 调用；配置 431 个；来源 431 个；领域 311 个。所有 Go 测试读取仓库内 JSON，不运行 Ruby、不连接生产设备。

## 可重复执行

```sh
python3 scripts/prepare-workspace.py
go test -race ./... -count=1
go vet ./...
python3 scripts/test-prepare-workspace.py
python3 scripts/check-delivery.py
GOTOOLCHAIN=go1.26.0 go test ./...
```

`check-delivery.py` 创建临时目录并在结束时清理，不依赖 sibling 工程，也不更改当前 Go workspace。脚本安装目标是临时 GOBIN，不覆盖用户现有二进制。

使用参考工程的 Ruby bundle 独立复核已提交金样（路径按本机调整）：

```sh
cd /Users/wenwu.yan/Works/ruby/vxlan
PATH=/opt/homebrew/opt/ruby/bin:$PATH bundle exec ruby -Ilib \
  /Users/wenwu.yan/Works/go/go-vxlan/scripts/verify-ruby-parsers.rb \
  /Users/wenwu.yan/Works/go/go-vxlan /Users/wenwu.yan/Works/ruby/vxlan
```

开发期金样来源：

- `scripts/export-ruby-corpus.rb`：通过 `bundle exec rspec -r SCRIPT` 包装 Config/RuntimeParser/ShowRunningConfig 的实际调用。`VXLAN_CORPUS_DIR` 指向独立临时目录；导出按内容 SHA256 命名。配置保存 name/records/issues/evidence，去除不稳定时间。运行态原 spec 调用合并为 `testdata/runtime/upstream-spec.json`，每项保留 ID。
- `testdata/runtime/generate.rb`：使用 Ruby 原实现生成额外运行态对抗场景，覆盖 `golden.json`。仅在有意刷新基线时运行并检查差异。
- `scripts/export-source-corpus.rb GO_ROOT [OUTPUT]`：用参考 bundle 从现有配置输入重新导出来源元数据；提供 OUTPUT 可写到临时文件后比较。
- `scripts/export-domain-corpus.rb`：领域原 spec 调用，输出由 `VXLAN_DOMAIN_DIR` 指定。相关 specs 为 recommendations、change_plan_value、service/catalog、fabric/scope、fabric/review、prefix_list_references、change_plan、acl_policy。随后运行 `scripts/export-domain-extra.rb` 补齐额外边界。

刷新金样必须先核对 Ruby 基线哈希、检查预期变化，再运行 Go 测试。不能通过盲目重写金样消除差异。

## 独立审阅与修正

运行态、配置、来源/型号注册表、领域、CLI/报告/apply 均完成独立审阅。修正包括源身份极值/Unicode处理、外部复制边界、服务目录重复扫描、清单规则映射、确认时取消、提示符截断、摘要诊断格式及持久化失败。所有已复现重要问题都已回归验证。

Go map 派生数组排序、数值指纹输入域、对象可变性、时间/文本排版与缓存实现的明确差异见 [兼容矩阵](compatibility.md)，没有把它们归一化后宣称逐字等价。

## 尚未实测

此处是初次离线交付的验证边界；后续 6 台真实 NX-OS SSH 只读验证见文末。真实 PostgreSQL 数据源、生产配置写入与业务连通性、Linux/macOS amd64 原生执行、远程 CI、部署及公开发布仍未执行。PostgreSQL/缓存复用的连接和选项已对照公开 API 检查；本次端到端清单运行测试为本地 HTTP。跨平台编译不能代替各平台实机运行。

最低工具链下载使用临时本地代理和独立 GOMODCACHE，Go 默认 checksum database 验证保持开启；未修改全局 Go 配置或其他工作区的下载进程。

## 渐进优化第 1 轮：配置覆盖与 JSON 证据边界

2026-10-26，在上一轮未提交工作区上完成本轮针对性审查与修复；不代表重新审计了全部领域语法。无新增依赖，无设备操作、提交或发布。

已用失败测试复现并关闭 4 类问题：

1. `.env` 中已被 YAML/进程环境覆盖的无效 Netdisco 值仍导致启动失败。现在复用 connector 的分层加载器，在类型解码前屏蔽低优先级值；有效默认值、来源相对路径及最终生效的无效值仍分别正确继承/解析/拒绝。
2. `normalize` 与离线证据读取经过 float64，导致 `9007199254740993` 被改写为 `9007199254740992`。现在从采集标准化到建议输出使用精确数值；覆盖 int64 外大整数、非整数及指数形式。
3. JSON 重复键被后值静默覆盖。证据和计划现在共用严格读取边界，转义后同名的键也会拒绝；有合法 SHA256 的歧义计划在确认读行前返回 2。
4. ACL 序号为 null、字符串或小数时通过了校验。现在要求 1～4294967295 的整数；接近整数但不相等的 schema/VLAN/VNI 也不会被浮点舍入后接受。

新增 11 个回归测试函数及 1 个 fuzz 入口。原失败测试先红后绿；独立输入审阅完成，复查未发现该范围内剩余已复现的重要缺陷。检查所有 CLI JSON 解码与数值比较同类位置：`Report.invalidate` 的剩余 `json.Unmarshal` 只检查本机生成摘要的字符串状态，不用于证据、计划、身份或数值解释。

本轮新鲜验证：

- `go test -race ./... -count=1`：通过，root 18.768s、adapter 1.795s、cli 2.551s。
- `go vet ./...`：通过。
- `go test ./cli -run '^$' -fuzz '^FuzzEvidenceDocument$' -fuzztime=15s -parallel=2`：通过，42,325 次执行，未发现崩溃或往返不一致。
- Go 1.26.0 全包测试：通过，CLI 0.787s；未变更的 root/adapter 使用其有效缓存。
- `python3 scripts/check-delivery.py`：四平台编译、隔离源码恢复与全包测试、外部消费者、临时安装后 version/parse 全部通过。
- 重新构建本地 `bin/vxlan`：真实二进制在隔离 HOME/CWD 下完成 `collect --show-config` 覆盖旧值及 `review` 拒绝重复键的冒烟测试，无设备访问。

本轮没有宣称性能提升或真实设备验证。输入约束与数字表示更新已同步到 README 和 compatibility.md；代码仍保留为本地未提交工作区。

## 实机只读采集与 Ruby 数据比对

2026-10-26，经用户明确要求，读取现有 VXLAN 资产源，清单含 83 台 NX-OS。抽取 6 台（3 Leaf、1 Border、2 Spine），覆盖 N9KC93108TCEX、N9KC93180YCFX、N9KC93180YCFX3、N9KC9336CFX2、N9KC9336CFX2E、N9KC93180YCEX 六种型号；并发 2，固定只读查询，未执行 apply 或保存配置。

### 现场发现与修正

- 全局共享 YAML 为另一种配置格式，Go/Ruby 均在连接前拒绝。此次使用隔离 XDG/CWD，显式加载原 VXLAN 配置及现有凭据文件；未修改用户原配置或凭据。
- Go 将扁平外部 `backup.yml` 的 `backup.directory` 误认作配置包裹层。已用合成回归用例确认红灯并修复，保留扁平和分区格式的清单内容。
- NX-OS 提示符前真实出现 `CR CR LF CR`；旧匹配规则导致 `prompt_error`。已支持 CR/LF 边界及尾随换行，仍精确匹配当前设备提示符；保留“正文中的其他 # 行不能提前结束”回归。
- Go 适配层原先把终端回显直接送入解析器，缺少 Ruby CtxDriver 的终端渲染、确认提示符去除及首行命令回显去除。已复用冻结 connector 的原有渲染器补齐；正文后续同名行保留，原始回执 SHA256/字节数独立保存为 evidence。

### 实测结果

- 6 台均完成传输与报告保存；78 次命令回执包含 12 次终端准备和 66 次维度查询。vPC 经配置证据确认未配置，6 台均没有发送多余 vPC 查询。
- 共解析 8,835 条记录，4 台 complete、2 台 partial；批次退出码 1 符合不完整证据规则，所有设备 `report_saved=true`。
- 两台 Spine 的 `show l2route evpn mac all` / `mac-ip all` 仅返回说明、表头及分隔线，无记录或显式空表标记。保留 `missing_completeness_evidence`；没有放宽解析规则将其包装成 complete。Ruby 同样返回 partial。
- 第一层差分：对同一批 66 份真实传输回显，分别调用 Go 适配正文处理和 Ruby CtxDriver Response.value!，再使用各自解析器；status/records/issues 全部一致。
- 第二层差分：将最终采集正文回放给原 Ruby Collector；6 台共 78 个观测（72 个请求维度及 6 个 collection 汇总）的 status/records/issues 全部一致，无差异。时间戳和运行目录未参与比较；记录数组与诊断没有排序归一化。
- Ruby 运行环境：4.0.7，ctx_driver 0.2.4、ctx_parser 0.2.4、net-connector 0.14.2；参考 VXLAN 源码版本保持原基线。

原始数据、回放 JSON 和设备报告仅保存于本地私有 `.work/live-validation-*/`，不纳入源码或公开测试夹具。新增公开回归全部为合成文本。本次数据是六台设备某一时刻的验证，不能外推为 83 台均验证完成或业务健康结论。

修正后重新通过：`go test -race ./... -count=1`（root 17.227s / adapter 1.630s / cli 1.833s）、`go vet ./...`、5 项依赖恢复检查、四平台编译、隔离源码恢复/全包测试、外部模块消费及安装后二进制冒烟检查。
