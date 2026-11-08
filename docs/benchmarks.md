# VXLAN 业务基准

2026-11-07，在 macOS arm64 / Apple M5 / Go 1.27.3 上测量本轮候选，固定 `-cpu=1 -benchtime=300ms -count=6`，前后使用相同输入、工具链和任务 go.work。与 Wireless 串行采样，测量期间停止其他模块重测试。结果反映合成业务输入，不能代替生产设备性能验收。

`configuration/services_bench_test.go` 覆盖两条业务路径：4 台设备上 64/256/1024 个 VLAN/VNI 的服务关联，以及 4/16/64 台设备上各 16 个 VNI 的 Fabric 审查。每四台有一台缺少网关地址，生成有效的跨设备一致性检查和候选。`evidence_bench_test.go` 覆盖 128/512/2048 条观察的公开投影及已验证值复制，包含大于 2^53 的整数、高精度小数、nil/空容器和来源顺序。构造输入不计入计时。

为输出目录设置 `task_dir` 后，从 VXLAN 仓库执行；正式版本复测使用固定的远程依赖：

```sh
GOTOOLCHAIN=go1.27.3 GOFLAGS=-mod=readonly GOWORK=off \
  go test -run '^$' -bench 'Benchmark(Evidence|ServiceCatalog|FabricReview)' \
  -benchmem -benchtime=300ms -count=6 -cpu=1 . ./configuration \
  > "$task_dir/vxlan-bench-before.txt"
# 改动后执行完全相同命令，输出改为 vxlan-bench-after.txt。
benchstat "$task_dir/vxlan-bench-before.txt" "$task_dir/vxlan-bench-after.txt"
```

使用任务已有的固定 benchstat 二进制；原始 before/after、benchstat 及 CPU/分配 profile 保存在任务根，未纳入源码。before 为本轮配置/状态重构后的候选、gateway 优化前的源码；没有将工具链升级算作优化收益。

| Fabric 设备数 | 耗时 before → after | 耗时变化 | B/op before → after | allocs/op 变化 |
| --- | --- | --- | --- | --- |
| 4 | 1.291 → 1.300 ms | +0.65% | 1.915 → 1.918 MiB | +0.29% |
| 16 | 6.778 → 5.787 ms | -14.62% | 8.733 → 7.648 MiB | -14.61% |
| 64 | 44.49 → 23.41 ms | -47.37% | 52.63 → 30.71 MiB | -46.45% |

以上 Fabric 耗时变化均为 `p=0.002, n=6`。4 台设备只有一个待修正成员，缓存带来小额开销；设备规模增加时收益明显。64 台分配 profile 中约 71% 的累计对象分配落在 `reviewGateway`：循环重复构造同一组 peer 上下文，并对同地址/VNI/VRF 重查 Fabric 子网。

优化只调整一次审查内的计算：peer 上下文去重移出候选循环，地址/VNI/成员范围固定后按精确 VRF 值复用冲突查询。每条建议的冲突证据仍独立复制，跨 VRF 查询、证据顺序、错误传播及候选许可保持原规则。Ruby 领域金样与新增跨 VRF/可变证据隔离回归通过。

服务目录已有一次反向关联索引，本轮不再改它；公开证据投影与复制也保持严格校验和深复制。未修改的对照项目分配不变，耗时变化约在 1.4% 以内，未宣称这些路径获得优化收益。
