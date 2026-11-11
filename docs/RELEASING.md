# 发布

沿用 AnyTLS 的 CI artifact 复用流程，仓库为 gatework/go-vxlan。

1. 更新 cli.Version、docs/releases/vVERSION.md，提交并推送 main。
2. CI 在 Linux/macOS 和 Go 1.26.x/1.27.x 执行 make check（共享标准、架构、race、vet、模块与交付检查）；新工具链扫描漏洞。
3. 全部门禁通过后构建四平台归档，上传 source-COMMIT；两平台下载同一 artifact 做原生离线冒烟。
4. 只有精确提交的 CI 全部成功才创建 vVERSION 标签。Release 作业只下载成功 main CI 的产物，不重新构建。
5. 校验构建信息、提交、平台、许可证及摘要，先建立草稿，上传附件后逐字回读，再公开发布。重跑不会覆盖已有不同内容。

本地准备：GOWORK=off GOFLAGS=-mod=readonly go test -race ./...；python3 scripts/test-reuse-release.py；python3 scripts/test-publish-release.py。
干净提交打包：GOWORK=off sh scripts/package.sh；sh scripts/verify-release.sh dist vVERSION COMMIT。
私有设备数据、.env、.work 和本地二进制不纳入源码或发行包。源码中的示例与测试资料来源见 docs/verification.md。
