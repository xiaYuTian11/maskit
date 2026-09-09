# Changelog

本文件记录对用户可见的变更；格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## [Unreleased]

## [0.2.0] - 2026-09-09

发布增强与上线版本。

### 优化与修复
- 增强桌面壳跨平台进程清理与守护机制（Unix 自底向上树状进程终止）。
- 增强面板安全边界校验（外部 URL 边界白名单、重定向凭据安全抹除）。
- 完善前端 TypeScript strict 模式类型检查与代码健壮性。
- 清理内部注释与代码规范，支持系统托盘本地化与平滑更新。
- 完整支持客户端远程无缝升级链路。

## [0.1.0] - 2026-09-09

首个公开开源版本。

### 功能
- 反向代理多端口脱敏：客户端 `base_url` 指向本机端口，请求体内敏感信息替换为 `{{LABEL_xxxxxx}}` 占位符后转发，响应流式逐事件还原。
- 内置规则：手机号 / 邮箱 / 身份证 / 银行卡 / IBAN / 车牌 / 内网 IP / API Key / JWT / 私钥 / 连接串等，另支持自定义词表与正则。
- 跨请求占位符滑动窗口复用，多轮对话上下文一致。
- Fail-closed：脱敏管线异常或请求体超 32MB 一律阻断，绝不放行明文。
- 透明直连兜底：代理未启动时端口仍由轻量层监听并原样转发，不断网。
- 被动安全审计：错误泄漏 / 身份换芯 / 工具调用改写 / SSE 异常 / 响应投毒 / 跨请求污染 / 危险动作信号。
- 本地事件库（SQLite）、统计仪表盘、战绩分享卡；凭据类事件只存摘要。
- Windows 桌面版（Tauri 2）：系统托盘、单实例、引擎崩溃自愈、开机自启。
- Docker 镜像（amd64 / arm64）内嵌 Web 控制台，远程访问需 `MASKIT_PANEL_TOKEN`。
- 中英文界面一键切换、深浅主题。

[Unreleased]: https://github.com/xiaYuTian11/maskit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.2.0
[0.1.0]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.1.0
