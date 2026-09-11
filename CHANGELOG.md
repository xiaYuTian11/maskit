# Changelog

本文件记录对用户可见的变更；格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## [Unreleased]

## [0.2.3] - 2026-09-11

反向代理兼容与配置健壮性修复版本。

### 修复
- 修复反向代理 / CDN（Nginx、EdgeOne 等）HTTPS 终止环境下页面白屏：静态资源（HTML / JS / CSS）不再经过 Origin 与 Host 校验，仅 `/api/*` 控制面接口进入安全防线。
- 修复 Origin 校验在反代回源 Origin 与源站不一致时把用户挡在面板之外的问题：新增配置项 `origin_check`（设置页「控制面访问安全」开关），以及环境变量 `MASKIT_DISABLE_ORIGIN_CHECK=1` 逃生舱。
- 增加控制台 Origin 拦截自救能力：登录门与配置接口在收到合法 Token 时精准识别拦截原因并提供一键解除通道，杜绝反代 Origin 错误导致设置页陷入死锁。
- 修复反向代理路由丢失 Query 参数的缺陷：完整保留客户端与 Target 自带的 query 参数（如 Azure OpenAI `?api-version=...`、Gemini `?key=...` 及流式参数等）。
- 修复配置归一化与 sidecar 同步脱节问题：配置清洗修正结果原子持久化写回磁盘，sidecar 与面板 100% 保持相同规范化路由表，锁内原子同步消除内存竞态。
- 修复多个纯中文名称客户端因内部路径前缀塌缩成同一 `/up` 而被整条丢弃的问题：自动生成 `up_N` 前缀、冲突时自动追加序号消解，客户端不再丢失；同名客户端改为去重并给出提示。
- 优化客户端预设路径与 Base URL 复制：前端一键复制符合 OpenAI SDK 规范的标准接入地址（自动带 `/v1`），预设剔除宽泛的裸 `/v1` 防范非 JSON 接口误伤，`Content-Type` 改为大小写不敏感。

### 文档
- 补充 Docker 端口按需映射说明（单模型仅需映射 18701）与 Nginx 反向代理参考配置（含 `MASKIT_TRUST_PROXY` 与 SSE 流式 `proxy_buffering off`）。
- 统一快捷登录链接口径为 `/#token=...`（fragment 不随请求发送、不进代理访问日志），规范 Docker 环境变量 Token 示例为标准 ASCII 格式。

## [0.2.2] - 2026-09-10

界面直达与价格同步优化版本。

### 优化与修复
- 顶栏导航区新增 GitHub 官方图标，支持点击一键打开系统默认浏览器直达开源项目主页。
- 修复手动点击「立即同步价格」时因开关校验导致的 HTTP 502 报错；手动触发自动视同授权并同步。
- 完善自托管价格源与 OpenRouter 格式的无缝兼容。
- 优化 DeepSeek 等主流系列模型的默认费率兜底，减少未收录后缀时的未定价展示。

## [0.2.1] - 2026-09-09

修复与体验优化版本。

### 优化与修复
- 修复 Windows 任务栏图标由于缺少多尺寸位图导致的白纸空白问题（补齐 16~256 全尺寸标准 ICO）。
- 移除关于页遗留的反馈卡片，避免重复入口。
- 修复高级设置中点击「去客户端管理配置」跳转导致下方内容空白的问题。
- 关闭 Dependabot 自动化拉取 PR 限制，保持仓库 PR 列表清爽。

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

[Unreleased]: https://github.com/xiaYuTian11/maskit/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.2.3
[0.2.2]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.2.2
[0.2.1]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.2.1
[0.2.0]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.2.0
[0.1.0]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.1.0
