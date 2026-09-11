# Changelog

本文件记录对用户可见的变更；格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## [Unreleased]

## [0.2.6] - 2026-09-11

注入请求头占位符覆盖客户端真实凭据（中转站 401）与 CI 单测死锁修复版本。  
Release v0.2.6: Fix CI unit test deadlock, credential header clobbering (401 errors), and enable macOS Apple Silicon DMG packaging.

### 修复 / Bug Fixes
- 修复「注入请求头」仍留占位符时**把客户端自带的真实凭据覆盖掉**、导致上游返回 401「无效的令牌」：现在整值为 `<...>` 的占位符一律跳过注入，客户端自带凭据照常透传。
  *Fix: Skip injecting header placeholders like `<YOUR_API_KEY>` to prevent overwriting client-sent credentials and causing upstream 401 Unauthorized errors.*
- 修复注入请求头值为空时同样会覆盖客户端凭据的问题：空值一并跳过注入并告警。
  *Fix: Skip empty or whitespace header values to avoid clearing client credentials.*
- **「注入请求头」中的凭据类请求头一律不再注入**：Maskit 只做透明转发，凭据归客户端所有，严禁在此字段注入 `Authorization`、`x-api-key` 等凭据头。
  *Security & Reliability: Disallow injecting credential headers (`Authorization`, `x-api-key`, etc.) via `extra_headers`; only protocol headers (such as `anthropic-beta`) are permitted.*
- 修复客户端类型预设**预填凭据头占位符**这一配置陷阱：`Authorization` / `x-api-key` 不再进预设。
  *UX Fix: Remove credential placeholders from client presets so users are never misled.*
- 修复 GitHub Actions Linux 虚拟机运行单测时的 `socketserver` 挂起死锁：`_stop_passthrough` 增加后台线程有界超时关闭保护。
  *CI Fix: Resolve unbounded hang in `socketserver.shutdown()` on headless runners with bounded timeout.*
- 开启 GitHub Actions 原生 macOS（Apple Silicon M系列）DMG 桌面安装包自动化构建。
  *Platform: Enable automated macOS arm64 DMG bundle compilation in GitHub Release workflow.*

### 优化 / Improvements
- 「注入请求头」收进设置弹窗的「高级选项」折叠区，默认收起；保存客户端时拦截占位符与凭据头并给出明确提示。
  *Move injected headers under an "Advanced Options" collapsible section; intercept placeholders and credential headers before saving.*

### 测试 / Tests
- 补充「注入请求头为占位符/空值时不得覆盖客户端自带凭据」与「凭据头一律不得注入」等 7 组单测；全量 535 项单测全部通过。
  *Add comprehensive unit test coverage for header injection guard rails; 535 tests passing.*

## [0.2.5] - 2026-09-11

代理启动超时、Secret 前缀短凭据与日志筛选修复版本。

### 修复
- 修复弱 CPU / 多 upstream 机器启动代理被误判失败（Issue #19）：就绪等待上限由固定 15s 放宽到 60s，并支持 `MASKIT_START_READY_TIMEOUT` 环境变量覆盖；启动失败分支不再对存活子进程调用会永久挂起的 `p.stdout.read()`，改用有界超时读取，保证 `proxy_starting` 一定复位；错误信息不再渲染成 `b'...'` 形式。
- 修复 Secret 前缀凭据的后缀长度阈值过严（19 位）导致自建平台、内网鉴权、测试环境的 8~16 位短 Key 全部漏判：阈值下调至 8 位，同时仍避开 `sk-demo`、`sk-test` 一类极短日常词。
- 修复 `total_tokens` 兜底把「总 token」误记为「输入 token」的偏差：仅在 prompt/completion 均为 0 时才使用 `total_tokens` 兜底。
- 移除 `transparent.py` 中与 `shield_defaults.py` 重复的 `_extract_usage` 实现，统一走 `shield_defaults.extract_usage`（补齐 `meta.tokens` 与 `total_tokens` 兼容）。
- 修复日志页「类型筛选」在海量日志下被 `LIMIT` 截断、筛不到较早事件的问题：类型过滤下推到数据库（新增 `event_type` 参数，命中 `idx_events_type_ts`），`/api/logs` 与 `/api/logs/export` 均支持 `type` 参数。
- 修复日志合并把同一 sid 的第三个及以后事件静默覆盖到已合并行的问题；非 MASK/RESTORE 类型（ERR/BLOCK/SCAN_WARN 等）即便带 sid 也独立成行展示。
- 修复敏感词排序词表「等长换词不生效」：缓存失效原本只比较词条数量，把 `{张三, 李四}` 换成 `{密, 王五}`（条数不变）时会继续沿用旧词表 —— 新词不脱敏、已删除的旧词继续脱敏，**漏脱敏与过脱敏同时发生**，且症状随调用顺序漂移极难排查。现改为按内容比较，任何写入词表的路径都自动正确。

### 优化
- 日志页「无数据」与「加载中」状态改按首次加载判定，后台轮询不再让空列表持续转圈。
- 敏感词新增按钮支持回车提交；输入框有内容时按钮变为「保存」，避免误触收起输入框。
- Secret 前缀卡片说明补全匹配规则：明确 `@` 可出现在前缀任意位置（不再表述为「以 @ 开头」）、前缀之后需跟随至少 8 位密文字符，并指引更短的固定 Key 改用「敏感词」列表（按字面精确匹配、无长度门槛）。
- 敏感词新增 1~2 字符的词时给出误伤告警：自定义词是无边界字面子串匹配，例如加入 `a1` 会把 `data1` 打码成 `dat{{TERM_x}}`，进而改坏发往上游的 prompt。
- 合并正则的缓存命中判断提前到构建匹配片段之前：`mask()` 热路径不再做词表排序与正则拼接（实测 2000 次调用仅首次构建），并修掉「跳过非法正则词」日志每次请求都重打一遍的刷屏（20 次调用由 20 条降为 1 条）。

### 测试
- 补充 8 位短 Key 与 `@` 前缀的脱敏/还原用例、Rerank 用量提取用例、`/api/logs?type=` 下推过滤用例、启动超时不阻塞用例。
- 补充「短于前缀阈值的固定 Key 经敏感词列表仍可完整脱敏/还原」用例，锁住设置页指引的这条兜底路径。
- 补充「等长换词必须立即生效」回归护栏：把缓存失效改回只比长度，该用例必挂（已实测验证）。
- 修复 `test_single_char_custom_word_requires_boundary` 的用例顺序依赖：改为直接覆盖惰性重建路径，不再依赖上一个用例残留的词表缓存。
- 修复 `tests/smoke_stream.py` 监听端口与探测端口不一致（硬编码 5899 vs `PROXY_PORT` 18992）导致流式冒烟测试无法通过的问题。

### 文档
- 社区论坛链接更新为 LINUX DO 项目专帖。

## [0.2.4] - 2026-09-11

代理启动稳定性、Secret 前缀配置与 Rerank 支持修复版本。

### 修复
- 修复 Windows GUI 打包态（无控制台）点击启动代理即崩溃挂起：引擎入口在导入任何三方库之前补齐 `sys.stdin/stdout/stderr`，避免 mitmproxy 日志处理器对 `None` 调用 `isatty()` 抛 `AttributeError` 并弹出阻塞式错误框。
- 修复 Secret 前缀配置被误丢弃与误限制：允许不带尾部连字符的自定义前缀（如 `hf_`、`x_`），显式清空 `secret_prefixes` 时不再被默认值回填；前缀中的 `-` 与 `_` 逐字符安全转义后视为等价，杜绝二次替换嵌套。
- 修复发布流水线长期停留在 Draft 状态：Release 资产上传完成后自动转为正式发布，发布标题统一为 `Data Maskit <tag>`。
- 修复 Rerank 接口未被纳入默认脱敏路径与业务字段扫描：新增 `/v1/rerank`、`/rerank` 默认路径，`documents` 纳入 LLM 业务键与扫描容器。

### 优化
- Rerank 响应用量提取兼容 Cohere 风格 `meta.tokens`。
- 设置页 Secret 前缀卡片补充说明文案与格式校验提示（重复前缀、非法格式）。

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
