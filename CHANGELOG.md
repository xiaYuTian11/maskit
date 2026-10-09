# Changelog

本文件记录对用户可见的变更；格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## [Unreleased]

### 修复
- 日志：上游首包后彻底静默、被 mitmproxy 连接空闲看门狗（默认 600 秒）掐断的请求，此前写成「客户端断开」并把排查方向带向客户端；现改判为 `upstream_idle`（责任方上游）并给出连续静默秒数，`docs/SETTINGS.md` 同步说清三条互不相同的静默时间线。

### Fixed
- Logs: a request whose upstream fell silent after the first byte and was killed by mitmproxy's inactivity watchdog (600s by default) used to be written as a client disconnect, pointing triage at the wrong side; it is now attributed as `upstream_idle` (owner: upstream) with the idle seconds, and `docs/SETTINGS.md` spells out the three distinct silence timelines.

### 新增
- 引擎：C1 上游传输接管（可选开关 `upstreams[].takeover`，默认关闭）。开启后旁路 mitmproxy 上游连接，由进程级 httpx keep-alive 连接池跨客户端共享上游连接，把每天数万次 TCP 握手降到数百次，丢包暴露从「每请求赌一次」降回「每批次赌一次」。TLS 证书校验默认严格（verify=True）、32 MiB 上限守卫平移、客户端凭据头原样透传（仅剥内部路由头）、有/无出口代理双池按上游分流均覆盖；`takeover=false` 时走原逻辑，零影响。
- 面板：客户端编辑页新增「接管上游连接」开关；此前 `takeover` 只能手改 config.json，且面板任何一次保存都会把它静默抹掉。
- 引擎：metrics 暴露 `c1_sidecar` 状态字段（enabled/port/stats/pool），便于面板观测连接池效果。

### Added
- Engine: C1 upstream takeover (opt-in via `upstreams[].takeover`, off by default). When enabled, bypasses mitmproxy's upstream connection and routes through a process-level httpx keep-alive pool shared across all clients — daily TCP handshakes drop from tens of thousands to hundreds, packet-loss exposure shifts from "per-request gamble" back to "per-batch gamble". TLS verification stays strict (verify=True), the 32 MiB body guard carries over, client credential headers pass through untouched (only internal routing headers are stripped), and proxied/direct upstreams get their own pool. With `takeover=false`, the original path is used with zero impact.
- Panel: the client editor gains a "take over upstream connection" switch; previously `takeover` could only be set by editing config.json by hand, and every panel save silently wiped it.
- Engine: metrics now expose a `c1_sidecar` status field (enabled/port/stats/pool) for pool-effect observability.

## [0.8.1] - 2026-10-09

### 修复
- 引擎：卡住的上游建连 / TLS 握手改为有预算（默认 20 秒，`MASKIT_CONNECT_STALL_S`），超预算时取消正在建立这一跳的任务并立即回 502，客户端不再空等约 127 秒的内核重传；事件归因为 `handshake_timeout`（上游、可重试）。这只治「死等多久」，链路丢包本身仍需系统层处理。

### Fixed
- Engine: a stalled upstream connect / TLS handshake is now budgeted (20s by default, `MASKIT_CONNECT_STALL_S`); over budget the task establishing that hop is cancelled and the client gets a clean 502 instead of waiting out the ~127s kernel retransmit ladder, attributed as `handshake_timeout` (upstream, retryable). This bounds the dead wait and makes it retryable — the packet loss itself is a link-layer problem.

### 新增
- 面板：顶栏新增常驻「帮助」入口（页面导览、快速上手、常见问题、教程跳转）与三步首次引导；引导仅在尚未配置任何客户端时自动弹出，老用户升级不会被打断。
- 文档：新增 `docs/SETTINGS.md`，按页面与开关逐项解释配置口径。

### Added
- Panel: the top bar gains a permanent Help entry (page guide, quick start, FAQ, tutorial links) and a three-step first-run guide that auto-opens only while no client is configured, so upgrades never interrupt existing users.
- Docs: added `docs/SETTINGS.md`, explaining each page and switch.

### 优化
- 日志：「隐藏噪声」默认开启（实测取消记录与脱敏记录约 1:1，列表一半被取消行占据），并记住开关选择——刷新或重开客户端后仍生效；开关说明改为列出实际隐藏的五类事件（透传/跳过/绕过/取消/DNS 错误）。
- 版本号：面板连不上时侧栏与「关于」卡回退显示客户端版本并标注来源（此前 502 这类故障截图上根本没有版本号，报障无从判断），面板启动日志首行也带上版本。
- 设置：上游连接策略的「连接复用 / 空闲期限 / 建连预算 / TLS 预算」四项补上悬停说明，明确它们是建连与握手预算，不是模型请求或 SSE 流的时长。

### Changed
- Logs: hide noise events by default (cancelled rows were ~1:1 with mask rows) and remember the toggle across sessions; the tooltip now names the five hidden event types.
- Version: when the panel is unreachable, the sidebar and About card fall back to the client version with an explicit source note (such failure screenshots previously carried no version at all); the panel startup log line now prints it too.
- Settings: the four upstream connection-policy fields now explain on hover that they budget connection setup and the TLS handshake, not model requests or SSE streams.

## [0.8.0] - 2026-10-05

### 修复
- Docker：容器改以 uid 1001（仍非 root）运行，NAS 挂载宿主目录（属主多在 1000 段）不再报 sqlite 打不开；前端构建镜像升 Node 24（PR #33 by @chung1912）。
- Linux：托盘支持左键直接唤醒主窗口，右键保留菜单，避免每次打开窗口都要多选一次。
- 日志：已完成交付后的客户端关连接不再记成「取消」（CANCEL），并给取消事件补齐归因字段（已下发字节/回调次数、脱敏耗时、上游与模型），列表不再被无信息量的取消行刷屏、真中断也不再与收尾断开长得一样。
- 引擎：思考强度排查提示只在上游**参数类错误**（400/422）时给出，Cloudflare 524 / 502 这类上游超时不再被误报成「reasoning_effort 取值不被支持」。
- 仓库安全：演示样例与「填样例」文本里的号码/邮箱/凭据改为运行时拼接，源码里不再出现真实形态的值（历史事故：工具调用里的占位符字面量被本机网关还原成真实值后落盘）；新增守卫测试。
- 引擎：已完成的请求收到客户端断开时，证据里的阶段不再被改回「响应流进行中」——已完成这一事实不再被抹掉。
- 引擎：签名思考块（Anthropic `thinking`/`redacted_thinking`）整块只读，不再被改写而破坏上游签名校验导致会话永久 400；豁免数量随事件上报（`signed_blocks_skipped`）。
- 引擎：响应侧不再还原思考轨迹（SSE 增量 / 快照 / 整包回退同口径），客户端存回的历史占位符与签名保持逐字节一致；其它无签名约束的推理通道照常还原。
- 发版：更新元数据补齐 `linux-<arch>-deb` 条目并对 `.deb` 单独签名，deb 安装的 Linux 客户端不再报 `invalid updater binary format`。
- 引擎：语义识别的 CPU 预算改按**实际 CPU 开销**结算（旧口径按墙钟计费，同样的预算实测实吃近两倍 CPU），并关掉 ONNX 线程池在每次推理后约 1 秒的空转——2 核机器上「CPU 被吃满」的两个真实来源。
- 引擎：长会话不再因语义识别预算被最老的历史吃光而漏检**最新一条**（新增「最新消息优先」预取）。
- 引擎：容器里的线程与并发**全部**改用实际可用核数（cgroup 配额 ∩ 亲和性）——脱敏池与辅助池此前仍按宿主核数开，`--cpus=2` 的容器在 16 核宿主上会疊 8 个线程；同时修正语义识别预算默认容量的换算（旧换算在多核机器上把允许量翻了一倍）。
- 打包：引擎产物补齐 `inspection.py` / `protocol_contracts.py` 明文模块——它们此前只在 PYZ 里、产物里没有文件，而发版流水线的「包内容断言」正要求它们存在（发版会直接红）；同时补上一条守门测试，把「workflow 断言的包内容」与「spec 的构建输入」钉在一起。
- 容器：Docker 镜像补拷 `agent-bundle/`，容器部署下「下载占位符 Skill 包」不再恒 500（本地与安装包都正常，只有容器里没有可发的包）。
- 日志：导出补齐**统一口径结论**（处置结论 / 完整度 / 原因码 / 签名块豁免数）与审计结论。这批字段是用字典展开发射的，既有的字段登记守卫看不见它们，于是能入库、详情页看得见、**导出里一个都没有** —— 拿导出找人复盘就只能看到现象（命中 0 条），看不到结论（直通未脱敏 / 检测不完整）。

### 新增
- 接入：新增首条真实请求标记验证与显式弱关联，配置或运行状态变化后旧证据失效；诊断包可先预览，再下载或保存同一份内容。
- Onboarding: verify a real request with a marker or explicit weak correlation, invalidate stale evidence, and preview the exact diagnostics snapshot before downloading or saving.
- 面板：日志页支持按**时间区间回看**（「只看某时间点之前的记录」），与「加载更早」共用历史通道，回到实时一键恢复。
- 面板：限时排障按钮显示**剩余倒计时**，不再只区分「排障中」这个状态。
- 面板：新增独立的**「清空内存映射」**动作（设置 → 高级），与「清空日志」「清空审计」「清空数字统计」互不影响；要清掉本地内存里那套「占位符 ↔ 原文」对照，以前只能重启代理，现在可以单独触发。
- 面板：接入页新增**本地试验台**——不填密钥、不出网，就地看这段文本会被脱敏成什么、能不能原样还原，命中明细含标签/原值长度/出现次数与「唯一实体数 vs 出现次数」的区别。
- 面板：接入页新增**占位符 Skill 包下载**与安装命令复制（包内容与 Release 资产同源），让编程助手原样使用占位符。
- 引擎：协议不可改写状态改由契约表驱动（`engine/protocol_contracts.py`），补齐 Responses / Gemini / LiteLLM / OpenRouter / Anthropic 检索结果五个同类载体，避免用户自定义词把签名与密文打烂而导致上游 400；工具参数里的同名键照常扫描。
- 引擎：事件与扩展桥接统一上报「处置结论 + 检测完整度 + 原因码」，列表与详情可区分已脱敏 / 扫描未命中 / 直通未脱敏 / 已阻断 / 检测不完整，不再一律显示「0 命中」。
- 引擎：新增「语义检测必须完整」开关（`ner_require_complete`，默认关）；开启后本轮语义识别没跑完即在出网前 503 阻断，不冒充「已扫干净」。
- 面板：日志页新增**写入粒度**切换（最小记录 / 本地详细）与 15 分钟限时排障；最小模式在**写入侧**就不落对话正文与原文（数据库、引擎 stdout、内存日志、诊断包与导出同口径），词榜只保留类别分布。
- 面板：日志页可**往回翻历史**（反向游标），历史模式下暂停实时刷新并可随时回到实时；导出严格对齐当前筛选，并明确告知导出条数与匹配总数（截断不再静默）。
- 面板：新增独立的「清空数字统计」动作，与「清空日志」「清空审计记录」彼此独立，清日志不再需要担心趋势图跟着归零。
- 配置：单条请求体上限可配置（`config.max_request_body_mb`，默认 32MiB、范围 1~256MiB），面板与引擎两进程同源；带大附件的合法请求不再只能放弃（会同步抬高内存与单条跳敏耗时的预算）。
- 引擎：新增叶子结果缓存——多轮长会话每轮重发整段历史时，未变化的正文不再重复扫描（实测续跑 14ms → 1ms。键是进程密钥摘要，值为脱敏后文本与占位符清单，**被脱敏的值不在其中**，且逐条核对该占位符指向的仍是当初那个原文）。
- 引擎：语义识别缓存容量可配（`MASKIT_NER_CACHE_MAX` / `MASKIT_NER_CACHE_CHARS`，默认 4096→32768 条），并在启动阶段预热模型，不再把加载耗时压在第一个用户请求上。
- 日志：失败事件新增结构化归因字段（责任方：引擎 / 上游 / 客户端 / DNS / 出口代理，以及异常类型），导出与诊断包同步带上。
- 面板：设置页显示语义识别的实际生效值（可用核数 / 并发 / ONNX 线程 / 每秒预算），排查「CPU 跑满」不必再去翻日志。
- 面板：开启「语义检测必须完整」时提示长会话风险（历史越长越容易超预算而被阻断）。

### 优化
- 引擎：`before_ts` 时间游标与 `before_seq` 同源筛选，非法时间参数按「不限时间」处理而不是报错。
- 性能基线：`scripts/bench_mask.py` 补齐 NER 冷/热缓存、长上下文与 1/4/8 并发三组可重跑测量，并修掉三处会给出误导数字的样本设计（并发扫描未固定总量、长文本用重复模板、分段窗口跨档命中缓存）。
- 引擎：响应侧「不还原」的块类型与请求侧同源（同一张契约表导出），签名型推理块（OpenRouter `reasoning_details`）在整包与 SSE 两条还原路径上口径一致。
- 引擎：体积闸 413 错误体补 `hint`/`blocking` 与统一口径（代理与扩展两条链路同口径），超限不再无法归因；同时修正 `_MAX_REQUEST_BODY` 上“脱敏跑在 event loop 上”的过时注释。
- 日志：保留策略改为由面板后台任务驱动，不再只在用户打开日志页时才触发清理（磁盘增长与有没有人看页面无关）。
- 引擎：语义识别结果缓存改为**进程密钥摘要**作键、只存位置与类别，命中时从当前文本即时切出——缓存不再延长原文在内存里的停留窗口（冷热命中行为不变，换模型/检测版本也不会错误复用）。
- 性能基线：`bench_mask.py` 新增「多轮长会话」组，并修掉两处会被缓存命中的样本（固定文本、复用会话 id 会把「缓存命中」测成「脱敏性能」）。

---

### Fixed
- Docker: the container now runs as uid 1001 (still non-root), so NAS bind-mounts owned by 1000-range users no longer fail with "unable to open database file"; frontend build stage upgraded to Node 24 (PR #33 by @chung1912).
- Linux: left-clicking the tray now opens the main window directly, while right-clicking keeps the menu.
- Logs: a client closing the connection after the response was fully delivered is no longer recorded as a cancellation (CANCEL), and cancel events now carry attribution fields (delivered bytes / stream callback count, masking duration, upstream and model) — genuine aborts no longer look identical to post-completion closes.
- Engine: the thinking-level hint is now attached only to parameter-type upstream errors (400/422); gateway timeouts such as Cloudflare 524 / 502 are no longer misreported as an unsupported `reasoning_effort` value.
- Repo hygiene: sample and "fill sample" texts now build phone/email/key values at runtime, so the source no longer contains real-shaped values (past incident: a placeholder literal written through a tool call was restored to its real value on disk by the local gateway); guarded by a new test.
- Engine: when a completed request sees the client disconnect, the recorded transport phase is no longer rewritten to "stream in progress" — the completion fact is preserved.
- Engine: signed thinking blocks (Anthropic `thinking`/`redacted_thinking`) are now treated as read-only, so masking no longer invalidates the upstream signature and permanently breaks the conversation with HTTP 400; the exempted block count is reported as `signed_blocks_skipped`.
- Engine: reasoning traces are no longer restored on the response side (SSE deltas, snapshots and whole-body fallback now agree), keeping the client-side history byte-identical to what the signature covers; reasoning channels without a signature keep being restored.
- Release: the update manifest now ships signed `linux-<arch>-deb` entries, so Linux clients installed from `.deb` no longer fail with `invalid updater binary format`.
- Engine: the semantic-recognition CPU budget is now settled by **actual CPU cost** (the old accounting charged wall-clock time, which let the same budget consume twice the CPU), and the ONNX thread pool no longer spins for about a second after every inference — the two real sources behind “CPU pegged” on 2-core machines.
- Engine: long conversations no longer skip the **newest** message because the oldest history ate the semantic-recognition budget (new newest-first prefetch).
- Engine: threads and concurrency now **all** derive from the actually available cores (cgroup quota ∩ affinity) — the masking and aux pools still sized from the host core count, so a `--cpus=2` container on a 16-core host stacked 8 threads; also fixed the NER budget's default capacity conversion (the old one doubled the allowance on many-core machines).
- Packaging: the engine artifact now ships the `inspection.py` / `protocol_contracts.py` plaintext modules — they used to live only in the PYZ with no file in the artifact, while the release pipeline's package-content assertion requires them (the release would have failed outright); a new guard test ties the workflow's asserted contents to the spec's build inputs.
- Docker: the image now copies `agent-bundle/`, so “download the placeholder skill package” no longer returns 500 in container deployments (source and packaged installs were fine; only containers had no bundle to serve).
- Logs: exports now include the **unified verdict** (decision / completeness / reason codes / signed-block exemptions) and the audit verdict. Those fields are emitted through a dict spread, so the existing field-registration guard could not see them: they were stored and visible in the detail dialog but **completely absent from exports** — an exported log showed only the symptom (0 hits), never the conclusion (passthrough unmasked / detection incomplete).

### Added
- Panel: logs can be filtered by **time range** ("only records before this moment"), sharing the same history path as "load older", with one click back to live.
- Panel: the time-limited trace button now shows a **remaining countdown** instead of just an "active" state.
- Panel: a separate **"clear memory mappings"** action (Settings → Advanced), independent of clearing logs, audit records or numeric stats; dropping the in-memory placeholder ↔ original mapping no longer requires restarting the proxy.
- Panel: the clients page gained a **local lab** — no API key, nothing sent upstream: see what a text gets masked into, whether it restores back, and per-hit details (label, original length, occurrences, and the difference between unique entities and occurrences).
- Panel: the clients page can now **download the placeholder skill package** and copy the install command (same artifact as the Release asset), so coding assistants use placeholders verbatim.
- Engine: non-rewritable protocol state is now driven by a contract table (`engine/protocol_contracts.py`), covering five more carriers (Responses, Gemini, LiteLLM, OpenRouter and Anthropic search results) so a user-added word can no longer corrupt signatures or encrypted blobs into upstream 400s; same-named keys inside tool arguments keep being scanned.
- Engine: events and the browser bridge now report a unified `decision` / `completeness` / `reason_codes`, so the list and the detail dialog can tell masked / scanned-clean / passthrough / blocked / incomplete apart instead of showing “0 hits” for all of them.
- Engine: new “require complete semantic detection” switch (`ner_require_complete`, off by default). When on, a round whose semantic detection did not finish is blocked with 503 before leaving the machine instead of pretending it was scanned.
- Panel: the logs page gained a **write-detail switch** (minimal / detailed) plus a 15-minute time-boxed trace; minimal mode stores no conversation body or plaintext **at the write side** (database, engine stdout, in-memory log, diagnostics bundle and export share one projection), and the word leaderboard keeps label distribution only.
- Panel: the logs page can now **page back into history** (reverse cursor); history mode pauses live refresh and can return to live anytime, and export now matches the current filters exactly and reports exported vs matched totals (truncation is no longer silent).
- Panel: a separate **clear numeric stats** action, independent from clearing logs and clearing audit records — clearing logs no longer risks wiping the trend charts.
- Config: the single-request body limit is now configurable (`config.max_request_body_mb`, default 32 MiB, range 1–256 MiB), consistent across the panel and the engine, so legitimate requests with large attachments are no longer dead ends (it raises the memory and per-request masking-time budgets accordingly).
- Engine: a new per-leaf result cache — when a client resends the whole history every turn, unchanged text is no longer re-scanned (measured: 14 ms → 1 ms on continuation turns). The key is a process-key digest; the value is the masked text plus the placeholder list, and **no masked value is stored**; every entry also re-verifies that its placeholder still points at the original it was created for.
- Engine: the semantic-recognition cache capacity is configurable (`MASKIT_NER_CACHE_MAX` / `MASKIT_NER_CACHE_CHARS`, default 4096 → 32768 entries) and the model is now warmed up at startup instead of during the first user request.
- Logs: failure events now carry structured attribution fields (owner: engine / upstream / client / DNS / egress proxy, plus the exception type), included in exports and the diagnostics bundle.
- Panel: the settings page now shows the effective semantic-recognition values (available cores / concurrency / ONNX threads / per-second budget), so “why is my CPU pegged” no longer requires digging through logs.
- Panel: enabling “require complete semantic detection” now warns about the long-conversation risk (the longer the history, the more likely it exceeds the budget and gets blocked).

### Changed
- Engine: the `before_ts` time cursor shares the same filters as `before_seq`; a malformed time value now means "no time limit" instead of an error.
- Benchmarks: `scripts/bench_mask.py` gains reproducible NER cold/warm, long-context and 1/4/8-concurrency groups, and fixes three sample designs that produced misleading numbers (concurrency sweep without a fixed total, repetitive long documents, and cross-tier segment cache hits).
- Benchmarks: `bench_mask.py` gains a **multi-turn long-conversation** group and fixes two samples that were served from cache (fixed text and a reused session id turned “cache hit” into “masking performance”).
- Engine: the response-side "do not restore" block types now come from the same contract table as the request side, so signed reasoning blocks (OpenRouter `reasoning_details`) behave identically on the whole-body and SSE restore paths.
- Engine: the 413 size-gate response now carries `hint`/`blocking` and the unified report (same shape on the proxy and extension paths), so oversized requests are attributable; also fixed the stale `_MAX_REQUEST_BODY` comment claiming masking still runs on the event loop.
- Logs: retention is now driven by a background task in the panel instead of only triggering when the logs page happens to be open (disk growth does not depend on anyone watching it).
- Engine: the semantic-recognition result cache is now keyed by a **process-key digest** and stores only positions and categories, rebuilding the text from the current input on a hit — the cache no longer extends how long plaintext stays in memory (hit/miss behaviour is unchanged, and a model or detection-version change can never reuse stale results).

## [0.7.0] - 2026-10-02

### 修复
- 引擎：NER 请求预算过期不再续期，取消与等待不再额外开启推理窗口。
- 引擎：修复真实流取消、垃圾回收重入与压缩响应配额，避免迟到回复、假 503 和响应漏审计。
- 构建：隔离发布构建并验收真实 frozen 引擎，保留本机运行数据，拒绝不完整模型包。
- 构建：`--release-only` 暂存根改到磁盘固定路径（拒绝默认落在 tmpfs 吃内存），发布前逐个断言产物内确实含引擎与 NER 模型，并把 `zstandard` 显式写进 requirements。
- 面板：未知连接策略不再使整份配置回退；桌面控制面请求不再经过环境代理。
- 面板：统一 HTTP/2 缺省为关闭，保留用户明确选择，避免模板与运行配置口径不一致。
- 引擎：自定义词表里的 `re:` 词不再能拖垮整张词表（一个词编译失败曾让自定义词与内置词组一起静默失效）。
- 引擎：无汉字的识别窗口不再送入语义模型，稀疏中文正文的识别耗时降约 74%（实测）。
- 面板：日志列表标注 5xx 来源（上游返回 / 网关拦截 / 代理未运行），上游 503 不再被误读成网关故障。

### 优化
- 引擎：语义识别分段粒度由 20000 字收紧到 4000 字，长会话第二轮重推开销降约 3 倍（实测 2308ms → 778ms）。
- 引擎：事件库在保留策略执行后按需回收死空间（实测 237.5MB → 159MB）。

### 新增
- 诊断：记录真实连接选择与 TLS 阶段，增加本地心跳及 NER 等待指标，避免将无响应一律归因于上游。
- 自检：新增 S35（敏感词表未生效）与 S36（事件库死空间未回收）。
- 面板：`/api/status` 外发词表生效口径（配置词数 / 引擎生效词数 / 问题清单）。

---

### Fixed
- Engine: expired NER request budgets no longer renew, and cancellation or waiting cannot grant extra inference windows.
- Engine: fixed native stream cancellation, GC reentrancy and compressed-response admission to prevent late replies, spurious 503s and skipped audits.
- Build: isolate release builds and verify the actual frozen engine, preserving local runtime data and rejecting incomplete model bundles.
- Build: `--release-only` now stages on a fixed on-disk path (refusing a tmpfs default that ate RAM), every artifact is asserted to actually contain the engine and NER model before release, and `zstandard` is declared explicitly in requirements.
- Panel: unknown connection policies no longer reset the entire configuration; desktop control-plane requests bypass environment proxies.
- Panel: default HTTP/2 consistently to off while preserving explicit choices, avoiding drift between templates and runtime configuration.
- Engine: one broken `re:` word can no longer take down the whole word table (a single bad pattern silently disabled custom and built-in groups together).
- Engine: recognition windows without CJK characters are no longer sent to the semantic model — ~74% less inference time on sparsely-Chinese content (measured).
- Panel: the log list now labels the origin of 5xx (upstream / gateway block / proxy stopped); an upstream 503 is no longer misread as a gateway failure.

### Changed
- Engine: semantic-recognition segment size tightened from 20000 to 4000 chars — ~3x cheaper re-push on the second turn of a long session (measured 2308ms -> 778ms).
- Engine: the event DB reclaims dead space after the retention pass (measured 237.5MB -> 159MB).

### Added
- Diagnostics: record actual connection selection and TLS phases, with local heartbeat and NER wait metrics instead of assuming every missing response is an upstream failure.
- Self-check: new S35 (sensitive words not taking effect) and S36 (event DB dead space).
- Panel: `/api/status` now exposes word-table effect counts (configured / engine-active / issues).

---

## [0.6.2] - 2026-09-29

### 新增
- 桌面端：支持 Linux amd64 与 arm64 架构桌面安装包（`.deb` 与 `.AppImage` 格式）。
- 脚本：新增 Linux 本地一键打包（`build.sh`）与热更新部署（`scripts/local-dev-deploy.sh`）脚本。

### 优化
- 发布：更新器元数据生成脚本支持识别 Linux 双架构独立签名与更新直链。
- 测试：修复门禁脚本与冒烟测试在虚拟环境为符号链接时的工具定位。

---

### Added
- Desktop: added Linux desktop package support for amd64 and arm64 architectures (`.deb` and `.AppImage` formats).
- Scripts: added Linux one-click build (`build.sh`) and local hot-update deployment (`scripts/local-dev-deploy.sh`) scripts.

### Changed
- Release: updater metadata generation script now distinguishes independent signatures and update URLs for both Linux architectures.
- Tests: fixed tool and binary discovery in verification and smoke tests under symlinked virtual environments.

---

## [0.6.1] - 2026-09-28

### 修复
- 引擎：语义识别的单请求预算上限由固定 60 秒改为可配置（默认 **10 秒**）—— 冷缓存一轮就能吃满 60 秒，把请求推过客户端 180 秒超时窗口（实测脱敏 58.5s + 上游首包 91.7s ≈ 150s）。
  ⚠️ **行为变更**：升级后大会话（≳100KB）的语义识别会更容易降级 —— 手机号/邮箱/身份证/密钥等**规则类脱敏不受任何影响**，只有专用模型才能识别的自由文本中文人名/机构/详细地址会漏。需要旧口径请在设置页调大「单请求识别预算」，或设环境变量 `MASKIT_NER_REQ_BUDGET_S`。
- 引擎：连接异常事件（`resp=0`）补上 `mask=` 与 `upstream_wait=`，一眼区分「卡在脱敏」还是「卡在上游」。
- 引擎：超长文本不再「整条不做语义识别」，改为按窗口分段识别 —— 长会话里的大段正文不再整段漏码。
- 面板：日志 tail 通道加长度上限；内存溢出补可归因日志（此前 OOM 只有堆栈、没有端点）。

### 新增
- 设置页：可配置语义识别单请求预算上限（环境变量 `MASKIT_NER_REQ_BUDGET_S` 可硬盘覆盖）。
- 引擎：语义识别缓存命中率与超长文本分段计数随 `/api/engine/metrics` 外发，冷热差异不再靠人肉翻事件库。

---

### Bug Fixes
- Engine: the per-request NER budget cap is now configurable (default **10s**, was a fixed 60s) — a cold cache could burn the full 60s and push the request past the client's 180s timeout (measured: 58.5s masking + 91.7s upstream ≈ 150s).
  ⚠️ **Behaviour change**: after upgrading, semantic recognition degrades sooner on large sessions (≳100KB). Rule-based masking (phones, emails, ID numbers, secrets) is **unaffected** — only free-text Chinese names, organisations and addresses are affected. To restore the old behaviour, raise “Per-request NER budget” in Settings or set `MASKIT_NER_REQ_BUDGET_S`.
- Engine: connection-error events (`resp=0`) now carry `mask=` and `upstream_wait=`, so "stuck in masking" and "stuck upstream" are distinguishable at a glance.
- Engine: over-long text is no longer skipped entirely by semantic recognition; it is now segmented, so big bodies in long sessions are no longer left unmasked.
- Panel: the log tail channel now has a length cap, and out-of-memory errors log an attributable endpoint (previously a bare traceback).

### Added
- Settings: the per-request NER budget cap is configurable (env `MASKIT_NER_REQ_BUDGET_S` overrides it).
- Engine: NER cache hit/miss counters and long-text segmentation counts are exported via `/api/engine/metrics`.

---

## [0.6.0] - 2026-09-28

### 修复
- 引擎：修复大模型生成代码时改写凭据标签（如将连接串 CONNSTR 改写为 PASSWORD/SECRET）导致无法还原的问题，引入凭据标签同义互通反查。
- 引擎：修掉"长会话拖慢整个代理"的队头阻塞——审计扫描窗口由 512KB 收到 128KB 并加时间预算，脱敏线程池按核数自适应（1~4），响应侧的**还原/审计/扫描整体移出事件循环**（流式收尾一并下池）。
- 引擎：脱敏队列改为按字节预算与条数上限准入（超限回 503 + `Retry-After`，带抖动），并在 worker 异常路径上也归还名额；首次在内存上给并发设了天花板。
- 引擎：新增端到端上限（默认 120s，`MASKIT_ENGINE_DEADLINE_S`），超时回结构化 503 而不是无限等待；等待超时不会中断已在跑的 worker。
- 引擎：语义识别加进程级并发信号量与每秒推理预算，过载时**降级但不断链**并记录原因（`global_throttled`）；修掉初始化竞态（并发首调可能建出两个 ONNX 会话）。
- 引擎：浏览器扩展链路解除全局串行 —— 脱敏/文件脱敏/流式还原这些重活移出 `_EXT_LOCK`（多标签页并发时不再互相堵），并把「必须持锁」与「必须不持锁」两侧都写成静态守卫。
- 修复：`audit.scan_max` / `parse_max` / `time_budget_ms` 手改 config.json 后被配置归一化抹掉（自检提示让用户改这三个键，却会被自检自己抹掉）；新增：响应侧等待脱敏线程池超过 2s 时留痕（`aux_wait_ms` 进事件、导出与审计弹窗），并把审计耗时/扫描字节/是否截断真正显示在审计详情弹窗里（此前只在后端落库，前端渲染的是永远取不到值的死分支）。
- 引擎：修掉流式收尾下池引入的两处线程归属问题（延后 `_drop` 可能抹掉同一会话的新实例、审计熔断在 aux 线程回写 `flow.response`），并给审计运行时计数器加锁；审计缓存键补上 `ct` 与响应头摘要（同 body 不同头不再回放旧结论）。
- 引擎：请求体不再被解析两遍；响应侧新增可读的「为什么整包」原因与每条请求的脱敏排队时长，事件详情直接可见。
- 引擎：流式收尾（审计 + 响应扫描）下池，并去掉四处 O(body) 白烧；审计只解码"会被用到的文本"（超 2MB 的响应不再为 128KB 扫描窗口把整份 body 解码成字符串），**响应哈希仍是全量 sha256**（证据语义不变）；同轮修掉"进程名取错 CSV 列导致每次端口判定都白跑一次 8s 超时 PowerShell"的老问题，端口快照改为一次 `tasklist` + 一次 CIM 批量归类（含 5s 缓存）。
- 修复：四处 P0 —— 非流式请求用量恒为 0（拿流式字段做判据）、整包路径 `_drop` 漏传 `expect` 会抹掉同会话新实例、S32 读错键名导致「事件库写失败」永不触发、S03 把自身端口误判成被占用。
- 修复：自检的跨线程共享状态补锁（aux 统计、canary 注册表、`peak_wait_ms`），修掉 `_AUX_PENDING` 双减、S11 零样本误报与 OK_NOTES 与已触发结论自相矛盾；测试不再依赖执行顺序。
- 修复：审计探测窗口不再被模块级常量冻结（改 `audit.scan_max` 立即生效）、等待类指标不再因挂在错误的 gate 下永不显示、`peak_wait_ms` 峰值不再被并发覆盖、事件库队列字节默认值校正为 `max(32MB, workers × 8MB)`。
- 引擎：语义识别预算不足时改为**有界等待**（`MASKIT_NER_WAIT_MS`，默认 2s）：等到即推理，等不到仍降级；新增 `budget_waited` 计数区分「补上了」与「真降级」（随 `/api/engine/metrics` 外发；界面与自检结论暂不展示）。

### 新增
- 设置页：一键自检的结论文案跟随界面语言（中/英），英文界面下不再输出中文结论（含诊断包内嵌的同一份结论）。
- 引擎：503 增加来源归因（上游 / 本机熔断 / 兜底层），事件详情与自检都能一眼区分"是上游拒的还是本机拦的"。
- 设置页：新增**一键自检**（设置 → 健康检查与恢复），把端口、队列、语义识别降级、审计截断、磁盘与容器 CPU 限流翻译成「问题 + 证据 + 建议动作」，只读本机数据、不联网；诊断包同步升级为 schema 2 并内嵌该结论。
- 引擎：新增 `/api/engine/metrics`（走 `/api/` 三重校验）暴露脱敏队列、审计耗时与语义识别治理器状态，供面板与自检共用。

### 文档
- 文档：`README` 增「多并发调优与 503 排查」章节（503 四种来源的分辨方法、容器 CPU 配额与 NER 的关系），`SECURITY.md` 登记本轮新增的环境变量并补上"审计扫描预算"这一能力边界。
- 引擎：启动时对「语义识别已开启但模型缺失」显式告警，并在 README 说明 NER 模型不随源码仓库分发。

---

### Bug Fixes
- Engine: fixed placeholder restoration failure when LLMs rewrite credential labels (e.g. CONNSTR to PASSWORD/SECRET) by introducing synonym credential label reverse-lookup.
- Engine: fixed head-of-line blocking behind long conversations — the audit scan window is now 128KB (was 512KB) with a time budget, the masking pool adapts to the core count (1–4), and response-side restore/audit/scan moved off the event loop (**the streaming finish path included**).
- Engine: the masking queue now admits by byte budget and in-flight count (over-limit answers 503 + a jittered `Retry-After`) and returns the quota even when a worker raises; concurrency finally has an explicit ceiling.
- Engine: added an end-to-end deadline (120 s by default, `MASKIT_ENGINE_DEADLINE_S`) that answers a structured 503 instead of waiting forever; hitting it does not kill the in-flight worker.
- Engine: NER now has a process-wide inference semaphore and a per-second budget, degrading (with a recorded reason, `global_throttled`) instead of breaking the chain; fixed an init race where concurrent first calls could build two ONNX sessions.
- Engine: removed global serialization on the browser-extension path — masking, document masking and stream restore moved out of `_EXT_LOCK` (concurrent tabs no longer queue behind each other), with static guards for both "must lock" and "must not lock".
- Fixed: `audit.scan_max` / `parse_max` / `time_budget_ms` were silently erased from config.json by config normalization (the self-check told users to edit them, then wiped them itself). Added: response-side wait on the masking pool is now traced when it exceeds 2s (`aux_wait_ms` in events, exports and the event dialog), and audit cost/scan-bytes/truncation are now actually rendered in the audit detail dialog (previously DB-only, with the frontend rendering a branch that could never resolve).
- Engine: fixed two thread-ownership issues introduced by offloading the stream finish (a deferred `_drop` could wipe a re-created session, and the audit block wrote `flow.response` on an aux thread), locked the audit runtime counters, and added `ct` + response-header digest to the audit cache key (identical bodies with different headers no longer replay a stale verdict).
- Engine: request bodies are no longer parsed twice; responses now carry a readable "why whole-body" reason and each request reports its mask-queue wait, both visible in the event detail.
- Engine: the streaming finish path (audit + response scan) is now offloaded, and three needless O(body) passes were removed. The audit now decodes only the text it actually uses (responses over 2 MB no longer get a full-body decode just to feed a 128 KB scan window) while the response hash stays a full sha256 (evidence semantics unchanged). The same pass fixed a long-standing bug where the process name was read from the wrong CSV column (so every port ownership check fell through to an 8 s-timeout PowerShell call); port snapshots now use one `tasklist` plus one batched CIM query with a 5 s cache.
- Fixed four P0 defects: non-streaming requests always reported zero usage (a stream-only field was used as the predicate), the whole-body path dropped the `expect` argument and could wipe a re-created session, S32 read the wrong key so "event DB writes failing" never fired, and S03 mistook Maskit's own port for a foreign one.
- Locked the self-check's cross-thread state (aux stats, canary registry, peak_wait_ms) and fixed the double decrement of `_AUX_PENDING`, S11's zero-sample false positive and OK_NOTES contradicting fired findings; tests no longer depend on execution order.
- The audit probe window is no longer frozen by a module-level constant (editing audit.scan_max takes effect immediately), wait metrics are no longer hidden behind the wrong gate, peak_wait_ms can no longer lose updates under concurrency, and the event-queue byte default is corrected to max(32MB, workers x 8MB).
- Engine: NER now waits inside a bounded window (MASKIT_NER_WAIT_MS, 2 s default) when the budget is exhausted — it infers if the budget returns, degrades otherwise; the new budget_waited counter separates "recovered" from real degradation and is exported via /api/engine/metrics only (the UI and the self-check conclusion do not show it yet).

### Added
- Settings: the one-click self-check conclusion now follows the UI language (Chinese/English); an English UI no longer shows Chinese conclusions, including the copy embedded in the diagnostics bundle.
- Engine: 503s are now attributed (upstream / local fail-closed / fallback), so the event detail and the self-check tell upstream rejections apart from local blocking at a glance.
- Settings: added **One-click self-check** (Settings → Health Check & Recovery) turning ports, queueing, NER degradation, audit truncation, disk and container CPU throttling into "problem + evidence + suggested action". It reads local data only and never goes online; the diagnostics bundle is now schema 2 and embeds the conclusion.
- Engine: added `/api/engine/metrics` (behind the `/api/` triple guard) exposing mask-queue, audit-timing and NER-governor state for both the panel and the self-check.

### Docs
- Docs: `README` gained a "concurrency tuning & 503 triage" section (how to tell the four 503 sources apart, why container CPU quotas matter for NER); `SECURITY.md` registers the new environment variables and documents the audit scan budget as an explicit capability boundary.
- Engine: warns loudly at startup when semantic recognition is enabled but the model is missing, and the README now states that the NER model is not distributed with the source repo.

## [0.5.0] - 2026-09-24

### 新增 / Added
- 审计：凭据示例不再被报成「响应投毒」（代码块/低熵形态降为仅记录），新增三档审计预设与审计阻断开关、主动探针临时启用、以及「高风险操作时间线」视图（仅该视图放宽门槛，默认视图不受影响）。
  *Audit: credential examples are no longer reported as response poisoning (code blocks / low-entropy shapes are downgraded to record-only), plus three audit presets with a blocking switch, temporary probe enablement, and a Risky-action timeline view that relaxes the severity floor only inside that view.*
- 审计：新增「危险命令拦截」（审计页 → 主动安全探针）——检测模型下发的删根、擦盘、删库、fork 炸弹等命令并落库到高风险操作时间线，默认只记录不改写，可切换改写或阻断，支持自定义规则与白名单。
  *Audit: added dangerous-command interception (Audit page → Active security probe tab) — detects model-issued commands such as root deletion, disk wiping, DROP DATABASE and fork bombs into the risky-action timeline. Record-only by default, switchable to rewrite or block, with custom rules and an allow list.*

### 修复 / Bug Fixes
- 引擎：修复长会话脱敏阻塞整个代理、在途请求被上游掐断后返回 502 的问题——脱敏重活移出 mitmproxy 事件循环，并给语义识别加单请求总预算、扩充结果缓存。
  *Engine: fixed long conversations blocking the whole proxy and surfacing 502s when in-flight upstream connections were dropped — masking now runs off the mitmproxy event loop, with a per-request NER budget and a larger result cache.*
- 引擎：共享全局态（占位符复用表、自定义词映射、配置热重载）改为互斥 + 原子发布，修掉多线程下的后缀撞车与半填充词表；PEM 私钥规则由 O(n²) 降为线性（1.49MB 病态输入 880ms → 25ms）。
  *Engine: shared state (placeholder reuse tables, custom-word mappings, hot reload) is now mutex-protected and published atomically, fixing cross-thread suffix collisions and partially published word lists; the PEM private-key rule is now linear instead of O(n²) (1.49 MB pathological input: 880 ms → 25 ms).*
- 引擎：占位符复用表改为按窗口批量回收，表满时签发 300 个新占位符由 144ms 降到 1.6ms；TTL 与容量语义不变。
  *Engine: reuse-table pruning is now batched per time window — 300 new placeholders against a full table dropped from 144 ms to 1.6 ms, with TTL and capacity semantics unchanged.*
- 引擎：自定义词映射重建改为「锁外派生 + 锁内换表」（锁序 _SYNC_LOCK → _STATE_LOCK），配置保存时不再让在途脱敏干等。
  *Engine: custom-word mapping rebuild now derives outside the state lock and only swaps tables under it (lock order _SYNC_LOCK → _STATE_LOCK), so live masking no longer waits on a config save.*
- 引擎：语义识别（NER）限流口径修正 —— 单请求总预算由固定 2s 改为按体积伸缩（10s 打底、每 MB +120s、封顶 60s），单条长度上限 2000→20000 字；本轮发生降级时 MASK 事件带 ner_truncated 与原因，不再静默。旧口径可用 `tests/measure_ner_coverage.py --budget 2.0` 复现（200 条/43KB 实测 74~101/200 个人名明文出网，截断点随机器负载浮动，所以不给单一数字），修复后 0。
  *Engine: corrected NER throttling — the per-request budget is now size-aware (10 s base, +120 s/MB, capped at 60 s) instead of a fixed 2 s, and the per-text limit went from 2 000 to 20 000 chars; a degraded round is now flagged in the MASK event via ner_truncated and its reasons. Reproduce the old behaviour with `tests/measure_ner_coverage.py --budget 2.0` (74–101 of 200 names leaked in a 43 KB conversation; the cut point floats with machine load, hence a range), 0 after.*
- 引擎：语义识别的时间闸门按**实测**成本重新标定（单位成本 93µs/字节）。单次调用上限 2s→10s：旧值跑不完一条上限长度文本，导致超长无实体文本每轮重付冷推理且永不进缓存（实测 20000 字 2123/2013/2049ms → 修复后 4806ms 一次、之后 1ms）。请求级每 MB 系数 20s→120s：旧值比实测成本小约 8 倍，中等体积请求会在半途静默停手。
  *Engine: re-calibrated the NER time gates against measured cost (93 µs/byte). Per-call limit 2 s → 10 s: the old value could not finish a max-length text, so long entity-free text re-paid cold inference every round and never entered the cache (measured 2 123/2 013/2 049 ms at 20 000 chars → 4 806 ms once, then 1 ms). Per-MB request budget 20 s → 120 s: the old value was ~8× below measured cost, so mid-sized requests silently stopped halfway.*
- 引擎：跳过原因统一记账（按请求 + 进程级）并加锁；单次超时/推理失败改在发生处记账（`deadline`/`infer_failed`），不再用一个笼统键把异常误报成超时。
  *Engine: skip reasons are now accounted uniformly (per request and process-wide) behind a lock; call timeout and inference failure are recorded where they happen (`deadline` / `infer_failed`) instead of one blanket key that mislabelled exceptions as timeouts.*
- 前端：设置页与事件详情弹窗共用同一份跳过原因标签；设置页改为遍历引擎上报的键（未登记的回退原始键名），不再因为漏加一行就把整条降级从界面上消失。
  *Frontend: the settings page and the event detail dialog now share one set of skip-reason labels; the settings page iterates the keys the engine actually reports (unknown ones fall back to the raw key), so a missing line can no longer hide a whole degradation reason from the UI.*
- 引擎：单次语义识别调用上限 2s→6s —— 旧值低于「跑完一条上限长度文本」的成本，于是超长且无实体的文本每轮都重付冷推理且永不进缓存（实测 20000 字 4806ms/轮 → 修复后 1ms）。
  *Engine: raised the per-call NER time limit from 2 s to 6 s — the old value was below the cost of finishing a max-length text, so long entity-free text re-paid cold inference every round and never entered the cache (measured 4 806 ms per round at 20 000 chars → 1 ms after).*
- 引擎：浏览器扩展链路（`/api/ext/mask`、`/api/ext/mask-file`）补上语义识别总预算与降级上报——响应带 `ner_skipped`，事件带降级标记；降级但零命中时也记一条，不再静默。
  *Engine: the browser-extension endpoints (`/api/ext/mask`, `/api/ext/mask-file`) now open a total NER budget and report degradation — the response carries `ner_skipped` and the event is flagged; a degraded round with zero hits is still recorded instead of staying silent.*
- 前端：事件详情弹窗新增「本轮语义识别降级」提示（原因 × 条数，中英双语）；MASK 与 RESTORE 两条事件都带该信息，详情回源 RESTORE 时同样可见。
  *Frontend: the event detail dialog now shows a “semantic recognition degraded this round” notice (reason × count, bilingual); the flag is carried on both MASK and RESTORE events, so detail lookups that resolve to RESTORE show it too.*
- 本地部署脚本：修复「替换安装文件时命中句柄占用即中止、且中止后不拉起客户端」的问题——改为等进程退出 + 删除/覆盖重试 + 引擎目录先落暂存再换名就位，并保证失败时也拉起客户端并回滚备份。
  *Local deploy script: fixed a mid-swap abort on locked files that left the client stopped — it now waits for processes to exit, retries delete/copy, stages the engine dir before swapping it in, and always restarts the client with a backup rollback on failure.*
- 发版流程：修复预发布版本号（`X.Y.Z-beta.N`）被过严正则误判为「版本分叉」而中止打包的问题，并让版本校验失败时回滚全部版本文件。
  *Release: fixed prerelease versions (`X.Y.Z-beta.N`) being wrongly reported as a version mismatch due to over-strict regexes, and version-check failures now restore all version files.*
- 发版流程：预发布判定改为「tag 含 `-` 即预发布」（不再只认 `-beta`/`-alpha`/`-rc`）。原先 `vX.Y.Z-dev` 这类 tag 会被当成正式版发布，进而产出 `latest.json` 并把 `ghcr.io/...:latest` 指向非正式构建。
  *Release: pre-release detection now treats any tag containing `-` as a pre-release (instead of only `-beta`/`-alpha`/`-rc`). Previously a tag like `vX.Y.Z-dev` was published as a stable release, producing `latest.json` and repointing `ghcr.io/...:latest` at an unreleased build.*

### 优化 / Changed
- 文档：修正对外能力表述——扩展站点支持改为「ChatGPT / Claude / DeepSeek 三站已实测」，附件脱敏补充「未适配站点文件本体不脱敏并弹窗提示」，规则库写明「21 类中默认开启 7 类」，NER 标注默认关闭，并说明「引擎不可用时明文直通＝不脱敏」。
  *Docs: corrected capability claims — extension site support now states the three verified sites, attachment masking notes unmasked files on unsupported sites with a popup warning, the rule library states that 7 of 21 rules are on by default, NER is marked off by default, and "engine down = unmasked passthrough" is documented.*

## [0.4.0] - 2026-09-21

### 新增 / Added
- 浏览器扩展：新增 XMLHttpRequest（XHR）请求与单文件/Blob 直传拦截，覆盖现代 Web AI 文件上传与对象存储直传场景。
  *Browser extension: added XMLHttpRequest and single-file/Blob upload interception, protecting modern web-AI file uploads and object storage direct uploads.*
- 浏览器扩展：设置页新增老版 Office 文档（.doc / .xls）自动转码脱敏开关，并补注文档格式支持清单。
  *Browser extension: added auto-convert & mask switch for legacy Office documents (.doc / .xls) with supported formats list in settings.*
- 拦截日志：类型筛选新增「浏览器扩展」大类并精简收敛底层原语，列表强化显示浏览器扩展与文档脱敏徽标。
  *Logs: added Browser Extension category in type filter, consolidated low-level primitives, and added badges for extension and doc masking.*

### 修复 / Bug Fixes
- 浏览器扩展：修复 DeepSeek 网页版 XHR 流式回复中占位符未还原的问题（XHR 响应还原目前**仅覆盖 DeepSeek**；附件上传场景尚未适配）。
  *Browser extension: fixed unrestored placeholders in XHR-streamed replies on DeepSeek web (XHR response restoration currently covers DeepSeek only; attachment uploads are not yet supported).*
- 浏览器扩展：修复脱敏桥超时响应未还原与广泛模式读取失败导致的静默放行问题。
  *Browser extension: fixed unrestored responses after bridge timeouts and silent bypasses when wide-mode failed to load.*
- 浏览器扩展：修复正文特征词导致会话复用失效，以及 URLSearchParams 表单与同步 XHR 漏脱敏问题。
  *Browser extension: fixed session-reuse breakage caused by typing-probe false positives, plus unmasked URLSearchParams and sync XHR requests.*
- 浏览器扩展：修复服务工作线程冷启动后「引擎不可用即阻断」配置丢失，以及部分异常路径静默放行的问题。
  *Browser extension: fixed lost "block on engine down" setting after service-worker restart and silent bypasses on exception paths.*
- 浏览器扩展：完善 Claude / DeepSeek 等网页端单数 `/completion` 路径匹配，补全签发表校验诊断日志。
  *Browser extension: improved path matching for singular `/completion` endpoints and added diagnostic logs for signature validation.*
- 引擎：修复 Office 文档重压缩体积无法与原始字节对齐时静默返回原文的问题，确保始终脱敏出网。
  *Engine: fixed original document leakage when OOXML recompression length misaligned, ensuring masked bytes are always sent.*
- 引擎：修复大写 Content-Type 响应未还原与超大 JSON 解析阻塞问题，收敛漏脱敏上报去重缓存。
  *Engine: fixed unrestored uppercase Content-Type responses, event loop stalls on huge JSONs, and bounded extension deduplication tables.*
- 发版流程：修复浅克隆下扩展变更自动检测失效的问题。
  *Release: fixed extension change detection failing under shallow git clones.*

## [0.3.2] - 2026-09-20

### 修复 / Bug Fixes
- 浏览器扩展：修复桌面端设置页误将内部协议 `http://tauri.localhost` 显示为服务地址的问题，自动回显 `http://127.0.0.1:5801` 并增加一键复制按钮。
  *Browser extension: fix desktop settings page incorrectly showing internal `http://tauri.localhost` as engine URL; now displays `http://127.0.0.1:5801` with a one-click copy button.*

### 优化 / Changed
- 界面文案产品化：全面去除开发者内部黑话，将“旋转令牌”通俗化优化为“重置令牌”，重构服务异常阻断与高级设置的引导说明。
  *UI text refinement: replaced internal jargon with clear descriptions, renamed "Rotate Token" to "Reset Token", and polished explanations across settings.*

## [0.3.1] - 2026-09-19

### 新增 / Added
- 全端全功能一体包（Windows、macOS、Docker）：CI 发布流水线自动化拉取本地 NER 模型并完整打包入包，开箱即用，免去手动下载配置。
  *All-in-One packages across all platforms (Windows, macOS, Docker): the CI release pipeline automatically fetches the local NER model and bundles it out-of-the-box, eliminating manual downloads.*

### 优化 / Changed
- Docker 构建加速与解耦：前端静态构建改用宿主原生架构执行（`--platform=$BUILDPLATFORM`），消除 QEMU 模拟 Node.js 导致的构建死锁；桌面端发版与 Docker 解耦。
  *Docker build acceleration & decoupling: frontend static build now runs on host native platform (`--platform=$BUILDPLATFORM`), removing QEMU emulation deadlocks; desktop release decoupled from Docker.*

## [0.3.0] - 2026-09-19

### 新增 / Added
- 内置本地 AI 实体识别（NER，配置项 `ner_enabled`，默认关）：本地 ONNX 模型识别人名 / 机构 / 地址，补齐确定性规则覆盖不到的自由文本；设置页可开关，模型或依赖缺失时界面与健康检查直接说明原因。实测「规则 + NER」联动下，样例集敏感值的明文残留从 74% 降到 11%。
  **全功能一体包**：Windows 官方安装包已完整内置本地语义识别模型（All-in-One 全功能一体包，开箱即用，无需额外下载或配置），设置页开启即可直接使用。
  *New built-in local AI entity recognition (NER, config key `ner_enabled`, off by default): a local ONNX model detects person / organisation / address names that deterministic rules cannot cover; toggle in settings, and the reason is spelled out in the UI and health check when the model or its dependencies are missing. On the sample set, combining rules with NER cuts the plaintext left in requests from 74% to 11%.*
  *All-in-One package: The official Windows installer bundles the local semantic recognition model out-of-the-box (All-in-One package, no extra downloads or configuration required), simply enable in settings to use.*
- 安全审计新增提示词注入检测：伪造协议级系统轮次、索要系统提示词、凭据外发指令、base64/转义编码绕过；泛化的「忽略以上指令」句式只在同现客观载荷时上报，避免把模型讲解误判成投毒。
  *New prompt-injection detection in the security audit: faked protocol-level system turns, system-prompt extraction requests, credential-exfil instructions, and base64/escape-encoded payloads; ordinary "ignore previous instructions" wording is reported only when an objective payload co-occurs, so explanations are not mistaken for poisoning.*
- 扩展设置页新增「推荐站点」：18 个国内外常见 AI 站点一键授权添加（含 Gemini / Grok / Perplexity / Copilot / Mistral / Poe、DeepSeek / 豆包 / 通义千问 / Qwen / Kimi / 元宝 / 智谱 / 文心一言 / 讯飞星火 / 小米 MiMo），路径未实测的站点统一打「未实测」标记。
  *New "Recommended sites" list in the extension options page: 18 common AI sites added with a single grant (Gemini, Grok, Perplexity, Copilot, Mistral, Poe, DeepSeek, Doubao, Tongyi Qianwen, Qwen, Kimi, Yuanbao, ChatGLM, ERNIE Bot, iFlytek Spark, Xiaomi MiMo). Sites whose request paths are unverified are marked as such.*
- 浏览器扩展桥接（`extension/`，Chrome/Edge MV3）：把网页版 AI（ChatGPT / Claude）发出的请求接入本地引擎打码、回包流式还原。100% 本地运算，零外传。
  *Browser extension bridge (`extension/`, Chrome/Edge MV3): routes web-AI (ChatGPT / Claude) requests through the local engine for masking and restores responses as they stream. 100% local, zero egress.*
- 引擎新增 `/api/ext/ping|mask|restore|rotate-token` 四个端点与 `ext_bridge_enabled` / `ext_token` / `ext_block_when_engine_down` / `ext_record_events` 四个配置项。
  *New engine endpoints `/api/ext/{ping,mask,restore,rotate-token}` and config keys `ext_bridge_enabled` / `ext_token` / `ext_block_when_engine_down` / `ext_record_events`.*
- 事件与统计新增「入口」维度（代理链路 / 浏览器扩展）：事件页可筛选，词榜与首页词明细按入口分组同屏，分享战绩卡改为仅统计代理链路并在卡面标注口径。
  *New "ingress" dimension (proxy link vs browser extension) in events and stats: filterable in the log page, word rankings grouped side by side, and the share card now covers only the proxy link with its scope stated on the card.*
- 设置页新增「浏览器扩展」区块（链路开关、访问令牌、旋转确认），高级设置新增「记录浏览器扩展流量」开关（默认开）。
  *New "Browser extension" settings section (toggle, token, rotation confirmation) and a "Record browser-extension traffic" switch under advanced settings (on by default).*
- 内网 IPv6 规则（`IPV6_PRIVATE`，默认关）：fe80:: 链路本地与 fc00::/7 ULA，语义校验排除公网/文档段与 MAC 地址。
  *Private IPv6 rule (`IPV6_PRIVATE`, default off): fe80:: link-local and fc00::/7 ULA, with semantic validation excluding public/doc ranges and MAC addresses.*
- USCC 校验位验证（GB 32100-2015 MOD31）：开启规则后误伤率压至 1/31。
  *USCC check-digit validation (GB 32100-2015 MOD31): false-positive rate down to 1/31 when the rule is enabled.*
- README 部署章节补单端口模式（5802 路径前缀路由）说明。
  *README deployment docs: single-port mode (5802 path-prefix routing) section.*
- 仪表盘新增「出口代理已启用但无客户端勾选」状态横幅与「MASKIT_PANEL_TOKEN 被忽略」提醒（stderr 双写 + 面板可见）。
  *Dashboard banners for "egress enabled but unused" and "MASKIT_PANEL_TOKEN rejected" (now also double-written to stderr).*
- 浏览器扩展静态门禁（`scripts/check-extension.mjs`）并入全量门禁（13 → 14 项）：校验扩展 i18n 双语键集、脚本加载顺序、manifest 与静态站点清单一致性、驼峰 `runAt`、本机外请求等红线；新增 JS 引用的 DOM id 必须存在于对应 HTML（拦住「按钮点了没反应」那一类）。
  *New browser-extension static gate (`scripts/check-extension.mjs`) added to the full gate set (13 → 14 items): checks i18n key parity, script load order, manifest/site-list consistency, camelCase `runAt`, and off-machine request red lines; now also asserts every DOM id referenced by JS exists in the matching HTML (catches the "buttons do nothing" class).*
- 自定义敏感词改用确定性占位符 + 常驻映射：同一敏感词跨会话、跨重启都拿到同一后缀，长任务与 Agent 工具调用不再因 TTL 过期或引擎重启而还原不回来。
  *Custom sensitive words now use deterministic placeholders with a resident mapping: the same word gets the same suffix across sessions and restarts, so long tasks and agent tool calls no longer become unrestorable after TTL expiry or an engine restart.*
- 浏览器扩展新增独立发布包 `Maskit_<版本>_extension.zip`，随 Release 一起分发：扩展不在桌面安装包里，不用源码的用户此前无处可下，现在下载解压即可在 `chrome://extensions` 加载。
  *The browser extension now ships as its own release asset, `Maskit_<version>_extension.zip`: it is not inside the desktop installer, so web-app users without the source tree had nowhere to get it — now they download, unzip and load it from `chrome://extensions`.*

### 修复 / Bug Fixes
- 引擎：消除 Python 3.13 下子进程 `bufsize=1` 二进制模式运行告警，发版脚本增加一体包模型完整性自检与前置门禁。
  *Engine: eliminate Python 3.13 RuntimeWarning on subprocess `bufsize=1` in binary mode; add all-in-one bundle preflight gates to release scripts.*
- 脱敏：NER 在经规则替换后的文本上识别实体会导致上下文被截断、实体残片明文泄漏（如「西城区」被打码后，其后的「网点营业厅」失去前序上下文漏打码）；现改为在干净原文上抽取实体，经 OffsetMap 坐标单调映射回伤疤文本，并在映射失败时安全降级跳过 NER、绝不混用原文与伤疤坐标系，同起点实体按长区间贪心优先。
  *Masking: running NER on text already mutated by deterministic rules truncated entity context and leaked entity fragments in plaintext (e.g. masking "Xicheng District" caused following "branch office" to lose its context and go unmasked); entities are now extracted from the clean original and translated back via a monotonic OffsetMap, with graceful degradation skipping NER on mapping errors without cross-coordinate mixing, and greedy longest-span selection for identical starts.*
- 脱敏：数值型敏感值、敏感值当 JSON 键名、重复键三条路径既不命中也不抛异常，于是「零改写」分支把客户端原始字节原样放行——明文出网，而 fail-closed 只兜异常、兜不住「静默判定为无需改写」。三条现全部覆盖；协议字段、工具名与 JSON Schema 骨架按白名单保持原样。
  *Masking: three paths — numeric sensitive values, sensitive values used as JSON key names, and duplicate keys — neither matched nor raised, so the zero-rewrite branch passed the client's original bytes upstream verbatim: plaintext egress, and fail-closed only covers exceptions, not a silent "no rewrite needed". All three are covered now; protocol fields, tool names and JSON Schema skeletons stay intact via a whitelist.*
- 脱敏：顶层键名扫描只在扩展链路生效，同一个请求体走代理链路与走扩展链路会得到不同结果；两条链路现共用同一判据。
  *Masking: top-level key-name scanning only applied on the extension link, so the same request body produced different results through the proxy link; both links now share one predicate.*
- 扩展：扩展总开关关闭（`enabled=false`）后内容脚本照常送原文打码、页面照常被改写，而 popup 显示「已停用」；文本与文档两条链路现已认账。
  *Extension: with the master switch off (`enabled=false`) the content script kept sending plaintext for masking and pages kept being rewritten while the popup said "disabled"; both the text and document links now honour it.*
- 扩展：令牌可被发往任意外域——地址框旁的「测试连接」按钮不校验主机就存盘，而真正持有令牌的 SW 也不自校验；现校验下沉到 SW 并只允许 127.0.0.1 / localhost。
  *Extension: the token could be sent to an arbitrary host — the "test connection" button next to the address field saved without any host check, and the service worker that actually holds the token did not validate either; the check now lives in the service worker and only 127.0.0.1 / localhost are allowed.*
- 扩展：≤80 字符的写请求整体跳过打码（与 multipart 分支不一致），属静默未脱敏；下限降到 8。
  *Extension: write requests of ≤80 characters skipped masking entirely (inconsistent with the multipart branch) — a silent unmasked path; the floor is now 8.*
- 扩展：24–25MB 的 Office 附件必然硬失败——整份文件 base64 后超过引擎 32MB 闸门，413 被当作阻断 → 页面直接网络错误；上限对齐到 23MB，超限改为原样透传并明确提示未脱敏。
  *Extension: Office attachments of 24–25 MB always failed hard — base64 inflation pushed the body past the engine's 32 MB gate, the 413 counted as blocking, and the page saw a network error; the limit is aligned to 23 MB, and oversize files now pass through with an explicit "not masked" notice.*
- 扩展：`/api/ext/restore` 没有体积闸门、`ext_frames` 没有条目上限，启用站点上的任意脚本都能用它撑大引擎内存；两者均已补齐。
  *Extension: `/api/ext/restore` had no size gate and `ext_frames` no entry cap, so any script on an enabled site could grow engine memory; both are now bounded.*
- 扩展：扩展链路落库的事件对象里，`dialog` / `req_preview` / `resp_preview` 直接写原文切片，凭据因此进了本地事件库（`items[]` 本身是合规的，只看它就发现不了）；写侧与 `/api/logs` 读侧现都做凭据清洗，普通 PII 原文照常保留供详情弹窗对照。
  *Extension: the event object written by the extension link put raw text slices into `dialog` / `req_preview` / `resp_preview`, so credentials reached the local event store (`items[]` itself was compliant, which is why checking only that missed it); both the write side and the `/api/logs` read side now scrub credentials, while ordinary PII plaintext is still kept for the detail dialog's before/after view.*
- 审计：PEM 私钥正则在「只有 BEGIN 没有 END」的文本上二次回溯，12KB 响应体就要约 2.8 秒，且审计扫描吃全量响应体——上游回一个畸形 4xx 就能把本地代理的事件循环 CPU 打满；现改为线性匹配，并把扫描输入截断（结构化解析仍读全量，否则换芯检测会静默失效）。
  *Audit: the PEM private-key regex backtracked quadratically on text containing BEGIN without END — about 2.8 s for a 12 KB body — and the audit scanned the full response body, so one malformed 4xx from upstream could saturate the local proxy's event loop; matching is now linear and the scan input is truncated (structured parsing still reads everything, otherwise model-swap detection would silently break).*
- 审计：换芯检测被「响应文本块非空」门控，而判定只看模型字段——tool_use-only、reasoning-only、拒答空答这些编程助手最主流的响应形态上检测完全失效，恶意中转回一个空 content 即可绕过；现已与文本内容解耦。
  *Audit: model-swap detection was gated on "response has a non-empty text chunk" although the verdict only uses the model field, so it was entirely dead on the response shapes coding assistants mostly produce — tool_use-only, reasoning-only, empty refusals — and a malicious relay could bypass it by returning an empty content; detection is now decoupled from text content.*
- 审计：审计中心在后端读失败（引擎未运行 / 5xx / 令牌失效）时渲染成绿色「未发现任何篡改或泄漏行为」，把「没读到」显示成「没问题」；现区分两者并给出失败原因与重试，同时说明筛选只作用于最近 500 条。
  *Audit: when the backend read failed (engine down, 5xx, invalid token) the audit centre rendered the green "no tampering or leakage detected" state, showing "nothing read" as "nothing wrong"; the two are now distinguished, with the failure reason and a retry, plus a note that filters only cover the latest 500 events.*
- 审计：清空审计留痕没有二次确认，误点即丢失唯一的篡改/泄漏证据链；已加确认弹窗。
  *Audit: clearing the audit trail had no confirmation, so a stray click destroyed the only tampering/leakage evidence chain; a confirmation dialog was added.*
- 审计：讲解 ChatML / Llama 特殊 token 的回复被误判为提示词注入（成对标记齐全即报 MEDIUM）；现跳过代码块并要求标记行首锚定，真注入照常检出。
  *Audit: answers explaining ChatML / Llama special tokens were flagged as prompt injection (two markers in a row meant MEDIUM); code blocks are now skipped and a marker must be line-anchored, while real injections are still detected.*
- 审计：SSE 解析要求 `data:` 后必须带空格，而规范里空格可选——发无空格形态的上游会让换芯与流异常两项审计静默失效（还原路径不受影响，所以表面完全正常）；已按规范解析。
  *Audit: SSE parsing required a space after `data:` although the spec makes it optional, so upstreams emitting the no-space form silently disabled model-swap and stream-anomaly auditing (the restore path was unaffected, so nothing looked wrong); parsing now follows the spec.*
- NER：预算耗尽或推理异常时的**部分**实体结果被写入缓存，此后该文本一直返回残缺结果；同时空结果不写负缓存导致无实体的长文本每次重复推理。现只缓存完整结果，空结果也进负缓存。
  *NER: partial entity results from an exhausted budget or an inference error were written to the cache, so that text kept returning incomplete results; empty results were also not negatively cached, so entity-free long text was re-inferred on every request. Only complete results are cached now, and empty results are negatively cached too.*
- NER：地名识别把「北京」「中国」这类裸行政区当成地址脱敏，造成过度脱敏与词榜噪声；现跳过裸行政区（含区/省/自治区后缀），带门牌或机构名的地址照常识别。
  *NER: bare administrative names such as "Beijing" or "China" were masked as addresses, over-masking and polluting the word rankings; bare regions (including district/province/autonomous-region suffixes) are now skipped, while addresses carrying a street number or a place name are still detected.*
- NER：实体标签为空时索引越界抛异常；重叠实体的裁剪按起点整条丢弃，在被后缀扩充推过起点时会把尾部区间漏成明文。两处均已修。
  *NER: an empty entity label caused an index error, and overlap trimming dropped whole entities by start offset, leaking the tail span as plaintext when a suffix expansion pushed past the next start. Both fixed.*
- 打包：`.dockerignore` 没有排除 99MB 的 NER 模型目录，而容器根本不装 `onnxruntime` / `tokenizers`，带进去只是白占镜像层；同时误把根目录冒烟语料的排除项覆盖成了模型子目录。已修正。
  *Build: `.dockerignore` did not exclude the 99 MB NER model directory even though the container ships neither `onnxruntime` nor `tokenizers`, wasting an image layer; it had also overwritten the smoke-data exclusion with a model subdirectory. Both corrected.*
- 文档：NER 的「明文残留 74%→11%」未标注前提（模型与 `onnxruntime` 不在官方安装包与 Docker 镜像里），已补注。
  *Docs: the NER "plaintext left 74% → 11%" figure lacked its prerequisite (the model and `onnxruntime` ship in neither the official installer nor the Docker image); noted now.*
- 浏览器扩展：在面板重新打开桥接开关（或用户改对令牌）后，扩展侧退避仍把接下来的请求按直通发出去——最长 5s 明文出网且页面无任何提示；现首次进入退避的下一次调用立刻探测，探测再失败仍保持 5s 间隔（防洪不变），并把两条已与实现漂移的扩展 e2e 断言改成真契约。
  *Browser extension: after the bridge switch was turned back on in the panel (or the token fixed), the extension's backoff still passed the following requests straight through — up to 5 s of plaintext egress with no signal on the page; the next call after first entering the backoff now probes immediately, repeated failures keep the 5 s spacing (flood protection unchanged), and two extension e2e assertions that had drifted from the implementation were rewritten to the real contract.*
- 脱敏：整词匹配（`sensitive_word_whole`）对中文词等于「永不脱敏」——汉字之间没有词边界，把汉字放进两侧边界字符类后，开了整词的中文词 100% 漏打码且毫无提示；现按词形分档（中文词退化为子串匹配，宁可多打码不可漏打码），并把一条恒为真的整词断言改成真断言。
  *Masking: whole-word mode (`sensitive_word_whole`) silently disabled masking for Chinese words, since CJK text has no word boundaries and including CJK in the boundary class left them unmasked with no warning; boundaries are now picked per word shape (CJK falls back to substring matching, over-masking rather than leaking) and a vacuously-true whole-word assertion was replaced with real ones.*
- 脱敏：新增自定义敏感词不与全局占位符后缀查重，撞上活跃后缀（同标签即完整占位符相同）时会静默改写该占位符指向，换会话后把另一实体的原文还原到它身上；现并入全局后缀索引避让并加回归用例。
  *Masking: a newly added custom word did not check the global placeholder suffix index, so a collision with a live suffix (same label meant the identical placeholder) silently repointed that placeholder and restored another entity's plaintext at its position in later sessions; new words now avoid every live suffix, with a regression test.*
- 配置：`default_config()` 漏声明 `ner_enabled` / `sensitive_word_whole` / `wizard_done` / `meta`，config.json 损坏走降级分支时这几个键经增量接口保存会被判「未知配置项」400；已补齐并加键位对齐回归。
  *Config: `default_config()` left `ner_enabled` / `sensitive_word_whole` / `wizard_done` / `meta` undeclared, so on the degraded path (corrupt config.json) patching them answered 400 "unknown config key"; all are declared now, with a key-parity regression added.*
- 脱敏：开启 NER 时，实体若与已有占位符相交，整段（含其中的明文）会被原样放行——多轮对话历史带回占位符即触发，属漏脱敏。现按区间替换并在占位符边界切开，两侧明文分别打码；同时去掉「每个实体做一次全文正则替换」带来的二次耗时。
  *Masking: with NER on, an entity overlapping an existing placeholder was dropped whole and its plaintext went upstream — any multi-turn history carrying placeholders triggered it. Entities are now applied by span and split at placeholder boundaries so both sides get masked; the per-entity full-text replacement (69 s on a 100k-character body) is gone.*
- 脱敏：NER 的失败路径此前完全静默（模型缺失、依赖未装、推理异常、超长跳过、预算耗尽），表现为「开了没效果」。现每类原因留一条日志，并在 `/api/status` 与 `/api/health` 暴露可用性；超长文本与时间预算加硬上限，不再可能把代理冻住。
  *Masking: NER failure paths were completely silent (missing model, missing dependencies, inference errors, over-length skips, exhausted budget), looking like "enabled but no effect". Each cause now logs once and availability is exposed via `/api/status` and `/api/health`; long text and time budgets are now hard-capped so the proxy can no longer be frozen.*
- 审计：`/api/audit/events` 的读侧降噪过滤被一并作用在**检测**读路径上，被隐藏的信号在风险矩阵里永远看不到，而矩阵照样显示绿色。探针结果聚合现已显式绕开该过滤。
  *Audit: the read-side noise filter on `/api/audit/events` also applied to the detection read path, so hidden signals could never surface in the risk matrix while it still rendered green. Probe aggregation now bypasses that filter explicitly.*
- 统计：首页与统计页的「告警」不含审计高危信号，换芯、投毒、凭据外发只能靠主动翻审计页才能发现。现按同一口径并入（含按小时与按天曲线）。
  *Stats: the "alerts" figure on the dashboard and stats page excluded audit high-severity findings, so model swaps, poisoning and credential exfiltration were only discoverable by opening the audit page. They are now folded into the same figure, hourly and daily curves included.*
- 打包：`build.ps1` 的运行时产物清理会连 NER 模型自带的 `config.json` 一起删掉（该目录不入库，删了不可恢复）；PyInstaller spec 又无条件收录该目录（干净检出上直接构建失败），且 excludes 排掉了 NER 必需的 numpy / tokenizers。三处已修，并新增打包前模型完整性自检。
  *Build: `build.ps1`'s runtime-artifact cleanup also deleted the NER model's own `config.json` (the directory is not in git, so this was unrecoverable); the PyInstaller spec then included that directory unconditionally (failing clean-checkout builds) while `excludes` dropped the numpy / tokenizers the NER engine needs. All three are fixed, with a pre-pack model integrity check added.*
- 测试：NER 用例硬断言模型在位，门禁结果取决于本机是否恰好有那个 98MB 目录（本地绿、CI 红）。模型相关用例改为 skip 守卫，并补上不依赖模型的回归：实体与占位符相交不得漏明文、失败必须留痕、长度与预算护栏。
  *Tests: NER cases hard-asserted the model was present, so the gate depended on whether the machine happened to have that 98 MB directory (green locally, red in CI). Model-dependent cases now skip, and model-free regressions were added: entities overlapping placeholders must not leak plaintext, failures must be logged, and the length/budget guardrails must hold.*
- 安全审计：模型换芯检测在所有 OpenAI 兼容流式响应上完全失效（响应 model 只在 Claude 的 message_start 里提取），现已覆盖流式 chunk；同时新增同家族「偷偷换档」检测（gpt-4o → gpt-4o-mini 记中危）。
  *Security audit: identity-swap detection was dead on every OpenAI-compatible streaming response (the response model was read only from Claude's message_start); it now covers stream chunks, and same-family tier downgrades (gpt-4o → gpt-4o-mini) are reported as medium.*
- 安全审计：同一次换芯会落库两条完全相同的发现（主检测块被复制成两份）。
  *Security audit: a single identity swap was recorded twice (the main detection block had been duplicated).*
- 浏览器扩展：同一个 SSE 事件块里混有两种 data 行时，未命中豆包信封的行既不还原也不再交给标准管线，占位符原样留在页面上。
  *Browser extension: when one SSE event block carried two data lines, lines that missed the Doubao envelope were neither restored nor handed to the standard pipeline, leaving raw placeholders on the page.*
- 脱敏还原：收尾补发在无模板可克隆时裸拼文本，SSE/NDJSON 客户端按规范整行忽略导致丢字；整包 NDJSON 回退路径还漏了收尾补发。
  *Restore: the tail flush appended bare text when no template was available, which SSE/NDJSON clients discard as an unparsable line; the bulk NDJSON fallback path also skipped the tail flush entirely.*
- 脱敏还原：响应嵌套超过 24 层时占位符既不还原也不计数，排障时分不清「没还原」和「本来就没有占位符」。
  *Restore: placeholders in responses nested deeper than 24 levels were neither restored nor counted, making "not restored" indistinguishable from "nothing to restore".*
- 浏览器扩展：文件脱敏失败（引擎超时/掩码失败/解包失败）时 popup 仍报「已脱敏 N 个文件」，把最危险的失败模式包装成成功。
  *Browser extension: when file masking failed (engine timeout, mask failure, unpack failure) the popup still reported "N files masked", disguising the most dangerous failure mode as success.*
- 浏览器扩展：模型逐 token 输出时占位符会被 SSE 事件边界切开，页面上留下裸 `{{...}}` 而不是还原成原文。现改由引擎按事件与字段粒度还原（与代理链路同一份实现），并顺带消除正文与工具参数共用一个还原缓冲导致的串字。
  *Browser extension: placeholders split across SSE event boundaries while the model streamed token by token, leaving raw `{{...}}` on the page instead of the original text. Restoration now runs per event and per field in the engine (the same implementation the proxy link uses), which also removes the text corruption caused by sharing one restore buffer between message text and tool arguments.*
- 浏览器扩展：引擎状态不会随实际情况更新——引擎关掉后 popup 仍绿标（状态停在上一次的值），改对令牌后红标也不消失（启动时空令牌必然吃一次 403，状态被钉死）。现已按 ping 结果显式更新状态。
  *Browser extension: engine status never followed reality — the popup stayed green after the engine was stopped (status frozen at its previous value) and stayed red after the token was fixed (a cold start always takes one 403 with an empty token, pinning the status). Status is now updated explicitly from the ping result.*
- 浏览器扩展：拦截默认采用精准对话模式（已知对话接口），杜绝非对话业务数据污染，并保留广泛模式开关供按需启用。
  *Browser extension: interception now defaults to precise mode (known chat endpoints) to avoid contaminating non-chat data, with an optional wide mode switch retained.*
- 浏览器扩展：附件（multipart）此前整包跳过，文本字段里的敏感信息裸着发出。现按字段处理——文本字段打码、文件原样透传、boundary 重新生成；检测到图片/文件时弹窗明说「附件内容不脱敏」。
  *Browser extension: multipart attachments were skipped wholesale, leaking whatever sensitive text sat in their text fields. Now handled field by field — text fields masked, files passed through byte-for-byte, boundary regenerated — and the popup states plainly that attachment contents are not masked.*
- 浏览器扩展：检测不到本地引擎时不再静默不生效，弹窗显示「未检测到本地程序」并给出下载地址（地址由 manifest 的 homepage_url 推导，扩展代码内无外域字面 URL）；令牌错误时不显示该引导，避免把人带去重装。
  *Browser extension: no longer fails silently when the local engine is missing — the popup says so and offers a download link (derived from the manifest's `homepage_url`, so no off-machine URL literal lives in extension code). The hint is suppressed on token errors so users are not sent to reinstall.*
- 浏览器扩展：删掉的站点仍在打码。ChatGPT / Claude 是 manifest 静态注册的脚本，无法用 API 注销，用户删除后脚本照样注入、照样送 body，界面却显示「已删除」；现在以配置为准在打码入口兜底，不启用就不打码。同时去掉设置页「内置 / 已添加」标签，所有站点一律可新增可删除。
  *Browser extension: deleted sites were still being masked. ChatGPT / Claude are statically declared in the manifest and cannot be unregistered via API, so their scripts kept injecting and forwarding bodies while the UI said "deleted". Masking now honours the config at the entry point, and the options page no longer labels any site "built-in" — every site can be added and removed alike.*
- 浏览器扩展：推荐站点里两个域名是错的、四个海外站点的对话接口漏过路径白名单，加起来 6 个站「添加了却完全不脱敏」（页面毫无异常）。域名按实测落点纠正（文心一言 yiyan.baidu.com → wenxin.baidu.com，小米 MiMo xiaomimimo.com → mimo.xiaomi.com），白名单补 Gemini / Grok / Perplexity / Poe 的 RPC 形态路径；未登录探测确认「命中上述路径形态的请求必被打码」，这 16 个站的真实对话路径仍未验证，界面维持「未实测」标记。
  *Browser extension: two recommended domains were wrong and four overseas sites' chat endpoints slipped past the path allowlist — 6 sites were "added but never masked", with no visible symptom. Domains corrected to where the sites actually land (ERNIE Bot `yiyan.baidu.com` → `wenxin.baidu.com`, Xiaomi MiMo `xiaomimimo.com` → `mimo.xiaomi.com`) and RPC-style paths added for Gemini / Grok / Perplexity / Poe. A logged-out probe confirms requests matching those path shapes are always masked; the real chat endpoints of those 16 sites remain unverified, so the UI keeps the "unverified" mark.*
- 浏览器扩展：多个时机同时重注册动态脚本（安装 / 启动 / 设置页刷新）会互相踩，Chrome 报重复脚本 ID 后该站点静默不注入。已加并发锁，同一时刻只跑一次重注册。
  *Browser extension: concurrent re-registrations (install / startup / options resync) raced each other and Chrome rejected some with a duplicate script ID, silently dropping injection for those sites. Now serialised with an in-flight lock.*
- 扩展设置页与后台的通信整体失灵（「测试连接」必失败、会话占用恒空白、添加站点拿不到重注册确认）：后台用 `!sender.tab` 判断"是不是扩展自己的页面"，而以标签页打开的设置页 `sender.tab` 是有值的，导致管理消息全部超时。已改为按 `sender.url` 的 scheme 判定，并加静态门禁拦住同类写法。
  *Extension options page could not talk to its background worker at all ("Test connection" always failed, session usage stayed blank, added sites reported no confirmation) because the background judged "extension's own page" by `!sender.tab`, while an options page opened as a tab does have `sender.tab`. Now judged by the `sender.url` scheme, with a static gate to block the same mistake.*
- 扩展添加站点：后台没回应时不再报「已保存」成功，改为黄标提示需重新加载（写进存储 ≠ 脚本真的注入了）。
  *Adding a site no longer reports success when the background does not respond; it warns that a reload is needed (persisted ≠ actually injected).*
- 扩展弹窗的「设置 / 刷新」按钮点了没反应：`popup.html` 漏写 `id="recentTitle"`，渲染时抛异常把初始化掐断在绑定按钮之前；已补齐 id，并把事件绑定提到取数之前，渲染失败不再连坐按钮。
  *Extension popup's Settings/Refresh buttons did nothing: `popup.html` was missing `id="recentTitle"`, so a render-time error aborted initialisation before the click handlers were bound. The id is restored and binding now happens before data loading, so a render failure can no longer take the buttons down.*
- 透传兜底层：https 出口代理按 TLS 编排 CONNECT（原明文直连必握手失败）；上游空闲超时 900s→300s，mid-stream 失败不再叠加错误状态行；同名多值请求头合并转发不再丢值；恢复透传 accept-encoding（仅还原映射非空时降级为 gzip/deflate 并流式解压后再还原，br/zstd 在该情形下被拒；映射为空则原样透传）。
  *Passthrough: https egress proxies now do TLS-then-CONNECT (was plaintext and always failed); upstream idle timeout 900s→300s with no status-line corruption on mid-stream failures; duplicate request headers joined instead of dropped; Accept-Encoding passed through again (degraded to gzip/deflate with stream decompression only while a restore map is active — br/zstd are dropped in that case — and passed through untouched otherwise).*
- 扩展桥接：令牌失效或面板关开关时不再每个流式分片都重试（原先一条回答就把引擎 800 行运行日志冲干净），改为退避 + 每 5 秒低速探测，改对令牌后自动秒级恢复；popup 红标文案区分「token 失效」与「引擎未运行」。
  *Extension bridge: no longer retries on every streaming chunk when the token is invalid or the panel switch is off (a single answer used to wipe the engine's 800-line runtime log). Now backed off with a 5s low-rate probe that self-heals seconds after the token is fixed; the popup red status distinguishes "token invalid" from "engine not running".*
- 诊断包泄漏明文敏感词：词榜的词面在「统计记录明文」开启时是明文，原先原样进包（诊断包是发给开发者的），现只脱敏词面、保留类别与计数。
  *Diagnostics bundle leaked plaintext sensitive words: word faces are plaintext when "record plaintext words" is on, and were shipped as-is in a bundle meant to be sent to developers. Now only the word face is scrubbed; labels and counts are kept.*
- 重复的浏览器扩展设置页「在本机面板旋转令牌」按钮永远失败（该端点需要面板令牌，扩展只有扩展令牌），改为打开面板设置页。
  *The browser-extension options page's "rotate token in the panel" button could never succeed (that endpoint requires the panel token while the extension only holds the extension token) — it now opens the panel settings page instead.*
  - 三处测试结果不确定（两处读本机真实事件库、一处并发用例靠线程调度赌胜负），跑过真实代理或负载一变就随机红；已分别改为显式隔离与确定性握手复现。
    *Three non-deterministic tests (two read the real local event store, one raced on thread scheduling) failed randomly once a real proxy run existed or load changed; now explicitly isolated, with the race reproduced deterministically via an explicit handshake.*
- /v1 通配卡片不再同时展示两个相同的 Base URL 复制项。
  */v1 wildcard cards no longer show two identical Base URL copy entries.*
- 自定义敏感词：禁用后不再永久豁免回收（此前要改两次配置才生效，且禁用词的明文会一直留在内存里可还原），其映射也不再挤占普通条目的复用额度。
  *Custom words: disabling one now takes effect in the same reload instead of the next, its plaintext no longer stays restorable in memory, and its mappings no longer eat into the reuse budget of ordinary entries.*
- 还原容错：模型把占位符写成 `{{ TOKEN_x }}`、`\{\{...\}\}` 或只剩单花括号时，原先会留下 `{{ ` / `\{\` 残渣（值出来了但命令仍是坏的，容易被误判成还原成功），现在整体吃掉、零残渣。
  *Restore tolerance: when the model wrote a placeholder as `{{ TOKEN_x }}`, `\{\{...\}\}` or with a single brace, residue like `{{ ` and `\{\` used to survive (the value came back but the command stayed broken, easily mistaken for success); the whole form is now consumed with no residue.*
- 内网 IPv6 规则（默认关）漏检：`gateway:fd00::5` 这类紧跟冒号的写法整段匹配不到，`Fe80::1` 这类混合大小写会被特征预检整条跳过且不留痕，两处均已修正。
  *Private-IPv6 rule (off by default): addresses right after a colon (`gateway:fd00::5`) matched nothing, and mixed-case forms like `Fe80::1` were skipped by the marker pre-check with no trace; both fixed.*
- 透传兜底层：上游谎报 `Content-Encoding: gzip`（正文其实是明文）时，客户端原先拿到「200 + 静默截断的 body」，现在改为原样整段透传。
  *Passthrough: when an upstream lied about `Content-Encoding: gzip` (body actually plaintext), clients used to get a 200 with a silently truncated body; the bytes now pass through untouched.*
- 门禁污染本机数据：透传用例会把假 PASS 事件写进开发者本机的真实事件库（跑一次门禁就多几条），已在用例内隔离。
  *Gate runs polluted local data: passthrough tests wrote fake PASS events into the developer's real event store on every run; now isolated in the test.*

### 优化 / Changed
- 配置：删除从未被任何代码消费的 `NER_AI` 规则开关（点了没用的假开关），`config.example.json` 补上 `ner_enabled`（模板缺项时手工改配置的用户看不到这项能力）。
  *Config: removed the `NER_AI` rule switch, which no code ever consumed (a toggle that did nothing), and added `ner_enabled` to `config.example.json` (template omissions hid the feature from users who hand-edit config).*
- 全局 UI 视觉重构：新增深浅自适应「天境流光」旗舰默认壁纸与通透毛玻璃参数，侧边栏、顶栏、弹窗遮罩与浮层实现全景联动，消除厚重视觉割裂。
  *Global UI visual overhaul: added an adaptive "Ambient Flow" flagship default wallpaper and frosted-glass preset, unifying sidebar, header, dialog overlay, and popovers with consistent translucency.*
- 扩展内部重复的常量与函数（站点清单、路径未适配清单、域名校验与 match pattern）收敛为单一来源 `extension/shared.js`，消除三份实现互相漂移的隐患。
  *Duplicated constants and helpers inside the extension (site list, unsupported-paths list, domain validation and match pattern) are consolidated into a single `extension/shared.js`, removing the risk of three implementations drifting apart.*
- 扩展端点不再放行 `Origin: null`（无来源上下文没有合法调用方）；事件「入口」维度的取值改为白名单归一化（非法值回落 `proxy`，不再产生筛不出来的隐形分组）。
  *Extension endpoints no longer allow `Origin: null` (no-source contexts have no legitimate caller); the events "ingress" dimension is now allowlist-normalized (unknown values fall back to `proxy` instead of forming an invisible, unfilterable bucket).*
- 运行日志尾部通道补上 `ingress` 与 `client_app` 字段（原先该视图看不到入口、也看不到是谁发的）。
  *Tail-channel log records now carry `ingress` and `client_app` (previously the tail view showed neither the ingress nor the caller).*
- 「出口代理已启用但没人勾选」不再在每次保存配置时弹 toast（改为仪表盘常驻状态横幅）。
  *"Egress enabled but unused" no longer toasts on every config save (persistent dashboard banner instead).*

## [0.2.12] - 2026-09-15

### 新增 / Added
- 公网 IPv4 内置规则（`IP_PUBLIC`，默认关）：边界断言防版本号/文件名误伤，语义校验排除私网/环回/组播/CGNAT/RFC 段，白名单豁免知名公共 DNS，版本号形态（全个位数、Java 构建号 `1.8.0.202`）放行；已知漏检面见规则说明。
  *Public IPv4 rule (`IP_PUBLIC`, default off): boundary assertions against version-number/file-name false positives, semantic validation excluding private/loopback/multicast/CGNAT/RFC ranges, well-known DNS whitelisted, version shapes (all-single-digit, Java build numbers) exempted.*
- 透传模式占位符尽力还原：停止代理或关闭过滤后，从事件库（48h、非凭据）还原模型回复中的占位符，计数并入 PASS 事件。
  *Best-effort placeholder restoration in passthrough mode from the event store (48h, non-credential); counts attached to PASS events.*
- 客户端配置重构：默认「通用聚合」模板（`/v1` 通配）、端点推荐池；移除预设注入请求头（占位值会顶掉客户端真 key）。
  *Client config revamp: default general-aggregate template (`/v1` wildcard), endpoint suggestions; preset header chips removed.*
- 界面：侧边栏折叠记忆、数据密集页放宽版心、仪表盘百分比封顶展示。
  *UI: sidebar collapse memory, wider data-dense pages, capped percentage display.*

### 修复 / Bug Fixes
- TOKEN 漏检全大写 `BEARER` 头；explicit 模式改域名不生效（现自动重启代理）；占位符预热超容量淘汰方向反转与孤儿泄漏；清空日志后跨进程事件复活与日志页游标停更；升级迁移不再覆盖显式 `stop_mode`。
  *Fixed: uppercase `BEARER` misses; explicit-mode domain changes not taking effect (now auto-restarts); warmup eviction order and orphan leaks; cross-process event resurrection and stale log cursor after clearing; migration no longer overrides explicit `stop_mode`.*
- 透传兜底层硬化：socket 读超时、HEAD/OPTIONS 支持、畸形 chunked 请求 400、413/503 前排空请求体、自启异常挂兜底。
  *Passthrough hardening: socket read timeout, HEAD/OPTIONS support, 400 on malformed chunked bodies, request-body draining before error responses, autostart exception fallback.*
- 前端：侧边栏 tooltip 文案互换、`/v1` 通配 Base URL 缺 `/v1`、日志清空后页码不归位。
  *Frontend: swapped sidebar tooltips, missing `/v1` in wildcard Base URL, stale page number after log clear.*

### 优化 / Changed
- App 退出不再挂明文直连兜底（退出即断连）；手动停止仍按 stop_mode 语义。
  *App exit no longer starts the plaintext fallback; manual stops keep stop_mode semantics.*
- 关闭过滤开关后保留流式效果；FAIL_CLOSED 非白名单非 JSON 阻断尊重过滤开关。
  *Streaming preserved when filtering is off; the FAIL_CLOSED block honors the filter switch.*
- 价格缓存原子写，并真正实现定期刷新（原「7 天自动刷新」未实现）。
  *Atomic price-cache writes plus a real periodic refresh loop.*
- 引擎自愈收紧：重启 CAS 互斥防双引擎；孤儿清理加进程身份校验，绝不误杀无关进程。
  *Tighter self-healing: CAS restart mutex; identity-checked orphan cleanup that never kills foreign processes.*

## [0.2.11] - 2026-09-14

### 修复 / Bug Fixes
- 修复**仪表盘统计卡片大数字溢出边框**：百万级以上数字按中英体系自适应进位（中文万/亿、英文 M/B），完整千分位通过悬浮提示展示；分享卡主数字按位数动态缩小字号；模型排行 Token 用量改紧凑进位；前缀保真度卡展示改为「上下文缓存友好度」文案并新增逐项悬浮说明，平均首个差异字节改用 KB/MB 自适应单位。同步把面板自动打开的地址带上 `#token=`，免去每次手动输入访问令牌。
  *Fixed dashboard stat cards overflowing their borders with large numbers: values beyond the compact threshold now scale adaptively per unit system (CJK 万/亿, Latin M/B) with the full thousands-separated figure available as a hover tooltip; the share card scales its headline font down by digit count; model rankings use compact token formatting; the prefix-fidelity card is retitled "Context Cache Health" with per-metric hover explanations, and the average first-diff byte now renders in adaptive KB/MB units. The auto-opened panel URL also carries `#token=` so the access token no longer has to be typed by hand.*

## [0.2.10] - 2026-09-13

### 新增 / Added
- 新增**控制台词条一键穿透日志与全链路详情看板**：首页「今日脱敏词明细」与「今日还原明细」支持直接点击任一词条，自动携带参数跳转至「拦截审计日志」并开启全局搜索；日志列表直观展示每条记录命中的敏感词标签（如 `PHONE`、`CONNSTR` 等）；日志详情弹窗新增出站脱敏（用户请求）与入站还原（模型响应）链路节点全景看板，对照卡片强化原文与占位符直观对比，彻底解决“不知道脱敏了什么、还原了什么”的困惑。
  *Added one-click word-to-log navigation and full-link audit detail dialog: Top masked and restored items on the Dashboard can now be clicked directly to navigate to the Interception Logs page with pre-filled search filters; log table rows prominently display matched sensitive tags (`PHONE`, `CONNSTR`, etc.); the log detail modal now features a visual pipeline stage banner (Outbound Masking vs. Inbound Restoring) with side-by-side comparison cards, making it immediately clear what was intercepted and what was restored.*
- 新增**请求前缀诊断字段**（均不含原文）：MASK 事件新增 `body_rewritten`（本次是否回写了请求体）、`first_diff_byte`（回写后与客户端原始字节的首个差异位置；二分查找实现，超过 1 MB 记 -1，不参与任何脱敏决策）、`suffix_reused`（命中的占位符是否沿用了复用表里的旧 token）。此前用户报「接入后上游缓存命中率归零」时，无法区分是网关改了字节还是上游自己 miss，只能靠猜。有了这三项，一次日志就能定位；它们同时也是判断「要不要做字节级精确替换」的唯一实测依据 —— 实测一条带空格 + `\u` 转义的请求，首个差异位落在 byte 9（`{"model": ` 的空格），而真正的敏感值在 byte 74，中间 65 字节的前缀被凭空改动。
  *Added request-prefix diagnostics (no plaintext involved) to MASK events: `body_rewritten` (whether the body was written back at all), `first_diff_byte` (the first position that differs from the client's original bytes, found by binary search, reported as -1 above 1 MB, and never used in any masking decision) and `suffix_reused` (whether the matched placeholder reused an existing token from the reuse table). Previously, when someone reported "upstream cache hit rate dropped to zero after installing", there was no way to tell whether the gateway had changed the bytes or upstream had simply missed — only guesswork. These three fields answer it from a single log line, and they are also the only measured basis for deciding whether byte-level exact replacement is worth building: on a measured request with spaces and `\u` escapes, the first differing byte was byte 9 (the space in `{"model": `) while the actual sensitive value sat at byte 74, meaning 65 bytes of prefix had been altered for no reason.*
- 新增 `scripts/purge-daily-words.py`：按标签定向清理事件库 `daily_words` 词级明细的运维工具，用于一次性清掉历史规则误报累积的 `<CONNSTR>` 垃圾词条（面板的「清空日志」会删掉**全部日期**的词明细，且会把 `events` 一起清掉，太钝）。**默认只演练（只读）**，`--yes` 才写库；写库前检查 `shield.pid` 确认引擎未在运行（`--force` 可跳过，不推荐），并把库整份备份为 `<库名>.bak-purge-<时间戳>`。刻意**不碰** `daily_stats` / `daily_status` / `daily_tokens`（遵循「清日志不清统计」口径）与 `events`（清明细请用面板），脚本会把由此产生的「词明细合计 ≠ 脱敏总数」差额明确打出来。支持 `--day all` 清理全部保留期、`--db` 指定库文件。
  *Added `scripts/purge-daily-words.py`, an operations tool that removes `daily_words` entries for a given label — used to clear the `<CONNSTR>` junk accumulated by earlier false positives in one go (the panel's "clear logs" wipes the word detail for **every** date and takes `events` with it, which is far too blunt). It **defaults to a read-only dry run**; only `--yes` writes. Before writing it checks `shield.pid` to confirm the engine is not running (`--force` overrides, not recommended) and backs the whole store up to `<db>.bak-purge-<timestamp>`. It deliberately leaves `daily_stats` / `daily_status` / `daily_tokens` alone (honouring "clearing logs does not clear statistics") as well as `events` (use the panel to clear details), and prints the resulting gap between the word-detail total and the masked-event total so the difference is not mistaken for a no-op. `--day all` covers the whole retention window and `--db` points at a specific store.*
- 新增**仪表盘「前缀保真度」卡**：把上一条新增的三个前缀诊断字段接成可视化统计 —— 零改写透传率（请求体一个字节都没被改动的比例，主指标）、占位符复用率、平均首个差异字节。第一列按「样本数 / 总数」标注，第二、三列分母是**改写次数**（`suffix_reused` 与 `first_diff_byte` 都只在回写分支才有意义——零改写透传的请求没签发占位符、也没有差异位），既避免把「只有一个样本的均值」读成全量结论，也避免把「100 次请求 10 次命中、8 次复用」稀释成 8%；数据随「今日 / 近7天 / 近30天」切换，没有任何样本时显示「暂无数据」而不是一排 0，并进一步区分「本区间压根没请求」与「有请求但都早于该项统计上线」——后者正是升级当天的形态，不能显示成「脱敏没生效」。数据由事件库新增的日摘要表 `daily_prefix` 增量维护，只收带诊断字段的 MASK 事件，随「统计永久保存」策略保留、不随保留期裁剪。
  *Added a "Prefix Fidelity" dashboard card that visualises the three request-prefix diagnostics from the entry above: the byte-identical pass-through rate (the share of request bodies forwarded without a single byte changed, shown as the headline figure), the placeholder reuse rate and the average first-diff byte. The first column is annotated "samples / total"; the second and third use **rewrites** as their denominator, because both placeholder reuse and the first-diff byte are only meaningful when the body was actually rewritten (a byte-identical request issues no placeholder and has no diff position) — this keeps an average over a single sample from being read as a whole-range conclusion, and stops "10 hits and 8 reuses across 100 requests" from being diluted to 8%. The figures follow the Today / 7-day / 30-day selector, and with no samples the card reads "no data" rather than a row of zeros, further distinguishing "no requests in range" from "requests exist but predate this metric" — the latter is exactly what an upgrade day looks like and must not read as "masking is not working". The numbers come from a new `daily_prefix` daily summary table maintained incrementally by the event writer (masked events carrying the diagnostics only) and kept under the "statistics are retained forever" policy, never trimmed by the retention window.*

### 修复 / Bug Fixes
- 修复 **CONNSTR 规则把工具文档当成真实凭据脱敏**：AI 编码助手每轮都会把内置网络工具的参数说明（`proxy: http://user:pass@host:port or socks5://host:port`）注入提示词，旧规则只要看到 `://…:密码@` 就签发占位符，单日累计 800+ 次、长期霸占面板「今日脱敏词明细」第一名，把真实泄漏挤到后面。新增 `_connstr_ok` 形态校验，只豁免「一眼是文档/代码模板」的连接串——非数字端口且用户名或密码是占位形态、密码整体是锚定模板（`{password}` / `$PORT` / `%PWD%`）、占位主机且密码是占位词、经典 `user:pass` 对——真实内网/生产连接串照常脱敏与流式还原。
  *Fixed the `CONNSTR` rule masking tool documentation as if it were a real credential. Coding agents inject their built-in network tool docs (`proxy: http://user:pass@host:port or socks5://host:port`) into every prompt, and the old rule issued a placeholder for any `://…:password@` it saw — 800+ hits a day, permanently topping the panel's daily masked-word list and pushing real leaks down. A new `_connstr_ok` shape check exempts only strings that are unmistakably documentation templates: a non-numeric port combined with a placeholder-shaped user or password; an anchored template password (`{password}` / `$PORT` / `%PWD%`); a dummy host combined with a placeholder password; or the classic `user:pass` pair. Real intranet and production connection strings are still masked and restored as before.*
- 修复**豁免规则放走真实口令的五种形态**（同批复审）：① 模板判据从「密码含 `$ % { [ <` 字符类」改为锚定整体形态，否则 `mysql://root:p%40ssw0rd@…` 全明文上行；② 占位主机必须与占位密码同时成立，否则 `admin:S3cret99@host:5432` 被放行；③ IPv6 字面量整体解析 `[::1]:5432`，否则端口被读成 `::1` 而误豁免；④ 豁免必须让下游规则避让——CONNSTR 让路后 EMAIL 会把「口令尾@host」当邮箱吃掉，输出 `postgres://app:Xk9${{EMAIL_x}}:5432/prod`，看着有占位符、实际口令前半截明文；⑤ EMAIL 规则本地部分以下划线开头（`_svc@corp.com`）此前整段不匹配。
  *Fixed five ways the exemption could let a real password through (same review pass): (1) the template test is now anchored to the whole value instead of a `$ % { [ <` character class, which used to exempt `mysql://root:p%40ssw0rd@…` in full plaintext; (2) a dummy host now requires a placeholder password too, so `admin:S3cret99@host:5432` is no longer passed through; (3) IPv6 literals are parsed as a whole (`[::1]:5432`), since splitting on the first colon read the port as `::1` and wrongly exempted it; (4) an exemption must now shield its span from later rules — with `CONNSTR` stepping aside, `EMAIL` swallowed the password tail plus host and emitted `postgres://app:Xk9${{EMAIL_x}}:5432/prod`, which looks masked while the first half of the password travels in plaintext; (5) `EMAIL` no longer skips local parts starting with an underscore (`_svc@corp.com`).*
- 修复**豁免判据把占位主机当成「密码是假的」的佐证，导致真实口令明文上行**（提交前复审）：规则 1 的条件是「非数字端口 **且** 用户名/密码/主机至少一项是占位形态」，而主机像模板与端口像模板是**同一类信号** —— 拿它去证「密码是假的」属于循环论证。于是任何「非数字端口 + 占位主机名」的连接串被整体豁免，密码原样出网：实测 `postgres://admin:S3cret99@{host|hostname|myhost|server|myserver|example.com|test.com|sample.com|your-host|yourdomain.com|db.example|db.invalid}:port/db` **12/12 全部漏检**（改动前 `://user:pass@` 一律脱敏，属本批新引入的漏检面，非存量）。现收紧为佐证只能是**用户名或密码**是占位词；主机只在第 3 档与占位密码**同时**成立时才作数。回归验证：12 个占位主机名漏检 0、7 个文档模板误伤 0、8 条真实口令（含 `Xk9$mQ2p`、`p%40ssw0rd`、`[::1]:5432`）漏检 0；代价是「非占位用户名 + 非占位密码 + 模板端口」这类混合串由豁免转为脱敏（fail-closed 方向）。
  *Fixed the exemption test treating a placeholder host as evidence that the password is fake, which let real passwords travel in plaintext (pre-commit review). Rule 1 read "non-numeric port **and** at least one of user/password/host is placeholder-shaped" — but a template-shaped host is the *same class of signal* as a template-shaped port, so using it to prove "the password is fake" is circular. Any connection string with a non-numeric port plus a placeholder hostname was therefore exempted wholesale with the password in the clear: measured on `postgres://admin:S3cret99@{host|hostname|myhost|server|myserver|example.com|test.com|sample.com|your-host|yourdomain.com|db.example|db.invalid}:port/db`, all 12 leaked (before this batch `://user:pass@` was always masked, so this gap was newly introduced, not pre-existing). The evidence is now restricted to a placeholder-shaped **user or password**; a host only counts in rule 3 where it must hold together with a placeholder password. Regression results: 0 of 12 placeholder hosts leak, 0 of 7 documentation templates are harmed, 0 of 8 real passwords (including `Xk9$mQ2p`, `p%40ssw0rd`, `[::1]:5432`) are missed; the cost is that mixed strings with a real-looking user, a real-looking password and a template port move from exempt to masked — the fail-closed direction.*
- 修复**统计页凭据预览被二次打码成畸形串**：凭据类落库的已经是安全预览（`<CONNSTR 4 位>`、`<PEM 私钥 1024 字节>`、`sk-…3456`），前端再打一遍会显示成 `<CO******* 位>`。现按调用方传入的凭据标志直接展示；判据不再看字符串形状，避免非凭据敏感词（如自定义的 `<内部系统>`）在「显示明文」关闭时被原样展示。
  *Fixed credential previews being masked a second time in the stats UI into malformed strings: credentials are already stored as safe previews (`<CONNSTR 4 位>`, `<PEM 私钥 1024 字节>`, `sk-…3456`), and re-masking them produced `<CO******* 位>`. The preview is now shown as-is based on the credential flag passed by the caller; the check no longer keys off string shape, so a non-credential sensitive word such as a custom `<内部系统>` is not displayed verbatim while "show plaintext" is off.*
- 修复**请求体被无差别重序列化，导致上游 Prompt Cache 整段失效**：`request()` 原先无条件用 `json.dumps(body, ensure_ascii=False)` 回写请求体。`json.dumps` 的默认分隔符是 `(", ", ": ")`，会在每个逗号与冒号后补一个空格；`ensure_ascii=False` 又会把客户端的 `\u5f20\u4e09` 展开成「张三」。于是**哪怕一个敏感词都没命中**，上游收到的字节也与客户端发出的不同（实测紧凑体 113 字节被改写成 123 字节）——而按前缀命中的 Prompt Cache 只要前缀一变就整段 miss，多轮长会话每轮都重新计费。现由 `_mask_hit` 记录「本次是否真的替换过」：一个敏感词都没命中就**一个字都不动** `flow.request.content`；确实需要回写时改用紧凑分隔符 `(",", ":")`，并按客户端已表现出的转义策略选择 `ensure_ascii`，尽量让前缀字节保持一致。
  *Fixed request bodies being re-serialised unconditionally, which invalidated the upstream prompt cache entirely. `request()` used to write the body back with an unconditional `json.dumps(body, ensure_ascii=False)`. `json.dumps` defaults to the `(", ", ": ")` separators, inserting a space after every comma and colon, while `ensure_ascii=False` expanded the client's `\u5f20\u4e09` into literal characters. So even when not a single sensitive word matched, the upstream received different bytes from the client (a 113-byte compact body measured at 123 bytes after rewriting) — and a prefix-based prompt cache misses completely once the prefix changes, re-billing every turn of a long conversation. `_mask_hit` now records whether anything was actually replaced: with no match, `flow.request.content` is left completely untouched; when a rewrite is genuinely required it uses the compact `(",", ":")` separators and follows the escaping mode the client has already demonstrated, keeping as much of the prefix byte-identical as possible.*
- 修复 **Anthropic `cache_control` 被自定义词表误伤、缓存指令静默失效**：`cache_control` 一直被列在 `_MASK_ALWAYS_SKIP` 里，但该集合只在递归的**字符串分支**生效，而 `cache_control` 恒为对象 `{"type": "ephemeral"}` —— 判定被整个绕过，`"ephemeral"` 照常送进脱敏管线。默认词表不命中这个英文词，所以线上一直无感；一旦自定义词表里出现同形词，指令会被写成 `{"type": "{{TERM_xxxxxx}}"}`，上游判其非法。现按语义拆成 `_MASK_SKIP_SCALAR_KEYS`（仅字符串叶子）与 `_MASK_SKIP_SUBTREE_KEYS`（整棵子树跳过），只把结构固定、无业务载荷的 `cache_control` 放进后者。`response_format` / `format` 虽是同类 dict 值键但**故意不收** —— OpenAI 的 `json_schema` 与 Ollama 的 `format` 都可以是一整份 JSON Schema，其 `enum` 可能承载真实业务取值，整棵跳过等于新增一条漏检路径而收益为零；该决定由一条反向锁用例守住。
  *Fixed Anthropic `cache_control` being mangled by custom word lists, which silently invalidated cache directives. `cache_control` had always been listed in `_MASK_ALWAYS_SKIP`, but that set is only consulted in the recursion's string branch while `cache_control` is always an object (`{"type": "ephemeral"}`) — so the check was bypassed entirely and `"ephemeral"` went straight through the masking pipeline. The default word list never matches that English word, which is why it went unnoticed; as soon as a custom list contains a similarly shaped word the directive is rewritten to `{"type": "{{TERM_xxxxxx}}"}` and rejected upstream. The set is now split by semantics into `_MASK_SKIP_SCALAR_KEYS` (string leaves only) and `_MASK_SKIP_SUBTREE_KEYS` (whole subtrees skipped), with only the structurally fixed, payload-free `cache_control` in the latter. `response_format` and `format` are dict-valued keys of the same kind but are deliberately excluded: OpenAI's `json_schema` and Ollama's `format` can each be an entire JSON Schema whose `enum` may carry real business values, so skipping them wholesale would open a new detection gap for zero benefit. A reverse-lock test guards that decision.*
- 修复**命中敏感词时前缀被整段改写、上游缓存照样 miss**：新增字节级精确替换 —— 只把被脱敏的那个字符串字面量就地换掉，客户端 body 的排版（冒号后空格、缩进、数字写法、`\u` 转义风格）原样保留。此前命中后要整棵 `json.dumps` 重序列化，排版被一并抹掉，与客户端原始字节的首个差异位从「真正的敏感值」前移到 body 开头附近，上游按前缀做的 Prompt Cache 从差异位起整段 miss。实测五种客户端排版（紧凑 / 带空格 / 缩进 / 原字符 / `\u` 转义），首个差异位现在**全部正好落在被脱敏的值上**，此前分别是 byte 1~9。正确性由 `json.loads(结果) == 脱敏后的树` 等价校验兜底：一旦多替换了一处（命中键名、命中有意跳过的字段、把历史占位符切碎）就整条退回重序列化 —— 而退回的是**同一棵已脱敏的树**，因此这条路径在任何情况下都不会放行原文。超过 8 MB 的请求体不做替换、直接走原路径（首版定 1 MB 时判断「省下的前缀对齐收益抵不过 CPU 开销」，实测不成立，见下方优化条目）。另有一条**独立的退回线**：单次请求里被脱敏的唯一原文超过上限时同样退回重序列化（每个原文按两种合法 JSON 写法各建一条匹配分支，因此 64 个原文 ≈ 128 个分支）。发版复审时在 8 MB body 上复测了档位 —— splice 生效与退路 `json.dumps` 耗时**同价**（32 分支 21ms / 128 分支 23ms / 256 分支 27ms vs 22ms），退回并不省时间、只是白白丢掉前缀保真，于是把上限从 64 提到 **128**（覆盖单请求 64 个不同敏感值，日常长会话不再踩线），并补用例锁住「80 分支必须仍走 splice」；同时验证了 splice 生效/退回两条路径的还原结果完全一致 —— 上限只影响写回方式，不影响脱敏与还原（还原只看占位符→rev 映射）。`MASKIT_BYTE_SPLICE=0` 可一键关闭整条替换路径。
  *Fixed the request prefix being rewritten wholesale whenever a sensitive word was hit — which still made upstream miss. A new byte-level replacement swaps only the affected string literal in place, leaving the client's body layout (spaces after colons, indentation, number formatting, `\u` escaping style) untouched. Previously a hit triggered a whole-tree `json.dumps` re-serialisation that erased the layout and moved the first differing byte from the actual sensitive value up to near the start of the body; a prefix-based upstream prompt cache misses completely from that point on. Measured across five client layouts (compact, spaced, indented, literal characters, `\u` escapes), the first differing byte now lands exactly on the masked value in every case; it used to be byte 1-9. Correctness is guaranteed by an equivalence check (`json.loads(result) == masked tree`): if the replacement touched one position too many — a key name, a deliberately skipped field, an existing placeholder — the whole request falls back to re-serialisation, and since that fallback re-serialises the very same masked tree, this path can never let plaintext through. Bodies over 8 MB skip the replacement entirely (the first release capped this at 1 MB on the assumption that the prefix alignment saved was not worth the CPU; measurement disproved that — see the improvements entry below). There is a **second, independent fallback line**: a request whose masked text contains more distinct originals than the cap also falls back to re-serialisation, because each original contributes two alternation branches (literal and `\uXXXX` forms), so 64 originals mean roughly 128 branches. During the pre-release review the limits were re-benchmarked on an 8 MB body — splice costs the same as the `json.dumps` fallback (21ms at 32 branches, 23ms at 128, 27ms at 256, versus 22ms for dumps), so falling back saved no time and simply threw away prefix fidelity; the cap therefore went from 64 up to **128** (covering 64 distinct sensitive values per request, so everyday long conversations no longer trip it), with a new test locking "80 branches must still splice". Restore was verified identical on both the spliced and the fallback paths — the cap only affects how the body is written back, never masking or restoring (restore reads only the placeholder→rev map). `MASKIT_BYTE_SPLICE=0` turns the whole replacement path off.*

- 修复**「EMAIL 避让」误放过紧跟豁免连接串的真实邮箱**（提交前复审，2026-09-13）：连接串被判为文档模板而豁免后，本应只让 EMAIL 避开**与豁免区间重叠**的「口令尾@host」命中，实现却判成了「紧接在被豁免连接串之后」——而真正要防的口令尾起点在 `@` **之前**（前一个字符是 `:`，前置短路直接放行，等于这道判断从没挡住过它）。副作用是：连接串的主机名本身是邮箱时（`redis://default:{password}@zhang.san@example.com:6379`），那个**真实邮箱被整段跳过、明文上行**。现改为按区间判「重叠」而非「紧接其后」，并补上双向用例——此前把该函数整体改成 `return False`，660 个用例依然全过，说明它**一条用例都没有**。
  *Fixed the "EMAIL avoidance" check letting a real email through when it followed an exempted connection string (pre-commit review, 2026-09-13). Once a connection string is judged a documentation template and exempted, only EMAIL matches that **overlap** the exempted span (the "password-tail@host" shape) should be skipped; the implementation instead tested "immediately follows the exempted connection string" — yet the password tail it was meant to protect starts *before* the `@` (the preceding character is `:`), so the early-out returned false and the check never actually guarded anything. The side effect: when the connection string's hostname is itself an email (`redis://default:{password}@zhang.san@example.com:6379`), that **real email was skipped entirely and sent in plaintext**. The check now tests interval overlap instead of adjacency, with tests locking both directions — replacing the function body with a plain `return False` used to leave all 660 tests green, meaning it had **no test coverage at all**.*

### 优化 / Improved
- 优化**字节级替换的体积上限从 1 MB 放宽到 8 MB**（长会话是前缀缓存收益最大的场景，却恰好被 1 MB 挡在门外）：首版定 1 MB 的理由是「省下的前缀对齐收益抵不过 CPU 开销」，实测不成立 —— 完整路径（替换 + 调用方的 `json.loads` 等价校验）对退路 `json.dumps` 的耗时比，1 MB 为 1.34x、8 MB 为 1.17x，最坏只多 4 ms。诊断字段 `first_diff_byte` 的 1 MB 上限**刻意不跟着放宽**：它是每次回写都要算的纯诊断值，耗时随差异位置后移暴涨（1 MB 最末 14.5 ms、8 MB 达 173 ms），跟着放宽会把热路径拖慢一个数量级。两个上限互不联动由一条用例锁住。
  *Raised the byte-level replacement size cap from 1 MB to 8 MB — long conversations are where the prefix cache pays off most, and 1 MB excluded exactly those. The original 1 MB was justified as "the prefix alignment saved is not worth the CPU", which measurement disproved: over the full path (the replacement plus the caller's `json.loads` equivalence check) the cost relative to the `json.dumps` fallback is 1.34x at 1 MB and 1.17x at 8 MB, at most 4 ms worse. The 1 MB cap on the `first_diff_byte` diagnostic is deliberately **not** relaxed with it: that value is pure diagnostics recomputed on every write-back, and its cost grows sharply as the diff position moves later (14.5 ms at 1 MB versus 173 ms at 8 MB), so relaxing it would slow the hot path by an order of magnitude. A test locks the two caps so they cannot be silently coupled later.*

## [0.2.9] - 2026-09-12

### 新增 / Added
- 新增**控制面增量配置端点** `POST /api/config/patch`：以 `set` / `merge` / `map_del` / `list_add` / `list_remove` / `list_upsert` / `list_del` 七种操作做「只改指定路径」的写入。此前设置页每次保存都要提交整份 `config.json` 快照，两个标签页或「设置页 + 审计页」并发保存时，后到的陈旧快照会把先到的改动整片覆盖（容器型字段只能整份提交）。前端全部容器型调用点已改为增量下发。
  *Added an incremental control-plane config endpoint (`POST /api/config/patch`) with seven operations (`set` / `merge` / `map_del` / `list_add` / `list_remove` / `list_upsert` / `list_del`) that touch only the named path. Previously every save from the settings UI posted a whole `config.json` snapshot, so two concurrent saves (two tabs, or the settings and audit pages) let a stale snapshot silently wipe the other's edits — container-typed fields could only be written as a whole. All container-typed call sites in the frontend now send incremental patches.*
- 新增 **NDJSON 流式还原**（Ollama `/api/chat`、`/api/generate` 等换行分隔 JSON）：整包与逐行增量都能还原，半截占位符按行扣留、跨 TCP 块拼接，收尾补发。此前这类响应完全不被识别，占位符原样留在模型回复里。
  *Added NDJSON streaming restoration (Ollama `/api/chat`, `/api/generate` and other newline-delimited JSON). Both whole-body and line-by-line deltas are restored, half-placeholders are held back per line and stitched across TCP chunks, with a final flush. Previously these responses were not recognised at all and placeholders stayed in the model output verbatim.*
- 新增 `scripts/verify-all.py`：本地与 CI **共用的唯一门禁清单**（13 项，按 `python` / `frontend` / `rust` / `version` 分组）。`build.ps1` 改为直接调用它，`scripts/check-workflows.py` 增加与 `ci.yml` 的**双向漂移比对**，任一侧漏加/多加都会在 PR 阶段报错。此前门禁散在两处，本地「过了 `build.ps1` 却被 CI 拦下」时 tag 已经推走了。
  *Added `scripts/verify-all.py`, the single gate manifest shared by local runs and CI (13 checks grouped as `python` / `frontend` / `rust` / `version`). `build.ps1` now calls it directly, and `scripts/check-workflows.py` cross-checks it against `ci.yml` in both directions so a missing or extra gate fails during the PR. The gate list used to live in two places, which meant a local run could pass `build.ps1` and still be blocked by CI — after the tag had already been pushed.*
- 新增 `rust-macos` CI job（`macos-latest` 编译 + 单测）。`lib.rs` 里有二十多处 `#[cfg(target_os = "macos")]` 分支，此前只有 Windows 会编译，macOS 分支的编译错误要等打 tag 走发版工作流才暴露。
  *Added a `rust-macos` CI job (compile + unit tests on `macos-latest`). `lib.rs` carries 20+ `#[cfg(target_os = "macos")]` branches that only Windows used to compile, so macOS-only compile errors surfaced only when a tag triggered the release workflow.*
- 新增 **.env 导入跳过原因全面中英双语国际化**：解析器在输出中文原因文本的同时输出 `reasonKey` 与 `reasonArgs`，前端 `EnvImportDialog` 根据当前语言自动呈现地道翻译，彻底消除英文界面下跳过原因硬编码中文的问题，并通过 `scripts/check-env-import.mjs` 全量边界回归保障。
  *Added full bilingual internationalisation for .env import skip reasons: the parser now outputs `reasonKey` and `reasonArgs` alongside the fallback reason text, and `EnvImportDialog` automatically renders native translations based on current language, eliminating hardcoded Chinese skip reasons in the English UI with full test coverage in `scripts/check-env-import.mjs`.*

### 修复 / Bug Fixes
- 修复**引擎崩溃后自愈能力永久静默失效**：watchdog 的限频分支只 `continue`，而那一刻 child 引用已被清空，下一轮既看不到「进程退出」也看不到「假死」，于是「1 分钟后重试」变成永不重试，唯一恢复途径是用户手动点「重启引擎」。现改为把待重试时刻排进队列，倒计时结束即重拉，错误文案里的秒数是真实倒计时。
  *Fixed silent, permanent loss of crash self-healing. The watchdog's rate-limit branch only did `continue`, but by then the child handle had already been cleared, so the next iteration saw neither "process exited" nor "hung" — turning "retry in one minute" into "never retry", with the only recovery being a manual "restart engine". The retry time is now queued and honoured, and the countdown in the error message is real.*
- 修复**凭据原文经模型复述后落库**：会话里已识别的凭据若被模型原样复述回来，还原阶段会把它重新写进事件库明细。现对还原后的文本再做一次凭据清洗（长度阈值 + 已知凭据集合），凭据类明细恒只存打码 preview 与 sha256 摘要。
  *Fixed credential plaintext landing in the event store when the model echoes it back. A credential already masked in the session, if repeated verbatim by the model, was written back into the log detail during restoration. Restored text is now scrubbed again (length threshold plus known-credential set), so credential details only ever store a redacted preview and a sha256 digest.*
- 修复**凭据标签集在 5 处各写一份**、新增或改名时漏改某处会导致凭据分类失效：收敛为单一定义源 `engine/credential_labels.py` 与 `frontend/src/lib/credential-labels.ts`，并加跨端一致性用例。同步修正 `event_store` 的凭据判定口径。
  *Fixed the credential label set being duplicated in five places, where adding or renaming one would silently break credential classification. It now has a single source of truth (`engine/credential_labels.py` and `frontend/src/lib/credential-labels.ts`) guarded by cross-language consistency tests, and the `event_store` credential predicate was aligned.*
- 修复**统计历史的小时分桶恒等于事件时间戳**：SQLite 的 `/` 对整数做浮点除法，`(ts/3600)*3600` 并不取整，于是 `GROUP BY` 退化成每个事件一个桶。现改为 `CAST(ts / 3600 AS INTEGER) * 3600`（两处），并补小时路径用例（此前该分支零引用，所以漏网）。
  *Fixed hourly bucketing in the stats history being a no-op. SQLite's `/` performs floating-point division on integers, so `(ts/3600)*3600` did not truncate and `GROUP BY` degenerated to one bucket per event. Now uses `CAST(ts / 3600 AS INTEGER) * 3600` in both places, with tests for the hourly path (previously unreferenced, which is how it slipped through).*
- 修复 **SSE 负载不是 JSON 对象时的异常路径**，并修复 `CONNSTR` 正则 `[a-z][a-z0-9+.-]*://` 在长标识符文本上的超线性回溯：量词封顶 `{0,63}`（32KB 语料 1345ms → 7.4ms）。同时修好了对抗语料本身的假阴性——原语料只有 2 个词起始位置，形不成「N 起点 × O(N) 回溯」的乘积，倍率恒为 2.00，从不告警。
  *Fixed the exception path for non-object SSE payloads, and the super-linear backtracking of the `CONNSTR` pattern `[a-z][a-z0-9+.-]*://` on long identifier text by capping the quantifier to `{0,63}` (32KB input: 1345ms → 7.4ms). The adversarial corpus itself had a false negative — it contained only two word-start positions, so it could not produce the "N starts × O(N) backtracking" product and always reported a 2.00× ratio, never warning.*
- 修复**事件库损坏后面板永久 500**：`DatabaseError`（真损坏）现在把坏文件挪成 `event-store.sqlite3.corrupt-<时间戳>` 并重建空库（**绝不删除**原文件）；`OperationalError`（锁竞争、路径不可写）保持原样抛出，不碰用户文件。同时读路径不再每次查询都跑十几条 `CREATE TABLE/INDEX IF NOT EXISTS`（按路径记忆，换路径才重建），并修掉 `_connect()` 在 PRAGMA 失败时泄漏连接的问题。
  *Fixed the panel returning 500 forever after event-store corruption. A `DatabaseError` (genuine corruption) now moves the file aside as `event-store.sqlite3.corrupt-<timestamp>` and recreates an empty store — the original is never deleted — while an `OperationalError` (lock contention, unwritable path) still propagates without touching user files. Read paths no longer re-run a dozen `CREATE TABLE/INDEX IF NOT EXISTS` per query (the schema is now remembered per path and rebuilt only when the path changes), and `_connect()` no longer leaks a connection when a PRAGMA fails.*
- 修复**日志列表按类型过滤时的全量排序**：补 `(type, id)` 复合索引。查询形态是 `WHERE id > ? AND type = ? ORDER BY id LIMIT n`（按 id 游标增量取某一类型），只有 `(type, ts)` 时会退化成「扫完整个类型段 → 临时排序树」；100 万行实测首屏 292ms → 6ms、增量 40ms → 5ms。`(type, ts)` 保留给按时间范围的聚合查询。
  *Fixed full sorting when filtering the log list by type by adding a `(type, id)` composite index. The query shape is `WHERE id > ? AND type = ? ORDER BY id LIMIT n` (cursor-by-id, single type), which degraded to "scan the whole type range then build a temp sort tree" with only `(type, ts)` present; measured on 1M rows, first load went 292ms → 6ms and incremental polling 40ms → 5ms. `(type, ts)` is kept for time-range aggregations.*
- 修复**桌面壳「假就绪」**：就绪判定从「5801 TCP 可连」改为请求免令牌的 `/healthz`。端口被无关进程占用、或 Flask 已 listen 但工作线程死锁时，TCP 握手照样成功，于是壳把状态置为就绪、托盘显示「引擎已就绪」，而前端所有请求超时。watchdog 的假死判定同样改用 `/healthz`（Flask 死锁时端口照常握手，只探 TCP 永远看不到假死）。
  *Fixed false-ready states in the desktop shell: readiness now probes the token-free `/healthz` instead of just opening a TCP connection to 5801. When the port is held by an unrelated process, or Flask is listening but its worker threads are deadlocked, the TCP handshake still succeeds — so the shell marked itself ready and the tray said "engine ready" while every request timed out. The watchdog's hang detection uses `/healthz` too, since a deadlocked Flask still completes TCP handshakes.*
- 修复**手动重启引擎阻塞界面**：`restart_engine` 改为后台线程执行并立即返回（此前同步执行，含最长 3s 等待收尾 + 20s 就绪轮询，IPC 线程被占满，前端 await 期间表现为「点了没反应」）。同时用 Drop 兜底复位 `restart_in_flight`——该标志位若因 panic 留在 `true`，watchdog 会永久 `continue`，与上面那条自愈失效是同一失效模式。
  *Fixed the manual engine restart blocking the UI: `restart_engine` now runs on a background thread and returns immediately (it used to run synchronously, including up to 3s of graceful-shutdown waiting plus a 20s readiness poll, occupying the IPC thread so the UI looked frozen). A Drop guard now resets `restart_in_flight`, because leaving it `true` after a panic would make the watchdog `continue` forever — the same failure mode as the self-healing bug above.*
- 修复**壳层与引擎的面板端口环境变量不一致**：壳只认 `SHIELD_ENGINE_PORT`，引擎只认 `LLM_SHIELD_PANEL_PORT`，用户按任一侧改端口后壳仍探 5801，永远判不出「已就绪」。壳现在两个名字都认（优先引擎侧那个）。
  *Fixed the panel-port environment variable mismatch between shell and engine: the shell only honoured `SHIELD_ENGINE_PORT` while the engine only honoured `LLM_SHIELD_PANEL_PORT`, so changing the port on either side left the shell probing 5801 and never reporting ready. The shell now accepts both, preferring the engine's.*
- 修复**引擎日志无限增长**：壳在追加前做 5 MiB 轮转（保留一份 `.1`）。引擎的 stdout/stderr 是 append 打开的，桌面端常驻数周可涨到几百 MB。同时关闭 werkzeug 逐请求访问日志（面板每 2.5s 轮询一次，默认关；`MASKIT_ACCESS_LOG=1` 可开），被拒绝的控制面请求改为一条结构化日志，只记方法/路径/原因/来源，不记令牌（连长度都不记）。
  *Fixed unbounded engine log growth: the shell now rotates at 5 MiB before appending (keeping one `.1`). The engine's stdout/stderr is opened for append and could reach hundreds of MB over weeks of desktop uptime. Werkzeug's per-request access log is now off by default (the panel polls every 2.5s; set `MASKIT_ACCESS_LOG=1` to re-enable), and rejected control-plane requests produce one structured line recording method/path/reason/origin only — never the token, not even its length.*
- 修复**发版脚本的静默失败**：`release.ps1` 的原生命令（`git pull` / `add` / `commit` / `push` / `tag`）此前不检查退出码，PowerShell 的 `$ErrorActionPreference` 也管不到外部进程，失败会继续往下走并打印「发布完成」。现每步校验退出码、tag 已存在必须中止、无改动时明确提示 tag 未推送并给出手动命令、detached HEAD 直接拦截。
  *Fixed silent failures in the release script: its native commands (`git pull` / `add` / `commit` / `push` / `tag`) did not check exit codes, and PowerShell's `$ErrorActionPreference` does not cover external processes, so a failure would continue and still print "release complete". Every step now verifies its exit code, an existing tag aborts, a no-change run states plainly that the tag was not pushed and prints the manual command, and a detached HEAD is rejected up front.*
- 修复**未签名时发版工作流静默降级**：缺少更新签名密钥时保留 Release 草稿并输出 `::warning::`，不再生成一个「装不上更新」的正式版。
  *Fixed the release workflow silently degrading when unsigned: with no update-signing key it now keeps the Release as a draft and emits a `::warning::` instead of publishing a release whose builds cannot auto-update.*
- 修复 `tests/soak_health.py` **读错数据目录**：产品更名为 Data Maskit 后数据目录已变成 `%APPDATA%\Maskit`，脚本仍按 `%APPDATA%\LLMShield` 读取，事件库计数恒为 `-1`、令牌永远读不到，整份巡检结果失真却不报错。现按引擎同一口径解析（优先 `LLM_SHIELD_DATA_DIR`），端口也认引擎侧变量。
  *Fixed `tests/soak_health.py` reading the wrong data directory: after the rename to Data Maskit the data root became `%APPDATA%\Maskit`, but the script still read `%APPDATA%\LLMShield`, so the event count was always `-1`, the token was never found, and the whole soak report was quietly meaningless. It now resolves the directory the same way the engine does (preferring `LLM_SHIELD_DATA_DIR`) and honours the engine's port variable.*
- 修复**重启引擎后日志插件在正式版不生效**：`tauri-plugin-log` 此前只在 debug 构建注册，正式版里壳层所有 `log::warn!` / `log::error!`（自启自愈失败、更新后重启失败、系统代理地址解析失败）全部丢失，用户遇到问题没有任何可查线索。现正式版也注册，并把文件上限从插件默认的 40KB 提到 2MiB、保留两份。
  *Fixed the log plugin being inactive in release builds: `tauri-plugin-log` was only registered under debug, so every shell-side `log::warn!` / `log::error!` (autostart self-heal failure, post-update restart failure, system-proxy resolution failure) was lost in production, leaving users with nothing to inspect. It is now registered in release as well, with the file limit raised from the plugin's 40KB default to 2MiB and two files kept.*
- 修复**流式响应极端长行/无分隔符数据流导致内存无上限增长**：为 SSE / NDJSON 流式接管增加 `_SSE_BUF_MAX`（4MB）半事件缓冲上限，流式处理优先在最后换行符保留完整事件行以保护合法 JSON 不被截碎，超限时强制刷新重置；同时修复响应扫描超长时 CPU 阻塞事件循环风险（`_SCAN_BODY_MAX` 512KB 封顶截断 + 特征预检），以及反向代理返回 HTML 403 时前端误清 token 强制踢出用户的边界问题。
  *Fixed unbounded memory growth when handling extreme streaming lines or delimiter-free streams: added a 4MB buffer cap (`_SSE_BUF_MAX`) for SSE / NDJSON, preserving line boundaries where possible to avoid corrupting valid JSON and flushing on overflow; also capped whole-response scanning (`_SCAN_BODY_MAX` at 512KB + pattern precheck) to prevent event loop blocking, and fixed a frontend edge case where a reverse proxy HTML 403 erroneously cleared the auth token.*
- 修复**被拒绝的控制面请求缺少现场**：关闭 werkzeug 访问日志后，403 不再无迹可循（见上）。
  *Fixed rejected control-plane requests leaving no trace: with werkzeug's access log disabled, a 403 no longer passes without a record (see above).*

### 优化 / Changed
- 发版链路加固：`ci.yml` / `release.yml` / `test-macos-build.yml` 各 job 增加 `timeout-minutes`；`release.yml` 的 `docker` job 改为 `needs: [docker-smoke, desktop]`，避免桌面端失败却已把 `latest` 推到 `ghcr.io`；`.github/dependabot.yml` 注明 `open-pull-requests-limit: 0` 是自 0.2.1 起有意关闭常规版本更新 PR（经 git 历史确认），而非漏填。
  *Release pipeline hardening: every job in `ci.yml` / `release.yml` / `test-macos-build.yml` now sets `timeout-minutes`; `release.yml`'s `docker` job now `needs: [docker-smoke, desktop]` so a failed desktop build cannot leave `latest` already pushed to `ghcr.io`; and `.github/dependabot.yml` documents that `open-pull-requests-limit: 0` intentionally disables routine version-update PRs (confirmed via git history), rather than being an omission.*
- 文档与代码对齐：`AGENTS.md` §4、`CONTRIBUTING.md`、`docs/RELEASE_CHECKLIST.md` 统一指向 `scripts/verify-all.py` 作为门禁唯一清单（不再各自抄一份命令）；`docs/BRANCH_PROTECTION.md` 补上 `rust-macos` 必需项与用 `gh api` 核对的方法；`docs/PLATFORM_SUPPORT.md` 修正「官方桌面端仅支持 Windows」与 macOS DMG 已发布的矛盾表述及 Node 版本下限；`SECURITY.md` 新增环境变量清单（含 `MASKIT_ACCESS_LOG`）并说明 `LLM_SHIELD_*` 遗留前缀的处理口径。
  *Documentation aligned with the code: `AGENTS.md` §4, `CONTRIBUTING.md` and `docs/RELEASE_CHECKLIST.md` now all point at `scripts/verify-all.py` as the single gate manifest instead of each copying the command list; `docs/BRANCH_PROTECTION.md` adds the `rust-macos` required check and how to verify it via `gh api`; `docs/PLATFORM_SUPPORT.md` fixes the contradiction between "desktop builds are Windows-only" and the already-shipped macOS DMG, plus the Node version floor; and `SECURITY.md` gains an environment-variable table (including `MASKIT_ACCESS_LOG`) and states how the legacy `LLM_SHIELD_*` prefix is handled.*
- 清理死代码与过时注释：删除从未被调用的 `_placeholder()`（其 docstring 描述的「每会话随机占位符」与现行的滑动窗口复用设计相矛盾）；修正指向已不存在的 `app.py` / `panel.bat` 的注释，以及一条会指引用户运行不存在文件的权限报错文案；`{{LABEL_hex6}}` 等过时格式说明改为与当前后缀字符集一致。
  *Dead code and stale comments removed: deleted the never-called `_placeholder()` (whose docstring described per-session random placeholders, contradicting the sliding-window reuse design now in place); fixed comments referencing the long-gone `app.py` / `panel.bat` and an admin-permission error message that told users to run a file that no longer exists; and updated format notes such as `{{LABEL_hex6}}` to match the current suffix alphabet.*

## [0.2.8] - 2026-09-12

修复占位符「按后缀反查」兜底在预热后失效、反向代理非白名单路径明文上行安全漏洞，以及 Responses API 流式响应多 part 通道缓冲隔离。  
Release v0.2.8: Fix false-positive suffix index collision disabling placeholder fallback after warm-up, resolve cleartext forwarding on non-whitelisted reverse-proxy paths under fail-closed, and isolate multi-part Responses SSE buffers.

### 修复 / Bug Fixes
- 修复**占位符「按后缀反查」兜底在启动预热后大面积失效**的问题：后缀索引登记时用对象身份比较（`is not`）判断是否撞车，而预热从事件库 `json.loads` 出来的 token 与索引里已存的那个**值相等但对象不同**——同一个 token 被登记两次就会被误判成撞车，后缀被永久标记为不可用。复用表的设计目的就是跨请求复用同一占位符，因此事件库里同一 token 出现多条事件是常态，预热覆盖的事件越多、失效面越大；且该状态**无法自愈**，运行时的补登记也救不回来。表现为模型改写花括号、标签大小写或尾部残缺的占位符还原不出来，且没有任何日志，用户只能看到裸占位符。现改为值比较（`!=`）；真撞车（两个不同 token 抢同一后缀）的处理语义完全不变（感谢 @duncan0k 报告 #27）。
  *Fix: the suffix-index fallback for placeholder restoration was silently disabled after startup warm-up. The index used identity comparison (`is not`) to detect suffix collisions, but tokens rehydrated from the event store via `json.loads` are equal by value yet distinct objects — registering the same token twice was treated as a collision and the suffix was permanently marked unusable. Reusing one placeholder across requests is exactly what the reuse table is for, so multiple events per token are the norm and the blast radius grew with every warm-up; the state was also unrecoverable at runtime. Symptom: placeholders whose braces, label casing or trailing braces the model rewrote were never restored, with no log line at all. Now compares by value (`!=`); genuine collisions (two different tokens sharing a suffix) behave exactly as before (thanks to @duncan0k in #27).*
- 修复 **fail-closed 开启时非白名单路径的 JSON 请求仍明文上行**的问题：反向代理模式下，请求已经落在用户配置的上游路由上，但若路径不在该上游的白名单内、且请求体不含任何已知 LLM 特征键，此前会直接原样转发，**完全不检查 fail_closed**（默认开启）。未配置 `paths` 时白名单只有 7 条默认路径，`/v1/vector_stores`、`/v1/fine_tuning/jobs`、`/v2/...` 以及厂商新增端点上的 `{"text":"张三 13800138000"}` 都会明文直达上游。这与主管线「已配置路由 + fail-closed 一律脱敏」的口径冲突——放行判据 `_LLM_BODY_KEYS` 是白名单，永远追不上新协议；此前还存在「请求体解析失败反而比解析成功更安全」的倒挂。现改为 fail_closed 开启时统一交给主管线按未知形态脱敏，仅用户显式关闭 fail_closed 时才透传。⚠️ 行为变化：此后反向代理模式下 `/v1/files`、`/v1/fine_tuning/jobs` 等管理类 JSON 调用也会进入脱敏并建立会话（感谢 @duncan0k 报告 #28）。
  *Fix: JSON requests on non-whitelisted paths were forwarded in cleartext even with fail-closed enabled. In reverse-proxy mode, once a request matched a configured upstream, a path outside that upstream's whitelist with a body carrying none of the known LLM keys was passed through verbatim **without ever consulting fail-closed** (on by default). With no `paths` configured the whitelist is only the 7 default entries, so `/v1/vector_stores`, `/v1/fine_tuning/jobs`, `/v2/...` and any new vendor endpoint receiving `{"text":"张三 13800138000"}` went upstream in the clear. That contradicts the main pipeline's rule — "configured route + fail-closed ⇒ always mask" — and the allow-list `_LLM_BODY_KEYS` can never keep up with new protocols; it also produced the perverse result that a body failing to parse was safer than one that parsed fine. Now such requests are handed to the main pipeline and masked as unknown shape when fail-closed is on; passthrough only happens when the user explicitly turns fail-closed off. ⚠️ Behaviour change: management-style JSON calls such as `/v1/files` and `/v1/fine_tuning/jobs` are now masked and create a session in reverse-proxy mode (thanks to @duncan0k in #28).*
- 修复 **Responses 流式响应中同一 output item 的多个 content part 共用还原缓冲**的问题：通道键此前只用 `output_index`，而规范允许一个 message item 携带多个 `output_text` part，于是 part 0 的 `.done` 会清掉 part 1 的半截占位符缓冲，交错的增量也会把半截占位符串进另一个 part 的正文。现按 `content_index` 隔离通道；`content_index` 缺失或为 0 时通道键与改动前完全一致，官方端点（每条消息仅一个 part）的行为零变化。此问题主要影响自建/中转的多 part 实现（感谢 @duncan0k 报告 #29）。
  *Fix: multiple content parts of one Responses output item shared a single restoration buffer. The channel key used only `output_index`, but a message item may carry several `output_text` parts, so part 0's `.done` discarded part 1's buffered half-placeholder and interleaved deltas spliced a half-placeholder into the other part's text. Channels are now separated by `content_index`; when it is missing or 0 the key is byte-for-byte what it was before, so official endpoints (one part per message) behave exactly as before. This mainly affects self-hosted or relayed implementations that emit multiple parts (thanks to @duncan0k in #29).*
- 修复**发版脚本可能把 `[Unreleased]` 章节渲染成线上 Release body**的问题：`render-release-notes.py` 一直声明该章节不参与渲染，但实现里并没有这条规则，此前只是**碰巧**因为章节为空才报错。一旦按正常流程在发版前往 Unreleased 写入条目，这个防护就失效——若误传 `Unreleased` 作为版本号，未发布内容会被发到线上 Release 页。现显式拒绝该版本号。
  *Fix: the release-notes script could render the `[Unreleased]` section into a published GitHub Release body. `render-release-notes.py` always claimed that section is excluded, but nothing in the implementation enforced it — it only errored out **by accident** because the section happened to be empty. As soon as entries are written to Unreleased (the normal pre-release workflow) that guard disappears, and passing `Unreleased` as the version would publish unreleased notes. The version is now rejected explicitly.*

## [0.2.7] - 2026-09-11

命令行工具调用中的占位符还原加固、敏感词管理页「从 .env 导入」，以及 macOS (Apple Silicon) 原生 DMG 发布与在线更新。  
Release v0.2.7: Harden placeholder restoration in command-line tool calls, add ".env import" to the sensitive-word manager, and support native macOS (Apple Silicon) DMG release with OTA updates.

### 新增 / Features
- 敏感词管理页新增「📂 从 .env 导入」：粘贴或选择 `.env` 文件后自动解析（支持 `export` 前缀、单双引号、双引号转义、行内注释、BOM、CRLF、重复 key），按变量名与值形态**智能识别凭据**并推荐对应分类，可逐行勾选与调整目标分类后一键合入词库；解析时自动跳过空值、过短（< 3 字符，避免无边界子串匹配误伤代码）、超长（> 200 字符，后端会静默丢弃）与重复定义的行，并在预览区列明跳过原因。
  *Feature: Added "Import from .env" to the sensitive-word manager. Paste or pick a `.env` file and it is parsed automatically (`export` prefix, single/double quotes, double-quote escapes, inline comments, BOM, CRLF, duplicate keys). Rows are heuristically classified as credentials by variable name and value shape, with a recommended category you can review and change per row before merging into the word list in one click. Blank, too-short (< 3 chars, which would substring-match and corrupt surrounding code), too-long (> 200 chars, silently dropped by the backend) and duplicate rows are skipped with the reason shown in the preview.*
- **凭据类行的目标分类被收窄为 7 个凭据标签**（`API_KEY` / `TOKEN` / `SECRET` / `ACCESS_KEY` / `JWT` / `CONNSTR` / `PRIVATE_KEY`）：词库分类名会原样成为占位符标签，只有这 7 个标签才会让引擎对事件库**只写摘要与掩码、不写原文**；把密钥导入其它分类等于把明文写进本地 SQLite。
  *Credential rows can only target the 7 credential labels (`API_KEY` / `TOKEN` / `SECRET` / `ACCESS_KEY` / `JWT` / `CONNSTR` / `PRIVATE_KEY`). A category name becomes the placeholder label verbatim, and only these 7 labels make the engine store a digest and mask — never the plaintext — in the local event database. Importing a secret under any other category would write it to SQLite in cleartext.*
- 新增 `scripts/check-env-import.mjs`（27 项边界用例，含真实 `.env` 样例端到端），已接入 CI 门禁（`frontend` job，Node 22）。
  *Added `scripts/check-env-import.mjs` (27 edge cases including an end-to-end real-world `.env` sample), now wired into the CI gate (`frontend` job, Node 22).*
- 支持 macOS 原生 DMG 桌面安装包自动构建：GitHub Actions Release 工作流增加 `macos-latest` arm64 编译节点，正式 Release 自动附带 `Maskit_<版本>_aarch64.dmg`。
  *Support native macOS DMG bundle compilation: Added `macos-latest` arm64 runner to GitHub Release workflow, producing `Maskit_<version>_aarch64.dmg` automatically on release.*
- 统一跨平台自动更新元数据 `latest.json`，同时支持 Windows (`windows-x86_64`) 与 macOS (`darwin-aarch64`) 在线签名静默/增量升级。
  *Unified multi-platform `latest.json` updater manifest supporting both Windows (`windows-x86_64`) and macOS (`darwin-aarch64`) OTA signature-verified updates.*
- 新增 `scripts/check-workflows.py` 并接入 CI 门禁（`version` job）：校验 `.github/workflows` 下每个 workflow 的 YAML 可解析、job 与 step 结构完整，并把显式 `shell: bash` 的步骤抽出来跑 `bash -n`。此前 CI 不 lint workflow，YAML 或 `run` 块写坏只会在推送后（最坏是发版那一刻）才暴露。
  *Added `scripts/check-workflows.py` to the CI gate (`version` job): it checks that every workflow under `.github/workflows` parses as YAML with a well-formed job/step structure, and runs `bash -n` on steps that declare `shell: bash`. Previously CI did not lint workflows, so a broken YAML file or `run` block only surfaced after the push — at worst at release time.*

### 修复 / Bug Fixes
- 修复**日志保留天数设为 0（永久保留）失效**的问题：底层已支持 0 天不清理，但控制面多处使用 `value or 7` 短路判断，导致设为 0 时被强制回退为默认 7 天。现统一通过 `_normalize_retention` 归一化处理，前端设置输入框增加负数防呆限制并在中英文提示中明确「0 表示永久保留」（感谢 @Shy7777 提交 #22）。
  *Fix: Preserve unlimited log retention when retention days is set to 0. The backend storage already supported 0 as unlimited, but panel endpoints fell back to 7 days via truthiness checks (`value or 7`). Normalized retention parsing across endpoints, added input sanitation, and updated bilingual tooltips to reflect unlimited retention (thanks to @Shy7777 in #22).*
- 修复**流式响应中输入 Token 少记或丢失**的问题：Anthropic 协议将输入用量放在开头的 `message_start`，而 Responses 协议使用 `response.usage`；长流式响应（>64KB）会把开头挤出尾部缓冲区导致输入用量永久漏计，后续 chunk 还会把已有字段冲掉。现支持完整事件用量合并，透传模式引入 `SSEUsageAccumulator` 逐行累积 SSE 用量，低内存且不受截断影响（感谢 @Shy7777 提交 #23）。
  *Fix: Collect token usage reliably across streaming protocols. Anthropic puts input tokens in the initial `message_start` and Responses uses `response.usage`; long streams (>64KB) previously pushed early chunks past the tail buffer, losing prompt counts, while later chunks could overwrite existing fields. Now merges usage across snapshots and uses `SSEUsageAccumulator` in passthrough mode to track streaming lines with bounded memory (thanks to @Shy7777 in #23).*
- 修复**日志页切后台积压后恢复轮询跳漏记录**的问题：当积压超过 200 条时，旧逻辑使用 `ORDER BY id DESC LIMIT 200` 截断了最早的数据，客户端游标跳跃导致中间记录被永久跳过。现增量查询改用 `ORDER BY id ASC LIMIT ?`，配合 `has_more` 与 `next_since` 游标，前端支持最多 5 页连续追赶拉取（感谢 @Shy7777 提交 #24）。
  *Fix: Avoid skipping events during incremental log polling. When more than 200 events accumulated in the background, `ORDER BY id DESC LIMIT 200` truncated the oldest unread records, advancing the cursor past unseen rows. Incremental queries now paginate in ascending order (`ORDER BY id ASC`), returning `has_more` and `next_since` for up to 5 catch-up batches in the UI (thanks to @Shy7777 in #24).*
- 修复**多候选回答（`n > 1`）或稀疏 Choice 时流式还原错乱与断流**的问题：原逻辑按 chunk 内的数组位置区分通道，导致不同 `choice.index` 混用缓冲拼错半截占位符，且一个 choice 结束会暴力清空所有通道。现按真实 `choice.index` 隔离还原缓冲区，结束事件仅定向刷新对应通道，并补齐 Responses 终态快照清理（感谢 @Shy7777 提交 #25）。
  *Fix: Isolate SSE restoration by completion choice index. Chunks with sparse choices previously shared restoration channels based on array positions, concatenating partial placeholders across choices and prematurely flushing unrelated channels on completion. Restorations are now isolated by `choice.index`, only finishing channels are flushed, and completed Responses snapshots clear stale tails (thanks to @Shy7777 in #25).*
- 修复**设置页快速切换规则时的竞态覆盖回滚**：连续点击规则开关时，整表旧快照被依次入队发送，导致后一次保存把前一次修改覆盖（例如连续关 EMAIL 和 PHONE，EMAIL 又会被恢复开启）。现新增受控的 `/api/config/builtin_rules` 原子更新接口，仅在锁内合并提交的变更字段，并防呆禁用空规则操作（感谢 @Shy7777 提交 #26）。
  *Fix: Preserve independent rule changes during queued saves. Rapidly toggling built-in rules previously queued full snapshots based on stale state, causing the second save to overwrite the first (e.g. toggling off EMAIL and then PHONE would turn EMAIL back on). Added a dedicated `/api/config/builtin_rules` atomic endpoint to patch changed rules under the configuration lock (thanks to @Shy7777 in #26).*
- 修复模型把占位符写成**转义形态**（`\{\{IPPRIVATE_x\}\}`）时还原不彻底、留下 `\{\` 与 `\}\}` 残渣的问题：真值确实出来了，但命令仍然是坏的，用户会误判成「还原成功」，比彻底不还原更危险。现在整个转义块连同反斜杠一并替换，且流式响应的 chunk 边界落在反斜杠与花括号之间时也不再漏残渣。
  *Fix: Fully restore escaped placeholders (`\{\{X\}\}`) including their backslashes, instead of leaving `\{\` / `\}\}` residue that silently breaks the resulting command — previously the real value appeared while the command stayed broken, which is more dangerous than no restore at all.*
- 修复模型改写占位符**标签**（`IPPRIVATE` → `IP_PRIVATE`、或整段小写）导致完全还原不了的问题：按 6 位随机后缀反查即可救回（仅纯辅音后缀入索引，标签被整段换名时仍拒绝猜测，宁可失败可见）。同时修正这类还原在事件明细里被误标成「未还原」的问题。
  *Fix: Restore placeholders whose label the model rewrote (`IPPRIVATE` → `IP_PRIVATE`, or lowercased) via reverse-lookup on the 6-char random suffix. Only consonant suffixes are indexed, and renamed labels are still refused rather than guessed. Also corrects such restores being wrongly flagged as "not restored" in event details.*
- 修复**流式响应中途出错时丢弃已扣留文本**的问题：还原函数默认只清空一个缓冲槽，正文、思考、工具参数各自通道里被扣住的半截占位符会被静默丢弃，客户端看到的文本凭空少一截（实测：`结尾{{NAME_ab` 之后直接跳到下一块）。现在异常分支会把各通道滞留一并补发，且补发事件独立成行——与残片粘成 `data: {…}data: {…}` 时，严格按行解析的 SDK 会整条丢弃，等于白补。
  *Fix: Stop dropping withheld text when a streaming response fails mid-stream. The restore call only flushed a single buffer slot, so half-placeholders held per channel (content / reasoning / tool arguments) were silently discarded and the client saw a gap in the text. The error path now flushes every channel, and each flush event is emitted on its own line — glued onto a fragment as `data: {…}data: {…}` a strict line-based SDK would discard the whole event.*
- 修复「从 .env 导入」里**选了目标分类却忘了勾选该行**时的死角：确认按钮置灰、文案是「导入 0 项」，而页脚提示只覆盖「勾了但没选分类」这一种情况，用户完全无从判断为什么点不动（真机复现）。现在**选中目标分类即视为确认导入该行**，会自动把它勾上；用户仍可手动取消勾选。
  *Fix: Selecting a target category now auto-checks that row. Previously, choosing a category without ticking the checkbox left the confirm button disabled and reading "Import 0" with no explanation — the footer hint only covered the opposite case (ticked but no category), so users had no way to tell why they could not proceed. The checkbox can still be unticked manually.*

### 优化 / Improvements
- 增强 `generate-latest-json.py` 多平台签名解析，提前绑定版本标签防止未绑定变量异常。
  *Improve multi-platform signature parser in `generate-latest-json.py` to ensure robust manifest generation across platforms.*
- 独立 Windows 与 Unix 平台的 Python 依赖安装步骤，规避跨 Shell 语法差异。
  *Separate platform-specific Python installation steps in Release workflow to prevent shell syntax conflicts.*
- 修正 Release 说明文案与实际行为不符的问题：原文案称「本工作流不组装也不发布 `latest.json`」，而紧接着的步骤就会组装并上传该文件，属公开发布页上的用户可见错误信息；未签名包的 `UNSIGNED.txt` 标记与未签名场景的说明也一并改为只陈述该安装包自身缺少签名，不再对全局更新元数据下结论。
  *Fix: Corrected the release notes to match what the workflow actually does. The text claimed the workflow "does not assemble or publish latest.json updater metadata" while the very next steps do exactly that — a user-visible error on the public release page. The `UNSIGNED.txt` marker and the unsigned-build note now state only that the bundle itself carries no signature instead of making a claim about the global manifest.*
- 消除还原路径上两处**正则回溯**引起的超线性耗时：`_PARTIAL_RX` 与 `_ESCAPED_PLACEHOLDER_RX` 中的无上限反斜杠量词（`\\*` / `\\+`）在「连续反斜杠」文本上会退化成 O(N²)，32KB 输入实测 293ms（流式场景下会拖慢每个 chunk，表现为编辑器里逐字输出卡顿）。量词封顶为 `\\{0,3}` / `\\{1,3}` 后恢复线性（同输入 0.4ms），且对全部真实转义形态逐条等价。已对引擎热路径上的所有正则做回溯扫描，确认无其它超线性项。
  *Improve: Remove two super-linear regex backtracking hotspots in the restore path. Unbounded backslash quantifiers (`\\*` / `\\+`) in `_PARTIAL_RX` and `_ESCAPED_PLACEHOLDER_RX` degraded to O(N²) on runs of backslashes — 293 ms for a 32 KB input, which slowed every chunk in streaming mode and showed up as stuttering output. Capping them at `\\{0,3}` / `\\{1,3}` restores linear behaviour (0.4 ms for the same input) with identical results on every real escape form. All regexes on the engine hot path were scanned for backtracking; no other super-linear case remains.*

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

[0.4.0]: https://github.com/xiaYuTian11/maskit/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/xiaYuTian11/maskit/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/xiaYuTian11/maskit/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/xiaYuTian11/maskit/compare/v0.2.12...v0.3.0
[0.2.12]: https://github.com/xiaYuTian11/maskit/compare/v0.2.11...v0.2.12
[0.2.11]: https://github.com/xiaYuTian11/maskit/compare/v0.2.10...v0.2.11
[0.2.10]: https://github.com/xiaYuTian11/maskit/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/xiaYuTian11/maskit/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/xiaYuTian11/maskit/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/xiaYuTian11/maskit/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/xiaYuTian11/maskit/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/xiaYuTian11/maskit/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/xiaYuTian11/maskit/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.2.3
[0.2.2]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.2.2
[0.2.1]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.2.1
[0.2.0]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.2.0
[0.1.0]: https://github.com/xiaYuTian11/maskit/releases/tag/v0.1.0
