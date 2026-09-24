# 安全政策（Security Policy）

## 支持的版本

| 版本 | 支持状态 |
|------|---------|
| 最新 release | 积极支持 |
| 更早版本 | 不再维护 |

## 报告漏洞（Reporting a Vulnerability）

请**不要**在 GitHub Issues 公开披露漏洞细节。通过以下方式私密报告：

1. GitHub Security Advisories（推荐）：仓库 → Security → Report a vulnerability
2. 或在 GitHub 上私信维护者 [@xiaYuTian11](https://github.com/xiaYuTian11)

请在报告中包含：

- 受影响版本
- 复现步骤（最小化）
- 影响描述（能拿到什么/破坏什么）
- 建议修复（可选）

我们承诺 7 天内回复确认，修复后按严重级别协调披露时间。

## 威胁模型与信任边界

Data Maskit 是一个**本地脱敏代理**：拦截本机 LLM API 请求，敏感信息替换为占位符后转发上游，响应返回前还原。

### 明文数据在哪、留多久、谁能读

数据目录：Windows `%APPDATA%\Maskit`，macOS `~/Library/Application Support/Maskit`，Linux `~/.local/share/maskit`，Docker `/data`（卷），源码运行 `engine/`。

| 数据 | 文件 | 保留时间 | 访问控制 |
|------|------|---------|---------|
| 事件明细（含普通 PII 原文） | `shield-events.sqlite3` | 默认 7 天（可配置） | Windows 打包版启动时 ACL 收紧到当前用户；其它平台依赖目录权限 |
| 凭据类原文（API key/token） | **不落库**（只存 preview + sha256 摘要） | — | — |
| proxy_token（面板 API 令牌） | `proxy_token` | 每次启动重新生成 | 同数据目录 |
| 配置（upstream/词表/规则） | `config.json`（+ `config.json.bak-*` 备份） | 永久 | 同数据目录 |
| 调试日志（仅 `debug: true` 时） | `debug-YYYYMMDD.log`，**含未脱敏请求原文** | 手动清理 | 同数据目录；默认关闭 |

> 内存中另有一张「占位符 ↔ 原文」复用表（不落盘）：规则命中的条目按该表 TTL 回收（至少 24 小时，`session_ttl` 更大时跟随），
> 只服务于跨请求复用与流式还原。**例外**：已启用的自定义敏感词（`custom_words`）其映射常驻到该词被禁用或删除为止——
> 它取自用户自己配置里本就明文保存的词表，长任务与工具调用需要它跨会话稳定；一旦禁用或删除，立即回到上面的回收规则。

### 出站清单（本项目承诺零遥测，以下是全部主动出网点）

| 出站 | 默认 | 内容 | 关闭方式 |
|------|------|------|---------|
| 转发到你配置的 LLM 上游 | 开（这是产品功能） | 脱敏后的请求 | — |
| 模型价格目录同步（`price_sync_url`，默认 `mask.ciyuanroute.com`，失败回退 openrouter.ai） | **关** | 仅 GET，不带任何用户数据 | 设置 → 高级 → 价格同步 |
| 版本检查 / 更新下载（桌面版经 Tauri Updater；Web / Docker 版先由**浏览器**直连 GitHub API，失败再退到**服务端** `/api/update/check`） | **自动**：启动后约 8 秒静默查一次，之后每 6 小时复查；点「检查更新」可立即触发 | 当前版本号 | 无法关闭；仅探测版本号与元数据，不发送任何使用数据，下载仅在点击「安装」后发生 |

> Web / Docker 版先由浏览器直连 `api.github.com`（该源已在面板 CSP `connect-src` 放行）；
> 直连失败（浏览器到 GitHub 不通）时退到服务端 `/api/update/check`，源顺序为
> 「自定义源（`update_check_url`）→ 静态 `latest.json` → GitHub API」，结果缓存 10 分钟。
> 两条路都保留是因为出网能力属于谁取决于部署环境：国内服务器 + 用户本地有代理时
> 只有浏览器能通；内网/离线终端 + 服务器有出口时只有服务器能通。
> 静态 `latest.json` 不计入 GitHub 匿名 API 限流（60 次/小时/IP），服务端缓存
> 把多人共用出口的消耗压到 ~6 次/小时。可用 `update_check_url` 指向镜像或自建中转
> （设置 → 关于与更新）。

除上表外，引擎与前端**不发送任何统计、崩溃报告或日志**。反馈诊断包只在用户点击「保存」后生成到本地文件，由用户自行决定是否上传。

浏览器扩展（`extension/`）**只有一类出站：本机面板 `127.0.0.1` / `localhost` 的 `/api/ext/*`**（清单里 `host_permissions` 也只有这两个）。它不使用 `storage.sync`、不加载任何远程代码、不 `console.log` 请求正文，除面板外的任何地址都不在其权限范围内。

### 浏览器扩展桥接（Browser Bridge）

扩展把网页版 AI（ChatGPT / Claude）从浏览器发出的请求送进本引擎打码，回包按占位符流式还原。链路本身仍在**本机**完成，但**输入面比代理链路宽**，因此单独声明几条边界。

#### ① (A) / (B) 分流：只有引擎「明确拒绝」才阻断，其余一律直通

扩展按**响应里有没有 `blocking: true`** 判定，不是按状态码枚举：

- **(A) 阻断**——只有引擎显式标注 `blocking: true`：脱敏管线异常（503）、请求体超 32MB（413）、请求体非法（400）。命中即 reject，页面看到失败。
- **(B) 直通**——**其余全部**，包括 `403 ext_bridge_disabled`（面板关了扩展链路）、`403 invalid_token`（令牌错/轮换未更新）、引擎未启动 / 端口不通、任何未识别的状态码。

**必须明示的后果：`(B)` 里的 403 直通 = 未脱敏。**也就是说，**面板关掉开关或令牌失效时，请求会以原文发往上游**，扩展不会替你断网。这是刻意的默认（红线 3「绝不断网」优先），代价是「关掉/配错 ≠ 更安全，而是不脱敏」。扩展 popup 会把这些状态标成**红/黄色**并写明「未脱敏」，事件页/运行日志同时留痕，不要把它当成「已开启保护」。

枚举状态码必然漏（今日的 403 是直通，明天上游加个 418 就可能被误判成阻断导致全站断网），所以**默认桶只能给直通**。

**`ext_block_when_engine_down` 的作用范围是「整个 (B) 类」，不只是「引擎连不上」**（SPEC §0 / §5.1：该开关只管 (B) 类）。打开它等于把上面每一个 (B) 场景从「直通（未脱敏）」翻成「页面请求失败」：引擎进程未起、端口不通、超时、令牌失效、**面板里关掉扩展开关**、以及任何未识别状态。代价要看清：

- 打开后，**「在面板关掉扩展开关」不再等于直通，而是网页 AI 全站不可用**（因为 403 `ext_bridge_disabled` 也属 (B) 类）。如果你只是想在引擎挂掉时断网、又想保留「关开关即直连」，就不要打开它。
- 反过来也成立：**它是唯一能让上面那些 403 变成阻断的开关**。追求「宁可不脱敏也不出网」的场景（如受限网络策略下）才该打开。

引擎**明确**失败（`blocking:true`：脱敏管线异常 503 / 体积超限 413 / 请求体非法 400）恒阻断，无开关、不可配。

#### ② `ext_token`：位置、权限与轮换后果

- 位置：`config.json` 的 `ext_token`（与面板令牌 `proxy_token` / `X-Shield-Token` **是两个东西**）。
- **浏览器侧还有一份明文副本**：扩展把令牌存在 `chrome.storage.local` 的 `token` 键下（**不是** `storage.session`、**不是** `storage.sync`）。这意味着：① 它随浏览器 profile 落盘，profile 目录的任何读取者（同机其他用户、备份/同步工具、恶意扩展——后者本来就能读所有扩展的 local 存储）都能拿到它；② 它**不会**同步到你的浏览器账号（这正是禁用 `storage.sync` 的原因：那等于外传）。**因此 `ext_token` 的信任边界是「本机 profile」，不是「只有引擎知道」。** 设备共享或 profile 会被复制时，请到面板轮换令牌。
- 权限：只够打 `/api/ext/` 下的**五个**端点：`ping` / `mask` / `restore` / `mask-file` / `warn`。打 `/api/config`、`/api/ext/rotate-token` 等一律 403。轮换只能用面板令牌从 `/api/ext/rotate-token` 发起（**扩展自己没有旋转按钮**：它只有 `ext_token`，去调旋转端点必然 403；扩展设置页的「在面板中旋转令牌」只是替你打开面板设置页）。
- 这五个端点里**只有 `/api/ext/warn` 的调用方不受信任**：它是「疑似对话请求但 body 形态不受支持」的上报口，`path` 由页面提供，因此**已启用站点的任意页面脚本**都能打（不限本扩展注入的那两个脚本）——`panel.py` 的 `_EXT_WARN_MAX` 注释已把这当作前提。它能造成的后果限于**污染事件库与运行日志**（写一条 PASS/SKIP 事件），不能读写配置、不能取回令牌；去重表有硬上限（200 条）防止刷满。其余四个端点都必须携带正确 `ext_token` 且由自身站点脚本发起才有意义。
- 轮换后果：扩展持旧令牌 → 全部请求 `403 invalid_token` → **(B) 直通 = 未脱敏**，直到你到扩展设置里填入新令牌。**`_backup_config_file` 生成的 `config.json.bak-*` 里仍含旧令牌**，作废旧令牌时请一并清理这些备份。
- **403 的降速重试（可观测行为，别误判成"卡死"）**：`invalid_token` / `ext_bridge_disabled` 是**持续性**拒绝，而扩展的还原调用是**每个 SSE 分片一次**。若每次都真打一次面板，一条回答就能把面板 800 行运行日志环形缓冲冲干净（诊断能力归零）。所以扩展对这两类 403 进入**退避**：最多每 5s 真发一次请求，期间其余调用直接按 (B) 直通。副作用是——**在扩展设置里改对令牌后，最长约 5s 才恢复脱敏**（退避期内的探测命中即自愈）；popup 在此期间显示红标「已降速重试中」。注意这个降速**只影响扩展侧的重试节奏，不影响拒绝日志本身**：面板仍然照常记录 403（见 ④ 最后一条），只是频率从"每分片一行"降到"每 5s 一行"。
- **Origin 校验的一个例外（已实测）**：`/api/*` 默认做 Origin 同源校验；`/api/ext/` 下的**五个端点**（`ping` / `mask` / `restore` / `mask-file` / `warn`）额外放行**浏览器扩展 scheme** 的 Origin（`chrome-extension://` / `moz-extension://` / `safari-web-extension://`）。原因是扩展 SW 的 POST **确实带 `Origin: chrome-extension://<扩展ID>`**（非 GET/HEAD 请求按 Fetch 规范一律附加 Origin），而**扩展 ID 随安装方式与浏览器 profile 变化、引擎无法枚举**，不放行则每个脱敏请求都被 403 打回、扩展按直通处理 = 全站静默未脱敏。**Web 页面 Origin 仍然被拒**（放行只作用于上述五个端点），`ext_token` 仍是主防线。`Origin: null`（沙箱 iframe / `data:` / `file://` 这类**无来源**上下文）**不在放行范围**：扩展上下文恒有 `chrome-extension://` 来源，放行 `null` 没有任何合法调用方，只会给「本地 HTML + 已知令牌」多开一道门。

#### ③ 共享部署 = 未隔离（重要）
引擎的会话表、还原缓冲、事件库都是**进程级全局**，按 `sid` 区分，而 `sid` 由引擎签发、扩展回传。所以：

- 把同一个引擎（尤其 Docker / 远程模式）暴露给多人协作使用时，**持 token 的一方可以拿别人的 `sid`+文本去打 `/api/ext/restore`**，从而还原他人占位符；跨会话的还原缓冲回落同样存在。
- 结论：**扩展桥接只适用于单人本机场景**。多人共享请每人一套实例（或至少一套数据目录），不要靠 token 做租户隔离。

#### ④ 扩展链路的明文同样落本地事件库

- 扩展事件的输入是**浏览器里命中白名单的 LLM 请求体**，覆盖面明显宽于「用户主动发给 AI 的内容」——可能包含登录后自动填充的表单文本、粘贴的整段文档。
- 这些请求会写进本地事件库（`shield-events.sqlite3`），**非凭据条目的原文照旧明文入库**（与代理链路同一口径，凭据类仍只有 preview + sha256）。数据不出本机。
- 两个开关控制它，都在「设置 → 高级 → 日志与隐私」：
  - `ext_record_events`（**记录浏览器扩展流量**，默认开）：关闭后扩展链路**不写事件库与统计**，但**脱敏/还原照常**、popup 的 (A)/(B) 状态照常、`/api/ext/ping` 计数照常。
  - `record_plaintext_words`（统计记录明文，默认开）：关闭后词榜只记打码形态。
- **「关统计 ≠ 不脱敏」**：`ext_record_events` 只停持久化。反过来说，**想不再被记录，不能用「关掉扩展」以外的办法**——因为关掉扩展功能本身会让请求直通（未脱敏，见 ①）。
- 一条不受本开关管：`api_guard` 的 403 拒绝日志（`reason=invalid_token` / `ext_bridge_disabled`）是**安全事件**，照常记录——关掉它等于看不见「有人拿错 token 打端点」。

### Docker / 远程访问模式

`MASKIT_PANEL_HOST=0.0.0.0` 时面板进入远程模式：Host 校验放开、Origin 改为同源校验，**所有 `/api/*` 仍必须携带 `X-Shield-Token`**（来自 `MASKIT_PANEL_TOKEN`、`MASKIT_PANEL_TOKEN_FILE`，或启动日志打印的随机值）。5801 与 187xx 端口只应暴露给可信网络，反代端口本身不做鉴权，Compose 默认只绑定回环地址。

如果 HTTPS 在可信反向代理处终止，请显式设置 `MASKIT_TRUST_PROXY=1`，并让代理覆盖单跳 `X-Forwarded-Proto` / `X-Forwarded-Host`；应用默认不信任这些头。浏览器登录推荐打开根路径后粘贴令牌，临时链接使用 `/#token=...`（fragment 不进访问日志）；`?token=...` 仅为旧版本兼容。

`/api/*` 除令牌外还有一层 Origin 同源校验（CSRF 纵深防御）。若前置代理/CDN 回源时改写了 `Origin`，校验会拒绝这些请求；**静态资源（HTML / JS / CSS）不参与该校验**，因此即使校验拒绝也只会影响接口调用，不会导致页面白屏。遇到拒绝时优先排查代理是否正确透传 `X-Forwarded-Proto` / `X-Forwarded-Host` 并配合 `MASKIT_TRUST_PROXY=1`；仅在确实无法对齐时才关闭校验：环境变量 `MASKIT_DISABLE_ORIGIN_CHECK=1`（需在启动前设置，日志会打印警告）或设置页的 `origin_check` 开关（默认开启）。**关闭后 `/api/*` 的跨源防御只剩 `X-Shield-Token` 单层**，此时必须确保面板端口只暴露给可信网络。

### 环境变量清单

| 变量 | 默认 | 作用 | 安全提示 |
|------|------|------|---------|
| `MASKIT_PANEL_HOST` | `127.0.0.1` | 面板监听地址；设 `0.0.0.0` 进入远程模式 | 远程模式只应暴露给可信网络 |
| `MASKIT_LISTEN_HOST` | `127.0.0.1` | 反代/透传/兜底端口的监听地址 | 同上；Docker 下通常一起设为 `0.0.0.0` |
| `MASKIT_PANEL_TOKEN` | 随机生成 | 固定面板令牌（<16 位直接忽略并回退随机） | 等价于面板控制权，勿写入镜像或仓库 |
| `MASKIT_PANEL_TOKEN_FILE` | 无 | 从文件读取令牌（容器 secret 场景） | 文件权限须仅属主可读 |
| `MASKIT_TRUST_PROXY` | `0` | 信任单跳 `X-Forwarded-Proto` / `X-Forwarded-Host` | **仅**在前置代理会覆盖（而非追加）这些头时开启 |
| `MASKIT_DISABLE_ORIGIN_CHECK` | `0` | 关闭 `/api/*` 的 Origin 同源校验 | 跨源防御降级为仅令牌单层，启动会打警告 |
| `MASKIT_ACCESS_LOG` | `0` | 打开 werkzeug 逐请求访问日志 | 默认关闭：面板每 2.5s 轮询一次，开启后 `engine-stdout.log` 会快速增长 |
| `MASKIT_START_READY_TIMEOUT` | `60` | 代理冷启动就绪等待上限（秒） | 只影响启动判定 |
| `MASKIT_BYTE_SPLICE` | `1` | 命中敏感词时只就地替换被脱敏的字符串字面量（保住客户端 body 排版与上游前缀缓存）；设 `0` 退回整棵重序列化 | 只影响回写字节与 CPU，**不改变发往上游的内容**：替换结果必须通过 `json.loads(结果) == 脱敏后的树` 等价校验，不过即退回重序列化 |
| `MASKIT_BIND_HOST` | `127.0.0.1` | `docker-compose.yml` 的主机侧绑定地址 | 公网部署必须显式确认 |
| `LLM_SHIELD_DATA_DIR` | 平台约定 | 覆盖数据目录（配置、事件库、日志、`proxy_token`） | 指向共享目录会削弱文件权限隔离 |
| `LLM_SHIELD_PANEL_PORT` | `5801` | 覆盖面板端口 | 壳层与前端据此探活，改了要一并放通防火墙 |
| `LLM_SHIELD_UPSTREAM` | 空 | 覆盖检测到的本地上游代理 | — |

> **前缀说明**：`LLM_SHIELD_*` 是更名前（LLM Shield → Data Maskit）的遗留前缀，
> 仍在生效且会被继续支持（改数据目录/端口的口径已固化在文档与部署脚本里）。
> **新增变量一律使用 `MASKIT_*`**，不要新增 `LLM_SHIELD_*`。
> 面板端口的两个名字 `LLM_SHIELD_PANEL_PORT`（引擎侧）与 `SHIELD_ENGINE_PORT`
> （壳层早期用法）现在都能被壳识别，优先前者。

### 信任边界（明确不防什么）

- **不防本机恶意程序**：任何以当前用户权限运行的进程都可以读事件库/配置。数据目录 ACL 只挡其他用户，不挡同用户进程。
- **不防上游 relay 关联分析**：占位符跨请求复用（同一实体每轮对话用同一占位符），上游虽看不到明文，但能推断"同一个实体反复出现"。对高保密场景，请自行评估。
- **不防侧信道**：脱敏发生在请求上行前，但请求**时序/长度/频率**对上游可见。
- **不防模型复述**：模型可能在回复中复述占位符语义（如"你刚才提到的联系人"）。还原只处理占位符本身。
- **命令拦截（危险命令）只在响应阶段、只挡明文形态**：它拦的是「命令送到客户端（Agent 可能去执行）」，既不撤回已经发出的请求，也不代表上游没生成过。绕过形态包括写成 `a=rm; $a`、放进脚本再执行；改写/阻断只作用于「工具参数」通道内的明文，而 `Write`/`Edit` 的**文件内容也在该通道**（往 `.sql` 里写 `DROP TABLE` 会命中，属已知误伤面，白名单可豁免）；浏览器扩展链路不经过它。切到「阻断」时仅静默已勾选的通道，非流式响应会被换成 503，客户端 SDK 可能按上游故障重试同一条命令。

### 根证书说明

- 反向代理多端口模式（推荐）**不需要安装任何证书**。
- 仅本机透明捕获（WinDivert，需管理员）会向系统信任库安装 mitmproxy CA。卸载请执行：`certutil -user -delstore Root "mitmproxy"`（或对应 store）。
- 该 CA 只用于本机捕获，不随程序分发。

### fail-closed 设计

- 脱敏管线异常 → 503 阻断，**绝不放行未脱敏原文上行**。
- 非 JSON 请求体 → 503；JSON 解析失败 → 400；请求体超 32MB → 413。
- 审计信号触发自动停用 upstream 的开关（`audit.fail_closed`）默认关闭，用户自选。

## 已审计项

- 后端 0 处 `eval`/`exec`/`os.system`/`shell=True`/`pickle.load`
- event_store.py 0 处 SQL 字符串拼接（全参数化）
- 凭据类事件恒只存摘要，导出恒剔除 `items[].original`
- 数据目录 ACL 启动时自动收紧（`_harden_data_dir_acl`）
- 扩展桥接端点全部挂在 `/api/` 命名空间内（受 Host / Origin / 令牌三重校验），根空间只有静态资源
- 扩展 `host_permissions` 只有 `127.0.0.1` / `localhost`；无 `storage.sync`、无远程代码、无请求正文日志
- 语义识别（NER）降级恒可见：跳过原因（`too_long` / `deadline` / `infer_failed` / `budget_exhausted` / `model_unavailable` / `model_missing` / `om_compose` / `runtime`）既进事件（`ner_truncated` + `ner_skip_reasons`，MASK 与 RESTORE 都带）也进设置页计数，引擎与前端键集合一致由 `tests/test_regressions.py` 的契约测试锁住——**静默降级等于「以为开了、其实没脱」**
- 已登记的上游依赖告警：RustSec **[RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html)**（`glib::VariantStrIter` 迭代器实现 UB，`informational = "unsound"`，修复版本 `>=0.20.0`）。`glib` 经 Tauri → GTK 引入（`atk → gtk ← libappindicator ← tray-icon ← tauri`），**仅 Linux 目标存在**（`cargo tree -i glib` 在 Windows 目标下为空），发布物（Windows NSIS / macOS DMG / Python 引擎镜像）不含该依赖，自有代码也不调用受影响方法
  - 2026-09-24 核验：**当前无任何可用升级能消除它** —— `tauri 2.11.6`（最新稳定）仍 `gtk ^0.18` + `tray-icon ^0.24`；`tray-icon 0.25.1`（最新）仍 `gtk ^0.18` + `libappindicator ^0.9`；`libappindicator 0.9.0`（最新）仍 `glib ^0.18`；gtk-rs 最新稳定 `gtk 0.19.0` 也仍低于要求的 `0.20`。唯一带 gtk 0.20 的可能路径是 `tauri 3.0.0-alpha`，属预发布、不适合生产
  - 因此**不本地改依赖、不锁版本、不打 `[patch]` 强提**：强行把 glib 提到 0.20 会与同族 gtk 0.18 的 API 不兼容，直接打断 Linux 构建。下次升 Tauri 时用 `cargo tree -i glib` 复检，升到 `gtk >= 0.20` 即自然消除
