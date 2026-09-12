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

### 出站清单（本项目承诺零遥测，以下是全部主动出网点）

| 出站 | 默认 | 内容 | 关闭方式 |
|------|------|------|---------|
| 转发到你配置的 LLM 上游 | 开（这是产品功能） | 脱敏后的请求 | — |
| 模型价格目录同步（`price_sync_url`，默认 `mask.ciyuanroute.com`，失败回退 openrouter.ai） | **关** | 仅 GET，不带任何用户数据 | 设置 → 高级 → 价格同步 |
| 版本检查 / 更新下载（桌面版经 Tauri Updater，Web / Docker 版经 GitHub Releases API） | **自动**：启动后约 8 秒静默查一次，之后每 6 小时复查；点「检查更新」可立即触发 | 当前版本号 | 无法关闭；仅探测版本号与元数据，不发送任何使用数据，下载仅在点击「安装」后发生 |

除上表外，引擎与前端**不发送任何统计、崩溃报告或日志**。反馈诊断包只在用户点击「保存」后生成到本地文件，由用户自行决定是否上传。

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
