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
| 版本检查 / 更新下载（桌面版，GitHub Releases API） | 用户点击时 | 当前版本号 | 不点「检查更新」 |

除上表外，引擎与前端**不发送任何统计、崩溃报告或日志**。反馈诊断包只在用户点击「保存」后生成到本地文件，由用户自行决定是否上传。

### Docker / 远程访问模式

`MASKIT_PANEL_HOST=0.0.0.0` 时面板进入远程模式：Host 校验放开、Origin 改为同源校验，**所有 `/api/*` 仍必须携带 `X-Shield-Token`**（来自 `MASKIT_PANEL_TOKEN`，或启动日志打印的随机值）。5801 与 187xx 端口只应暴露给可信网络，反代端口本身不做鉴权。

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
