# 数据面具 Maskit 项目工程规范与架构指南

> 本文件是 Data Maskit 开源项目的开发总控指南与唯一工程规范基准。

---

## 1. 架构总览

Data Maskit 是一款专为大模型打造的**100% 本地隐私脱敏与还原网关**。拦截开发终端（Cursor、Claude Code、Codex 等）发往 LLM 的 API 请求，在本地自动打码成业务占位符后转发上游，并在模型回答返回时毫秒级流式无感还原。

### 架构分层
```text
┌─────────────────────────────────────────────────────────────┐
│ 桌面壳层 (src-tauri/)                                       │
│   - 基于 Tauri 2 (Rust) 构建，系统托盘常驻、单实例控制       │
│   - 引擎进程生命周期管理、端口探活、开机自启自愈             │
└──────────────────────────────┬──────────────────────────────┘
                               │ (IPC / HTTP 本地通信)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 引擎核心层 (Python 3.13 + mitmproxy)                        │
│   - engine_entry.py: Sidecar 入口与自启编排                 │
│   - panel.py: Flask API 控制面服务 + WebUI 静态文件托管      │
│   - transparent.py: 核心脱敏/还原流式代理 Addon             │
│   - event_store.py: SQLite 本地事件库与统计维护              │
│   - audit_engine.py / audit_signals.py: 安全审计与风险引擎   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 前端展示层 (frontend/)                                      │
│   - React 19 + TypeScript + Vite + Tailwind CSS + shadcn/ui │
│   - 顶栏一键中英双语快捷切换、深浅主题切换、自适应仪表盘     │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 核心文件与模块职责

| 路径 | 核心职责 | 维护与改动红线 |
|---|---|---|
| `transparent.py` | 核心脱敏代理引擎（mitmproxy addon） | 负责正则特征扫描、占位符生成、跨 chunk SSE 流式还原；**改动必须跑全量单测 + 流式冒烟**。 |
| `panel.py` | Flask 控制面服务（5801 端口） | 提供配置读写、代理启停、日志查询、统计分析与 WebUI 静态托管；`__version__` 为版本唯一真相来源。 |
| `engine_entry.py` | 引擎 Sidecar 运行入口 | 负责环境就绪探测、ACL 权限收紧、代理自启与透明直连兜底。 |
| `event_store.py` | SQLite 本地日志与统计引擎 | 负责事件写入批量事务、崩溃自愈、日统计增量维护；凭据类恒只存哈希摘要。 |
| `audit_signals.py` | 纯函数安全审计信号检测 | 严禁引入重依赖，保持纯 Python stdlib 实现，永不抛异常。 |
| `audit_engine.py` | 主动探针与安全风险矩阵评估 | 负责跨请求隔离性测试、提示词注入与投毒检测。 |
| `shield_defaults.py` | 默认脱敏规则与用量解析器 | 包含标准内置规则定义及各大模型 Token 用量解析提取。 |
| `frontend/` | React 19 现代化前端源码 | 新增 UI 必须遵守 Tailwind 类 + 语义组件，严格支持中文/英文双语国际化。 |
| `src-tauri/` | Tauri 2 跨平台桌面壳 | 系统托盘、开机自启自愈、引擎崩溃守护、进程隔离。 |
| `build.ps1` | 一键打包发版流水线 | 自动编排单测、前端构建、PyInstaller 引擎、Tauri NSIS 安装包。 |
| `Dockerfile` | 容器化部署配置 | 适用于 Linux / NAS / 团队私有网关运行，内嵌 Web 控制台。 |

---

## 3. 关键工程约束与安全红线

1. **100% 本地运算与零外传（绝对安全红线）**：
   - 脱敏与还原全部在本地进程内运行，严禁添加任何形式的用户追踪、云端日志收集或遥测上报代码。
2. **Fail-Closed 严格安全熔断**：
   - 脱敏管线发生未捕获异常或请求体超过 32MB 时，必须立即回退 503 阻断，**绝不放行未脱敏明文请求出网**。
3. **原生透明直连兜底（Passthrough，绝不断网）**：
   - 当用户停止代理或未启动脱敏代理时，本地端口必须由轻量兜底层维持监听，并执行**明文透明直连转发（Passthrough）**，确保用户的日常开发网络调用绝对不会因中间件原因中断。
4. **毫秒级 SSE 流式打字机接管**：
   - 针对 `text/event-stream` 响应，逐事件增量还原下发。跨 chunk 占位符必须智能缓冲拼接，中途无事件时返回空列表 `[]`（严禁返回 `b""` 导致 chunked 语法提前断连）。
5. **占位符规范（`{{LABEL_后缀}}`）**：
   - 后缀必须采用 6 位纯辅音随机串，彻底消除大模型对十六进制数做变异算术的诱因；
   - 跨请求维持滑动窗口复用，保证多轮对话上下文逻辑一致。
6. **凭据安全红线**：
   - API_KEY、TOKEN、SECRET、JWT、ACCESS_KEY、PRIVATE_KEY 类日志，在事件库中恒只存 preview + sha256 摘要，导出时恒剔除原文。
7. **控制面接口命名空间红线（`/api/` 前缀）**：
   - `panel.py` 的 `api_guard` 只对 `/api/*` 执行 Host / Origin / `X-Shield-Token` 三重校验；非 `/api/` 路径（SPA HTML、`/assets/*`、favicon 等由 `serve_spa` 托管）一律免检。这是为了让反向代理 / CDN（Nginx、EdgeOne）HTTPS 终止环境下，浏览器加载 `crossorigin` 模块脚本时携带的 Origin 不被误判 403 导致整页白屏（实测事故）。
   - 因此**任何新增的控制面端点必须挂在 `/api/` 前缀下**，否则会自动绕过全部安全防线；根空间只允许放纯静态资源。
   - 关闭 Origin 校验（`config.origin_check=false` 或环境变量 `MASKIT_DISABLE_ORIGIN_CHECK=1`）只应用于受信任反代 / CDN 场景，且必须在 `SECURITY.md` 中同步说明。

---

## 4. 验证与测试流程

代码变更后必须按序通过以下四道门禁：

```powershell
# 1. Python 语法编译与单元测试
python -m py_compile engine/*.py
python -m unittest discover -s tests

# 2. 流式与出口代理冒烟测试
python tests/smoke_stream.py
python tests/smoke_egress.py

# 3. 前端类型检查、构建、Lint、中英文字典对齐（0 error）
cd frontend
npm run build
npm run lint
node ../scripts/check-i18n.mjs
cd ..

# 4. Rust 桌面壳测试（改动 src-tauri 时必跑）
cd src-tauri
cargo check
cargo test --lib
cd ..

# 5. 版本号四处一致（panel.py / tauri.conf.json / Cargo.toml / package.json）
python scripts/check-version.py
```

与 CI（`.github/workflows/ci.yml` 的 `python` / `frontend` / `rust` / `version` 四个 job）完全对应。

### 运行时文件约定

- `engine/config.example.json` 是随包分发的配置模板；源码态首次运行在 `engine/` 生成 `config.json`（已 gitignore），打包态生成到用户数据目录。**不要把 `engine/config.json` 提交进仓库。**
- 事件库 `shield-events.sqlite3`、`proxy_token`、`config.json.bak-*`、`model_prices_cache.json` 等全部是运行时产物，已 gitignore / dockerignore，`build.ps1` 打包前会清理。
- 测试样例中凭据形态的字符串必须一眼可见是伪造的（`sk-test-0000…`），真实上游 key 只能来自环境变量 `LLM_SHIELD_API_KEY`。
- 新增任何对外网络请求必须默认关闭并登记到 `SECURITY.md` 出站清单。

---

## 5. 打包与发布规范

- **发版前置授权红线（绝对铁律，严禁擅自发版）**：
  - 任何 AI 助手（包括当前 Agent、任何子代理及后续会话）**严禁在未经用户明确书面授权确认的情况下执行任何发布动作**（包括但不限于：执行 `git push origin v*`、执行发版脚本 `release.ps1`、调用 GitHub API 创建 Release、修改线上 Release 状态）；
  - 发版前必须先完成所有本地全量门禁，并向用户展示最终变动清单与验证证据，**在用户明确发出“确认发版/发版吧”等指令后方可执行**。用户如果仅要求“检查/审计/看看”，本轮只输出报告，严禁顺手执行发版。

- **发版日志中英双语规范（强制）**：
  - 每次发版时，`CHANGELOG.md` 与 GitHub Release 说明必须提供**中英双语（Bilingual）对照**，方便海内外开发者理解变更细节；
  - 格式遵循 Keep a Changelog，重大修复与破坏性变动需附带中英文说明。

- **多平台构建矩阵**：
  - **Windows 桌面端**：`x86_64` NSIS 安装包；
  - **macOS 桌面端**：`arm64`（Apple Silicon）DMG 安装包，由 GitHub Actions `macos-latest` 原生编译；
  - **Docker 容器**：`linux/amd64` 与 `linux/arm64` 双架构镜像（推送到 `ghcr.io`）。

- **一键全自动发版（推荐）**：使用 `release.ps1`，自动编排「前置 git pull 对齐 -> build.ps1 打包与门禁验证 -> git commit -> git tag -> 推送主分支与 Tag」：
  ```powershell
  # 自动读取并按当前/指定版本号完成构建、提交流水线与推送
  .\release.ps1 -Version "0.2.6"

  # 仅打包测试，不执行 git commit/push
  .\release.ps1 -BuildOnly
  ```

- **底层打包流水线**：`build.ps1`（纯构建编排，不含 Git 提交命令）：
  ```powershell
  # 发布模式（不杀本机运行中的生产实例）
  .\build.ps1 -ReleaseOnly

  # 或指定正式版本号打包
  .\build.ps1 -ReleaseOnly -Version "1.0.0"
  ```
- 打包产物位于：
  - Windows: `src-tauri\target\release\bundle\nsis\Maskit_<版本>_x64-setup.exe`；
  - macOS: `src-tauri/target/release/bundle/dmg/Maskit_<版本>_aarch64.dmg`。
