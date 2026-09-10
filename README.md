<p align="center">
  <img src="frontend/public/favicon.svg" width="96" height="96" alt="Maskit Logo" />
</p>

<h1 align="center">Data Maskit (数据面具)</h1>

<p align="center">
  <strong>专为大模型打造的本地隐私脱敏网关 · 请求自动占位打码 · 回复打字机无感还原 · 默认无遥测</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://github.com/xiaYuTian11/maskit/releases"><img src="https://img.shields.io/github/v/release/xiaYuTian11/maskit?display_name=tag&color=emerald" alt="Release"></a>
  <a href="https://github.com/xiaYuTian11/maskit/actions/workflows/ci.yml"><img src="https://github.com/xiaYuTian11/maskit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://linux.do/"><img src="https://img.shields.io/badge/Community-LINUX%20DO-2563eb?logo=linux&logoColor=white" alt="LINUX DO"></a>
  <img src="https://img.shields.io/badge/Desktop-Windows-blueviolet.svg" alt="Desktop: Windows">
  <img src="https://img.shields.io/badge/Docker-amd64%20%7C%20arm64-2496ED.svg?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Stack-Tauri%202%20%7C%20React%2019%20%7C%20Python%203.13-orange.svg" alt="Tech Stack">
  <a href="README_EN.md"><img src="https://img.shields.io/badge/Language-English-lightgrey.svg" alt="English README"></a>
</p>

<p align="center">简体中文 | <a href="README_EN.md">English</a></p>

---

## 💡 为什么需要 Maskit？

当你在日常开发中使用 **Cursor、Claude Code（结合 cc-switch）、Codex、ChatGPT 或各类 AI 编码助手** 时，你可能在不知不觉中将以下敏感信息发送给外部大模型或中转服务商：

- 🔑 **代码中的凭据与密钥**：`sk-proj-...`、`ghp_...`、云厂商 AccessKey、JWT Token、PEM 私钥证书
- 🌐 **内网资产与拓扑**：数据库连接串（`mysql://root:Pass123@192.168.1.50:3306/db`）、私有 IP 地址（`10.x` / `172.16.x` / `192.168.x` / `100.64.x` CGNAT）
- 👤 **个人与业务隐私（PII）**：手机号、身份证、银行卡、车牌号、客户名单、企业内部项目代号

**Maskit 的使命**：在你的开发终端与外部 AI 服务之间架设一道透明的“本地隐私防护网关”——**所有请求出网前在本地自动打码成结构化占位符，大模型回答后再毫秒级流式无感还原成原文**。

---

## 📸 界面截图

| 控制台概览 (Dashboard) | 客户端管理 (Clients) |
|:---:|:---:|
| ![控制台概览](docs/screenshots/dashboard.png) | ![客户端管理](docs/screenshots/clients.png) |
| **实时拦截日志 (Logs)** | **敏感词库管理 (Words)** |
| ![拦截日志](docs/screenshots/logs.png) | ![敏感词库](docs/screenshots/words.png) |
| **数据统计与成本排行 (Stats)** | **安全审计中心 (Audit)** |
| ![数据统计](docs/screenshots/stats.png) | ![安全审计中心](docs/screenshots/audit.png) |

---

## 🔄 工作原理

<p align="center">
  <img src="docs/architecture-zh.svg" alt="Data Maskit 工作原理架构图" width="100%" />
</p>

### 真实效果对比

| 阶段 | 内容样例 | 说明 |
|---|---|---|
| **你输入的内容** | `请帮我排查数据库连接：mysql://root:Pass123@192.168.1.50:3306/db，联系人李四 13800138000` | 包含高危数据库连接与手机号 |
| **大模型收到的内容** | `请帮我排查数据库连接：{{CONNSTR_zkpmqx}}，联系人{{TERM_fnqtsw}} {{PHONE_bcdfgh}}` | 敏感词已全被替换，模型完全不知道真实凭据与号码 |
| **模型生成的回答** | `建议检查 {{CONNSTR_zkpmqx}} 的防火墙端口，并让 {{TERM_fnqtsw}} 核对权限` | 模型围绕占位符正常推理与分析 |
| **你最终看到的回答** | `建议检查 mysql://root:Pass123@192.168.1.50:3306/db 的防火墙端口，并让 李四 核对权限` | **秒级无感还原，开发与阅读体验完全不受影响** |

#### 🔬 真实脱敏与还原事件对照明细
<p align="center">
  <img src="docs/screenshots/event-detail.png" alt="真实脱敏与还原事件明细" width="85%" />
</p>

> **实锤效果**：上图中，发往大模型时手机号已被打码为 `{{PHONE_jvbspm}}`（模型完全没有拿到真实号码），而大模型思考作答完毕后，返回给你时毫秒级无感还原回 `13899998888`！可在日志弹窗中一键开启「高亮还原」进行精确比对。

---

## ✨ 核心优势与特色

- 🔒 **本地处理，默认无遥测**：脱敏与还原完全在本地进程内完成，不上传日志、统计或崩溃报告，也不内置第三方追踪 SDK。请求仍会按你的配置转发到 LLM 上游；可选的价格目录同步默认关闭，桌面更新检查只在用户触发时运行，完整清单见 [SECURITY.md](SECURITY.md)。本地事件库可能保留普通 PII，发布前请阅读数据保留与信任边界说明。
- ⚡ **毫秒级 SSE 流式接管（打字机体验）**：针对 OpenAI / Anthropic 的 `text/event-stream` 流式响应，逐事件还原下发，跨 chunk 占位符智能拼接缓冲，完全保留打字机般丝滑的输出体验。
- 🔌 **反向代理多端口模式（免装 CA 根证书）**：为每个上游分配独立本地端口（如 `18701`），客户端只需将 `base_url` 指向本地端口，无需配置系统全局代理，无需往系统信任区导入 CA 根证书。
- 🛡️ **原生透明直连兜底（未启动代理绝不断网）**：
  - **核心护城河设计**：很多代理工具一旦未启动或崩溃，就会导致全电脑的 AI 工具报“网络连接失败”。
  - Maskit 拥有原生 **Fallback 兜底架构**：哪怕未启动代理，本地端口依然由轻量底层维持监听，并执行**明文透明直连转发（Passthrough）**，API 调用照常返回，**绝不会让你的开发环境意外断网**！
- 🎯 **开箱即用规则库 + 自定义敏感词**：
  - 内置覆盖：PEM 私钥、数据库连接串、API Key/Token、手机号、身份证、银行卡、车牌、内网 IPv4/IPv6 等；
  - 自定义词库：支持一键整分类启停禁用、整词匹配边界防御、正则表达式扩展。
- 🌐 **两种部署形态**：
  - **Windows 桌面客户端**（Tauri 2 + React 19）：系统托盘常驻、引擎崩溃自愈、开机自启，顶栏一键中英双语切换；
  - **Docker（amd64 / arm64）**：Linux 服务器 / NAS / macOS 上无头运行，内嵌同一套 Web 控制台，浏览器远程管理（令牌鉴权）。
  - **桌面包**：Windows NSIS 是当前主发行形态；macOS DMG 与 Linux deb/AppImage 由 tag CI 构建，下载前请以对应 Release 资产的签名、公证和平台说明为准。

---

## 🛠️ 主流 AI 编程工具接入指南

Maskit 为每个上游服务商分配一个专属本地端口（默认 `18701` 对应 OpenAI，`18702` 对应 DeepSeek，`18703` 对应 Anthropic，可在客户端自定义添加与修改）。

### 1. Cursor 接入
打开 Cursor → 进入 `Settings` → `Models`：
- 将 **OpenAI Base URL** 修改为：
  ```text
  http://127.0.0.1:18701/v1
  ```
- 凭据填入你的真实 API Key（Maskit 在本地收到请求后会安全转发给真实上游）。

---

### 2. Claude Code 接入（结合 cc-switch 超简单！）

如果你使用社区广受好评的多渠道切换工具 **[cc-switch](https://github.com/super-l/cc-switch)**：
1. 打开 `cc-switch` 渠道列表，找到你正在使用的 Claude 渠道；
2. 直接将其 **Base URL** 修改为 Maskit 的 Anthropic 端口：
   ```text
   http://127.0.0.1:18703
   ```
3. 保存后切换生效，之后所有在终端敲 `claude` 触发的对话与代码扫描，出网前全部自动无感脱敏！

> **纯命令行方式**：
> ```bash
> export ANTHROPIC_BASE_URL="http://127.0.0.1:18703"
> claude
> ```

---

### 3. Codex / 终端 AI 编程助手接入
终端启动 Codex 或其它命令行编码助手时，只需设置环境变量即可无感接入：
```bash
# Linux / macOS
export OPENAI_BASE_URL="http://127.0.0.1:18701/v1"
export OPENAI_API_KEY="your-api-key"
codex

# Windows PowerShell
$env:OPENAI_BASE_URL = "http://127.0.0.1:18701/v1"
$env:OPENAI_API_KEY = "your-api-key"
codex
```

---

### 4. Python / LangChain / LlamaIndex 代码接入
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:18701/v1",
    api_key="your-api-key"
)

# 正常调用，全链路自动占位打码与流式还原
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "我的数据库是 mysql://root:Pass123@192.168.1.100:3306"}]
)
print(response.choices[0].message.content)
```

---

## 🚀 下载与部署

### 方式 A：Windows 桌面客户端（推荐）

1. 前往 **[GitHub Releases 下载页面](https://github.com/xiaYuTian11/maskit/releases)**；
2. 下载最新的安装包 `Maskit_<版本>_x64-setup.exe`；
3. 双击安装运行，在托盘或界面中点击「启动代理」即可。

---

### 方式 B：使用 Docker 部署（Linux / macOS / NAS / 团队私有网关）

**无需克隆仓库或下载源码**，直接从 GitHub 容器镜像库拉取官方预构建的多架构镜像（原生支持 `linux/amd64` 与 `linux/arm64`），内嵌完整 Web 控制台：

#### 1. 一行命令秒级启动（首选推荐）
直接在服务器或终端运行，Docker 会自动从云端拉取镜像：
```bash
docker run -d \
  --name maskit \
  --restart unless-stopped \
  -p 5801:5801 \
  -p 18701-18710:18701-18710 \
  -v maskit_data:/data \
  -e MASKIT_PANEL_TOKEN="change-me-to-a-long-random-string" \
  ghcr.io/xiayutian11/maskit:latest
```

#### 2. 或使用 Docker Compose 编排
在任意目录创建 `docker-compose.yml`（无需仓库代码）：
```yaml
services:
  maskit:
    image: ghcr.io/xiayutian11/maskit:latest
    container_name: maskit
    restart: unless-stopped
    ports:
      - "${MASKIT_BIND_HOST:-127.0.0.1}:${MASKIT_PANEL_HOST_PORT:-5801}:5801"         # Web 管理控制台
      - "${MASKIT_BIND_HOST:-127.0.0.1}:${MASKIT_OPENAI_HOST_PORT:-18701}:18701"       # OpenAI 反向代理通道
      - "${MASKIT_BIND_HOST:-127.0.0.1}:${MASKIT_DEEPSEEK_HOST_PORT:-18702}:18702"     # DeepSeek 反向代理通道
      - "${MASKIT_BIND_HOST:-127.0.0.1}:${MASKIT_ANTHROPIC_HOST_PORT:-18703}:18703"   # Anthropic 反向代理通道
      - "${MASKIT_BIND_HOST:-127.0.0.1}:${MASKIT_CUSTOM_HOST_START:-18704}-${MASKIT_CUSTOM_HOST_END:-18710}:18704-18710" # 自定义端口段
    volumes:
      - maskit_data:/data   # 持久化：词库、规则、配置、事件库
    environment:
      - TZ=Asia/Shanghai
      - MASKIT_PANEL_TOKEN=change-me-to-a-long-random-string   # 控制台登录令牌，≥16 位；生产建议用 token file
      # - MASKIT_PANEL_TOKEN_FILE=/run/secrets/maskit_panel_token
volumes:
  maskit_data:
```
启动运行：
```bash
docker compose up -d
```

#### 2. 打开 Web 控制台
浏览器打开 `http://<你的服务器IP>:5801/`，在登录页粘贴令牌。临时便利链接可使用 `/#token=<MASKIT_PANEL_TOKEN>`：fragment 不会随 HTTP 请求发送；旧版 `?token=` 仍兼容，但会进入访问日志和浏览器历史，不建议在反代环境使用。
没设置固定令牌时，引擎每次启动生成随机令牌并打印到 `docker logs maskit`。生产环境建议使用 Docker secret，并把 `MASKIT_PANEL_TOKEN_FILE` 指向只读文件。

> 5801 与 187xx 端口本身没有网络层隔离，请只暴露给可信网络（内网 / VPN / 反向代理加 TLS）。

反向代理终止 HTTPS 时，在容器环境变量中设置 `MASKIT_TRUST_PROXY=1`，并确保代理覆盖（不是追加）单跳 `X-Forwarded-Proto` / `X-Forwarded-Host`；否则保持默认值，避免客户端伪造转发头。

#### 3. Docker 容器后续升级
```bash
docker compose pull && docker compose up -d
```
数据在命名卷 `maskit_data` 中，升级无损。想直接看文件可改成 bind mount `./maskit_data:/data`（容器以 uid 10001 运行，需先 `chown -R 10001 ./maskit_data`）。

### 从旧官网安装包迁移到 GitHub Release

旧版本安装包内置的是旧更新地址，无法凭空发现 GitHub Release。第一次迁移请从 [GitHub Releases](https://github.com/xiaYuTian11/maskit/releases) 手动下载并安装新包，覆盖原安装目录即可；`%APPDATA%\Maskit` 中的配置、词库和事件库会保留。安装完成后，后续“检查更新”才会使用 GitHub Release。升级前建议先导出配置备份，回滚时重新安装上一版本即可。

---

### 方式 C：从源码运行与二次开发

#### 环境要求
- **Python** 3.13（其它版本未验证）
- **Node.js** 20+
- **Rust** stable（仅编译 Tauri 桌面壳时需要；`Cargo.toml` 声明最低 1.77）

```bash
git clone https://github.com/xiaYuTian11/maskit.git
cd maskit

# 1. Python 依赖
pip install -r requirements.txt

# 2. 只跑引擎 + Web 控制台（浏览器打开 http://127.0.0.1:5801，令牌见 engine/proxy_token）
python engine/panel.py

# 3. 前端开发（vite 热更新，配合上一步的引擎）
cd frontend && npm ci && npm run dev

# 4. 桌面壳开发（需 Rust）
cd frontend && npx tauri dev

# 5. 自动化测试
python -m unittest discover -s tests
python tests/smoke_stream.py
```

首次运行会在 `engine/` 生成 `config.json`（已 gitignore），模板见 `engine/config.example.json`。Windows 安装包用 `.\build.ps1 -ReleaseOnly` 打包。贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 💬 社区与交流

平台限制、Docker/源码运行矩阵见 [平台与部署支持](docs/PLATFORM_SUPPORT.md)；维护者发版前按 [发布检查清单](docs/RELEASE_CHECKLIST.md) 验证。

- **官方 QQ 交流群**：**`489926214`**（欢迎入群交流使用反馈、规则建议与最新进展）；
- 使用问题与想法：[GitHub Discussions](https://github.com/xiaYuTian11/maskit/discussions) 或 **[LINUX DO 社区](https://linux.do/)**；
- Bug / 功能建议：[GitHub Issues](https://github.com/xiaYuTian11/maskit/issues)（有模板）；
- 安全漏洞：请走私密渠道，见 [SECURITY.md](SECURITY.md)。

---

## 📜 开源协议（AGPL-3.0）

Data Maskit 基于 **[GNU AGPL-3.0](LICENSE)** 许可证发布。个人开发者、研究人员及所有开源项目均可**完全免费、不受限制**地使用源码及所有核心功能。如需在闭源商业产品中分发或集成，请遵循 AGPL-3.0 相关条款要求。

<p align="center">
  Made with ❤️ by TMW & Contributors.
</p>
