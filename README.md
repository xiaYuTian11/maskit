<p align="center">
  <img src="frontend/public/favicon.svg" width="96" height="96" alt="Maskit Logo" />
</p>

<h1 align="center">Data Maskit (数据面具)</h1>

<p align="center">
  <strong>专为大模型打造的本地隐私脱敏网关 · 请求自动占位打码 · 回复打字机无感还原 · 100% 本地运算零泄漏</strong>
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

当你在日常开发中使用 **Cursor、Claude Code、Aider、ChatGPT 或各类 AI 编码助手** 时，你可能在不知不觉中将以下敏感信息发送给外部大模型或中转服务商：

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

---

## ✨ 核心优势与特色

- 🔒 **100% 纯本地运行，零遥测**：脱敏与还原完全在本地进程内完成，不上传任何日志，没有统计、崩溃上报或第三方 SDK。除转发到你自己配置的 LLM 上游外，唯一可选的出站是「模型价格目录同步」（默认关闭）与桌面版手动「检查更新」，全部列在 [SECURITY.md 出站清单](SECURITY.md#出站清单本项目承诺零遥测以下是全部主动出网点)。
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
  - **Docker（amd64 / arm64）**：Linux 服务器 / NAS / macOS 上无头运行，内嵌同一套 Web 控制台，浏览器远程管理（令牌鉴权）。macOS / Linux 桌面版尚未提供。

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

### 3. Aider 命令行编程助手
终端启动 Aider 时指定 Base URL：
```bash
aider --openai-api-base http://127.0.0.1:18701/v1 --openai-api-key sk-xxxx
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

无需图形界面或桌面环境，直接在服务器上作为团队共享的脱敏网关运行，**内嵌完整 Web 控制台**：

#### 1. 使用 Docker Compose（推荐）
在服务器上创建 `docker-compose.yml`（与仓库根目录的 [docker-compose.yml](docker-compose.yml) 相同）：
```yaml
services:
  maskit:
    image: ghcr.io/xiayutian11/maskit:latest
    container_name: maskit
    restart: unless-stopped
    ports:
      - "5801:5801"         # Web 管理控制台
      - "18701:18701"       # OpenAI 反向代理通道
      - "18702:18702"       # DeepSeek 反向代理通道
      - "18703:18703"       # Anthropic 反向代理通道
      - "18704-18710:18704-18710" # 自定义端口段
    volumes:
      - maskit_data:/data   # 持久化：词库、规则、配置、事件库
    environment:
      - TZ=Asia/Shanghai
      - MASKIT_PANEL_TOKEN=change-me-to-a-long-random-string   # 控制台登录令牌，≥16 位
volumes:
  maskit_data:
```
启动运行：
```bash
docker compose up -d
```

#### 2. 打开 Web 控制台
浏览器访问 `http://<你的服务器IP>:5801/?token=<MASKIT_PANEL_TOKEN>`（或打开后在登录页粘贴令牌）。
没设置 `MASKIT_PANEL_TOKEN` 时引擎每次启动生成随机令牌并打印到 `docker logs maskit`。

> 5801 与 187xx 端口本身没有网络层隔离，请只暴露给可信网络（内网 / VPN / 反向代理加 TLS）。

#### 3. Docker 容器后续升级
```bash
docker compose pull && docker compose up -d
```
数据在命名卷 `maskit_data` 中，升级无损。想直接看文件可改成 bind mount `./maskit_data:/data`（容器以 uid 10001 运行，需先 `chown -R 10001 ./maskit_data`）。

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

首次运行会在 `engine/` 生成 `config.json`（已 gitignore），模板见 `engine/config.example.json`。Windows 安装包用 `.uild.ps1 -ReleaseOnly` 打包。贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 💬 社区与交流

- 使用问题与想法：[GitHub Discussions](https://github.com/xiaYuTian11/maskit/discussions) 或 **[LINUX DO 社区](https://linux.do/)**；
- Bug / 功能建议：[GitHub Issues](https://github.com/xiaYuTian11/maskit/issues)（有模板）；
- 安全漏洞：请走私密渠道，见 [SECURITY.md](SECURITY.md)。

---

## 📜 开源协议（AGPL-3.0）

Data Maskit 基于 **[GNU AGPL-3.0](LICENSE)** 许可证发布。个人开发者、研究人员及所有开源项目均可**完全免费、不受限制**地使用源码及所有核心功能。如需在闭源商业产品中分发或集成，请遵循 AGPL-3.0 相关条款要求。

<p align="center">
  Made with ❤️ by TMW & Contributors.
</p>
