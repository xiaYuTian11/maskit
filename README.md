<p align="center">
  <img src="frontend/public/favicon.svg" width="96" height="96" alt="Maskit Logo" />
</p>

<h1 align="center">Data Maskit (数据面具)</h1>

<p align="center">
  <strong>专为大模型打造的本地隐私脱敏与还原网关 · 物理打码 + 流式无感还原 · 100% 本地运算零遥测</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://github.com/xiaYuTian11/maskit/releases/latest"><img src="https://img.shields.io/github/v/release/xiaYuTian11/maskit?color=green&label=Release" alt="Latest Release"></a>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Docker-blueviolet" alt="Cross Platform">
  <img src="https://img.shields.io/badge/Privacy-100%25%20Local%20%26%20Zero%20Egress-success" alt="100% Local">
</p>

<p align="center">
  <a href="README_EN.md">English Documentation</a> ｜ <strong>简体中文</strong>
</p>

---

## 💡 为什么需要 Maskit？

当你在使用 **Cursor、Claude Code、Codex、ChatGPT 或各类 AI 编程助手** 时，真实数据往往在不知不觉中被上传至云端模型：

- 🔑 **代码密钥与凭据**：`sk-proj-...`、`ghp_...`、云厂商 AccessKey、JWT、PEM 私钥；
- 🌐 **内网资产拓扑**：数据库连接串（`mysql://root:pass@192.168.1.50:3306/db`）、内部 IP 与域名；
- 👤 **业务敏感信息（PII）**：手机号、身份证、真实姓名、邮箱、银行卡与保密代号；
- 🖼️ **截图与文档附件**：终端报错截图、Word 内嵌图片、扫描件 PDF —— **肉眼可见但文本规则抓不到**。

**Maskit 的使命**：在你的开发终端与大模型之间架设一道透明的本地网关 —— **出网前在本地打码成结构化占位符（图片则物理涂黑），模型回答时毫秒级流式无感还原为原文！**

---

## 🔄 效果对比一览

<p align="center">
  <img src="docs/architecture-zh.svg" alt="Data Maskit 工作原理架构图" width="100%" />
</p>

| 环节 | 内容示例 | 说明 |
|---|---|---|
| **你的原始输入** | `排查数据库：mysql://root:Pass123@192.168.1.50:3306/db，联系人李四 13800138000` | 包含高危数据库连接串与联系电话 |
| **大模型收到的内容** | `排查数据库：{{CONNSTR_zkpmqx}}，联系人{{TERM_fnqtsw}} {{PHONE_bcdfgh}}` | 敏感数据全被置换，**外部大模型完全看不见真实隐私** |
| **模型生成的回答** | `建议检查 {{CONNSTR_zkpmqx}} 的连通性，并让 {{TERM_fnqtsw}} 核对权限` | 模型围绕占位符正常推理与回答 |
| **你最终看到的呈现** | `建议检查 mysql://root:Pass123@192.168.1.50:3306/db 的连通性，并让 李四 核对权限` | **本地毫秒级无感还原，开发体验零割裂！** |

<details>
<summary><b>🔍 点击展开：查看真实脱敏与还原明细截图（含 CoT 思维链分析与实时高亮对照）</b></summary>
<br />
<p align="center">
  <img src="docs/screenshots/event-detail.png" alt="真实脱敏与还原事件明细" width="85%" />
</p>
</details>

---

## ✨ 核心亮点

### 🛡️ 1. 深度文本脱敏与多轮一致性
- **21 类内置规则**：默认开启 API Key、银行卡、数据库连接串、邮箱、身份证、座机、手机号等核心规则；其余 14 类（PEM 私钥、JWT、云 AccessKey、IP 等）按需一键开启，有效防误报；
- **自定义敏感词与正则**：支持分组管理业务词、姓名与项目代号，采用常驻确定性占位符；
- **多轮会话滑动窗口复用**：同一会话中，“张三”在第 1 轮和第 20 轮始终映射为同一个占位符，**大模型逻辑推理完全一致不串号**；
- **本地 AI 语义识别（NER）**：内置离线轻量级 ONNX 语义模型，精准识别自由文本中的人名、机构与地址。

### 🖼️ 2. 本地图片与文档多模态脱敏（OCR 字符级物理打码）
- **多载体全覆盖**：终端截图、浏览器扩展上传图片、Word（`.docx`）内嵌图片、扫描件/矢量 PDF 页面；
- **实体级精准打码**：只涂手机号、身份证、邮箱等敏感字符，**保留「姓名：」「手机：」「部门：」等结构标签**，模型仍能理解排版；
- **PDF 文本层彻底清洗**：敏感页转为位图打码并清除底层不可见文本层（防复制泄漏），干净页保留原有高清矢量；
- **安全不失真**：图片物理遮蔽出网（不可逆、不还原），内置可选 **RapidOCR + ONNX Runtime** 本地引擎，零外传、主包轻量按需启用。

### 🌐 3. 全开发工具与全生态接入
- **开发终端全兼容**：Cursor、Claude Code、Codex、Pi、OpenCode、Aider 及任意可配 Base URL 的 CLI / SDK；
- **浏览器扩展联动（Chrome / Edge）**：针对 ChatGPT、Claude、DeepSeek 网页版提供无缝隐私打码与打字机流式还原，支持附件文档直接脱敏；
- **毫秒级 SSE 流式接管**：增量还原切片与跨 chunk 拼接，**完全保留官方丝滑打字机体验，不迟滞、不卡顿**。

### 🔒 4. 100% 本地运算与高可用兜底
- **免装自签名根证书**：纯本地端口反向代理模式，无需向操作系统注入不受信任的 CA 证书；
- **Passthrough 原生直连兜底**：关闭代理或退出程序时，端口维持监听并**自动透明直连转发明文**，**你的 AI 工具绝不会意外断网**；
- **零遥测与安全合规**：纯本地运行，不含任何外部追踪代码与用户数据上报，凭据类仅在本地存摘要。

---

## 🛠️ 1 分钟极速接入

只需将你工具中的 **API Base URL** 指向 Maskit 对应的本地端口即可！
> 默认端口映射：OpenAI 协议 `http://127.0.0.1:18701/v1` ｜ DeepSeek 协议 `http://127.0.0.1:18702/v1` ｜ Anthropic 协议 `http://127.0.0.1:18703`

### 1. Cursor
打开 Cursor → `Settings` → `Models`：
- **OpenAI Base URL**：`http://127.0.0.1:18701/v1`
- 填入你的真实 API Key（Maskit 在本地安全转发给上游服务）。

### 2. Claude Code
在 **[cc-switch](https://github.com/farion1231/cc-switch)** 中将渠道 Base URL 改为 `http://127.0.0.1:18703`，或直接通过终端环境变量启动：
```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:18703"
claude
```

### 3. CLI / 环境变量（Codex / Pi / Aider 等）
```bash
# Linux / macOS
export OPENAI_BASE_URL="http://127.0.0.1:18701/v1"
export OPENAI_API_KEY="your-api-key"

# Windows PowerShell
$env:OPENAI_BASE_URL = "http://127.0.0.1:18701/v1"
$env:OPENAI_API_KEY = "your-api-key"
```

### 4. 代码调用（Python / LangChain）
```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:18701/v1", api_key="your-api-key")

# 正常调用，全链路自动本地打码与流式还原
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "排查数据库连接：mysql://root:Pass123@192.168.1.100:3306"}]
)
print(response.choices[0].message.content)
```

### 5. 浏览器扩展（ChatGPT / Claude / DeepSeek 网页版）
从 [Releases](https://github.com/xiaYuTian11/maskit/releases/latest) 下载 `Maskit_<版本>_extension.zip`，在浏览器扩展管理页开启「开发者模式」并加载解压目录，在桌面端开启扩展联动并填入令牌即可无感打码。

---

## 📸 功能界面概览

| 控制台概览 (Dashboard) | 客户端多端口管理 (Clients) |
|:---:|:---:|
| ![控制台概览](docs/screenshots/dashboard.png) | ![客户端管理](docs/screenshots/clients.png) |
| **实时拦截日志 (Logs)** | **敏感词库与正则 (Words)** |
| ![拦截日志](docs/screenshots/logs.png) | ![敏感词库](docs/screenshots/words.png) |
| **数据统计与成本看板 (Stats)** | **安全审计中心 (Audit)** |
| ![数据统计](docs/screenshots/stats.png) | ![安全审计中心](docs/screenshots/audit.png) |

---

## 🚀 下载与安装

### 方式 A：桌面客户端（推荐个人日常使用）

前往 **[GitHub Releases 最新发布页](https://github.com/xiaYuTian11/maskit/releases/latest)** 下载对应平台安装包：

- **Windows**：下载 `Maskit_<版本>_x64-setup.exe`，安装后托盘常驻，支持全自动无缝更新；
- **macOS (Apple Silicon)**：下载 `Maskit_<版本>_aarch64.dmg`，拖入“应用程序”文件夹即可。
  > 💡 **macOS 首次打开提示**：若提示未验证，右键点击 Maskit 选择「打开」，或在终端执行：
  > `xattr -cr /Applications/Maskit.app`
- **Linux**：提供 `.deb` 与 `.AppImage`（支持 x86_64 与 aarch64）。

---

### 方式 B：Docker 私有网关（推荐团队 / 服务器 / NAS 部署）

直接拉取官方多架构镜像（支持 `linux/amd64` 与 `linux/arm64`），内嵌完整 Web 控制台：

```bash
docker run -d \
  --name maskit \
  --restart unless-stopped \
  -p 127.0.0.1:5801:5801 \
  -p 127.0.0.1:18701:18701 \
  -p 127.0.0.1:18702:18702 \
  -p 127.0.0.1:18703:18703 \
  -v maskit_data:/data \
  ghcr.io/xiayutian11/maskit:latest
```
浏览器打开 `http://127.0.0.1:5801` 即可进入管理控制台。

---

<details>
<summary><b>🔧 点击展开：源码编译与本地开发指引</b></summary>
<br />

#### 运行环境
- Python 3.13+
- Node.js 20+
- Rust 1.80+（若需编译桌面壳层）

#### 本地启动
```bash
# 1. 克隆仓库
git clone https://github.com/xiaYuTian11/maskit.git
cd maskit

# 2. 安装 Python 引擎依赖
pip install -r requirements.txt

# 3. 安装前端依赖并构建
cd frontend && npm install && npm run build && cd ..

# 4. 启动核心引擎服务（默认端口 5801）
python engine/panel.py
```
</details>

<details>
<summary><b>🛡️ 点击展开：安全边界、已知限制与进阶说明</b></summary>
<br />

1. **思维链轨迹保护（Thinking Blocks）**：Anthropic 签名思考块整块不做脱敏以保证签名完整性（避免会话 400 破坏）；无签名约束的正文、工具参数与其它模型思考块照常打码还原；
2. **多模态图像脱敏特性**：图片脱敏为物理覆盖、不可逆阻断；上游模型无法回答被覆盖的原图内容；
3. **危险命令拦截边界**：作为辅助安全网，主要检查明文形态高危命令（如 `rm -rf /`、`DROP DATABASE`），仅在配置开启后告警/阻断，不承诺覆盖高级混淆变种；
4. **日志隐私级别**：支持「最小记录（不落盘原文）」、「本地详细」与「15分钟临时排障」三种模式，敏感凭据恒只记录哈希摘要。
</details>

---

## 🤝 参与贡献与社区

欢迎提交 Issue 与 Pull Request！请查阅 [CONTRIBUTING.md](CONTRIBUTING.md) 了解开发规范与门禁流程。

- **GitHub Issues**：[问题反馈与功能建议](https://github.com/xiaYuTian11/maskit/issues)
- **开源协议**：本项目基于 [AGPL-3.0 License](LICENSE) 开源。
