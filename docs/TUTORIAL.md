# 📖 Data Maskit 从零到上手：保姆级图文配置指南

> 本教程带你 3 分钟搞定 Data Maskit 的安装、配置与主流 AI 工具（Cursor、Claude Code、Codex、Pi 等）接入，实现代码与提示词中的敏感数据**出网自动打码、回答毫秒级无感流式还原**。

---

## 目录
- [一、30 秒搞懂核心原理](#一30-秒搞懂核心原理)
- [二、下载与安装启动](#二下载与安装启动)
  - [形态 A：Windows 桌面客户端（最推荐）](#形态-awindows-桌面客户端最推荐)
  - [形态 B：Docker 一行命令启动（Linux / macOS / NAS）](#形态-bdocker-一行命令启动linux--macos--nas)
- [三、核心配置：添加与管理上游渠道](#三核心配置添加与管理上游渠道)
- [四、主流工具 1 分钟接入实战](#四主流工具-1-分钟接入实战)
  - [1. Cursor 接入指南](#1-cursor-接入指南)
  - [2. Claude Code 接入（结合 cc-switch 最简单）](#2-claude-code-接入结合-cc-switch-最简单)
  - [3. Codex / Pi / OpenCode / 终端 CLI 接入](#3-codex--pi--opencode--终端-cli-接入)
  - [4. Python / Node.js 等代码 SDK 接入](#4-python--nodejs-等代码-sdk-接入)
- [五、验证脱敏与还原实测效果](#五验证脱敏与还原实测效果)
- [六、进阶玩法：自定义敏感词库与规则开关](#六进阶玩法自定义敏感词库与规则开关)
- [七、常见问题排查 (FAQ)](#七常见问题排查-faq)

---

## 一、30 秒搞懂核心原理

很多开发者担心代理中间件会拖慢速度、或需要安装不安全的 CA 根证书。Maskit 采用了极其轻量的**反向代理网关架构**：

```text
你的开发工具 (Cursor / Claude Code / Codex)
       │
       │  ① 发送带真实密码/手机号的请求 (本地 HTTP 明文，无需 CA 证书)
       ▼
【Data Maskit 本地网关 (127.0.0.1:18701~18710)】
       │
       │  ② 内存正则扫描：自动将敏感信息替换为 {{LABEL_xxxxxx}} 占位符
       ▼
外部大模型服务商 (OpenAI / Anthropic / DeepSeek)
       │  (模型仅看到占位符，完全接触不到你的真实机密)
       ▼
【Data Maskit 本地网关】
       │
       │  ③ 毫秒级 SSE 逐字流式拼接，将占位符秒级还原回原文
       ▼
你的开发工具 (Cursor 界面显示原生打字机流式输出，你看到的是完全还原的明文！)
```

<p align="center">
  <img src="architecture-zh.svg" alt="架构原理图" width="100%" />
</p>

---

## 二、下载与安装启动

### 形态 A：Windows 桌面客户端（最推荐）

1. 打开 GitHub Releases 下载页：[https://github.com/xiaYuTian11/maskit/releases](https://github.com/xiaYuTian11/maskit/releases)；
2. 下载最新的 `Maskit_x.x.x_x64-setup.exe` 安装包；
3. 双击直接安装运行。启动后它会常驻系统托盘，并弹出管理主控制台：

<p align="center">
  <img src="screenshots/dashboard.png" alt="控制台概览" width="90%" />
</p>

- 顶部状态显示 **🟢 运行中** 即表示脱敏代理已就绪；
- 点击右上角 **“停止代理”** 可以随时暂停脱敏；
- **核心保障（绝不断网）**：哪怕你点击了“停止代理”或关掉了软件，底层依然维持透明直连，你的 Cursor/Claude **绝对不会报网络连接断开**！

---

### 形态 B：Docker 一行命令启动（Linux / macOS / NAS）

如果你在没有界面的服务器或 NAS 上使用，直接敲这行命令启动官方多架构镜像：

```bash
docker run -d \
  --name maskit \
  --restart unless-stopped \
  -p 5801:5801 \
  -p 18701:18701 \
  -v maskit_data:/data \
  -e MASKIT_PANEL_TOKEN="YourSecretToken123456" \
  ghcr.io/xiayutian11/maskit:latest
```

> 💡 **提示**：若前置配合 Nginx 反代或仅供本机使用，建议加上 `127.0.0.1:` 保护端口（`-p 127.0.0.1:5801:5801`）；大模型端口（如 `18701`）按需映射即可，用几个大模型就映射几个端口。

启动后，在浏览器中打开：
`http://<服务器IP>:5801/#token=YourSecretToken123456`
（或直接访问 `http://<服务器IP>:5801` 在弹出的输入框中输入密码）即可进入完整的 Web 控制台！

---

## 三、最关键的一步：怎么看本地 IP+端口？怎么填到外部软件？

很多初次使用的开发者最容易困惑的一点是：**“我配置了客户端，然后呢？我该拿什么地址去填我自己的软件？”**

其实整个逻辑极其简单，只有 3 个动作：**看卡片 ➔ 点复制 ➔ 去别的软件粘贴！**

---

### 1. 搞懂概念：什么是“客户端卡片”？
在 Maskit 里，一个“客户端卡片”就等于**一条专属的本地隐私隧道**：
- **卡片上的本地端口**：比如 `18701`，代表 Maskit 在你电脑上开辟的“安全入口”；
- **卡片上的目标地址 (Target)**：代表真实的大模型服务器（如 OpenAI 官方或你的中转站）。

<p align="center">
  <img src="screenshots/clients.png" alt="客户端管理界面" width="90%" />
</p>

---

### 2. 怎么拿到对应的 Base URL？（卡片自带一键复制！）
看上图里每一张客户端卡片：
1. 卡片中央有一栏 **`Base URL`**，例如显示：`http://127.0.0.1:18701/v1`；
2. **直接点击右侧的「复制」按钮**，这个本地安全地址就已经进入你的电脑剪贴板了！

> 💡 **小贴士**：
> - `127.0.0.1` 代表“你自己的这台电脑（本机回环）”；
> - `18701` 就是这个渠道对应的专属端口号；
> - 拼起来就是你的专属本地 Base URL：**`http://127.0.0.1:18701/v1`**。

---

### 3. 拿到这个地址后，怎么在各种软件里填写？

| 你使用的工具 | 应该改哪个设置项？ | 填什么地址？ | 你的 API Key 填哪里？ |
|---|---|---|---|
| **Cursor** | `Settings` ➔ `Models` ➔ `Override OpenAI Base URL` | `http://127.0.0.1:18701/v1` | 原样填在 Cursor 自己的 API Key 输入框 |
| **Claude Code (cc-switch)** | 在 `cc-switch` 里编辑你当前用的渠道 ➔ `Base URL` | `http://127.0.0.1:18703` | 原样保留原渠道的 Key |
| **Codex / CLI 终端** | 环境变量 `$env:OPENAI_BASE_URL` | `http://127.0.0.1:18701/v1` | `$env:OPENAI_API_KEY="你的真实Key"` |
| **NextChat / ChatGPT-Next-Web** | 设置 ➔ 接口地址 (Base URL) | `http://127.0.0.1:18701` (或局域网IP) | 填你的真实 Key |
| **Python / LangChain 代码** | `OpenAI(base_url="...", api_key="...")` | `http://127.0.0.1:18701/v1` | 填你的真实 Key |

> ⚠️ **核心原则**：
> 1. **Base URL**：永远改成你在 Maskit 卡片上复制出来的本地 `http://127.0.0.1:端口/v1`；
> 2. **API Key 与模型名**：**完全不用动！** 以前该填什么还填什么。请求发到 Maskit 之后，Maskit 会在本地自动把你真实的 Key 和脱敏后的提示词安全转发给目标大模型！

---

## 四、主流工具 1 分钟接入实战

接入极其简单，原则只有一个：**把原本调往公网的 Base URL 改为你本地的对应端口！**

### 1. Cursor 接入指南

打开 Cursor 界面，按快捷键 `Ctrl + ,`（或进入右上角设置齿轮），点击 **Models**：

1. 找到 **OpenAI API Key** 设置项；
2. 开启 **Override OpenAI Base URL**；
3. 将 Base URL 修改为：
   ```text
   http://127.0.0.1:18701/v1
   ```
4. 凭据处填入你的真实 API Key（Maskit 在本地收到后会自动打理好安全转发）。

> 提示：如果你使用的是 DeepSeek 渠道，将端口改为 `http://127.0.0.1:18702/v1` 即可。

---

### 2. Claude Code 接入（结合 cc-switch 最简单）

如果你平时使用社区广受好评的多渠道切换工具 **[cc-switch](https://github.com/super-l/cc-switch)**：

1. 打开 `cc-switch` 客户端，找到你正在使用的 Claude 渠道；
2. 点击编辑，将 **Base URL** 直接修改为 Maskit 的本地 Anthropic 端口：
   ```text
   http://127.0.0.1:18703
   ```
3. 保存生效。之后在终端执行 `claude` 敲代码时，所有提示词出网前全部自动脱敏！

**如果你是纯命令行启动**，只需在终端敲入环境变量：
```bash
# macOS / Linux
export ANTHROPIC_BASE_URL="http://127.0.0.1:18703"
claude

# Windows PowerShell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:18703"
claude
```

---

### 3. Codex / Pi / OpenCode / 终端 CLI 接入

对于 Codex CLI、Pi 编码助手、OpenCode 或各类基于 OpenAI 协议的终端命令行工具：

**Windows PowerShell 终端**：
```powershell
$env:OPENAI_BASE_URL = "http://127.0.0.1:18701/v1"
$env:OPENAI_API_KEY = "你的真实API密钥"
codex
```

**macOS / Linux 终端**：
```bash
export OPENAI_BASE_URL="http://127.0.0.1:18701/v1"
export OPENAI_API_KEY="你的真实API密钥"
codex
```

---

### 4. Python / Node.js 等代码 SDK 接入

在代码中调用官方 SDK 时，只需把 `base_url` 改写为本地代理：

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:18701/v1",  # 指向本地 Maskit 代理端口
    api_key="sk-your-real-key"
)

# 正常发起调用，全链路本地打码与流式还原自动进行
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "帮我连接测试库：mysql://admin:{{CONNSTR_qvvsmx}}@192.168.1.100:3306/prod"}
    ]
)
print(response.choices[0].message.content)
```

---

## 五、验证脱敏与还原实测效果

配置完成后，我们怎么确认打码确实生效了呢？

1. 在你的 Cursor 或 Claude Code 中，随便发一句包含敏感数据的内容，例如：
   > *“请帮我记录联系电话：13899998888，请原样回复我。”*
2. 打开 Maskit 客户端，点击左侧菜单栏的 **“拦截日志”**：

<p align="center">
  <img src="screenshots/logs.png" alt="拦截日志列表" width="90%" />
</p>

你会看到清晰的两条记录：
- **MASK（出网打码）**：捕获到包含 `PHONE` 标签的敏感项，出网前被替换为了类似 `{{PHONE_jvbspm}}` 的占位符；
- **RESTORE（流式还原）**：模型回答返回时，网关将占位符秒级还原回了你原本的手机号！

点击任意一行日志，会弹出 **“事件详情”** 弹窗：

<p align="center">
  <img src="screenshots/event-detail.png" alt="事件详情明细" width="75%" />
</p>

- 打开底部的 **“高亮还原”** 开关，可以一目了然地看到大模型生成的完整推理过程，以及哪几个词是在本地被毫秒级换回来的！

---

## 六、进阶玩法：自定义敏感词库与规则开关

点击左侧菜单栏的 **“敏感词库”**：

<p align="center">
  <img src="screenshots/words.png" alt="敏感词库管理" width="90%" />
</p>

### 1. 内置规则按需启停
- 系统默认开启了核心的高危项：`API_KEY`（密钥）、`CONNSTR`（数据库连接串密码）、`PHONE`（手机号）、`EMAIL`（邮箱）、`IDCARD`（身份证）、`CARD`（银行卡）等；
- 对于内网 IP（10.x/172.x）等容易与代码版本号混淆的规则，默认关闭，你可以根据自己公司合规要求一键勾选启用。

### 2. 添加内部专有词与代号
- 如果公司有内部绝密代号（如 “火星计划”、“Project-Titan”）或重要客户姓名；
- 在页面输入词汇添加，支持整词边界匹配（避免子串误命中更长单词）。只要代码或提问中包含该词，出网前一律打码成 `{{TERM_xxxxxx}}`！

---

## 七、常见问题排查 (FAQ)

### Q1：关掉 Maskit 代理后，我的 Cursor / 终端会断网吗？
**绝对不会！** 这是 Maskit 的核心护城河设计。即使你停止了脱敏或退出程序，本地端口依然由极轻量的直连兜底层维持监听，并以透明直传（Passthrough）模式转发请求，你的开发环境不会受到丝毫影响。

### Q2：为什么大模型回答里能看到我的密码/手机号？这算泄露吗？
**不算，这正是“无感还原”的效果！**
外部大模型在生成回答时，实际上看到的只是 `{{CONNSTR_zkpmqx}}` 这样的占位符。回答传输回你的电脑内存时，Maskit 在本地毫秒级把占位符替换回了真实信息。你可以在 **“拦截日志”** 弹窗中亲眼证实模型实际接收的内容。

### Q3：会拖慢大模型的输出速度或首字延迟吗？
**不会！** Maskit 采用微秒级 SSE 事件流直通技术，上游输出一个字，本地立刻透传一个字（零整包缓冲）。实测首字延迟（TTFT）增加不到 1 毫秒，100% 保留原生打字机丝滑手感。

---

> 💬 如有更多配置疑问，欢迎加入官方交流 QQ 群：**`489926214`**，或前往 [GitHub Discussions](https://github.com/xiaYuTian11/maskit/discussions) 交流反馈！
