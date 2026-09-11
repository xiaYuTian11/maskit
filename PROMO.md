# 【开源首发】Data Maskit：专为大模型打造的本地隐私脱敏与还原网关（Cursor / Claude Code / Codex / Pi 即插即用）

各位开发者们好！

在日常开发中使用 **Cursor、Claude Code（配合 cc-switch）、Codex、Pi、OpenCode、ChatGPT 或各类 AI 编码助手** 时，大家经常需要将大段代码、报错日志和配置文件发给外部大模型分析。在这个过程中，你可能在不知不觉中将以下敏感信息发送给了外部大模型或中转服务商：

* 🔑 **代码中的凭据与密钥**：`sk-proj-...`、`ghp_...`、云厂商 AccessKey、JWT Token、PEM 私钥证书等
* 🌐 **内网资产与网络拓扑**：数据库连接串（`mysql://root:Pass123@192.168.1.50:3306/db`）、私有 IP 地址（`10.x` / `172.16.x` / `192.168.x` / `100.64.x` CGNAT）
* 👤 **个人与业务隐私（PII）**：手机号、身份证、银行卡、车牌号、真实姓名、客户名单、企业内部项目代号等

**Data Maskit 的使命**：在你的开发终端与外部 AI 服务之间架设一道透明的“本地隐私防护网关”——**所有请求出网前在本地自动打码成结构化占位符，大模型回答后再毫秒级流式无感还原成原文**！

---

### 💡 它有什么不同？（核心护城河与特色）

#### 1. ⚡ 毫秒级 SSE 流式无感还原（真·打字机体验）
很多代理工具还原时会卡住流式输出，等整句生成完才吐出来，严重破坏打字机手感。Maskit 实现了逐事件跨 chunk 智能拼接缓冲，**完全保留官方原生丝滑的逐字打字机体验，不卡顿、不迟滞**。

#### 2. 🛡️ 原生 Fallback 直连兜底（未启动代理绝不断网）
很多代理工具一旦崩溃或忘记开启，整个电脑的 AI 工具全屏报错网络连接失败。Maskit 采用原生直连兜底层：**哪怕你退出软件或停止脱敏代理，本地端口依然由轻量底层维持监听并透明直连转发明文，你的日常开发环境绝对不断网**！

#### 3. 🔌 免装自签名 CA 根证书，即插即用
不需要往操作系统导入危险的自签名 CA 根证书，不用担心系统安全拦截。Maskit 为不同渠道分配专属本地端口（默认 `18701` 对应 OpenAI，`18702` 对应 DeepSeek，`18703` 对应 Anthropic），只需在工具中把 `base_url` 改为本地端口即可。

#### 4. 🎯 规则库 + 自定义词库 + 长会话实体一致性
- **内置 19 类正则扫描规则**：涵盖 API Key、私钥、数据库连接串、手机、身份证、邮箱、银行卡等，默认收敛核心隐私，低误报；
- **自定义敏感词与正则扩展**：支持按分类管理内部人名、项目代号、业务敏感词，支持整词匹配边界；
- **滑动窗口复用机制**：同一长对话中，“张三”在第 1 轮和第 10 轮始终映射为同一个占位符，**大模型逻辑推理完全一致不串号**！

#### 5. 🔒 100% 纯本地运行，零外部遥测
脱敏与还原全部在本地进程内运行，**不收集任何用户隐私，不上传日志，没有埋点与第三方追踪 SDK**。

---

### 🚀 快速上手

#### 方式 A：Windows 桌面客户端（推荐个人日常使用）
1. 前往 **[GitHub Releases 下载页面](https://github.com/xiaYuTian11/maskit/releases)**；
2. 下载最新的 `Maskit_<版本>_x64-setup.exe` 安装包；
3. 双击安装运行，系统托盘常驻，支持全自动数字签名（Minisign）无缝在线更新。

#### 方式 B：Docker 一行命令秒级启动（推荐 Linux / macOS / NAS / 团队私有网关）
**无需下载源码**，直接拉取 GitHub 官方多架构预构建镜像（原生支持 `linux/amd64` 与 `linux/arm64`），内嵌完整 Web 控制台：
```bash
docker run -d \
  --name maskit \
  --restart unless-stopped \
  -p 127.0.0.1:5801:5801 \
  -p 127.0.0.1:18701-18710:18701-18710 \
  -v maskit_data:/data \
  -e MASKIT_PANEL_TOKEN="请设置你的随机控制台访问密码" \
  ghcr.io/xiayutian11/maskit:latest
```
浏览器打开 `http://<服务器IP>:5801/?token=<你的密码>` 即可直接管理！

---

### 🛠️ 常见开发工具配置（支持任意可配 Base URL 的工具）

* **Cursor**：`Settings` → `Models` → `OpenAI Base URL` 改为 `http://127.0.0.1:18701/v1`
* **Claude Code**：使用 **[cc-switch](https://github.com/farion1231/cc-switch)** 将 Base URL 切换为 `http://127.0.0.1:18703`，或终端运行 `export ANTHROPIC_BASE_URL="http://127.0.0.1:18703"`
* **Codex / Pi / OpenCode / 命令行工具**：
  ```bash
  export OPENAI_BASE_URL="http://127.0.0.1:18701/v1"
  export OPENAI_API_KEY="your-api-key"
  ```

---

### 💬 开源地址与交流反馈

* 🔗 **GitHub 开源地址**：[https://github.com/xiaYuTian11/maskit](https://github.com/xiaYuTian11/maskit)
* 🐧 **官方交流 QQ 群**：**`489926214`**（欢迎进群交流规则建议、Bug 反馈与最新进展）
* 🌐 **论坛讨论**：**[LINUX DO 社区讨论专区](https://linux.do/)**

如果 Data Maskit 对你的日常开发隐私保护有帮助，欢迎来 GitHub 点个 **Star 🌟** 支持一下！感谢大家！
