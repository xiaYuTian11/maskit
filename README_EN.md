<p align="center">
  <img src="frontend/public/favicon.svg" width="96" height="96" alt="Maskit Logo" />
</p>

<h1 align="center">Data Maskit</h1>

<p align="center">
  <strong>Local LLM Privacy & Data Masking Gateway · Automatic Placeholder Masking · Typewriter Stream Restoration · 100% Local Processing</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://github.com/xiaYuTian11/maskit/releases"><img src="https://img.shields.io/github/v/release/xiaYuTian11/maskit?display_name=tag&color=emerald" alt="Release"></a>
  <a href="https://github.com/xiaYuTian11/maskit/actions/workflows/ci.yml"><img src="https://github.com/xiaYuTian11/maskit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://linux.do/"><img src="https://img.shields.io/badge/Community-LINUX%20DO-2563eb?logo=linux&logoColor=white" alt="LINUX DO"></a>
  <img src="https://img.shields.io/badge/Desktop-Windows-blueviolet.svg" alt="Desktop: Windows">
  <img src="https://img.shields.io/badge/Docker-amd64%20%7C%20arm64-2496ED.svg?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Stack-Tauri%202%20%7C%20React%2019%20%7C%20Python%203.13-orange.svg" alt="Tech Stack">
  <a href="README.md"><img src="https://img.shields.io/badge/Language-中文-red.svg" alt="Chinese README"></a>
</p>

<p align="center">
  <b>English</b> | <a href="README.md">简体中文</a>
</p>

---

## 💡 Why Maskit?

When coding with **Cursor, Claude Code, Aider, ChatGPT, or AI coding assistants**, you might unintentionally send sensitive credentials, private IPs, or personal identifiers (PII) to external LLM providers:

- 🔑 **Credentials & Secrets**: `sk-proj-...`, `ghp_...`, Cloud AccessKeys, JWT tokens, PEM private keys
- 🌐 **Internal Infrastructure**: DB connection strings (`mysql://root:Pass123@192.168.1.50:3306/db`), private IP addresses (`10.x`, `172.16.x`, `192.168.x`, `100.64.x` CGNAT)
- 👤 **PII & Business Secrets**: Phone numbers, ID cards, credit cards, customer names, internal project codenames

**Maskit's Mission**: A transparent, ultra-fast privacy gateway running entirely on your local machine. **It intercepts requests, replaces sensitive text with structured placeholders before upstream delivery, and seamlessly restores the original text in real-time typewriter stream.**

---

## 📸 Screenshots

| Dashboard Overview | Client Management |
|:---:|:---:|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Clients](docs/screenshots/clients.png) |
| **Real-time Interception Logs** | **Sensitive Word Management** |
| ![Logs](docs/screenshots/logs.png) | ![Words](docs/screenshots/words.png) |
| **Usage Stats & Cost Ranking** | **Security & Audit Center** |
| ![Stats](docs/screenshots/stats.png) | ![Audit](docs/screenshots/audit.png) |

---

## 🔄 How It Works

<p align="center">
  <img src="docs/architecture-en.svg" alt="Data Maskit Architecture Diagram" width="100%" />
</p>

### Real-World Example: Before vs. After

| Stage | Content Example | Note |
|---|---|---|
| **What You Enter** | `Diagnose connection: mysql://root:Pass123@192.168.1.50:3306/db, contact Alice 13800138000` | Contains sensitive database credentials & phone number |
| **What the Model Receives** | `Diagnose connection: {{CONNSTR_zkpmqx}}, contact {{TERM_fnqtsw}} {{PHONE_bcdfgh}}` | Sensitive info replaced with tokens; LLM never sees raw credentials |
| **Model's Response** | `Check firewall ports for {{CONNSTR_zkpmqx}} and verify permissions with {{TERM_fnqtsw}}` | The model reasons normally around placeholders |
| **What You Actually See** | `Check firewall ports for mysql://root:Pass123@192.168.1.50:3306/db and verify permissions with Alice` | **Restored in real-time typewriter stream. Zero disruption to your workflow.** |

---

## ✨ Key Features & Highlights

- 🔒 **100% Local Execution, Zero Telemetry**: Masking and restoration run strictly inside local processes. No analytics, no crash reporting, no third-party SDKs. Apart from forwarding to the LLM upstream you configure, the only optional outbound calls are the model-price catalog sync (off by default) and the manual "Check for updates" on desktop; all of them are listed in [SECURITY.md](SECURITY.md).
- ⚡ **Millisecond SSE Stream Takeover (Typewriter Experience)**: Intercepts `text/event-stream` responses, restoring tokens chunk by chunk with automatic cross-chunk buffer reassembly.
- 🔌 **Zero-Config Reverse Proxy (No CA Certificates Needed)**: Assigns dedicated local ports per upstream channel (e.g. `http://127.0.0.1:18701`). No system-wide root CA installation required.
- 🛡️ **Native Fallback Passthrough (Never Breaks Your API)**:
  - Many proxy tools cause system-wide AI failures if stopped or crashed.
  - Maskit features an integrated **Fallback Passthrough**: even if the proxy is stopped, the port remains listening and transparently forwards raw requests to upstream. **Your development environment will never experience unexpected connection dropouts.**
- 🎯 **Built-in Rules + Custom Wordlists**:
  - Built-in: PEM private keys, DB connection strings, API keys/tokens, phone numbers, ID cards, bank cards, license plates, private IPv4/IPv6 ranges;
  - Custom: Category-level toggles, whole-word boundary defense, and custom regular expressions.
- 🌐 **Two Deployment Modes**:
  - **Windows desktop app** (Tauri 2 + React 19): system tray, engine crash self-healing, auto-start, one-click bilingual switching;
  - **Docker (amd64 / arm64)**: headless on Linux servers / NAS / macOS with the same embedded Web console, token-protected remote access. Native macOS / Linux desktop builds are not available yet.

---

## 🛠️ Integration with AI Dev Tools

Maskit allocates a dedicated local port for each upstream channel (default `18701` for OpenAI, `18702` for DeepSeek, `18703` for Anthropic; fully customizable).

### 1. Cursor
Go to `Settings` → `Models` → set **OpenAI Base URL**:
```text
http://127.0.0.1:18701/v1
```
Enter your real API key (Maskit safely forwards it to upstream locally).

---

### 2. Claude Code (Super easy with cc-switch!)
If you use the popular multi-channel tool **[cc-switch](https://github.com/super-l/cc-switch)**:
1. Open `cc-switch` and edit your active Claude channel;
2. Change the **Base URL** to Maskit's Anthropic port:
   ```text
   http://127.0.0.1:18703
   ```
3. Save and switch. All terminal `claude` prompts will be automatically masked before hitting the wire!

> **Pure CLI Export**:
> ```bash
> export ANTHROPIC_BASE_URL="http://127.0.0.1:18703"
> claude
> ```

---

### 3. Aider (Terminal AI Pair Programmer)
```bash
aider --openai-api-base http://127.0.0.1:18701/v1 --openai-api-key sk-xxxx
```

---

### 4. Python / LangChain / LlamaIndex Code
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:18701/v1",
    api_key="your-api-key"
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "My database is mysql://root:Pass123@192.168.1.100:3306"}]
)
print(response.choices[0].message.content)
```

---

## 🚀 Download & Deployment

### Option A: Windows Desktop Client (Recommended)
1. Head over to **[GitHub Releases](https://github.com/xiaYuTian11/maskit/releases)**;
2. Download the latest `Maskit_<version>_x64-setup.exe`;
3. Install and run. Click **Start Proxy** in the top bar or system tray.

---

### Option B: Docker / Docker Compose (Linux, macOS, NAS, Team Server)
Run headless with the embedded Web console (same file as [docker-compose.yml](docker-compose.yml) in the repo):

```yaml
services:
  maskit:
    image: ghcr.io/xiayutian11/maskit:latest
    container_name: maskit
    restart: unless-stopped
    ports:
      - "5801:5801"         # Web console
      - "18701:18701"       # OpenAI proxy
      - "18702:18702"       # DeepSeek proxy
      - "18703:18703"       # Anthropic proxy
      - "18704-18710:18704-18710" # Custom port range
    volumes:
      - maskit_data:/data   # Persistent state (words, rules, config, event DB)
    environment:
      - TZ=Asia/Shanghai
      - MASKIT_PANEL_TOKEN=change-me-to-a-long-random-string   # console login token, >= 16 chars
volumes:
  maskit_data:
```

Run with:
```bash
docker compose up -d
```
Then open `http://<Server_IP>:5801/?token=<MASKIT_PANEL_TOKEN>` (or paste the token on the sign-in page). If `MASKIT_PANEL_TOKEN` is not set, a random token is generated on every start and printed to `docker logs maskit`.

> Ports 5801 and 187xx have no network-level isolation; expose them only to trusted networks (LAN / VPN / reverse proxy with TLS).

**Updating**:
```bash
docker compose pull && docker compose up -d
```
Data lives in the named volume `maskit_data` and survives upgrades. Prefer a bind mount? Use `./maskit_data:/data` and run `chown -R 10001 ./maskit_data` first (the container runs as uid 10001).

---

### Option C: Build from Source

#### Prerequisites
- **Python** 3.13 (other versions untested)
- **Node.js** 20+
- **Rust** stable (only for the Tauri desktop shell; `Cargo.toml` declares 1.77 minimum)

```bash
git clone https://github.com/xiaYuTian11/maskit.git
cd maskit

# 1. Python dependencies
pip install -r requirements.txt

# 2. Engine + Web console only (open http://127.0.0.1:5801, token in engine/proxy_token)
python engine/panel.py

# 3. Frontend dev server (vite HMR, talks to the engine above)
cd frontend && npm ci && npm run dev

# 4. Desktop shell dev (requires Rust)
cd frontend && npx tauri dev

# 5. Tests
python -m unittest discover -s tests
python tests/smoke_stream.py
```

The first run creates `engine/config.json` (gitignored) from `engine/config.example.json`. Windows installers are built with `.uild.ps1 -ReleaseOnly`. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 💬 Community

- Questions & ideas: [GitHub Discussions](https://github.com/xiaYuTian11/maskit/discussions) or **[LINUX DO](https://linux.do/)**;
- Bugs / feature requests: [GitHub Issues](https://github.com/xiaYuTian11/maskit/issues) (templates provided);
- Security vulnerabilities: private channel only, see [SECURITY.md](SECURITY.md).

---

## 📜 License (AGPL-3.0)

Data Maskit is licensed under the **[GNU AGPL-3.0](LICENSE)**. Free for personal, research, and open-source usage that conforms to the license terms.

---

<p align="center">
  Made with ❤️ by TMW & Contributors.
</p>
