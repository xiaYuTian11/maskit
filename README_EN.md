<p align="center">
  <img src="frontend/public/favicon.svg" width="96" height="96" alt="Maskit Logo" />
</p>

<h1 align="center">Data Maskit</h1>

<p align="center">
  <strong>Local Privacy Masking & Real-Time Restoration Gateway for LLMs · Automatic Token Masking · Millisecond Typewriter Stream Restoration · 100% Local Processing & Zero Telemetry</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://github.com/xiaYuTian11/maskit/releases"><img src="https://img.shields.io/github/v/release/xiaYuTian11/maskit?display_name=tag&color=emerald" alt="Release"></a>
  <a href="https://github.com/xiaYuTian11/maskit/actions/workflows/ci.yml"><img src="https://github.com/xiaYuTian11/maskit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://linux.do/"><img src="https://img.shields.io/badge/Community-LINUX%20DO-2563eb?logo=linux&logoColor=white" alt="LINUX DO"></a>
  <a href="https://github.com/xiaYuTian11/maskit"><img src="https://img.shields.io/badge/QQ%20Group-489926214-12B7F5.svg" alt="QQ Group"></a>
  <img src="https://img.shields.io/badge/Desktop-Windows%20%7C%20macOS-blueviolet.svg" alt="Desktop: Windows | macOS">
  <img src="https://img.shields.io/badge/Docker-amd64%20%7C%20arm64-2496ED.svg?logo=docker&logoColor=white" alt="Docker">
  <a href="README.md"><img src="https://img.shields.io/badge/Language-%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-lightgrey.svg" alt="Chinese README"></a>
</p>

<p align="center"><a href="README.md">简体中文</a> | English</p>

---

## 💡 Why Maskit?

When using **Cursor, Claude Code, Codex, Pi, OpenCode, ChatGPT, or any AI coding assistant**, sensitive information can easily be transmitted to external LLM providers:

- 🔑 **Credentials & Secrets**: `sk-proj-...`, `ghp_...`, Cloud AccessKeys, JWT Tokens, private keys;
- 🌐 **Internal Infrastructure**: DB connection strings (`mysql://root:Pass123@192.168.1.50:3306/db`), private IP addresses (`10.x`, `172.16.x`, `192.168.x`);
- 👤 **Business Privacy (PII)**: Phone numbers, ID numbers, real names, credit cards, proprietary internal project names;
- 📄 **Documents & Attachments**: Word (`.docx` / `.doc`), Excel (`.xlsx` / `.xls`), and PowerPoint (`.pptx`) files uploaded to web AI containing confidential business data.

**Maskit's Mission**: Act as a transparent local privacy gateway between your developer tools and external AI providers — **mask sensitive tokens before requests leave your machine, and restore them in real-time typewriter stream as answers arrive**!

---

## 🔄 Core Architecture & Real-World Comparison

<p align="center">
  <img src="docs/architecture-en.svg" alt="Data Maskit Architecture" width="100%" />
</p>

| Stage | Example Content | Practical Effect |
|---|---|---|
| **What You Typed** | `Connect to DB: mysql://root:Pass123@192.168.1.50:3306/db, contact Alice 13800138000` | Contains database passwords and real phone numbers |
| **What LLM Receives** | `Connect to DB: {{CONNSTR_zkpmqx}}, contact {{TERM_fnqtsw}} {{PHONE_bcdfgh}}` | All sensitive data replaced; **external model never sees raw secrets** |
| **What LLM Answers** | `Check firewall connectivity for {{CONNSTR_zkpmqx}} and verify permissions with {{TERM_fnqtsw}}` | Model reasons, plans, and writes code naturally using placeholders |
| **What You Actually See** | `Check firewall connectivity for mysql://root:Pass123@192.168.1.50:3306/db and verify permissions with Alice` | **Restored in millisecond typewriter stream with zero workflow disruption!** |

<details>
<summary><b>🔍 Click to expand: View real-world masking & restoration dialog screenshot (with CoT & highlight mode)</b></summary>
<br />
<p align="center">
  <img src="docs/screenshots/event-detail.png" alt="Real Masking & Restoration Details" width="85%" />
</p>
</details>

---

## ✨ Highlights & Feature Overview

### 🛡️ 1. Deep Masking with Multi-turn Consistency
- **21 Built-in Scanner Rules (7 on by default)**: core privacy and credential rules (API key, bank card, DB connection string, email, ID card, landline, phone) are enabled out of the box; the other 14 (PEM private keys, JWT, tokens, secrets, cloud AccessKeys, private/public IPs, IPv6, MAC, license plates, USCC, HK/Macau travel permits, IBAN, and more) stay off so rare high-false-positive rules cannot derail the model's reasoning about your code and config, and can be enabled per rule in Settings;
- **Custom Wordlists & Regex**: Categorized custom dictionary for names, codenames, and proprietary business terms; full regex support with resident deterministic placeholders;
- **Sliding-window Placeholder Reuse**: Placeholders remain consistent across long conversations. "Alice" is assigned the exact same token in turn 1 and turn 20, preserving model reasoning consistency.

### 🤖 2. Local AI Entity Recognition (NER Semantic Model)
- **Unstructured Free-Text Protection**: Built-in lightweight local ONNX model detects Chinese person names (NAME), organizations (ORG), and detailed physical addresses (ADDR) where regex rules fall short;
- **Clean Original Extraction + Monotonic OffsetMap**: Extracts entities from the clean original context and translates coordinates back to the mutated text via a monotonic `OffsetMap`, completely eliminating plaintext fragment leakage caused by context truncation;
- **100% Offline Local Inference**: Runs entirely inside your local process without any external network calls; **off by default** (regex rules already cover the common cases) and can be enabled with one click in Settings.

### 🌐 3. Browser Extension Ecosystem (Web AI Privacy)
- **Seamless Web AI Protection**: A Chrome & Edge MV3 extension. **ChatGPT, Claude, and DeepSeek are individually verified and pre-authorized out of the box — no manual site adding required** (you still need to enable the extension bridge and paste the access token in Settings); 14 more common AI sites (Kimi, Qwen, Tencent Yuanbao, ChatGLM, ERNIE Bot, Gemini, Grok, Perplexity, Copilot, and more) can be added with one click from Settings, unverified ones are clearly labeled, and custom sites are supported;
- **Dual-Channel Interception (Fetch + XHR Engines)**: Intercepts standard Fetch as well as low-level `XMLHttpRequest` requests and streaming responses (XHR response restoration currently covers DeepSeek web only); other sites keep native behavior untouched;
- **Direct Document & Attachment Masking (ChatGPT / Claude)**: Word (`.docx` / `.doc`), Excel (`.xlsx` / `.xls`), and PowerPoint (`.pptx`) files are parsed and masked locally before upload to cloud models; **on sites not yet supported (e.g. DeepSeek) the uploaded file itself is not masked** (passed through as-is), and the extension shows an explicit "attachment not masked" notice — do not send confidential files to those sites;
- **Local Masking + Typewriter Stream Restoration**: Prompts are masked locally before departure, and model responses are restored in real-time typewriter stream right inside the web chat UI with multi-turn session consistency.

### ⚡ 4. Millisecond SSE Stream Takeover (Native Typewriter Flow)
- Intercepts `text/event-stream` chunk by chunk with incremental restoration;
- Automatically reassembles split tokens across chunk boundaries, **maintaining native typewriter responsiveness without lag**.
- **Reasoning traces stay protocol-faithful (disclosed)**: Anthropic extended-thinking (`thinking`) blocks carry an upstream signature; rewriting the signed text invalidates verification and permanently breaks that conversation with HTTP 400. The gateway therefore restores placeholders **only in visible text and tool arguments**, keeps placeholders inside reasoning traces, and leaves signed thinking blocks unmasked as a whole (the count is reported in the event detail instead of silently skipped). Other reasoning channels without a signature keep being restored as usual.

### 🔌 5. No Root CA Installation + Native Fallback Passthrough (Never Breaks Your API)
- **Multi-port Reverse Proxy**: Dedicated local ports per model channel (e.g. `18701` for OpenAI, `18703` for Anthropic). Change `base_url` to local port without installing untrusted self-signed root CAs;
- **Fallback Passthrough Guarantee**: If the proxy is stopped or closed, ports automatically fallback to raw transparent passthrough. **Your coding tools will never experience unexpected connection dropouts!**

### 🧪 6. Local Offline Lab & Coding Assistant Skill Contract
- **Try It Out (Offline Local Lab)**: No API key needed, nothing sent upstream. Paste any text on the Clients page to inspect masked tokens, round-trip restoration, and hit breakdowns in milliseconds, clearly illustrating the difference between unique entities and occurrences;
- **Coding Assistant Skill (Placeholder Contract)**: Ships built-in with the package (`maskit-placeholders`), downloadable with a single click or installable via command line. Guides Claude Code, Cursor, Codex, and other assistants to use placeholders verbatim without inventing tokens, splitting them, substituting mock data, or needlessly refusing requests.

### 📊 7. Real-time Logs, Security Audit & Cost Tracking
- Inspect full request/response diffs with one-click highlight mode;
- **Adjustable log write detail (minimal / detailed / time-boxed trace)**: minimal mode stores no conversation body or plaintext **at the write side** (database, engine logs, diagnostics bundle and export share one projection) and keeps label distribution only; keep “detailed” when you need long-lived masked↔original comparison; troubleshooting can open a 15-minute time-boxed window (auto-closes on expiry and on restart, and still stores no plaintext). The logs page can also **page back into history** and return to live at any time.
- **Passive Security Audit & Prompt Injection Detection**: Monitors upstream model responses and detects prompt extraction attempts, credential exfiltration instructions, and destructive command patterns;
- **Dangerous Command Interception (opt-in, record-only by default)**: Flags model-issued commands such as `rm -rf /`, `mkfs`, `DROP DATABASE` and fork bombs into the Risky-action timeline. By default it neither rewrites nor blocks (zero byte change); you can switch to "rewrite with a harmless notice" or "block", and define custom rules plus an allow list. **Literal shapes only** (`a=rm; $a`, or writing the command into a script, will slip through) — a safety net, not a vault.
- **Command interception scope (stated as-is)**: detection only looks at the **tool-argument channel** — the arguments of `Write`/`Edit` (i.e. the content about to be written to a file) are on that channel too, so writing `DROP TABLE users` into a `.sql` migration matches as well; browser-extension traffic (ChatGPT / Claude web) does **not** go through command interception; in "block" mode only the **selected channels** stop streaming (unselected channels keep flowing) and non-streaming responses are replaced with a 503.
- Live token usage & model pricing cost estimation.

---

## 📸 Screenshots

| Dashboard | Client Port Management |
|:---:|:---:|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Clients](docs/screenshots/clients.png) |
| **Real-time Logs** | **Sensitive Words & Regex** |
| ![Logs](docs/screenshots/logs.png) | ![Words](docs/screenshots/words.png) |
| **Cost & Token Stats** | **Security Audit** |
| ![Stats](docs/screenshots/stats.png) | ![Audit](docs/screenshots/audit.png) |

---

## 🛠️ Universal Integration Guide (Any Tool with Base URL Support)

Integration is universal: **Simply change your tool's API Base URL to point to Maskit's local port**!
> Default mapping: OpenAI `http://127.0.0.1:18701/v1` ｜ DeepSeek `http://127.0.0.1:18702/v1` ｜ Anthropic `http://127.0.0.1:18703`

### 1. Cursor
Go to `Settings` → `Models`:
- **OpenAI Base URL**: `http://127.0.0.1:18701/v1`
- Enter your API Key (Maskit forwards it securely to upstream).

### 2. Claude Code (with cc-switch)
- In **[cc-switch](https://github.com/farion1231/cc-switch)**, set the Claude channel **Base URL** to:
  `http://127.0.0.1:18703`
- Or launch from terminal:
  ```bash
  export ANTHROPIC_BASE_URL="http://127.0.0.1:18703"
  claude
  ```

### 3. Codex / Pi / OpenCode / Aider / CLI Tools
Set environment variables:
```bash
# Linux / macOS
export OPENAI_BASE_URL="http://127.0.0.1:18701/v1"
export OPENAI_API_KEY="your-api-key"

# Windows PowerShell
$env:OPENAI_BASE_URL = "http://127.0.0.1:18701/v1"
$env:OPENAI_API_KEY = "your-api-key"
```

### 4. SDK & Code (Python / Node.js / LangChain)
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:18701/v1",
    api_key="your-api-key"
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Check DB: mysql://root:Pass123@192.168.1.100:3306"}]
)
print(response.choices[0].message.content)
```

### 5. Custom Relay / Aggregator Channels (e.g. One API / New API)
1. In "Clients", click "Add Client";
2. **Target Base URL**: your relay address (e.g. `https://api.your-relay.com`);
3. **Local Port**: assign an unused port (e.g. `18709`);
4. **Masking Paths**: simply enter `/v1` (prefix matching automatically covers `/v1/chat/completions`, `/v1/models`, etc.);
5. Save, then set your AI tool's Base URL to `http://127.0.0.1:18709/v1`!

### 6. Browser Extension (ChatGPT, Claude & Web AI)

Web-based AI platforms cannot configure an API Base URL. Use Maskit's browser extension for fully automated masking and stream unmasking:

1. **Install Extension**: Download `Maskit_<version>_extension.zip` from [Releases](https://github.com/xiaYuTian11/maskit/releases/latest) and extract it. In Chrome/Edge, open `chrome://extensions` → toggle **Developer mode** → click **Load unpacked** and select the extracted folder (source users can directly load the `extension/` directory);
2. **Connect to Engine**: In Maskit desktop dashboard `Settings → Browser Extension`, enable the extension bridge and copy your **Access Token** into the extension's settings popup;
3. **Enable Sites**: `chatgpt.com`, `claude.ai`, and `deepseek.com` are pre-authorized out of the box; the other 14 preset sites can be granted with one click in the extension settings (unverified ones are labeled), and custom sites are supported.

> 💡 **Status & Troubleshooting**:
> - **File & Attachment Masking**: Web-attachment uploads and Office document masking (`.docx` / `.xlsx` / `.pptx` and transcoded `.doc` / `.xls`) are adapted for ChatGPT / Claude and need no manual scrubbing; on sites not yet adapted (e.g. DeepSeek) the uploaded file itself is not masked and the extension shows a popup notice;
> - Extension icon popup clearly displays current state: Green (Protected), Yellow (**engine offline — plaintext passthrough: not masked, but still connected**), Red (invalid token or bridge disabled — **also passthrough, not masked**);
> - **When the engine is unreachable or the token is invalid, the extension passes traffic through unmasked by default** (the "never disconnect" trade-off); enable "Block when engine unavailable" in Settings if you would rather see requests fail than leave them unmasked;
> - Extension events are logged in the dashboard's "Event Logs" and can be filtered by ingress (Proxy Link vs Browser Extension).

---

## 🚀 Download & Deployment

### Option A: Desktop Client (Windows / macOS, Recommended for Personal Use)

Download the latest release package for your operating system from **[GitHub Releases](https://github.com/xiaYuTian11/maskit/releases)**:

- **Windows Users**: Download `Maskit_<version>_x64-setup.exe` installer. Control from system tray with automated Minisign-verified updates;
- **macOS Users (Apple Silicon M-Series)**: Download `Maskit_<version>_aarch64.dmg`, open it, and drag `Maskit.app` into your `Applications` folder.
  > 💡 **macOS First Launch Notice**: If macOS Gatekeeper alerts that the app "cannot be opened because Apple cannot check it for malicious software", right-click `Maskit.app` in Finder and select **Open**, or run the following command in Terminal to clear the quarantine flag:
  > ```bash
  > xattr -cr /Applications/Maskit.app
  > ```

---

### Option B: Docker Private Gateway (Recommended for Teams / Servers / NAS)
**No source checkout required.** Pull the official multi-arch image (native `linux/amd64` and `linux/arm64`):

```bash
docker run -d \
  --name maskit \
  --restart unless-stopped \
  -p 127.0.0.1:5801:5801 \
  -p 127.0.0.1:18701:18701 \
  -v maskit_data:/data \
  -e MASKIT_PANEL_TOKEN="change-me-to-a-strong-token" \
  ghcr.io/xiayutian11/maskit:latest
```

> 💡 **Port Mapping & Network Guide**:
> - `5801`: **Web Console Port (Required)** for dashboard, rules, and client management;
> - `18701` onwards: **LLM Reverse Proxy Ports (Map on demand)**. For example, 18701 for OpenAI and 18702 for DeepSeek. **Only map the ports you actively use** (e.g. `-p 127.0.0.1:18701-18703:18701-18703` for three upstreams); do not blindly expose a wide port range;
> - **Host Binding**: Bind to `-p 127.0.0.1:5801:5801` when behind Nginx or for local-only use. For direct IP access across a private LAN/intranet without Nginx, drop the `127.0.0.1:` prefix (`-p 5801:5801 -p 18701:18701`);
> - **Console Token**: `MASKIT_PANEL_TOKEN` must be **≥16 ASCII characters** (avoid non-ASCII/CJK characters to prevent falling back to random log tokens).

Open `http://<server-ip>:5801` directly in your browser and enter your configured token in the login dialog (or use `http://<server-ip>:5801/#token=<your-token>` for quick sign-in; the fragment is never sent in the request and never lands in proxy access logs, and the token is stripped from the URL once loaded).

> **Security Tip & Reverse Proxy (Nginx Config)**:
> Bound to `127.0.0.1` by default to avoid exposing unauthenticated proxy ports to the public internet. If placing behind an Nginx reverse proxy with TLS, **make sure to pass `-e MASKIT_TRUST_PROXY=1` in your docker run command** (so the panel trusts the forwarded `X-Forwarded-Proto: https` header and avoids CSRF/Origin rejections):
> ```nginx
> server {
>     listen 443 ssl;
>     server_name maskit.example.com;
>     # ssl certificates...
>
>     # 1. Web Console (Sign-in via Token dialog)
>     location / {
>         proxy_pass http://127.0.0.1:5801;
>         proxy_set_header Host $host;
>         proxy_set_header X-Real-IP $remote_addr;
>         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
>         proxy_set_header X-Forwarded-Proto $scheme;  # Crucial: informs backend that external proto is https
>         proxy_set_header X-Forwarded-Host $host;
>     }
>
>     # 2. Model Proxy Port (e.g. OpenAI; disable buffering for real-time streaming; restrict to private LAN if possible)
>     location /openai/ {
>         proxy_pass http://127.0.0.1:18701/;
>         proxy_set_header Host $host;
>         proxy_buffering off;
>         proxy_read_timeout 600s;
>     }
> }
> ```

#### Advanced: Single-Port Mode (one proxy port for Docker)

Prefer not to map one port per client? Use **single-port prefix mode**: all clients share port 5802 and are distinguished by path prefix. In the console's "Clients" page, each client's **Path Prefix (base_path)** becomes the path part of the client's `base_url`:

```bash
docker run -d \
  --name maskit \
  --restart unless-stopped \
  -p 127.0.0.1:5801:5801 \
  -p 127.0.0.1:5802:5802 \
  -v maskit_data:/data \
  -e MASKIT_PANEL_TOKEN="YourSecretToken123456" \
  ghcr.io/xiayutian11/maskit:latest
```

Given two clients (path prefixes `/openai` and `/anthropic`), point external tools at:

| Client | Base URL |
|---|---|
| OpenAI protocol (prefix `/openai`) | `http://<server-ip>:5802/openai/v1` |
| Anthropic protocol (prefix `/anthropic`) | `http://<server-ip>:5802/anthropic` |

> 💡 **Multi-port vs single-port**: multi-port (18701+) gives each client a dedicated port and the shortest `base_url` — ideal for local personal use; single-port maps just 5802 — ideal when container ports are constrained or you route everything through one Nginx prefix. Both modes coexist: prefix routing on 5802 and each client's dedicated port work simultaneously.

---

## 🔥 Concurrency Tuning & 503 Triage (Read This When Things Get Slow)

Maskit's masking runs **only on your own machine** — every request costs local CPU. When many agents
(Cursor + Claude Code + Codex + a script) share one gateway, the local CPU is the bottleneck, not the upstream.

### Recommended settings

| Scenario | What to do |
|---|---|
| 1–2 agents on a personal machine | Defaults are fine. Semantic recognition (NER) stays on. |
| 4+ agents, or NER enabled on a 1–2 core box | Turn **NER off** in Settings, or give the container/machine more CPU. NER is the single biggest CPU consumer. |
| Docker on a small VPS | Set `--cpus` to what you actually have (e.g. `--cpus=2`): thread count, concurrency, pool widths and the NER budget all adapt to the **actually available** cores (cgroup quota ∩ affinity mask). Without `--cpus` the process treats every core it can see as its own and looks "pinned at 100%". |
| Large bodies / many parallel streams | Lower concurrency at the client; the queue budget (`MASKIT_MASK_QUEUE_BYTES`) is **backpressure, not throughput** — raising it only delays the rejection. |

Masking pool width adapts to the **actually available** core count (1–4, always 1 on ≤2 cores) and can be overridden
with `MASKIT_MASK_WORKERS`. Note that plain-Python rule scanning is GIL-bound: adding workers helps most with NER
(ONNX releases the GIL) and with avoiding head-of-line blocking, not with raw regex throughput.

The NER **global CPU budget** defaults to 75% of what the NER thread pool could consume
(concurrency × ONNX threads × 750, measured in **CPU milliseconds per second**, not wall-clock) and can be
overridden with `MASKIT_NER_BUDGET`; exhausting it behaves exactly like the per-request budget below.

The NER **per-request budget** defaults to **10 seconds** (Settings → Proxy behaviour → per-request budget,
or the `MASKIT_NER_REQ_BUDGET_S` environment variable, which overrides the UI). It caps how slow masking
may get on a single request: clients typically time out at 180s while the upstream first byte alone can take
100s, so the budget is what is left for the upstream. When it runs out, semantic recognition degrades,
regex rules still apply, and the event detail marks `budget_exhausted`. Raising it masks bigger bodies more
completely, but the failure mode is then a client-side `connection closed` (not a Maskit 503).

### A 503 is not always "the gateway is overloaded"

Since 0.6.0 every 503 is attributed. Open the event detail, or run **Settings → One-click self-check**:

| `block_source` / reason | Meaning | What to do |
|---|---|---|
| `upstream` | The **upstream/relay** returned it (Maskit merely recorded it). Multiple agents on one API key is the usual cause | Lower concurrency, add retry backoff, or use separate keys |
| `engine_busy` | The local masking queue hit its byte/count budget | Lower concurrency; raise `MASKIT_MASK_QUEUE_BYTES` only if the machine truly has headroom |
| `engine_timeout` | One request exceeded the end-to-end deadline (`MASKIT_ENGINE_DEADLINE_S`, default 120s) | Check for a huge body or an overloaded box; the request result is discarded, the client may retry |
| `fallback` | The proxy is stopped and the fallback listener is configured to answer 503 | Start the proxy, or set the stop mode to `passthrough` |

**One-click self-check** (Settings → Health Check & Recovery) turns the same signals into
"problem + evidence + suggested action", including bare-metal vs container CPU throttling
(`nr_throttled`), NER degradation reasons, queue backlog and writer drops. It never uploads anything.

> 📦 **The NER model is not distributed with the source repo**: `engine/models/ner_mini_zh/`
> (a ~100MB quantized ONNX) is `.gitignore`d and ships only inside the **desktop installers** and the
> **official Docker image**. When running from source or building your own image, place these three files
> under `engine/models/ner_mini_zh/`: `config.json`, `tokenizer.json`, `model_quantized.onnx`.
> Otherwise the "Semantic recognition" toggle can be turned on but will do nothing — the engine logs a
> warning at startup, and **One-click self-check** in Settings reports the model as unavailable.


---

### Option C: Run from Source

```bash
git clone https://github.com/xiaYuTian11/maskit.git
cd maskit

# 1. Install dependencies
pip install -r requirements.txt

# 2. Build frontend & start engine (skip frontend build if only using console API)
cd frontend && npm install && npm run build && cd ..
python engine/panel.py

# 3. Frontend dev server (Vite hot-reload, recommended)
cd frontend && npm run dev
```

> 💡 **Testing Tip**: Run `python scripts/verify-all.py` for the complete 15-item test suite (unit tests, build, lint, version consistency, public release audit). If working on the browser extension, run `python tests/e2e_ext_bridge.py` for end-to-end browser tests.

---

## 💬 Community & Support

- **Official QQ Group**: **`489926214`** (Discussion, rule feedback & release updates);
- Forum: **[LINUX DO Community](https://linux.do/t/topic/2884715)**;
- Feedback: [GitHub Issues](https://github.com/xiaYuTian11/maskit/issues) & [GitHub Discussions](https://github.com/xiaYuTian11/maskit/discussions);
- Security Vulnerabilities: see [SECURITY.md](SECURITY.md).

---

## 📜 License

Data Maskit is released under the **[GNU AGPL-3.0](LICENSE)**. Free for personal developers, researchers, and open-source projects. For commercial redistribution or embedding into closed-source products, please comply with AGPL-3.0 terms.

<p align="center">
  Made with ❤️ by TMW & Contributors.
</p>
