"""
Data Maskit 控制面板 - 本地 Flask 服务

由桌面壳（Tauri）作为 sidecar 拉起，也可手动运行：
    python engine/panel.py            # 源码态
    MaskitEngine.exe                  # 打包态
浏览器访问 http://127.0.0.1:5801
管：启停本地显式代理 / 配置站点敏感词 / 实时日志 / 紧急恢复 / 装证书
"""
# Data Maskit — 本地 LLM 敏感信息脱敏代理
# Copyright (C) 2026 TMW
#
# 本程序是自由软件：你可以依据自由软件基金会发布的 GNU Affero 通用公共许可证
# （版本 3）条款重新分发和/或修改它。
# 本程序基于「希望有用」的目的分发，但不附带任何担保；亦无对适销性或特定用途
# 适用性的默示担保。详见 GNU Affero 通用公共许可证。
# 你应已随本程序收到一份 GNU AGPL 副本；若无，见 <https://www.gnu.org/licenses/>。
__version__ = '0.5.0'
import json
import codecs
import copy
import hashlib
import logging
import math
import io
import zipfile
import base64
import xml.etree.ElementTree as ET
import os
import platform
import re
import sys
import secrets
import atexit
import signal
import time
import socket
import subprocess
import threading
import webbrowser
import zlib
from pathlib import Path
from collections import deque
from urllib.parse import urlparse, urlsplit, unquote
from flask import Flask, request, jsonify, make_response, send_file
from shield_defaults import (
    DEFAULT_DOMAINS,
    DEFAULT_PATHS,
    DEFAULT_SECRET_PREFIXES,
    DEFAULT_TTL,
    DEFAULT_UPSTREAMS,
    DEFAULT_BUILTIN_RULES,
    DEFAULT_EGRESS_PROXY,
    DEFAULT_COMMAND_BLOCK,
    BUILTIN_RULE_META,
    validate_command_regex,
    parse_egress_proxy,
    OPENROUTER_MODELS_URL,
    PRICE_SYNC_INTERVAL_DAYS,
    MODEL_PRICES,
    extract_usage,
    SSEUsageAccumulator,
)
from credential_labels import CREDENTIAL_LABELS

# 资源目录（打包后随 exe 发布的只读资源：templates、transparent.py、shield_defaults.py）
# PyInstaller onefire 时为 sys._MEIPASS；开发时为脚本所在目录。
_BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", None) or Path(__file__).parent.resolve())
# 可写数据目录：config.json、events.sqlite3、logs。
# 优先 LLM_SHIELD_DATA_DIR（测试/子进程数据隔离，transparent.py/event_store.py 同源读取）；
# 打包后按平台规范落盘（见 _default_data_root）；开发时默认脚本目录。
APP_DIR_NAME = "Maskit"          # Windows / macOS 的目录名（有大小写与空格惯例）
APP_DIR_NAME_POSIX = "maskit"    # Linux 的目录名（XDG 惯例全小写）
# 更名前的旧目录名，用于一次性迁移（1.5.66 及以前叫 LLM Shield）
_LEGACY_DIR_NAMES = ("LLMShield", "llmshield")


def _default_data_root() -> Path:
    """跨平台可写数据目录（配置、事件库、日志、崩溃转储）。

    | 平台 | 路径 | 依据 |
    | --- | --- | --- |
    | Windows | `%APPDATA%\\Maskit` | 漫游用户数据的系统约定位置 |
    | macOS | `~/Library/Application Support/Maskit` | Apple File System 编程指南 |
    | Linux | `$XDG_DATA_HOME/maskit`，缺省 `~/.local/share/maskit` | XDG Base Directory |

    为什么不跟安装目录走：装到 Program Files / /Applications 时程序目录对普通
    用户只读；且换目录重装、卸载都不应波及用户配置与历史事件。
    """
    home = Path.home()
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        return (Path(base) if base else home / "AppData" / "Roaming") / APP_DIR_NAME
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / APP_DIR_NAME
    base = os.environ.get("XDG_DATA_HOME")
    return (Path(base) if base else home / ".local" / "share") / APP_DIR_NAME_POSIX


def _migrate_legacy_data_root(target: Path) -> None:
    """把更名前的数据目录内容搬到新目录（幂等，只在新目录还没有 config.json 时执行）。

    更名 LLM Shield → Data Maskit 会换掉数据目录名，老用户升级后如果不迁移，
    表现是「配置、客户端、词库、历史统计全没了」——比不改名严重得多。

    判据用「新目录没有 config.json」而不是「新目录不存在」：Tauri 壳在拉起引擎前
    就会往新目录写 engine-stdout.log，目录必然已存在，用存在性判断会导致迁移永不触发。

    逐项 rename 而非整目录 rename：新目录可能已有壳写的日志文件；同名项一律跳过，
    保证「新的赢」，不覆盖任何已有数据。单项失败不影响其余项。
    """
    if (target / "config.json").exists():
        return
    for legacy_name in _LEGACY_DIR_NAMES:
        legacy = target.parent / legacy_name
        if not legacy.is_dir() or not (legacy / "config.json").exists():
            continue
        try:
            target.mkdir(parents=True, exist_ok=True)
            moved = 0
            for item in list(legacy.iterdir()):
                dst = target / item.name
                if dst.exists():
                    continue
                try:
                    item.rename(dst)
                    moved += 1
                except Exception:
                    # 跨盘/占用/权限：单项跳过，旧目录原件保留，可手工搬
                    pass
            if moved:
                # 留一张纸条说明数据去哪了，避免用户回头翻旧目录以为丢了
                try:
                    (legacy / "MOVED.txt").write_text(
                        f"数据已迁移到 {target}\n（更名为 Data Maskit）\n",
                        encoding="utf-8",
                    )
                except Exception:
                    pass
            return
        except Exception:
            # 迁移整体失败不阻断启动：按空目录继续，旧目录原样保留
            return


_env_data_dir = os.environ.get("LLM_SHIELD_DATA_DIR")
if _env_data_dir:
    DATA_ROOT = Path(_env_data_dir)
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
elif getattr(sys, "frozen", False):
    DATA_ROOT = _default_data_root()
    _migrate_legacy_data_root(DATA_ROOT)
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
else:
    DATA_ROOT = Path(__file__).parent.resolve()
os.environ.setdefault("LLM_SHIELD_DATA_DIR", str(DATA_ROOT))
from event_store import (
    DB_PATH,
    LEGACY_JSONL_PATH,
    RETENTION_DAYS as LOG_RETENTION_DAYS,
    INGRESS_VALUES,
    clear_events,
    console_decode,
    fetch_events,
    fetch_event_by_id,
    import_legacy_jsonl_once,
    init_db,
    prune_events,
    append_audit_event,
    enqueue_audit_event,
    enqueue_event,
    flush_audit_queue,
    fetch_audit_events,
    clear_audit_events,
    prune_audit_events,
    today_stats,
    stats_range,
    set_record_plaintext_words,
    fetch_restore_items,
    fetch_sibling_event,
    db_max_event_id,
    _ensure_db,
)
import audit_engine as audit_eng
ROOT = DATA_ROOT  # 兼容旧引用（CONFIG_PATH/PID_FILE/ENV_BACKUP_PATH 等可写文件）
CONFIG_PATH = DATA_ROOT / "config.json"
SCRIPTS_DIR = _BUNDLE_ROOT  # transparent.py / shield_defaults.py 所在目录（只读资源）
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
MARKER = "# LLM-Shield"  # 紧急恢复脚本 scripts/emergency-restore.bat 依赖此标记定位 hosts 块，改动须同步
CA_CERT = Path(os.path.expanduser("~")) / ".mitmproxy" / "mitmproxy-ca-cert.cer"
def _default_panel_port() -> int:
    """面板端口：默认 5801，可用环境变量 LLM_SHIELD_PANEL_PORT 覆盖（测试/冲突规避）。"""
    try:
        return int(os.environ.get("LLM_SHIELD_PANEL_PORT") or "5801")
    except ValueError:
        return 5801


PANEL_PORT = _default_panel_port()
PROXY_PORT = 5802
PID_FILE = ROOT / "shield.pid"
# mitmdump 启动就绪等待上限：冷启动要加载 transparent.py + 绑定全部 upstream 端口，
# 在弱 CPU（如 NAS/低配云主机）或多 upstream 场景下常需 20s 左右。
# 默认放宽到 60s（端口就绪即提前退出，不影响正常机型速度），并支持环境变量覆盖。
try:
    _START_READY_TIMEOUT = int(os.environ.get("MASKIT_START_READY_TIMEOUT", "60").strip() or "60")
except Exception:
    _START_READY_TIMEOUT = 60
ENV_BACKUP_PATH = ROOT / "shield-env-backup.json"
EVENT_LOG_PATH = LEGACY_JSONL_PATH
# 面板监听地址：桌面版恒 127.0.0.1；Docker/无头部署用 MASKIT_PANEL_HOST=0.0.0.0 开放。
PANEL_HOST = os.environ.get("MASKIT_PANEL_HOST", "127.0.0.1").strip() or "127.0.0.1"
# 远程模式 = 监听地址不是回环：Host 校验放开、Origin 改为同源校验，
# X-Shield-Token 仍是唯一主防线（面板可改上游/注入头，绝不可免 token）。
REMOTE_MODE = PANEL_HOST not in {"127.0.0.1", "localhost", "::1"}
# 控制面 Origin 校验逃生舱（环境变量，容器/反代场景用）。
# EdgeOne/CDN 回源时 Origin 与源站 scheme://host 不一致会让面板 403，
# 用户连 UI 都进不去，只能靠环境变量在启动前关闭校验（UI 开关见 config.origin_check）。
# 默认关闭：宁可先排查反代透传 X-Forwarded-*，也不要整体关掉 CSRF 防线。
_DISABLE_ORIGIN_CHECK_ENV = os.environ.get("MASKIT_DISABLE_ORIGIN_CHECK", "").strip() == "1"
if _DISABLE_ORIGIN_CHECK_ENV:
    print("[panel] 警告：已设置 MASKIT_DISABLE_ORIGIN_CHECK=1，控制面 Origin 校验已关闭"
          f"（适用于受信任反向代理/CDN 场景）；API 仍受 X-Shield-Token 保护）")
# 配置级 Origin 校验开关（默认开；与 UI 开关 origin_check 同步）。与
# _DISABLE_ORIGIN_CHECK_ENV 是「或」关系：任一关闭即放行。
_origin_check_enabled = True
# ── 浏览器扩展桥接（Browser Bridge v1）运行时状态 ──────────────────────────
# 与 _origin_check_enabled 同款模式：load_config / save_config 写盘后由
# _sync_runtime_config 原子同步，端点与 guard 不每次读盘。
# ── 扩展协议版本（与产品版本**解耦**）────────────────────────────────
#
# 【为什么不能拿 __version__ 来比】扩展自己的 manifest.version 是 1.0.0，客户端版本与扩展的发布节奏不同步，
# 两者**从来就不同步**（一个是浏览器扩展的发布节奏，一个是桌面 App 的），拿产品版本号
# 做兼容判定必然误报。真正要回答的是「两边对 /api/ext/* 的字段与语义是否一致」，
# 所以另立一个只随**接口契约**变化的整数。
#
# 改动规则：**只在 `/api/ext/*` 的请求/响应结构或语义发生变化时** +1，
# 产品发版、UI 调整、内部重构一律不动它。
# 扩展侧在 shared.js 里声明自己实现的版本（EXT_PROTOCOL_VERSION），两者不等即报警。
EXT_PROTOCOL_VERSION = 1

# ext_token 是 config.json 里第一个**长期**密钥（不随重启轮换），只对下面三个
# 精确白名单端点有效；API_TOKEN 对全部 /api/* 有效（二选一）。
# **精确白名单不用前缀**：否则扩展 token 能打到 /api/config、/api/ext/rotate-token。
_EXT_ENDPOINTS = frozenset({"/api/ext/ping", "/api/ext/mask", "/api/ext/restore", "/api/ext/mask-file", "/api/ext/warn"})

# 「疑似对话请求但 body 形态不受支持」的上报去重表（见 /api/ext/warn）。
# 整站漏脱敏时每一发请求都会上报，不去重会把事件页刷满、把真正要看的风险记录挤掉。
_ext_warn_seen: dict = {}
# 去重表的硬上限（**严格有界**，不能只靠时间淘汰）：见 api_ext_warn 里的淘汰逻辑。
# 该端点对已启用站点的任意页面脚本可达（path 由页面提供），不能假设调用方友善。
_EXT_WARN_MAX = 200
# 扩展上下文能出现的 Origin scheme。**扩展 ID 无法枚举**（解压加载/商店/profile 各异），
# 所以只能按 scheme 放行；详见 _origin_ok() 里的实测说明与安全影响。
_EXT_ORIGIN_SCHEMES = ("chrome-extension://", "moz-extension://", "safari-web-extension://")
_ext_cfg_state = {
    "ext_bridge_enabled": False,
    "ext_token": "",
    "ext_block_when_engine_down": False,
    "ext_record_events": True,
    # 旧版 Office(.doc/.xls) 转换开关，**默认关闭**（理由见下方完整默认配置里的长注释）。
    "ext_convert_legacy_office": False,
}


def _ext_cfg():
    """当前生效的扩展桥接运行时配置（不读盘，避免每个请求一次 config 解析）。"""
    return _ext_cfg_state


def _ext_token_ok(token):
    """校验扩展侧令牌：必须与 ext_token 精确相等（只对 _EXT_ENDPOINTS 有效）。

    ext_token 未生成（空）时恒 False —— 不允许"没设 token 就全放行"。
    compare_digest 对非 ASCII str 会抛 TypeError → 500，先转 bytes（同 API_TOKEN）。
    """
    ref = str(_ext_cfg_state.get("ext_token") or "")
    if not ref or not token:
        return False
    try:
        return secrets.compare_digest(token.encode("utf-8", "replace"),
                                      ref.encode("utf-8", "replace"))
    except Exception:
        return False


# 反代 HTTPS 终止时显式信任单跳 X-Forwarded-*。默认关闭，避免直接暴露面板时
# 客户端伪造转发头绕过 Origin 同源校验；启用者必须确保前置代理覆盖而非追加这些头。
TRUST_PROXY_ENV = "MASKIT_TRUST_PROXY"
# 反代/兜底端口监听地址：与面板一样，Docker 用 MASKIT_LISTEN_HOST=0.0.0.0 对外
LISTEN_HOST = os.environ.get("MASKIT_LISTEN_HOST", "127.0.0.1").strip() or "127.0.0.1"
# API token 每次启动随机；远程模式下用户无法读容器内 proxy_token 文件，
# 允许 MASKIT_PANEL_TOKEN 固定（≥16 位，太短直接忽略并回退随机，宁可拒绝也不弱化）。
_MIN_PANEL_TOKEN_LEN = 16
# 环境变量 token 被拒绝的标志：仅作 /api/status 展示（Docker 无头用户翻不到
# 启动日志，必须能在面板首屏看到「我设置的 token 没生效」）。
PANEL_TOKEN_ENV_REJECTED = False
_env_token = os.environ.get("MASKIT_PANEL_TOKEN", "").strip()
if _env_token and (len(_env_token) < _MIN_PANEL_TOKEN_LEN or not _env_token.isascii()):
    msg = (f"[panel] MASKIT_PANEL_TOKEN 无效（需 ≥{_MIN_PANEL_TOKEN_LEN} 位 ASCII），"
           f"已忽略并改用随机 token")
    # stdout + stderr 双写：容器日志采集器常只挂 stderr，单写 stdout 等于没写
    print(msg)
    print(msg, file=sys.stderr, flush=True)
    PANEL_TOKEN_ENV_REJECTED = True
    _env_token = ""
API_TOKEN = _env_token or secrets.token_urlsafe(24)
INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
LABEL_RE = re.compile(r"^[A-Za-z0-9_\-\u4e00-\u9fff]{1,40}$")
MAX_ITEMS = 500
MAX_WORD_LEN = 200
# 敏感词总量上限（跨所有标签）：合并正则 O(总词数×长度)，超大词表会拖慢
# 每次请求的脱敏扫描（审计 P1）。面板保存时超限截断 + 提示；引擎侧另有防御。
MAX_TOTAL_WORDS = 5000
MAX_PREFIX_LEN = 32
MIN_TTL = 10
MAX_TTL = 86400


def _safe_public_text(value, limit=0):
    """返回可展示的错误/诊断文本，避免把凭据、PII 或本机路径带出接口。

    `_scrub_text` 在本文件后部定义，但请求只会在模块初始化完成后进入 Flask；
    通过运行时查找既避免重复维护脱敏规则，也让早期启动异常有保守兜底。
    """
    try:
        scrub = globals().get("_scrub_text")
        if callable(scrub):
            return scrub(value, limit)
        text = str(value)
        if limit and len(text) > limit:
            text = text[-limit:]
        return text
    except Exception:
        return "<redacted>"

app = Flask(__name__, static_folder=None)


@app.errorhandler(Exception)
def _api_error_handler(e):
    """统一 JSON 错误响应：/api/* 路由异常不再返回 Flask 默认 HTML 500 页，
    否则前端 fetch JSON 解析失败直接白屏。"""
    try:
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return jsonify({
                "ok": False,
                "error": _safe_public_text(e.description or e.name, 300),
            }), e.code
    except Exception:
        pass
    if request.path.startswith("/api/"):
        safe_error = _safe_public_text(e, 300)
        _emit_log(f"[panel] API 异常: {safe_error}")
        return jsonify({"ok": False, "error": safe_error}), 500
    return e


def _host_ok():
    # 远程模式（Docker）下 Host 是服务器 IP/域名，无法枚举白名单，交给 token 把关
    if REMOTE_MODE:
        return True
    host = (request.host or "").split(":", 1)[0].lower()
    return host in {"127.0.0.1", "localhost"}


def _trust_proxy_enabled():
    """是否由部署者明确授权读取单跳 X-Forwarded-* 头。"""
    return os.environ.get(TRUST_PROXY_ENV, "").strip() == "1"


def _forwarded_single_value(name):
    """读取一个严格的单跳转发头；缺失、空值或多值一律返回 None。"""
    raw = request.headers.get(name, "").strip()
    if not raw or "," in raw:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch.isspace() for ch in raw):
        return None
    return raw


def _valid_forwarded_host(value):
    """验证 X-Forwarded-Host 只包含一个 host[:port]，不含 userinfo/path。"""
    if not value:
        return False
    try:
        parsed = urlsplit("//" + value)
        if parsed.username or parsed.password or parsed.path not in ("", "/"):
            return False
        if parsed.query or parsed.fragment or not parsed.hostname:
            return False
        parsed.port  # 触发非法端口 ValueError
        return True
    except (TypeError, ValueError):
        return False


def _effective_request_origin():
    """返回当前请求对外可见的 scheme/host（默认使用 Flask 原值）。"""
    scheme = (request.scheme or "http").lower()
    host = request.host
    if not _trust_proxy_enabled():
        return scheme, host
    forwarded_proto = _forwarded_single_value("X-Forwarded-Proto")
    forwarded_host = _forwarded_single_value("X-Forwarded-Host")
    if forwarded_proto and forwarded_proto.lower() in {"http", "https"}:
        scheme = forwarded_proto.lower()
    if forwarded_host and _valid_forwarded_host(forwarded_host):
        host = forwarded_host
    return scheme, host


def _normalize_origin(value):
    """规范化 Origin，拒绝路径/query/userinfo，并折叠默认端口。"""
    try:
        parsed = urlsplit(str(value or "").strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or parsed.username or parsed.password:
            return None
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment or not parsed.hostname:
            return None
        port = parsed.port
        if port is None:
            port = 80 if scheme == "http" else 443
        return scheme, parsed.hostname.lower(), port
    except (TypeError, ValueError):
        return None


def _origin_ok():
    # 逃生舱/配置开关：任一关闭即放行（仅作 CSRF 纵深防御；API 主防线仍是 X-Shield-Token）。
    if _DISABLE_ORIGIN_CHECK_ENV or not _origin_check_enabled:
        return True
    origin = request.headers.get("Origin")
    if not origin:
        return True
    # 扩展端点：合法调用方是浏览器扩展上下文，其 Origin 是 `chrome-extension://<扩展ID>`。
    # **扩展 ID 随安装方式（解压加载 / 商店）与浏览器 profile 变化，引擎无从枚举**，
    # 只能按 scheme 放行，再往下就只能靠 ext_token 这一道了（compare_digest 24 字符）。
    #
    # 实测修正（2026-09-15，真 Chrome + 扩展 + Playwright）：扩展 SW 的 **POST 确实带
    # Origin**（值为 `chrome-extension://<id>` 且 host 权限已授予）。SPEC §3.2 注释里
    # 「SW 的 fetch 不带 Origin（实测 C1）」只在 **GET/HEAD** 上成立——按 Fetch 规范，
    # 非 GET/HEAD 请求一律附加 Origin。不加这条放行，全部 mask/restore 都会被
    # `origin_rejected` 403 打回，而扩展侧把 403 当 (B) 直通 → **全站静默未脱敏**
    # （页面看起来完全正常，这是最危险的一种失败）。
    #
    # 安全影响：Web 页面的 Origin 仍然被拒——万一 token 外泄，跨源页面也用不上这个端点。
    #
    # **不放行 `Origin: null`（2026-09-15 收紧）**：早期这里额外放行了 `origin == "null"`
    # 以求稳（"万一某个 Chrome 版本把扩展 Origin 序列化成 null"），但按 Fetch 规范，
    # `null` 只来自沙箱 iframe / `data:` / `file://` 这类**无来源**上下文，扩展上下文
    # 恒有 `chrome-extension://<id>` 来源（真机 e2e 实测确认）。放行 null 等于给
    # 「任意本地 HTML 文件 + 已知 token」多开一道门，而它没有任何合法调用方 ——
    # 收益为零、风险为正，删掉。真出现 null 的现场，宁可先 403 留痕（可归因），
    # 也不要静默放行。
    if request.path in _EXT_ENDPOINTS and origin.lower().startswith(_EXT_ORIGIN_SCHEMES):
        return True
    # 远程模式：SPA 与 API 同源托管，Origin 必须等于本次请求的 scheme://host，
    # 拒绝任何外站页面借用户浏览器发起的跨源调用（token 在内存里，但 CSRF 面仍要关死）。
    if REMOTE_MODE:
        scheme, host = _effective_request_origin()
        return _normalize_origin(origin) == _normalize_origin(f"{scheme}://{host}")
    # 放行面：本地面板同源 + Tauri 壳页面（tauri://localhost / http://tauri.localhost）。
    # Tauri 壳的 fetch 经 Rust reqwest 代发（tauri-plugin-http），WebView2 会对跨域
    # 请求自动附加 Origin: tauri://localhost（Request 构造时带入，JS 无法覆盖）——
    # 不放行则新桌面壳全部 403。X-Shield-Token 仍是主防线（每次启动随机、仅本机）。
    return origin in {
        f"http://127.0.0.1:{PANEL_PORT}",
        f"http://localhost:{PANEL_PORT}",
        "tauri://localhost",
        "http://tauri.localhost",
    }


def _guard_reject(reason, resp, status=403):
    """拒绝控制面请求时留一条**结构化**日志。

    关掉 werkzeug 访问日志后（见 run_panel 末尾），这里就是「谁被拒了、为什么」
    的唯一现场。只记方法/路径/原因/来源 Host 与 Origin —— 绝不记 token，
    连长度都不记（长度也是信息）。
    """
    try:
        _emit_log(f"[panel] 拒绝 {request.method} {request.path} reason={reason} "
                  f"host={request.headers.get('Host', '')} origin={request.headers.get('Origin', '')}")
    except Exception:
        pass
    return resp, status


@app.before_request
def api_guard():
    # 存活探针：不需要 token（Docker HEALTHCHECK 拿不到随机 token），只回 ok，不泄露任何状态
    if request.path == "/healthz":
        return jsonify({"ok": True})
    # 静态托管资源（SPA HTML、JS/CSS assets/*、favicon 等由 serve_spa 托管）：
    # 纯静态文件无状态且无副作用，生产 bundle 不含 token。现代浏览器在加载
    # <script type="module" crossorigin> 静态资源时规范强制附带 Origin 头；
    # 若在反向代理（Nginx/EdgeOne 等）HTTPS 终止环境下对其做 Origin/Host 校验，
    # 会因协议/回源域名不一致误判 403 导致 JS 被拦、页面一片死白（实测事故）。
    # 因此静态资源直接放行，仅 /api/* 控制面接口进入安全防线。
    if not request.path.startswith("/api/"):
        return None
    if not _host_ok():
        return _guard_reject("host_rejected",
                             jsonify({"ok": False, "error": "host_rejected",
                                      "message": "非法请求来源 Host"}))

    # API 令牌校验（主防线）：任何外部未授权请求在第一道防线直接阻断
    token = request.headers.get("X-Shield-Token", "")
    # compare_digest 对非 ASCII str 会抛 TypeError → 500，先转 bytes
    if request.path in _EXT_ENDPOINTS:
        # 扩展端点：ext_token 或 API_TOKEN 二选一。ext_token **不得**用于其他
        # /api/*（精确白名单而非前缀，否则 rotate-token 会被扩展 token 打到）。
        if not (_ext_token_ok(token)
                or secrets.compare_digest(token.encode("utf-8", "replace"), API_TOKEN.encode("utf-8"))):
            return _guard_reject("invalid_token",
                                 jsonify({"ok": False, "error": "invalid_token",
                                          "message": "无效请求令牌"}))
        # 用户关掉总开关的语义是「我要直连」，不是「我要断网」：回 403 且**不带
        # blocking**，扩展侧按 (B) 默认桶直通（红线 2）。带 blocking 等于让
        # 「面板关开关」变成「网页 AI 全站不可用」。
        if not _ext_cfg_state.get("ext_bridge_enabled"):
            return _guard_reject("ext_bridge_disabled",
                                 jsonify({"ok": False, "error": "ext_bridge_disabled",
                                          "message": "浏览器扩展桥接未启用"}))
    elif not secrets.compare_digest(token.encode("utf-8", "replace"), API_TOKEN.encode("utf-8")):
        return _guard_reject("invalid_token",
                             jsonify({"ok": False, "error": "invalid_token",
                                      "message": "无效请求令牌"}))

    if not _origin_ok():
        # 管理员紧急自救放行：
        # 若操作者已持有经过强密码校验合法的 X-Shield-Token，且本次请求是关闭 Origin 校验的自救操作，
        # 允许放行，杜绝反代 Origin 配置错误导致设置页陷入无法自救的死锁。
        if request.method == "POST" and (
            request.path == "/api/config/disable_origin_check"
            or (request.path == "/api/config" and isinstance(request.get_json(silent=True), dict) and request.get_json(silent=True).get("origin_check") is False)
        ):
            return None
        origin = request.headers.get("Origin", "")
        scheme, host = _effective_request_origin() if REMOTE_MODE else ("http", f"127.0.0.1:{PANEL_PORT}")
        return _guard_reject("origin_rejected", jsonify({
            "ok": False,
            "error": "origin_rejected",
            "message": "Origin 校验未通过",
            "current_origin": origin,
            "expected_origin": f"{scheme}://{host}",
        }))

    return None


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    # script-src 只给 'self'：SPA 的脚本全部来自同源 /assets/*，无需 nonce，
    # 也不需要 'unsafe-inline'（模板内联事件属性已清零，审计 P2-2 收口）。
    # style-src 保留 'unsafe-inline'：页面有大量 <style> 块与 style 属性，
    # 收紧会禁掉整页样式，收益与风险不成比例。
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    )
    return resp

# ========== 状态 ==========
state = {
    "proxy_running": False,
    "proxy_starting": False,
    "proxy_stopping": False,
    "proxy_pid": None,
    "passthrough": False,        # 透传兜底中（未启动 mitmdump，端口仍转发但不脱敏）
    "fallback_mode": "",         # 当前兜底形态：""=无 / "passthrough"=明文直连 / "error"=503 占位
    "upstream": "",
    "capture_mode": "reverse",
    "started_at": 0,
    "stop_requested": False,   # 主动停止标记，区分"用户点了停止"与"进程崩了"
    "last_error": "",          # 最近一次自动恢复失败原因，供面板展示
    "generation": 0,           # 每次启停递增，隔离旧 watchdog，避免干扰新进程
    "port_down_rounds": 0,     # watchdog 连续检测到端口缺失的轮数（连续 N 轮才重启，防抖）
}

# mitmdump 异常退出后的自动重启上限（连续失败超过此数即降频，避免无意义刷日志）
_WATCHDOG_MAX_RESTARTS = 5
# 超过上限后转入的慢速重试间隔（秒）。不是放弃：占端口的第三方进程退出、
# mitmdump 重新装好等外部条件恢复后，能自己救回来，不必等用户手动点启动。
_WATCHDOG_IDLE_RETRY = 120
# watchdog 连续多少轮（每轮 5s）检测到 upstream 端口未监听才触发重启。
# 取 2 = 约 10s：单轮可能是 netstat 偶发空结果或端口重绑瞬间，不足以判定故障。
_PORT_DOWN_RESTART_ROUNDS = 2
# 外部命令超时（秒）：certutil/taskkill/ipconfig 卡住会把 Flask 请求线程永久挂死
_CMD_TIMEOUT = 20

# 导出单次上限。比 fetch_events 给轮询用的 1000 大——导出是用户显式点一次的动作，
# 响应大一点无所谓；轮询是 3 秒一次，必须小。超出时导出结果里带 truncated=True。
EXPORT_MAX = 5000


def _no_window():
    """子进程不弹黑窗（CREATE_NO_WINDOW）。netstat/taskkill/ipconfig 被高频调用，
    没这个 flag 会每次闪一个 cmd 黑窗（api_status 每 2.5s 轮询一次就弹一次）。"""
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run_console(argv, timeout=None):
    """跑系统控制台命令，返回 (returncode, stdout+stderr 文本)。

    不能用 subprocess 的 text=True：Windows 下 netstat/tasklist/taskkill 按系统
    代码页输出（中文为 GBK），而 PYTHONUTF8=1 会把 text 模式默认编码定成
    utf-8 导致解码异常；故取原始字节，交 console_decode 跨平台安全解码。

    超时/启动失败按调用方既有语义抛出，由各调用点的 except 处理。
    """
    kwargs = {
        "capture_output": True,
        "timeout": _CMD_TIMEOUT if timeout is None else timeout,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = _no_window()
    proc = subprocess.run(argv, **kwargs)
    return proc.returncode, console_decode((proc.stdout or b"") + (proc.stderr or b""))


def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

log_buf = deque(maxlen=800)      # 原始日志行
events = deque(maxlen=800)       # 解析后事件 {seq, ts, type, ...}
seq_lock = threading.Lock()
buf_lock = threading.Lock()      # 保护 log_buf/events 的 append 与遍历
_seq = [0]
_last_log_prune = [0.0]
proc = {"p": None}
lock = threading.Lock()
# 保护配置的「读-改-写」整体：Flask 默认多线程，/api/config 保存与 load_config
# 里的迁移写入可能并发。单独的原子写只保证文件不半截，挡不住丢更新
# （两个线程各自读到旧配置、各改一处、后写的覆盖先写的）。可重入：
# load_config 内部会调 save_config 落迁移标记。
cfg_lock = threading.RLock()
shutdown_lock = threading.Lock()
shutdown_done = False
_console_handler_ref = None


def _next_seq():
    with seq_lock:
        _seq[0] += 1
        return _seq[0]


# mitmproxy 内核的连接噪音行：每 2.5s 状态轮询的端口探测/客户端握手都会刷一行，
# 800 行环形缓冲几分钟就被占满，崩溃现场的 Traceback 全被冲掉。一律不进 log_buf。
_CONN_NOISE_RE = re.compile(r"client (connect|disconnect|tls|handshake)|server (connect|disconnect)|\d+\.\d+\.\d+\.\d+:\d+: client")


def _emit_log(line: str):
    line = line.rstrip("\r\n")
    if not line:
        return
    ev = None
    if line.startswith("SHIELD\t"):
        parts = line.split("\t", 2)
        typ = parts[1] if len(parts) > 1 else "?"
        try:
            data = json.loads(parts[2]) if len(parts) > 2 and parts[2] else {}
        except Exception:
            data = {"raw": parts[2] if len(parts) > 2 else ""}
        ev = {"seq": _next_seq(), "ts": time.time(), "type": typ, **data}
    with buf_lock:
        if not ev and _CONN_NOISE_RE.search(line):
            return  # 连接噪音不进日志缓冲（避免刷掉崩溃现场）
        log_buf.append(line)
        if ev:
            events.append(ev)


# tail 通道脱敏白名单：log_buf 保留 SHIELD 行原文供本地排障
# （800 行环形缓冲不外传），但 /api/logs 会把 tail 回传给前端直接 textContent
# 展示——original/dialog/req_preview 等明文不能经此通道泄漏（与「明文只进详情
# 弹窗」约束一致）。白名单外字段一律剔除；非 SHIELD 行（mitmdump 连接日志、
# [panel] 行）原样返回。
_TAIL_KEEP_FIELDS = {
    "seq", "ts", "type", "host", "path", "method", "status",
    "count", "restored", "http_status", "model", "upstream", "sid", "reason", "msg",
    # ingress（proxy/ext）与 client_app 都是**非敏感的结构性字段**：
    #   · ingress：入口维度。事件页早就能看见它，tail 通道不收的话两个视图口径不一致；
    #   · client_app：tail 通道的「上游」列取的正是 upstream || client_app，
    #     原本没收它 —— 于是 tail 里那一列**一直是空的**，排查时分不清是谁发的。
    #     顺手一起补，二者都不含正文/占位符/原文。
    "ingress", "client_app",
}


def _tail_line_sanitize(line: str) -> str:
    """把 SHIELD 事件行裁剪为仅含展示安全字段的行；其余行原样返回。"""
    line = line.rstrip("\r\n")
    if not line.startswith("SHIELD\t"):
        return line
    parts = line.split("\t", 2)
    if len(parts) < 3:
        return line
    try:
        data = json.loads(parts[2])
    except Exception:
        return line
    if not isinstance(data, dict):
        return line
    keep = {k: v for k, v in data.items() if k in _TAIL_KEEP_FIELDS}
    its = data.get("items")
    if isinstance(its, list):
        keep["items"] = [
            {"label": str(i.get("label") or ""), "preview": str(i.get("preview") or "")}
            for i in its if isinstance(i, dict)
        ]
    return "SHIELD\t" + parts[1] + "\t" + json.dumps(keep, ensure_ascii=False)


def prune_event_log(now=None, retention_days=None):
    """Keep structured event logs bounded. retention_days 默认读配置 log_retention_days。"""
    try:
        if retention_days is None:
            try:
                retention_days = _normalize_retention(load_config().get("log_retention_days", LOG_RETENTION_DAYS))
            except Exception:
                retention_days = LOG_RETENTION_DAYS
        result = prune_events(now=now, retention_days=retention_days)
        # 审计表同样受保留策略约束（曾漏掉：audit_events 只增不删，磁盘无限膨胀）
        try:
            from event_store import prune_audit_events
            prune_audit_events(now=now, retention_days=retention_days)
        except Exception:
            pass
        return result
    except Exception as e:
        return {"ok": False, "error": _safe_public_text(e, 240), "removed": 0}


def preload_events(limit=800):
    """Import legacy JSONL once; SQLite is queried directly by /api/logs."""
    try:
        result = import_legacy_jsonl_once()
        return {"ok": bool(result.get("ok")), "loaded": int(result.get("imported", 0) or 0)}
    except Exception as e:
        return {"ok": False, "error": _safe_public_text(e, 240), "loaded": 0}


def clear_logs():
    with buf_lock:
        log_buf.clear()
        events.clear()
    try:
        return clear_events()
    except Exception as e:
        return {"ok": False, "error": _safe_public_text(e, 240)}


# ========== 命令行客户端环境变量 + Windows 当前用户系统代理 ==========
CLIENT_ENV = {
    "HTTP_PROXY": f"http://127.0.0.1:{PROXY_PORT}",
    "HTTPS_PROXY": f"http://127.0.0.1:{PROXY_PORT}",
    "http_proxy": f"http://127.0.0.1:{PROXY_PORT}",
    "https_proxy": f"http://127.0.0.1:{PROXY_PORT}",
    "NO_PROXY": "localhost,127.0.0.1,::1",
    "no_proxy": "localhost,127.0.0.1,::1",
    "NODE_EXTRA_CA_CERTS": str(CA_CERT),
}
SYSTEM_PROXY = {
    "ProxyEnable": (1, "REG_DWORD"),
    "ProxyServer": (f"http=127.0.0.1:{PROXY_PORT};https=127.0.0.1:{PROXY_PORT}", "REG_SZ"),
    "ProxyOverride": ("localhost;127.0.0.1;::1;<local>", "REG_SZ"),
}


def _read_user_env(name):
    if sys.platform != "win32":
        return False, ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return True, value
    except Exception:
        return False, ""


def _write_user_env(name, value):
    if sys.platform != "win32":
        return
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as key:
            if value is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
    except Exception:
        pass


def _read_system_proxy_value(name):
    if sys.platform != "win32":
        return False, "", 0
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ) as key:
            value, value_type = winreg.QueryValueEx(key, name)
            return True, value, value_type
    except Exception:
        return False, "", 0


def _write_system_proxy_value(name, value, value_type=None):
    if sys.platform != "win32":
        return
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if value is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            else:
                if value_type is None:
                    value_type = winreg.REG_DWORD if name == "ProxyEnable" else winreg.REG_SZ
                winreg.SetValueEx(key, name, 0, value_type, value)
    except Exception:
        pass


def _broadcast_env_change():
    try:
        import ctypes
        result = ctypes.c_ulong()
        ctypes.windll.user32.SendMessageTimeoutW(
            0xFFFF, 0x001A, 0, "Environment", 0x0002, 5000, ctypes.byref(result)
        )
    except Exception:
        pass


def _broadcast_proxy_change():
    try:
        import ctypes
        ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass


def _backup_values():
    return {
        "pid": os.getpid(),
        "created_at": time.time(),
        "env": {
            name: {"exists": exists, "value": value}
            for name in CLIENT_ENV
            for exists, value in [_read_user_env(name)]
        },
        "system_proxy": {
            name: {"exists": exists, "value": value, "type": value_type}
            for name in SYSTEM_PROXY
            for exists, value, value_type in [_read_system_proxy_value(name)]
        },
    }


def apply_client_env():
    """把命令行/系统代理环境变量指向本地代理（Windows）。

    ⚠️ 当前**没有生产调用点**（仅 `tests/test_shield.py` 引用）：这个「自动改用户
    环境变量」的能力还没有 UI 入口，接线与否属产品决定，所以先留着而不是删掉。
    配套的 `restore_client_env()` 在生产路径上是活的（退出、`/api/restore` 紧急
    恢复都要还原用户环境，包括清理更早版本写下的备份），删掉本函数会让那套还原
    逻辑失去写入方、无从验证。
    """
    if os.environ.get("LLM_SHIELD_AUTO_ENV", "1") == "0":
        return
    if os.name != "nt" and ENV_BACKUP_PATH.name == "env_backup.json":
        return
    try:
        if not ENV_BACKUP_PATH.exists():
            backup = _backup_values()
            server = (backup.get("system_proxy", {}).get("ProxyServer", {}) or {}).get("value", "")
            enabled = (backup.get("system_proxy", {}).get("ProxyEnable", {}) or {}).get("value", 0)
            old_upstream = parse_system_proxy(server) if enabled else ""
            if old_upstream:
                backup["old_upstream"] = old_upstream
                os.environ["LLM_SHIELD_UPSTREAM"] = old_upstream
            ENV_BACKUP_PATH.write_text(json.dumps(backup, ensure_ascii=False, indent=2), encoding="utf-8")
        for name, value in CLIENT_ENV.items():
            _write_user_env(name, value)
        for name, (value, value_type_name) in SYSTEM_PROXY.items():
            value_type = 4 if value_type_name == "REG_DWORD" else 1
            _write_system_proxy_value(name, value, value_type)
        _broadcast_env_change()
        _broadcast_proxy_change()
        _emit_log("[panel] 已设置命令行代理环境变量和 Windows 当前用户系统代理")
    except Exception as e:
        _emit_log(f"[panel] 设置客户端代理失败: {e}")


def restore_client_env():
    if os.environ.get("LLM_SHIELD_AUTO_ENV", "1") == "0":
        return
    if os.name != "nt" and ENV_BACKUP_PATH.name == "env_backup.json":
        return
    try:
        if ENV_BACKUP_PATH.exists():
            backup = json.loads(ENV_BACKUP_PATH.read_text(encoding="utf-8"))
            values = backup.get("env") or backup.get("values") or {}
            for name in CLIENT_ENV:
                old = values.get(name, {"exists": False, "value": ""})
                _write_user_env(name, old.get("value", "") if old.get("exists") else None)
            system_proxy = backup.get("system_proxy") or {}
            for name in SYSTEM_PROXY:
                old = system_proxy.get(name, {"exists": False, "value": "", "type": 0})
                _write_system_proxy_value(
                    name,
                    old.get("value", "") if old.get("exists") else None,
                    old.get("type") or None,
                )
            ENV_BACKUP_PATH.unlink(missing_ok=True)
        else:
            # 无备份时清空所有 Shield 管理的环境变量。属于「紧急恢复」语义——
            # 可能会连带删掉用户自己原有的 HTTP_PROXY 等（不是 Shield 设的）。
            # 记日志提示用户（审计第三批 P3：值得提示）。
            _emit_log("[panel] 无环境备份，清空所有代理环境变量（注意：可能包含用户原有变量）")
            for name in CLIENT_ENV:
                _write_user_env(name, None)
            for name in SYSTEM_PROXY:
                _write_system_proxy_value(name, None)
        _broadcast_env_change()
        _broadcast_proxy_change()
        _emit_log("[panel] 已恢复命令行代理环境变量和 Windows 当前用户系统代理")
    except Exception as e:
        _emit_log(f"[panel] 恢复客户端代理失败: {e}")


# ========== 旧版 hosts marker 清理 ==========
def hosts_restore():
    """只清理本工具 marker 行，避免覆盖用户在 hosts 中的其他修改。"""
    if not is_admin():
        return False, "需管理员权限"
    lines = Path(HOSTS_FILE).read_text(encoding="utf-8", errors="replace").splitlines()
    new_lines = [l for l in lines if MARKER not in l]
    if new_lines != lines:
        Path(HOSTS_FILE).write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        _flushdns()
        return True, None
    _flushdns()
    return True, None


def _flushdns():
    # 加超时：ipconfig 偶发卡住会把调用它的 Flask 请求线程一起挂死
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=_CMD_TIMEOUT,
                       creationflags=_no_window())
    except Exception:
        pass


# ========== 透传层（不脱敏直连） ==========
# 用户核心诉求：打开软件=客户端可用；启动代理=脱敏。
# 未启动 mitmdump 时，面板直接监听 upstream 端口并原样转发到上游（透传不脱敏），
# 端口永远有人监听，客户端不会「连接被拒」。启动代理时透传让位，mitmdump 接管。
import http.server
import http.client

_passthrough = {"servers": {}, "lock": threading.Lock(), "mode": ""}


def _read_chunked_body(rfile, limit=64 * 1024 * 1024):
    """读取 Transfer-Encoding: chunked 请求体并解码（BaseHTTPRequestHandler 不自动解）。

    必须先判后读：chunk 头里的 `size` 由客户端完全控制，`rfile.read(size)` 会按它
    分配并阻塞读取。以前是「先读后判」（读完再比 limit），一个 `FFFFFFFF` 的 chunk
    头就能让进程分配几个 GB 或长时间挂住。透传层在 Docker 下会监听
    0.0.0.0（MASKIT_LISTEN_HOST），是网络可达的，所以这条要按不可信输入处理。

    畸形 chunk 头（非十六进制）/ 中途 EOF 一律 raise：曾静默 break 返回半截 body，
    截断的 JSON 被转发上游报 400——错误被移花接木，排障困难（审计 P2）。
    """
    body = b""
    while True:
        try:
            line = rfile.readline()
        except Exception:
            raise ValueError("chunked_read_error")
        if not line:
            raise ValueError("chunked_body_truncated")  # 客户端中途断连，body 不完整
        try:
            size = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            raise ValueError("malformed_chunk_header")
        if size == 0:
            # 吃掉 trailing headers 到空行
            while True:
                try:
                    t = rfile.readline()
                except Exception:
                    break
                if t in (b"\r\n", b"\n", b""):
                    break
            break
        if size < 0 or len(body) + size > limit:
            raise ValueError("request body too large")
        chunk = rfile.read(size)
        if len(chunk) < size:
            raise ValueError("chunked_body_truncated")
        body += chunk
        rfile.read(2)  # 块尾 CRLF
    return body


# ===== 透传模式的占位符还原（stop_mode=passthrough 的体验闭环）=====
# 背景：脱敏管线（mitmdump）停掉后，客户端对话历史里的占位符随请求原样上行
# （这是特性：上游本来看到的就是占位符），但模型回复里复述的占位符此前会
# 原样落到客户端——agent 拿占位符当真值执行命令直接失败，且无任何事件可归因。
#
# 数据源：事件库 MASK 事件的 items（与引擎侧 _warmup_recent_from_db 同款、同过滤）。
# 凭据类在库里只有 digest + preview、没有 original，天然不会被还原——
# 「凭据原文永不落盘」红线不动，凭据占位符在透传模式维持不还原（可见性靠
# PASS 事件里的 unresolved 计数）。
_PT_RESTORE_TTL = 60.0        # 映射缓存刷新周期：透传期间引擎仍在写 MASK 事件
_PT_RESTORE_MAX_EVENTS = 5000  # 与引擎侧 _WARMUP_MAX_EVENTS 对齐
_PT_RESTORE = {"map": {}, "loaded_at": 0.0, "lock": threading.Lock()}
# 只认严格形态：兜底路径不做标签改写容错（IP_PUBLIC/全小写等变体留给脱敏管线）
_PT_TOKEN_RX = re.compile(r"\{\{[A-Z0-9]{1,12}_[a-z0-9]{6}\}\}")
# 尾部疑似被 TCP 边界切开的半截占位符（"{{IPPR" / "{{IPPUBLIC_qz"）：
# 先扣住等下一块，流末（final=True）再处理
_PT_PARTIAL_RX = re.compile(r"\{\{[A-Za-z0-9_]{1,18}$")
# 缓冲硬顶：上游持续推送无帧边界的巨型数据时防无界累积，超限强制按 final 清空
_PT_BUF_MAX = 4 << 20


def _pt_should_restore(ct_lower, encoding):
    """PT 还原启用判据：JSON/SSE/NDJSON 且响应编码可还原。

    gzip/deflate 由调用方配 zlib 流式解压器后再进还原链路（请求侧已恢复
    透传 accept-encoding，不再强制全站非压缩）；brotli 等 stdlib 解不了的
    编码返回 False——压缩字节流不是 UTF-8 文本，errors="replace" 解码再
    回写会把整条响应损坏（脱敏路径 transparent 的 responseheaders 有同款守卫）。
    """
    if "json" not in ct_lower and "text/event-stream" not in ct_lower:
        return False
    enc = (encoding or "").lower().strip()
    return not enc or enc in ("identity", "gzip", "deflate")


def _pt_restore_map():
    """token -> original 映射（只读事件库，60s 缓存；失败返回旧值并留日志）。

    与引擎侧预热同款口径：48h 窗口、凭据类剔除、原文是占位符的剔除。
    事件按 id 倒序（最新在前），setdefault 保证同一 token 以最新事件为准。
    空映射同样吃满 60s 缓存：无 MASK 事件的实例若每次都查库，透传期间
    每请求一次 SELECT 纯属浪费（曾因条件写成 `_PT_RESTORE["map"] and ...`
    而空表永不缓存）。
    """
    with _PT_RESTORE["lock"]:
        now = time.time()
        if _PT_RESTORE["loaded_at"] and now - _PT_RESTORE["loaded_at"] < _PT_RESTORE_TTL:
            return _PT_RESTORE["map"]
        m = {}
        try:
            import sqlite3
            # 数据目录只认一处，不做候选回落：回落等于隔离环境读生产库
            env_dir = os.environ.get("LLM_SHIELD_DATA_DIR")
            if env_dir:
                db_path = os.path.join(env_dir, "shield-events.sqlite3")
            else:
                appdata = os.environ.get("APPDATA")
                db_path = (os.path.join(appdata, "Maskit", "shield-events.sqlite3")
                           if appdata else "shield-events.sqlite3")
            if os.path.isfile(db_path):
                cutoff = now - 48 * 3600
                # 注意：sqlite3 的 with 只管事务不关连接，Windows 下句柄不释放
                # 会锁住数据目录（隔离测试实例 cleanup 直接 PermissionError）。
                conn = sqlite3.connect(db_path, timeout=5)
                try:
                    rows = conn.execute(
                        "SELECT payload FROM events WHERE ts >= ? AND type = 'MASK' "
                        "ORDER BY id DESC LIMIT ?",
                        (cutoff, _PT_RESTORE_MAX_EVENTS),
                    ).fetchall()
                finally:
                    conn.close()
                for (payload_str,) in rows:
                    try:
                        p = json.loads(payload_str)
                        for it in p.get("items", []) or []:
                            tok = it.get("tok")
                            orig = it.get("original")
                            label = it.get("label") or ""
                            if not tok or not orig or not _PT_TOKEN_RX.fullmatch(tok):
                                continue
                            if label in CREDENTIAL_LABELS or _PT_TOKEN_RX.fullmatch(orig):
                                continue
                            m.setdefault(tok, orig)
                    except Exception:
                        pass
            # 成功才刷新缓存内容；失败保留旧映射。loaded_at 两种情况都刷新：
            # 失败若不刷新，DB 持续故障时每个透传请求都重查一次库 + 刷一条日志。
            _PT_RESTORE["map"] = m
            _PT_RESTORE["loaded_at"] = now
        except Exception as e:
            _PT_RESTORE["loaded_at"] = now
            _emit_log(f"[panel] 透传还原映射加载失败(继续用旧值): {e}")
        return _PT_RESTORE["map"]


def _pt_restore_text(text, rmap, stats):
    """占位符还原（尽力而为）：查不到的计入 unresolved 并原样放行。

    替换值按 JSON 字符串转义（json.dumps 去引号）：LLM 响应里占位符出现在
    JSON 字符串值内，原文含引号/换行时必须转义，否则客户端 JSON 解析直接
    报错。纯文本上下文里遇到含引号的原文会多出 \\\" —— 透传兜底可接受的
    残余风险（PII 原文极少含引号）。
    """
    def _sub(m):
        tok = m.group(0)
        orig = rmap.get(tok)
        if orig is None:
            stats.setdefault("unresolved", set()).add(tok)
            return tok
        stats["restored"] = stats.get("restored", 0) + 1
        return json.dumps(orig, ensure_ascii=False)[1:-1]
    return _PT_TOKEN_RX.sub(_sub, text)


def _pt_restore_frames(buf, delim, rmap, stats, final):
    """按帧边界（delim，如 "\\n\\n"/"\\n"）还原 buf 中的完整帧，返回 (输出, 剩余缓冲)。

    delim=None（整包 JSON）：无帧边界可依，靠尾部「疑似半截占位符」扣留
    （_PT_PARTIAL_RX）保证跨 64KB read1 边界切开的占位符等到下一块再还原——
    曾整段直接吐出，占位符跨读边界时既不还原也不计 unresolved。
    剩余缓冲只在非 final 时保留，流末（final=True）全量处理。
    """
    if delim is None:
        if final:
            return _pt_restore_text(buf, rmap, stats), ""
        m = _PT_PARTIAL_RX.search(buf)
        if m:
            return _pt_restore_text(buf[: m.start()], rmap, stats), buf[m.start():]
        return _pt_restore_text(buf, rmap, stats), ""
    out = []
    while True:
        idx = buf.find(delim)
        if idx < 0:
            break
        frame, buf = buf[:idx], buf[idx + len(delim):]
        # 分隔符必须随帧回填，否则 SSE 事件边界（\n\n）被吞、相邻事件粘连
        out.append(_pt_restore_text(frame, rmap, stats) + delim)
    if final:
        if buf:
            out.append(_pt_restore_text(buf, rmap, stats))
        return "".join(out), ""
    # 尾部疑似半截占位符：扣住等下一块，其余照常下发
    m = _PT_PARTIAL_RX.search(buf)
    if m:
        out.append(buf[: m.start()])
        return "".join(out), buf[m.start():]
    return "".join(out), buf


def _pt_restore_chunk(state, data, rmap, stats, final):
    """PT 流式回调的增量入口：state 是调用方持有的 {decoder, buf, delim}。"""
    text = state["decoder"].decode(data, final=final)
    state["buf"] += text
    if state["delim"] == "\n\n":
        # SSE 允许 CRLF；统一成 LF 再切帧（与脱敏管线同款归一化）
        state["buf"] = state["buf"].replace("\r\n", "\n")
    if len(state["buf"]) > _PT_BUF_MAX:
        # 无帧边界的巨型数据：强制按 final 清空，防止缓冲无界增长
        out, state["buf"] = _pt_restore_frames(state["buf"], state["delim"], rmap, stats, True)
        return out
    out, state["buf"] = _pt_restore_frames(state["buf"], state["delim"], rmap, stats, final)
    return out


# PT 上游空闲读超时（秒）：socket timeout 是「单次 recv 的上限」而非总时长，
# 900s 意味着上游静默挂死时客户端要干等 15 分钟才拿 502。SSE 正常事件间隔是
# 秒级，300s 静默基本等于挂死；真有超长思考的模型用户可在上游侧配心跳。
_PT_UPSTREAM_TIMEOUT = 300


def _pt_connect_via_proxy(proxy_host, proxy_port, proxy_is_tls, host, port, timeout, target_tls):
    """经出口代理建到目标 host:port 的连接（CONNECT 隧道）。

    http 代理：http.client 自带 set_tunnel 即可；https 代理（与代理本身先 TLS
    握手再发 CONNECT）http.client 不支持双层 TLS，必须手工编排 socket：
    TCP 连代理 → TLS(代理) → 发 CONNECT → 读 2xx → 目标是 https 再套一层 TLS。
    此前 https:// 出口代理被当明文 TCP 对待，代理期待 TLS 握手却收到明文
    CONNECT，必握手失败（与 mitmproxy via 行为分叉，审计 P1）。
    返回已就绪的 http.client 连接（sock 已注入）；CONNECT 被拒抛 OSError。
    """
    if not proxy_is_tls:
        # https 目标必须用 HTTPSConnection：connect() 在 _tunnel() 后对目标
        # wrap TLS（SNI=目标）；HTTPConnection 的隧道内是明文 HTTP，https 上游
        # 期待 TLS 握手却收到明文，全部请求失败（复审 #1——此前回归于此）
        conn_cls = http.client.HTTPSConnection if target_tls else http.client.HTTPConnection
        conn = conn_cls(proxy_host, proxy_port, timeout=timeout)
        conn.set_tunnel(host, port)
        return conn
    import socket as _socket
    import ssl as _ssl
    raw = _socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT).wrap_socket(raw, server_hostname=proxy_host)  # 与代理本身的 TLS 层
    try:
        sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("ascii"))
        # 响应行 + 头部读完为止（只要状态行就够判断，头部按行吃到空行丢弃）
        status_line = b""
        while b"\r\n" not in status_line:
            b_ = sock.recv(1)
            if not b_:
                raise OSError("egress proxy closed connection during CONNECT")
            status_line += b_
        try:
            status_code = int(status_line.split()[1])
        except (IndexError, ValueError):
            status_code = 0
        if status_code < 200 or status_code >= 300:
            raise OSError(f"egress proxy CONNECT rejected: {status_line.decode('latin-1', 'replace').strip()}")
        while True:  # 吃掉剩余响应头直到空行
            line = b""
            while b"\r\n" not in line:
                b_ = sock.recv(1)
                if not b_:
                    break
                line += b_
            if line in (b"\r\n", b"\n", b""):
                break
        if target_tls:
            sock = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT).wrap_socket(sock, server_hostname=host)  # 隧道内目标 TLS 层
        # 连接类按目标协议选（wrap 后的 sock 是 TLS/明文都与目标匹配）；
        # 必须补 set_tunnel：sock 已注入时 connect() 被跳过、不会重发 CONNECT，
        # 但 putrequest 生成 Host 头读的是 _tunnel_host——漏了它目标会收到
        # 「Host: 代理地址」，按 Host 路由的 CDN（Cloudflare 等）直接 403/421
        conn_cls = http.client.HTTPSConnection if target_tls else http.client.HTTPConnection
        conn = conn_cls(proxy_host, proxy_port, timeout=timeout)
        conn.set_tunnel(host, port)
        conn.sock = sock  # 注入手工建好的连接，后续 request() 直接复用
        return conn
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def _make_passthrough_handler(target, proxy_url=None, upstream_name=None):
    parsed = urlparse(target)
    use_https = parsed.scheme == "https"
    host = parsed.hostname
    port = parsed.port or (443 if use_https else 80)
    path_prefix = parsed.path.rstrip("/")
    target_query = parsed.query or ""

    proxy_parsed = urlparse(proxy_url) if proxy_url else None
    proxy_host = proxy_parsed.hostname if proxy_parsed else None
    proxy_port = proxy_parsed.port or (443 if proxy_parsed.scheme == "https" else 80) if proxy_parsed else None
    # 事件库里的 upstream 会出现在日志/诊断导出；不要把配置 URL 的 userinfo/query
    # 当作展示值写进去（实际连接仍使用上面的 parsed target）。
    up_val = _safe_upstream_display(upstream_name) or _safe_target(target)

    class PT(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # socket 读超时：半开连接（断电/无 FIN）会永久阻塞 handler 线程，
        # ThreadingHTTPServer 线程按连接无上限 → 线程/内存缓慢泄漏（审计 P2）。
        timeout = 300
        # 小块 SSE 立刻下发：Nagle 攒包会把首字节延迟放大几十毫秒
        disable_nagle_algorithm = True

        def log_message(self, *a):
            pass

        def _drain_request_body(self, max_bytes=1 << 20):
            """回错误前尽量读掉请求体：Windows 上关闭带未读数据的 socket 发 RST，
            客户端可能看不到 413/503 响应而是连接重置（注释里描述过的老坑）。"""
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                return
            remaining = min(length, max_bytes)
            try:
                while remaining > 0:
                    got = self.rfile.read(min(remaining, 65536))
                    if not got:
                        break
                    remaining -= len(got)
            except Exception:
                pass

        def _do_forward(self, head=False):
            _fwd_t0 = time.perf_counter()
            _first_byte_ms = None
            headers_sent = False  # mid-stream 失败时禁止再 send_error（会叠状态行损坏响应）
            # Content-Length 缺失/畸形/为 0（GET、无 body POST）→ 空 body；
            # chunked 请求手动解码后按完整 body 转发（http.client 不支持直接透传 chunk 帧）
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (ValueError, TypeError):
                length = -1
            # 请求体上限：防声明超大正文占满线程/内存（审计性能观察项）
            if length > _MAX_PASSTHROUGH_BODY:
                self._drain_request_body()
                self.send_error(413, "Request body too large")
                return
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                try:
                    body = _read_chunked_body(self.rfile)
                    if len(body) > _MAX_PASSTHROUGH_BODY:
                        self._drain_request_body()
                        self.send_error(413, "Request body too large")
                        return
                    length = len(body)
                except Exception:
                    self.send_error(400)
                    return
            elif length <= 0:
                body = b""
            else:
                body = self.rfile.read(length)

            # 尝试从请求体提取模型名与流式标识（与透明代理 MASK/RESTORE 保持一致）
            req_model = ""
            req_stream = None
            if body:
                try:
                    b_json = json.loads(body.decode("utf-8", errors="ignore"))
                    if isinstance(b_json, dict):
                        req_model = str(b_json.get("model") or "")[:120]
                        if "stream" in b_json:
                            req_stream = "stream" if b_json["stream"] is True else "non_stream"
                except Exception:
                    pass

            client_host = self.client_address[0] if self.client_address else ""
            client_port = self.client_address[1] if self.client_address and len(self.client_address) > 1 else None
            client_str = f"{client_host}:{client_port}" if client_host and client_port else client_host

            # 原样转发客户端头，UA 必须保留（Cloudflare 会按 UA 拦 Python-urllib）。
            # 同名多值头不再互相覆盖：dict 只留最后一个会丢多值语义（mitmproxy
            # 模式保留多值，兜底层丢，两模式行为分叉）。HTTP/1.1 头语义下 ", "
            # 合并等价于逐条发送；Cookie 例外——RFC 6265 的分隔符是 "; "，
            # 用 ", " 合并会让上游把 'sid=1,' 当畸形 cookie，会话静默失效。
            headers = {}
            for k, v in self.headers.items():
                lk = k.lower()
                if lk in ("host", "content-length", "transfer-encoding", "connection", "proxy-connection"):
                    continue
                if k in headers:
                    headers[k] = headers[k] + ("; " if lk == "cookie" else ", ") + v
                else:
                    headers[k] = v
            headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            # 还原映射非空时把 accept-encoding 限定到可解编码（gzip/deflate/identity）：
            # 上游若选 br/zstd，压缩字节流 stdlib 解不了，占位符会原样透传给用户
            # 且无任何事件留痕，换回 gzip 又正常——完全无法归因。透传期无还原
            # 期望（映射为空）时不改写，保留完整压缩协商。
            try:
                _may_restore = bool(_pt_restore_map())
            except Exception:
                _may_restore = False
            if _may_restore:
                _ae_key = next((k for k in headers if k.lower() == "accept-encoding"), None)
                if _ae_key:
                    _tokens = [t.strip() for t in headers[_ae_key].split(",") if t.strip()]
                    _ok = ("gzip", "deflate", "identity", "x-gzip")
                    if any(t.split(";")[0].strip() not in _ok for t in _tokens):
                        headers[_ae_key] = "gzip, deflate"
            try:
                if proxy_host and proxy_port:
                    # 走出口代理 CONNECT 隧道（境内中转直连，境外官方 API 走代理）；
                    # https 代理（与代理先 TLS）由 _pt_connect_via_proxy 手工编排
                    conn = _pt_connect_via_proxy(
                        proxy_host, proxy_port,
                        (proxy_parsed.scheme or "http").lower() == "https",
                        host, port, _PT_UPSTREAM_TIMEOUT, use_https)
                else:
                    conn = (http.client.HTTPSConnection(host, port, timeout=_PT_UPSTREAM_TIMEOUT)
                            if use_https else http.client.HTTPConnection(host, port, timeout=_PT_UPSTREAM_TIMEOUT))
            except Exception as e:
                # 建链失败（代理拒绝/不可达）：与转发失败同款 502 + ERR 落库
                try:
                    enqueue_event({
                        "ts": time.time(), "type": "ERR", "host": host, "method": self.command,
                        "path": self.path.split("?")[0], "status": 502, "http_status": 502,
                        "upstream": up_val, "model": req_model or None,
                        "client": client_str, "client_host": client_host, "client_port": client_port,
                        "msg": f"passthrough-connect: {type(e).__name__}: {_safe_public_text(e, 120)}",
                        "upstream_ms": round((time.perf_counter() - _fwd_t0) * 1000, 1),
                        "passthrough": True,
                    })
                except Exception:
                    pass
                # 此处不得 _drain_request_body()：请求体在上方已全量读入内存，
                # rfile 已排空，再按 Content-Length 读会阻塞到 socket 超时
                # （300s）——代理宕机期间每个带 body 的 POST 都白等 5 分钟
                try:
                    self.send_error(502, "透传连接失败，请查看面板日志")
                except Exception:
                    pass
                return
            try:
                # 合并 Target 与客户端请求的 Query 参数，绝不丢失 api-version 等必要参数
                if "?" in self.path:
                    client_pure, client_q = self.path.split("?", 1)
                else:
                    client_pure, client_q = self.path, ""
                merged_path = (path_prefix + client_pure) if path_prefix else client_pure
                queries = [q for q in (target_query, client_q) if q]
                upstream_path = merged_path + ("?" + "&".join(queries) if queries else "")
                conn.request(self.command, upstream_path, body=body, headers=headers)
                resp = conn.getresponse()
                ct_lower = (resp.getheader("Content-Type") or "").lower()
                # 占位符还原（透传体验闭环）：JSON / SSE / NDJSON 且映射非空时启用。
                # 失败兜底：还原链路任何异常都退回原样透传，绝不搞断连接。
                # gzip/deflate 由下面的解压器处理（请求侧已恢复透传 accept-encoding，
                # 不再为了还原把全站响应都打成非压缩——大响应透传变慢，审计 P2）。
                # 解压器只在还原激活（映射非空）时创建：纯解压透传没有任何收益，
                # 却强制剥 Content-Length 改 EOF 定界，把 keep-alive 也一起打断。
                resp_encoding = (resp.getheader("Content-Encoding") or "").lower().strip()
                rmap = _pt_restore_map() if _pt_should_restore(ct_lower, resp_encoding) else {}
                gzip_decomp = None
                if rmap and resp_encoding in ("gzip", "deflate"):
                    gzip_decomp = (zlib.decompressobj(16 + zlib.MAX_WBITS)
                                   if resp_encoding == "gzip"
                                   else zlib.decompressobj())
                pt_state = None
                pt_stats = {}
                if rmap:
                    if "text/event-stream" in ct_lower:
                        _delim = "\n\n"  # SSE 事件以空行分隔
                    elif any(t in ct_lower for t in ("x-ndjson", "ndjson", "jsonl", "jsonlines")):
                        _delim = "\n"    # NDJSON 一行一帧
                    else:
                        _delim = None    # 整包 JSON：无帧边界，靠半截占位符扣留
                    pt_state = {
                        "decoder": codecs.getincrementaldecoder("utf-8")(errors="replace"),
                        "buf": "", "delim": _delim,
                    }
                    pt_stats = {"restored": 0}
                self.send_response(resp.status)
                # 响应定界策略：上游给了 Content-Length（非流式）→ 原样保留，
                # 客户端可 keep-alive 复用连接；SSE/chunked/无长度 → 剥 TE 头 +
                # Connection: close 以 EOF 定界（http.client 已解 chunked 成纯 body）。
                is_streaming = resp.getheader("Transfer-Encoding", "").lower() == "chunked" or \
                    "text/event-stream" in ct_lower or \
                    not resp.getheader("Content-Length")
                if pt_state is not None or gzip_decomp is not None:
                    # 还原/解压会改变 body 字节与长度：必须剥原 Content-Length 改 EOF 定界
                    is_streaming = True
                for k, v in resp.getheaders():
                    lk = k.lower()
                    if lk == "transfer-encoding" or lk == "connection":
                        continue
                    if lk == "content-length" and is_streaming:
                        continue
                    if lk == "content-encoding" and gzip_decomp is not None:
                        continue  # 解压后不再是 gzip，转发该头会让客户端二次解压出错
                    self.send_header(k, v)
                # 客户端请求 Connection: close 时响应必须同款 close，否则客户端
                # 按头等 EOF 永远等不到（BaseHTTPRequestHandler 已解析进
                # self.close_connection，但响应头的 Connection 是这里手发的）。
                client_wants_close = bool(getattr(self, "close_connection", False))
                self.send_header("Connection",
                                 "close" if (is_streaming or client_wants_close) else "keep-alive")
                self.end_headers()
                headers_sent = True  # mid-stream 失败只能断流，不得再 send_error 叠加状态行
                # 流式逐块回传（SSE 兼容：不缓存整段）。
                # 必须用 read1()：read(n) 会攒满 n 字节才返回，LLM SSE 单事件只有
                # 几十~几百字节永远攒不满 64KB → 客户端等整个生成结束才见首字节
                # （实测 read=2.0s 一次性返回 vs read1=0s 逐块返回）。
                sent = 0
                chunks_read = 0
                usage_stream = (SSEUsageAccumulator()
                                if "text/event-stream" in ct_lower
                                else None)
                resp_tail_chunks = []
                tail_len = 0
                raw_deflate_tried = False  # deflate 有 zlib 包装/raw 两种流（HTTP 歧义）
                while True:
                    chunk = resp.read1(65536)
                    chunks_read += 1
                    if not chunk:
                        break
                    if _first_byte_ms is None:
                        _first_byte_ms = (time.perf_counter() - _fwd_t0) * 1000
                    if gzip_decomp is not None:
                        # gzip/deflate 增量解压：解出的明文进还原/下发链路。
                        # deflate 首块解压失败（zlib.error）时回退 raw 解压器重试
                        # 一次——IIS 等服务器常发非合规 raw deflate，硬抛会让
                        # 客户端收到 200 + 空 body 的静默损坏响应
                        raw_chunk = chunk
                        try:
                            chunk = gzip_decomp.decompress(raw_chunk)
                        except zlib.error:
                            if resp_encoding == "deflate" and not raw_deflate_tried:
                                raw_deflate_tried = True
                                gzip_decomp = zlib.decompressobj(-zlib.MAX_WBITS)
                                chunk = gzip_decomp.decompress(raw_chunk)
                            elif chunks_read == 1:
                                # 首块就解压失败 → 上游/反代谎报 Content-Encoding（正文其实是明文）：
                                # 响应头此刻已经发出、Content-Encoding 也已被剥，抛异常只会让客户端拿到
                                # 「200 + 静默截断的 body」。改为放弃解压与还原、把字节原样透传 —— 谎报
                                # 场景下正文本就是明文，原样下发正是客户端要的东西。非首块失败不在此列：
                                # 那是真压缩流中途损坏，只能按原逻辑断流。
                                gzip_decomp = None
                                pt_state = None
                                chunk = raw_chunk
                            else:
                                raise
                        if not chunk:
                            continue  # zlib 内部攒头部/字典时可能整块吃掉不出货
                    if pt_state is not None:
                        # 还原后可能为空串（帧不完整/半截占位符被扣留），跳过写入
                        try:
                            chunk = _pt_restore_chunk(pt_state, chunk, rmap, pt_stats, final=False).encode("utf-8")
                        except Exception:
                            # 还原失败退回原样透传：先吐出已扣住的缓冲（半截帧/占位符
                            # 残片，不吐就丢字），本块再原样下发；后续块不再尝试还原
                            held = (pt_state.get("buf") or "").encode("utf-8", errors="replace")
                            pt_state = None
                            if held:
                                sent += len(held)
                                self.wfile.write(held)
                                self.wfile.flush()
                    if not chunk:
                        continue
                    sent += len(chunk)
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    if usage_stream is not None:
                        # 用量逐行累计，避免长流把 message_start 的输入计数挤出尾部。
                        try:
                            usage_stream.feed(chunk)
                        except Exception:
                            pass  # 计费解析失败不影响原样转发
                    else:
                        # 非 SSE 响应仍只留存尾部，最大 64KB。
                        resp_tail_chunks.append(chunk)
                        tail_len += len(chunk)
                        while tail_len > 65536 and resp_tail_chunks:
                            tail_len -= len(resp_tail_chunks.pop(0))
                # 流末收尾：扣住的不完整帧 / 半截占位符全部按 final 吐出，
                # 否则客户端丢最后几个字（占位符永不闭合时原样放行并计入 unresolved）
                if pt_state is not None:
                    try:
                        tail = _pt_restore_chunk(pt_state, b"", rmap, pt_stats, final=True).encode("utf-8")
                    except Exception:
                        tail = b""
                    if tail:
                        sent += len(tail)
                        self.wfile.write(tail)
                        self.wfile.flush()
                        if usage_stream is None:
                            resp_tail_chunks.append(tail)
                            tail_len += len(tail)
                self.wfile.flush()
                # SSE 保留独立的累计用量；兼容末行没有换行的上游。
                resp_usage = usage_stream.usage if usage_stream is not None else {}
                try:
                    if usage_stream is not None:
                        resp_usage = usage_stream.feed(b"", final=True)
                    elif resp_tail_chunks:
                        tail_text = b"".join(resp_tail_chunks).decode("utf-8", errors="replace")
                        resp_usage = extract_usage(tail_text)
                except Exception:
                    pass
                # 透传期间记 PASS 事件：不脱敏时段的流量也要留痕
                # （此前透传完全不记日志，用户无法确认流量经过了自己）
                try:
                    ev = {
                        "ts": time.time(), "type": "PASS", "host": host, "method": self.command,
                        "path": self.path.split("?")[0], "status": resp.status,
                        "http_status": resp.status,
                        "bytes": sent, "passthrough": True, "upstream": up_val,
                        "model": req_model or None,
                        "stream_mode": req_stream,
                        "stream_actual": "stream" if is_streaming else ("whole" if req_stream == "stream" else None),
                        "usage": resp_usage or None,
                        "client": client_str,
                        "client_host": client_host,
                        "client_port": client_port,
                        # 透传耗时（毫秒）：upstream_ms=总耗时；first_byte_ms=首字节
                        "upstream_ms": round((time.perf_counter() - _fwd_t0) * 1000, 1),
                        "first_byte_ms": round(_first_byte_ms or 0, 1),
                    }
                    # 占位符还原计数（并入 PASS 而不是另发 RESTORE：usage 统计收
                    # RESTORE 与带 usage 的 PASS 各一次，两发会把 token 用量双计）。
                    # unresolved>0 时用户能从日志看出「回复里有占位符没还原」。
                    if pt_stats:
                        ev["restored"] = pt_stats.get("restored", 0)
                        ev["unresolved"] = len(pt_stats.get("unresolved") or ())
                    enqueue_event(ev)
                except Exception:
                    pass
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                # 客户端主动断连（如 Chat 生成中点停止），属正常取消，记 CANCEL 事件，不作为 ERR 告警
                try:
                    enqueue_event({
                        "ts": time.time(), "type": "CANCEL", "host": host, "method": self.command,
                        "path": self.path.split("?")[0], "status": 499, "http_status": 499,
                        "upstream": up_val, "model": req_model or None,
                        "client": client_str, "client_host": client_host, "client_port": client_port,
                        "msg": "客户端主动断连",
                        "upstream_ms": round((time.perf_counter() - _fwd_t0) * 1000, 1),
                        "passthrough": True,
                    })
                except Exception:
                    pass
            except Exception as e:
                # 透传失败记 ERR 事件（曾只发 502 不落库，面板「像没坏」无法排障）。
                # 只记元数据（host/耗时/异常类），不记 body/密钥。
                try:
                    enqueue_event({
                        "ts": time.time(), "type": "ERR", "host": host, "method": self.command,
                        "path": self.path.split("?")[0], "status": 502, "http_status": 502,
                        "upstream": up_val, "model": req_model or None,
                        "client": client_str, "client_host": client_host, "client_port": client_port,
                        "msg": f"passthrough: {type(e).__name__}: {_safe_public_text(e, 120)}",
                        "upstream_ms": round((time.perf_counter() - _fwd_t0) * 1000, 1),
                        "passthrough": True,
                    })
                except Exception:
                    pass
                # headers 已发出时（mid-stream 上游挂死/超时）只能断流：send_error 会
                # 往已发 200 头的流里再写一个 502 状态行，客户端看到的是损坏响应。
                # 必须显式置 close_connection：非流式路径已发 Connection: keep-alive，
                # 不置的话 handler 返回后还在等下一个请求，客户端却在等剩余 body，
                # 双方互等到客户端自身超时（表现为无限转圈而非快速失败）
                try:
                    if not headers_sent:
                        self.send_error(502, "透传转发失败，请查看面板日志")
                    else:
                        self.close_connection = True
                except Exception:
                    pass
            finally:
                conn.close()

        do_GET = _do_forward
        do_POST = _do_forward
        do_PUT = _do_forward
        do_PATCH = _do_forward
        do_DELETE = _do_forward
        # CORS 预检直接转发上游（此前落 BaseHTTPRequestHandler 默认 501，
        # 兜底模式反而制造新故障形态——浏览器客户端在兜底期间预检全挂）
        do_OPTIONS = _do_forward

        def do_HEAD(self):
            # 健康检查：响应头原样转发、不带 body（上游对 HEAD 本就不回 body，
            # read1 循环自然为空）；此前落默认 501，探活全部误报。
            self._do_forward(head=True)

    return PT


class _PassthroughHTTPServer(http.server.ThreadingHTTPServer):
    """透传 HTTP 服务：handler 线程设 daemon + 读超时，避免面板退出被挂起连接卡住。"""

    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # 客户端半途断开等错误不刷日志


# 透传层请求体上限（64MB，审计性能观察项）：超大正文会占满线程与内存
_MAX_PASSTHROUGH_BODY = 64 * 1024 * 1024


def _stop_mode():
    """代理不可用时的兜底形态。默认 passthrough。

    - passthrough（默认）：透传直连，不脱敏。可用性优先，软件运行未启动代理时
      也能正常转发，客户端请求不中断；启动代理后开启脱敏。
    - error：端口继续监听，任何请求立刻回 503 + shield_unavailable。
      既不明文外传（与 fail-closed 的安全初衷一致），又让客户端拿到明确错误。
    - block：端口完全不监听，客户端直接连不上。
    """
    try:
        mode = str(load_config().get("stop_mode") or "passthrough").strip().lower()
    except Exception:
        return "passthrough"
    return mode if mode in ("error", "passthrough", "block") else "passthrough"


def _passthrough_allowed():
    """是否允许明文透传兜底（仅 stop_mode=passthrough）。

    保留为独立判定：`_start_fallback` 之外，外部脚本/排障时判断「当前会不会明文
    直连」比读三态字符串直观。
    """
    return _stop_mode() == "passthrough"


# 503 兜底日志节流：客户端（IDE）通常会自动重试，不节流会瞬间刷爆事件库
_error_listener_log = {"ts": 0.0, "count": 0}


def _make_error_handler(upstream_name=None):
    """构造 503 占位 handler：端口有人监听，但明确告知 Shield 不可用。"""

    class ERR(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # 同 PT：半开连接不能永久占用 handler 线程（审计 P2）
        timeout = 300

        def log_message(self, *a):
            pass

        def _reject(self):
            # 必须读掉请求体：不读干净就回响应，客户端侧常表现为连接重置而非 503
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (ValueError, TypeError):
                length = 0
            body = b""
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                # chunked 请求体也要读干净（上限内），否则回 503 后未读数据
                # 触发 RST，客户端看到的是连接重置而不是错误信息
                try:
                    body = _read_chunked_body(self.rfile, limit=1 << 20)
                except Exception:
                    body = b""
            elif length > 0:
                try:
                    body = self.rfile.read(min(length, _MAX_PASSTHROUGH_BODY))
                except Exception:
                    pass
            req_model = ""
            if body:
                try:
                    b_json = json.loads(body.decode("utf-8", errors="ignore"))
                    if isinstance(b_json, dict):
                        req_model = str(b_json.get("model") or "")[:120]
                except Exception:
                    pass
            # OpenAI 兼容的错误结构：绝大多数客户端/SDK 会把 error.message 直接显示
            # 出来，用户一眼看到「Shield 没起来」，不必去猜是不是自己网络问题。
            payload = json.dumps({
                "error": {
                    "message": "Data Maskit 脱敏代理当前不可用，请求已被拦截，未发送到上游。"
                               "请打开 Data Maskit 面板查看状态并启动代理。",
                    "type": "shield_unavailable",
                    "code": "shield_unavailable",
                }
            }, ensure_ascii=False).encode("utf-8")
            try:
                self.send_response(503)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
            except Exception:
                return
            # 记 BLOCK 事件（fail-closed 阻断），30s 节流并带累计次数，
            # 避免 IDE 自动重试把事件库刷爆，同时不让用户以为「什么都没发生」
            now = time.time()
            _error_listener_log["count"] += 1
            if now - _error_listener_log["ts"] > 30:
                dropped = _error_listener_log["count"]
                _error_listener_log["ts"] = now
                _error_listener_log["count"] = 0
                client_host = self.client_address[0] if self.client_address else ""
                client_port = self.client_address[1] if self.client_address and len(self.client_address) > 1 else None
                client_str = f"{client_host}:{client_port}" if client_host and client_port else client_host
                try:
                    enqueue_event({
                        "ts": now, "type": "BLOCK",
                        "host": _safe_public_text(self.headers.get("Host", "") or "", 255),
                        "method": self.command, "path": self.path.split("?")[0],
                        "status": 503, "http_status": 503, "reason": "shield_unavailable",
                         "upstream": _safe_upstream_display(upstream_name),
                        "model": req_model or None,
                        "client": client_str,
                        "client_host": client_host,
                        "client_port": client_port,
                        "msg": f"代理未运行，已拒绝请求（近 30s 共 {dropped} 次）",
                    })
                except Exception:
                    pass

        do_GET = _reject
        do_POST = _reject
        do_PUT = _reject
        do_PATCH = _reject
        do_DELETE = _reject

    return ERR


def _start_error_listener():
    """启动 503 占位监听：每个 upstream 端口一个，保证端口始终有人应答。"""
    with _passthrough["lock"]:
        if _passthrough["servers"]:
            return 0
        started = 0
        for u in (load_config().get("upstreams") or []):
            port = int(u.get("port") or 0)
            name = str(u.get("name") or "").strip()
            target = str(u.get("target") or "").strip()
            if port <= 0 or port > 65535:
                continue
            try:
                srv = _PassthroughHTTPServer((LISTEN_HOST, port), _make_error_handler(upstream_name=name or target))
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                _passthrough["servers"][port] = srv
                started += 1
            except OSError as e:
                _emit_log(f"[panel] 503 占位端口 {port} 启动失败: {e}")
        _passthrough["mode"] = "error" if started else ""
        state["passthrough"] = False  # 503 占位不是透传，前端不能显示「明文直连」
        state["fallback_mode"] = "error" if started else ""
        if started:
            _emit_log(f"[panel] 已启动 503 占位监听 {started} 个端口"
                      f"（代理不可用，客户端会收到明确错误而非网络异常）")
        return started


def _start_fallback(reason=""):
    """代理不可用时的统一兜底入口，形态由 stop_mode 决定。

    所有「代理没起来/停了/崩了」的路径都必须走这里，不要各自散写
    `if _passthrough_allowed(): _start_passthrough()` —— 那样新增 error 模式时
    会漏掉分支，导致部分路径仍然端口无人监听（客户端看到的还是网络异常）。
    """
    mode = _stop_mode()
    try:
        if mode == "passthrough":
            return _start_passthrough()
        if mode == "error":
            return _start_error_listener()
    except Exception as e:
        _emit_log(f"[panel] 兜底监听启动失败({mode}) {reason}: {e}")
        return 0
    # block：端口完全不监听，客户端直接连不上
    state["fallback_mode"] = ""
    _emit_log(f"[panel] {reason}：stop_mode=block，端口已释放，客户端将断连")
    return 0


def _start_passthrough():
    """启动透传：为每个 upstream 端口起一个转发线程。已有则跳过。"""
    with _passthrough["lock"]:
        if _passthrough["servers"]:
            return 0
        cfg = load_config()
        egress = cfg.get("egress_proxy") or {}
        egress_url = egress.get("url") if egress.get("enabled") else ""
        started = 0
        for u in (cfg.get("upstreams") or []):
            port = int(u.get("port") or 0)
            target = str(u.get("target") or "").strip()
            name = str(u.get("name") or "").strip()
            if port <= 0 or port > 65535 or not target:
                continue
            use_proxy = bool(u.get("use_proxy")) and bool(egress_url)
            proxy_url = egress_url if use_proxy else None
            try:
                srv = _PassthroughHTTPServer((LISTEN_HOST, port), _make_passthrough_handler(target, proxy_url=proxy_url, upstream_name=name))
                t = threading.Thread(target=srv.serve_forever, daemon=True)
                srv._serve_thread = t
                t.start()
                _passthrough["servers"][port] = srv
                started += 1
            except OSError as e:
                _emit_log(f"[panel] 透传端口 {port} 启动失败: {e}")
        state["passthrough"] = bool(_passthrough["servers"])
        _passthrough["mode"] = "passthrough" if started else ""
        state["fallback_mode"] = "passthrough" if started else ""
        if started:
            _emit_log(f"[panel] 已启动透传（不脱敏直连）{started} 个端口，客户端可直接使用")
        return started


def _stop_passthrough():
    """停止全部兜底监听（透传或 503 占位），启动 mitmdump 前必须让出端口。

    先 shutdown() 让 serve_forever 循环退出（阻塞 ≤ poll_interval，默认 0.5s），
    再 server_close() 关 socket。
    注意：在后台线程中以有界超时执行 srv.shutdown()，若服务从未在独立线程运行
    （如单元测试 Mock 环境），避免直接调 shutdown() 触发 Python socketserver 标准库无界死锁。
    """
    with _passthrough["lock"]:
        for srv in _passthrough["servers"].values():
            try:
                t = threading.Thread(target=srv.shutdown, daemon=True)
                t.start()
                t.join(timeout=1.0)
            except Exception:
                pass
        for srv in _passthrough["servers"].values():
            try:
                srv.server_close()
            except Exception:
                pass
        _passthrough["servers"].clear()
        _passthrough["mode"] = ""
        state["passthrough"] = False
        state["fallback_mode"] = ""
    return True


# ========== 上游代理检测 ==========
def detect_upstream():
    old_upstream = os.environ.get("LLM_SHIELD_UPSTREAM", "").strip()
    if old_upstream and upstream_available(old_upstream):
        return old_upstream
    return ""


def upstream_available(upstream):
    try:
        parsed = urlparse(upstream)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return False
        if host in {"127.0.0.1", "localhost", "::1"}:
            return _port_listen(port)
        return True
    except Exception:
        return False


def parse_system_proxy(server):
    server = str(server or "").strip()
    if not server:
        return ""
    # IE 多协议格式：http=host;https=host;socks=host —— 取 http 段
    seg = ""
    for part in server.split(";"):
        if part.startswith("http="):
            seg = part[len("http="):]
            break
    if not seg:
        seg = server.split(";")[0]
    for pre in ("http://", "https://", "http=", "https="):
        if seg.startswith(pre):
            seg = seg[len(pre):]
    if not seg or seg.endswith(f":{PROXY_PORT}"):
        return ""
    return "http://" + seg


def _port_listen(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


# netstat 结果 3s TTL 缓存：api_status 被前端 2.5s 轮询高频调用，每次 spawn
# netstat 子进程实测中位数 ~54ms，常驻面板时持续消耗 CPU/句柄。
# 缓存「最近一次 netstat 解析出的全部监听端口 → PID 集合」，
# 调用方按各自 wanted 过滤后返回，端口集合不同也能复用同一份快照。
_netstat_cache = {"ts": 0.0, "data": {}}


def _posix_listening_port_pids(wanted):
    """读取 POSIX 监听 socket，并尽量映射到进程 PID。

    Docker 基础镜像通常没有 `netstat`/`ss`/`lsof`，仅用 TCP connect 探测虽然
    能知道端口存活，却无法清理崩溃残留。Linux 优先读 procfs（无额外依赖），
    macOS/无 procfs 环境再回退到 lsof/ss；映射失败时保留空 PID 集合，调用方
    仍可使用端口存在性，而不会误杀 PID 1 或其他进程。
    """
    wanted = {int(p) for p in wanted if int(p) > 0}
    found = {}
    socket_inodes = {}
    proc_net = Path("/proc/net")
    if proc_net.is_dir():
        for name in ("tcp", "tcp6"):
            path = proc_net / name
            try:
                rows = path.read_text(encoding="ascii", errors="ignore").splitlines()
            except Exception:
                continue
            for row in rows[1:]:
                parts = row.split()
                # local_address, state, inode are fields 1, 3, 9 in procfs.
                if len(parts) < 10 or parts[3].upper() != "0A":
                    continue
                try:
                    port = int(parts[1].rsplit(":", 1)[1], 16)
                    inode = parts[9]
                except (ValueError, IndexError):
                    continue
                if port in wanted and inode:
                    socket_inodes.setdefault(port, set()).add(inode)
        for port in socket_inodes:
            found[port] = set()
        if socket_inodes:
            proc_root = Path("/proc")
            try:
                proc_dirs = list(proc_root.iterdir())
            except Exception:
                proc_dirs = []
            inode_to_port = {
                inode: port for port, inodes in socket_inodes.items() for inode in inodes
            }
            for proc_dir in proc_dirs:
                if not proc_dir.name.isdigit():
                    continue
                try:
                    fds = (proc_dir / "fd").iterdir()
                    for fd in fds:
                        try:
                            link = os.readlink(fd)
                        except (FileNotFoundError, PermissionError, OSError):
                            continue
                        if not link.startswith("socket:[") or not link.endswith("]"):
                            continue
                        port = inode_to_port.get(link[8:-1])
                        if port is not None:
                            found.setdefault(port, set()).add(int(proc_dir.name))
                except (FileNotFoundError, PermissionError, NotADirectoryError, OSError):
                    continue
            return found

    # macOS and stripped-down containers: use available userland tools, always argv-list
    # invocation (no shell) so port values cannot become command syntax.
    for command in ("lsof", "ss"):
        for port in wanted:
            try:
                if command == "lsof":
                    _rc, out = _run_console(
                        ["lsof", "-nP", "-a", "-iTCP:" + str(port), "-sTCP:LISTEN", "-t"],
                        timeout=min(_CMD_TIMEOUT, 5),
                    )
                    pids = {int(x) for x in (out or "").split() if x.isdigit()}
                else:
                    _rc, out = _run_console(["ss", "-ltnpH"], timeout=min(_CMD_TIMEOUT, 5))
                    pids = set()
                    for line in (out or "").splitlines():
                        if not re.search(rf":{port}(?:\s|$)", line):
                            continue
                        pids.update(int(x) for x in re.findall(r"pid=(\d+)", line))
                # lsof exits 1/no output when the port is not listening; do not
                # turn that into a false-positive empty PID set.
                if pids:
                    found[port] = pids
            except (FileNotFoundError, OSError, ValueError):
                continue
        if command == "lsof" and found and len(found) == len(wanted):
            break
        if command == "ss" and found:
            break
    return found


def _harden_data_dir_acl():
    """收紧数据目录 ACL：仅当前用户 + SYSTEM + Administrators 可访问。"""
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return
    try:
        domain = os.environ.get("USERDOMAIN", "")
        user = os.environ.get("USERNAME", "")
        principal = f"{domain}\\{user}" if domain and user else user
        _rc, out = _run_console([
            "icacls", str(DATA_ROOT),
            "/inheritance:r",
            "/grant:r", f"{principal}:(OI)(CI)F",
            "SYSTEM:(OI)(CI)F",
            "Administrators:(OI)(CI)F",
        ], timeout=30)
        if _rc != 0:
            _emit_log(f"[panel] 数据目录 ACL 收紧失败: {(out or '').strip()[-200:]}")
            return
        # 显式移除剩余非目标主体（/inheritance:r 只清继承，清不掉显式授予）
        allowed_lower = {principal.lower(), "nt authority\\system",
                         "builtin\\administrators", "ownerrigh", "creatorown"}
        _rc2, out2 = _run_console(["icacls", str(DATA_ROOT)], timeout=30)
        for line in (out2 or "").splitlines():
            line = line.strip()
            # ACL 行格式：首行 `<路径> <SID>:(权限)`，后续行 `<SID>:(权限)`；
            # SID 可能含空格（NT AUTHORITY\SYSTEM）。用最后的 ":(" 定位 SID，
            # 避免路径盘符冒号/内部空格误拆。无 ":(" 的是说明行（已成功处理等）。
            if ":(" not in line:
                continue
            head = line[:line.index(":(")].strip()
            sid = head.split()[-1] if head else ""
            if not sid or "(I)" in line:  # 继承权限：第一步已清，残留跳过
                continue
            if sid.lower() in allowed_lower:
                continue
            # 非目标主体（Everyone/Users/沙箱 SID 等）：显式移除
            _run_console(["icacls", str(DATA_ROOT), "/remove:g", sid], timeout=30)
        _emit_log(f"[panel] 数据目录 ACL 已收紧（仅 {principal} + SYSTEM + Administrators）")
    except Exception as e:
        _emit_log(f"[panel] 数据目录 ACL 收紧异常: {_safe_public_text(e, 240)}")


def _listening_port_pids(ports, fresh=False):
    """一次 netstat 返回指定监听端口 -> PID，避免逐端口 0.3s 超时累加。

    结果 3s TTL 缓存（_netstat_cache）：api_status 轮询不必每次都起子进程。
    注意：netstat 原始行全量解析后缓存，再按 wanted 过滤返回。

    **启停路径必须传 fresh=True**（强制绕过并刷新缓存）。曾一律吃缓存：
    start_proxy 在 _stop_passthrough() 真实释放端口后立刻查占用，读到的却是 3s 内
    「透传/上一个 mitmdump 还在监听」的旧快照 → 误判「端口被非 mitmdump 进程占用，
    无法启动」；_free_upstream_ports() 也杀不掉（那 PID 就是面板自己，被 os.getpid()
    排除），sleep(0.3) 后复查仍在同一个缓存窗口内，于是必然启动失败。
    最稳定的踩法是「停止 → 立刻启动」：stop_proxy 杀完进程后自己查一次残留端口，
    正好把「mitmdump 还在监听」写进缓存，紧接着的 start_proxy 直接读到它。
    叠加 stop_mode 不兜底时全部 upstream 端口无人监听 → 客户端集体断网，
    正是「偶发性、软件启动了也不能正常转发」的主因（v1.5.61 修）。
    """
    wanted = {int(p) for p in ports if int(p) > 0}
    if not wanted:
        return {}
    now = time.time()
    if not fresh and now - _netstat_cache["ts"] < 3.0 and _netstat_cache["data"]:
        cached = _netstat_cache["data"]
        return {port: pids for port, pids in cached.items() if port in wanted}
    found = {}
    if sys.platform != "win32":
        found = _posix_listening_port_pids(wanted)
    else:
        try:
            _rc, out = _run_console(["netstat", "-ano", "-p", "tcp"], timeout=min(_CMD_TIMEOUT, 5))
        except Exception:
            out = ""
        if out:
            for line in out.splitlines():
                if "LISTENING" not in line.upper() and "LISTEN" not in line.upper():
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                try:
                    port = int(parts[1].rsplit(":", 1)[-1])
                    pid = int(parts[-1])
                except Exception:
                    continue
                if port in wanted:
                    found.setdefault(port, set()).add(pid)
    # POSIX 工具不可用时，连接探测只补充端口存在性，不伪造 PID（PID 1 可能被误杀）。
    if sys.platform != "win32":
        for p in wanted - set(found):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.05)
                    if s.connect_ex(("127.0.0.1", p)) == 0:
                        found[p] = set()
            except Exception:
                pass
    _netstat_cache["ts"] = now
    _netstat_cache["data"] = found
    return {port: pids for port, pids in found.items() if port in wanted}


def _expected_listen_ports(cfg=None, capture_mode=None):
    """代理正常运行时应当处于监听状态的端口。

    reverse：每个 upstream 各一个端口，**全部**都必须就绪 —— 缺一个，那条
    upstream 的客户端就连不上，而进程还活着、面板照样显示「运行中」。
    其余模式：单个 PROXY_PORT（与历史就绪判定保持一致，不改行为）。
    注意 local 模式由 WinDivert 透明捕获，端口语义不同，调用方（watchdog）
    需自行跳过端口校验，避免误判成故障反复重启。
    """
    try:
        cfg = load_config() if cfg is None else cfg
        mode = capture_mode or cfg.get("capture_mode", "reverse")
        if mode == "reverse":
            return sorted({
                int(u.get("port") or 0) for u in (cfg.get("upstreams") or [])
                if 0 < int(u.get("port") or 0) <= 65535
            })
        return [PROXY_PORT]
    except Exception:
        return [PROXY_PORT]


def _process_exists(pid):
    try:
        pid = int(pid)
    except Exception:
        return False
    if pid <= 0:
        return False
    if sys.platform != "win32":
        # POSIX 没有 tasklist/Win32 API；kill(pid, 0) 只探测存在性，不发送信号。
        # 权限不足同样说明进程存在。Linux zombie 已不再提供可用代理进程，视为不存在。
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        try:
            stat = (Path("/proc") / str(pid) / "stat").read_text(
                encoding="ascii", errors="ignore"
            )
            # comm 字段可含空格/括号，状态字段在最后一个 ')' 后的第一个字符。
            state_field = stat.rsplit(")", 1)[-1].strip()
            if state_field.startswith("Z"):
                return False
        except (FileNotFoundError, PermissionError, OSError):
            pass
        return True
    # 校验可执行名，防 PID 复用误判（PID 已回收给别的进程时旧 PID 会被误认为"还在运行"）
    try:
        _rc, out = _run_console(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"])
        return bool(out.strip())
    except Exception:
        pass
    try:
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
    except Exception:
        pass
    return False


def _taskkill_pid(pid):
    try:
        pid = int(pid)
    except Exception:
        return False, "invalid pid"
    if pid <= 0 or pid == os.getpid():
        return False, "refusing to kill current/invalid pid"
    if sys.platform != "win32":
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return False, "process not found"
        except PermissionError:
            return False, "permission denied"
        except OSError as e:
            return False, f"terminate failed: {_safe_public_text(e, 160)}"
        # 给 mitmdump 一个短暂的优雅退出窗口；卡死时升级 SIGKILL，避免端口长期占用。
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if not _process_exists(pid):
                return True, "terminated"
            time.sleep(0.05)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return True, "terminated"
        except PermissionError:
            return False, "permission denied"
        except OSError as e:
            return False, f"kill failed: {_safe_public_text(e, 160)}"
        return (not _process_exists(pid)), "killed"
    try:
        _rc, out = _run_console(["taskkill", "/PID", str(pid), "/T", "/F"])
    except Exception as e:
        return False, f"taskkill 超时或失败: {_safe_public_text(e, 260)}"[-300:]
    return _rc == 0, out.strip()[-300:]


def _read_pid_file():
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _read_process_cmdline(pid):
    """读取进程命令行，供跨平台身份校验使用；失败返回空串。"""
    try:
        pid = int(pid)
    except Exception:
        return ""
    if pid <= 0:
        return ""
    if sys.platform == "win32":
        try:
            _rc, out = _run_console(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"],
                timeout=min(_CMD_TIMEOUT, 8),
            )
            return out or ""
        except Exception:
            return ""
    proc_cmdline = Path("/proc") / str(pid) / "cmdline"
    try:
        raw = proc_cmdline.read_bytes()
        if raw:
            return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except (FileNotFoundError, PermissionError, OSError):
        pass
    # macOS 没有 procfs；ps 是系统自带且使用 argv 列表，不经过 shell。
    try:
        _rc, out = _run_console(["ps", "-p", str(pid), "-o", "command="], timeout=min(_CMD_TIMEOUT, 5))
        return out or ""
    except Exception:
        return ""


def _value_points_to_shield(value):
    text = str(value or "").lower()
    return re.search(
        rf"(?:127\.0\.0\.1|localhost|\[::1\]|::1):{PROXY_PORT}(?=$|[;/,\s])",
        text,
    ) is not None


def _system_proxy_points_to_shield():
    enabled_exists, enabled, _ = _read_system_proxy_value("ProxyEnable")
    server_exists, server, _ = _read_system_proxy_value("ProxyServer")
    return bool(enabled_exists and enabled and server_exists and _value_points_to_shield(server)), str(server or "")


def _user_env_points_to_shield():
    hits = []
    for name in CLIENT_ENV:
        exists, value = _read_user_env(name)
        if exists and _value_points_to_shield(value):
            hits.append(name)
    return hits


def health_check():
    p = proc["p"]
    tracked_pid = p.pid if p and p.poll() is None else None
    pid_file = _read_pid_file()
    system_proxy_shield, system_proxy_server = _system_proxy_points_to_shield()
    env_hits = _user_env_points_to_shield()
    port_5801 = _port_listen(PANEL_PORT)
    port_5802 = _port_listen(PROXY_PORT)
    stale_pid_file = bool(pid_file and not _process_exists(pid_file))
    cfg = load_config()
    # state["capture_mode"] 只在启停时写入，代理运行中可能还是 None（自启动路径下尤其明显），
    # 直接拿来比对会把 reverse 模式误判成需要 CA 证书 → 健康检查假报错。
    capture_mode = (state.get("capture_mode") if tracked_pid else None) or cfg.get("capture_mode", "reverse")
    issues = []
    if stale_pid_file:
        issues.append("stale_pid_file")
    if system_proxy_shield and not tracked_pid:
        issues.append("system_proxy_points_to_shield_without_proxy")
    if env_hits and not tracked_pid:
        issues.append("user_env_points_to_shield_without_proxy")
    if port_5802 and not tracked_pid:
        issues.append("untracked_5802_listener")
    if capture_mode != "reverse" and not CA_CERT.exists():
        issues.append("ca_cert_missing")
    if capture_mode == "local" and not is_admin():
        issues.append("local_mode_needs_admin")

    checks = [
        {
            "id": "panel_port",
            "label": "面板端口 5801",
            "ok": bool(port_5801),
            "detail": "监听中" if port_5801 else "未监听",
            "fixable": False,
        },
        {
            "id": "proxy_process",
            "label": "代理进程",
            "ok": bool(tracked_pid) or not PID_FILE.exists() or not stale_pid_file,
            "detail": f"PID {tracked_pid}" if tracked_pid else ("未运行" if not PID_FILE.exists() else "PID 文件残留"),
            "fixable": bool(stale_pid_file),
            "fix_action": "restore" if stale_pid_file else None,
        },
        {
            "id": "system_proxy",
            "label": "系统代理残留",
            "ok": not (system_proxy_shield and not tracked_pid),
            "detail": system_proxy_server or "未指向 Shield",
            "fixable": bool(system_proxy_shield and not tracked_pid),
            "fix_action": "restore",
        },
        {
            "id": "user_env",
            "label": "用户环境变量残留",
            "ok": not (env_hits and not tracked_pid),
            "detail": ("、".join(env_hits) if env_hits else "未指向 Shield"),
            "fixable": bool(env_hits and not tracked_pid),
            "fix_action": "restore",
        },
        {
            "id": "ca_cert",
            "label": "CA 证书",
            "ok": bool(CA_CERT.exists()) or capture_mode == "reverse",
            "detail": (
                "反向代理模式无需 CA"
                if capture_mode == "reverse"
                else ("已生成" if CA_CERT.exists() else "缺失（透明/显式模式需要）")
            ),
            "fixable": capture_mode != "reverse" and not CA_CERT.exists(),
            "fix_action": "cert",
        },
        {
            "id": "admin",
            "label": "管理员权限",
            "ok": is_admin() or capture_mode != "local",
            "detail": "是" if is_admin() else ("否（透明捕获需要）" if capture_mode == "local" else "否（当前模式不强制）"),
            "fixable": False,
        },
    ]
    # reverse 多端口监听概览。端口可用性单独返回，不计入“网络残留”健康结论：
    # 健康检查的 ok 主要回答是否需要恢复系统环境；端口未监听由 UI 提示重启。
    reverse_ports = []
    port_issues = []
    if capture_mode == "reverse":
        # 端口状态一次 netstat 快照。逐端口 _port_listen 是 0.3s 超时 × N 个 upstream
        # （9 个 ≈ 2.7s 阻塞），且裸 TCP 连接会刷爆 mitmdump 日志、掩盖崩溃现场。
        _ups = cfg.get("upstreams") or []
        # 健康检查是用户主动触发（且 recover_network 末尾复查），结论要用来决定
        # 是否重启/修复，必须实时快照，不能吃 3s 缓存。
        _live = _listening_port_pids({
            int(u.get("port") or 0) for u in _ups if 0 < int(u.get("port") or 0) <= 65535
        }, fresh=True)
        for u in _ups:
            port = int(u.get("port") or 0)
            listening = bool(port and port in _live)
            reverse_ports.append({
                "name": u.get("name"),
                "port": port,
                "listening": listening,
                "expected": bool(tracked_pid),
            })
            if tracked_pid and port and not listening:
                port_issues.append(f"upstream_port_down:{u.get('name')}:{port}")
                checks.append({
                    "id": f"port_{port}",
                    "label": f"客户端端口 {port}（{u.get('name')}）",
                    "ok": False,
                    "detail": "应监听但未监听，建议重启代理",
                    "fixable": True,
                    "fix_action": "restart",
                })
            elif port:
                checks.append({
                    "id": f"port_{port}",
                    "label": f"客户端端口 {port}（{u.get('name')}）",
                    "ok": (not tracked_pid) or listening,
                    "detail": "监听中" if listening else ("未启动" if not tracked_pid else "未监听"),
                    "fixable": bool(tracked_pid and not listening),
                    "fix_action": "restart" if tracked_pid and not listening else None,
                })

    # 去重 issues 但保持顺序
    seen = set()
    uniq_issues = []
    for x in issues:
        if x not in seen:
            seen.add(x)
            uniq_issues.append(x)

    return {
        "ok": not uniq_issues,
        "issues": uniq_issues,
        "port_issues": port_issues,
        "checks": checks,
        "admin": is_admin(),
        "panel_port_listening": port_5801,
        "proxy_port_listening": port_5802,
        "tracked_pid": tracked_pid,
        "pid_file": pid_file,
        "pid_file_exists": PID_FILE.exists(),
        "pid_file_process_alive": _process_exists(pid_file) if pid_file else False,
        "stale_pid_file": stale_pid_file,
        "env_backup_exists": ENV_BACKUP_PATH.exists(),
        "system_proxy_points_to_shield": system_proxy_shield,
        "system_proxy_server": system_proxy_server,
        "user_env_points_to_shield": env_hits,
        "ca_cert_exists": CA_CERT.exists(),
        "capture_mode": capture_mode,
        "reverse_ports": reverse_ports,        "proxy_running": bool(tracked_pid),
    }


def recover_network():
    steps = []
    pid_file = _read_pid_file()
    p = proc["p"]
    tracked_pid = p.pid if p else None

    ok, err = stop_proxy()
    steps.append({"name": "stop_tracked_proxy", "ok": ok, "detail": err or "ok"})

    if pid_file and pid_file == tracked_pid:
        steps.append({"name": "kill_pid_file_process", "ok": True, "detail": f"already stopped tracked proxy: {pid_file}"})
    elif pid_file and _process_exists(pid_file):
        killed, detail = _taskkill_pid(pid_file)
        steps.append({"name": "kill_pid_file_process", "ok": killed, "detail": detail or str(pid_file)})
    elif pid_file:
        steps.append({"name": "kill_pid_file_process", "ok": True, "detail": f"not running: {pid_file}"})
    try:
        PID_FILE.unlink(missing_ok=True)
        steps.append({"name": "remove_pid_file", "ok": True, "detail": "ok"})
    except Exception as e:
        steps.append({"name": "remove_pid_file", "ok": False, "detail": _safe_public_text(e, 240)})

    system_proxy_shield, server = _system_proxy_points_to_shield()
    if ENV_BACKUP_PATH.exists():
        restore_client_env()
        steps.append({"name": "restore_env_backup", "ok": True, "detail": "backup restored"})
    elif system_proxy_shield:
        try:
            _write_system_proxy_value("ProxyEnable", 0)
            _write_system_proxy_value("ProxyServer", None)
            _broadcast_proxy_change()
            steps.append({"name": "disable_shield_system_proxy", "ok": True, "detail": server})
        except Exception as e:
            steps.append({"name": "disable_shield_system_proxy", "ok": False, "detail": _safe_public_text(e, 240)})
    else:
        steps.append({"name": "system_proxy", "ok": True, "detail": "not pointing to Shield"})

    env_hits = _user_env_points_to_shield()
    for name in env_hits:
        try:
            _write_user_env(name, None)
            steps.append({"name": f"clear_user_env:{name}", "ok": True, "detail": "removed"})
        except Exception as e:
            steps.append({"name": f"clear_user_env:{name}", "ok": False, "detail": _safe_public_text(e, 240)})
    if env_hits:
        _broadcast_env_change()
    else:
        steps.append({"name": "user_env", "ok": True, "detail": "not pointing to Shield"})

    if is_admin():
        ok, err = hosts_restore()
        steps.append({"name": "hosts_marker_cleanup", "ok": ok, "detail": err or "ok"})
    else:
        steps.append({"name": "hosts_marker_cleanup", "ok": True, "detail": "skipped: not admin"})

    after = health_check()
    return {"ok": all(s["ok"] for s in steps) and after["ok"], "steps": steps, "health": after}


# ========== mitmdump 子进程 ==========
def _mitmdump_argv0():
    """代理子进程的命令前缀。

    打包态：用引擎自己的 exe + --mitmdump（见 engine_entry._run_as_mitmdump）。
    安装包里没有 mitmdump.exe，裸命令名只能在装了 mitmproxy 的开发机上解析成功；
    干净机器上代理永远起不来，且失败得很安静——端口仍被 503 兜底占着，
    用户看到的是「代理已启动但请求全 503」（SHIELD-NO-MITMDUMP-001）。

    源码态：保留系统 mitmdump，开发时不用先打包就能跑。
    """
    if getattr(sys, "frozen", False):
        return [sys.executable, "--mitmdump"]
    return ["mitmdump"]


def _child_env_for_mitmdump():
    """构造 mitmdump 子进程环境。

    打包态 PyInstaller 会把 _internal（含自带 pythonXYZ.dll）放进本进程的 DLL 搜索
    路径并写入 PATH。mitmdump.exe 是外部 Python 安装的独立解释器，若先搜到我们打包的
    python314.dll，就会加载错版本运行时，在 import _socket 时直接炸：
        ImportError: Module use of python314.dll conflicts with this version of Python
    （v1.5.44-46 用 Python 3.14 打包、系统 mitmdump 属 3.13 时实际发生，
    表现为「mitmdump 启动失败」且所有 187xx 端口无人监听。）

    因此必须从子进程 PATH 里剔除 bundle 目录，并清掉 PyInstaller 的运行时私有变量，
    让 mitmdump 用它自己那套解释器与 DLL。PYTHONPATH 仍需指向 _BUNDLE_ROOT，
    transparent.py 要从那里 import shield_defaults / event_store。
    """
    # 打包态已改成用引擎自身跑 mitmdump（见 _mitmdump_argv0），子进程要的正是
    # bundle 里那套解释器与 DLL——这时绝不能再剔除 bundle 目录，剔了就找不到运行时。
    # 下面那套清理只对源码态的外部 mitmdump.exe 有意义（它自带解释器，
    # 混进我们打包的 pythonXYZ.dll 会在 import _socket 时直接炸）。
    if getattr(sys, "frozen", False):
        return {
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "LLM_SHIELD_DATA_DIR": str(DATA_ROOT),
        }
    bundle_dirs = set()
    for d in (_BUNDLE_ROOT, getattr(sys, "_MEIPASS", None), Path(sys.executable).parent if getattr(sys, "frozen", False) else None):
        if d:
            bundle_dirs.add(str(Path(d)).rstrip("\\/").lower())
    clean_path = os.pathsep.join(
        seg for seg in (os.environ.get("PATH") or "").split(os.pathsep)
        if seg.strip() and seg.strip().rstrip("\\/").lower() not in bundle_dirs
    )
    env = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "LLM_SHIELD_DATA_DIR": str(DATA_ROOT),
        "PYTHONPATH": str(_BUNDLE_ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""),
        "PATH": clean_path,
    }
    # 这些是 PyInstaller 注入的运行时私有变量，传给子进程会让它误判自己也在 bundle 内
    for k in ("_MEIPASS", "_PYI_APPLICATION_HOME_DIR", "_PYI_ARCHIVE_FILE",
              "_PYI_PARENT_PROCESS_LEVEL", "PYTHONHOME"):
        env.pop(k, None)
    return env


def _spawn_mitmdump_sidecar(args):
    """启动一次短命 mitmdump sidecar（例如生成 CA），返回 Popen。

    必须复用 `_mitmdump_argv0()`：源码态使用 PATH 中的 mitmdump，打包态则
    让当前引擎 exe 进入 `--mitmdump` 分支；直接写裸命令会使干净安装包失效。
    """
    argv = _mitmdump_argv0() + list(args)
    kwargs = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "env": _child_env_for_mitmdump(),
    }
    if sys.platform == "win32":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if flags:
            kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(argv, **kwargs)


def _stop_sidecar_process(sidecar):
    """有界停止证书生成 sidecar，不影响面板正在跟踪的代理进程。"""
    if sidecar is None:
        return
    try:
        if sidecar.poll() is not None:
            return
    except Exception:
        return
    try:
        if sys.platform != "win32":
            pid = int(sidecar.pid)
            pgid = os.getpgid(pid)
            if pgid == pid and pgid != os.getpgrp():
                os.killpg(pgid, signal.SIGTERM)
            else:
                sidecar.terminate()
        else:
            _taskkill_pid(sidecar.pid)
    except Exception:
        try:
            sidecar.terminate()
        except Exception:
            pass
    try:
        sidecar.wait(timeout=3)
    except Exception:
        try:
            sidecar.kill()
        except Exception:
            pass


def _reader(stream):
    """读 mitmdump stdout 的线程。

    历史 bug：text 模式 + encoding=utf-8 下，上游响应里混入非法 UTF-8 字节
    （0xbb 等）时 _readerthread 的 read() 抛 UnicodeDecodeError，线程直接死亡，
    之后 mitmdump 的 SHIELD 事件行再也读不到 → 日志/事件静默丢失（用户看到
    「请求没记录」）。改为二进制读 + errors=replace 手动解码，永不崩。
    """
    try:
        while True:
            chunk = stream.readline()
            if not chunk:
                break
            try:
                _emit_log(chunk.decode("utf-8", errors="replace"))
            except Exception:
                pass
    except Exception:
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _start_proxy_locked():
    state["stop_requested"] = False
    state["generation"] = int(state.get("generation", 0)) + 1
    generation = state["generation"]
    state["last_error"] = ""
    cfg = load_config()
    capture_mode = cfg.get("capture_mode", "reverse")
    if capture_mode == "local" and not is_admin():
        return False, "本机透明捕获需要管理员权限，请以管理员身份重新启动 Maskit（或右键 → 以管理员身份运行）"
    if capture_mode == "explicit" and _port_listen(PROXY_PORT):
        return False, f"本地代理端口 {PROXY_PORT} 已被占用"
    if capture_mode != "reverse":
        domains = enabled_domains(cfg)
        if not domains:
            return False, "未配置启用的目标域名"
    use_h2 = "true" if cfg.get("http2", True) else "false"
    up = detect_upstream() if capture_mode == "explicit" else ""
    args = _mitmdump_argv0() + ["-s", str(_BUNDLE_ROOT / "transparent.py")]
    if capture_mode == "local":
        args += ["--mode", "local"]
        # local 模式不用 --allow-hosts：WinDivert 已拦截被捕获进程的所有流量，
        # --allow-hosts 会让非目标域名在 passthrough 重建连接时出现状态错位（issue #8270/#7023），
        # 改由 transparent.py 的 is_target() 在应用层过滤。
    elif capture_mode == "reverse":
        # 反向代理多端口模式：每个 upstream 一个本地端口（18700-18799 冷门段）。
        # 客户端 base_url 指向 http://127.0.0.1:<port>，无需装 CA，无需 header。
        # mitmproxy 单进程多 listen 端口：--mode regular@port 重复传入。
        ups = cfg.get("upstreams") or []
        if not ups:
            return False, "未配置反向代理 upstream"
        used_ports = set()
        configured_ports = {
            int(u.get("port") or 0) for u in ups
            if 0 < int(u.get("port") or 0) <= 65535
        }
        # 透传让位必须在端口占用检查之前：透传是面板自身进程监听的，
        # _free_upstream_ports 只杀 mitmdump（排除自身 PID），不先停透传
        # 端口永远"被占用"，启动必然失败（曾出现：停止代理后再启动报端口占用）。
        _stop_passthrough()
        # fresh=True：透传刚让出端口，必须实时快照，否则读到旧缓存误判占用
        if _listening_port_pids(configured_ports, fresh=True):
            _free_upstream_ports()
            time.sleep(0.3)
        occupied = _listening_port_pids(configured_ports, fresh=True)
        if occupied:
            _start_fallback("端口被占用")
            return False, f"端口 {sorted(occupied)[:3]} 被非 mitmdump 进程占用，无法启动"
        listen_h = LISTEN_HOST
        for u in ups:
            p = int(u.get("port") or 0)
            if p <= 0 or p > 65535:
                return False, f"upstream {u.get('name')} 端口非法: {p}"
            if p in used_ports:
                return False, f"upstream {u.get('name')} 端口重复: {p}"
            used_ports.add(p)
            args += ["--mode", f"regular@{listen_h}:{p}"]
    else:  # explicit
        listen_h = LISTEN_HOST
        args += [
            "--listen-host", listen_h,
            "-p", str(PROXY_PORT),
            "--mode", f"upstream:{up}" if up else "regular",
        ]
    args += [
        "--set", "flow_detail=0",
        "--set", "termlog_verbosity=warn",
        "--set", "connection_strategy=lazy",
        "--set", f"http2={use_h2}",
    ]
    # --allow-hosts 只在 explicit 模式限制 MITM 范围；reverse 由 addon 路由，local 不用。
    if capture_mode == "explicit":
        allow_hosts = _build_allow_hosts(enabled_domains(cfg))
        if allow_hosts:
            args += ["--allow-hosts", allow_hosts]
    # 透传让位：mitmdump 要占用 upstream 端口，先停掉面板的透传监听。
    # reverse 分支已在端口校验前停过（幂等），此处兜底 explicit/local 模式。
    # 失败路径统一在下方恢复透传，避免"启动失败 → 所有 187xx 端口无人监听"。
    _stop_passthrough()
    try:
        child_env = _child_env_for_mitmdump()
        extra_kwargs = {}
        if sys.platform == "win32":
            flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            if flags:
                extra_kwargs["creationflags"] = flags
        else:
            # POSIX sidecar 建立独立 session，停止时可连同其可能拉起的子进程一起回收。
            extra_kwargs["start_new_session"] = True
        # Python 3.13 下二进制模式（未启用 text=True）传 bufsize=1 会触发
        # RuntimeWarning: line buffering (buffering=1) isn't supported in binary mode。
        # 此处省略 bufsize（使用默认缓冲），_reader 依然通过 stream.readline() 按行流式读取。
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env=child_env,
                             **extra_kwargs)
    except FileNotFoundError:
        _start_fallback("mitmdump 未找到")
        return False, "mitmdump 未找到，请 pip install mitmproxy"
    # 就绪等待：原先固定 sleep(0.8) 只判进程死活，不判端口是否 listen。
    # mitmdump 要加载 transparent.py 并绑定全部 upstream 端口，冷启动实测
    # 常超过 1s；面板过早报「已启动」，客户端此刻连过去就是「网络连接异常」。
    # 必须等**全部**端口就绪：曾只探第一个（upstreams[0].port），其余端口绑定
    # 失败照样报「启动成功」→ 面板显示运行中、那些 upstream 的客户端却连不上，
    # 是「软件启动了也不能转发」的另一条路径。
    # 用 netstat 快照而非逐端口 _port_listen：后者会对已监听端口建立真实 TCP
    # 连接，刷爆 mitmdump 日志并掩盖崩溃现场（见 _listening_port_pids 注释）。
    expect_ports = _expected_listen_ports(cfg, capture_mode)
    ready_deadline = time.time() + _START_READY_TIMEOUT
    ready = False
    missing = list(expect_ports)
    while time.time() < ready_deadline:
        if p.poll() is not None:
            break
        live = _listening_port_pids(expect_ports, fresh=True)
        missing = [x for x in expect_ports if x not in live]
        if not missing:
            ready = True
            break
        time.sleep(0.15)
    if p.poll() is not None or not ready:
        if p.poll() is None:
            # 端口迟迟不 listen：进程还活着但不可用，先杀掉释放端口，避免占端口的僵尸
            _emit_log(f"[panel] mitmdump {_START_READY_TIMEOUT}s 内未监听端口 {missing}，判定启动失败")
            try:
                _kill_proxy_tree(p.pid)
            except Exception:
                pass
        out = ""
        try:
            # 进程终止后以有界超时安全读取输出，绝不裸调用可能对存活子进程无界阻塞的
            # p.stdout.read()（Issue #19：弱 CPU 冷启动超时时该调用会永久挂死面板线程）。
            if p.stdout:
                raw = p.stdout.read() if p.poll() is not None else p.communicate(timeout=1.5)[0]
                # Popen 未启用 text=True，读回的是 bytes；不解码会让错误提示渲染成 b'...'
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                out = (raw or "")[-500:]
        except Exception:
            pass
        _start_fallback("启动失败")
        reason = out.strip() or (f"{_START_READY_TIMEOUT}s 内未监听端口 {missing}"
                                 if not ready else "进程已退出")
        return False, f"mitmdump 启动失败: {reason}"
    proc["p"] = p
    try:
        PID_FILE.write_text(str(p.pid), encoding="utf-8")
    except Exception:
        pass
    state["proxy_running"] = True
    state["proxy_pid"] = p.pid
    state["upstream"] = up
    state["capture_mode"] = capture_mode
    state["started_at"] = time.time()
    state["last_restart_ok_ts"] = time.time()  # watchdog 用：稳定运行 60s 后重置连续崩溃计数
    # 手动/自动启动成功都清失败告警；auto_recovered_at 由 watchdog/
    # _restart_proxy_locked 在自动恢复成功时单独设置，手动启动不显示恢复提示。
    state["auto_recover_fail"] = ""
    state["auto_recovered_at"] = None
    threading.Thread(target=_reader, args=(p.stdout,), daemon=True).start()
    threading.Thread(target=_watchdog, args=(generation,), daemon=True).start()
    if capture_mode == "local":
        _emit_log(f"[panel] 启动本机透明捕获 pid={p.pid} mode=local")
    elif capture_mode == "reverse":
        _emit_log(f"[panel] 启动反向代理 pid={p.pid} listen={LISTEN_HOST} upstreams={len(cfg.get('upstreams') or [])}")
    else:
        _emit_log(f"[panel] 启动显式代理 pid={p.pid} listen={LISTEN_HOST}:{PROXY_PORT} upstream={_safe_target(up) if up else 'direct'}")
    return True, None


def start_proxy():
    with lock:
        if proc["p"] and proc["p"].poll() is None:
            return False, "已在运行"
        state["proxy_starting"] = True
        try:
            return _start_proxy_locked()
        finally:
            state["proxy_starting"] = False


def _kill_proxy_tree(pid):
    """停止 mitmdump 及其子进程，Windows/POSIX 均不留下占端口的孤儿。"""
    if not pid:
        return
    try:
        pid = int(pid)
    except Exception:
        return
    p = proc.get("p")
    if sys.platform == "win32":
        # taskkill /T /F 会递归处理 mitmdump 拉起的 python 子进程。
        try:
            _taskkill_pid(pid)
        except Exception:
            pass
        # 兜底：再 terminate/kill 一次
        try:
            if p and p.pid == pid and p.poll() is None:
                p.kill()
        except Exception:
            pass
        return

    # POSIX：启动时使用 start_new_session=True，优先终止独立进程组；
    # 不满足该条件时只杀明确跟踪的 Popen 对象/单个 PID，避免误伤宿主进程组。
    group_killed = False
    try:
        pgid = os.getpgid(pid)
        own_pgid = os.getpgrp()
        if pgid == pid and pgid != own_pgid:
            os.killpg(pgid, signal.SIGTERM)
            group_killed = True
    except (ProcessLookupError, PermissionError, OSError):
        pass
    if not group_killed:
        try:
            if p and getattr(p, "pid", None) == pid and p.poll() is None:
                p.terminate()
            else:
                _taskkill_pid(pid)
        except Exception:
            pass
    # 给优雅退出留短窗口，随后对仍存活的已跟踪进程升级 kill。
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            alive = p is not None and getattr(p, "pid", None) == pid and p.poll() is None
            if not alive and not _process_exists(pid):
                break
        except Exception:
            break
        time.sleep(0.05)
    try:
        if p and getattr(p, "pid", None) == pid and p.poll() is None:
            p.kill()
        elif _process_exists(pid) and group_killed:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _is_mitmdump_pid(pid):
    """确认 PID 是自己的 mitmdump 进程（按可执行名 + 命令行校验），防止误杀第三方进程。"""
    try:
        pid = int(pid)
    except Exception:
        return False
    if pid <= 0 or pid == os.getpid():
        return False
    if sys.platform != "win32":
        low = _read_process_cmdline(pid).lower()
        return any(mark in low for mark in ("mitmdump", "mitmproxy.tools", "transparent.py"))
    try:
        _rc, out = _run_console(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"])
    except Exception:
        return False
    name = ""
    try:
        name = out.splitlines()[0].split(",")[1].strip('"') if out.strip() else ""
    except Exception:
        return False
    if "mitmdump" in name.lower():
        return True
    # tasklist 只给可执行名，而 mitmdump 会再拉 python.exe 子进程持有端口
    # （见 _kill_proxy_tree），必须查命令行才能认出来。
    # 原用 `wmic process ...`：Windows 11 24H2 起系统已默认移除 WMIC（本机
    # `where wmic` 实测找不到），该分支恒抛异常返回 False → python.exe 子进程
    # 永远不被识别 → _free_upstream_ports() 释放不掉端口 → 下次启动直接报
    # 「端口被非 mitmdump 进程占用，无法启动」。改用 CIM（PowerShell 内置，
    # 无外部依赖）。pid 已 int() 过，无注入面。
    try:
        _rc, out2 = _run_console(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"],
            timeout=min(_CMD_TIMEOUT, 8))
    except Exception:
        return False
    low = (out2 or "").lower()
    # 认两类：mitmdump 本体，以及 mitmdump 拉起、加载了本项目 addon 的 python 子进程。
    # 只匹配 "mitmdump" 会漏掉后者（它的命令行里只有 transparent.py）。
    return "mitmdump" in low or "transparent.py" in low


def _db_size_mib():
    """事件库文件大小（MiB），失败返回 0（仅展示用，不抛）。"""
    try:
        return os.path.getsize(DB_PATH) / (1024 * 1024)
    except Exception:
        return 0.0


# 「本产品引擎进程」的命令行特征：入口脚本名（源码态）+ 打包后的可执行文件名
# （与 src-tauri/src/lib.rs 的 ENGINE_NAMES 保持一致）。全部小写，比对前统一 lower()。
# 刻意**不含**裸产品名 "maskit" / "llmshield"：子串匹配会把「在仓库目录下跑起来、
# 又恰好占用 18701-18719 或某个 upstream 端口」的无关进程误判成本产品面板，进而
# taskkill /T /F 连子孙进程一起杀掉（数据丢失风险，审计 P1）。
_SHIELD_ENGINE_CMDLINE_MARKERS = (
    "panel.py",
    "engine_entry.py",
    "maskitengine",      # MaskitEngine.exe（打包态，新名）
    "llmshieldengine",   # LLMShieldEngine.exe（更名前；新旧版本可能共存于同一台机器）
)


def _is_shield_panel_pid(pid):
    """识别「另一个本产品面板」进程（源码 panel.py 或打包 MaskitEngine.exe）。

    面板自身会起 503 占位/透传监听器占住上游端口（_start_fallback），它不是
    mitmdump 进程，_is_mitmdump_pid 认不出来 → 换实例/重启时端口永远「被非
    mitmdump 进程占用」→ 自动重启失败（实测空窗 29 分钟，只能手动断开再启用）。
    特征：CommandLine 含 panel.py 或产品名；mitmdump 类进程由 _is_mitmdump_pid
    管，这里明确排除避免重复识别。调用方必须已确认该进程占用上游端口。

    产品名要同时认新旧两套（maskit / llmshield）：更名后新旧版本可能共存于同一台
    机器，只认新名会让「旧版占着端口」重新变成认不出的僵局。

    但**不能用裸产品名做子串匹配**：那等于「命令行里出现 maskit 四个字母」就算数，
    任何在仓库目录（`D:\\work\\...\\maskit`）下跑起来、又恰好监听 18701-18719 或
    某个 upstream 端口的无关进程都会被 `taskkill /T /F` 连子孙一起杀掉。这里改成
    只认具体的入口脚本名与打包后的可执行文件名（与 lib.rs 的 ENGINE_NAMES 一致）。
    """
    try:
        pid = int(pid)
    except Exception:
        return False
    if pid <= 0 or pid == os.getpid():
        return False
    if sys.platform != "win32":
        low = _read_process_cmdline(pid).lower()
        if "mitmdump" in low or "mitmproxy.tools" in low or "transparent.py" in low:
            return False
        return any(mark in low for mark in _SHIELD_ENGINE_CMDLINE_MARKERS)
    try:
        _rc, out = _run_console(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"],
            timeout=min(_CMD_TIMEOUT, 8))
    except Exception:
        return False
    low = (out or "").lower()
    if "mitmdump" in low or "transparent.py" in low:
        return False  # mitmdump 类进程走 _is_mitmdump_pid，不在这里重复识别
    return any(mark in low for mark in _SHIELD_ENGINE_CMDLINE_MARKERS)


def _free_upstream_ports():
    """一次扫描并释放代理端口，避免逐端口 netstat 阻塞启停请求。

    杀两类占用者：mitmdump 相关进程（含 python 子进程），以及另一个 LLM Shield
    面板的 503 占位/透传监听（_is_shield_panel_pid）。曾直接按端口杀 PID，会强杀
    占用 187xx 段的无关第三方进程（数据丢失风险）；也曾在面板 503 占位占端口时
    杀不掉导致自动重启失败——只杀可识别为 Shield 相关、且确在监听上游端口的进程。
    """
    # 隔离防护：若本实例不是主面板 5801（如副端口 5901 测试运行），且主面板正在运行，
    # 绝不能越界强杀主面板正在服务的 18701..18720 端口，防止意外打断正常用户的生产客户端。
    if PANEL_PORT != 5801 and _port_listen(5801):
        return []
    ports = set()
    try:
        ports.add(int(PROXY_PORT))
    except Exception:
        pass
    try:
        for u in (load_config().get("upstreams") or []):
            p = int(u.get("port") or 0)
            if 0 < p < 65536:
                ports.add(p)
    except Exception:
        pass
    # 固定冷门段兜底
    for p in range(18701, 18720):
        ports.add(p)
    port_pids = _listening_port_pids(ports, fresh=True)
    pid_ports = {}
    for port, pids in port_pids.items():
        for pid in pids:
            if pid in (0, os.getpid()):
                continue
            if _is_mitmdump_pid(pid) or _is_shield_panel_pid(pid):
                pid_ports.setdefault(pid, []).append(port)
    freed = []
    for pid, bound_ports in pid_ports.items():
        ok, detail = _taskkill_pid(pid)
        freed.append(f"{','.join(map(str, bound_ports))}->{pid}:{'ok' if ok else detail}")
    return freed


def _stop_proxy_locked(skip_fallback=False):
    state["stop_requested"] = True  # 让 watchdog 知道这是主动停止，不要自动拉起
    state["generation"] = int(state.get("generation", 0)) + 1
    p = proc["p"]
    pid = None
    if p is not None:
        try:
            pid = p.pid
        except Exception:
            pid = None
    if not pid:
        pid = _read_pid_file()
    # 1) 杀进程树（含 mitmdump 拉起的 python 子进程）
    if pid:
        _kill_proxy_tree(pid)
        # 再等一下让端口释放
        try:
            if p and p.poll() is None:
                p.wait(timeout=2)
        except Exception as e:
            _emit_log(f"[panel] 等待进程退出超时(忽略): {_safe_public_text(e, 240)}")
    proc["p"] = None
    state["proxy_running"] = False
    state["proxy_pid"] = None
    state["auto_recovered_at"] = None  # 手动停止后不再提示「已自动恢复」
    state["auto_recover_fail"] = ""  # 手动停止也清失败告警，避免横幅残留
    state["capture_mode"] = load_config().get("capture_mode", "reverse")
    try:
        PID_FILE.unlink(missing_ok=True)
    except Exception as e:
        _emit_log(f"[panel] 删除 PID 文件失败(忽略): {e}")
    # 2) 若端口仍被占，强制清残留（一次 netstat 快照，避免逐端口 0.3s 探测）
    still = []
    try:
        ports = set()
        for u in (load_config().get("upstreams") or []):
            port = int(u.get("port") or 0)
            if port:
                ports.add(port)
        ports.add(PROXY_PORT)
        # fresh=True：刚杀完进程，缓存里还是「在监听」的旧快照，会误判残留
        still = sorted(port for port in _listening_port_pids(ports, fresh=True))
    except Exception as e:
        _emit_log(f"[panel] 停止后端口查询失败(跳过回收检测): {e}")
    if still:
        freed = _free_upstream_ports()
        _emit_log(f"[panel] 停止后端口仍占用 {still}，已强制释放: {freed[:8]}")
    _emit_log("[panel] 停止本地代理")
    # 停止后行为按 stop_mode（见 _stop_mode）：error（默认）= 端口继续监听并回
    # 503 shield_unavailable；passthrough = 明文直连；block = 端口释放、客户端断连。
    if skip_fallback:
        # App 退出专用（skip_fallback=1）：整个引擎进程几秒后就会被壳终止，兜底
        # 监听活不过那几秒、只会把未脱敏明文放出去。用户语义是「我退出了脱敏
        # 网关」，端口释放、客户端 connection refused 才是诚实的行为。
        # 「绝不断网」红线约束的是引擎还在跑的场景（手动停止/崩溃自愈），不约束退出。
        _emit_log("[panel] 已停止代理（退出流程：不挂兜底监听，端口释放、客户端将断连）")
    else:
        _start_fallback("已停止代理")
    return True, None


def stop_proxy(skip_fallback=False):
    """停止代理：杀 mitmdump 进程树 + 释放 187xx 端口，避免「停止后再启动端口被占用」。

    skip_fallback=True 仅用于 App 退出流程：不挂兜底监听（见 _stop_proxy_locked 尾部注释）。
    """
    with lock:
        state["proxy_stopping"] = True
        try:
            return _stop_proxy_locked(skip_fallback=skip_fallback)
        finally:
            state["proxy_stopping"] = False


def _watchdog(generation=None):
    """守护 mitmdump：进程退出或端口失守时自动拉起（指数退避），上游变化时重启。

    以前只清状态不重启：代理一崩所有 187xx 端口直接拒连，用户要手动回面板点启动，
    而客户端只会看到连接被拒——最难排查的一类"不好用"。
    注意：循环条件不能依赖 state["proxy_running"]（api_status 轮询会写它），
    否则代理一旦退出，下次轮询就把它置 False，watchdog 直接退出不再拉起。
    这里用 stop_requested + generation 判定，只有主动停止或新一轮启停才退出。

    两类故障都要守（v1.5.61 补齐第二类）：
    1. 进程退出 —— p.poll() 可见。
    2. **进程活着但端口没了** —— mitmdump 只绑上部分 --mode 端口，或运行中某个
       listener 挂掉。此前完全不检测：面板显示「运行中」、health_check 也早就
       能算出 port_issues，却只在 UI 写「建议重启」，没有任何自动修复，那条
       upstream 的客户端就一直连不上。这正是「软件启动了也不能正常转发」。
    """
    if generation is None:
        generation = state.get("generation", 0)
    while not state.get("stop_requested"):
        time.sleep(5)
        if generation != state.get("generation"):
            return  # 这是上一轮进程的 watchdog，绝不能干预新一轮启停
        p = proc["p"]
        proc_dead = not p or p.poll() is not None
        port_down = []
        if not proc_dead:
            # local 模式由 WinDivert 透明捕获，不绑固定端口，跳过端口校验，
            # 否则会被恒判故障、无限重启。
            if state.get("capture_mode") != "local":
                try:
                    expect = _expected_listen_ports()
                    if expect:
                        live = _listening_port_pids(expect, fresh=True)
                        port_down = [x for x in expect if x not in live]
                except Exception:
                    port_down = []  # 探测本身失败不算故障，宁可漏报不误杀
            if port_down:
                rounds = int(state.get("port_down_rounds") or 0) + 1
                state["port_down_rounds"] = rounds
                _emit_log(f"[panel] upstream 端口未监听 {port_down}"
                          f"（第 {rounds}/{_PORT_DOWN_RESTART_ROUNDS} 次确认，进程仍存活）")
                if rounds < _PORT_DOWN_RESTART_ROUNDS:
                    continue  # 防抖：单轮可能是 netstat 偶发空结果或端口重绑瞬间
                state["port_down_rounds"] = 0
                _emit_log(f"[panel] 端口 {port_down} 持续未监听，重启代理恢复转发")
                _restart_proxy_locked(f"端口失守 {port_down}")
                return  # 成功则新 watchdog 已起；失败时 _restart_proxy_locked 已排程重试
            state["port_down_rounds"] = 0
        if proc_dead:
            _emit_log("[panel] 检测到 mitmdump 退出")
            _dump_crash_context()
            with lock:
                proc["p"] = None
                state["proxy_pid"] = None
            try:
                PID_FILE.unlink(missing_ok=True)
            except Exception:
                pass
            if state.get("stop_requested"):
                state["proxy_running"] = False
                return
            # 崩溃后先清残留端口占用（挂死的旧 mitmdump / 另一面板的 503 占位监听），
            # 否则自动重启会被「端口被非 mitmdump 进程占用」挡住（曾空窗 29 分钟，
            # 只能手动断开再启用）。清理失败不阻断后续流程。
            try:
                freed = _free_upstream_ports()
                if freed:
                    _emit_log(f"[panel] 已清理残留端口占用: {freed}")
            except Exception as e:
                _emit_log(f"[panel] 清理残留端口占用失败: {e}")
            # 崩溃后立刻按 stop_mode 兜底：error（默认）挂 503 占位监听，
            # 让客户端拿到明确错误而不是「连接被拒」；passthrough 则明文直连。
            _start_fallback("mitmdump 崩溃")
            # 连续崩溃计数跨代际（放 state，成功重启后不清零）：
            # 启动后 <60s 就崩算连续崩溃；稳定运行 60s+ 才算恢复，重置计数
            with lock:
                now = time.time()
                last_ok = state.get("last_restart_ok_ts") or 0
                restarts = state.get("restarts") or 0
                if last_ok and now - last_ok > 60:
                    restarts = 0
                restarts += 1
                state["restarts"] = restarts
            if restarts > _WATCHDOG_MAX_RESTARTS:
                # 放弃自动重启但**不结束线程**：继续以长间隔巡检，一旦外部条件
                # 恢复（占端口的第三方退出、mitmdump 重新装好）就能自己救回来。
                # 曾直接 return，代理从此永久停摆，只能靠用户手动点启动。
                state["proxy_running"] = False
                state["last_error"] = (f"mitmdump 连续 {restarts} 次异常退出，已降低重试频率"
                                       f"（当前兜底：{state.get('fallback_mode') or 'block'}）")
                state["auto_recover_fail"] = state["last_error"]
                _emit_log(f"[panel] mitmdump 连续 {restarts} 次异常退出，转入 {_WATCHDOG_IDLE_RETRY}s 慢速重试")
                if _sleep_interruptible(_WATCHDOG_IDLE_RETRY, generation):
                    return
                with lock:
                    state["restarts"] = 0  # 慢速重试前清零，重新获得一轮快速重试额度
                continue
            delay = min(2 ** (restarts - 1), 30)  # 退避，避免端口占用类故障疯狂重启刷日志
            state["proxy_running"] = False
            _emit_log(f"[panel] {delay}s 后自动重启代理（第 {restarts} 次）")
            # 退避期间用户可能点了停止：必须复查，否则代理"复活"（停止功能失效）
            if _sleep_interruptible(delay, generation):
                state["proxy_running"] = False
                return
            ok, err = start_proxy()
            if not ok:
                # 重启失败**不能 return**：曾在此结束线程，代理从此无人守护，
                # 叠加 stop_mode=block 就是永久断网直到用户手动干预。
                # 继续留在循环里，下一轮按退避继续尝试。
                state["last_error"] = f"自动重启失败: {err}"
                state["auto_recover_fail"] = f"自动重启失败: {err}"
                _emit_log(f"[panel] 自动重启失败: {err}（将继续重试）")
                # 启动失败也留现场：端口残留清理不掉等场景占端口的是谁，
                # 只有现场文件能归因（曾出现面板起来后代理 8 分钟才拉起）
                try:
                    _dump_crash_context(reason="startfail")
                except Exception:
                    pass
                _start_fallback("自动重启失败")
                # start_proxy 无论成败都已递增 generation，本地代次必须跟上，
                # 否则下一轮循环开头的代次校验会让这个 watchdog 立刻自我退出。
                generation = state.get("generation", generation)
                continue
            # 自动恢复成功：记录时间供前端提示；清掉失败告警
            state["auto_recovered_at"] = time.time()
            state["auto_recover_fail"] = ""
            _emit_log("[panel] 代理已自动重启")
            return  # start_proxy 已拉起新的 watchdog 线程
        # 稳定运行：连续崩溃计数靠 last_restart_ok_ts>60s 自动清零（见上方崩溃分支），
        # 这里不再维护局部 restarts（曾有无意义的局部变量 restarts=0，已删）
        if state.get("capture_mode") not in {"explicit"}:
            continue
        desired_upstream = detect_upstream()
        current_upstream = state.get("upstream", "")
        if desired_upstream != current_upstream:
            _emit_log(
                f"[panel] 检测到上游代理变化：{current_upstream or 'direct'} -> {desired_upstream or 'direct'}，重启本地代理"
            )
            _restart_proxy_locked("上游代理变化")
            return


def _sleep_interruptible(seconds, generation):
    """可中断等待：期间用户点停止或发生新一轮启停则立即返回 True（应退出）。

    曾直接 time.sleep(delay)：最长 30s 里用户点了「停止」也毫无反应，
    醒来后才发现要退出——期间面板状态与实际行为不一致。
    """
    deadline = time.time() + max(0, seconds)
    while time.time() < deadline:
        if state.get("stop_requested") or generation != state.get("generation"):
            return True
        time.sleep(min(0.5, max(0.05, deadline - time.time())))
    return bool(state.get("stop_requested") or generation != state.get("generation"))


def _restart_proxy_locked(reason):
    """停止并重新启动代理，失败时保证兜底监听在位且守护不中断。

    stop_proxy() 会置 stop_requested=True 并递增 generation，start_proxy() 再把
    它复位——顺序不能颠倒，否则新起的 watchdog 会立刻自我退出。
    """
    stop_proxy()
    ok, err = start_proxy()
    if not ok:
        state["last_error"] = f"{reason}后重启失败: {err}"
        state["auto_recover_fail"] = state["last_error"]
        _emit_log(f"[panel] {reason}后重启本地代理失败: {err}")
        try:
            _dump_crash_context(reason="startfail")
        except Exception:
            pass
        _start_fallback(f"{reason}后重启失败")
        # stop_proxy() 留下的 stop_requested=True 和递增过的 generation 都要收拾：
        # 这是内部重启而非用户主动停止。不复位 stop_requested → 调用方的 while 循环
        # 直接退出；不接手新代次 → 旧 watchdog 也会因代次不符退出。两者叠加就是
        # 「一次重启失败 = 代理永久无人守护」，正是本次要修的问题。
        state["stop_requested"] = False
        threading.Thread(target=_watchdog, args=(state.get("generation"),),
                         daemon=True).start()
    else:
        state["auto_recovered_at"] = time.time()
        state["auto_recover_fail"] = ""
    return ok


def _dump_crash_context(reason="crash"):
    """mitmdump 退出/启动失败时把完整现场落盘（崩溃现场），避免被 800 行环形缓冲冲掉。

    写独立文件 crash-dumps/crash-<时间戳>-<reason>.txt：退出码、进程状态、上游端口占用表
    （每端口 PID + 可执行名 + 命令行 + 是否 Shield 相关）、crash log 尾部。
    保留最近 10 份。曾只有 log_buf 尾部且混在 proxy-crash.log 里：掉网时
    mitmdump 静默退出无任何输出，现场文件是唯一能归因的线索。
    reason="startfail"：watchdog 自动重启失败（如端口残留清理不掉）时也留现场，
    曾出现面板启动后代理 8 分钟才拉起、期间 503 频发，却查不到占端口的是谁。
    """
    try:
        import datetime
        dump_dir = DATA_ROOT / "crash-dumps"
        dump_dir.mkdir(exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        fname = dump_dir / f"crash-{ts}-{reason}.txt"
        p = proc.get("p")
        poll = p.poll() if p else None
        lines = [
            f"==== {datetime.datetime.now().isoformat(timespec='seconds')} ====",
            f"proxy_running={state.get('proxy_running')} pid={state.get('proxy_pid')} "
            f"generation={state.get('generation')} restarts={state.get('restarts')} "
            f"stop_requested={state.get('stop_requested')} fallback={state.get('fallback_mode')}",
            f"popen={'present' if p else 'none'} poll={poll} "
            f"returncode={p.returncode if p and poll is not None else 'n/a'}",
            "-- upstream port occupancy --",
        ]
        try:
            ports = set(range(18701, 18721))
            try:
                ports.add(int(PROXY_PORT))
            except Exception:
                pass
            occ = _listening_port_pids(ports, fresh=True)
            for port in sorted(occ):
                for pid in occ[port]:
                    try:
                        _rc, out = _run_console(
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                             f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"],
                            timeout=8)
                        cl = (out or "").strip().replace(chr(10), " ")[:300]
                    except Exception:
                        cl = "?"
                    shield = "mitmdump" if _is_mitmdump_pid(pid) else (
                        "panel" if _is_shield_panel_pid(pid) else "other")
                    lines.append(f"  {port}: pid={pid} class={shield} cmd={cl}")
        except Exception as e:
            lines.append(f"  (port scan failed: {e})")
        lines.append("-- crash log tail --")
        try:
            crash = DATA_ROOT / "proxy-crash.log"
            if crash.exists():
                lines.append(crash.read_bytes()[-20000:].decode("utf-8", errors="replace"))
        except Exception:
            pass
        fname.write_text("\n".join(lines), encoding="utf-8")
        _emit_log(f"[panel] 崩溃现场已写入 {fname}")
        try:  # 只留最近 10 份，防堆积
            for o in sorted(dump_dir.glob("crash-*.txt"))[:-10]:
                o.unlink(missing_ok=True)
        except Exception:
            pass
    except Exception:
        pass


# ========== 配置 ==========
def default_config():
    return {
        "capture_mode": "reverse",
        "target_domains": list(DEFAULT_DOMAINS),
        "domains_disabled": [],
        "api_paths": list(DEFAULT_PATHS),
        "sensitive": {},
        # 新结构：sensitive 仍用 {label: [words]} 兼容；组禁用/词禁用独立字段
        "sensitive_disabled": [],
        "sensitive_word_disabled": {},
        # 整词匹配清单：命中这些词的打码要求两侧是词边界（避免「王」打中「王国」）。
        # 走 /api/config/patch 的 list_add/list_remove 维护（前端 Settings 在用）。
        "sensitive_word_whole": [],
        "builtin_rules": dict(DEFAULT_BUILTIN_RULES),
        "secret_prefixes": list(DEFAULT_SECRET_PREFIXES),
        "debug": False,
        "diagnostic_unmatched": False,
        # AI 命名实体识别（本地 ONNX 模型，需 engine/models/ner_mini_zh/ 三件套
        # 且装了 onnxruntime+tokenizers）。默认关：缺模型/缺依赖时是纯负收益，
        # 且概率模型只应作为规则打码的补充。开源包不含模型（见 .gitignore）。
        "ner_enabled": False,
        "session_ttl": DEFAULT_TTL,
        "http2": False,
        "upstreams": list(DEFAULT_UPSTREAMS),
        "filter_enabled": True,
        "fail_closed": True,
        "response_scan": True,
        # 控制面 Origin 校验开关（默认开）。反代/CDN 回源时 Origin 与源站
        # scheme://host 不一致会导致面板 403——无法进 UI 时用环境变量
        # MASKIT_DISABLE_ORIGIN_CHECK=1 逃生；能进 UI 时关这个开关等效。
        "origin_check": True,
        # 敏感词统计是否记录明文。默认开：打码 preview（1**@***.com）排出来的
        # 排行榜没有信息量，而数据只落本机 SQLite、不出网。关掉后库里永不出现明文。
        "record_plaintext_words": True,
        # ── 浏览器扩展桥接（Browser Bridge v1，默认关）──
        # ext_token 是 config.json 里第一个长期密钥：只对 /api/ext/{ping,mask,restore}
        # 三个精确白名单端点有效（API_TOKEN 对全部 /api/* 有效）。首次启用时自动生成固化。
        "ext_bridge_enabled": False,
        "ext_token": "",
        # (B) 类（引擎未启动 / 端口不通 / 403 直通类）是否改为阻断。默认 false=直通，
        # 与「透明直连兜底、绝不断网」这条红线同语义；(A) 类无开关、恒阻断。
        "ext_block_when_engine_down": False,
        # 扩展流量是否写入本地事件库与统计。**只管落库与统计**：脱敏/还原与
        # 「未脱敏状态」可见性照常（详见 SECURITY.md 与 SPEC §5.3 三条边界）。
        "ext_record_events": True,
        # 旧版 Office(.doc / .xls) 转码开关，**默认关闭**。
        #
        # 它不是格式转换，而是有损重建：用 `decode('utf-16le', errors='ignore')` 从 OLE
        # 二进制里“捞”可读字符串，再塞进手写的极简 OOXML 骨架。实测后果：
        #   ① 图片/表格结构/样式/公式/多 sheet/批注/页眉页脚全部丢失；
        #   ② 二进制碎片被当成正文段落捞进去（实测正文里出现整段乱码）；
        #   ③ hits==0（完全无敏感信息）时**照样替换文件**，不需要脱敏的文件也遭破坏；
        #   ④ 不经过 _pad_zip_to_size 对齐，体积可以膨胀（.xls 实测 +127%），
        #      仍有上游 file_size_mismatch 拒收风险；
        #   ⑤ 输出是 OOXML，却仍以 .doc 文件名与原 MIME 上传（扩展侧不改文件名），
        #      上游按 application/msword 解析极易失败。
        # 开着它 = 用户上传的文档在上游被换成另一个东西，AI 读到的内容（残缺 + 乱码）不可信。
        # 关闭后 .doc / .xls 原样上行（文件完整、但不脱敏），扩展会明确提示用户另存为
        # .docx / .xlsx 再传。这是“诚实告知不支持”优于“静默产出残缺文件”的取舍。
        "ext_convert_legacy_office": False,
        "stream_response": True,
        # 流式接管黑名单：确认某上游接管后断连时把 host 填进来，保持整包路径。
        # 默认空：曾预置的 opencode.ai 是误判（真因是引擎在无完整 SSE 事件可发时
        # 返回 b""，被写成 chunked 终止块），修复后实测流式正常，不需要排除。
        "stream_exclude_hosts": [],
        "stop_mode": "passthrough",
        # 出口代理：Shield 转发到上游时经由的 HTTP 代理。开关在这里，
        # 具体哪个 upstream 走由 upstreams[].use_proxy 决定（境内中转直连、
        # 境外官方 API 走代理，互不影响）。
        "egress_proxy": dict(DEFAULT_EGRESS_PROXY),
        "model_prices": {},
        # 默认关闭：这是引擎唯一的**周期性**主动出站请求（拉模型价格表），交给用户显式开启
        "price_sync_enabled": False,
        "price_sync_url": DEFAULT_PRICE_SYNC_URL,
        "price_sync_interval_days": 7,
        # 更新检查源：留空 = 内置源（GitHub 静态 latest.json → GitHub API）。
        # 国内/内网服务器连不上 GitHub 时填镜像或自建中转；GitHub API 的
        # tag_name/body/published_at 与 latest.json 的 version/notes/pub_date
        # 两种格式后端都会归一化，换源不用动前端。
        "update_check_url": "",
        "log_retention_days": 7,
        "autostart": False,
        "start_minimized": False,
        "auto_start_proxy": True,
        # 向导完成标记与引擎自用的迁移标记袋（poison_scan_default_on 等）。
        # 两者都由 normalize_config 产出，必须在这里也列出来——本函数是「合法键」
        # 的唯一真相来源，_config_patch_node/_apply_config_patch 用 `key not in cfg`
        # 拒绝未知键，而 config.json 损坏时 _load_config_locked 会直接返回未归一化的
        # default_config()，缺键的字段在那条路径上会变成 400。
        "wizard_done": False,
        "meta": {},
        "audit": {
            "enabled": True,
            "passive": True,
            "active_probes": False,
            "severity_floor": "MEDIUM",
            "auto_report": False,
            # 审计的**响应级**熔断（默认关）：CRITICAL 时把本次响应换成 503。
            # 必须出现在本函数里——它是「合法键」的唯一真相来源，_config_patch_node
            # 用 `key/path 不存在` 拒绝未知字段；漏了它前端那个开关存不下去。
            "fail_closed": False,
            "signals": {
                "error_leak": True,
                "identity_swap": True,
                "tool_call_rewrite": True,
                "sse_anomaly": True,
                "response_poison": True,
                "cross_request_pollution": True,
                "dangerous_action": True,
            },
        },
        # 命令拦截（W2-3）：默认 observe（只记录）+ 仅工具参数通道。
        # 内置危害命令作为**可读可改的默认值**随包分发，用户可在界面新增/修改/
        # 停用/删除（删除不复活，见 _normalize_command_block 的种子语义）。
        "command_block": copy.deepcopy(DEFAULT_COMMAND_BLOCK),
    }


def _uniq(items):
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _clean_domain(value):
    d = str(value or "").strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/", 1)[0].split(":", 1)[0].strip(".")
    if not d or not DOMAIN_RE.fullmatch(d):
        return None
    return d


def _normalize_retention(raw):
    """日志保留天数归一化。0 = 永久保留（付费版「不限期」权益的落地形式）。

    别改回 `max(1, min(90, ...))`：那样 PAID_QUOTA 里声明的 `None`（不限）
    在代码里结构上就兑现不了——付费用户填 365 会被静默压成 90，
    而界面照样显示他填的值。

    上限 3650 天（10 年）是实际意义上的不限，同时挡住负数与天文数字
    传进 SQLite 的时间戳运算。非法输入回落默认 7 天，不是回落 1 天——
    「保留一天」是个谁都不会主动选的值，出现它一定是 bug 而不是配置。
    """
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return 7
    if n <= 0:
        return 0
    return min(3650, n)


def normalize_config(raw, warnings=None):
    """校验并规整配置。

    warnings: 传入 list 时，把"被丢弃/被改写"的项写进去。以前这些都是静默发生的，
    用户输入的域名或客户端会凭空消失、端口被悄悄改掉，界面上完全没有解释。
    """
    warn = warnings if isinstance(warnings, list) else []
    if not isinstance(raw, dict):
        raise ValueError("配置必须是 JSON 对象")
    base = default_config()
    capture_mode = str(raw.get("capture_mode", base["capture_mode"]) or "reverse").strip().lower()
    if capture_mode not in {"reverse", "explicit", "local"}:
        capture_mode = "reverse"

    raw_domains = list(raw.get("target_domains", base["target_domains"]) or [])
    domains = [_clean_domain(d) for d in raw_domains]
    for src, cleaned in zip(raw_domains, domains):
        if str(src or "").strip() and not cleaned:
            warn.append(f"域名「{str(src)[:40]}」格式不合法，已忽略")
    domains = _uniq([d for d in domains if d])[:MAX_ITEMS]
    disabled_raw = {_clean_domain(d) for d in raw.get("domains_disabled", [])}
    disabled = [d for d in domains if d in disabled_raw]

    paths = []
    for p in raw.get("api_paths", base["api_paths"]):
        p = str(p or "").strip()
        if not p.startswith("/") or len(p) > 200 or any(c.isspace() for c in p):
            continue
        paths.append(p)
    paths = _uniq(paths)[:MAX_ITEMS] or list(DEFAULT_PATHS)

    sensitive = {}
    sensitive_disabled = set()
    sensitive_word_disabled = {}
    sens = raw.get("sensitive")
    total_words = 0
    if isinstance(sens, dict):
        for label, words in sens.items():
            label = str(label or "").strip()
            if not LABEL_RE.fullmatch(label):
                continue
            clean_words = []
            # 兼容 {"标签": ["词"]} 与 {"标签": {"enabled": bool, "words": [], "disabled_words": []}}
            if isinstance(words, dict):
                if not bool(words.get("enabled", True)):
                    sensitive_disabled.add(label)
                word_iter = words.get("words") or []
                dis = []
                for w in words.get("disabled_words") or []:
                    w = str(w or "").strip()
                    if w and len(w) <= MAX_WORD_LEN:
                        dis.append(w)
                if dis:
                    sensitive_word_disabled[label] = _uniq(dis)[:MAX_ITEMS]
            else:
                word_iter = words or []
            for word in word_iter:
                word = str(word or "").strip()
                if word and len(word) <= MAX_WORD_LEN:
                    # re: 前缀正则词逐条编译校验（审计 P0）：非法正则拒绝保存，
                    # 否则一个坏词会让整个合并正则失败 → mask 503 全部客户端被拒
                    if word.startswith("re:"):
                        try:
                            re.compile(word[3:])
                        except re.error as e:
                            warn.append(f"正则词「{word[:40]}」无效：{e}，已拒绝保存")
                            continue
                    if total_words >= MAX_TOTAL_WORDS:
                        warn.append(f"敏感词总数超过 {MAX_TOTAL_WORDS}，后续词已忽略（可精简词表提升脱敏性能）")
                        break
                    clean_words.append(word)
                    total_words += 1
            sensitive[label] = _uniq(clean_words)[:MAX_ITEMS]

    flat = raw.get("custom_words")
    if isinstance(flat, dict):
        for word, label in flat.items():
            label = str(label or "").strip()
            word = str(word or "").strip()
            if LABEL_RE.fullmatch(label) and word and len(word) <= MAX_WORD_LEN:
                if total_words >= MAX_TOTAL_WORDS:
                    warn.append(f"敏感词总数超过 {MAX_TOTAL_WORDS}，后续词已忽略（可精简词表提升脱敏性能）")
                    break
                sensitive.setdefault(label, [])
                if word not in sensitive[label]:
                    sensitive[label].append(word)
                    total_words += 1

    for lab in raw.get("sensitive_disabled") or []:
        lab = str(lab or "").strip()
        if LABEL_RE.fullmatch(lab):
            sensitive_disabled.add(lab)
    # 只保留仍存在的标签
    sensitive_disabled = [l for l in sensitive_disabled if l in sensitive]

    raw_swd = raw.get("sensitive_word_disabled")
    if isinstance(raw_swd, dict):
        for lab, words in raw_swd.items():
            lab = str(lab or "").strip()
            if not LABEL_RE.fullmatch(lab) or lab not in sensitive:
                continue
            dis = []
            for w in words or []:
                w = str(w or "").strip()
                if w and len(w) <= MAX_WORD_LEN and w in set(sensitive.get(lab) or []):
                    dis.append(w)
            if dis:
                sensitive_word_disabled[lab] = _uniq(dis)[:MAX_ITEMS]

    builtin_rules = dict(DEFAULT_BUILTIN_RULES)
    raw_builtin = raw.get("builtin_rules")
    if isinstance(raw_builtin, dict):
        # 身份证开关合并迁移（0.1.18）：旧配置 IDCARD（15 位）+ IDCARD18（18 位）
        # 两个键合并为单一 IDCARD。合并值取旧 IDCARD18（18 位二代证是绝对主体，
        # 用户对它的开关意图最能代表对“身份证”的整体意图）；旧键从配置中淘汰。
        # 注意：IDCARD18=False（用户明确关过 18 位证）时合并值应为 False，
        # 不能被旧 IDCARD=True 覆盖——所以只在 IDCARD18 键存在时用它的值。
        if "IDCARD18" in raw_builtin:
            raw_builtin["IDCARD"] = bool(raw_builtin.get("IDCARD18"))
            del raw_builtin["IDCARD18"]
        # 旧配置 IP 键迁移：v1.5.8 起 IP 拆成 IP_PRIVATE（默认开）+ IP_INTERNAL
        # （默认关——10.x 是最常见版本号格式，曾把 version 10.2.3.4 脱敏掉）。
        # 旧 IP:True → 私有段开、内网段关（保守：内网段默认关防误伤）。
        if "IP" in raw_builtin and "IP_PRIVATE" not in raw_builtin:
            raw_builtin["IP_PRIVATE"] = bool(raw_builtin.get("IP"))
            raw_builtin["IP_INTERNAL"] = False
        for k, v in raw_builtin.items():
            k = str(k or "").strip().upper()
            if k in builtin_rules:
                builtin_rules[k] = bool(v)

    prefixes = []
    raw_prefixes = raw.get("secret_prefixes", base["secret_prefixes"])
    if isinstance(raw_prefixes, list):
        for prefix in raw_prefixes:
            prefix = str(prefix or "").strip()
            if 1 <= len(prefix) <= MAX_PREFIX_LEN and re.fullmatch(r"[@A-Za-z0-9][@A-Za-z0-9_.-]*", prefix):
                prefixes.append(prefix)
    if "secret_prefixes" in raw and isinstance(raw["secret_prefixes"], list) and len(raw["secret_prefixes"]) == 0:
        prefixes = []
    else:
        prefixes = _uniq(prefixes)[:100] or list(DEFAULT_SECRET_PREFIXES)

    # 反向代理 upstream 路由表
    ups = []
    raw_ups = raw.get("upstreams", base["upstreams"])
    if isinstance(raw_ups, list):
        seen_names = set()
        seen_base = set()
        seen_port = set()
        for u in raw_ups:
            if not isinstance(u, dict):
                continue
            name = str(u.get("name") or "").strip()
            base_path = str(u.get("base_path") or "").strip()
            target = str(u.get("target") or "").strip()
            # name 限安全字符集（防 DOM XSS，允许中英文字母、数字、下划线、减号）
            if not name or not re.fullmatch(r"[A-Za-z0-9_\-\u4e00-\u9fff]{1,40}", name):
                warn.append(f"客户端名称「{name[:20] or '(空)'}」含不支持的字符（只能中英文、数字、_ 和 -），该条已忽略")
                continue
            if not target:
                warn.append(f"客户端「{name}」未填真实上游地址，该条已忽略")
                continue
            name_key = name.lower()
            if name_key in seen_names:
                warn.append(f"客户端「{name}」名称与已有条目重复，该条已忽略")
                continue
            seen_names.add(name_key)

            # base_path 规范化与自动冲突消解：
            # 纯中文或特殊字符无英数字符时，使用序号前缀（如 /up_2），避免全部塌缩成 /up；
            # 出现冲突时自动追加序号消解冲突，绝不因为内部路径前缀碰撞而把用户合法配置的客户端整条丢掉。
            # user_base 记录「用户显式填过且合法」的值：只有它被改名才告警——单端口前缀
            # 模式下 base_path 就是客户端 base_url 的路径，改名等于改契约，用户必须同步改
            # 客户端配置；静默改名会让他对着 404 找不到原因。自动生成的 /up_N 不告警（本就没契约）。
            slug = re.sub(r"[^A-Za-z0-9_\-]", "", name).lower()[:40]
            user_base = base_path
            if not base_path or not re.fullmatch(r"/[A-Za-z0-9_\-/]{1,60}", base_path):
                base_path = "/" + (slug or f"up_{len(ups) + 1}")
                user_base = ""
            if not base_path.startswith("/"):
                base_path = "/" + base_path
            candidate_base = base_path
            idx = 2
            while candidate_base in seen_base:
                candidate_base = f"{base_path}_{idx}"
                idx += 1
            if candidate_base != base_path and user_base:
                warn.append(
                    f"客户端「{name}」的路径前缀 {base_path} 与已有条目冲突，已自动改为 {candidate_base}"
                    "（单端口前缀模式下请同步更新该客户端的 base_url）"
                )
            base_path = candidate_base
            seen_base.add(base_path)
            # 端口：18700-18799 冷门段，未配或非法字符串则自动分配
            try:
                raw_port = int(u.get("port") or 0)
            except (ValueError, TypeError):
                raw_port = 0
            port = raw_port
            if port == 0:
                port = 18701 + len(ups)
            if port < 1024 or port > 65535 or port in seen_port:
                # 端口冲突或非法，自动重分配
                port = 18701 + len(ups)
                while port in seen_port:
                    port += 1
                if raw_port:
                    warn.append(f"客户端「{name}」端口 {raw_port} 不可用（冲突或越界），已自动改为 {port}")
            seen_port.add(port)
            target = str(u.get("target") or "").strip()
            scheme = "https"
            m_scheme = re.match(r"^(https?)://", target)
            if m_scheme:
                scheme = m_scheme.group(1)
                target = target[len(m_scheme.group(0)):]
            if not target:
                continue
            # 显式 http:// 保留（本地测试/内网网关场景），默认 https
            target = f"{scheme}://" + target
            paths_u = u.get("paths")
            if not isinstance(paths_u, list):
                paths_u = list(DEFAULT_PATHS)
            paths_u = [str(p or "").strip() for p in paths_u if str(p or "").strip().startswith("/")]
            paths_u = _uniq(paths_u)[:MAX_ITEMS] or list(DEFAULT_PATHS)
            # use_proxy：该 upstream 转发到真实上游时是否经由出口代理。
            # 逐 upstream 而非全局——境内中转（anyrouter 等）直连更快更稳，
            # 只有境外官方 API 需要代理，一刀切会把前者也绕远甚至绕挂。
            # extra_headers：转发前注入的静态请求头 {key: value}，只用于**与凭据无关**的
            # 协议头（如 anthropic-beta）。凭据头（Authorization / x-api-key / cookie 等）
            # 由 transparent._CREDENTIAL_HEADER_NAMES 在注入时跳过——凭据归客户端所有，
            # 这里保留原样存盘是为了让设置页能把历史遗留行展示出来给用户删。
            # 规范化：key 限安全字符、value 限长度，非法条目丢弃。
            extra_headers = {}
            raw_extra = u.get("extra_headers")
            if isinstance(raw_extra, dict):
                for k, v in raw_extra.items():
                    kk = str(k or "").strip()
                    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", kk):
                        continue
                    vv = str(v or "")
                    if len(vv) > 2048:
                        continue
                    extra_headers[kk] = vv
            ups.append({"name": name, "base_path": base_path, "port": port, "target": target,
                        "paths": paths_u, "use_proxy": bool(u.get("use_proxy")),
                        "extra_headers": extra_headers})
    if not ups:
        ups = list(DEFAULT_UPSTREAMS)

    try:
        ttl = int(raw.get("session_ttl", base["session_ttl"]))
    except Exception:
        ttl = base["session_ttl"]
    ttl = max(MIN_TTL, min(MAX_TTL, ttl))

    # 代理不可用时的兜底形态，三选一（语义见 _stop_mode）：
    # passthrough（默认）= 明文直连不脱敏，未启动代理时仍保证连通性；
    # error = 端口继续监听并回 503 shield_unavailable；
    # block = 端口完全不监听，客户端连不上。
    stop_mode = str(raw.get("stop_mode") or "passthrough").strip().lower()
    if stop_mode not in ("error", "block", "passthrough"):
        stop_mode = "passthrough"

    # 出口代理：Shield → 上游方向经由的 HTTP 代理。地址非法必须给出 warning，
    # 静默丢弃会变成「明明填了代理却仍然直连」，用户完全无从判断。
    raw_egress = raw.get("egress_proxy")
    if not isinstance(raw_egress, dict):
        raw_egress = {}
    egress_url = str(raw_egress.get("url") or "").strip()
    egress_enabled = bool(raw_egress.get("enabled"))
    if egress_url and parse_egress_proxy(egress_url) is None:
        warn.append(f"出口代理地址「{egress_url[:40]}」无法解析（只支持 http/https 代理，"
                    f"如 http://127.0.0.1:7890；socks5 不支持），已停用出口代理")
        egress_url = ""
        egress_enabled = False
    if egress_enabled and not egress_url:
        warn.append("出口代理已勾选启用但未填地址，已停用")
        egress_enabled = False
    egress = {"enabled": egress_enabled, "url": egress_url}
    # egress 状态提示与动作型 warning 分流（2026-09-15 用户反馈「随便干什么都弹」）：
    # 「启用了但没人勾」「勾了但全局没启用」是配置的**持续状态**，每次保存任意
    # 配置都会重复生成，前端 toast 弹一遍就烦一遍。这类状态改由 /api/status 的
    # egress_proxy + egress_proxy_users 驱动页面内联提示（Settings 页只做单客户端
    # 维度提示，「全局已启用但没人勾」的横幅在 Dashboard），不再进 warnings。动作型
    # warning（地址被丢弃、被连带停用）保留——那才是「本次保存改写了什么」的一次性告知。
    proxy_ups = [u.get("name") for u in ups if u.get("use_proxy")]
    if proxy_ups and not egress_enabled:
        warn.append(f"客户端「{', '.join(proxy_ups)}」勾选了「走代理」，但全局出口代理尚未启用或未填地址，将以直连方式转发")

    # ── 浏览器扩展桥接 ──
    # ext_token 只在「启用」时保证存在：启用了却没有 token = 扩展恒 403
    # invalid_token，用户完全无从归因（面板只显示一把空钥匙）。空则自动生成
    # 并随本次 normalize 的产物固化落盘（save_config 持久化的是本函数输出）。
    ext_enabled = bool(raw.get("ext_bridge_enabled", False))
    ext_token = str(raw.get("ext_token") or "").strip()
    if ext_token and (len(ext_token) > 200 or not ext_token.isascii()
                      or any(c.isspace() or ord(c) < 0x21 for c in ext_token)):
        warn.append("扩展桥接令牌含不支持的字符，已重新生成")
        ext_token = ""
    if ext_enabled and not ext_token:
        ext_token = secrets.token_urlsafe(24)

    return {
        "capture_mode": capture_mode,
        "target_domains": domains,
        "domains_disabled": disabled,
        "api_paths": paths,
        "sensitive": sensitive,
        "sensitive_disabled": sensitive_disabled,
        "sensitive_word_disabled": sensitive_word_disabled,
        "sensitive_word_whole": _uniq([str(w) for w in (raw.get("sensitive_word_whole") or []) if w])[:MAX_ITEMS],
        "builtin_rules": builtin_rules,
        "secret_prefixes": prefixes,
        "debug": bool(raw.get("debug", False)),
        "diagnostic_unmatched": bool(raw.get("diagnostic_unmatched", False)),
        "session_ttl": ttl,
        "http2": bool(raw.get("http2", True)),
        "upstreams": ups,
        "filter_enabled": bool(raw.get("filter_enabled", True)),
        "fail_closed": bool(raw.get("fail_closed", True)),
        "response_scan": bool(raw.get("response_scan", True)),
        "origin_check": bool(raw.get("origin_check", True)),
        "record_plaintext_words": bool(raw.get("record_plaintext_words", True)),
        "ext_bridge_enabled": ext_enabled,
        "ext_token": ext_token,
        "ext_block_when_engine_down": bool(raw.get("ext_block_when_engine_down", False)),
        "ext_record_events": bool(raw.get("ext_record_events", True)),
        "ext_convert_legacy_office": bool(raw.get("ext_convert_legacy_office", False)),
        "ner_enabled": bool(raw.get("ner_enabled", False)),
        "stream_response": bool(raw.get("stream_response", True)),
        "stream_exclude_hosts": _normalize_host_list(raw.get("stream_exclude_hosts")),
        "stop_mode": stop_mode,
        "egress_proxy": egress,
        "model_prices": _normalize_model_prices(raw.get("model_prices")),
        "price_sync_enabled": bool(raw.get("price_sync_enabled", False)),
        "price_sync_url": str(raw.get("price_sync_url") or DEFAULT_PRICE_SYNC_URL).strip(),
        "price_sync_interval_days": max(1, min(90, (int(raw.get("price_sync_interval_days", 7) or 7) if str(raw.get("price_sync_interval_days", "")).isdigit() else 7))),
        # 更新检查源：非法值静默丢弃（回落内置源）。这里不做 400：它只是个辅助配置，
        # 为它把整份配置卡在保存失败上，用户只会看到「保存失败」而不知道是哪个字段。
        "update_check_url": _normalize_update_check_url(raw.get("update_check_url")),
        # 日志保留天数：0 = 永久保留（付费版「日志不限期」权益）。
        # 原来钳成 max(1, min(90, ...))，而 PAID_QUOTA 声明的是 None（不限）——
        # 承诺在代码里结构上就兑现不了，付费用户设 365 会被静默压成 90（2026-08-17 审计）。
        # 上限放到 3650 天（10 年）是实际意义上的"不限"，同时避免把负数/天文数字
        # 传给 SQLite 的时间戳计算。负值一律归 0（=永久），不再回落成 1 天。
        "log_retention_days": _normalize_retention(raw.get("log_retention_days", 7)),
        "autostart": bool(raw.get("autostart", False)),
        "start_minimized": bool(raw.get("start_minimized", False)),
        "auto_start_proxy": bool(raw.get("auto_start_proxy", True)),
        "wizard_done": bool(raw.get("wizard_done", False)),
        "meta": raw.get("meta") if isinstance(raw.get("meta"), dict) else {},
        "audit": _normalize_audit(raw.get("audit")),
        "command_block": _normalize_command_block(raw.get("command_block"), warn),
    }


def _normalize_update_check_url(raw):
    """规范化「更新检查源」URL：非法一律返回 ""（= 用内置源）。

    只做**形态**校验，不要求白名单域名——这一项的全部意义就是让用户填自己的镜像/
    自建中转，锁死域名等于把功能废掉。允许 http：内网自建中转常是明文 HTTP，
    而这里取回的内容只用于「显示有新版本」，真正的下载地址由前端按 GitHub 固定
    仓库拼，被篡改也换不掉下载源。带 userinfo 的 URL 一律拒绝——用户很容易顺手把
    带账号密码的代理地址贴进来，那会让凭据出现在日志与状态接口里。

    非法输入静默回落 ""（不抛错）：它是辅助配置，为它让整份配置保存失败，
    用户只会看到「保存失败」而不知道是哪个字段错了。
    """
    try:
        text = str(raw or "").strip()
        if not text or len(text) > 2048:
            return ""
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
            return ""
        u = urlsplit(text)
        if u.scheme.lower() not in ("http", "https"):
            return ""
        if u.username or u.password:
            return ""
        if not u.hostname:
            return ""
        try:
            port = u.port
        except ValueError:
            return ""
        if port is not None and not (0 < port <= 65535):
            return ""
        return text
    except Exception:
        return ""


def _normalize_host_list(raw):
    """规范化主机列表（逗号/换行/空白分隔，去重去空，统一小写）。"""
    if isinstance(raw, str):
        raw = re.split(r"[\s,]+", raw)
    if not isinstance(raw, (list, tuple)):
        return []
    out, seen = [], set()
    for h in raw:
        if not isinstance(h, str):
            continue
        for part in re.split(r"[\s,]+", h):
            part = part.strip().lower().rstrip(".")
            if part and part not in seen:
                seen.add(part)
                out.append(part)
    return out


def _normalize_model_prices(raw):
    """规范化用户自配模型价格：{model: {input: $/1M, output: $/1M}}。

    非法条目丢弃（价格必须是非负有限数），模型名去空白。
    """
    if not isinstance(raw, dict):
        return {}
    out = {}
    for model, price in raw.items():
        if not isinstance(model, str) or not model.strip():
            continue
        if not isinstance(price, dict):
            continue
        try:
            pin = float(price.get("input") or 0)
            pout = float(price.get("output") or 0)
        except (TypeError, ValueError):
            continue
        if pin < 0 or pout < 0 or not (math.isfinite(pin) and math.isfinite(pout)):
            continue
        out[model.strip()] = {"input": round(pin, 6), "output": round(pout, 6)}
    return out


def _normalize_audit(raw):
    """规范化 audit 配置块。缺字段补默认。"""
    base = default_config()["audit"]
    if not isinstance(raw, dict):
        return base
    signals_raw = raw.get("signals") or {}
    base_signals = base["signals"]
    signals = {
        k: bool(signals_raw.get(k, base_signals[k]))
        for k in base_signals
    }
    floor = str(raw.get("severity_floor") or "MEDIUM").upper()
    if floor not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        floor = "MEDIUM"
    return {
        "enabled": bool(raw.get("enabled", True)),
        "passive": bool(raw.get("passive", True)),
        "active_probes": bool(raw.get("active_probes", False)),
        "severity_floor": floor,
        "auto_report": bool(raw.get("auto_report", False)),
        # 审计的响应级熔断（与脱敏主线的同名 fail_closed 不是一回事，见 transparent.py 注释）
        "fail_closed": bool(raw.get("fail_closed", False)),
        "signals": signals,
    }


# ========== 命令拦截（config.command_block）规范化 ==========
# 正则合法性交给 shield_defaults.validate_command_regex（**唯一校验源**：
# panel 保存时与 transparent 加载时都调它；两处各写一份必然漂移）。
CMD_MODES = ("observe", "rewrite", "block")
CMD_CHANNELS = ("tool", "text")


def _normalize_cmd_pattern(raw, warn):
    """规范化单条命令拦截规则；非法（正则编译不过 / 超长 / 嵌套量词）返回 None。

    非法条目**丢弃并告警，不静默**：warnings 会回传给前端提示，用户能知道
    「我加的那条为什么没生效」。
    """
    if not isinstance(raw, dict):
        return None
    rx_src = str(raw.get("regex") or "")
    if not rx_src.strip():
        return None
    label = str(raw.get("label") or "").strip()[:60]
    pid = str(raw.get("id") or "").strip()[:60]
    name = label or pid or rx_src[:24]
    ok, why = validate_command_regex(rx_src)
    if not ok:
        warn.append(f"命令拦截规则「{name}」{why}，已忽略")
        return None
    if not pid:
        # 用户新增时未带 id：按正则内容派生，**稳定且可复现**（不能用 hash()——
        # PYTHONHASHSEED 随进程变化，会把 id 改来改去）
        pid = "user-" + hashlib.sha1(rx_src.encode("utf-8")).hexdigest()[:10]
    return {
        "id": pid,
        "label": label,
        "regex": rx_src,
        "enabled": bool(raw.get("enabled", True)),
        "builtin": bool(raw.get("builtin", False)),
    }


def _normalize_command_block(raw, warn):
    """规范化 command_block 段。

    **种子语义（关键，用户 2026-09-22 明确要求「删除不复活」）**：
    只在 `patterns` 键**缺失**（或类型不对）时灌内置种子；键已存在时哪怕值是
    `[]` 也一律原样尊重。否则用户删掉的条目会被 `default_config()` 每次加载重新灌回，
    「删不掉」比不提供更糟。这是项目既有范式（transparent.py 的 stream_exclude_hosts
    同款约定：键存在但为空 = 用户显式清空，必须原样生效）。
    """
    base = default_config()["command_block"]
    if not isinstance(raw, dict):
        # 整段缺失=第一次运行 → 灌种子（开箱即用）
        return copy.deepcopy(base)
    mode = str(raw.get("mode") or "observe").strip().lower()
    if mode not in CMD_MODES:
        warn.append(f"命令拦截模式「{mode}」未知，已回落 observe（只记录）")
        mode = "observe"
    raw_patterns = raw.get("patterns")
    if not isinstance(raw_patterns, list):
        patterns = copy.deepcopy(base["patterns"])
    else:
        patterns = []
        seen = set()
        for item in raw_patterns:
            norm = _normalize_cmd_pattern(item, warn)
            if norm is None:
                continue
            if norm["id"] in seen:
                # id 撞车：补后缀而不是丢条目，否则用户新增的第二条会静默消失
                norm["id"] = f"{norm['id']}-{len(seen)}"
            seen.add(norm["id"])
            patterns.append(norm)
    allow = []
    for item in (raw.get("allow_patterns") or []):
        src = str(item or "").strip()
        if not src:
            continue
        ok, why = validate_command_regex(src)
        if not ok:
            warn.append(f"命令白名单「{src[:24]}」{why}，已忽略")
            continue
        allow.append(src)
    raw_channels = raw.get("channels")
    channels = [c for c in (raw_channels or []) if c in CMD_CHANNELS] if isinstance(raw_channels, list) else []
    if not channels:
        # 缺省只拦工具参数通道：正文里 AI 常**讲解**命令（「切勿运行 rm -rf /」），
        # 启用 text 必须由用户显式选择，不能被缺省值悄悄带上（§6.5）。
        channels = list(base["channels"])
    return {"mode": mode, "patterns": patterns,
            "allow_patterns": allow, "channels": channels}


def _sync_runtime_config(cfg):
    """把持久化配置同步给面板进程内直接依赖的运行时全局状态。

    load_config() 与 save_config() 写盘后均原子调用本函数，确保 UI 保存、
    API 调用与配置回滚后，内存中的开关（如 _origin_check_enabled）
    与明文统计设置 100% 立即生效，杜绝下一次读盘前的时序空窗期。
    """
    global _origin_check_enabled
    if isinstance(cfg, dict):
        _origin_check_enabled = bool(cfg.get("origin_check", True))
        # 扩展桥接四项开关同步进运行时状态（guard 与 /api/ext/* 读它，不读盘）。
        # 先 clear 再 update：配置里缺键时必须是「回默认」而不是「留着上一份」。
        _ext_cfg_state.update({
            "ext_bridge_enabled": bool(cfg.get("ext_bridge_enabled", False)),
            "ext_token": str(cfg.get("ext_token") or ""),
            "ext_block_when_engine_down": bool(cfg.get("ext_block_when_engine_down", False)),
            "ext_record_events": bool(cfg.get("ext_record_events", True)),
            "ext_convert_legacy_office": bool(cfg.get("ext_convert_legacy_office", False)),
        })
        try:
            set_record_plaintext_words(cfg.get("record_plaintext_words", True))
        except Exception:
            pass


def load_config():
    # 整个「读文件 → normalize → 迁移写回」必须在锁内完成：迁移分支会写盘，
    # 与并发的 /api/config 保存交错会互相覆盖。RLock 允许内部再调 save_config。
    # 内存状态（如 _origin_check_enabled）必须在锁内原子同步，避免读-写交错覆盖刚保存的值。
    with cfg_lock:
        cfg = _load_config_locked()
        _sync_runtime_config(cfg)
    return cfg


def _load_config_locked():
    if CONFIG_PATH.exists():
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            cfg = normalize_config(raw)
            # 投毒检测默认开启（强制迁移一次）：老配置（无迁移标记）显式关闭过
            # audit/response_scan，升级后默认改为开启并落标记；之后尊重用户手工选择
            meta = raw.get("meta") or {}
            if isinstance(meta, dict) and not meta.get("poison_scan_default_on"):
                cfg["audit"]["enabled"] = True
                cfg["response_scan"] = True
                cfg["meta"] = dict(meta, poison_scan_default_on=True)
                try:
                    save_config(cfg)
                except Exception:
                    pass
            # stream_response 自动适配迁移（v1.5.66）：流式/整包按客户端请求类型自动适配，
            # UI 不再暴露开关。老配置显式关闭过 stream_response 的升级后强制改为 True
            #（流式请求重新获得逐事件还原），落标记后尊重后续配置变化。
            # 注意 meta 必须从 cfg 读（前序迁移可能已写入新标记），不能从 raw 读旧值。
            meta = cfg.get("meta") or {}
            if isinstance(meta, dict) and not meta.get("stream_auto_migrated"):
                if not cfg.get("stream_response", True):
                    cfg["stream_response"] = True
                cfg["meta"] = dict(meta, stream_auto_migrated=True)
                try:
                    save_config(cfg)
                except Exception:
                    pass
            # 流式黑名单迁移（第二版）：v1.5.58 前会给老配置预置 opencode.ai，
            # 但那是误判——断连真因是引擎在「本次无完整 SSE 事件可发」时返回 b""，
            # 被 mitmproxy 按 chunked 语法写成终止块。修复后 opencode.ai 实测流式
            # 正常，若不摘掉这条，升级用户会继续走整包路径（白白失去流式）。
            # 只摘这一条历史误判值，用户自己加的 host 原样保留。
            meta = cfg.get("meta") or {}
            if isinstance(meta, dict) and not meta.get("stream_exclude_opencode_cleared"):
                hosts = cfg.get("stream_exclude_hosts") or []
                if "opencode.ai" in hosts:
                    cfg["stream_exclude_hosts"] = [h for h in hosts if h != "opencode.ai"]
                cfg["meta"] = dict(meta, stream_exclude_opencode_cleared=True)
                try:
                    save_config(cfg)
                except Exception:
                    pass
            # stop_mode 默认恢复为 passthrough，确保软件开着未启动代理时直接转发不中断
            meta = cfg.get("meta") or {}
            if isinstance(meta, dict) and not meta.get("stop_mode_passthrough_default_v2"):
                # 只补默认值，绝不覆盖用户显式选择。曾把用户显式配置的
                # stop_mode=error/block 静默改回 passthrough——明确选择 fail-closed
                # 的用户被换成「停止即明文直连」，隐私语义被无声改写（审计 P2）。
                # 缺省键由 normalize_config / default_config 兜成 passthrough。
                if "stop_mode" not in raw:
                    cfg["stop_mode"] = "passthrough"
                cfg["auto_start_proxy"] = True
                cfg["meta"] = dict(meta, stop_mode_passthrough_default_v2=True)
                try:
                    save_config(cfg)
                except Exception:
                    pass
            # 若归一化对配置进行了清洗修正（如端口冲突、base_path 冲突消解、缺失默认值等），
            # 必须在锁内原子持久化写回磁盘，确保盘上数据与面板内存权威 100% 同步，
            # 避免 sidecar 进程从磁盘读取到未归一化的冲突数据。
            if json.dumps(raw, sort_keys=True) != json.dumps(cfg, sort_keys=True):
                try:
                    save_config(cfg, allow_shrink=True)
                except Exception as e:
                    _emit_log(f"[panel] 归一化配置持久化写回失败: {e}")
            return cfg
        except Exception as e:
            _emit_log(f"[panel] 配置解析失败，使用默认配置: {e}")
    d = default_config()
    _sync_runtime_config(d)
    return d


def _read_config_raw():
    """直接读盘上的 config.json（不 normalize、不触发迁移写回）。

    护栏与差异日志只关心「盘上现在是什么」，走 load_config() 会触发迁移分支写盘，
    在 save_config 内部再写一次盘属于自找竞态。
    """
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


# 备份文件名规则：config.json.bak-<8位日期>-<6位时间>（列表端与回滚端共用）
# 曾未定义导致列表端 NameError 被吞 → bak-tool-enum-* 历史文件混入列表
# 且无法回滚（回滚端只认 <8位>-<6位>），用户点「回滚」报文件名非法。
_BACKUP_NAME_RX = re.compile(r"config\.json\.bak-[0-9]{8}-[0-9]{6}")


def _config_shape(c):
    """配置的结构性指标：客户端数 / 词库分类数 / 词总数 / 目标域名数。"""
    if not isinstance(c, dict):
        return None
    sen = c.get("sensitive") or {}
    if not isinstance(sen, dict):
        sen = {}
    return {
        "upstreams": len(c.get("upstreams") or []),
        "cats": len(sen),
        "words": sum(len(v or []) for v in sen.values() if isinstance(v, (list, tuple))),
        "domains": len(c.get("target_domains") or []),
    }


# 结构性缩减护栏阈值：一次删 1 个是正常操作，批量消失一定是覆盖事故。
# 曾实测发生：前端 saveConfig({...cfg, ...next}) 带着陈旧快照提交，
# 9 个客户端 + 47 个词被一次性覆盖成打包默认值（2026-08-13、08-14 各一次）。
_SHRINK_GUARD = {
    "upstreams": ("客户端", 2),
    "cats": ("词库分类", 2),
    "words": ("敏感词", 5),
    "domains": ("目标域名", 3),
}


def _guard_structural_shrink(old_cfg, new_cfg, warnings):
    """拦截批量消失：缩减量达阈值的字段回退成旧值，并写 warnings 告知用户。

    只拦「批量」不拦「逐个」——UI 上删客户端/删词都是一次一个，不受影响；
    而覆盖事故的特征恰恰是一次少掉一大片。宁可让用户多点几次，
    也不能让一次点击把整份配置清空（数据丢失不可逆，多点几次只是麻烦）。
    """
    old_shape = _config_shape(old_cfg)
    new_shape = _config_shape(new_cfg)
    if not old_shape or not new_shape:
        return new_cfg
    field_map = {
        "upstreams": "upstreams",
        "cats": "sensitive",
        "words": "sensitive",
        "domains": "target_domains",
    }
    reverted = set()
    for key, (label, threshold) in _SHRINK_GUARD.items():
        drop = old_shape[key] - new_shape[key]
        if drop < threshold:
            continue
        field = field_map[key]
        if field in reverted:
            continue
        new_cfg[field] = copy.deepcopy(old_cfg.get(field))
        reverted.add(field)
        msg = (f"已拦截异常的{label}批量删除（{old_shape[key]} → {new_shape[key]}，"
               f"一次减少 {drop} 项），该项配置已保持原值。"
               f"如确需批量删除请逐项操作。")
        if warnings is not None:
            warnings.append(msg)
        _emit_log(f"[panel] 配置护栏：{msg}")
    return new_cfg


def _log_config_delta(old_cfg, new_cfg):
    """结构性变更留痕：客户端/词库/域名的数量变化写进引擎日志（审计可追溯）。

    此前配置被覆盖时日志里只有一行「配置已保存」，事后无法判断是谁、改了什么。
    """
    old_shape = _config_shape(old_cfg)
    new_shape = _config_shape(new_cfg)
    if not old_shape or not new_shape or old_shape == new_shape:
        return
    parts = []
    for key, (label, _t) in _SHRINK_GUARD.items():
        if old_shape[key] != new_shape[key]:
            parts.append(f"{label} {old_shape[key]}→{new_shape[key]}")
    if not parts:
        return
    old_names = {str(u.get("name")) for u in (old_cfg.get("upstreams") or []) if isinstance(u, dict)}
    new_names = {str(u.get("name")) for u in (new_cfg.get("upstreams") or []) if isinstance(u, dict)}
    detail = ""
    if old_names - new_names:
        detail += f"，移除客户端 {sorted(old_names - new_names)}"
    if new_names - old_names:
        detail += f"，新增客户端 {sorted(new_names - old_names)}"
    _emit_log(f"[panel] 配置结构变更：{'，'.join(parts)}{detail}")


def save_config(cfg, warnings=None, allow_shrink=False):
    """保存配置。

    allow_shrink=True 用于显式的整份替换（如从备份回滚），跳过批量缩减护栏；
    常规保存一律走护栏，防止陈旧快照把用户配置整片抹掉。
    """
    cfg = normalize_config(cfg, warnings)
    # 原子写：先写临时文件再 os.replace，避免写一半时其他线程读到半文件
    # 导致 JSONDecodeError → 静默回退默认配置（用户配置全丢）。曾直接用 write_text 覆盖。
    # 锁保证同一时刻只有一个写者，配合调用方持锁完成读-改-写，杜绝丢更新。
    with cfg_lock:
        # 护栏 + 差异日志必须在锁内、备份之后、写盘之前：
        # 读到的旧配置就是本次将被覆盖的那一份，判断才有意义。
        old_cfg = _read_config_raw()
        if isinstance(old_cfg, dict):
            if not allow_shrink:
                cfg = _guard_structural_shrink(old_cfg, cfg, warnings)
            _log_config_delta(old_cfg, cfg)
        # 写前自动备份：任何误写/半写都能从 config.json.bak-* 恢复（保留最近 10 份）。
        # 曾发生单字段 POST /api/config 触发全量替换、用户配置被默认值覆盖的事故，
        # 备份是最后防线。
        try:
            _backup_config_file()
        except Exception as e:
            _emit_log(f"[panel] 配置备份失败(不阻断保存): {e}")
        tmp = None
        try:
            tmp = CONFIG_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, CONFIG_PATH)
            # 锁内原子同步运行时内存开关，杜绝多线程写盘与状态同步的交错竞态
            _sync_runtime_config(cfg)
        except Exception:
            if tmp is not None:
                try:
                    tmp.unlink(missing_ok=True)
                except Exception:
                    pass
            raise
    return cfg


def _backup_config_file():
    """把当前 config.json 复制为 config.json.bak-<时间戳>，保留最近 MAX 份。

    仅在文件存在且内容可解析时备份；备份目录与 config 同目录，文件名带时间戳
    便于按事故时间点找回。不备份内容损坏/缺失的（那种场景无意义）。
    """
    import shutil
    max_keep = 10
    if not CONFIG_PATH.exists():
        return
    try:
        json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return  # 当前文件已损坏，备份它没意义
    ts = time.strftime("%Y%m%d-%H%M%S")
    bak = CONFIG_PATH.with_name(f"config.json.bak-{ts}")
    try:
        shutil.copy2(CONFIG_PATH, bak)
    except Exception:
        return
    # 清理旧备份，只留最近 max_keep 份
    try:
        baks = sorted(CONFIG_PATH.parent.glob("config.json.bak-*"))
        for old in baks[:-max_keep]:
            try:
                old.unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        pass


def enabled_domains(cfg):
    """启用的域名 = 全部 - 禁用。"""
    disabled = set(cfg.get("domains_disabled") or [])
    return [d for d in cfg.get("target_domains", []) if d not in disabled]


def _build_allow_hosts(domains):
    """生成 --allow-hosts 正则：只对目标域名（含子域名）做 TLS 中间人，其余 passthrough。
    不限定端口，匹配 host 任意端口。"""
    parts = []
    for d in domains:
        d = (d or "").lower().rstrip(".")
        if not d:
            continue
        escaped = re.escape(d)
        parts.append(rf"^(?:.+\.)?{escaped}:\d+$")
    return "|".join(parts) if parts else ""


def _allow_hosts_of(cfg):
    """取某份配置派生出的 --allow-hosts 参数；解析失败返回 None（跳过重启判定）。"""
    try:
        return _build_allow_hosts(enabled_domains(cfg or {}))
    except Exception:
        return None


def _maybe_restart_for_allow_hosts(cfg, allow_before):
    """explicit 模式目标域名变化时重启代理，使新 --allow-hosts 生效。

    --allow-hosts 是 mitmdump 启动期参数：transparent.py 的热重载只更新路由
    变量，MITM 范围仍按旧白名单走——新增域名静默不脱敏、连 SKIP 事件都没有，
    用户无法归因（曾以为「域名热重载即时生效」）。其余捕获模式不受此影响
    （reverse 由 addon 路由、local 不用 --allow-hosts），不重启。
    返回是否执行了重启。
    """
    if allow_before is None or (cfg or {}).get("capture_mode") != "explicit":
        return False
    if not (proc["p"] and proc["p"].poll() is None):
        return False
    if _allow_hosts_of(cfg) == allow_before:
        return False
    _emit_log("[panel] explicit 模式目标域名变化，自动重启代理使 --allow-hosts 生效"
              "（MITM 域名白名单是启动参数，热重载改不到）")
    return bool(_restart_proxy_locked("explicit 模式域名变化"))


# ========== API ==========
@app.get("/api/config")
def api_get_config():
    cfg = load_config()
    # 附带内置规则元数据，供 UI 渲染开关（只读）
    return jsonify({
        **cfg,
        "_meta": {
            "builtin_rule_meta": BUILTIN_RULE_META,
            "version": __version__,
        },
    })


@app.post("/api/config")
def api_set_config():
    warnings = []
    # 保存前的监听端口集合：用于判断本次改动是否需要重启（见下）
    try:
        ports_before = set(_expected_listen_ports())
    except Exception as e:
        _emit_log(f"[panel] 读取当前监听端口失败: {_safe_public_text(e, 240)}")
        ports_before = set()
    try:
        incoming = request.get_json(force=True)
        if not isinstance(incoming, dict):
            return jsonify({"ok": False, "error": "配置必须是 JSON 对象"}), 400
        # 保存前的 explicit 模式 --allow-hosts 参数：与端口一样是启动期派生参数，
        # 域名/禁用域名变化后不重启就永远不生效（transparent 热重载只更新路由变量，
        # mitmproxy 的 MITM 范围仍按旧白名单走，新域名流量静默不脱敏）。
        try:
            allow_before = _build_allow_hosts(enabled_domains(load_config()))
        except Exception:
            allow_before = None
        # 整个「读当前配置 → 合并字段 → 校验写盘 → 同步内存」必须在 cfg_lock 临界区内原子完成！
        # 避免并发请求各自拿到旧快照后互相覆盖（实测两个并发 POST 各改一字段会丢掉一个更新）。
        with cfg_lock:
            merged = _load_config_locked()
            if isinstance(merged, dict):
                for k, v in incoming.items():
                    merged[k] = v
                incoming = merged
            cfg = save_config(incoming, warnings)
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 400
    _emit_log("[panel] 配置已保存（词表/规则/域名等热重载即时生效）")
    for w in warnings:
        _emit_log(f"[panel] 配置调整：{w}")
    # upstream 端口集合变了必须重启：端口是 mitmdump 启动参数 `--mode regular@<port>`
    # 固定下来的，transparent.py 的热重载只更新路由变量，**新端口不会凭空开始监听**。
    # 不自动重启的话，用户新增一个 upstream 后那个端口根本连不上，却看不出原因
    # （面板显示「运行中」、配置也确实保存了）。改动其他配置不触发重启。
    restarted = False
    try:
        ports_after = set(_expected_listen_ports(cfg))
        running = bool(proc["p"] and proc["p"].poll() is None)
        if running and ports_after != ports_before:
            _emit_log(f"[panel] upstream 端口变化 {sorted(ports_before)} -> {sorted(ports_after)}，"
                      f"自动重启代理使新端口生效")
            restarted = bool(_restart_proxy_locked("upstream 端口变化"))
        if not restarted:
            restarted = _maybe_restart_for_allow_hosts(cfg, allow_before)
    except Exception as e:
        _emit_log(f"[panel] 端口变化检测失败: {_safe_public_text(e, 240)}")
    # warnings 回传前端提示，避免用户输入被静默丢弃/改写却毫无解释
    return jsonify({"ok": True, "config": cfg, "warnings": warnings,
                    "proxy_restarted": restarted})


@app.post("/api/config/builtin_rules")
def api_set_builtin_rules():
    """Apply only the specified rule changes, without replacing a stale rule table."""
    changes = request.get_json(silent=True)
    if not isinstance(changes, dict) or not changes:
        return jsonify({"ok": False, "error": "规则更新必须是非空 JSON 对象"}), 400
    if any(rule not in DEFAULT_BUILTIN_RULES or type(enabled) is not bool
           for rule, enabled in changes.items()):
        return jsonify({"ok": False, "error": "规则名称必须有效，开关值必须是布尔值"}), 400
    warnings = []
    try:
        with cfg_lock:
            cfg = _load_config_locked()
            cfg["builtin_rules"].update(changes)
            cfg = save_config(cfg, warnings)
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 400
    _emit_log("[panel] 内置规则已更新")
    return jsonify({"ok": True, "config": cfg, "warnings": warnings, "proxy_restarted": False})


# ---- 配置增量端点（POST /api/config/patch）----------------------------------
# 背景：POST /api/config 的合并只发生在**顶层**（`merged[k] = v`），因此凡是
# 「值本身是容器」的字段（audit / egress_proxy / sensitive / upstreams /
# target_domains …），前端只能提交整份快照。快照一旦过期（多标签页、另一个
# 客户端、后端自身写入），并发修改就会被整对象覆盖且毫无提示。
# 本端点让前端下发「路径 + 操作」的增量，服务端在 cfg_lock 内完成局部修改，
# 消除覆盖窗口；同时它也是唯一能表达「删掉这一项」而无需回传整表的通道。
_CONFIG_PATCH_OPS = frozenset({
    "set",          # 覆盖指定路径的值（path 为空 = 覆盖整个键）
    "merge",        # 目标为对象：批量更新其中的键
    "map_del",      # 目标为对象：删除 value 列出的键
    "list_add",     # 目标为数组：追加 value 中尚不存在的标量项
    "list_remove",  # 目标为数组：移除 value 中存在的标量项
    "list_upsert",  # 目标为对象数组：按 name 就地更新或追加（支持 match 指定旧名）
    "list_del",     # 目标为对象数组：按 name 移除
})


def _config_patch_node(cfg, key, path, create_leaf=False):
    """在 cfg[key] 内按 path 下钻，返回该路径指向的节点。

    path 为空表示 cfg[key] 本身；中间节点必须是已存在的对象，否则视为非法路径
    （避免把拼写错误变成静默新建的键）。create_leaf=True 时允许末段缺失并就地
    建为空数组 —— 这是 list_add 需要的语义（往一个尚不存在的分类里加词）。
    """
    if key not in cfg:
        raise ValueError(f"未知配置项：{key}")
    node = cfg[key]
    for i, seg in enumerate(path):
        if not isinstance(seg, str) or not seg:
            raise ValueError("配置路径段必须是非空字符串")
        if not isinstance(node, dict):
            raise ValueError(f"配置路径 {path[:i]} 不是对象，无法继续下钻")
        if seg not in node:
            if create_leaf and i == len(path) - 1:
                node[seg] = []
            else:
                raise ValueError(f"配置路径 {path[:i + 1]} 不存在")
        node = node[seg]
    return node


def _apply_config_patch(cfg, key, op, path, value, match=None):
    """把一条增量操作应用到 cfg 上（就地修改），返回修改后的 cfg。"""
    if op not in _CONFIG_PATCH_OPS:
        raise ValueError(f"不支持的配置操作：{op}")
    if not isinstance(key, str) or not key:
        raise ValueError("key 必须是非空字符串")
    if key not in cfg:
        raise ValueError(f"未知配置项：{key}")
    if not isinstance(path, list):
        raise ValueError("path 必须是数组")
    # 先把整条路径校验一遍：set 只用得到 path[:-1] 下钻，若在这里漏检末段，
    # 非字符串段会被当成对象键写进去（json 再序列化成 "1" 这种垃圾键）。
    if any(not isinstance(seg, str) or not seg for seg in path):
        raise ValueError("配置路径段必须是非空字符串")
    if op == "set":
        if not path:
            cfg[key] = value
            return cfg
        # path 非空时允许创建末段（用于「新建一个敏感词分类」这类场景）；
        # 中间段仍必须已存在，拼错中间层会直接报错而不是静默建出一串空对象。
        parent = _config_patch_node(cfg, key, path[:-1])
        if not isinstance(parent, dict):
            raise ValueError(f"配置路径 {path[:-1]} 不是对象，无法赋值")
        parent[path[-1]] = value
        return cfg

    node = _config_patch_node(cfg, key, path, create_leaf=(op == "list_add"))
    if op == "merge":
        if not isinstance(node, dict) or not isinstance(value, dict):
            raise ValueError("merge 要求目标与取值都是对象")
        node.update(value)
    elif op == "map_del":
        if not isinstance(node, dict) or not isinstance(value, list):
            raise ValueError("map_del 要求目标是对象、取值是数组")
        if any(not isinstance(k, str) for k in value):
            raise ValueError("map_del 的取值必须是字符串数组")
        for k in value:
            node.pop(k, None)
    elif op in ("list_add", "list_remove"):
        if not isinstance(node, list) or not isinstance(value, list):
            raise ValueError(f"{op} 要求目标与取值都是数组")
        if any(not isinstance(item, str) for item in value):
            raise ValueError(f"{op} 的取值必须是字符串数组")
        if op == "list_add":
            for item in value:
                if item not in node:
                    node.append(item)
        else:
            node[:] = [x for x in node if x not in value]
    elif op == "list_upsert":
        if not isinstance(node, list) or not isinstance(value, dict):
            raise ValueError("list_upsert 要求目标是对象数组、取值是对象")
        if match is not None and not isinstance(match, str):
            raise ValueError("match 必须是字符串")
        val_name = value.get("name")
        target_name = match if match is not None else val_name
        if not isinstance(target_name, str) or not target_name:
            raise ValueError("list_upsert 需要 name 或 match 指明要更新的条目")
        if val_name is None:
            # 带 match 但 value 没传 name 时自动继承目标名，防止成为无名对象在 normalize 时被丢弃
            value = dict(value, name=target_name)
        elif not isinstance(val_name, str) or not val_name:
            raise ValueError("list_upsert 的条目必须包含非空字符串 name")
        for i, item in enumerate(node):
            if isinstance(item, dict) and item.get("name") == target_name:
                node[i] = value
                break
        else:
            node.append(value)
    else:  # list_del
        if not isinstance(node, list) or not isinstance(value, str) or not value:
            raise ValueError("list_del 要求目标是对象数组、取值是条目名")
        node[:] = [x for x in node if not (isinstance(x, dict) and x.get("name") == value)]
    return cfg


@app.post("/api/config/patch")
def api_patch_config():
    """按「路径 + 操作」增量修改单个配置项，避免整对象覆盖并发写入。

    请求体：{"key": "audit", "op": "set", "path": ["signals", "INJECTION"], "value": true}
    响应体与 POST /api/config 完全一致，便于前端复用同一套保存/提示逻辑。
    """
    try:
        ports_before = set(_expected_listen_ports())
    except Exception as e:
        _emit_log(f"[panel] 读取当前监听端口失败: {_safe_public_text(e, 240)}")
        ports_before = set()
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "请求体必须是 JSON 对象"}), 400
    key = body.get("key")
    op = body.get("op")
    if not isinstance(key, str) or not key:
        return jsonify({"ok": False, "error": "key 必须是非空字符串"}), 400
    if not isinstance(op, str):
        return jsonify({"ok": False, "error": "op 必须是字符串"}), 400
    if "value" not in body:
        return jsonify({"ok": False, "error": "缺少 value"}), 400
    path = body.get("path", [])
    warnings = []
    allow_before = None
    try:
        with cfg_lock:
            cfg = _load_config_locked()
            allow_before = _allow_hosts_of(cfg)
            cfg = _apply_config_patch(cfg, key, op, path, body["value"], body.get("match"))
            cfg = save_config(cfg, warnings)
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 400
    _emit_log(f"[panel] 配置增量已保存（{key} / {op}）")
    for w in warnings:
        _emit_log(f"[panel] 配置调整：{w}")
    restarted = False
    try:
        ports_after = set(_expected_listen_ports(cfg))
        running = bool(proc["p"] and proc["p"].poll() is None)
        if running and ports_after != ports_before:
            _emit_log(f"[panel] upstream 端口变化 {sorted(ports_before)} -> {sorted(ports_after)}，"
                      f"自动重启代理使新端口生效")
            restarted = bool(_restart_proxy_locked("upstream 端口变化"))
        if not restarted:
            restarted = _maybe_restart_for_allow_hosts(cfg, allow_before)
    except Exception as e:
        _emit_log(f"[panel] 端口变化检测失败: {_safe_public_text(e, 240)}")
    return jsonify({"ok": True, "config": cfg, "warnings": warnings,
                    "proxy_restarted": restarted})


@app.get("/api/config/backups")
def api_config_backups():
    """列出可用配置备份（config.json.bak-*），带结构摘要供用户判断该回滚到哪份。

    此前备份只躺在数据目录里，用户在 UI 上看不到、也不知道存在——2026-08-14
    配置被覆盖时，用户第一反应是「代理坏了」，实际数据一直在备份里躺着。
    """
    items = []
    try:
        for p in sorted(CONFIG_PATH.parent.glob("config.json.bak-*"), reverse=True):
            # 列表与回滚必须用同一套文件名规则：回滚端只认 bak-<8位>-<6位>，
            # 若这里放宽 glob，历史遗留的 bak-tool-enum-* 会被列出来却点不动
            # （回滚返回「备份文件名非法」），用户以为功能坏了。
            if not _BACKUP_NAME_RX.fullmatch(p.name):
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue  # 损坏的备份不展示，回滚过去只会二次事故
            shape = _config_shape(data) or {}
            items.append({
                "file": p.name,
                "mtime": p.stat().st_mtime,
                "size": p.stat().st_size,
                "upstreams": shape.get("upstreams", 0),
                "cats": shape.get("cats", 0),
                "words": shape.get("words", 0),
                "domains": shape.get("domains", 0),
            })
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500
    current = _config_shape(_read_config_raw()) or {}
    return jsonify({"ok": True, "backups": items, "current": current})


@app.post("/api/config/restore")
def api_config_restore():
    """从指定备份回滚配置。

    安全：只接受 config.json.bak-<时间戳> 形态的纯文件名，且必须位于数据目录内，
    杜绝 ../ 路径穿越读到任意文件。回滚本身也走 save_config（会先备份当前配置），
    所以「回滚错了」还能再滚回来。
    """
    body = request.get_json(silent=True) or {}
    name = str(body.get("file") or "")
    if not _BACKUP_NAME_RX.fullmatch(name):
        return jsonify({"ok": False, "error": "备份文件名非法"}), 400
    src = CONFIG_PATH.parent / name
    if not src.exists() or src.resolve().parent != CONFIG_PATH.parent.resolve():
        return jsonify({"ok": False, "error": "备份不存在"}), 404
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except Exception as e:
        return jsonify({"ok": False, "error": f"备份内容损坏: {_safe_public_text(e, 240)}"}), 400
    warnings = []
    try:
        ports_before = set(_expected_listen_ports())
    except Exception:
        ports_before = set()
    allow_before = _allow_hosts_of(load_config())
    try:
        # 回滚是显式的整份替换，必须绕过批量缩减护栏——否则「从 9 个回滚到 3 个」
        # 会被护栏挡下，用户永远滚不回去。备份机制本身是这里的安全网。
        cfg = save_config(data, warnings, allow_shrink=True)
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500
    _emit_log(f"[panel] 已从备份回滚配置: {name}")
    restarted = False
    try:
        ports_after = set(_expected_listen_ports(cfg))
        running = bool(proc["p"] and proc["p"].poll() is None)
        if running and ports_after != ports_before:
            restarted = bool(_restart_proxy_locked("配置回滚"))
        if not restarted:
            restarted = _maybe_restart_for_allow_hosts(cfg, allow_before)
    except Exception as e:
        _emit_log(f"[panel] 回滚后端口检测失败: {e}")
    return jsonify({"ok": True, "config": cfg, "warnings": warnings,
                    "proxy_restarted": restarted, "restored_from": name})


@app.post("/api/config/disable_origin_check")
def api_disable_origin_check():
    """管理员自救接口：在提供有效 Token 的前提下，一键关闭 Origin 校验。"""
    try:
        with cfg_lock:
            cfg = load_config()
            cfg["origin_check"] = False
            saved = save_config(cfg)
        _emit_log("[panel] 管理员通过自救接口关闭了 Origin 校验")
        return jsonify({"ok": True, "message": "Origin 校验已成功关闭", "config": saved})
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


@app.get("/api/status")
def api_status():
    p = proc["p"]
    running = bool(p and p.poll() is None)
    # 注意：不要在这里写 state["proxy_running"]。
    # watchdog 以它为循环条件，api_status 每 2.5s 轮询一次，若代理瞬间退出
    # 会被轮询置 False 导致 watchdog 提前退出、不再自动拉起（曾停摆 45 分钟）。
    cfg = load_config()
    # 未运行时以配置为准：高级设置里切换捕获模式后顶栏应立刻反映，不必等下次启停
    capture_mode = (state.get("capture_mode") if running else None) or cfg.get("capture_mode", "reverse")
    # 端口监听一次 netstat 快照，绝不逐端口 _port_listen（0.3s×9≈3s，
    # 且每 2.5s 的裸 TCP 探测会刷爆 mitmdump 日志、掩盖崩溃现场）
    live_ports = set(_listening_port_pids({
        int(u.get("port") or 0) for u in (cfg.get("upstreams") or [])
        if 0 < int(u.get("port") or 0) <= 65535
    }))
    upstream_ports = []
    status_upstreams = []
    for u in cfg.get("upstreams") or []:
        port = int(u.get("port") or 0)
        status_u = {
            "name": u.get("name"),
            "port": port,
            "target": _safe_target(u.get("target")),
            "base_path": u.get("base_path") or "",
            "paths": [str(p).split("?", 1)[0].split("#", 1)[0] for p in (u.get("paths") or [])],
            "use_proxy": bool(u.get("use_proxy")),
        }
        status_upstreams.append(status_u)
        upstream_ports.append({
            "name": u.get("name"),
            "port": port,
            "listening": bool(running and port in live_ports),
            "url": f"http://127.0.0.1:{port}" if port else "",
            "target": _safe_target(u.get("target")),
        })
    return jsonify({
        "version": __version__,
        # 环境变量 token 被拒绝（太短/非 ASCII）：前端据此弹一次性横幅提醒
        # Docker 用户「设置的 MASKIT_PANEL_TOKEN 没生效」，否则只能翻容器日志
        "panel_token_env_rejected": PANEL_TOKEN_ENV_REJECTED,
        "panel_pid": os.getpid(),
        "proxy_running": running,
        "proxy_starting": bool(state.get("proxy_starting")),
        "proxy_stopping": bool(state.get("proxy_stopping")),
        "proxy_pid": state.get("proxy_pid") if running else None,
        "passthrough": bool(state.get("passthrough")),
        # 当前兜底形态："" / "passthrough"（明文直连）/ "error"（503 占位监听）。
        # 与 stop_mode（用户配置的意图）区分：这个是**此刻实际生效**的状态。
        "fallback_mode": str(state.get("fallback_mode") or ""),
        "upstream": _safe_target(state.get("upstream", "")),
        "capture_mode": capture_mode,
        "proxy_port": PROXY_PORT,
        "proxy_url": f"http://127.0.0.1:{PROXY_PORT}",
        "upstreams": status_upstreams,
        "upstream_ports": upstream_ports,
        "admin": is_admin(),
        "ca_cert_exists": CA_CERT.exists(),
        "uptime": int(time.time() - state["started_at"]) if running else 0,
        # 自动恢复提示：watchdog 自动重启成功时间戳 / 失败原因（前端横幅用）
        "auto_recovered_at": state.get("auto_recovered_at"),
        "auto_recover_fail": state.get("auto_recover_fail") or "",
        "data_root": str(DATA_ROOT),
        # 事件库大小（MiB）：高级设置/仪表盘展示存储占用，7 天保留提示
        "db_size_mib": round(_db_size_mib(), 1),
        "bundle_root": str(_BUNDLE_ROOT),
        "autostart": bool(cfg.get("autostart", False)),
        "filter_enabled": bool(cfg.get("filter_enabled", True)),
        "fail_closed": bool(cfg.get("fail_closed", True)),
        "response_scan": bool(cfg.get("response_scan", True)),
        "record_plaintext_words": bool(cfg.get("record_plaintext_words", True)),
        "stream_response": bool(cfg.get("stream_response", True)),
        "stream_exclude_hosts": cfg.get("stream_exclude_hosts") or [],
        "stop_mode": str(cfg.get("stop_mode") or "passthrough"),
        # 出口代理配置 + 实际会走代理的客户端数（UI 用来提示「配了但没人用」）
        "egress_proxy": {
            "enabled": bool((cfg.get("egress_proxy") or {}).get("enabled")),
            "url": _safe_target((cfg.get("egress_proxy") or {}).get("url")),
        },
        "model_prices": cfg.get("model_prices") or {},
        "price_sync_enabled": bool(cfg.get("price_sync_enabled", False)),
        "price_sync_url": _safe_target(cfg.get("price_sync_url")),
        "price_sync_interval_days": max(1, min(90, int(cfg.get("price_sync_interval_days", 7) or 7))),
        # 更新检查源（留空 = 内置源）：前端设置页回显用。走 _safe_target 剥掉
        # userinfo/query，避免用户把带凭据的镜像地址存进来后被状态接口回显出去。
        "update_check_url": _safe_target(cfg.get("update_check_url")),
        "egress_proxy_users": [u.get("name") for u in (cfg.get("upstreams") or [])
                               if u.get("use_proxy")],
        "debug": bool(cfg.get("debug", False)),
        "start_minimized": bool(cfg.get("start_minimized", False)),
        "auto_start_proxy": bool(cfg.get("auto_start_proxy", True)),
        "audit": cfg.get("audit", {}),
        # NER 开关 + 可用性：开启但模型/依赖缺失时必须让前端能提示，否则表现为"开了没效果"
        "ner": _ner_status_payload(cfg),
        "needs_ca": capture_mode != "reverse",
        # 首次运行向导：upstreams 恒被回填默认值，用不上它判断，改用显式标记
        "wizard_recommended": not bool(cfg.get("wizard_done")),
        "last_error": state.get("last_error", ""),
    })


@app.get("/api/autostart")
def api_autostart_get():
    return jsonify({"enabled": autostart_enabled()})


@app.post("/api/autostart")
def api_autostart_set():
    data = request.get_json(force=True) or {}
    enable = bool(data.get("enabled"))
    ok = set_autostart(enable)
    return jsonify({"ok": ok, "enabled": autostart_enabled()})


@app.post("/api/auto_recover/dismiss")
def api_auto_recover_dismiss():
    """关闭自动恢复横幅（成功提示/失败告警），仅清内存状态，不影响 watchdog。"""
    state["auto_recover_fail"] = ""
    state["auto_recovered_at"] = None
    return jsonify({"ok": True})


# ========== 2.0 审计 API ==========
def _extract_chat_text(raw_bytes):
    """从 chat completions JSON 响应提取模型回显文本（transparent 还原后）。"""
    try:
        data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
    except Exception:
        return ""
    # OpenAI chat
    for c in data.get("choices", []):
        msg = c.get("message", {})
        if isinstance(msg.get("content"), str):
            return msg["content"]
        if isinstance(msg.get("content"), list):
            for p in msg["content"]:
                if isinstance(p, dict) and isinstance(p.get("text"), str):
                    return p["text"]
        if isinstance(c.get("text"), str):
            return c["text"]
    # Anthropic
    if isinstance(data.get("content"), list):
        for b in data["content"]:
            if isinstance(b, dict) and isinstance(b.get("text"), str):
                return b["text"]
    if isinstance(data.get("output_text"), str):
        return data["output_text"]
    # OpenAI Responses API 非流式：data.output[].content[].text
    if isinstance(data.get("output"), list):
        for item in data["output"]:
            if isinstance(item, dict) and isinstance(item.get("content"), list):
                for blk in item["content"]:
                    if isinstance(blk, dict) and isinstance(blk.get("text"), str):
                        return blk["text"]
    return ""


def _arg_int(name, default, lo=0, hi=100000):
    """健壮解析整数 query 参数：非法值退回默认，不让请求 500。"""
    try:
        val = int(request.args.get(name, default))
    except Exception:
        val = default
    return max(lo, min(hi, val))


@app.get("/api/audit/events")
def api_audit_events():
    since = _arg_int("since", 0, 0, 2**31)
    limit = _arg_int("limit", 500, 1, 5000)
    floor = request.args.get("floor") or None
    signal = request.args.get("signal") or None
    evs = fetch_audit_events(since=since, limit=limit, severity_floor=floor, signal_filter=signal)
    return jsonify({"events": evs, "count": len(evs)})


@app.post("/api/audit/clear")
def api_audit_clear():
    return jsonify(clear_audit_events())


# 主动审计扫描任务状态（同步跑最坏近 9 分钟，必须异步化，否则界面直接假死）
audit_job = {
    "running": False,
    "started_at": 0,
    "done": 0,
    "total": 0,
    "phase": "",
    "cancel": False,
    "result": None,
    "error": "",
    # W1-4：本次扫描是否临时改动过 audit.active_probes；非 None = 结束后要恢复的值。
    # 必须进 _audit_scan_worker 的 finally 消费（异常/取消路径同样要恢复）。
    "restore_active_probes": None,
}
# 审计启动互斥锁（审计 AUDIT-002）：并发请求同时过 running 检查会启动两轮付费探针
_audit_start_lock = threading.Lock()

# ========== 模型价格同步（在线目录 → 本地缓存） ==========
# 价格不写死：默认从官网转接端点同步（国内可达，官网服务器转发 OpenRouter 全量目录），
# 失败自动回退 OpenRouter 直连 → 本地缓存 → 内置兜底表。
# 启动时后台同步一次 + 每 7 天自动刷新；新模型出现在目录里即自动收录，用户零操作。
# 转接端点响应格式与 OpenRouter /api/v1/models 相同（{data: [{id, pricing}]}）。
PRICE_CACHE_PATH = DATA_ROOT / "model_prices_cache.json"
DEFAULT_PRICE_SYNC_URL = "https://mask.ciyuanroute.com/api/model-prices"
_price_cache = None          # 内存缓存 {prices, synced_at, source}
_price_sync_lock = threading.Lock()
_price_sync_state = {"syncing": False, "last_error": "", "last_sync": 0, "model_count": 0}


def _load_price_cache_memory():
    """读价格缓存（内存优先，冷启动从文件加载一次）。"""
    global _price_cache
    if _price_cache is None:
        from shield_defaults import load_price_cache
        _price_cache = load_price_cache(PRICE_CACHE_PATH)
    return _price_cache


def _sync_prices_now(background=True, force=False):
    """同步在线价格目录到本地缓存。

    background=True 时后台线程执行（不阻塞调用方）；False 前台执行（手动同步）。
    force=True 时跳过开关校验（手动触发视同用户明确授权本次出站请求）。
    成功更新 _price_cache + _price_sync_state；失败只记 last_error，不清缓存。

    这里**不写配置**。原先手动同步成功后会把整份 `cfg`（同步开始时读的陈旧快照）
    写回磁盘，两个问题：
      1. 出站请求可能耗时 20-40 秒，窗口内用户在设置页的任何改动都会被整份覆盖；
      2. 它还会静默把 `price_sync_enabled` 置为 true，等于替用户打开「周期性出站」，
         而这个开关在设置页本来就有独立控件（且未登记在 SECURITY.md 出站清单）。
    手动同步就是一次同步，是否开启周期同步由用户自己拨那个开关。
    """
    def _do():
        with _price_sync_lock:
            if _price_sync_state["syncing"]:
                return
            _price_sync_state["syncing"] = True
        try:
            cfg = load_config()
            if not force and not cfg.get("price_sync_enabled", False):
                _price_sync_state["last_error"] = "价格同步已关闭（设置）"
                return
            from shield_defaults import fetch_openrouter_prices, save_price_cache
            # 多源回退：用户官网（国内可达）→ OpenRouter（海外，直连可能不通）
            # 逐个尝试，第一个成功即停；全部失败记最后一个错误，不清本地缓存。
            custom_url = str(cfg.get("price_sync_url") or "").strip()
            sources = ([custom_url] if custom_url else []) + [OPENROUTER_MODELS_URL]
            prices = None
            last_err = ""
            for url in sources:
                try:
                    prices = fetch_openrouter_prices(url)
                    if prices:
                        save_price_cache(PRICE_CACHE_PATH, prices, url)
                        global _price_cache
                        _price_cache = {"prices": prices, "synced_at": time.time(), "source": url}
                        _price_sync_state.update({
                            "last_error": "", "last_sync": time.time(), "model_count": len(prices),
                        })
                        break
                except Exception as e:
                    last_err = f"{_safe_target(url)}: {_safe_public_text(e, 120)}"
            if prices is None:
                _price_sync_state["last_error"] = last_err
        except Exception as e:
            _price_sync_state["last_error"] = _safe_public_text(e, 200)
        finally:
            _price_sync_state["syncing"] = False

    if background:
        threading.Thread(target=_do, daemon=True).start()
    else:
        _do()


def _price_sync_loop():
    """价格定期复查循环：每 6h 调一次 _maybe_auto_sync_prices（内部自判是否过期）。

    用 Timer 自续期而不是常驻 while 循环：单次检查抛异常也不会杀死循环线程。
    """
    try:
        _maybe_auto_sync_prices()
    except Exception:
        pass
    t = threading.Timer(6 * 3600, _price_sync_loop)
    t.daemon = True
    t.start()


def _maybe_auto_sync_prices():
    """启动/定时触发：缓存缺失或超过配置间隔未同步 → 后台刷新。

    间隔取 config.price_sync_interval_days（默认 7 天，用户可配 1/3/7/30），
    不硬编码常量——价格目录更新节奏各家不同，用户自己定。
    """
    try:
        interval = 7
        try:
            interval = int((load_config().get("price_sync_interval_days") or 7))
            interval = max(1, min(90, interval))
        except Exception:
            interval = 7
        cache = _load_price_cache_memory()
        if cache is None:
            _sync_prices_now(background=True)
            return
        synced_at = float(cache.get("synced_at") or 0)
        if time.time() - synced_at > interval * 86400:
            _sync_prices_now(background=True)
    except Exception:
        pass


@app.get("/api/prices/status")
def api_prices_status():
    """价格同步状态（前端展示来源/时间/模型数）。"""
    try:
        cache = _load_price_cache_memory()
        state = dict(_price_sync_state)
        state["synced_at"] = state.pop("last_sync", 0) or (float(cache.get("synced_at") or 0) if cache else 0)
        state["model_count"] = state["model_count"] or (len(cache.get("prices") or {}) if cache else 0)
        state["source"] = (cache or {}).get("source") or ""
        state["builtin_count"] = len(MODEL_PRICES)
        return jsonify(state)
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


@app.post("/api/prices/sync")
def api_prices_sync():
    """手动触发价格同步（前台执行，等结果返回）。"""
    try:
        _sync_prices_now(background=False, force=True)
        state = dict(_price_sync_state)
        if state.get("last_error"):
            return jsonify({"ok": False, "error": state["last_error"], "state": state}), 502
        return jsonify({"ok": True, "state": state})
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


@app.get("/api/prices/list")
def api_prices_list():
    """价格明细（「查看模型价格」弹窗数据源）：在线同步目录 + 用户自配覆盖。

    返回 [{model, input, output, cache_read?, cache_write?}]，按模型名排序。
    cache_read = 缓存命中输入价、cache_write = 缓存写入价（部分模型才有），仅展示用。
    """
    try:
        cache = _load_price_cache_memory()
        cache_prices = (cache or {}).get("prices") or {}
        overrides = (load_config().get("model_prices") or {})
        merged = {**cache_prices, **overrides}
        models = []
        for model, price in merged.items():
            entry = {"model": str(model)}
            if isinstance(price, dict):
                try:
                    entry["input"] = round(float(price.get("input") or 0), 6)
                except (TypeError, ValueError):
                    entry["input"] = 0.0
                try:
                    entry["output"] = round(float(price.get("output") or 0), 6)
                except (TypeError, ValueError):
                    entry["output"] = 0.0
                cr = price.get("cache_read")
                if cr is not None:
                    try:
                        entry["cache_read"] = round(float(cr), 6)
                    except (TypeError, ValueError):
                        pass
                cw = price.get("cache_write")
                if cw is not None:
                    try:
                        entry["cache_write"] = round(float(cw), 6)
                    except (TypeError, ValueError):
                        pass
            models.append(entry)
        models.sort(key=lambda x: x["model"])
        return jsonify({"ok": True, "count": len(models), "models": models})
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


# ========== 版本更新检查（服务端探测） ==========
# 为什么必须由服务端出网：Web / Docker 部署下，出网能力属于**服务器**，而原先前端是拿
# **访问者的浏览器**去 fetch api.github.com —— 国内用户浏览器直连必然 NetworkError
# （表现为「检查更新失败：TypeError: NetworkError...」），跟服务器能不能通毫无关系。
# 服务端探测后，浏览器只需问自己的服务器要结果。
DEFAULT_UPDATE_API_URL = "https://api.github.com/repos/xiaYuTian11/maskit/releases/latest"
# 静态 release 资产（由 scripts/generate-latest-json.py 产出）比走 API 更好：
# ① 不计入 GitHub 匿名 API 限流（60 次/小时/IP，多人共用一个服务器出口很容易打满）；
# ② 内容就是面板要的 version / notes / pub_date。
# 但它只在**已签名**的正式版 Release 上产出（见 release.yml），拿不到时回落 API。
DEFAULT_UPDATE_STATIC_URL = "https://github.com/xiaYuTian11/maskit/releases/latest/download/latest.json"
UPDATE_CHECK_TTL = 600          # 10 分钟缓存：把多人共用出口的 API 消耗从「每次点击一次」压到 ~6 次/小时
UPDATE_CHECK_TIMEOUT = 15       # 比前端原来的 6s 宽——跨境请求 6s 太容易误判成失败
_update_check_cache = {"data": None, "at": 0.0}
_update_check_lock = threading.Lock()


def _fetch_update_source(url, timeout=UPDATE_CHECK_TIMEOUT):
    """GET 一个更新源，返回 (归一化后的 dict, 错误文本)。

    两种响应格式都接受并归一化：
      - GitHub API:  {tag_name, body, published_at}
      - latest.json: {version, notes, pub_date}
    这正是「换源不用改前端」的落点——前端只认 version/notes/pub_date 三个字段。
    """
    import json as _json
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github.v3+json, application/json",
        "User-Agent": "Maskit-UpdateCheck/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(256 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, _safe_public_text(e, 120)

    try:
        payload = _json.loads(raw)
    except Exception:
        return None, "响应不是合法 JSON"
    if not isinstance(payload, dict):
        return None, "响应格式不是对象"

    # 两种字段名都认（latest.json 用 version，GitHub API 用 tag_name）
    version = str(payload.get("version") or payload.get("tag_name") or "").strip()
    if not version:
        return None, "响应缺少版本字段"
    return {
        "version": version,
        "notes": str(payload.get("notes") or payload.get("body") or ""),
        "pub_date": str(payload.get("pub_date") or payload.get("published_at") or ""),
    }, ""


@app.get("/api/update/check")
def api_update_check():
    """服务端探测最新版本。多源回退 + TTL 缓存 + 明确错误语义。

    源顺序：用户自定义 URL（若配）→ 静态 latest.json → GitHub API。
    第一个成功即用；全部失败返回 502 + 可读原因，而不是把原始异常抛给用户。
    结果缓存 10 分钟：GitHub 匿名 API 限流 60 次/小时/IP，多人共用一个服务器出口时
    每次点击都打一次必然打满，缓存后降到 ~6 次/小时。
    """
    now = time.time()
    with _update_check_lock:
        cached = _update_check_cache["data"]
        if cached and now - _update_check_cache["at"] < UPDATE_CHECK_TTL:
            return jsonify({"ok": True, "cached": True, **cached})

    try:
        cfg = load_config()
    except Exception:
        cfg = {}
    custom = _normalize_update_check_url((cfg or {}).get("update_check_url"))
    sources = ([custom] if custom else []) + [DEFAULT_UPDATE_STATIC_URL, DEFAULT_UPDATE_API_URL]

    last_err, data, used = "", None, ""
    for url in sources:
        got, err = _fetch_update_source(url)
        if got:
            data, used = got, url
            break
        last_err = err

    if data is None:
        _emit_log(f"[panel] 更新检查失败（{len(sources)} 个源均不可用）: {last_err}")
        return jsonify({
            "ok": False,
            "error": "无法连接更新服务，请检查网络或在设置中配置更新检查源",
            "detail": last_err,
        }), 502

    data["source"] = used
    with _update_check_lock:
        _update_check_cache.update({"data": data, "at": now})
    return jsonify({"ok": True, "cached": False, **data})


@app.get("/api/audit/job")
def api_audit_job():
    """轮询扫描进度。前端据此显示进度与结果，刷新页面也能接回。"""
    return jsonify(_public_audit_job())


def _public_audit_job():
    """对外可见的 job 状态：`cancel` 是服务端标志，`restore_active_probes`
    是 W1-4 的内部恢复账目（已弹走），都不属于前端契约。"""
    return {k: v for k, v in audit_job.items()
            if k not in ("cancel", "restore_active_probes")}


@app.post("/api/audit/cancel")
def api_audit_cancel():
    if not audit_job["running"]:
        return jsonify({"ok": False, "error": "没有正在运行的扫描"})
    audit_job["cancel"] = True
    return jsonify({"ok": True})


@app.post("/api/audit/run")
def api_audit_run():
    """触发主动审计扫描（后台线程执行，立即返回；进度走 /api/audit/job）。"""
    data = request.get_json(force=True) or {}
    if not data.get("confirm"):
        return jsonify({
            "ok": False,
            "error": "需 confirm=true 二次确认（探针会发真实请求消耗 token）",
            "estimated_tokens": "~15-30k tokens（general profile 17 步探针）",
        }), 400
    # 并发防护（审计 AUDIT-002）：检查 running 与置位之间必须有锁，
    # 否则两个并发请求可能同时通过检查、启动两轮付费探针。
    with _audit_start_lock:
        if audit_job["running"]:
            return jsonify({"ok": False, "error": "已有扫描在运行", "job": _public_audit_job()}), 409
        upstream_name = str(data.get("upstream_name") or "").strip()
        model = str(data.get("model") or "claude-3-5-sonnet").strip()
        profile = str(data.get("profile") or "general").strip()
        if profile not in ("general", "web3", "full"):
            profile = "general"
        cfg = load_config()
        # 主动探针开关必须为真，否则整轮扫描是「花钱买一份假报告」：
        # 探针会真的发出请求并消耗 token，但 transparent 只在 AUDIT_ACTIVE_PROBES
        # 为真时才评估跨请求污染（D1/S7），关着的时候 D1 恒判「无异常」。
        # 与其给出一个从未执行的检查的「通过」，不如先拒绝并告诉用户怎么开。
        audit_cfg = cfg.get("audit") if isinstance(cfg.get("audit"), dict) else {}
        # 主动探针开关必须为真，否则整轮扫描是「花钱买一份假报告」：
        # 探针会真的发出请求并消耗 token，但 transparent 只在 AUDIT_ACTIVE_PROBES
        # 为真时才评估跨请求污染（D1/S7），关着的时候 D1 恒判「无异常」。
        # 与其给出一个从未执行的检查的「通过」，不如先拒绝并告诉用户怎么开。
        #
        # W1-4：关状态下 UI 不再吃 400 —— 前端确认弹窗里写明「将临时启用 +
        # 运行结束后自动恢复」，确认后带 `allow_temp_probes=true` 发起。
        # **不携带该标志的调用方（脚本/旧客户端）仍按原逻辑 400**：
        # 这是有意的兼容策略，不静默改变第三方调用者的行为。
        need_temp_enable = not audit_cfg.get("active_probes")
        if need_temp_enable and not data.get("allow_temp_probes"):
            return jsonify({
                "ok": False,
                "error": "主动探针未启用（设置 → 安全审计 → 主动探针）。"
                         "关闭状态下探针仍会发出并计费，但跨请求污染（D1）不会被评估、恒显示「无异常」，"
                         "等于拿一份假报告。请先启用再运行扫描。",
            }), 400
        target = None
        for u in cfg.get("upstreams") or []:
            if u.get("name") == upstream_name:
                target = u
                break
        if not target:
            return jsonify({"ok": False, "error": f"未找到 upstream: {_safe_public_text(upstream_name, 160)}"}), 400
        if not (proc["p"] and proc["p"].poll() is None):
            return jsonify({"ok": False, "error": "代理未运行，先启动代理"}), 400
        if not int(target.get("port") or 0):
            return jsonify({"ok": False, "error": "upstream 端口非法"}), 400
        # 临时启用必须在**全部校验通过之后**才写盘：任一 400 提前返回时
        # 配置都不能留下 active_probes=true 的脏状态。
        restore_to = None
        if need_temp_enable:
            restore_to = False
            _set_audit_active_probes(True)
            _emit_log("[panel] 主动探针已临时启用（扫描结束后自动恢复为关闭）")
        audit_job.update({
            "running": True, "started_at": time.time(), "done": 0, "total": 0,
            "phase": "准备探针", "cancel": False, "result": None, "error": "",
            # W1-4：待恢复的原值（None = 本次没动过该开关，finis 时无需处理）
            "restore_active_probes": restore_to,
        })
        threading.Thread(
            target=_audit_scan_worker,
            args=(target, upstream_name, model, profile, cfg),
            daemon=True,
        ).start()
    return jsonify({"ok": True, "started": True})


def _set_audit_active_probes(value):
    """把 `audit.active_probes` 写盘（只动这一个字段，不整表覆盖）。

    W1-4 的两处调用：临时启用前置 true；扫描结束的 `finally` 里恢复原值。
    必须走整份配置的读写改写（而不是写单字段文件），因为 transparent 的热重载
    按 config.json 的 mtime 触发，且 `save_config` 会做归一化与备份。
    """
    cfg = load_config()
    audit = dict(cfg.get("audit") or {})
    audit["active_probes"] = bool(value)
    cfg["audit"] = audit
    save_config(cfg)


def _audit_scan_worker(target, upstream_name, model, profile, cfg):
    """后台执行主动审计扫描，进度写 audit_job。"""
    try:
        result = _run_audit_scan(target, upstream_name, model, profile, cfg)
        audit_job["result"] = result
    except Exception as e:
        audit_job["error"] = _safe_public_text(e, 300)
        _emit_log(f"[audit] 扫描失败: {_safe_public_text(e, 200)}")
    finally:
        # W1-4：临时启用的探针开关必须恢复原值。放 finally 才能兼顾
        # 「正常跑完 / 抛异常 / 用户中途取消」三条路径（前端恢复会被刷新/关页漏掉）。
        restore = audit_job.pop("restore_active_probes", None)
        if restore is not None:
            try:
                cur = (load_config().get("audit") or {}).get("active_probes")
                # 只有「仍是我们临时置为 true 的那份」才恢复：用户在扫描期间手改了
                # 该开关时以用户为准，不静默覆盖用户的安全设置。
                if cur is True:
                    _set_audit_active_probes(restore)
                    _emit_log("[panel] 主动探针开关已恢复为扫描前的原值")
            except Exception as e:
                _emit_log(f"[panel] 恢复主动探针开关失败: {_safe_public_text(e, 200)}")
        audit_job["running"] = False
        audit_job["phase"] = "已完成" if not audit_job["error"] else "失败"


def _run_audit_scan(target, upstream_name, model, profile, cfg):
    """发合成探针过代理，结果落 audit_events + Markdown 报告。

    在后台线程执行：探针是串行真实请求（每个 timeout 30s），放在请求线程里
    最坏能把界面卡死近 9 分钟。参数已由调用方校验。
    """
    # 构造探针计划
    plan = audit_eng.build_probe_plan(upstream_name, model, profile)
    probe_ids = [p["probe_id"] for p in plan]
    # 逐个发请求过代理（用 urllib，走 127.0.0.1:port）
    import urllib.request as ur
    port = int(target.get("port") or 0)
    base_url = f"http://127.0.0.1:{port}"
    # 探针打的是本地端口，出口代理由引擎按 upstream 决定；这里必须禁用 urllib 的
    # 环境变量代理，否则用户设了 HTTP_PROXY 时连 127.0.0.1 都会被塞进代理，
    # 审计探针全部发送失败（且会被 coverage 判成 INCONCLUSIVE，看起来像上游有问题）。
    _probe_opener = ur.build_opener(ur.ProxyHandler({}))
    sent = 0
    audit_job["total"] = len(plan)
    audit_job["phase"] = "发送探针"
    floor = str(cfg.get("audit", {}).get("severity_floor") or "MEDIUM").upper()
    # 实际发送成功的探针集合：连发送都失败的（上游不可达/超时）不入 coverage，
    # 供 aggregate_step_findings 判 INCONCLUSIVE
    sent_probe_ids = set()
    for item in plan:
        if audit_job.get("cancel"):
            audit_job["phase"] = "已取消"
            break
        body = item["request_body"]
        # canary nonce 通过 header 注入 transparent 钩子（不进 request body）；
        # 畸形 JSON 探针的 body 是原始非法 JSON 字符串，不能 json.dumps 再包裹——
        # 避免把 "{not valid json" 序列化成合法 JSON 字符串字面量导致探针失效。
        if isinstance(body, dict):
            canaries = body.pop("_audit_canaries", None) or []
            req_body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, (str, bytes)):
            canaries = []
            req_body = body.encode("utf-8") if isinstance(body, str) else body
        else:
            canaries = []
            req_body = str(body).encode("utf-8")
        headers = {"content-type": "application/json"}
        headers.update(item.get("headers") or {})
        # 注入 probe_id + canaries 给 transparent 钩子
        headers["X-Shield-Probe-Id"] = item["probe_id"]
        if canaries:
            headers["X-Shield-Canaries"] = ",".join(canaries)
        path = item.get("path_override") or "/v1/chat/completions"
        # error trigger 的 unknown_endpoint 用 path_override
        if "_path_override" in headers:
            path = headers.pop("_path_override")
        actual_text = ""
        try:
            req = ur.Request(f"{base_url}{path}", data=req_body, headers=headers, method="POST")
            with _probe_opener.open(req, timeout=30) as resp:
                raw = resp.read()  # transparent 已还原的 body
                actual_text = _extract_chat_text(raw)
            sent += 1
            sent_probe_ids.add(item["probe_id"])
        except ur.HTTPError as e:
            # 4xx/5xx（error trigger 预期）— body 可能含泄漏，transparent 钩子已扫
            sent += 1
            sent_probe_ids.add(item["probe_id"])
            try:
                actual_text = _extract_chat_text(e.read())
            except Exception:
                pass
        except Exception as e:
            sent += 1
            sent_probe_ids.add(item["probe_id"])
            _emit_log(f"[audit] 探针 {item['probe_id']} 请求异常（可能预期）: {_safe_public_text(e, 120)}")
        # S3 tool-call echo 比对：expected vs actual（带 severity_floor 过滤，与 transparent 路径对齐）
        if item["step"] == "step8_toolcall" and item.get("meta", {}).get("expected") and actual_text:
            expected = item["meta"]["expected"]
            findings = audit_eng.sig.scan_tool_call_rewrite(expected, actual_text)
            for f in findings:
                if not audit_eng.sig.severity_ge(f.get("severity", "MEDIUM"), floor):
                    continue
                enqueue_audit_event({
                    "sid": item["probe_id"],
                    "host": _safe_target(target.get("target")) or _safe_upstream_display(upstream_name),
                    "method": "POST",
                    "path": path,
                    "signal_type": f.get("signal", "tool_call_rewrite"),
                    "severity": f.get("severity", "MEDIUM"),
                    "evidence": _safe_public_text(f.get("evidence", ""), 500),
                    "probe_id": item["probe_id"],
                })
        audit_job["done"] = sent

    # 收集结果前等待子进程 transparent 审计事件落库（跨进程：父子各自 _audit_queue，
    # flush_audit_queue 只 flush 父进程 S3 队列；子进程被动信号由其 writer 异步写 DB，
    # 这里 sleep 给子进程 writer 时间落库，再重试 collect 几次直到事件数稳定）
    try:
        flush_audit_queue()
    except Exception:
        pass
    audit_job["phase"] = "汇总结果"
    time.sleep(1.5)  # 给子进程 writer 落库窗口
    findings_by_probe = audit_eng.collect_findings_by_probe(probe_ids)
    # 重试：直到 probe 事件数稳定或超 5 轮（每轮 0.5s）
    prev_total = sum(len(v) for v in findings_by_probe.values())
    for _ in range(5):
        time.sleep(0.5)
        findings_by_probe = audit_eng.collect_findings_by_probe(probe_ids)
        cur_total = sum(len(v) for v in findings_by_probe.values())
        if cur_total == prev_total:
            break
        prev_total = cur_total
    # 传入实际执行的 step 集合：web3 探针可选，缺省步骤集不适用；
    # sent_probe_ids 区分「发送失败无回执」与「正常无异常」——
    # aggregate_matrix 据此算覆盖完整性（避免全部步骤无回执时被误判为 MEDIUM）
    step_findings = audit_eng.aggregate_step_findings(plan, findings_by_probe, sent_probe_ids=sent_probe_ids)
    matrix = audit_eng.aggregate_matrix(step_findings, {p["step"] for p in plan})
    # 渲染报告
    audit_job["phase"] = "生成报告"
    md = audit_eng.render_markdown_report(
        _safe_target(target.get("target")) or _safe_upstream_display(upstream_name),
        model,
        matrix,
        step_findings,
    )
    report_path = audit_eng.save_report(md, str(DATA_ROOT))
    _emit_log(f"[audit] 扫描完成：{sent}/{len(plan)} 探针，风险等级 {matrix['severity']}")
    return {
        "ok": True,
        "sent": sent,
        "plan_size": len(plan),
        "cancelled": bool(audit_job.get("cancel")),
        "severity": matrix["severity"],
        "matrix": matrix,
        "report_path": report_path,
        "step_findings": step_findings,
    }


@app.get("/api/audit/report/latest")
def api_audit_report_latest():
    """返回最新报告文件路径与内容。"""
    import glob
    files = sorted(glob.glob(str(DATA_ROOT / "audit-*.md")), reverse=True)
    if not files:
        return jsonify({"ok": False, "error": "无报告"}), 404
    p = files[0]
    try:
        content = Path(p).read_text(encoding="utf-8")
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500
    return jsonify({"ok": True, "path": p, "content": content})


@app.get("/api/health")
def api_health():
    result = health_check()
    try:
        # 写线程健康指标（审计要求可观测：队列长度/死信/丢弃/存活）
        from event_store import writer_stats
        result["writer_stats"] = writer_stats()
    except Exception:
        pass
    try:
        # NER 不可用（模型/依赖缺失）必须在健康检查里可见，不能只留在一条日志里
        result["ner"] = _ner_status_payload(load_config())
    except Exception:
        pass
    return jsonify(result)


@app.post("/api/proxy/start")
def api_start():
    ok, err = start_proxy()
    return jsonify({"ok": ok, "error": err})


@app.post("/api/proxy/stop")
def api_stop():
    # skip_fallback=1：App 退出专用——不挂兜底监听（见 _stop_proxy_locked 尾部注释），
    # 消除「退出后 3 秒明文直连窗口」。用户在面板/托盘手动停止不带此参数，
    # 仍走完整 stop_mode 语义（兜底直连 / 503 / 断连）。
    skip = request.args.get("skip_fallback") == "1"
    if not skip:
        body = request.get_json(silent=True)
        skip = isinstance(body, dict) and body.get("skip_fallback") is True
    ok, err = stop_proxy(skip_fallback=skip)
    return jsonify({"ok": ok, "error": err})


@app.get("/api/logs")
def api_logs():
    if time.time() - _last_log_prune[0] > 3600:
        prune_event_log()
        _last_log_prune[0] = time.time()
    since = _arg_int("since", 0, 0, 2**31)
    limit = _arg_int("limit", 500, 1, 1000)
    # 默认显示全部事件（含 SKIP/PASS 噪声）。曾默认 '1' 隐藏，用户会误以为日志丢了。
    sensitive_only = request.args.get("sensitive", "0") != "0"
    query = request.args.get("q", "")
    # 全文搜索开关：默认只搜结构化列（host/path/method/status/type），
    # payload LIKE 全表扫描仅在用户显式勾选「全文搜索（全库）」时启用。
    fulltext = request.args.get("fulltext", "0") != "0"
    event_type = request.args.get("type", "").strip().upper() or None
    if event_type and not re.fullmatch(r"[A-Z_]{1,32}", event_type):
        event_type = None
    # 入口维度过滤（proxy / ext）。**不改 event_type 也没有源码兼容问题**：
    # fetch_events 对非法/空值不过滤，老前端不带这个参数行为完全不变。
    # 前端把入口筛选落 URL query（可分享/可回退），加上首页词条跳转带的 &ingress=，
    # 「词条 ×N」与「点进去的日志条数」才是同一个口径。
    ingress = request.args.get("ingress", "").strip().lower() or None
    # 合法值集合与写入侧**同源**（`event_store.INGRESS_VALUES`）：早先这里手抄了
    # ("proxy", "ext")，一旦将来新增入口（比如 `ext2`）就会出现「事件写得进去、
    # 但筛选永远筛不出来」的静默不一致。非法值一律当"不过滤"，老前端不带参数行为不变。
    if ingress not in INGRESS_VALUES:
        ingress = None
    # First load shows the latest page; subsequent polls consume the oldest unseen
    # records. Fetch one extra row to tell the client whether it needs to catch up.
    incremental = since > 0
    ev = fetch_events(since=since, limit=limit + int(incremental), sensitive_only=sensitive_only,
                      query=query, fulltext=fulltext, event_type=event_type,
                      max_limit=1001, ascending=incremental, ingress=ingress)
    has_more = incremental and len(ev) > limit
    ev = ev[:limit]
    next_since = ev[-1]["seq"] if ev else since
    # slim：剔除只有详情弹窗才用的正文字段。这四个字段占 events 体积 79%
    # （dialog 34% + dialog_req 28% + resp_preview 9% + req_preview 8%），
    # 而列表行一个都不渲染。全量 1000 条实测 8.2MB → slim 后约 1.7MB。
    # 搜索框每敲一次（250ms 防抖）就是一次 full 刷新，不砍会持续拖垮面板。
    # 弹窗改由 /api/logs/detail 按 seq 单条回源取全量。
    if request.args.get("slim", "0") != "0":
        _HEAVY = ("dialog", "dialog_req", "dialog_resp", "req_preview", "resp_preview")
        slim_ev = []
        for e in ev:
            d = {k: v for k, v in e.items() if k not in _HEAVY}
            # items[].original 是敏感明文：列表行只展示 label 徽章与打码 preview，
            # 明细走 /api/logs/detail 回源全量，列表不直接下发 items 数组明文。
            its = d.get("items")
            if isinstance(its, list):
                d["items"] = [
                    {"label": str(i.get("label") or ""), "preview": str(i.get("preview") or "")}
                    for i in its if isinstance(i, dict)
                ]
            slim_ev.append(d)
        ev = slim_ev
    else:
        # 非 slim：整条 payload（含 dialog / *_preview / items[].original）直接下发，
        # 读侧必须兜一道凭据清洗（审计 B1）。三个理由：
        #   1) 扩展链路此前**写侧漏了清洗**，库里有凭据原文（现已修，但存量还在）；
        #   2) 升级用户的历史库里本来就有 CONNSTR / PRIVATE_KEY 等遗留明文；
        #   3) /api/logs 是按行原样回源的，不清洗等于把 API Key 渲染给任何持令牌的调用方。
        # 与 /api/logs/detail 同源（同一函数），口径一致。
        # **只清凭据**：普通 PII 的 original 照常下发 —— 详情弹窗的
        # 「脱敏 ↔ 原文」对照靠它，这条能力不能动。
        # 开销实测 0.27ms/条（dialog 约 2KB），1000 条约 0.3s，可接受；
        # 前端列表走 slim，这条路径只在直接调接口 / 老前端时命中。
        ev = [_scrub_legacy_event(e) for e in ev]
    # 附加估算费用（model × usage，价格来自在线同步目录 + 用户自配），
    # 供日志列表展示「本次请求费用」。纯数字字段，无敏感信息。
    try:
        from shield_defaults import estimate_cost
        _price_cache2 = (_load_price_cache_memory() or {}).get("prices") or {}
        _overrides2 = (load_config().get("model_prices") or {})
        for _e in ev:
            if _e.get("type") in ("RESTORE", "PASS"):
                _usage = _e.get("usage")
                if isinstance(_usage, dict):
                    _cost, _ = estimate_cost(
                        _e.get("model") or "",
                        _usage.get("prompt_tokens") or 0,
                        _usage.get("completion_tokens") or 0,
                        _overrides2, _price_cache2)
                    _e["cost_usd"] = round(_cost, 4)
    except Exception:
        pass
    with buf_lock:
        # 注意：内存 events 的 seq 与 SQLite 自增 id 不是同一命名空间，
        # 不能拿 since 去筛内存事件做兜底（会漏或重复），只回传原始日志尾巴。
        raw_tail = list(log_buf)[-200:]
    # 锁外做脱敏（避免持锁解析 JSON）：SHIELD 行只回传白名单字段
    tail = [_tail_line_sanitize(x) for x in raw_tail]
    try:
        retention = _normalize_retention(load_config().get("log_retention_days", LOG_RETENTION_DAYS))
    except Exception:
        retention = LOG_RETENTION_DAYS
    # 游标重置检测：清空日志（sqlite_sequence 重置）或损坏库隔离重建后 id 从 1
    # 重新开始，已打开的 Logs 页 cursor 仍是旧的高值 → `id > since` 永远空集，
    # 新日志一条不显示、用户误判代理不工作。给前端一个 reset 标志重新从 0 拉取。
    reset = False
    try:
        reset = incremental and next_since <= since and db_max_event_id() < since
    except Exception:
        reset = False
    return jsonify({
        "events": ev,
        "tail": tail,
        "retention_days": retention,
        "store": "sqlite",
        "db": str(DB_PATH),
        "sensitive_only": sensitive_only,
        "total": len(ev),
        "has_more": has_more,
        "next_since": next_since,
        "reset": reset,
    })


@app.get("/api/logs/detail")
def api_log_detail():
    """按 seq 取单条事件全量（含 dialog/preview 等正文字段）。

    列表用 ?slim=1 拿轻量数据（省掉 79% 体积），点开弹窗时才回源取这一条，
    避免为了极少数被点开的行、把上千条正文全量下发。
    """
    seq = _arg_int("seq", 0, 0, 2**31)
    if seq <= 0:
        return jsonify({"ok": False, "error": "缺少 seq"}), 400
    # 必须精确按 id 取：fetch_events 是 id > since 且 ORDER BY id DESC，
    # 用 since=seq-1&limit=1 会拿到集合里最大的那条（不是 seq 本身），实测 404。
    row = fetch_event_by_id(seq)
    if row is None:
        return jsonify({"ok": False, "error": "事件不存在或已过保留期"}), 404
    # 读侧凭据清洗：升级用户的历史库里仍有写侧修复之前落下的凭据明文，
    # 按 id 原样回源会把它们直接渲染进详情弹窗（见 _scrub_legacy_event）。
    scrubbed = _scrub_legacy_event(row)
    # 若本事件属于成对往返链路（带 sid），自动从同会话的配对事件补充缺失明细
    # （例如 RESTORE 补充 MASK 的 items 与 prompt，或 MASK 补充 RESTORE 的还原数与回答）
    sid = scrubbed.get("sid")
    if sid:
        sibling = fetch_sibling_event(sid, exclude_id=seq)
        if sibling:
            sib_scrubbed = _scrub_legacy_event(sibling)
            if not scrubbed.get("items") and sib_scrubbed.get("items"):
                scrubbed["items"] = sib_scrubbed["items"]
            if not scrubbed.get("dialog_req") and sib_scrubbed.get("dialog_req"):
                scrubbed["dialog_req"] = sib_scrubbed["dialog_req"]
            if not scrubbed.get("dialog") and sib_scrubbed.get("dialog"):
                scrubbed["dialog"] = sib_scrubbed["dialog"]
            if not scrubbed.get("req_preview") and sib_scrubbed.get("req_preview"):
                scrubbed["req_preview"] = sib_scrubbed["req_preview"]
            if not scrubbed.get("resp_preview") and sib_scrubbed.get("resp_preview"):
                scrubbed["resp_preview"] = sib_scrubbed["resp_preview"]
            if scrubbed.get("restored") is None and sib_scrubbed.get("restored") is not None:
                scrubbed["restored"] = sib_scrubbed["restored"]
    return jsonify({"ok": True, "event": scrubbed})


@app.get("/api/stats/today")
def api_stats_today():
    try:
        # range 参数：today(默认)|7d|30d 或数字N天。过0点后「今天」清零，
        # 用户可切「近7天」看昨天的数据。
        rng = request.args.get("range", "today")
        if rng and rng != "today":
            if rng == "7d":
                return jsonify(stats_range(days=7))
            elif rng == "30d":
                return jsonify(stats_range(days=30))
            else:
                try:
                    n = int(rng)
                    if n > 1:
                        return jsonify(stats_range(days=n))
                except ValueError:
                    pass
        return jsonify(today_stats())
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


@app.get("/api/stats/today/restore-items")
def api_stats_today_restore_items():
    """今日成功还原的敏感项明细（统计弹窗数据源）。

    由 event_store.fetch_restore_items 从当日 RESTORE 事件 payload 聚合，
    口径与 daily_words（只收 MASK）互补，避免同一敏感项双计；凭据类
    （API_KEY/TOKEN/SECRET/ACCESS_KEY/JWT）恒只返回 preview，不落 original。
    """
    try:
        limit = int(request.args.get("limit", 200))
    except Exception:
        limit = 200
    try:
        return jsonify(fetch_restore_items(limit=limit))
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


@app.get("/api/stats/history")
def api_stats_history():
    """历史统计（数据统计页柱状图/折线图数据源）。

    参数：
        days: 天数（day 粒度时为天数，hour 粒度时为小时数，默认 30 天/72 小时）
        granularity: day | hour（默认 day）
    """
    try:
        from event_store import stats_history
        days = int(request.args.get("days", 30))
        granularity = request.args.get("granularity", "day")
        return jsonify(stats_history(days=days, granularity=granularity))
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


@app.get("/api/stats/highlights")
def api_stats_highlights():
    """战绩卡片数据源：近 N 天的总量 + 按规则标签的命中分布。

    只出**聚合数字**，绝不含命中原文——这张卡是用来分享出去的，
    带一个词都可能把用户的公司名/客户名晒到公网上。
    label_summary 只读 daily_words 的 label 与 cnt 两列，不碰 word。
    """
    try:
        from event_store import stats_history, label_summary
        days = max(1, min(int(request.args.get("days", 7)), 90))
        rows = stats_history(days=days, granularity="day").get("data", [])
        total = {
            "requests": sum(int(r.get("requests") or 0) for r in rows),
            "mask_events": sum(int(r.get("mask_events") or 0) for r in rows),
            "restored": sum(int(r.get("restored") or 0) for r in rows),
            "tokens_prompt": sum(int(r.get("tokens_prompt") or 0) for r in rows),
            "tokens_completion": sum(int(r.get("tokens_completion") or 0) for r in rows),
        }
        labels = label_summary(days=days)
        return jsonify({
            "ok": True, "days": days,
            "total": total,
            "masked_items": sum(labels.values()),
            "labels": labels,
            "daily": [{"label": r.get("label"), "mask_events": r.get("mask_events")} for r in rows],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


@app.get("/api/stats/models")
def api_stats_models():
    """按模型聚合使用量 + 费用估算（「模型排行」数据源）。

    参数：days 统计窗口（默认 7 天）。
    返回 {"models": [{model, requests, prompt, completion, cost_usd, priced}]}。
    费用按内置价格表 + 用户自配（config.model_prices）估算，未定价模型 priced=false。
    """
    try:
        from event_store import stats_models
        from shield_defaults import estimate_cost
        days = int(request.args.get("days", 7))
        cfg = load_config()
        overrides = cfg.get("model_prices") or {}
        cache = _load_price_cache_memory()
        cache_prices = (cache or {}).get("prices") or {}
        models = stats_models(days=days)
        out = []
        for m in models:
            cost, price = estimate_cost(m["model"], m["prompt"], m["completion"], overrides, cache_prices)
            m["cost_usd"] = cost
            m["priced"] = price is not None
            out.append(m)
        return jsonify({"ok": True, "days": days, "models": out})
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


@app.get("/api/logs/export")
def api_logs_export():
    """导出近期事件为 JSON。默认脱敏：items[].original（明文）一律剔除，
    只留 preview/length/hash/label/tok（与 README「日志不记录原始敏感值」的导出
    口径一致）。凭据类本来就只有打码 preview，无明文可导。"""
    try:
        limit = int(request.args.get("limit", 2000))
    except Exception:
        limit = 2000
    limit = max(1, min(limit, EXPORT_MAX))
    sensitive_only = request.args.get("sensitive", "0") != "0"
    query = request.args.get("q", "")
    # 与 /api/logs 同口径：默认不扫 payload，仅在显式勾选全文搜索时启用
    fulltext = request.args.get("fulltext", "0") != "0"
    event_type = request.args.get("type", "").strip().upper() or None
    if event_type and not re.fullmatch(r"[A-Z_]{1,32}", event_type):
        event_type = None
    ev = fetch_events(since=0, limit=limit, sensitive_only=sensitive_only,
                      query=query, fulltext=fulltext, event_type=event_type, max_limit=EXPORT_MAX)
    # 是否被上限截断——拿满 limit 就说明后面还有。静默截断过一次：接口写着允许
    # 5000，底层却砍到 1000，用户导出一整天的日志只拿到 1000 条还以为是全部。
    truncated = len(ev) >= limit
    # 导出清洗：字段白名单。RESTORE 事件的 dialog/resp_preview 是还原后的正文
    # （含普通 PII 明文），只删 items[].original 无法完全拦截。
    # 正文类字段一律剔除，只保留元数据 + 打码 items。
    _EXPORT_KEEP_FIELDS = {
        "ts", "type", "sid", "host", "method", "path",
        "upstream", "model", "stream_mode", "stream_actual",
        "count", "restored", "status", "http_status",
        "mask_ms", "resp_ts", "first_byte_ms", "upstream_ms", "total_ms", "bytes", "usage", "cost_usd", "seq", "reason", "msg",
    }
    clean = []
    for e in ev:
        item = {k: v for k, v in e.items() if k in _EXPORT_KEEP_FIELDS}
        # msg/reason 承载异常文本或引擎提示，异常消息理论上可能回显请求片段：
        # 与诊断包口径一致过 _scrub_text 打码，避免导出文件残留明文形态
        for _k in ("msg", "reason"):
            if isinstance(item.get(_k), str):
                item[_k] = _scrub_text(item[_k])
        if isinstance(e.get("items"), list):
            clean_items = []
            for it in e["items"]:
                if not isinstance(it, dict):
                    continue
                clean_items.append({k: v for k, v in it.items() if k != "original"})
            item["items"] = clean_items
        clean.append(item)
    payload = {
        "exported_at": time.time(),
        "count": len(clean),
        "sensitive_only": sensitive_only,
        "query": query,
        "masked_export": True,  # 导出恒脱敏：不含任何 original 明文
        # truncated=True 表示还有更早的事件没导出来。宁可让用户看见「只导了 N 条」，
        # 也不能让他以为手上这份就是全部——审计场景下这个误会代价很大。
        "truncated": truncated,
        "limit": limit,
        "events": clean,
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    resp = make_response(body)
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Content-Disposition"] = 'attachment; filename="maskit-events.json"'
    return resp


# ============================ 浏览器扩展桥接（Browser Bridge v1） ============================
# 扩展侧唯一通信对象是本机 panel（http://127.0.0.1:5801），只走 /api/ext/* 三个端点。
# 全部脱敏/还原都复用 transparent 模块，落点在 **panel 进程** 那一份全局态
# （与 mitmdump 子进程那份互不可见，见 SPEC §1.1/C16）。
#
# 并发模型：mitmproxy 的 event loop 是单线程同步执行，panel 的 Flask 却是 threaded；
# 扩展是 panel 进程内第一个**高频**并发调用方。而 transparent 的 `_prune_recent`
# 会对 `_RECENT_FWD` 做 `list()` 快照，构造期并发插入会 RuntimeError → 用模块级
# `_EXT_LOCK` 把 transparent 调用段整体串行化。
#
# 2026-09-24 补充：代理链路的脱敏也搬到了自己的专职线程（`transparent._MASK_POOL`），
# 于是「panel 侧之间」的 `_EXT_LOCK` 不再足以保护 transparent 的全局表。
# 全局表本身的互斥改由 `transparent._STATE_LOCK` 负责（签发占位符、复用表清理、
# 映射重建）；`_EXT_LOCK` 继续管 panel 侧自己的不变量（`_EXT_STATS`、会话 inflight 等）。
#
# ⚠️ 锁序规矩：`_EXT_LOCK` → `transparent._STATE_LOCK`，**永远不能反向**。
# transparent 不回调 panel、不持锁做 I/O，所以不存在反向路径；
# **禁止在 `_EXT_LOCK` 临界区内调用任何会碰 panel 配置锁（cfg_lock）
# 的函数**（load_config / save_config / _sync_runtime_config 等）。`tr._maybe_reload`
# 今天只读 transparent 自己的配置文件，实测不碰 panel 锁；一旦它将来改读 panel
# 配置，就是 `_EXT_LOCK → cfg_lock` 与反向的经典死锁，届时应先重构锁边界。
_EXT_LOCK = threading.Lock()
# popup 的「今日累计」计数（只影响展示；`+=` 是读改写三步，故在锁内自增）。
_EXT_STATS = {"mask": 0, "restore": 0}
# `_sweep` 节流时间戳：restore 是每 SSE chunk 一次（代理路径是每请求一次），
# 不节流则每个 chunk 都全表扫一遍 sessions。
_EXT_LAST_SWEEP = 0.0
_EXT_SWEEP_INTERVAL = 10.0
# 请求体上限，**数值必须与 `transparent._MAX_REQUEST_BODY` 一致**（代理路径的同款红线：
# 超限一律 (A) 阻断，绝不半脱敏放行）。这里不 import transparent 取值——panel 进程能否
# import transparent 取决于跑在哪个解释器（见下面 mask 端点的失败路径注释），
# 把「闸门」这种必须无条件生效的判断绑到一个可能 import 失败的模块上不可接受。
_EXT_MAX_BODY = 32 * 1024 * 1024
# 文档脱敏的 NER 总预算（秒）：逐 run 调用 mask()，单条短文本实测约 10ms，一份
# 几千 run 的文档会线性堆到分钟级，而扩展侧 HTTP 超时更短——超预算后只停用语义
# 识别，确定性规则照常生效（见 transparent._ner_doc_budget）。
_EXT_FILE_NER_BUDGET_S = 8.0


def _ner_status_payload(cfg):
    """语义实体识别（NER）的开关与可用性（面板/健康检查用）。

    只看文件与**已记录的错误**，不主动加载模型（98MB，不能挂在状态轮询里）。
    开启但不可用时必须给出原因：否则用户只看到「开了没效果」，无从归因。
    """
    enabled = bool((cfg or {}).get("ner_enabled", False))
    info = {"enabled": enabled, "available": False, "initialized": False, "reason": "",
            "skips": {}}
    try:
        import ner_engine
        st = ner_engine.status()
        info["available"] = bool(st.get("available"))
        info["initialized"] = bool(st.get("initialized"))
        # 跳过计数必须透出（审计 M7）：`too_long` / `budget_exhausted` /
        # `inference_failed` 这些「开了 NER 但这段没做识别」的原因此前只写进程日志，
        # 界面上完全看不出——用户看到的是「开了 NER，长文本全跳过」却无从归因。
        # 计数是纯整数，不含任何原文，可以安全下发。
        skips = st.get("skips")
        if isinstance(skips, dict):
            info["skips"] = {str(k): int(v) for k, v in skips.items()}
        if enabled:
            if not info["available"]:
                info["reason"] = "模型文件缺失（engine/models/ner_mini_zh/model_quantized.onnx）"
            elif st.get("last_error"):
                info["reason"] = str(st.get("last_error"))
    except Exception as e:
        if enabled:
            info["reason"] = f"NER 模块不可用：{type(e).__name__}"
    return info


def _sweep_throttled(tr):
    """锁内调用：≥10s 才真正跑一次 `tr._sweep`，防 restore 每 chunk 全表扫。

    `tr` **必须由端点传入**（端点在函数内局部 import 的模块对象，模块级 helper
    看不到）——早期版本在这里直接写 `tr._sweep()` 是 NameError，会被端点的
    `except Exception` 吞掉后恒返回 (A) 阻断，而 (A) 不熔断，等于网页全站持续
    网络错误。抽 helper 时先查作用域。
    """
    global _EXT_LAST_SWEEP
    now = time.monotonic()
    if now - _EXT_LAST_SWEEP > _EXT_SWEEP_INTERVAL:
        tr._sweep()
        _EXT_LAST_SWEEP = now


@app.get("/api/ext/ping")
def api_ext_ping():
    """扩展存活探针：SW 每 60s 调一次，拿版本 / 开关 / 累计计数。"""
    return jsonify({"ok": True, "version": __version__,
                    # 协议版本：扩展侧比对本字段以发现「契约不兼容」
                    # （拿 version 比没用，见 EXT_PROTOCOL_VERSION 的注释）
                    "ext_protocol": EXT_PROTOCOL_VERSION,
                    "block_when_down": bool(_ext_cfg().get("ext_block_when_engine_down")),
                    "record_events": bool(_ext_cfg().get("ext_record_events", True)),
                    "stats": dict(_EXT_STATS)})


@app.post("/api/ext/warn")
def api_ext_warn():
    """扩展上报：**URL 命中对话白名单，但 body 的 content-type 不在可打码集合内**。

    这是本系统唯一一类「无感知漏脱敏」：用户以为内容被保护，实际原样明文出网。
    扩展侧 `bridge-main.js` 在 `isUrlMaskable && !isMaskableBody` 时上报，这里复用
    `transparent._emit_skip` 的事件通道（reason=`unsupported_content_type`），
    让它在事件页可见、可筛选，而不是无声消失。

    只在**本端点内**做 10s 去重，不改 `transparent._emit_skip` 的去重集合：
    那条函数属于核心代理链路，本次改动不碰它。

    只收元数据（host / 上游 path / content-type），**不收正文**：这个链路的意义恰恰是
    「我们没能处理它」，把正文收进来等于把已经漏出去的明文再抄一份进 SQLite。
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        host = str(data.get("host") or "")[:120]
        path = str(data.get("path") or "")[:200]
        ct = str(data.get("content_type") or "")[:80]
        key = (host, path, ct)
        now = time.time()
        if now - _ext_warn_seen.get(key, 0) < 10:
            return jsonify({"ok": True, "deduped": True})
        _ext_warn_seen[key] = now
        if len(_ext_warn_seen) > _EXT_WARN_MAX:
            # 先清过期项；**仍超限就按时间戳淘汰最旧的**，保证严格有界。
            # 旧实现只删 >60s 的条目：60s 内灌进 200+ 个不同 key 就永不回收，
            # 每个新 key 还会写一条 SQLite 事件。
            for k in [k for k, ts in _ext_warn_seen.items() if now - ts > 60]:
                _ext_warn_seen.pop(k, None)
            overflow = len(_ext_warn_seen) - _EXT_WARN_MAX
            if overflow > 0:
                for k, _ts in sorted(_ext_warn_seen.items(), key=lambda kv: kv[1])[:overflow]:
                    _ext_warn_seen.pop(k, None)
        if _ext_cfg().get("ext_record_events", True):
            import transparent as tr
            # force=True：与「已配置客户端」同一条可见性通道，保证这条不会被静默丢弃。
            tr._emit_skip(host=host, method="POST", path=path or "/ext/warn",
                          reason="unsupported_content_type", content_type=ct,
                          force=True)
        return jsonify({"ok": True})
    except Exception as e:
        # 可观测性失败绝不能反噬请求本身：只记异常类型名，不记 message（可能带正文片段）。
        try:
            _emit_log(f"[panel] ext warn 失败: {type(e).__name__}")
        except Exception:
            pass
        return jsonify({"ok": False, "error": "engine_error"})


@app.post("/api/ext/mask")
def api_ext_mask():
    """扩展请求体打码。sid 由**服务端**签发（客户端不能指定）。"""
    # 体积闸门必须**先于**任何读体动作（`get_json` 会把流完整读进内存）。
    # ⚠️ 只判 `content_length` 是不够的：无 `Content-Length` 时它是 None，
    # `(None or 0) > LIMIT` 判成 `0 > LIMIT` = False ——**闸门被整个绕过**
    # （实测 werkzeug：`Transfer-Encoding: chunked` → content_length is None）。
    # 所以显式分块也一律拒绝。扩展侧发的是字符串体、恒带 Content-Length，
    # 因此这条只会挡刻意分块的调用方，不影响正常链路。
    # 注：若将来需要「对任意 framing 都强制生效」，正解是 `MAX_CONTENT_LENGTH`
    # + 一个返回 `blocking:true` 的 413 errorhandler——**两者必须同时加**：
    # 只加前者会拿到 Flask 的 HTML 413 页，扩展按「无 blocking」归进 (B) 默认桶，
    # 于是超限体变成「未脱敏直通」，比现状更危险。
    if (request.content_length or 0) > _EXT_MAX_BODY or request.headers.get("Transfer-Encoding"):
        return jsonify({"ok": False, "error": "payload_too_large", "blocking": True}), 413
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text")
    if not isinstance(text, str) or not text:
        return jsonify({"ok": False, "error": "bad_request", "blocking": True}), 400
    sid = "ext:" + secrets.token_hex(8)          # 服务端生成，客户端不能指定
    t0 = time.perf_counter()
    try:
        import transparent as tr
        with _EXT_LOCK:
            # `force=True` 是**故意**的，别为了“省开销”改成非 force：本端点是每请求一条的
            # 热路径，但实测全量重载仅 209µs（mtime 短路 41µs，差 0.17ms，占单次 mask <5%），
            # 换来的是「每次 mask 都按最新配置确认」的硬语义（tests/test_ext_bridge.py::
            # test_t13_config_ttl_is_the_injection_point 守这条）。
            tr._maybe_reload(force=True)
            _sweep_throttled(tr)
            # 显式建会话：mask() 内部虽会懒建，但懒建**只在真有字符串叶子被扫描时**
            # 才发生——纯协议体或整棵命中 skip 规则时 sessions[sid] 根本不存在，
            # 下面的 s["inflight"] = True 就写在随即被丢弃的临时 dict 上，
            # inflight 保护从未生效，_sweep 按 TTL 回收会话后响应回来查不到 rev
            # → 占位符泄漏。demo 端点与代理路径都先显式建会话，这里对齐。
            # 注意**不传 source**：会话的 source 是「客户端 peer 信息」
            # （transparent._client_source → {client, client_host, client_port}），
            # 扩展链路没有 mitmproxy flow；塞 {"kind": "ext"} 只会被 _emit_skip /
            # _emit_restore_summary 的 **source 摊成 payload 里一个孤立的 kind 键。
            # 入口维度改用事件字段 ingress（与 source 正交）。
            tr._new_session(sid)
            # 给本链路的语义识别开**总**预算（与代理链路同口径，见 transparent._ner_req_budget）。
            # 本端点此前**完全没有**总预算：`ner_engine.CALL_BUDGET_S` 只管单次调用，
            # 而一个请求体里有多少个字符串叶子是没有上限的 —— 大 body 会按秒级占住
            # Flask 工作线程，而扩展侧 HTTP 超时更短，用户看到的就是「网页请求失败」。
            with tr._ner_doc_budget(tr._ner_req_budget(len(text.encode("utf-8")))):
                masked = tr.mask_body(text, sid)
            # 本轮降级（有空叶子没走 NER）：随响应回给扩展，并写进下面的 MASK 事件
            ner_skips = tr._ner_skips_of_this_round()
            s = tr.sessions[sid]
            items = tr._mask_event_items(sid)
            if ner_skips:
                s["ner_skips"] = ner_skips
            s["inflight"] = True
            _EXT_STATS["mask"] += 1              # += 是读改写三步，必须在锁内
        hit_count = len(s.get("last_hits") or set())
        # 仅当真实命中敏感词并发生打码时才产生 MASK 事件，彻底消除大量 0 命中的空白噪声日志。
        # 例外：本轮发生语义识别降级时即使 0 命中也要记 —— 降级意味着「本该识别出人名/
        # 机构/地址的文本没被识别」，而这恰好是最可能漏码的情形，不记就等于静默降级。
        if _ext_cfg().get("ext_record_events", True) and (hit_count > 0 or ner_skips):
            # dialog / req_preview 落库前必须过凭据清洗（审计 B1）。
            # 这两个字段是**客户端原始请求体**，`items` 里凭据类只有 digest+preview，
            # 但同一行 payload 的 dialog 会把 API Key 原文一起写进 SQLite ——
            # 违反「凭据类永远无法从 SQLite 回溯」这条硬约束。
            # 必须先在完整 text 上执行双重凭据清洗（会话已知凭据 + 形态正则），再做长度截断；
            # 严禁先截断再清洗，否则跨越 4000/800 边界的凭据会因正则特征破损而留下半截明文残片。
            # 清洗只针对**凭据形态**：普通 PII（手机号/身份证/姓名）的原文照旧保留，
            # 详情弹窗的「脱敏 ↔ 原文」对照能力不受影响。
            scrubbed_dialog = tr._redact_credentials(tr._redact_session_credentials(text, s))
            tr._emit("MASK", ingress="ext", sid=sid,
                     count=hit_count,
                     new_count=len(s.get("new_orig") or set()),
                     items=items, host=str(data.get("host") or ""), path="/ext/mask",
                     dialog=scrubbed_dialog[:4000],
                     req_preview=scrubbed_dialog[:800],
                     mask_ms=round((time.perf_counter() - t0) * 1000, 1),
                     **({"ner_truncated": True, "ner_skip_reasons": ner_skips}
                        if ner_skips else {}))
        return jsonify({"ok": True, "masked_text": masked, "sid": sid,
                        **({"ner_skipped": ner_skips} if ner_skips else {})})
    except Exception as e:
        # (A) 类：引擎明确失败 → 无条件阻断（红线 2），无开关。
        # 失败路径**必须留一条日志**，否则用户只看到「网页全站请求失败」、事件页
        # 一片空白，无从归因（R14）。这一支恰好包含 `import transparent` 失败——
        # panel 进程能否 import transparent 取决于它跑在哪个解释器。
        # `_emit_log` 只依赖 panel 自己的环形缓冲，不依赖 transparent，任何情况下可用。
        # 只记异常**类型名**、不记 message：message 可能带请求正文片段，而 log_buf
        # 会被 `_diagnostics_payload` 收进诊断包，等于把 PII 写进诊断包。
        try:
            _emit_log(f"[panel] ext mask 失败: {type(e).__name__}")
        except Exception:
            pass
        return jsonify({"ok": False, "error": "engine_error", "blocking": True}), 503


def _make_minimal_xlsx(lines):
    """纯标准库生成极简合规 .xlsx (SpreadsheetML) 字节流。"""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>\n'
            '  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\n'
            '</Types>'
        ))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>\n'
            '</Relationships>'
        ))
        zf.writestr("xl/_rels/workbook.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>\n'
            '</Relationships>'
        ))
        zf.writestr("xl/workbook.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
            '  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>\n'
            '</workbook>'
        ))
        sheet_rows = []
        for r_idx, line in enumerate(lines, 1):
            cells = line.split("\t") if "\t" in line else [line]
            c_xml = []
            for c_idx, cell_val in enumerate(cells, 1):
                col_letter = chr(64 + c_idx) if c_idx <= 26 else "A"
                escaped = cell_val.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                c_xml.append(f'<c r="{col_letter}{r_idx}" t="inlineStr"><is><t>{escaped}</t></is></c>')
            sheet_rows.append(f'<row r="{r_idx}">{"".join(c_xml)}</row>')
        zf.writestr("xl/worksheets/sheet1.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
            f'  <sheetData>{"".join(sheet_rows)}</sheetData>\n'
            '</worksheet>'
        ))
    return out.getvalue()


def _convert_and_mask_legacy_office(raw_bytes: bytes, ext: str, sid: str, tr):
    """旧版 Office (.doc / .xls) 兜底转码：**有损重建，默认关闭**。

    仅当用户在设置里显式打开 `ext_convert_legacy_office` 时才会走到这里。它不是
    格式转换：只有“从二进制里捞可读字符串 → 塞进手写极简 OOXML”两步，图片、表格
    结构、样式、公式、多 sheet、批注、页眉页脚全部丢失，且二进制碎片会被一并当成
    正文捞进去（实测正文中出现整段乱码）。保留实现是为了给“确实只关心纯文本、
    且能接受格式尽失”的用户留一个显式开关，绝不能当作默认安全能力。

    Returns:
        (masked_bytes, hits)。注意 hits == 0（无任何敏感信息）时**也会返回重建后的
        字节**，即调用方拿到的是一个已被改写的文件——这与 OOXML 路径
        `if total_hits == 0: return raw_bytes, 0` 的“无命中绝不动文件”原则相反。
    """
    text_lines = []
    # 1. 优先提取 UTF-16LE 文本段落（Word/Excel 经典编码）
    try:
        u16 = raw_bytes.decode('utf-16le', errors='ignore')
        for part in re.split(r'[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]+', u16):
            part = part.strip()
            if len(part) >= 2 and any('\u4e00' <= c <= '\u9fff' or c.isalnum() for c in part):
                text_lines.append(part)
    except Exception:
        pass

    # 2. 补充提取 UTF-8 / GBK / ASCII
    try:
        u8 = raw_bytes.decode('utf-8', errors='ignore')
        for part in re.split(r'[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]+', u8):
            part = part.strip()
            if len(part) >= 2 and any('\u4e00' <= c <= '\u9fff' or c.isalnum() for c in part):
                if part not in text_lines:
                    text_lines.append(part)
    except Exception:
        pass

    if not text_lines:
        return raw_bytes, 0

    hits = 0
    masked_lines = []
    for line in text_lines:
        m = tr.mask_body(line, sid)
        if m != line:
            hits += 1
        masked_lines.append(m)

    # 若是 .xls 表格，生成合规的 .xlsx 结构；若是 .doc 文档，生成合规的 .docx 结构
    if ext == "xls":
        return _make_minimal_xlsx(masked_lines), hits

    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
            '</Types>'
        )
        zf.writestr('[Content_Types].xml', content_types)
        rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>\n'
            '</Relationships>'
        )
        zf.writestr('_rels/.rels', rels)
        body_xml = []
        for p in masked_lines:
            escaped = p.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            body_xml.append(f'<w:p><w:r><w:t>{escaped}</w:t></w:r></w:p>')
        doc_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
            f'  <w:body>{" ".join(body_xml)}</w:body>\n'
            '</w:document>'
        )
        zf.writestr('word/document.xml', doc_xml)
    return out.getvalue(), hits


def _pad_zip_to_size(zip_bytes: bytes, target_size: int) -> bytes:
    """利用标准 ZIP 尾部 EOCD 注释字段填充，将 ZIP 文件无损对齐到目标字节大小。"""
    if len(zip_bytes) >= target_size:
        return zip_bytes
    diff = target_size - len(zip_bytes)
    eocd_pos = zip_bytes.rfind(b"PK\x05\x06")
    if eocd_pos == -1 or len(zip_bytes) - eocd_pos < 22:
        return zip_bytes
    existing_comment_len = int.from_bytes(zip_bytes[eocd_pos + 20:eocd_pos + 22], "little")
    new_comment_len = existing_comment_len + diff
    if new_comment_len > 65535:
        return zip_bytes
    return (
        zip_bytes[:eocd_pos + 20] +
        new_comment_len.to_bytes(2, "little") +
        zip_bytes[eocd_pos + 22:eocd_pos + 22 + existing_comment_len] +
        (b" " * diff)
    )


def mask_ooxml_bytes(raw_bytes: bytes, filename: str, sid: str, tr):
    """处理 Office 文档（.docx / .xlsx / .pptx / .doc / .xls）内部文本脱敏。

    采用 Python 原生 zipfile 与 xml.etree.ElementTree，零外部依赖，毫秒级解包替换并重新封包。
    支持老版 Office (.doc / .xls) 内存安全提取文本与转码。

    返回: (masked_bytes, total_hits)
    **只要命中过敏感值，返回的一定是打过码的字节**：体积无法与原始对齐时也不回退明文
    （回退会让 hit_count 归零，扩展侧会误判成「无敏感信息」而静默放行）。
    """
    ext = (filename.lower().split(".")[-1] if "." in filename else "").strip()
    # 旧格式转换默认关闭：开了它产出的“转换结果”是有损重建（丢图片/丢表格/混入乱码），
    # 用户上传的文件在上游会变成另一个东西。关闭时下面的 zipfile.is_zipfile 判定必然为假，
    # 于是 .doc/.xls 原样返回（文件完整、但不脱敏），扩展侧会明确提示用户转存新格式。
    if ext in ("doc", "xls") and _ext_cfg().get("ext_convert_legacy_office", False):
        return _convert_and_mask_legacy_office(raw_bytes, ext, sid, tr)

    in_buf = io.BytesIO(raw_bytes)
    if not zipfile.is_zipfile(in_buf):
        return raw_bytes, 0

    # 智能识别格式：若文件名缺少扩展名或为通用后缀，通过内部关键结构反推真实格式
    if ext not in ("docx", "xlsx", "pptx", "wps", "et", "dps"):
        try:
            with zipfile.ZipFile(in_buf, "r") as probe_zin:
                names = probe_zin.namelist()
                if any(n.startswith("xl/") for n in names):
                    ext = "xlsx"
                elif any(n.startswith("word/") for n in names):
                    ext = "docx"
                elif any(n.startswith("ppt/") for n in names):
                    ext = "pptx"
                else:
                    return raw_bytes, 0
        except Exception:
            return raw_bytes, 0
        in_buf.seek(0)

    # 解压体积上限防线：防止恶意构造的 Zip Bomb 导致解压内存爆满 (OOM)
    _MAX_TOTAL_UNCOMPRESSED = 64 * 1024 * 1024  # 64MB
    in_buf.seek(0)
    with zipfile.ZipFile(in_buf, "r") as test_zin:
        total_uncompressed = sum(item.file_size for item in test_zin.infolist())
        if total_uncompressed > _MAX_TOTAL_UNCOMPRESSED:
            _emit_log(f"[panel] Office 文档解压体积超限 ({total_uncompressed} > {_MAX_TOTAL_UNCOMPRESSED})，跳过内部脱敏")
            return raw_bytes, 0

    out_buf = io.BytesIO()
    total_hits = 0
    in_buf.seek(0)

    with (
        tr._ner_doc_budget(_EXT_FILE_NER_BUDGET_S),
        zipfile.ZipFile(in_buf, "r") as zin,
        zipfile.ZipFile(out_buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zout,
    ):
        for item in zin.infolist():
            content = zin.read(item.filename)
            fn = item.filename.lower()
            should_mask = False

            # Word (.docx / .wps)
            if ext in ("docx", "wps") and ((fn.startswith("word/") and fn.endswith(".xml")) or fn == "docprops/core.xml"):
                should_mask = True
            # Excel (.xlsx / .et)
            elif ext in ("xlsx", "et") and ((fn.startswith("xl/") and fn.endswith(".xml")) or fn == "docprops/core.xml"):
                should_mask = True
            # PowerPoint (.pptx / .dps)
            elif ext in ("pptx", "dps") and ((fn.startswith("ppt/") and fn.endswith(".xml")) or fn == "docprops/core.xml"):
                should_mask = True

            if should_mask:
                try:
                    for event, (prefix, uri) in ET.iterparse(io.BytesIO(content), events=("start-ns",)):
                        ET.register_namespace(prefix, uri)
                    tree = ET.fromstring(content)
                    modified = False

                    if ext == "docx" and fn.startswith("word/"):
                        # Word 段落遍历：处理 run 切分
                        for p in tree.iter():
                            if p.tag.split("}")[-1] == "p":
                                t_nodes = [n for n in p.iter() if n.tag.split("}")[-1] == "t"]
                                if not t_nodes:
                                    continue
                                # 第一阶段：单个 run 独立脱敏（保全格式独立性）
                                touched_runs = False
                                for n in t_nodes:
                                    if n.text:
                                        m = tr.mask_body(n.text, sid)
                                        if m != n.text:
                                            n.text = m
                                            touched_runs = True
                                            modified = True
                                            total_hits += 1
                                # 第二阶段：若单个 run 未命中，但整段拼接命中，说明敏感词跨 run 切分
                                if not touched_runs and len(t_nodes) > 1:
                                    full_text = "".join(n.text or "" for n in t_nodes)
                                    m_full = tr.mask_body(full_text, sid)
                                    if m_full != full_text:
                                        t_nodes[0].text = m_full
                                        for n in t_nodes[1:]:
                                            n.text = ""
                                        modified = True
                                        total_hits += 1
                    else:
                        for n in tree.iter():
                            tag = n.tag.split("}")[-1]
                            if (tag in ("t", "creator", "lastModifiedBy", "v") or tag.endswith("Text")) and n.text:
                                m = tr.mask_body(n.text, sid)
                                if m != n.text:
                                    n.text = m
                                    modified = True
                                    total_hits += 1

                    if modified:
                        content = ET.tostring(tree, encoding="utf-8", xml_declaration=True)
                except Exception:
                    pass
            zout.writestr(item.filename, content, compress_type=item.compress_type, compresslevel=9)

    # 一个敏感值都没命中：**原样返回原始字节**，绝不走重压缩。
    # 重压缩只会让体积漂移（Word 用的压缩器比 zlib 默认档更强，重压后反而变大），
    # 而上游（ChatGPT 等）按上传前声明的 file_size 校验实际收到的字节数，
    # 对不上就直接拒收（`file_size_mismatch`）—— 一个不含敏感信息的文件本来
    # 完全不需要改动，没有理由为它制造体积差。
    if total_hits == 0:
        return raw_bytes, 0

    out_val = out_buf.getvalue()
    if len(out_val) < len(raw_bytes):
        out_val = _pad_zip_to_size(out_val, len(raw_bytes))
    if len(out_val) != len(raw_bytes):
        # 体积对不齐的两种情况：① 重压后反而变大（打码本身会让内容变长，而 ZIP 注释
        # 补白**只能补大、不能削小**）；② 补白量超过 ZIP 注释字段的 64KB 上限。
        #
        # 此时**仍然返回已打码的字节**，绝不回退成原始明文：一旦回退，`hit_count` 会跟着
        # 归零，扩展侧 `maskSingleFile` 就会把这份文件当成「没有敏感信息」——既不替换上传
        # 内容、也不提示、也不记事件，用户以为受保护，整份文档却明文出网（实测可复现，
        # 见 tests/test_ext_bridge.py 的 size-mismatch 用例）。
        # 代价是上游若按上传前声明的 file_size 严格校验，可能回 file_size_mismatch 让这次
        # 上传失败——那是用户可见的报错，远优于静默明文。降级留一条面板日志便于定位。
        _emit_log(
            f"[panel] Office 重压缩体积无法对齐原始 ({len(out_val)} vs {len(raw_bytes)})，"
            f"仍返回脱敏结果（上游可能按 file_size 拒收）"
        )
    return out_val, total_hits


@app.post("/api/ext/mask-file")
def api_ext_mask_file():
    """扩展文档文件（docx / xlsx / pptx）打码。sid 由服务端签发或复用。"""
    if (request.content_length or 0) > _EXT_MAX_BODY or request.headers.get("Transfer-Encoding"):
        return jsonify({"ok": False, "error": "payload_too_large", "blocking": True}), 413
    data = request.get_json(force=True, silent=True) or {}
    filename = str(data.get("filename") or "").strip()
    b64_content = data.get("base64")
    sid = str(data.get("sid") or "").strip()
    if not isinstance(b64_content, str) or not b64_content or not filename:
        return jsonify({"ok": False, "error": "bad_request", "blocking": True}), 400

    if not sid or not sid.startswith("ext:"):
        sid = "ext:" + secrets.token_hex(8)

    t0 = time.perf_counter()
    try:
        raw_bytes = base64.b64decode(b64_content)
        import transparent as tr
        with _EXT_LOCK:
            # 同 /api/ext/mask：force=True 是故意的（理由见那里的注释）。
            tr._maybe_reload(force=True)
            _sweep_throttled(tr)
            tr._touch(sid)
            if sid not in tr.sessions:
                tr._new_session(sid)
            masked_bytes, hit_count = mask_ooxml_bytes(raw_bytes, filename, sid, tr)
            # 文件链路的总预算在 mask_ooxml_bytes 内部已开（_EXT_FILE_NER_BUDGET_S），
            # 这里把它的降级结果取出来上报：预算超了必须看得见，否则用户以为整份文件都脱了。
            ner_skips = tr._ner_skips_of_this_round()
            s = tr.sessions[sid]
            items = tr._mask_event_items(sid)
            if ner_skips:
                s["ner_skips"] = ner_skips
            s["inflight"] = True
            _EXT_STATS["mask"] += 1

        if _ext_cfg().get("ext_record_events", True) and (hit_count > 0 or ner_skips):
            tr._emit("MASK", ingress="ext", sid=sid,
                     count=hit_count,
                     new_count=len(s.get("new_orig") or set()),
                     items=items, host=str(data.get("host") or ""), path="/ext/mask-file",
                     dialog=f"[文件脱敏: {filename}]",
                     req_preview=f"Uploaded document: {filename} ({len(raw_bytes)} bytes)",
                     mask_ms=round((time.perf_counter() - t0) * 1000, 1),
                     **({"ner_truncated": True, "ner_skip_reasons": ner_skips}
                        if ner_skips else {}))

        masked_b64 = base64.b64encode(masked_bytes).decode("ascii")
        return jsonify({"ok": True, "base64": masked_b64, "sid": sid, "hit_count": hit_count,
                        **({"ner_skipped": ner_skips} if ner_skips else {})})
    except Exception as e:
        try:
            _emit_log(f"[panel] ext mask-file 失败: {type(e).__name__}")
        except Exception:
            pass
        return jsonify({"ok": False, "error": "engine_error", "blocking": True}), 503


@app.post("/api/ext/restore")
def api_ext_restore():
    """扩展响应流还原。**还原方向恒透传**：失败也把原文交回客户端（红线 3）。

    请求带 `content_type` 时走 `transparent.restore_stream_chunk`（分帧 + 槽位粒度），
    不带则退回旧的整段文本还原。**这个分支必须留着**：扩展是用户手动加载的，
    引擎与扩展的升级不同步是常态，旧扩展只会发 `text`——不能因为引擎更新了就把
    还装着旧扩展的用户打成「还原全失败」（那会表现为满屏 `{{...}}`，比不还原更糟）。

    为什么要区分两条路径见 `restore_stream_chunk` 的文档：整段文本还原无法拼接被
    SSE 事件边界切开的占位符，页面上会留下裸 `{{EMAIL_xxxxxx}}`。
    """
    # 体积闸门必须**先于**任何读体动作（审计 M2）：`get_json` 会把整个流读进内存，
    # 而本端点此前既没有 `_EXT_MAX_BODY` 也没有 chunked 判据（mask / mask-file 都有），
    # 于是任意脚本都能用它把引擎内存顶上去。
    #
    # ⚠️ 这里**不能**像 mask 那样回 413 + `blocking:true`：扩展侧把 blocking 当 (A)
    # 无条件阻断，而还原方向的红线是「恒透传」（红线 3）——阻断只会让用户看到半截响应。
    # 回一个不带 blocking 的 ok:false，扩展按 (B) 默认桶处理 → `handleRestore` 把
    # **原文**交回页面。超大 chunk 本来也还原不了（占位符必然被切断），透传是唯一安全行为。
    if (request.content_length or 0) > _EXT_MAX_BODY or request.headers.get("Transfer-Encoding"):
        return jsonify({"ok": False, "error": "payload_too_large"})
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text")
    sid = str(data.get("sid") or "").strip()        # 扩展回传 mask 签发的 sid
    stream_id = str(data.get("stream_id") or "").strip()
    final = bool(data.get("final"))
    escape = bool(data.get("escape"))               # 非流式文本类型才用得上
    content_type = str(data.get("content_type") or "")
    # sid 必须带 ext: 前缀 —— 否则扩展可以拿它去还原代理链路/他人会话的占位符。
    if not isinstance(text, str) or not sid.startswith("ext:") or not stream_id:
        return jsonify({"ok": False, "error": "bad_request"}), 400
    s = None
    try:
        import transparent as tr
        with _EXT_LOCK:
            _sweep_throttled(tr)
            # ⚠️ 这里**只 touch、不补建会话**。曾试过「会话不存在就 _new_session 补建」，
            # 目的是让 restore() 能正常计数；结果直接把安全门拆了：
            # restore() 见会话存在才会走替换流程，而替换流程会去查**全局**复用表
            # `_RECENT_REV`——于是任意自造 sid（`ext:000…0`）都能借复用表把占位符
            # 还原出来。tests/test_ext_bridge.py::test_t7 正是守这条，当场变红。
            # 计数改用 `_take_orphans_without_session`（只数、不还原），见下。
            tr._touch(sid)
            if content_type:
                out = tr.restore_stream_chunk(text, sid, stream_id,
                                              content_type=content_type,
                                              escape=escape, final=final)
            else:
                out = tr.restore(text, sid, channel=f"ext:{stream_id}",
                                 escape=escape, final=final)
        if final:
            items = []
            with _EXT_LOCK:
                s = tr.sessions.get(sid) or {}
                if s:
                    s["inflight"] = False
                _EXT_STATS["restore"] += 1          # += 读改写三步，必须在锁内
                # 锁内取值：还原计数由 `tr.restore()` 在会话里维护，出锁再读属于
                # 对同一 dict 的延迟读（本身无害），但锁内一次取干净更不容易被后人改坏。
                restored = int(s.get("restored") or 0)
                # unresolved/degraded 是**纯诊断计数**：`_update_stats` 不消费它们，
                # 只被日志页 renderSummary 用来标「未还原」「兜底还原」。扩展链路原先
                # 不发这两个字段 → 模型改写占位符时页面露出裸 `{{...}}`，而事件页那一行
                # 什么告警都不显示，用户无从判断是"引擎坏了"还是"模型在编"（代理链路
                # 正是因为看得见才没有踩这个坑）。这里补齐，两个字段都不进任何聚合。
                unresolved = int(s.get("unresolved") or 0)
                degraded = int(s.get("degraded") or 0)
                # 未还原占位符样本：只用于定位「到底是哪些 token 没还原、什么形态」。
                # 存的是占位符本身（不含任何明文），落库安全。取不到就是空列表。
                unresolved_samples = [str(x) for x in (s.get("unresolved_samples") or [])][:5]
                # 会话不存在时 restore() **只数不还原**（安全门：放行会让自造 sid 借
                # 全局复用表还原占位符），计数落在兜底表里，这里并进本次事件——
                # 否则「重启引擎后打开历史对话，页面上满屏 {{...}}」在事件页是 0。
                _ns_count, _ns_samples = tr._take_orphans_without_session(sid)
                if _ns_count:
                    unresolved += _ns_count
                    for _x in _ns_samples:
                        if len(unresolved_samples) < 5 and _x not in unresolved_samples:
                            unresolved_samples.append(_x)
                try:
                    restored_tokens = s.get("restored_tokens") or set()
                    seen_toks = set()
                    for orig, tok in list(s.get("fwd", {}).items())[:30]:
                        seen_toks.add(tok)
                        m = tr._PLACEHOLDER_PARTS_RX.match(tok)
                        lbl = s.get("labels", {}).get(orig, "")
                        is_cred = lbl in CREDENTIAL_LABELS
                        item = {
                            "tok": tok,
                            "label": lbl,
                            "hash": m.group(2) if m else "",
                            "length": len(orig),
                            "preview": tr._preview(orig, lbl),
                            "restored": tok in restored_tokens,
                        }
                        if is_cred:
                            item["cred"] = True
                            item["digest"] = tr._cred_digest(orig)
                        else:
                            item["original"] = orig
                        items.append(item)
                    # 补充：跨请求复用表（_RECENT_REV / _CUSTOM_WORD_REV）中还原出来的历史敏感项
                    # 避免本轮未脱敏新词时（如多轮追问），items 为空导致详情弹窗“右上角显示还原 N，下方无还原项目”
                    for tok in restored_tokens:
                        if tok in seen_toks or len(items) >= 30:
                            continue
                        seen_toks.add(tok)
                        rec = tr._RECENT_REV.get(tok) or tr._CUSTOM_WORD_REV.get(tok)
                        if rec and len(rec) >= 2:
                            orig, lbl = rec[0], rec[1]
                            m = tr._PLACEHOLDER_PARTS_RX.match(tok)
                            is_cred = lbl in CREDENTIAL_LABELS
                            item = {
                                "tok": tok,
                                "label": lbl,
                                "hash": m.group(2) if m else "",
                                "length": len(orig),
                                "preview": tr._preview(orig, lbl),
                                "restored": True,
                                "from_history": True,
                            }
                            if is_cred:
                                item["cred"] = True
                                item["digest"] = tr._cred_digest(orig)
                            else:
                                item["original"] = orig
                            items.append(item)
                except Exception:
                    items = []
            # 仅在有还原成功、有异常未还原，或会话发生过敏感词打码时才记录 RESTORE，杜绝空事件刷屏
            should_emit = (
                _ext_cfg().get("ext_record_events", True)
                and (restored > 0 or unresolved > 0 or degraded > 0 or len(items) > 0)
            )
            if should_emit:
                # 还原后的正文里可能**裸复述**了模型见过的凭据原文，落库前必须清洗
                # （审计 B1）。两道互补，与代理链路的 `_emit_restore_summary` 同源：
                #   1) `_redact_session_credentials`：拿本会话已知的凭据原文做精确串替换。
                #      形态正则拦不住「模型只复述了值本身」——CONNSTR 要求完整
                #      scheme://user:pass@host、PRIVATE_KEY 要求 PEM 头，裸值都不命中。
                #   2) `_redact_credentials`：按凭据形态跑正则，拦「用户自己贴的、
                #      本会话没脱敏过的」那种。
                # 顺序与代理链路一致（先会话精确串、后形态正则）。
                # 只清凭据：普通 PII 的原文照旧保留，详情弹窗对照能力不变。
                _out_text = out if isinstance(out, str) else ""
                _out_text = tr._redact_credentials(
                    tr._redact_session_credentials(_out_text, s))
                tr._emit("RESTORE", ingress="ext", sid=sid,
                         restored=restored, unresolved=unresolved, degraded=degraded,
                         unresolved_samples=unresolved_samples,
                         items=items,
                         resp_preview=_out_text[:800],
                         dialog=_out_text[:4000],
                         host=str(data.get("host") or ""), path="/ext/restore")
        return jsonify({"ok": True, "text": out})
    except Exception as e:
        # restore 是**每 chunk 一次**，逐次记录会把 800 行环形缓冲冲干净 ——
        # 只在 final（每条流一次）记一行。
        if final:
            try:
                _emit_log(f"[panel] ext restore 失败(final): {type(e).__name__}")
            except Exception:
                pass
        return jsonify({"ok": False, "text": text})     # 还原方向恒透传


@app.post("/api/ext/rotate-token")
def api_ext_rotate_token():
    """轮换扩展令牌（API_TOKEN 鉴权，**不在** ext_token 白名单内）。

    轮换后果：扩展持旧 token → 全部请求 403 invalid_token → (B) 类直通（未脱敏）
    直到用户到扩展设置更新 token。面板 UI 的旋转确认弹窗与此处应当表述一致；
    `_backup_config_file` 保留的历史 config.json.bak-* 里也含旧 token。
    """
    new_token = secrets.token_urlsafe(24)
    cfg = load_config()
    cfg["ext_token"] = new_token
    save_config(cfg)
    return jsonify({"ok": True, "ext_token": new_token})


@app.post("/api/demo/mask")
def api_demo_mask():
    """本地脱敏演示：不发上游，只验证规则是否生效。"""
    data = request.get_json(force=True) or {}
    text = str(data.get("text") or "").strip()
    if not text:
        text = "我是张三，电话13812345678，邮箱 test@example.com，key 是 sk-1234567890abcdefghijklmnopqrst"
    if len(text) > 4000:
        return jsonify({"ok": False, "error": "文本过长（最多 4000 字）"}), 400
    try:
        import transparent as tr
        # 持 `_EXT_LOCK`：本端点早于扩展桥接的锁约定，一直裸调 transparent。
        # 它会 `_maybe_reload` + 建会话 + mask，即与代理链路、扩展桥接一起改
        # transparent 的全局表（脱敏搬进专职线程后这件事才真正并发）。
        with _EXT_LOCK:
            tr._maybe_reload(force=True)
            sid = f"demo-{secrets.token_hex(4)}"
            tr._new_session(sid, source={"kind": "demo"})
            masked = tr.mask(text, sid)
            # 取副本：下面的展示组装在锁外做，不再依赖锁内的会话对象
            sess = dict(tr.sessions.get(sid) or {})
        fwd = sess.get("fwd") or {}
        labels = sess.get("labels") or {}
        # 只返回占位符与标签，不回传原文敏感值
        items = []
        for original, token in list(fwd.items())[:50]:
            items.append({
                "token": token,
                "label": labels.get(original) or "X",
                "original_len": len(str(original or "")),
            })
        # 清理 demo 会话，避免污染真实映射（与代理/扩展链路同一张会话表，同锁）
        try:
            with _EXT_LOCK:
                tr.sessions.pop(sid, None)
        except Exception:
            pass
        return jsonify({
            "ok": True,
            "input_len": len(text),
            "masked": masked,
            "count": len(fwd),
            "items": items,
            "changed": masked != text,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


@app.post("/api/upstream/test")
def api_upstream_test():
    """客户端连通性测试。

    mode:
      - port（默认）：只查本地端口是否监听
      - models：GET /v1/models（经本地端口，验证 key + 网关）
      - chat：POST 一条带敏感词的短对话（验证脱敏链路）
    """
    import urllib.error
    import urllib.request

    data = request.get_json(force=True) or {}
    name = str(data.get("name") or "").strip()
    try:
        port = int(data.get("port") or 0)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "端口必须是数字"}), 400
    if port < 0 or port > 65535:
        return jsonify({"ok": False, "error": "端口范围必须是 1-65535"}), 400
    mode = str(data.get("mode") or "port").strip().lower()
    if mode not in {"port", "models", "chat"}:
        return jsonify({"ok": False, "error": "不支持的测试模式"}), 400
    api_key = str(data.get("api_key") or data.get("apiKey") or "").strip()
    model = str(data.get("model") or "").strip()
    path_prefix = str(data.get("path_prefix") or "/v1").strip() or "/v1"
    if not path_prefix.startswith("/"):
        path_prefix = "/" + path_prefix

    cfg = load_config()
    ups = cfg.get("upstreams") or []
    target = None
    if name:
        for u in ups:
            if u.get("name") == name:
                target = u
                break
    if target is None and port:
        for u in ups:
            if int(u.get("port") or 0) == port:
                target = u
                break
    if target is None and name == "" and len(ups) == 1:
        target = ups[0]
    if target is None:
        return jsonify({"ok": False, "error": "未找到客户端"}), 400

    port = int(target.get("port") or 0)
    p = proc["p"]
    running = bool(p and p.poll() is None)
    listening = bool(port and _port_listen(port))
    base = f"http://127.0.0.1:{port}" if port else ""
    # 测试请求打的是**本地端口**，经 mitmdump 走完整链路 —— 出口代理由引擎按
    # upstream.use_proxy 决定，所以这里天然与真实转发同路，不必自己配代理。
    # 但必须显式禁用 urllib 的环境变量代理：用户为了让别的工具出境而设了
    # HTTP_PROXY/HTTPS_PROXY 时，urllib 会把发往 127.0.0.1 的请求也塞进代理，
    # 测试就会莫名其妙失败（而实际转发是好的），把排查方向彻底带偏。
    _local_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    tips = []
    if not running:
        tips.append("代理未运行，请先启动")
    elif not listening:
        tips.append("端口未监听，可能需重启代理使新端口生效")

    result = {
        "ok": running and listening,
        "name": target.get("name"),
        "port": port,
        "url": base,
        "base_url": f"{base}{path_prefix}" if base else "",
        "proxy_running": running,
        "listening": listening,
        "target": _safe_target(target.get("target")),
        "paths": [str(p).split("?", 1)[0].split("#", 1)[0] for p in (target.get("paths") or [])],
        "mode": mode,
        "tips": tips,
    }
    if mode == "port" or not (running and listening):
        if running and listening:
            result["message"] = "本地端口监听正常（未连接上游）"
            tips.append("本地端口正常。可填 API Key 后点「拉模型」或「一键聊天」做完整测试")
        return jsonify(result)

    if not api_key:
        result["ok"] = False
        result["error"] = "请填写 API Key"
        tips.append("models/chat 测试需要 API Key（只用于本次请求，不落盘）")
        return jsonify(result), 400

    def _http(method, url, body=None, timeout=45):
        headers = {
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "LLM-Shield-UpstreamTest/1.0",
            "Accept": "application/json",
        }
        data_bytes = None
        if body is not None:
            data_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data_bytes, method=method, headers=headers)
        try:
            with _local_opener.open(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return resp.status, raw, dict(resp.headers.items())
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
            raw = _safe_public_text(raw, 4000)
            return int(e.code or 0), raw, {}
        except Exception as e:
            return 0, _safe_public_text(e, 500), {}

    # 按 upstream paths 猜前缀：含 /zen/go/v1 则用它
    paths = target.get("paths") or []
    if any(str(p).startswith("/zen/go") for p in paths):
        path_prefix = "/zen/go/v1"
        result["base_url"] = f"{base}{path_prefix}"

    if mode == "models":
        status, raw, _ = _http("GET", f"{base}{path_prefix}/models", timeout=30)
        result["http_status"] = status
        result["raw_preview"] = _safe_public_text(raw or "", 800)
        models = []
        try:
            j = json.loads(raw)
            data_list = j.get("data") if isinstance(j, dict) else None
            if isinstance(data_list, list):
                for m in data_list[:50]:
                    if isinstance(m, dict) and m.get("id"):
                        models.append(str(m["id"]))
                    elif isinstance(m, str):
                        models.append(m)
            elif isinstance(j, dict) and isinstance(j.get("models"), list):
                for m in j["models"][:50]:
                    if isinstance(m, dict) and m.get("id"):
                        models.append(str(m["id"]))
                    elif isinstance(m, str):
                        models.append(m)
        except Exception:
            pass
        result["models"] = models
        result["ok"] = 200 <= status < 300
        if result["ok"]:
            tips.append(f"拉模型成功，共 {len(models)} 个（最多展示 50）")
        else:
            tips.append(f"拉模型失败 HTTP {status}，检查 key / 路径前缀 / 上游是否可达")
            result["error"] = f"HTTP {status}"
        return jsonify(result)

    if mode == "chat":
        if not model:
            # 先尝试 models 里第一个
            st2, raw2, _ = _http("GET", f"{base}{path_prefix}/models", timeout=20)
            try:
                j2 = json.loads(raw2)
                data_list = j2.get("data") if isinstance(j2, dict) else None
                if isinstance(data_list, list) and data_list:
                    m0 = data_list[0]
                    model = str(m0.get("id") if isinstance(m0, dict) else m0)
            except Exception:
                pass
        if not model:
            result["ok"] = False
            result["error"] = "未指定 model，且无法从 /models 自动获取"
            tips.append("请先拉模型，或手动填 model 名")
            return jsonify(result), 400
        # 支持自定义测试文本（工具页「真实脱敏测试」传入，默认内置占位符示例）
        probe_text = str(data.get("content") or "").strip() or (
            "连通性测试：电话13812345678 邮箱shield-test@example.com 请只回复OK"
        )
        body = {
            "model": model,
            "messages": [{"role": "user", "content": probe_text}],
            "max_tokens": 32,
            "stream": False,
        }
        # Anthropic 风格路径
        chat_url = f"{base}{path_prefix}/chat/completions"
        if path_prefix.rstrip("/").endswith("messages") or any(
            str(p).endswith("/messages") or str(p) == "/v1/messages" for p in paths
        ):
            # 仍优先 openai 兼容；若 paths 只有 messages 再切
            if all("/chat/completions" not in str(p) and "/completions" not in str(p) for p in paths):
                chat_url = f"{base}{path_prefix}/messages" if not path_prefix.endswith("/messages") else f"{base}{path_prefix}"
                body = {
                    "model": model,
                    "max_tokens": 32,
                    "messages": [{"role": "user", "content": probe_text}],
                }
        status, raw, _ = _http("POST", chat_url, body=body, timeout=60)
        result["http_status"] = status
        result["model"] = model
        result["chat_url"] = _safe_target(chat_url)
        result["raw_preview"] = _safe_public_text(raw or "", 1000)
        result["ok"] = 200 <= status < 300
        # 从回复里抽一点文本
        reply = ""
        try:
            j = json.loads(raw)
            if isinstance(j, dict):
                ch = j.get("choices")
                if isinstance(ch, list) and ch:
                    msg = ch[0].get("message") if isinstance(ch[0], dict) else None
                    if isinstance(msg, dict):
                        reply = str(msg.get("content") or "")
                    elif isinstance(ch[0], dict):
                        reply = str(ch[0].get("text") or "")
                cont = j.get("content")
                if not reply and isinstance(cont, list) and cont:
                    reply = str(cont[0].get("text") if isinstance(cont[0], dict) else cont[0])
                if not reply and isinstance(cont, str):
                    reply = cont
        except Exception:
            pass
        result["reply_preview"] = _safe_public_text(reply or "", 300)
        if result["ok"]:
            tips.append("聊天测试成功。请到「实时日志」查看 MASK/RESTORE（含手机号/邮箱脱敏）")
            tips.append("若日志仍空：取消勾选「只看敏感请求」，或点刷新")
        else:
            tips.append(f"聊天失败 HTTP {status}，检查 model 名与 key")
            result["error"] = f"HTTP {status}"
        return jsonify(result)

    result["ok"] = False
    result["error"] = f"未知 mode: {mode}"
    return jsonify(result), 400


@app.post("/api/open-data-dir")
def api_open_data_dir():
    """在资源管理器中打开数据目录。"""
    try:
        path = str(DATA_ROOT)
        if os.name == "nt":
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
        return jsonify({"ok": True, "path": _safe_public_text(path, 240)})
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240),
                        "path": _safe_public_text(DATA_ROOT, 240)}), 500


@app.post("/api/open-url")
def api_open_url():
    """在系统默认浏览器打开外部链接（如官网更新日志）。

    仅允许 https 白名单域名，防被当作任意 URL 打开器滥用。
    """
    try:
        data = request.get_json(force=True) or {}
        url = str(data.get("url") or "").strip()
        if not _is_allowed_external_url(url):
            return jsonify({"ok": False, "error": "url 不在白名单"}), 400
        if os.name == "nt":
            os.startfile(url)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", url])
        else:
            subprocess.Popen(["xdg-open", url])
        return jsonify({"ok": True, "url": url})
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


@app.post("/api/logs/clear")
def api_logs_clear():
    result = clear_logs()
    return jsonify(result)


@app.post("/api/restore")
def api_restore():
    result = recover_network()
    _emit_log(f"[panel] 一键恢复完成：{'OK' if result.get('ok') else 'CHECK'}")
    return jsonify(result)


@app.post("/api/cert")
def api_cert():
    # 安全闸门：安装系统根 CA 是最敏感的一次性操作，必须显式 confirm=true
    # 防止前端误调用或脚本自动装证书（审计第三批 P2）
    body = request.get_json(silent=True) or {}
    confirmed = request.args.get("confirm", "").lower() == "true" or body.get("confirm") is True
    if not confirmed:
        return jsonify({"ok": False, "error": "安装系统根 CA 需显式确认：传 confirm=true"}), 400
    if not CA_CERT.exists():
        # 起短命 mitmdump sidecar 强制生成 CA。复用引擎入口，保证冻结包不依赖
        # 安装机 PATH 中另有一个 mitmdump；同时不触碰正在运行的主代理句柄。
        sidecar = None
        try:
            sidecar = _spawn_mitmdump_sidecar(
                ["-p", "0", "-q", "--set", "connection_strategy=lazy"]
            )
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline and not CA_CERT.exists():
                time.sleep(0.2)
                try:
                    if sidecar.poll() is not None:
                        break
                except Exception:
                    break
        except FileNotFoundError:
            return jsonify({"ok": False, "error": "生成证书失败：未找到 mitmproxy sidecar，请先安装依赖"})
        except Exception as e:
            return jsonify({"ok": False, "error": f"生成证书失败: {_safe_public_text(e, 240)}"})
        finally:
            _stop_sidecar_process(sidecar)
    if not CA_CERT.exists():
        return jsonify({"ok": False, "error": f"未生成证书: {_safe_public_text(CA_CERT, 240)}"}), 500
    if sys.platform != "win32":
        # 不同 Linux 发行版/桌面环境的信任库位置不一致，不能盲写系统目录或
        # 隐式 sudo。返回已生成证书和明确的手动安装提示，由用户选择信任范围。
        scope = "manual"
        return jsonify({
            "ok": False,
            "scope": scope,
            "installed": False,
            "path": str(CA_CERT),
            "error": "已生成 mitmproxy CA；当前系统未自动修改信任库，请按系统文档手动安装",
        })
    args = ["certutil"]
    scope = "LocalMachine" if is_admin() else "CurrentUser"
    if not is_admin():
        args.append("-user")
    args += ["-addstore", "-f", "Root", str(CA_CERT)]
    # certutil 可能因证书存储弹窗/挂起而永不返回，必须限时
    try:
        rc, out = _run_console(args)
    except subprocess.TimeoutExpired:
        _emit_log(f"[panel] 装证书({scope}): 超时")
        return jsonify({"ok": False, "scope": scope, "error": f"certutil 超时（>{_CMD_TIMEOUT}s），请手动双击 {CA_CERT} 安装"})
    except Exception as e:
        return jsonify({"ok": False, "scope": scope, "error": f"certutil 执行失败: {_safe_public_text(e, 240)}"})
    safe_out = _safe_public_text(out, 500)
    _emit_log(f"[panel] 装证书({scope}): rc={rc}")
    return jsonify({"ok": rc == 0, "scope": scope, "output": safe_out, "installed": rc == 0})


def _find_web_dist() -> Path:
    """按优先级寻找 Web 控制台静态资源目录：环境变量 → 打包内置 web_dist → 源码构建 frontend/dist。"""
    env_dist = os.environ.get("MASKIT_WEB_DIST")
    if env_dist and Path(env_dist).exists():
        return Path(env_dist)
    for cand in (
        _BUNDLE_ROOT / "web_dist",
        _BUNDLE_ROOT.parent / "frontend" / "dist",
        _BUNDLE_ROOT.parent / "web_dist",
        ROOT / "frontend" / "dist",
        ROOT / "web_dist",
    ):
        if cand.exists() and (cand / "index.html").exists():
            return cand
    return _BUNDLE_ROOT / "web_dist"


WEB_DIST_DIR = _find_web_dist()


def _get_web_dist_dir() -> Path:
    global WEB_DIST_DIR
    if not WEB_DIST_DIR.exists():
        WEB_DIST_DIR = _find_web_dist()
    return WEB_DIST_DIR


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_spa(path):
    """静态文件托管（Docker 与 WebUI 模式支持）。"""
    if path.startswith("api/"):
        return jsonify({"ok": False, "error": "not_found"}), 404
    web_dir = _get_web_dist_dir()
    if web_dir.exists():
        target = web_dir / path
        # Werkzeug 已规范化 ..，这里再显式钉死在 web_dist 内，不依赖上游行为
        try:
            inside = target.resolve().is_relative_to(web_dir.resolve())
        except Exception:
            inside = False
        if path and inside and target.exists() and target.is_file():
            return send_file(str(target))
        index_file = web_dir / "index.html"
        if index_file.exists():
            return send_file(str(index_file))
    return jsonify({"ok": True, "service": "Data Maskit API", "version": __version__})


def open_browser():
    import time as _t
    _t.sleep(1.2)
    webbrowser.open(f"http://127.0.0.1:{PANEL_PORT}/#token={API_TOKEN}")


# ========== 开机自启 ==========
AUTOSTART_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
# 与 Rust 壳的 AUTOSTART_VALUE 必须一致：两侧不同名会出现「面板显示未开启自启，
# 实际注册表里有一条壳写的」这种对不上的状态
AUTOSTART_VALUE_NAME = "Maskit"
# 更名前的值名，读/写时顺带清理（指向已卸载的旧 exe，开机会弹找不到文件）
AUTOSTART_VALUE_NAME_LEGACY = "LLMShield"

def autostart_enabled():
    """自启是否开启。新旧值名任一存在都算开启。

    只认新名会让「升级前开过自启」的用户在面板里看到未开启，但开机仍会被旧项拉起
    ——UI 与实情脱节比少一个功能更糟。
    """
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0, winreg.KEY_READ) as key:
            for name in (AUTOSTART_VALUE_NAME, AUTOSTART_VALUE_NAME_LEGACY):
                try:
                    winreg.QueryValueEx(key, name)
                    return True
                except FileNotFoundError:
                    continue
            return False
    except FileNotFoundError:
        return False
    except OSError:
        return False


def _purge_stale_legacy_autostart():
    """清掉更名前那条已失效的自启项。

    两种情形删：
    1. 新值名已存在——同一个产品不需要两条自启项，旧的那条必然是过期路径；
    2. 旧项指向的 exe 已不存在——更名后旧安装被卸载，开机弹「找不到文件」。

    旧项指向的文件还在、且新项还没写时**不删**：用户可能真在靠它自启旧版，
    不能替他决定。这种情况由壳侧 heal_autostart() 负责（只有壳知道自己的真实
    路径，能把自启项直接改指到当前 exe）——2026-08-17 实测正是这一格：
    旧项指向构建树里的 llm-shield.exe（文件还在所以没被清），新项从未写入，
    开机拉起的是几天前的构建产物而不是装好的版本。

    启动时跑一次，失败静默（自启是锦上添花，不能挡住引擎启动）。
    """
    if sys.platform != "win32":
        return
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            try:
                val, _t = winreg.QueryValueEx(key, AUTOSTART_VALUE_NAME_LEGACY)
            except FileNotFoundError:
                return
            try:
                winreg.QueryValueEx(key, AUTOSTART_VALUE_NAME)
                winreg.DeleteValue(key, AUTOSTART_VALUE_NAME_LEGACY)
                return
            except FileNotFoundError:
                pass
            # 值形如 "C:\...\llm-shield.exe" --minimized，取第一个引号对里的路径
            m = re.match(r'^\s*"([^"]+)"', str(val or ""))
            exe = m.group(1) if m else str(val or "").split(" ")[0]
            if exe and not Path(exe).exists():
                winreg.DeleteValue(key, AUTOSTART_VALUE_NAME_LEGACY)
    except Exception:
        pass


def set_autostart(enable, exe_path=None):
    try:
        import winreg
        # Tauri 架构：panel 作为引擎 sidecar 运行，sys.executable 指向 LLMShieldEngine.exe，
        # 它不是自启入口（开机后无人拉起引擎）。reg 写入由 Rust 壳的 set_autostart 命令负责
        # （写壳 exe 路径 + --minimized）。这里只同步 config，避免用引擎 exe 覆盖壳路径。
        is_engine_sidecar = getattr(sys, "frozen", False) and "Engine" in (sys.executable or "")
        if not is_engine_sidecar:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0, winreg.KEY_SET_VALUE) as key:
                if enable:
                    path = exe_path or sys.executable
                    winreg.SetValueEx(key, AUTOSTART_VALUE_NAME, 0, winreg.REG_SZ, f'"{path}" --minimized')
                else:
                    try:
                        winreg.DeleteValue(key, AUTOSTART_VALUE_NAME)
                    except FileNotFoundError:
                        pass
        else:
            # 引擎 sidecar：仅删除时写 reg（禁用场景需清 reg）；启用时 reg 由 Rust 壳写，这里不动
            if not enable:
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, AUTOSTART_VALUE_NAME)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
        # 同步 config.autostart，避免与注册表实情脱节。
        # 读-改-写必须整体持 cfg_lock（与 save_config 的迁移写入并发时，
        # 单独原子写挡不住互相覆盖丢更新）。
        try:
            with cfg_lock:
                cfg = load_config()
                cfg["autostart"] = bool(enable)
                save_config(cfg)
        except Exception as e:
            _emit_log(f"[panel] 同步 autostart 到 config 失败: {e}")
        return True
    except Exception as e:
        _emit_log(f"[panel] 设置开机自启失败: {e}")
        return False


def shutdown():
    global shutdown_done
    with shutdown_lock:
        if shutdown_done:
            return
        shutdown_done = True
    # 仅在本面板确曾拉起代理，或当前仍持有子进程句柄时才执行 stop_proxy()，
    # 杜绝未启动代理的从属/测试面板退出时越界释放系统端口
    if state.get("proxy_running") or proc.get("p") is not None:
        stop_proxy()
    # 仅当存在环境备份时才恢复，禁止无备份时越界清空用户的系统代理环境变量
    if ENV_BACKUP_PATH.exists():
        restore_client_env()


def _handle_signal(signum, frame):
    shutdown()
    raise SystemExit(0)


def install_console_close_handler():
    if os.name != "nt":
        return
    try:
        import ctypes
        global _console_handler_ref
        handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)

        def _handler(ctrl_type):
            # CTRL_CLOSE_EVENT/LOGOFF/SHUTDOWN can terminate the process quickly;
            # keep cleanup bounded to local process/env restoration.
            shutdown()
            return False

        _console_handler_ref = handler_type(_handler)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_console_handler_ref, True)
    except Exception:
        pass


def _migrate_data_files():
    """首次启动：数据目录还没有 config.json 时，用随包的 config.example.json 初始化。

    只拷配置模板，绝不拷事件库——打包机上的 shield-events.sqlite3 是开发者自己的
    脱敏记录（含 PII 原文），曾有把它随安装包分发出去的风险。
    example 缺失也不报错：load_config 在文件不存在时会用 default_config()。
    """
    try:
        src_cfg = _BUNDLE_ROOT / "config.example.json"
        if src_cfg.exists() and not CONFIG_PATH.exists():
            CONFIG_PATH.write_text(src_cfg.read_text(encoding="utf-8"), encoding="utf-8")
    except Exception as e:
        _emit_log(f"[panel] 初始化配置失败: {e}")


# ========== 诊断包 ==========
# 存在的理由：崩溃现场、端口占用、错误事件本来就都写在 %APPDATA%\Maskit 下，
# 但用户不知道它们存在，报障时只剩一句「用不了」，来回问十轮才定位。
#
# 隐私红线（比 /api/logs/export 更严——这个文件是要发给开发者的）：
#   1. 绝不含 items[].original / dialog / req_preview / resp_preview 等还原正文
#   2. 绝不含 proxy_token、Authorization、URL 里的凭据
#   3. 日志与崩溃现场是自由文本，必须过 _scrub_text 再放进来
#   4. 不自动上报：只生成内容，由前端展示给用户看过之后自己决定发不发
# 宁可过度打码导致少一点线索，也不能泄一次原文——隐私政策白纸黑字写着
# 「原文永不离开设备」，破一次这个承诺，产品的全部卖点就没了。
# 凭据类。这一组**单独拎出来**是因为日志详情弹窗要复用它：
# 那里必须保留普通 PII 原文（脱敏↔原文对照是详情弹窗存在的理由），
# 但凭据一条都不能出现。混在一张表里就只能全打或全不打。
_SCRUB_CREDENTIAL_PATTERNS = [
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}"), r"\1 <redacted>"),
    # 常见 key 前缀（OpenAI sk-/中转 ah-/Groq gsk_/xAI xai- 等）
    (re.compile(r"(?i)\b(?:sk|ah|gsk|xai|pk|rk|ghp|glpat)[-_][A-Za-z0-9._\-]{8,}"), "<key>"),
    # 厂商固定格式：即使没有 `key=` 前缀也要清洗（上游错误页/回显常是裸值）。
    (re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35,}(?![A-Za-z0-9_-])"), "<key>"),
    (re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"), "<key>"),
    (re.compile(r"(?<![A-Za-z0-9_-])AKID[A-Za-z0-9]{13,32}(?![A-Za-z0-9_-])"), "<key>"),
    (re.compile(r"(?<![A-Za-z0-9_-])github_pat_[A-Za-z0-9_]{50,}(?![A-Za-z0-9_-])"), "<key>"),
    (re.compile(r"(?<![A-Za-z0-9_-])xox[baprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])"), "<key>"),
    (re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd"
                r"|access[_-]?key|private[_-]?key)([\"']?\s*[:=]\s*[\"']?)([^\s\"',;&]{4,})"),
     r"\1\2<redacted>"),
    # PEM 私钥整块（历史库里实测有 468 条明文）。放在这一组而不是 PII 组：
    # 它是所有凭据里最高危的，详情弹窗同样一个字符都不能露。
    (re.compile(r"-----BEGIN[A-Z \-]*PRIVATE KEY-----[\s\S]*?-----END[A-Z \-]*PRIVATE KEY-----"),
     "<private-key>"),
    # 连接串里的密码（scheme://user:PASS@host）——捕获组就是密码本身
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:@/]+:)([^\s@/]{4,})(@)"), r"\1<redacted>\3"),
]

# PII / 本机用户名。诊断包要打，日志详情**不打**。
_SCRUB_PII_PATTERNS = [
    # -- PII。身份证必须排在银行卡之前，否则 18 位会被当成卡号 --
    (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "<phone>"),
    (re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"), "<idcard>"),
    (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "<email>"),
    # 16-19 位连续数字：银行卡。会误伤纳秒时间戳，属可接受的过度打码
    (re.compile(r"(?<!\d)\d{16,19}(?!\d)"), "<digits>"),
    # -- 本机用户名。几乎每条路径里都有，属可识别信息 --
    (re.compile(r"(?i)([A-Z]:\\Users\\)[^\\\r\n\"']+"), r"\1<user>"),
    (re.compile(r"(/home/|/Users/)[^/\r\n\"']+"), r"\1<user>"),
]

_SCRUB_PATTERNS = _SCRUB_CREDENTIAL_PATTERNS + _SCRUB_PII_PATTERNS


def _scrub_text(s, limit=0):
    """自由文本打码。失败返回占位串而不是原文——scrub 出错时放行原文是最坏结果。"""
    try:
        out = str(s)
        for pat, rep in _SCRUB_PATTERNS:
            out = pat.sub(rep, out)
        if limit and len(out) > limit:
            out = out[-limit:]
        return out
    except Exception:
        return "<scrub failed>"


# 凭据标签集合：唯一定义源在 credential_labels.py。
# panel 不 import transparent（那会把 mitmproxy 拖进面板进程），所以以前这里复制一份、
# 靠测试守同步——结果 event_store 那份悄悄少了两类凭据。现在改成都 import 同一个
# stdlib-only 模块，从结构上消灭漂移；保留 `_CREDENTIAL_LABELS` 这个名字给既有调用点。
_CREDENTIAL_LABELS = CREDENTIAL_LABELS


def _scrub_credentials_only(s):
    """只打凭据，保留普通 PII。

    日志详情弹窗的定位是「脱敏 ↔ 原文对照」，把手机号邮箱一起打掉这功能就没了；
    但凭据一个字符都不能露（凭据原文不得入库、不得回显）。所以这里只跑凭据那一组。
    """
    try:
        out = str(s)
        for pat, rep in _SCRUB_CREDENTIAL_PATTERNS:
            out = pat.sub(rep, out)
        return out
    except Exception:
        return "<scrub failed>"


def _scrub_legacy_event(row):
    """日志详情读侧凭据清洗。

    写侧从某个版本起就不再把凭据原文落库了，但**升级用户的历史库里还留着**——
    实测生产库有 CONNSTR、PRIVATE_KEY 等遗留明文。
    "新写入已修" 不等于安全：/api/logs/detail 是按 id 原样回源的，
    点开一条老记录照样把私钥整块渲染出来。

    清库要动用户数据（而且不可逆），读侧清洗不动任何东西、且对未来写入是免费的
    冗余保护，所以做这一层。两件事：
      1. items[] 里凭据标签的 original 换成长度 + sha256 摘要（与写侧同形）
      2. dialog / *_preview 这类自由文本过一遍凭据正则

    普通 PII 的 original 照常保留 —— 那是详情弹窗存在的理由。
    """
    if not isinstance(row, dict):
        return row
    try:
        for item in row.get("items") or []:
            if not isinstance(item, dict):
                continue
            if str(item.get("label", "")).upper() not in _CREDENTIAL_LABELS:
                continue
            original = item.pop("original", None)
            if original is None:
                continue
            text = str(original)
            item["length"] = len(text)
            item["hash"] = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
            item.setdefault("preview", "<redacted>")
        for key in ("dialog", "dialog_req", "resp_preview", "req_preview", "msg", "reason"):
            if isinstance(row.get(key), str):
                row[key] = _scrub_credentials_only(row[key])
    except Exception:
        # 清洗失败一律不下发正文——放行原文是最坏结果（与 _scrub_text 同一取舍）
        return {k: v for k, v in row.items()
                if k not in ("items", "dialog", "dialog_req", "resp_preview", "req_preview")}
    return row


def _safe_target(url):
    """上游地址只留 scheme+host+path，剥掉 userinfo/query/fragment。

    该函数用于诊断、日志和状态展示，不改变实际转发地址。即使用户把 key
    放进 URL，也不会因为错误信息或健康检查而回显出去。
    """
    try:
        raw = str(url or "").strip()
        if not raw:
            return ""
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
            return "<redacted-target>"
        u = urlsplit(raw)
        scheme = (u.scheme or "").lower()
        host = u.hostname or ""
        if not scheme or not host or scheme not in {"http", "https"}:
            return "<redacted-target>"
        try:
            port = u.port
        except ValueError:
            return "<redacted-target>"
        # Normalize IDN for stable diagnostics, but never include userinfo.
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return "<redacted-target>"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if port:
            host = f"{host}:{port}"
        path = unquote(u.path or "")
        path = _safe_public_text(path, 1024)
        # A malformed path must not inject a second log/report line.
        path = "".join(ch if ord(ch) >= 0x20 and ord(ch) != 0x7F else " " for ch in path)
        return f"{scheme}://{host}{path}"
    except Exception:
        return "<redacted-target>"


def _safe_upstream_display(value):
    """清洗 upstream 展示值；允许普通配置名称，同时剥掉 URL 凭据。"""
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        return _safe_target(text)
    return _safe_public_text(text, 160)


_ALLOWED_EXTERNAL_GITHUB_PATH = "/xiaYuTian11/maskit"


def _is_allowed_external_url(url):
    """校验面板可调用的外部浏览器 URL。

    只接受 HTTPS、无 userinfo、默认/443 端口，并要求主机和路径边界精确匹配；
    例如 `github.com/xiaYuTian11/maskit.evil`、账号密码和非 443 端口都会拒绝。
    """
    try:
        raw = str(url or "").strip()
        if not raw or any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch == "\\" for ch in raw):
            return False
        parsed = urlsplit(raw)
        if parsed.scheme.lower() != "https" or parsed.username or parsed.password:
            return False
        # 外部入口只打开固定文档/仓库路径；query/fragment 可能携带 token 或
        # 把用户带到未审查的跳转参数，统一拒绝。
        if parsed.query or parsed.fragment:
            return False
        try:
            port = parsed.port
        except ValueError:
            return False
        if port not in (None, 443) or not parsed.hostname:
            return False
        host = parsed.hostname.lower()
        if host not in {"github.com", "linux.do"}:
            return False
        path = unquote(parsed.path or "/")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
            return False
        if host == "github.com":
            return path == _ALLOWED_EXTERNAL_GITHUB_PATH or path.startswith(
                _ALLOWED_EXTERNAL_GITHUB_PATH + "/"
            )
        return True
    except Exception:
        return False


def _diag_scrub_word_lists(stats):
    """把诊断包里词榜的**词面**过一遍 `_scrub_text`（计数与标签原样保留）。

    为什么必须做（实测缺陷）：`today_stats()` 的词榜在 `record_plaintext_words` 开启
    （**默认就是开**）时存的是**明文敏感值**——那是给用户自己在面板上看的数据，本来就该
    明文。但诊断包是**要发给开发者**的（见本函数调用处的隐私承诺：连日志、崩溃现场这些
    自由文本里的凭据与 PII 都要打码），明文一起带走等于把用户的手机号/邮箱/自定义词表
    原封不动外发——诊断包最不能出的就是这种错。

    只脱敏词面、保留 `label`/`count`：诊断需要的正是「哪一类、命中多少」，
    而不是「具体命中了什么」。`copy.deepcopy` 是防止污染调用方（同一份 dict 也可能
    被 `/api/stats/today` 复用）。
    """
    if not isinstance(stats, dict):
        return stats
    try:
        out = copy.deepcopy(stats)
    except Exception:
        return stats

    def scrub_pairs(pairs):
        if not isinstance(pairs, list):
            return
        for item in pairs:
            if isinstance(item, dict) and isinstance(item.get("word"), str):
                item["word"] = _scrub_text(item["word"], 120)

    def scrub_label_map(by_label):
        if isinstance(by_label, dict):
            for pairs in by_label.values():
                scrub_pairs(pairs)

    scrub_pairs(out.get("top_words"))
    scrub_label_map(out.get("by_label_words"))
    by_ingress = out.get("words_by_ingress")
    if isinstance(by_ingress, dict):
        for view in by_ingress.values():
            if isinstance(view, dict):
                scrub_pairs(view.get("top_words"))
                scrub_label_map(view.get("by_label_words"))
    return out


def _diagnostics_payload(error_limit=60):
    """组装诊断包。任何一节取数失败都降级成错误字符串，不让整包生成失败——
    诊断包恰恰是在系统半死不活的时候才用得上。"""
    cfg = load_config()
    out = {
        "schema": 1,
        "generated_at": int(time.time()),
        "masked": True,   # 与 masked_export 同义：本包不含任何还原正文
    }

    out["app"] = {
        "version": __version__,
        "platform": sys.platform,
        "os": platform.platform(),
        "arch": platform.machine(),
        "python": sys.version.split()[0],
        "frozen": bool(getattr(sys, "frozen", False)),
        "admin": is_admin(),
        "data_root_is_appdata": str(DATA_ROOT).lower().endswith("maskit"),
    }

    running = bool(state.get("proxy_running"))
    out["proxy"] = {
        "running": running,
        "capture_mode": state.get("capture_mode") or cfg.get("capture_mode", "reverse"),
        "fallback_mode": str(state.get("fallback_mode") or ""),
        "passthrough": bool(state.get("passthrough")),
        "restarts": state.get("restarts"),
        "generation": state.get("generation"),
        "uptime_s": int(time.time() - state["started_at"]) if running else 0,
        "last_error": _scrub_text(state.get("last_error", ""), 400),
        "auto_recovered_at": state.get("auto_recovered_at"),
        "auto_recover_fail": _scrub_text(state.get("auto_recover_fail") or "", 400),
        "ca_cert_exists": CA_CERT.exists(),
    }

    # 端口实况：一次性 netstat。fresh=True——诊断是一次性动作，读缓存会给出过期结论
    try:
        expected = set(_expected_listen_ports(cfg))
        occ = _listening_port_pids(expected, fresh=True)
        out["ports"] = [
            {"port": p, "listening": p in occ,
             "holder": ("mitmdump" if any(_is_mitmdump_pid(x) for x in occ.get(p, []))
                        else "panel" if any(_is_shield_panel_pid(x) for x in occ.get(p, []))
                        else "other" if occ.get(p) else "")}
            for p in sorted(expected)
        ]
    except Exception as e:
        out["ports"] = {"error": _safe_public_text(e, 240)}

    out["upstreams"] = [
        {"name": u.get("name"), "port": u.get("port"),
         "target": _safe_target(u.get("target")),
         "base_path": u.get("base_path"), "use_proxy": bool(u.get("use_proxy"))}
        for u in (cfg.get("upstreams") or [])
    ]

    # 配置只取开关类字段。绝不整包回传 config——里面有 sensitive 词库（用户的
    # 公司名、项目代号、客户名单），那是需要保护的内容本身，不是诊断信息。
    egress = cfg.get("egress_proxy") or {}
    out["settings"] = {
        "filter_enabled": bool(cfg.get("filter_enabled", True)),
        "fail_closed": bool(cfg.get("fail_closed", True)),
        "stream_response": bool(cfg.get("stream_response", True)),
        "stream_exclude_hosts": cfg.get("stream_exclude_hosts") or [],
        "response_scan": bool(cfg.get("response_scan", True)),
        "stop_mode": str(cfg.get("stop_mode") or "error"),
        "debug": bool(cfg.get("debug", False)),
        "diagnostic_unmatched": bool(cfg.get("diagnostic_unmatched", False)),
        "egress_proxy_enabled": bool(egress.get("enabled")),
        "egress_proxy_scheme": _safe_target(egress.get("url")).split("://")[0] if egress.get("url") else "",
        "audit_enabled": bool((cfg.get("audit") or {}).get("enabled", True)),
        "builtin_rules_on": sorted(k for k, v in (cfg.get("builtin_rules") or {}).items() if v),
        # 词库只报数量，不报内容
        "custom_word_groups": len(cfg.get("sensitive") or {}),
        "custom_word_count": sum(len(v or []) for v in (cfg.get("sensitive") or {}).values()),
    }

    out["license"] = {"edition": "community", "status": "active", "enforced": False}

    # 最近的异常事件。只留元数据 + 规则标签，items 连 preview 都不带
    # （preview 虽是打码的，但发给第三方时能少给一分是一分）
    try:
        bad = {"ERR", "BLOCK", "DNS_ERROR", "SCAN_WARN"}
        keep = ("ts", "type", "sid", "host", "path", "method", "status", "http_status",
                "stream_mode", "stream_actual", "reason", "count", "restored",
                "mask_ms", "total_ms")
        rows = []
        for e in fetch_events(since=0, limit=600, max_limit=EXPORT_MAX):
            if e.get("type") not in bad and int(e.get("http_status") or 0) < 400:
                continue
            row = {k: e[k] for k in keep if k in e}
            row["msg"] = _scrub_text(e.get("msg") or "", 500)
            row["rules"] = sorted({str(i.get("label")) for i in (e.get("items") or [])
                                   if isinstance(i, dict) and i.get("label")})
            rows.append(row)
            if len(rows) >= error_limit:
                break
        out["recent_errors"] = rows
        out["recent_error_count"] = len(rows)
    except Exception as e:
        out["recent_errors"] = {"error": _safe_public_text(e, 240)}

    try:
        # 词榜必须过 `_diag_scrub_word_lists`：`today_stats()` 在 record_plaintext_words
        # 开启（默认）时词面是**明文**，而诊断包是要发给开发者看的（见该 helper 的说明）。
        out["stats_today"] = _diag_scrub_word_lists(today_stats())
    except Exception as e:
        out["stats_today"] = {"error": _safe_public_text(e, 240)}

    # 崩溃现场：最近 3 份，各留尾部 6KB。这是 mitmdump 静默退出唯一的归因线索
    try:
        dumps = sorted((DATA_ROOT / "crash-dumps").glob("crash-*.txt"))[-3:]
        out["crash_dumps"] = [
            {"name": f.name, "size": f.stat().st_size,
             "content": _scrub_text(f.read_text(encoding="utf-8", errors="replace"), 6000)}
            for f in dumps
        ]
    except Exception as e:
        out["crash_dumps"] = {"error": _safe_public_text(e, 240)}

    out["log_tail"] = [_scrub_text(x, 600) for x in list(log_buf)[-200:]]
    return out


@app.get("/api/diagnostics")
def api_diagnostics():
    """生成诊断包（JSON）。故意不做额度限制——报障的绝大多数是免费用户，
    把诊断能力关在付费墙后面等于自断故障来源。"""
    try:
        payload = _diagnostics_payload()
    except Exception as e:
        # 整包失败也要给出点东西，否则用户连「生成失败」都没法报
        payload = {"schema": 1, "generated_at": int(time.time()), "masked": True,
                   "fatal": _safe_public_text(e, 240), "app": {"version": __version__}}
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    resp = make_response(body)
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    return resp


@app.post("/api/diagnostics/save")
def api_diagnostics_save():
    """把诊断包写到数据目录，返回路径供前端展示 / 打开所在文件夹。

    由 panel 写盘而不是浏览器下载：Tauri webview 的下载行为不稳定，
    而写数据目录是 panel 本来就在做的事，不需要新增任何文件系统权限。
    只保留最近 5 份，避免用户反复点击堆一堆大文件。
    """
    try:
        payload = _diagnostics_payload()
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = DATA_ROOT / f"diagnostics-{ts}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            for old in sorted(DATA_ROOT.glob("diagnostics-*.json"))[:-5]:
                old.unlink(missing_ok=True)
        except Exception:
            pass
        return jsonify({"ok": True, "path": str(path), "size": path.stat().st_size})
    except Exception as e:
        return jsonify({"ok": False, "error": _safe_public_text(e, 240)}), 500


def start_panel_server(open_browser_on_start=True):
    """启动 Flask 面板服务。供 `panel.py` 直接运行或桌面壳 sidecar 复用。
    在主线程调用时会注册信号处理和 console 关闭钩子；在子线程（pywebview 模式）跳过。
    """
    if ENV_BACKUP_PATH.exists():
        restore_client_env()
    _migrate_data_files()
    # 启动时确保数据库就绪：自动建表/迁移，并在库文件损坏时自动隔离并重建自愈
    _ensure_db()
    load_config()  # 预热配置并同步运行时全局状态
    prune_event_log()
    preload_events()
    # 价格目录后台自动同步（启动时 + 每 7 天过期刷新；失败静默，不阻塞启动）
    _maybe_auto_sync_prices()
    # 定期复查：桌面壳常驻数周不重启，只在启动时判断一次的话，开了
    # price_sync_enabled 的用户在进程生命周期内价格也永不刷新（审计 P2）。
    # 每 6 小时复查一次（_maybe_auto_sync_prices 内部自判是否超过同步间隔）。
    _price_sync_timer = threading.Timer(6 * 3600, _price_sync_loop)
    _price_sync_timer.daemon = True
    _price_sync_timer.start()
    # 把本次 token 写文件，供壳层/外部脚本读取。
    # 显式 0600：默认 umask 022 会落成 0644，同机其他本地用户即可读到面板令牌
    # —— 拿到它等于拿到代理开关与配置读写权限。Windows 上 mode 只影响只读位，
    # 该目录另有 ACL 收紧（仅当前用户 + SYSTEM + Administrators），两者互补。
    token_path = ROOT / "proxy_token"
    try:
        fd = os.open(str(token_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, API_TOKEN.encode("utf-8"))
        finally:
            os.close(fd)
        # 已存在的旧文件不会被 O_CREAT 的 mode 改写，必须显式再收紧一次
        os.chmod(token_path, 0o600)
    except Exception as e:
        _emit_log(f"[panel] 写 token 文件失败(壳层取不到 token): {e}")
    atexit.register(shutdown)
    # signal/console handler 只能在主线程注册；pywebview 模式下本函数在子线程运行
    is_main = threading.current_thread() is threading.main_thread()
    if is_main:
        signal.signal(signal.SIGINT, _handle_signal)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _handle_signal)
        install_console_close_handler()
    if open_browser_on_start:
        threading.Thread(target=open_browser, daemon=True).start()
    print(f"[panel] http://{PANEL_HOST}:{PANEL_PORT}")
    if REMOTE_MODE:
        # 远程模式下用户只能从这里拿到 token（随机时打印明文；固定时只提示来源）
        if _env_token:
            print("[panel] remote mode: token from MASKIT_PANEL_TOKEN; open http://<host>:%d (enter token in WebUI, or quick access: .../#token=<MASKIT_PANEL_TOKEN>)" % PANEL_PORT)
        else:
            print(f"[panel] remote mode: MASKIT_PANEL_TOKEN not set, generated token = {API_TOKEN}")
            print(f"[panel] open http://<host>:{PANEL_PORT} (enter token in WebUI, or quick access: .../#token={API_TOKEN})")
    print("[proxy] stopped; click Start in the panel when needed")
    # 关掉 werkzeug 的逐请求访问日志：面板每 2.5s 轮询 /api/status，桌面端常驻一天
    # 就是几万行，而它被 shell 以 append 方式写进 engine-stdout.log，把真正的启动
    # 失败/崩溃线索彻底埋掉（这也是那个文件能涨到几百 MB 的主因）。
    # 需要时用 MASKIT_ACCESS_LOG=1 打开；被拒绝的请求另有 api_guard 的结构化日志。
    if os.environ.get("MASKIT_ACCESS_LOG", "").strip() not in ("1", "true", "yes"):
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
    try:
        app.run(host=PANEL_HOST, port=PANEL_PORT, debug=False, use_reloader=False)
    finally:
        shutdown()


if __name__ == "__main__":
    import argparse as _ap
    _p = _ap.ArgumentParser(description="Data Maskit 引擎面板")
    _p.add_argument("--no-browser", action="store_true", help="不自动打开浏览器（测试/后台用）")
    _a = _p.parse_args()
    # 更名后的一次性清理：删掉指向已卸载旧 exe 的自启项（开机弹「找不到文件」）
    _purge_stale_legacy_autostart()
    start_panel_server(open_browser_on_start=not _a.no_browser)
