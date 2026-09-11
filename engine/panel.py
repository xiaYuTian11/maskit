"""
Data Maskit 控制面板 - 本地 Flask 服务
双击 panel.bat 启动，浏览器访问 http://127.0.0.1:5801
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
__version__ = '0.2.6'
import json
import copy
import hashlib
import math
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
    BUILTIN_RULE_META,
    parse_egress_proxy,
    OPENROUTER_MODELS_URL,
    PRICE_SYNC_INTERVAL_DAYS,
    MODEL_PRICES,
)

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
)
import audit_engine as audit_eng
ROOT = DATA_ROOT  # 兼容旧引用（CONFIG_PATH/PID_FILE/ENV_BACKUP_PATH 等可写文件）
CONFIG_PATH = DATA_ROOT / "config.json"
SCRIPTS_DIR = _BUNDLE_ROOT  # transparent.py / shield_defaults.py 所在目录（只读资源）
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
MARKER = "# LLM-Shield"
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
# 反代 HTTPS 终止时显式信任单跳 X-Forwarded-*。默认关闭，避免直接暴露面板时
# 客户端伪造转发头绕过 Origin 同源校验；启用者必须确保前置代理覆盖而非追加这些头。
TRUST_PROXY_ENV = "MASKIT_TRUST_PROXY"
# 反代/兜底端口监听地址：与面板一样，Docker 用 MASKIT_LISTEN_HOST=0.0.0.0 对外
LISTEN_HOST = os.environ.get("MASKIT_LISTEN_HOST", "127.0.0.1").strip() or "127.0.0.1"
# API token 每次启动随机；远程模式下用户无法读容器内 proxy_token 文件，
# 允许 MASKIT_PANEL_TOKEN 固定（≥16 位，太短直接忽略并回退随机，宁可拒绝也不弱化）。
_MIN_PANEL_TOKEN_LEN = 16
_env_token = os.environ.get("MASKIT_PANEL_TOKEN", "").strip()
if _env_token and (len(_env_token) < _MIN_PANEL_TOKEN_LEN or not _env_token.isascii()):
    print(f"[panel] MASKIT_PANEL_TOKEN 无效（需 ≥{_MIN_PANEL_TOKEN_LEN} 位 ASCII），已忽略并改用随机 token")
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
        return jsonify({"ok": False, "error": "host_rejected", "message": "非法请求来源 Host"}), 403

    # API 令牌校验（主防线）：任何外部未授权请求在第一道防线直接阻断
    token = request.headers.get("X-Shield-Token", "")
    # compare_digest 对非 ASCII str 会抛 TypeError → 500，先转 bytes
    if not secrets.compare_digest(token.encode("utf-8", "replace"), API_TOKEN.encode("utf-8")):
        return jsonify({"ok": False, "error": "invalid_token", "message": "无效请求令牌"}), 403

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
        return jsonify({
            "ok": False,
            "error": "origin_rejected",
            "message": "Origin 校验未通过",
            "current_origin": origin,
            "expected_origin": f"{scheme}://{host}",
        }), 403

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
    """跑 Windows 控制台命令，返回 (returncode, stdout+stderr 文本)。

    不能用 subprocess 的 text=True：netstat/tasklist/taskkill/wmic/certutil 按系统
    代码页输出（中文 Windows 为 GBK），而 PYTHONUTF8=1 会把 text 模式默认编码定成
    utf-8，解码异常抛在 subprocess 内部 _readerthread 中，调用方 except 捕不到，
    只留下线程堆栈 —— 后果是端口占用探测返回空、PID 存活校验与 mitmdump 识别恒为
    False（表现为"启动即网络异常"）。故取原始字节，交 console_decode 解码。

    超时/启动失败按调用方既有语义抛出，由各调用点的 except 处理。
    """
    proc = subprocess.run(
        argv, capture_output=True,
        timeout=_CMD_TIMEOUT if timeout is None else timeout,
        creationflags=_no_window(),
    )
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
                retention_days = int(load_config().get("log_retention_days") or LOG_RETENTION_DAYS)
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
    """读取 Transfer-Encoding: chunked 请求体并解码（BaseHTTPRequestHandler 不自动解）。"""
    body = b""
    while True:
        try:
            line = rfile.readline()
        except Exception:
            break
        if not line:
            break
        try:
            size = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            break
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
        body += rfile.read(size)
        rfile.read(2)  # 块尾 CRLF
        if len(body) > limit:
            raise ValueError("request body too large")
    return body


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

        def log_message(self, *a):
            pass

        def _do_forward(self):
            _fwd_t0 = time.perf_counter()
            _first_byte_ms = None
            # Content-Length 缺失/畸形/为 0（GET、无 body POST）→ 空 body；
            # chunked 请求手动解码后按完整 body 转发（http.client 不支持直接透传 chunk 帧）
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (ValueError, TypeError):
                length = -1
            # 请求体上限：防声明超大正文占满线程/内存（审计性能观察项）
            if length > _MAX_PASSTHROUGH_BODY:
                self.send_error(413, "Request body too large")
                return
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                try:
                    body = _read_chunked_body(self.rfile)
                    if len(body) > _MAX_PASSTHROUGH_BODY:
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

            # 原样转发客户端头，UA 必须保留（Cloudflare 会按 UA 拦 Python-urllib）
            headers = {}
            for k, v in self.headers.items():
                lk = k.lower()
                if lk in ("host", "content-length", "transfer-encoding", "connection", "proxy-connection", "accept-encoding"):
                    continue
                headers[k] = v
            headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            if proxy_host and proxy_port:
                # 走出口代理 CONNECT 隧道（境内中转直连，境外官方 API 走代理）
                if use_https:
                    conn = http.client.HTTPSConnection(proxy_host, proxy_port, timeout=900)
                    conn.set_tunnel(host, port)
                else:
                    conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=900)
                    conn.set_tunnel(host, port)
            else:
                conn = (http.client.HTTPSConnection(host, port, timeout=900)
                        if use_https else http.client.HTTPConnection(host, port, timeout=900))
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
                self.send_response(resp.status)
                # 响应定界策略：上游给了 Content-Length（非流式）→ 原样保留，
                # 客户端可 keep-alive 复用连接；SSE/chunked/无长度 → 剥 TE 头 +
                # Connection: close 以 EOF 定界（http.client 已解 chunked 成纯 body）。
                is_streaming = resp.getheader("Transfer-Encoding", "").lower() == "chunked" or \
                    "text/event-stream" in resp.getheader("Content-Type", "").lower() or \
                    not resp.getheader("Content-Length")
                for k, v in resp.getheaders():
                    lk = k.lower()
                    if lk == "transfer-encoding" or lk == "connection":
                        continue
                    if lk == "content-length" and is_streaming:
                        continue
                    self.send_header(k, v)
                self.send_header("Connection", "close" if is_streaming else "keep-alive")
                self.end_headers()
                # 流式逐块回传（SSE 兼容：不缓存整段）。
                # 必须用 read1()：read(n) 会攒满 n 字节才返回，LLM SSE 单事件只有
                # 几十~几百字节永远攒不满 64KB → 客户端等整个生成结束才见首字节
                # （实测 read=2.0s 一次性返回 vs read1=0s 逐块返回）。
                sent = 0
                resp_tail_chunks = []
                tail_len = 0
                while True:
                    chunk = resp.read1(65536)
                    if not chunk:
                        break
                    if _first_byte_ms is None:
                        _first_byte_ms = (time.perf_counter() - _fwd_t0) * 1000
                    sent += len(chunk)
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    # 留存尾部 chunk（用于提取 usage 计费，最大 64KB）
                    resp_tail_chunks.append(chunk)
                    tail_len += len(chunk)
                    if tail_len > 65536:
                        while tail_len > 65536 and resp_tail_chunks:
                            tail_len -= len(resp_tail_chunks.pop(0))
                self.wfile.flush()
                # 尝试从尾部文本提取 token usage（供首屏 Token 与费用估算）
                resp_usage = {}
                if resp_tail_chunks:
                    try:
                        from shield_defaults import extract_usage
                        tail_text = b"".join(resp_tail_chunks).decode("utf-8", errors="replace")
                        resp_usage = extract_usage(tail_text)
                    except Exception:
                        pass
                # 透传期间记 PASS 事件：不脱敏时段的流量也要留痕
                # （此前透传完全不记日志，用户无法确认流量经过了自己）
                try:
                    enqueue_event({
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
                    })
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
                try:
                    self.send_error(502, "透传转发失败，请查看面板日志")
                except Exception:
                    pass
            finally:
                conn.close()

        do_GET = _do_forward
        do_POST = _do_forward
        do_PUT = _do_forward
        do_PATCH = _do_forward
        do_DELETE = _do_forward

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

        def log_message(self, *a):
            pass

        def _reject(self):
            # 必须读掉请求体：不读干净就回响应，客户端侧常表现为连接重置而非 503
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (ValueError, TypeError):
                length = 0
            body = b""
            if length > 0:
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
        return False, "本机透明捕获需要管理员权限，请用桌面快捷方式或右键以管理员身份运行 panel.bat"
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
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             bufsize=1,
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


def _is_shield_panel_pid(pid):
    """识别「另一个本产品面板」进程（源码 panel.py 或打包 MaskitEngine.exe）。

    面板自身会起 503 占位/透传监听器占住上游端口（_start_fallback），它不是
    mitmdump 进程，_is_mitmdump_pid 认不出来 → 换实例/重启时端口永远「被非
    mitmdump 进程占用」→ 自动重启失败（实测空窗 29 分钟，只能手动断开再启用）。
    特征：CommandLine 含 panel.py 或产品名；mitmdump 类进程由 _is_mitmdump_pid
    管，这里明确排除避免重复识别。调用方必须已确认该进程占用上游端口。

    产品名要同时认新旧两套（maskit / llmshield）：更名后新旧版本可能共存于同一台
    机器，只认新名会让「旧版占着端口」重新变成认不出的僵局。
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
        return any(mark in low for mark in ("panel.py", "engine_entry.py", "maskit", "llmshield"))
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
    return "panel.py" in low or "maskit" in low or "llmshield" in low


def _free_upstream_ports():
    """一次扫描并释放代理端口，避免逐端口 netstat 阻塞启停请求。

    杀两类占用者：mitmdump 相关进程（含 python 子进程），以及另一个 LLM Shield
    面板的 503 占位/透传监听（_is_shield_panel_pid）。曾直接按端口杀 PID，会强杀
    占用 187xx 段的无关第三方进程（数据丢失风险）；也曾在面板 503 占位占端口时
    杀不掉导致自动重启失败——只杀可识别为 Shield 相关、且确在监听上游端口的进程。
    """
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


def _stop_proxy_locked():
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
    _start_fallback("已停止代理")
    return True, None


def stop_proxy():
    """停止代理：杀 mitmdump 进程树 + 释放 187xx 端口，避免「停止后再启动端口被占用」。"""
    with lock:
        state["proxy_stopping"] = True
        try:
            return _stop_proxy_locked()
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
        "builtin_rules": dict(DEFAULT_BUILTIN_RULES),
        "secret_prefixes": list(DEFAULT_SECRET_PREFIXES),
        "debug": False,
        "diagnostic_unmatched": False,
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
        # 默认关闭：这是引擎唯一的主动出站请求（拉模型价格表），交给用户显式开启
        "price_sync_enabled": False,
        "price_sync_url": DEFAULT_PRICE_SYNC_URL,
        "price_sync_interval_days": 7,
        "log_retention_days": 7,
        "autostart": False,
        "start_minimized": False,
        "auto_start_proxy": True,
        "audit": {
            "enabled": True,
            "passive": True,
            "active_probes": False,
            "severity_floor": "MEDIUM",
            "auto_report": False,
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
    if egress_enabled and not any(u.get("use_proxy") for u in ups):
        warn.append("出口代理已启用，但没有任何客户端勾选「走代理」，当前不会生效")

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
        "stream_response": bool(raw.get("stream_response", True)),
        "stream_exclude_hosts": _normalize_host_list(raw.get("stream_exclude_hosts")),
        "stop_mode": stop_mode,
        "egress_proxy": egress,
        "model_prices": _normalize_model_prices(raw.get("model_prices")),
        "price_sync_enabled": bool(raw.get("price_sync_enabled", False)),
        "price_sync_url": str(raw.get("price_sync_url") or DEFAULT_PRICE_SYNC_URL).strip(),
        "price_sync_interval_days": max(1, min(90, (int(raw.get("price_sync_interval_days", 7) or 7) if str(raw.get("price_sync_interval_days", "")).isdigit() else 7))),
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
    }


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
        "signals": signals,
    }


def _sync_runtime_config(cfg):
    """把持久化配置同步给面板进程内直接依赖的运行时全局状态。

    load_config() 与 save_config() 写盘后均原子调用本函数，确保 UI 保存、
    API 调用与配置回滚后，内存中的开关（如 _origin_check_enabled）
    与明文统计设置 100% 立即生效，杜绝下一次读盘前的时序空窗期。
    """
    global _origin_check_enabled
    if isinstance(cfg, dict):
        _origin_check_enabled = bool(cfg.get("origin_check", True))
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
                if str(cfg.get("stop_mode") or "").strip().lower() in ("error", "block"):
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
    except Exception as e:
        _emit_log(f"[panel] 端口变化检测失败: {_safe_public_text(e, 240)}")
    # warnings 回传前端提示，避免用户输入被静默丢弃/改写却毫无解释
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
        "egress_proxy_users": [u.get("name") for u in (cfg.get("upstreams") or [])
                               if u.get("use_proxy")],
        "debug": bool(cfg.get("debug", False)),
        "start_minimized": bool(cfg.get("start_minimized", False)),
        "auto_start_proxy": bool(cfg.get("auto_start_proxy", True)),
        "audit": cfg.get("audit", {}),
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
    force=True 时跳过开关校验（手动触发视同用户明确授权），成功后自动启用开关。
    成功更新 _price_cache + _price_sync_state；失败只记 last_error，不清缓存。
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
                        if force and not cfg.get("price_sync_enabled", False):
                            try:
                                cfg["price_sync_enabled"] = True
                                save_config(cfg)
                            except Exception:
                                pass
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


@app.get("/api/audit/job")
def api_audit_job():
    """轮询扫描进度。前端据此显示进度与结果，刷新页面也能接回。"""
    return jsonify({k: v for k, v in audit_job.items() if k != "cancel"})


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
            return jsonify({"ok": False, "error": "已有扫描在运行", "job": {k: v for k, v in audit_job.items() if k != "cancel"}}), 409
        upstream_name = str(data.get("upstream_name") or "").strip()
        model = str(data.get("model") or "claude-3-5-sonnet").strip()
        profile = str(data.get("profile") or "general").strip()
        if profile not in ("general", "web3", "full"):
            profile = "general"
        cfg = load_config()
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
        audit_job.update({
            "running": True, "started_at": time.time(), "done": 0, "total": 0,
            "phase": "准备探针", "cancel": False, "result": None, "error": "",
        })
        threading.Thread(
            target=_audit_scan_worker,
            args=(target, upstream_name, model, profile, cfg),
            daemon=True,
        ).start()
    return jsonify({"ok": True, "started": True})


def _audit_scan_worker(target, upstream_name, model, profile, cfg):
    """后台执行主动审计扫描，进度写 audit_job。"""
    try:
        result = _run_audit_scan(target, upstream_name, model, profile, cfg)
        audit_job["result"] = result
    except Exception as e:
        audit_job["error"] = _safe_public_text(e, 300)
        _emit_log(f"[audit] 扫描失败: {_safe_public_text(e, 200)}")
    finally:
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
    return jsonify(result)


@app.post("/api/proxy/start")
def api_start():
    ok, err = start_proxy()
    return jsonify({"ok": ok, "error": err})


@app.post("/api/proxy/stop")
def api_stop():
    ok, err = stop_proxy()
    return jsonify({"ok": ok, "error": err})


@app.get("/api/logs")
def api_logs():
    if time.time() - _last_log_prune[0] > 3600:
        prune_event_log()
        _last_log_prune[0] = time.time()
    since = _arg_int("since", 0, 0, 2**31)
    limit = _arg_int("limit", 500, 1, 5000)
    # 默认显示全部事件（含 SKIP/PASS 噪声）。曾默认 '1' 隐藏，用户会误以为日志丢了。
    sensitive_only = request.args.get("sensitive", "0") != "0"
    query = request.args.get("q", "")
    # 全文搜索开关：默认只搜结构化列（host/path/method/status/type），
    # payload LIKE 全表扫描仅在用户显式勾选「全文搜索（全库）」时启用。
    fulltext = request.args.get("fulltext", "0") != "0"
    event_type = request.args.get("type", "").strip().upper() or None
    if event_type and not re.fullmatch(r"[A-Z_]{1,32}", event_type):
        event_type = None
    ev = fetch_events(since=since, limit=limit, sensitive_only=sensitive_only,
                      query=query, fulltext=fulltext, event_type=event_type)
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
        retention = int(load_config().get("log_retention_days") or LOG_RETENTION_DAYS)
    except Exception:
        retention = LOG_RETENTION_DAYS
    return jsonify({
        "events": ev,
        "tail": tail,
        "retention_days": retention,
        "store": "sqlite",
        "db": str(DB_PATH),
        "sensitive_only": sensitive_only,
        "total": len(ev),
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
    return jsonify({"ok": True, "event": _scrub_legacy_event(row)})


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
        tr._maybe_reload(force=True)
        sid = f"demo-{secrets.token_hex(4)}"
        tr._new_session(sid, source={"kind": "demo"})
        masked = tr.mask(text, sid)
        sess = tr.sessions.get(sid) or {}
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
        # 清理 demo 会话，避免污染真实映射
        try:
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


def _find_web_dist():
    """按优先级寻找 Web 控制台静态资源目录：环境变量 → 打包内置 web_dist → 源码构建 frontend/dist。"""
    env_dist = os.environ.get("MASKIT_WEB_DIST")
    if env_dist and Path(env_dist).exists():
        return Path(env_dist)
    for cand in (_BUNDLE_ROOT / "web_dist", ROOT / "frontend" / "dist", ROOT / "web_dist"):
        if cand.exists() and (cand / "index.html").exists():
            return cand
    return _BUNDLE_ROOT / "web_dist"


WEB_DIST_DIR = _find_web_dist()


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_spa(path):
    """静态文件托管（Docker 与 WebUI 模式支持）。"""
    if path.startswith("api/"):
        return jsonify({"ok": False, "error": "not_found"}), 404
    if WEB_DIST_DIR.exists():
        target = WEB_DIST_DIR / path
        # Werkzeug 已规范化 ..，这里再显式钉死在 web_dist 内，不依赖上游行为
        try:
            inside = target.resolve().is_relative_to(WEB_DIST_DIR.resolve())
        except Exception:
            inside = False
        if path and inside and target.exists() and target.is_file():
            return send_file(str(target))
        index_file = WEB_DIST_DIR / "index.html"
        if index_file.exists():
            return send_file(str(index_file))
    return jsonify({"ok": True, "service": "Data Maskit API", "version": __version__})


def open_browser():
    import time as _t
    _t.sleep(1.2)
    webbrowser.open(f"http://127.0.0.1:{PANEL_PORT}")


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
    stop_proxy()
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


# 凭据标签集合。必须与 transparent.CREDENTIAL_LABELS 一致——
# panel 不 import transparent（那会把 mitmproxy 拖进面板进程），所以这里复制一份，
# 由 tests 里的同步用例守死，别让两边悄悄漂移。
_CREDENTIAL_LABELS = {"API_KEY", "TOKEN", "SECRET", "ACCESS_KEY", "JWT",
                      "CONNSTR", "PRIVATE_KEY"}


def _scrub_credentials_only(s):
    """只打凭据，保留普通 PII。

    日志详情弹窗的定位是「脱敏 ↔ 原文对照」，把手机号邮箱一起打掉这功能就没了；
    但凭据一个字符都不能露（AGENTS 约束 13）。所以这里只跑凭据那一组。
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
        out["stats_today"] = today_stats()
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
    """启动 Flask 面板服务。供 panel.py 直接运行或 app.py (pywebview) 复用。
    在主线程调用时会注册信号处理和 console 关闭钩子；在子线程（pywebview 模式）跳过。
    """
    if ENV_BACKUP_PATH.exists():
        restore_client_env()
    _migrate_data_files()
    init_db()
    load_config()  # 预热配置并同步运行时全局状态
    prune_event_log()
    preload_events()
    # 价格目录后台自动同步（启动时 + 每 7 天过期刷新；失败静默，不阻塞启动）
    _maybe_auto_sync_prices()
    # 把本次 token 写文件，供外部脚本/测试读取（仅本机 127.0.0.1 可访问，文件权限继承用户）
    try:
        (ROOT / "proxy_token").write_text(API_TOKEN, encoding="utf-8")
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
