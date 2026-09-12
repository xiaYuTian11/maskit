# 数据面具 Maskit — 本地 LLM 敏感信息脱敏代理
# Copyright (C) 2026 TMW
#
# 本程序是自由软件：你可以依据自由软件基金会发布的 GNU Affero 通用公共许可证
# （版本 3）条款重新分发和/或修改它。
# 本程序基于「希望有用」的目的分发，但不附带任何担保；亦无对适销性或特定用途
# 适用性的默示担保。详见 GNU Affero 通用公共许可证。
# 你应已随本程序收到一份 GNU AGPL 副本；若无，见 <https://www.gnu.org/licenses/>。
import json
import locale
import os
import queue
import re
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from contextlib import closing
from credential_labels import CREDENTIAL_LABELS


ROOT = Path(__file__).parent.resolve()
# 数据目录：打包后从 LLM_SHIELD_DATA_DIR 读，开发时回退脚本目录
_DATA_ROOT = Path(os.environ.get("LLM_SHIELD_DATA_DIR") or str(ROOT)).resolve()
DB_PATH = _DATA_ROOT / "shield-events.sqlite3"
LEGACY_JSONL_PATH = _DATA_ROOT / "shield-events.jsonl"
RETENTION_DAYS = 7
EVENT_QUEUE_MAX = 5000

_event_queue = queue.Queue(maxsize=EVENT_QUEUE_MAX)
_writer_lock = threading.Lock()
_writer_started = False
# 已完成建表的 DB 路径（False = 尚未初始化）。存路径而不是布尔量：中途换
# DB_PATH（测试、或把数据目录指到别处）必须重新建表，否则读路径会 no such table。
_db_ready = False
_source_lock = threading.Lock()
_tcp_cache = {"ts": 0.0, "ports": {}}
_process_cache = {}


def _connect(schema=False):
    """打开 SQLite 连接。schema=True 时才执行建表/建索引 DDL（仅 init_db 调用）。

    曾默认每次都执行 3 个 CREATE TABLE + 6 个 CREATE INDEX，而 append_event
    每条事件开新连接 → 每条日志 9 条多余 SQL，高流量下 writer 队列积压。
    """
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        # PRAGMA journal_mode 会真的去读文件头，是「文件不是数据库」这类损坏的
        # 报错点。这里补一层 close：_connect 抛异常时调用方拿不到 conn，
        # 不关就会泄漏到 GC 才释放。
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
    except Exception:
        conn.close()
        raise
    if not schema:
        return conn
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            type TEXT NOT NULL,
            sid TEXT,
            host TEXT,
            method TEXT,
            path TEXT,
            count INTEGER DEFAULT 0,
            restored INTEGER DEFAULT 0,
            status TEXT,
            http_status INTEGER,
            payload TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    # 复合索引 (type, ts)：fetch_restore_items 按「当日 + type='RESTORE'」过滤，
    # 单列 ts 索引在 type 过滤后仍需回表扫当日全部事件；复合索引让过滤直接
    # 命中索引段，避免逐行读 payload（审计性能项 P1-1）。
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(type, ts)")
    # 复合索引 (type, id)：fetch_events 的过滤/排序形态是
    #   WHERE id > ? AND type = ? ORDER BY id [ASC|DESC] LIMIT n
    # 即「按 id 游标增量取某一类型」。`id` 是 rowid，落在 (type, id) 的第二列上，
    # 计划器可直接把它当范围约束用（type=? AND id>?），无需 INDEXED BY 或 ANALYZE。
    # 只有 (type, ts) 时该查询会退化成「扫完整个类型段 → TEMP B-TREE 排序」：
    # 100 万行实测（首屏/增量 × 升降序四场景）
    #   292.4 / 40.5 / 29.1 / 24.3 ms  →  6.3 / 5.4 / 5.7 / 6.3 ms（5~46 倍）
    # 注意保留 (type, ts)：按时间范围查（stats / fetch_restore_items）时它才是最优，
    # 两个索引各管一种形态，不要互相替换。
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type_id ON events(type, id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_sid ON events(sid)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_count ON events(count)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    # 2.0 审计事件表（与 events 分离，避免污染脱敏日志）
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            sid TEXT,
            host TEXT,
            method TEXT,
            path TEXT,
            signal_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            evidence TEXT,
            request_hash TEXT,
            response_hash TEXT,
            probe_id TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_events(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_signal ON audit_events(signal_type)")
    # 日统计摘要表（审计性能项）：写线程增量维护，today_stats 不再全量扫当日 payload。
    # daily_words.word 只存非凭据原文（凭据 items 无 original，落 preview 打码），
    # 与旧口径一致：有 original 用明文，无则用 preview 兜底。
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_stats (
            day TEXT NOT NULL,
            type TEXT NOT NULL,
            events INTEGER DEFAULT 0,
            count_sum INTEGER DEFAULT 0,
            restored INTEGER DEFAULT 0,
            PRIMARY KEY (day, type)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_status (
            day TEXT NOT NULL,
            status TEXT NOT NULL,
            cnt INTEGER DEFAULT 0,
            PRIMARY KEY (day, status)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_words (
            day TEXT NOT NULL,
            label TEXT NOT NULL,
            word TEXT NOT NULL,
            cnt INTEGER DEFAULT 0,
            PRIMARY KEY (day, label, word)
        )
        """
    )
    # token 用量日摘要：只收 RESTORE 事件的 usage（每请求一次，不双计）
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_tokens (
            day TEXT PRIMARY KEY,
            prompt INTEGER DEFAULT 0,
            completion INTEGER DEFAULT 0
        )
        """
    )
    # 模型使用日摘要：只收 RESTORE 事件（成功的响应才算使用量），
    # 统计每个模型每天发起了多少请求、消耗多少 token（供「模型排行」+ 费用估算）。
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_models (
            day TEXT NOT NULL,
            model TEXT NOT NULL,
            requests INTEGER DEFAULT 0,
            prompt INTEGER DEFAULT 0,
            completion INTEGER DEFAULT 0,
            errors INTEGER DEFAULT 0,
            PRIMARY KEY (day, model)
        )
        """
    )
    # daily_models 补充 errors 失败统计列（已有库平滑迁移）
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(daily_models)").fetchall()]
        if "errors" not in cols:
            conn.execute("ALTER TABLE daily_models ADD COLUMN errors INTEGER DEFAULT 0")
    except Exception:
        pass
    # 内部元数据（迁移标记等）：daily_stats 摘要表上线时，升级前写入的事件
    # 没有摘要——用 meta 标记做一次性回填，保证升级当天统计不丢（审计 DATA-002）。
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )
    return conn


def _migrate_daily_stats(conn, now):
    """把摘要表上线前写入的事件回填进 daily_stats（只执行一次，防重复计数）。

    语义（审计 DATA-002）：
    - daily_stats_created：新代码首次写库时间（init_db 时写入，之后不变）——
      此前写入的事件都没有摘要；
    - daily_stats_migrated：回填完成的标记（= created）。已标记则不再回填，
      否则会对"已同步过摘要的新事件"重复累加（ON CONFLICT cnt+1 会翻倍，
      且 day 边界变化后第二次触发就是重复）。
    """
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='daily_stats_created'").fetchone()
        created = float(row[0]) if row and row[0] else now
        row = conn.execute("SELECT value FROM meta WHERE key='daily_stats_migrated'").fetchone()
        migrated = float(row[0]) if row and row[0] else 0.0
        if migrated > 0:
            return
        recs = conn.execute(
            "SELECT ts, payload FROM events WHERE ts >= ? AND ts < ?",
            (migrated, created),
        ).fetchall()
        for ts, pl in recs:
            try:
                rec = json.loads(pl)
                rec["ts"] = ts
            except Exception:
                continue
            _update_stats(conn, rec)
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('daily_stats_migrated', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(created),),
        )
        conn.commit()
    except Exception:
        pass


# 摘要写入失败的累计计数（_update_stats 内 try 用）。摘要表偏差是「看不见的坏」：
# 失败必须留痕，否则面板的今日统计会静默少计，与 events 对不上也无人知晓。
_stats_write_errors = 0
_stats_write_error_ts = 0.0

# 敏感词统计是否记录明文（config.record_plaintext_words，默认开）。
# 事件写入分散在两个进程（面板 Flask / mitmdump 插件），各自在配置热重载时
# 调 set_record_plaintext_words() 同步这个模块级开关——不在此处读文件，
# 否则每条事件写入都要 stat 一次 config.json。
RECORD_PLAINTEXT_WORDS = True


def set_record_plaintext_words(enabled) -> None:
    """同步「敏感词统计记录明文」开关（配置热重载时调用，两个写入进程各调各的）。"""
    global RECORD_PLAINTEXT_WORDS
    RECORD_PLAINTEXT_WORDS = bool(enabled)


def _update_stats(conn, rec):
    """增量维护日统计摘要（与 events 同事务提交，失败静默——事件照常落库）。

    口径与旧实现完全一致（审计 DATA-001）：
    - daily_stats：所有事件类型计数（MASK/RESTORE/PASS/BLOCK/...）；
    - daily_status：只收 RESTORE 事件的状态分布；
    - daily_words：只收 MASK 事件 items（旧 today_stats 只扫 MASK payload，
      若 RESTORE 也收会把同一脱敏项记两次——实测 MASK+RESTORE 计为 PHONE=2）。
    """
    try:
        ts = float(rec.get("ts") or time.time())
        day = time.strftime("%Y-%m-%d", time.localtime(ts))
        typ = str(rec.get("type") or "")
        if not typ:
            return
        conn.execute(
            "INSERT INTO daily_stats(day, type, events, count_sum, restored) VALUES(?,?,1,?,?) "
            "ON CONFLICT(day,type) DO UPDATE SET "
            "events=events+1, count_sum=count_sum+excluded.count_sum, restored=restored+excluded.restored",
            (day, typ, _int_or_none(rec.get("count")) or 0, _int_or_none(rec.get("restored")) or 0),
        )
        # 还原状态分布只收 RESTORE 事件（与旧口径一致）
        if typ == "RESTORE" and rec.get("status"):
            conn.execute(
                "INSERT INTO daily_status(day, status, cnt) VALUES(?,?,1) "
                "ON CONFLICT(day,status) DO UPDATE SET cnt=cnt+1",
                (day, str(rec.get("status"))),
            )
        # 敏感词明细只收 MASK 事件（避免 RESTORE 重复计数）
        # Token 用量与模型统计：收 RESTORE 与带 usage 的 PASS 事件（透传直连）
        if typ in ("RESTORE", "PASS"):
            usage = rec.get("usage")
            p = 0
            c = 0
            if isinstance(usage, dict):
                p = _int_or_none(usage.get("prompt_tokens")) or 0
                c = _int_or_none(usage.get("completion_tokens")) or 0
                if p or c:
                    conn.execute(
                        "INSERT INTO daily_tokens(day, prompt, completion) VALUES(?,?,?) "
                        "ON CONFLICT(day) DO UPDATE SET "
                        "prompt=prompt+excluded.prompt, completion=completion+excluded.completion",
                        (day, p, c),
                    )
            # 模型使用摘要：请求数 + token 数同源（RESTORE 或带 usage 的 PASS 事件），
            # 失败请求（无 RESTORE/PASS 错误）不计——口径=「成功完成的调用」
            model = str(rec.get("model") or "").strip()
            if model and (typ == "RESTORE" or p > 0 or c > 0):
                conn.execute(
                    "INSERT INTO daily_models(day, model, requests, prompt, completion, errors) VALUES(?,?,1,?,?,0) "
                    "ON CONFLICT(day, model) DO UPDATE SET "
                    "requests=requests+1, prompt=prompt+excluded.prompt, completion=completion+excluded.completion",
                    (day, model, p, c),
                )
            return
        if typ == "ERR":
            # 记录模型的失败调用数（供「模型排行」展示成功率）
            model = str(rec.get("model") or "").strip()
            if model:
                conn.execute(
                    "INSERT INTO daily_models(day, model, requests, prompt, completion, errors) VALUES(?,?,0,0,0,1) "
                    "ON CONFLICT(day, model) DO UPDATE SET errors=errors+1",
                    (day, model),
                )
            return
        if typ != "MASK":
            return
        for it in rec.get("items") or []:
            if not isinstance(it, dict):
                continue
            lbl = str(it.get("label") or "其他")
            # 敏感词排行榜要看的是「哪个词被脱敏得最多」，打码 preview（1**@***.com）
            # 排出来的榜没有信息量。是否记录明文由用户在高级设置里决定：
            #   开（默认）：存原文，排行榜可读；数据只落本机 SQLite，不出网。
            #   关：只存打码 preview，库里永不出现明文。
            # 与 /api/logs 的 slim 红线不冲突——那条约束的是事件列表推送面，
            # 明文仍只经 /api/logs/detail 回源；这里是用户显式选择的统计维度。
            # 凭据类 items 本身就没有 original（脱敏时即丢弃），永远走 preview。
            if RECORD_PLAINTEXT_WORDS:
                word = str(it.get("original") or it.get("preview") or "")
            else:
                word = str(it.get("preview") or "")
            if not word:
                word = "?"
            conn.execute(
                "INSERT INTO daily_words(day, label, word, cnt) VALUES(?,?,?,1) "
                "ON CONFLICT(day,label,word) DO UPDATE SET cnt=cnt+1",
                (day, lbl, word),
            )
    except Exception as e:
        # 摘要失败不能拖垮同事务的事件落库，所以仍不抛出。但必须留痕：
        # 静默 pass 会让「今日统计」长期偏差（审计 DATA-001 口径依赖这些表）。
        global _stats_write_errors, _stats_write_error_ts
        _stats_write_errors += 1
        now = time.time()
        if now - _stats_write_error_ts > 30:
            _stats_write_error_ts = now
            try:
                import sys
                sys.stderr.write(
                    f"[shield-event-writer] daily stats update failed "
                    f"(累计 {_stats_write_errors} 次): {e}\n"
                )
                sys.stderr.flush()
            except Exception:
                pass


def init_db():
    with closing(_connect(schema=True)) as conn:
        # 摘要表上线时间戳（首次运行写入，之后不变）：升级前写入的事件靠它回填（审计 DATA-002）
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('daily_stats_created', ?) "
            "ON CONFLICT(key) DO NOTHING",
            (str(time.time()),),
        )
        # 一次性迁移（审计第三批 P1）：历史 daily_words 存了 original 明文，
        # 违反 slim 红线（明文只走 /api/logs/detail 回源）。无法从打码 preview
        # 反推，直接删除历史词表行（只丢统计不丢事件，事件原文仍在 events 表）。
        # 用 meta 标记幂等。
        row = conn.execute("SELECT value FROM meta WHERE key='daily_words_pii_purged'").fetchone()
        if not row:
            conn.execute("DELETE FROM daily_words")
            conn.execute("INSERT INTO meta(key, value) VALUES('daily_words_pii_purged', '1')")
        conn.commit()


def _quarantine_corrupt_db(reason):
    """把损坏的事件库挪到一边，返回新路径（失败返回 ""）。调用方随后重建空库。

    只处理**真正的损坏**（`sqlite3.DatabaseError` 且非 `OperationalError`——后者是
    锁竞争 / 路径不可写，重试或改权限即可，挪文件只会白丢数据）。

    旧文件一律保留为 `<name>.corrupt-<时间戳>`，绝不删除：事件库是本地唯一副本，
    宁可占盘也不能替用户做「删掉」的决定。用户还能拿它去 sqlite3 里抢救数据。
    """
    try:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = DB_PATH.with_name(f"{DB_PATH.name}.corrupt-{stamp}")
        for suffix in ("", "-wal", "-shm"):
            src = DB_PATH.with_name(DB_PATH.name + suffix)
            if not src.exists():
                continue
            dst = base if not suffix else base.with_name(base.name + suffix)
            src.replace(dst)
        return str(base)
    except Exception:
        return ""


def _ensure_db():
    """确保 DB_PATH 指向的库已建好 schema（**每个路径只做一次** DDL）。

    以前读路径直接调 init_db()，每次查询都要跑十几条 CREATE TABLE/INDEX IF NOT
    EXISTS；而且旧实现是布尔量 _db_ready，中途换 DB_PATH（测试、以及把数据目录
    指到别处）会跳过建表。这里改成「记住已初始化的路径」，换路径自动重建。
    """
    global _db_ready
    if _db_ready == str(DB_PATH):
        return
    try:
        init_db()
    except sqlite3.OperationalError:
        raise  # 锁竞争 / 路径不可写：交给调用方的降级逻辑，绝不能动用户的文件
    except sqlite3.DatabaseError as exc:
        # 文件不是数据库 / 镜像损坏。不处理的话面板每个统计接口都 500、写线程
        # 永久降级，用户没有任何自救路径。挪走坏文件重建空库，功能至少恢复。
        moved = _quarantine_corrupt_db(str(exc))
        sys.stderr.write(
            f"[shield-event-store] 事件库损坏（{exc}），已移到 {moved or '(移动失败，未删除原文件)'} "
            f"并重建空库\n"
        )
        init_db()
    _db_ready = str(DB_PATH)


def _console_encodings():
    """Windows 控制台输出的候选解码顺序。

    顺序不能反：GBK 字节按 utf-8 解会抛异常并自然回落，而 utf-8 字节按 GBK 解
    会「成功」但产出乱码（静默错误）。所以 utf-8 先试，失败才用系统代码页。

    不能用 locale.getpreferredencoding(False) 定位系统代码页：PYTHONUTF8=1 会把
    它的返回值强制成 utf-8，正是要绕开的那层。直接问 Win32 的 OEM 代码页
    （netstat/tasklist 等控制台程序的实际输出编码，中文 Windows 为 936）。
    """
    encs = ["utf-8"]
    try:
        import ctypes
        cp = int(ctypes.windll.kernel32.GetOEMCP())
        if cp:
            encs.append(f"cp{cp}")
    except Exception:
        pass
    encs.append(locale.getpreferredencoding(False) or "utf-8")
    return encs


def console_decode(raw):
    """解码控制台命令的原始字节，任何情况下不抛异常。"""
    for enc in _console_encodings():
        try:
            return (raw or b"").decode(enc)
        except Exception:
            continue
    return (raw or b"").decode("utf-8", errors="replace")


def _run_console(argv, timeout):
    """跑 Windows 控制台命令并返回 stdout 文本，解码失败不抛。

    不能用 subprocess 的 text=True：netstat/tasklist 按系统代码页输出（中文
    Windows 为 GBK），而 PYTHONUTF8=1 会把 text 模式默认编码定成 utf-8，解码
    异常抛在 subprocess 内部的 _readerthread 里，调用方的 except 捕不到 ——
    表现为线程堆栈刷屏 + 来源归因（进程名/PID）静默全空。故取原始字节自行解码。
    """
    try:
        proc = subprocess.run(
            argv, capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return ""
    return console_decode(proc.stdout)


def _int_or_none(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except Exception:
        return None


def _split_endpoint(value):
    text = str(value or "").strip()
    if not text:
        return None, None
    if text.startswith("[") and "]:" in text:
        host, port = text.rsplit(":", 1)
        return host.strip("[]"), _int_or_none(port)
    if ":" not in text:
        return text, None
    host, port = text.rsplit(":", 1)
    return host, _int_or_none(port)


def _refresh_tcp_cache(now=None):
    now = time.time() if now is None else float(now)
    with _source_lock:
        if now - _tcp_cache["ts"] < 2.0:
            return dict(_tcp_cache["ports"])
    ports = {}
    try:
        for line in _run_console(["netstat", "-ano", "-p", "tcp"], 1.2).splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0].upper() != "TCP":
                continue
            _, port = _split_endpoint(parts[1])
            pid = _int_or_none(parts[-1])
            if port and pid:
                ports.setdefault(port, pid)
    except Exception:
        ports = {}
    with _source_lock:
        _tcp_cache["ts"] = now
        _tcp_cache["ports"] = ports
    return dict(ports)


def _process_info(pid):
    pid = _int_or_none(pid)
    if not pid:
        return "", ""
    now = time.time()
    with _source_lock:
        cached = _process_cache.get(pid)
        if cached and now - cached["ts"] < 15:
            return cached["name"], cached["cmd"]
    name = ""
    cmd = ""
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        ps = (
            "$p=Get-CimInstance Win32_Process -Filter \"ProcessId=%d\";"
            "if($p){[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "$p|Select-Object Name,CommandLine|ConvertTo-Json -Compress}"
        ) % pid
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1.5,
            creationflags=flags,
        )
        if proc.stdout.strip():
            data = json.loads(proc.stdout)
            name = str(data.get("Name") or "")
            cmd = str(data.get("CommandLine") or "")
    except Exception:
        pass
    if not name:
        try:
            out = _run_console(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], 1.0)
            line = out.strip().splitlines()[0]
            name = line.split(",", 1)[0].strip('"')
        except Exception:
            pass
    with _source_lock:
        _process_cache[pid] = {"ts": now, "name": name, "cmd": cmd}
        if len(_process_cache) > 200:
            expired = [p for p, v in _process_cache.items() if now - v["ts"] > 60]
            for p in expired:
                del _process_cache[p]
    return name, cmd


def _classify_process(name, cmd):
    hay = f"{name} {cmd}".lower()
    if "@earendil-works" in hay or "pi-coding-agent" in hay:
        return "Pi"
    if "@openai" in hay and "codex" in hay:
        return "Codex"
    if "codex.exe" in hay:
        return "Codex"
    if "@anthropic-ai" in hay or "claude-code" in hay or "claude.exe" in hay:
        return "Claude"
    if "trae.exe" in hay or "\\trae\\" in hay or "/trae/" in hay:
        return "Trae"
    if "cursor.exe" in hay or "\\cursor\\" in hay or "/cursor/" in hay:
        return "Cursor"
    if "vscode" in hay or "code.exe" in hay:
        return "VS Code"
    if name:
        return re.sub(r"\.exe$", "", name, flags=re.I)
    return ""


def _enrich_source(record):
    rec = dict(record)
    if rec.get("client_app"):
        return rec
    port = _int_or_none(rec.get("client_port"))
    if not port:
        return rec
    pid = _refresh_tcp_cache().get(port)
    if not pid:
        return rec
    name, cmd = _process_info(pid)
    app = _classify_process(name, cmd)
    rec["client_pid"] = pid
    if name:
        rec["client_process"] = name
    if app:
        rec["client_app"] = app
    return rec


def append_event(record):
    _ensure_db()
    rec = _enrich_source(record)
    rec.setdefault("ts", time.time())
    payload = json.dumps(rec, ensure_ascii=False)
    with closing(_connect()) as conn:
        cur = conn.execute(
            """
            INSERT INTO events
            (ts, type, sid, host, method, path, count, restored, status, http_status, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                float(rec.get("ts") or time.time()),
                str(rec.get("type") or ""),
                rec.get("sid"),
                rec.get("host"),
                rec.get("method"),
                rec.get("path"),
                _int_or_none(rec.get("count")) or 0,
                _int_or_none(rec.get("restored")) or 0,
                rec.get("status"),
                _int_or_none(rec.get("http_status")),
                payload,
            ),
        )
        rowid = cur.lastrowid
        _update_stats(conn, rec)
        conn.commit()
        return rowid


def append_audit_event(record):
    """2.0 审计事件写入（同步，内部用）。永不抛异常。"""
    try:
        _ensure_db()
        rec = dict(record)
        rec.setdefault("ts", time.time())
        with closing(_connect()) as conn:
            conn.execute(
                """
                INSERT INTO audit_events
                (ts, sid, host, method, path, signal_type, severity, evidence, request_hash, response_hash, probe_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    float(rec.get("ts") or time.time()),
                    rec.get("sid"),
                    rec.get("host"),
                    rec.get("method"),
                    rec.get("path"),
                    str(rec.get("signal_type") or ""),
                    str(rec.get("severity") or "LOW"),
                    str(rec.get("evidence") or "")[:300],
                    rec.get("request_hash"),
                    rec.get("response_hash"),
                    rec.get("probe_id"),
                ),
            )
            conn.commit()
        return True
    except Exception:
        return False


# 审计事件异步写队列（复用 events 的 writer 模式，避免热路径同步 sqlite）
_audit_queue = queue.Queue(maxsize=EVENT_QUEUE_MAX)
_audit_writer_started = False
_audit_writer_lock = threading.Lock()
_audit_writer_error_ts = 0.0
_audit_writer_thread = None
# 写线程故障监控：连续失败计数/死信计数/丢弃计数，_ensure_* 每入队时检查线程存活，
# 异常退出后自动重启（曾因 UnboundLocalError 一条异常打死线程，日志从此静默丢失）
_audit_writer_stats = {"restarts": 0, "dead_letters": 0, "drops": 0, "last_err": ""}


def _audit_writer_loop():
    while True:
        record = _audit_queue.get()
        try:
            # 清空 cutoff 前的旧事件：丢弃（防"清空又冒出来"）
            if _audit_clear_cutoff and float(record.get("ts") or 0) < _audit_clear_cutoff:
                continue
            # append_audit_event 内部吞异常返回 False：必须检查返回值，
            # 否则 DB 不可写时审计事件静默丢失、dead_letters 恒为 0（审计 AUDIT-001）
            ok = append_audit_event(record)
            if not ok:
                raise RuntimeError("append_audit_event failed")
        except Exception as e:
            # 注意：这里给 _audit_writer_error_ts 赋值前必须声明 global，
            # 否则 UnboundLocalError 会把写线程打死（曾真实发生，事件静默丢失）
            global _audit_writer_error_ts
            now = time.time()
            # 每次失败都计数（与 drops 同口径），告警再节流
            _audit_writer_stats["dead_letters"] += 1
            _audit_writer_stats["last_err"] = str(e)[:200]
            if now - _audit_writer_error_ts > 30:
                _audit_writer_error_ts = now
                try:
                    import sys
                    sys.stderr.write(f"[shield-audit-writer] append failed: {e}\n")
                    sys.stderr.flush()
                except Exception:
                    pass
        finally:
            _audit_queue.task_done()


def _ensure_audit_writer():
    global _audit_writer_started, _audit_writer_thread
    if _audit_writer_thread is not None and _audit_writer_thread.is_alive():
        return
    with _audit_writer_lock:
        if _audit_writer_thread is not None and _audit_writer_thread.is_alive():
            return
        was_dead = _audit_writer_thread is not None
        try:
            _ensure_db()
        except Exception:
            pass  # DB 暂不可用：线程照起，写失败记死信
        _audit_writer_started = True
        t = threading.Thread(target=_audit_writer_loop, name="shield-audit-writer", daemon=True)
        t.start()
        _audit_writer_thread = t
        if was_dead:
            _audit_writer_stats["restarts"] += 1


def enqueue_audit_event(record):
    """热路径用：非阻塞入队，后台线程写库。队列满则节流记 stderr。"""
    global _audit_writer_error_ts
    _ensure_audit_writer()
    try:
        _audit_queue.put_nowait(dict(record))
        return True
    except queue.Full:
        # 每次丢弃都计数（审计：曾只在 30s 节流分支 +1，数字远小于真实丢弃）
        _audit_writer_stats["drops"] += 1
        now = time.time()
        if now - _audit_writer_error_ts > 30:
            _audit_writer_error_ts = now
            try:
                import sys
                sys.stderr.write(f"[shield-audit-queue] full, event dropped: {record.get('signal_type','?')}\n")
                sys.stderr.flush()
            except Exception:
                pass
        return False


def flush_audit_queue():
    """等待队列写完（测试用）。"""
    _audit_queue.join()


# 已撤销的审计记录在读侧隐藏：保留数据库原文，不做破坏性清理，但不能继续
# 淹没安全审计 UI。判据调整见 audit_signals.py（2026-08-18）。
_DEPRECATED_AUDIT_EVIDENCE_PREFIXES = (
    ("error_leak", "upstream_host:%"),
    ("error_leak", "fs_path:%"),
    ("error_leak", "stack_trace:%"),
    ("identity_swap", "identity_claim:%"),
    ("sse_anomaly", "%"),
    ("canary_leak", "%"),
)


def _audit_visibility_filter():
    """返回审计历史读侧过滤 SQL 子句与参数（不删除数据库记录）。"""
    clauses, params = [], []
    for signal_type, evidence_pattern in _DEPRECATED_AUDIT_EVIDENCE_PREFIXES:
        clauses.append("NOT (signal_type = ? AND COALESCE(evidence, '') LIKE ?)")
        params.extend([signal_type, evidence_pattern])
    return clauses, params


def fetch_audit_events(since=0, limit=500, severity_floor=None, signal_filter=None):
    """读取审计事件。since=id（返回 id>since 的）。severity_floor=LOW/MEDIUM/HIGH/CRITICAL。"""
    _ensure_db()
    since = int(since or 0)
    limit = max(1, min(int(limit or 500), 1000))
    visibility_clauses, visibility_params = _audit_visibility_filter()
    where = ["id > ?", *visibility_clauses]
    params = [since, *visibility_params]
    # 仅过滤 UI/API 读侧，不删除历史行：用户清空审计日志前数据库内容保持不变。
    if severity_floor:
        # CASE 计算严重度秩，避免加列
        ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        floor_rank = ranks.get(severity_floor, 0)
        if floor_rank:
            case_expr = (
                "CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
                "WHEN 'MEDIUM' THEN 2 ELSE 1 END"
            )
            where.append(f"({case_expr}) >= {floor_rank}")
    if signal_filter:
        where.append("signal_type = ?")
        params.append(signal_filter)
    sql = (
        "SELECT id, ts, sid, host, method, path, signal_type, severity, evidence, "
        "request_hash, response_hash, probe_id FROM audit_events WHERE "
        + " AND ".join(where)
        + " ORDER BY id DESC LIMIT ?"
    )
    params.append(limit)
    with closing(_connect()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
    out = []
    for r in reversed(rows):
        out.append({
            "seq": r["id"],
            "ts": r["ts"],
            "sid": r["sid"],
            "host": r["host"],
            "method": r["method"],
            "path": r["path"],
            "signal_type": r["signal_type"],
            "severity": r["severity"],
            "evidence": r["evidence"],
            "probe_id": r["probe_id"],
            "request_hash": r["request_hash"],
            "response_hash": r["response_hash"],
        })
    return out


def prune_audit_events(now=None, retention_days=RETENTION_DAYS):
    _ensure_db()
    now = time.time() if now is None else float(now)
    # 与 prune_events 同一套语义：<=0 = 永久保留，不是「留一天」
    if int(retention_days) <= 0:
        return {"ok": True, "removed": 0, "retained": "forever"}
    cutoff = now - int(retention_days) * 86400
    with closing(_connect()) as conn:
        cur = conn.execute("DELETE FROM audit_events WHERE ts < ?", (cutoff,))
        removed = cur.rowcount
        conn.commit()
        return {"ok": True, "removed": removed}


# 审计事件清空 cutoff：clear_audit_events() 置当前时间戳，cutoff 前入队的事件丢弃
# （审计 SHIELD-CLEAR-001：曾无 cutoff，清空后队列旧事件回写）
_audit_clear_cutoff = 0.0


def clear_audit_events():
    global _audit_clear_cutoff
    _ensure_db()
    _audit_clear_cutoff = time.time()
    # 排空未写审计队列
    drained = 0
    while True:
        try:
            _audit_queue.get_nowait()
            _audit_queue.task_done()
            drained += 1
        except queue.Empty:
            break
    with closing(_connect()) as conn:
        conn.execute("DELETE FROM audit_events")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_events'")
        conn.commit()
    # 兜底：写线程已取走但未提交的旧事件按 cutoff 补删
    with closing(_connect()) as conn:
        conn.execute("DELETE FROM audit_events WHERE ts < ?", (_audit_clear_cutoff,))
        conn.commit()
    return {"ok": True, "dropped_inflight": drained}


_writer_error_ts = 0.0
_writer_thread = None
# 写线程故障监控（审计要求）：重启次数 / 死信（写入失败被丢弃）计数 / 队列溢出丢弃计数
_writer_stats = {"restarts": 0, "dead_letters": 0, "drops": 0, "last_err": ""}
# 批量写窗口（秒）：一次事务攒多条事件，显著降低逐条连接+提交的开销
_BATCH_WINDOW = 0.05
# 清空日志 cutoff：clear_events() 置当前时间戳，cutoff 前入队的事件一律丢弃，
# 防止"清空后旧队列事件又回写"（清空竞态，审计 P1-5）
_clear_cutoff = 0.0


def _append_many(records):
    """批量写事件：一次连接 + 一个事务。

    降级策略（审计性能项）：整批失败（DB 打不开/锁）抛异常由调用方记死信；
    单条坏事件（字段类型异常等）在批量模式无法单独定位，先整体回滚，
    由调用方逐条重试——坏事件只丢自己，不拖死同批其余事件。
    返回写成功的条数。
    """
    if not records:
        return 0
    _ensure_db()
    with closing(_connect()) as conn:
        for rec in records:
            rec = _enrich_source(rec)
            rec.setdefault("ts", time.time())
            payload = json.dumps(rec, ensure_ascii=False)
            conn.execute(
                """
                INSERT INTO events
                (ts, type, sid, host, method, path, count, restored, status, http_status, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    float(rec.get("ts") or time.time()),
                    str(rec.get("type") or ""),
                    rec.get("sid"),
                    rec.get("host"),
                    rec.get("method"),
                    rec.get("path"),
                    _int_or_none(rec.get("count")) or 0,
                    _int_or_none(rec.get("restored")) or 0,
                    rec.get("status"),
                    _int_or_none(rec.get("http_status")),
                    payload,
                ),
            )
            _update_stats(conn, rec)
        conn.commit()
    return len(records)


def _append_many_with_degrade(records):
    """批量写；失败后逐条降级重试（单条失败跳过继续，返回 (成功数, 失败数)）。

    防"一条坏事件导致整批 50 条全部回滚丢弃"（审计性能项）。
    """
    try:
        return _append_many(records), 0
    except Exception:
        ok_count = 0
        fail_count = 0
        for rec in records:
            try:
                _append_many([rec])
                ok_count += 1
            except Exception:
                fail_count += 1
        return ok_count, fail_count


def _writer_loop():
    while True:
        record = _event_queue.get()
        batch = [record]
        try:
            deadline = time.time() + _BATCH_WINDOW
            while time.time() < deadline:
                try:
                    batch.append(_event_queue.get_nowait())
                except queue.Empty:
                    break
        except Exception:
            pass
        # 本批真实丢失的事件条数，异常分支据此按条累加死信。
        # 必须在 try 之外初始化：否则 cutoff 过滤那行抛错时 lost 未绑定，
        # except 里引用它会再抛 UnboundLocalError 把写线程打死。
        lost = 0
        try:
            # 清空 cutoff 前的旧事件：丢弃，防"清空又冒出来"
            fresh = [r for r in batch if not _clear_cutoff or float(r.get("ts") or 0) >= _clear_cutoff]
            if fresh:
                _ok_n, _fail_n = _append_many_with_degrade(fresh)
                if _fail_n:
                    # 降级后仍有失败（DB 打不开等系统性故障）：记死信（审计 AUDIT-001 同口径）
                    lost = _fail_n
                    raise RuntimeError(f"{_fail_n}/{len(fresh)} events failed after degrade")
        except Exception as e:
            # 注意：给 _writer_error_ts 赋值前必须声明 global，
            # 否则 UnboundLocalError 会把写线程打死（曾真实发生，日志静默丢失）
            global _writer_error_ts
            now = time.time()
            # 按**事件条数**累加，与 drops 同口径：一批 50 条全失败只 +1 会让
            # dead_letters 远小于真实丢失量，DB 持续故障时数字看着"还好"。
            # lost 为 0 说明异常来自 _append_many_with_degrade 之外（如 cutoff 过滤
            # 时 float() 抛错），此时整批都没落库，按 batch 全长计。
            _writer_stats["dead_letters"] += lost or len(batch)
            _writer_stats["last_err"] = str(e)[:200]
            if now - _writer_error_ts > 30:
                _writer_error_ts = now
                try:
                    import sys
                    sys.stderr.write(f"[shield-event-writer] batch write failed, {len(batch)} events dropped: {e}\n")
                    sys.stderr.flush()
                except Exception:
                    pass
        finally:
            for _ in batch:
                _event_queue.task_done()


def _ensure_writer():
    """确保事件写线程存活：线程异常退出（曾因 UnboundLocalError 打死）后下次入队自动重启。

    DB 初始化失败（磁盘满/权限/路径失效）不阻止线程启动：写失败记死信，
    DB 恢复后后续事件自动续写，而不是整个日志链路静默失明。
    """
    global _writer_started, _writer_thread
    if _writer_thread is not None and _writer_thread.is_alive():
        return
    with _writer_lock:
        if _writer_thread is not None and _writer_thread.is_alive():
            return
        was_dead = _writer_thread is not None
        try:
            _ensure_db()
        except Exception:
            pass  # DB 暂不可用：线程照起，写失败记死信
        _writer_started = True
        t = threading.Thread(target=_writer_loop, name="shield-event-writer", daemon=True)
        t.start()
        _writer_thread = t
        if was_dead:
            _writer_stats["restarts"] += 1


def _reset_writer():
    """Reset writer and DB state. Intended for tests."""
    global _writer_started, _db_ready, _writer_thread, _clear_cutoff
    with _writer_lock:
        _writer_started = False
        _db_ready = False
        _writer_thread = None
        _clear_cutoff = 0.0


_event_queue_overflow_ts = 0.0


def enqueue_event(record):
    """Queue a non-critical event write without blocking the request path."""
    _ensure_writer()
    try:
        _event_queue.put_nowait(dict(record))
        return True
    except queue.Full:
        # 队列满静默丢会让人误以为"日志没记录"：每次丢弃都计数（审计：
        # 曾只在 30s 节流分支 +1，数字远小于真实丢弃），告警再节流到 stderr
        global _event_queue_overflow_ts
        _writer_stats["drops"] += 1
        now = time.time()
        if now - _event_queue_overflow_ts > 30:
            _event_queue_overflow_ts = now
            try:
                import sys
                sys.stderr.write(
                    f"[shield-event-writer] event queue full ({_event_queue.maxsize}), "
                    f"dropped {_writer_stats['drops']} events so far; 检查 DB 写入是否阻塞\n"
                )
                sys.stderr.flush()
            except Exception:
                pass
        return False


def writer_stats():
    """写线程健康指标：存活 / 队列长度 / 死信 / 丢弃 / 重启次数（审计要求可观测）。"""
    return {
        "event_writer_alive": bool(_writer_thread and _writer_thread.is_alive()),
        "audit_writer_alive": bool(_audit_writer_thread and _audit_writer_thread.is_alive()),
        "event_queue_size": _event_queue.qsize(),
        "audit_queue_size": _audit_queue.qsize(),
        "event_writer": dict(_writer_stats),
        "audit_writer": dict(_audit_writer_stats),
        "clear_cutoff": _clear_cutoff,
    }


def flush_event_queue():
    """Wait for queued event writes. Intended for tests and controlled shutdown checks."""
    _event_queue.join()


def _row_to_event(row):
    rec = json.loads(row["payload"])
    rec["seq"] = row["id"]
    return rec


def fetch_event_by_id(event_id):
    """按 SQLite 主键精确取单条事件（含 dialog/preview 等正文字段）。

    列表接口用 slim=1 下发轻量数据，详情弹窗按 seq 回源走这里。
    不能用 fetch_events(since=id-1, limit=1) 代替：那是 id > since 且
    ORDER BY id DESC，会返回集合里最大的那条而非目标 id。
    """
    _ensure_db()
    try:
        eid = int(event_id)
    except Exception:
        return None
    if eid <= 0:
        return None
    with closing(_connect()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, payload FROM events WHERE id = ?", (eid,)
        ).fetchone()
    return _row_to_event(row) if row else None


# 凭据标签：唯一定义源在 credential_labels.py（panel / transparent / 前端共用）。
# 以前这里自己写了一份 5 元素的集合，少了 CONNSTR 与 PRIVATE_KEY —— 结果是
# 「凭据原文永不落库」在**读路径**上失效：修复前写入的历史 RESTORE payload 里
# CONNSTR 项带 original（连接串密码原文），fetch_restore_items 会把它当普通 PII 返回。
_RESTORE_CREDENTIAL_LABELS = CREDENTIAL_LABELS

# 占位符格式 {{LABEL_后缀}}：命中视为不可展示原文（RESTORE 明细的 original 可能是
# 占位符本身——客户端跨请求复述时把上轮 token 当原文再次脱敏），弹窗回退打码 preview。
# 模块级编译：此前在 fetch_restore_items 函数体内每次调用重新编译（审计 P2-4）。
# 后缀两种形态都要认：0.1.13 起新签发的是 6 位纯辅音（不让模型把它当数字去改写，
# 见 transparent._TOKEN_ALPHABET），历史库里全是 6 位 hex。这里与
# transparent._SUFFIX_PAT 必须保持一致——event_store 不 import transparent
# （那会把 mitmproxy 拖进面板进程），所以是刻意的副本，由测试守死两边不漂移。
_PLACEHOLDER_RE = re.compile(r"^\{\{[A-Z0-9]{1,12}_(?:[0-9a-f]{6}|[bcdfghjkmnpqrstvwxz]{6})\}\}$")


def _day_end(now):
    """返回 now 所在本地自然日的下一次零点，兼容夏令时切换。"""
    lt = time.localtime(now)
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + 1, 0, 0, 0, 0, 0, -1))


def fetch_restore_items(now=None, limit=200):
    """查询今日成功还原的敏感项（仅返回统计弹窗所需的安全字段）。

    RESTORE 明细存于事件 payload，不能从 daily_words 反推：daily_words 只收
    MASK，避免同一敏感项被 MASK+RESTORE 双计。此查询不走 /api/logs 的分页/筛选，
    保证首页统计与全库当日口径一致；凭据类即使历史 payload 误带 original，也按
    标签再次拦截，永不从该接口返回明文。

    两个真实数据坑（v1.5.55 修）：
    1. 不能按 ts DESC 加 LIMIT 截取——成功还原事件分散在一天各时段，会被大量
       no_placeholder_in_response 事件挤出窗口，导致弹窗恒空。全天扫描当日
       RESTORE 事件，limit 只约束聚合结果的条数。
    2. RESTORE 明细的 original 可能是占位符本身（客户端跨请求复述时把上轮
       token 当原文再次脱敏），弹窗展示占位符无意义且泄露映射格式，回退打码
       preview。
    """
    _ensure_db()
    now = time.time() if now is None else float(now)
    day_start = _day_start(now)
    day_end = _day_end(now)
    try:
        limit = max(1, min(int(limit or 200), 500))
    except Exception:
        limit = 200
    with closing(_connect()) as conn:
        rows = conn.execute(
            """
            SELECT ts, status, payload
            FROM events
            WHERE ts >= ? AND ts < ? AND type = 'RESTORE'
            ORDER BY ts DESC, id DESC
            """,
            (day_start, day_end),
        ).fetchall()

    aggregates = {}
    total_events = 0
    restored_count = 0
    item_count = 0
    for ts, status_col, payload in rows:
        try:
            rec = json.loads(payload)
        except Exception:
            continue
        status = rec.get("restore_status") or rec.get("status") or status_col
        # 兼容早期只记录 restored/unresolved 计数、没有 status 字段的事件。
        if not status and _int_or_none(rec.get("restored")) and not _int_or_none(rec.get("unresolved")):
            status = "restored"
        if status != "restored":
            continue
        total_events += 1
        restored_count += max(0, _int_or_none(rec.get("restored")) or 0)
        event_keys = set()
        for raw in rec.get("items") or []:
            if not isinstance(raw, dict) or raw.get("restored") is not True:
                continue
            label = str(raw.get("label") or "其他")
            cred = bool(raw.get("cred")) or label in _RESTORE_CREDENTIAL_LABELS
            preview = str(raw.get("preview") or "")
            original = None if cred else raw.get("original")
            if original is not None:
                original = str(original)
                # 历史数据兼容：original 可能是占位符本身，按不可展示处理
                if _PLACEHOLDER_RE.match(original):
                    original = None
            # 凭据没有可展示原文，按标签/打码值合并；普通 PII 按实际原文合并，
            # original 为占位符/缺失时回退打码 preview。
            key = (label, preview) if cred or original is None else (label, original)
            if key in event_keys:
                continue
            event_keys.add(key)
            item_count += 1
            item = aggregates.get(key)
            if item is None:
                item = {
                    "label": label,
                    "preview": preview,
                    "length": max(0, _int_or_none(raw.get("length")) or 0),
                    "events": 0,
                }
                if cred:
                    item["cred"] = True
                elif original is not None:
                    item["original"] = original
                aggregates[key] = item
            item["events"] += 1

    items = list(aggregates.values())
    items.sort(key=lambda it: (-int(it.get("events") or 0), str(it.get("label") or ""), str(it.get("original") or it.get("preview") or "")))
    # limit 必须真正生效：以前算出来却从未使用，而 docstring 写着「limit 只约束聚合
    # 结果的条数」——实现与注释不符，当日明细多时响应体无上限（审计 P1）。
    total_items = len(items)
    items = items[:limit]
    return {
        "ok": True,
        "day_start": day_start,
        "total_events": total_events,
        "restored_count": restored_count,
        "item_count": len(items),
        "total_items": total_items,
        "truncated": total_items > len(items),
        "items": items,
    }


def fetch_events(since=0, limit=500, sensitive_only=False, query="", fulltext=False,
                 event_type=None, max_limit=1000, ascending=False):
    """读取事件列表。

    since=id（返回 id>since 的，供增量轮询）；limit 约束返回条数；
    ascending=True 按游标之后最早的记录分页，避免增量积压时跳过中间记录。
    默认仍取最新记录，保持首次加载、导出和历史调用的语义。
    sensitive_only 隐藏 PASS/SKIP；query 搜索主机/路径/方法/状态/类型等结构化列。
    event_type 按事件类型精确过滤（下推到 SQL，命中 idx_events_type_id：
        本查询按 id 游标分页 + ORDER BY id，`(type, id)` 才是匹配的复合索引）。
        它与 sensitive_only 互斥且优先级更高：显式指定类型时以类型为准，否则
        「只看 SKIP」这类查询会被 sensitive_only 的 NOT IN ('SKIP','PASS') 判成空集。
    fulltext=True 时才额外扫描 payload 大字段（LIKE 无索引，逐行读 payload 代价高，
    默认关闭；审计性能项 P0-5——搜索框默认走结构化列，全文检索由前端显式开启）。

    max_limit: 硬上限。默认 1000 是为了保护 3 秒一次的前端轮询——单次响应再大
        会把面板拖垮。但导出是用户显式点的一次性操作，用同一个上限会让导出文件
        被静默截断（接口层写着允许 5000，这里却砍到 1000，调用方完全无从察觉）。
        所以放出来让调用方按场景决定，并由调用方负责告知截断。
    """
    _ensure_db()
    since = int(since or 0)
    limit = max(1, min(int(limit or 500), int(max_limit or 1000)))
    where = ["id > ?"]
    params = [since]
    if event_type:
        where.append("type = ?")
        params.append(str(event_type).strip().upper())
    elif sensitive_only:
        # 「隐藏透传」：隐藏 PASS/SKIP（过网关但未脱敏的只读/非LLM）
        # MASK/RESTORE/BLOCK/BYPASS 即使 count=0 也显示
        where.append("type NOT IN ('SKIP', 'PASS')")
    q = str(query or "").strip()
    if q:
        like = f"%{q}%"
        # 结构化列优先（host/path/method/status/type 是短列，扫描成本远低于 payload）；
        # payload LIKE 仅在显式 fulltext=True 时加入同一括号（任一字段命中即匹配，
        # 与旧语义一致），默认避免搜索框触发全表大字段扫描（审计性能项 P0-5）。
        cols = ["host", "path", "method", "status", "type"]
        if fulltext:
            cols.append("payload")
        where.append("(" + " OR ".join(f"{c} LIKE ?" for c in cols) + ")")
        params.extend([like] * len(cols))
    sql = (
        "SELECT id, payload FROM events WHERE "
        + " AND ".join(where)
        + (" ORDER BY id ASC LIMIT ?" if ascending else " ORDER BY id DESC LIMIT ?")
    )
    params.append(limit)
    with closing(_connect()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_event(row) for row in (rows if ascending else reversed(rows))]


def prune_events(now=None, retention_days=RETENTION_DAYS):
    _ensure_db()
    now = time.time() if now is None else float(now)
    # retention_days <= 0 = 永久保留（付费版「日志不限期」）。
    # 曾用 max(1, ...) 把 0 当成 1 天，等于把「不限期」实现成「只留一天」——
    # 恰好是承诺的反面，而且用户看不出来（界面显示不限，数据每天在掉）。
    if int(retention_days) <= 0:
        return {"ok": True, "removed": 0, "retained": "forever"}
    cutoff = now - int(retention_days) * 86400
    with closing(_connect()) as conn:
        cur = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        removed = cur.rowcount
        # 统计摘要表策略（用户要求：统计永久保存）：
        #   daily_stats / daily_status / daily_tokens：纯数字计数，永久保留，不随保留期裁剪。
        #   daily_words：存 PII 打码 preview，随保留期裁剪（与事件明细一致，防词级 PII 超期留存）。
        # 曾统一按 day_cutoff 裁剪四张表 → 7 天后统计卡/图表全部归零，用户以为数据丢了。
        day_cutoff = time.strftime("%Y-%m-%d", time.localtime(cutoff))
        # conn.execute("DELETE FROM daily_stats WHERE day <= ?", (day_cutoff,))
        # conn.execute("DELETE FROM daily_status WHERE day <= ?", (day_cutoff,))
        conn.execute("DELETE FROM daily_words WHERE day <= ?", (day_cutoff,))
        # conn.execute("DELETE FROM daily_tokens WHERE day <= ?", (day_cutoff,))
        conn.commit()
        return {"ok": True, "removed": removed}


def clear_events():
    """清空事件库（含清空竞态防护，审计 P1-5 / SHIELD-CLEAR-001）。

    1) 置 cutoff（cutoff 前入队的事件由写线程丢弃）；2) 排空当前未写队列；
    3) 同一事务删除 `events` + `daily_words`——**数字摘要表一律保留**
    （用户明确要求「清日志不清统计」）。判据是含不含 PII：daily_words 存词级
    打码 preview 属于日志明细，daily_stats/daily_status/daily_tokens 是纯数字计数，
    清掉等于把用户几个月的趋势图归零，而他只是想清日志；
    4) 按 cutoff 补删一次兜住写线程正在写旧事件的窗口。清空之后的新事件正常写入。

    这段 docstring 曾写「删除 events + 三个日统计摘要表」，与下面的实现相反——
    实现只删 daily_words。注释和代码不一致时，改注释别改代码（2026-08-17 修正）。
    """
    global _clear_cutoff
    _ensure_db()
    _clear_cutoff = time.time()
    # 排空未写队列：这些事件发生在清空之前，直接丢弃
    drained = 0
    while True:
        try:
            _event_queue.get_nowait()
            _event_queue.task_done()
            drained += 1
        except queue.Empty:
            break
    with closing(_connect()) as conn:
        conn.execute("DELETE FROM events")
        # 统计摘要表全部保留（用户要求：统计永久保存，清日志不清统计）：
        #   daily_stats    每日请求/脱敏/还原/告警计数（纯数字，无 PII）
        #   daily_status   还原状态计数（纯数字，无 PII）
        #   daily_tokens   token 用量（纯数字，无 PII）
        # 仅删 daily_words：它存 PII 打码 preview（曾存原文，已迁移为 preview），
        # 清日志时一并清掉词级明细，与「清空日志=真删除」语义一致。
        # conn.execute("DELETE FROM daily_stats")
        # conn.execute("DELETE FROM daily_status")
        conn.execute("DELETE FROM daily_words")
        # conn.execute("DELETE FROM daily_tokens")  # 不删
        conn.execute("DELETE FROM sqlite_sequence WHERE name='events'")
        # 摘要表清空后迁移标记失效：后续事件重新增量累积
        conn.execute("DELETE FROM meta WHERE key='daily_stats_migrated'")
        conn.commit()
    # 兜底：写线程已取走但未提交的旧事件（窗口竞态）按 cutoff 补删
    with closing(_connect()) as conn:
        conn.execute("DELETE FROM events WHERE ts < ?", (_clear_cutoff,))
        conn.commit()
    try:
        LEGACY_JSONL_PATH.write_text("", encoding="utf-8")
    except Exception:
        pass
    return {"ok": True, "dropped_inflight": drained}


def _day_start(now):
    lt = time.localtime(now)
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))


def today_stats(now=None):
    """按本地自然日聚合今日拦截统计（仪表盘数据源）。

    优先读 daily_stats/daily_status/daily_words 摘要表（写线程增量维护，
    O(当日行数) 而非全量扫当日 payload——审计性能项：2 万事件时从 ~158ms 降到亚毫秒）。
    旧库（升级前写入的事件无摘要）自动回退全量扫描，口径与摘要一致。
    """
    _ensure_db()
    now = time.time() if now is None else float(now)
    day_start = _day_start(now)
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    with closing(_connect()) as conn:
        # 升级迁移：摘要表上线前的事件回填一次（meta 标记幂等）
        _migrate_daily_stats(conn, now)
        rows = conn.execute(
            "SELECT type, events, count_sum, restored FROM daily_stats WHERE day=?", (day,)
        ).fetchall()
        status_rows = conn.execute(
            "SELECT status, cnt FROM daily_status WHERE day=?", (day,)
        ).fetchall()
        word_rows = conn.execute(
            "SELECT label, word, cnt FROM daily_words WHERE day=?", (day,)
        ).fetchall()
        token_row = conn.execute(
            "SELECT prompt, completion FROM daily_tokens WHERE day=?", (day,)
        ).fetchone()
    tokens = {}
    if token_row:
        tokens = {"prompt": int(token_row[0] or 0), "completion": int(token_row[1] or 0)}
    if not rows:
        return _today_stats_legacy(now=now, day_start=day_start)

    by_type = {
        str(typ): {"events": int(events or 0), "count_sum": int(count_sum or 0)}
        for typ, events, count_sum, _restored in rows
    }

    def _ev(typ):
        return by_type.get(typ, {}).get("events", 0)

    def _sum(typ):
        return by_type.get(typ, {}).get("count_sum", 0)

    requests = _ev("MASK") + _ev("PASS") + _ev("BYPASS") + _ev("BLOCK")
    alerts = _ev("BLOCK") + _ev("ERR") + _ev("SCAN_WARN")
    status_map = {str(s or ""): int(n or 0) for s, n in status_rows}
    restore_ok = status_map.get("restored", 0)
    restore_failed = status_map.get("unresolved", 0)
    alerts += restore_failed
    restore_by_status = dict(status_map)
    by_label = {}
    top_words = {}
    for lbl, w, c in word_rows:
        by_label[str(lbl)] = by_label.get(str(lbl), 0) + int(c or 0)
        key = (str(lbl), str(w))
        top_words[key] = top_words.get(key, 0) + int(c or 0)
    by_label_words = {}
    for (lbl, w), c in top_words.items():
        by_label_words.setdefault(lbl, []).append({"word": w, "count": c})
    for lst in by_label_words.values():
        lst.sort(key=lambda x: -x["count"])
    top_list = sorted(
        ({"label": lbl, "word": w, "count": c} for (lbl, w), c in top_words.items()),
        key=lambda x: -x["count"],
    )[:20]
    return {
        "ok": True,
        "day_start": day_start,
        "masked_items": _sum("MASK"),
        "mask_events": _ev("MASK"),
        "restored": _ev("RESTORE"),
        "restore_ok": restore_ok,
        "restore_failed": restore_failed,
        "requests": requests,
        "alerts": alerts,
        "tokens": tokens,
        "by_type": by_type,
        "restore_by_status": restore_by_status,
        "by_label": by_label,
        "by_label_words": by_label_words,
        "top_words": top_list,
    }


def stats_range(days=1, now=None):
    """按最近 N 个自然日聚合统计（仪表盘「今日/近7天/近30天」数据源）。

    口径与 today_stats 一致，但汇总最近 N 天的 daily_stats/daily_status/daily_words/
    daily_tokens 摘要行求和。过 0 点后「今天」清零是预期行为，用户切「近7天」
    即可看到昨天的数据。
    """
    _ensure_db()
    now = time.time() if now is None else float(now)
    days = max(1, min(int(days), 90))  # 上限 90 天（保留期一般 7-30 天）
    day_start = _day_start(now)
    # 最近 N 天的日期列表（含今天）
    days_list = []
    for i in range(days):
        t = now - i * 86400
        days_list.append(time.strftime("%Y-%m-%d", time.localtime(t)))
    placeholders = ",".join("?" * len(days_list))
    with closing(_connect()) as conn:
        rows = conn.execute(
            f"SELECT type, SUM(events), SUM(count_sum), SUM(restored) FROM daily_stats WHERE day IN ({placeholders}) GROUP BY type",
            days_list,
        ).fetchall()
        status_rows = conn.execute(
            f"SELECT status, SUM(cnt) FROM daily_status WHERE day IN ({placeholders}) GROUP BY status",
            days_list,
        ).fetchall()
        word_rows = conn.execute(
            f"SELECT label, word, SUM(cnt) FROM daily_words WHERE day IN ({placeholders}) GROUP BY label, word",
            days_list,
        ).fetchall()
        token_row = conn.execute(
            f"SELECT SUM(prompt), SUM(completion) FROM daily_tokens WHERE day IN ({placeholders})",
            days_list,
        ).fetchone()
    tokens = {"prompt": int(token_row[0] or 0), "completion": int(token_row[1] or 0)}
    by_type = {
        str(typ): {"events": int(events or 0), "count_sum": int(count_sum or 0)}
        for typ, events, count_sum, _restored in rows
    }
    # 如果摘要表为空（新库无数据），回退全量扫描最近 N 天
    if not rows:
        return _today_stats_legacy_range(now=now, since=now - days * 86400)

    def _ev(typ):
        return by_type.get(typ, {}).get("events", 0)

    def _sum(typ):
        return by_type.get(typ, {}).get("count_sum", 0)

    requests = _ev("MASK") + _ev("PASS") + _ev("BYPASS") + _ev("BLOCK")
    alerts = _ev("BLOCK") + _ev("ERR") + _ev("SCAN_WARN")
    status_map = {str(s or ""): int(n or 0) for s, n in status_rows}
    restore_ok = status_map.get("restored", 0)
    restore_failed = status_map.get("unresolved", 0)
    alerts += restore_failed
    restore_by_status = dict(status_map)
    by_label = {}
    top_words = {}
    for lbl, w, c in word_rows:
        by_label[str(lbl)] = by_label.get(str(lbl), 0) + int(c or 0)
        key = (str(lbl), str(w))
        top_words[key] = top_words.get(key, 0) + int(c or 0)
    by_label_words = {}
    for (lbl, w), c in top_words.items():
        by_label_words.setdefault(lbl, []).append({"word": w, "count": c})
    for lst in by_label_words.values():
        lst.sort(key=lambda x: -x["count"])
    top_list = sorted(
        ({"label": lbl, "word": w, "count": c} for (lbl, w), c in top_words.items()),
        key=lambda x: -x["count"],
    )[:20]
    return {
        "ok": True,
        "day_start": day_start,
        "range_days": days,
        "masked_items": _sum("MASK"),
        "mask_events": _ev("MASK"),
        "restored": _ev("RESTORE"),
        "restore_ok": restore_ok,
        "restore_failed": restore_failed,
        "requests": requests,
        "alerts": alerts,
        "blocked": _ev("BLOCK"),
        "errs": _ev("ERR"),
        "scan_warns": _ev("SCAN_WARN"),
        "tokens": tokens,
        "by_type": by_type,
        "restore_by_status": restore_by_status,
        "by_label": by_label,
        "by_label_words": by_label_words,
        "top_words": top_list,
    }


def label_summary(days=7):
    """近 N 天按规则标签聚合的命中量（战绩卡片数据源）。

    直接读 daily_words 摘要表求和——它由写线程增量维护，
    不用扫 events 的 payload。**只读 label 与 cnt，不碰 word 列**：
    word 是命中的原文（公司名、客户名等），卡片是要拿去分享的，
    一个字都不能带上去。

    返回 {label: 次数}，按次数降序。
    """
    _ensure_db()
    days = max(1, min(int(days), 90))
    since_day = time.strftime("%Y-%m-%d", time.localtime(time.time() - (days - 1) * 86400))
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT label, SUM(cnt) AS n FROM daily_words WHERE day >= ? GROUP BY label ORDER BY n DESC",
            (since_day,),
        ).fetchall()
    # _connect() 不挂 row_factory，取的是裸 tuple，别按列名索引
    return {str(r[0]): int(r[1] or 0) for r in rows}


def stats_history(days=30, granularity="day"):
    """按天或小时聚合历史统计（数据统计页柱状图/折线图数据源）。

    Args:
        days: 查询天数（day 粒度时为天数，hour 粒度时为小时数）
        granularity: day | hour

    返回 [{ts, label, day/hour, requests, mask_events, restored, alerts, tokens_prompt, tokens_completion}]
    按时间升序，适合直接渲染折线图/柱状图。
    """
    _ensure_db()
    now = time.time()
    days = max(1, min(int(days), 90))
    result = []
    audit_visibility_clauses, audit_visibility_params = _audit_visibility_filter()
    audit_visibility_sql = " AND " + " AND ".join(audit_visibility_clauses)
    if granularity == "hour":
        # 按小时聚合：扫 events 表（无小时摘要表，直接 GROUP BY）
        hours = min(days, 72)  # 小时粒度上限 72 小时（3 天）
        since = now - hours * 3600
        with closing(_connect()) as conn:
            # 分桶必须 CAST 成整数再乘回去。ts 是 REAL（见 events 表定义），
            # SQLite 的 REAL/INTEGER 结果恒为 REAL，`(ts / 3600) * 3600` 精确等于 ts
            # 本身 —— GROUP BY 退化成「每个事件一个桶」，小时图实际是坏的
            # （实测 3 个同小时事件 → 3 个桶；CAST 后 → 1 个桶）。
            rows = conn.execute(
                """SELECT CAST(ts / 3600 AS INTEGER) * 3600 AS hour_bucket, type, COUNT(*),
                          COALESCE(SUM(count), 0), COALESCE(SUM(restored), 0)
                   FROM events WHERE ts >= ? GROUP BY hour_bucket, type""",
                (since,),
            ).fetchall()
            # 审计信号事件按小时聚合
            audit_hours = conn.execute(
                "SELECT CAST(ts / 3600 AS INTEGER) * 3600, COUNT(*) FROM audit_events WHERE ts >= ?"
                + audit_visibility_sql + " GROUP BY 1",
                (since, *audit_visibility_params),
            ).fetchall()
        # 聚合成 hourly buckets
        buckets = {}
        for hb, typ, cnt, csum, rstd in rows:
            if hb not in buckets:
                buckets[hb] = {"requests": 0, "mask_events": 0, "restored": 0, "alerts": 0}
            b = buckets[hb]
            if typ in ("MASK", "PASS", "BYPASS", "BLOCK"):
                b["requests"] += cnt
            if typ == "MASK":
                b["mask_events"] += cnt
            if typ == "RESTORE":
                b["restored"] += cnt
            if typ in ("BLOCK", "ERR", "SCAN_WARN"):
                b["alerts"] += cnt
        audit_hour_map = {hb: n for hb, n in audit_hours}
        for hb in sorted(buckets.keys()):
            b = buckets[hb]
            result.append({
                "ts": hb,
                "label": time.strftime("%m-%d %H:00", time.localtime(hb)),
                "hour": int(hb),
                **b,
                "tokens_prompt": 0,  # 小时粒度无 token 摘要
                "tokens_completion": 0,
                "audit_signals": int(audit_hour_map.get(hb, 0)),
                "audit_high": 0,
            })
    else:
        # 按天聚合（优先读 daily_stats 摘要表）
        days_list = []
        for i in range(days):
            t = now - i * 86400
            days_list.append(time.strftime("%Y-%m-%d", time.localtime(t)))
        placeholders = ",".join("?" * len(days_list))
        with closing(_connect()) as conn:
            rows = conn.execute(
                f"SELECT day, type, events, count_sum, restored FROM daily_stats WHERE day IN ({placeholders})",
                days_list,
            ).fetchall()
            token_rows = conn.execute(
                f"SELECT day, prompt, completion FROM daily_tokens WHERE day IN ({placeholders})",
                days_list,
            ).fetchall()
            # 审计信号事件（audit_events 表）按天聚合：注入审计/投毒检测信号数
            day_start_ts = time.mktime(time.strptime(days_list[-1], "%Y-%m-%d"))
            audit_rows = conn.execute(
                "SELECT ts, severity FROM audit_events WHERE ts >= ?" + audit_visibility_sql,
                (day_start_ts, *audit_visibility_params),
            ).fetchall()
        # 聚合成 day buckets
        day_buckets = {}
        for d, typ, ev, csum, rstd in rows:
            if d not in day_buckets:
                day_buckets[d] = {"requests": 0, "mask_events": 0, "restored": 0, "alerts": 0}
            b = day_buckets[d]
            if typ in ("MASK", "PASS", "BYPASS", "BLOCK"):
                b["requests"] += int(ev or 0)
            if typ == "MASK":
                b["mask_events"] += int(ev or 0)
            if typ == "RESTORE":
                b["restored"] += int(ev or 0)
            if typ in ("BLOCK", "ERR", "SCAN_WARN"):
                b["alerts"] += int(ev or 0)
        token_map = {}
        for d, p, c in token_rows:
            token_map[d] = {"prompt": int(p or 0), "completion": int(c or 0)}
        # audit_events 按天聚合（0点边界）
        audit_map = {}
        for ts, sev in audit_rows:
            d = time.strftime("%Y-%m-%d", time.localtime(ts))
            b = audit_map.setdefault(d, {"audit_signals": 0, "audit_high": 0})
            b["audit_signals"] += 1
            if str(sev or "") in ("HIGH", "CRITICAL"):
                b["audit_high"] += 1
        for d in sorted(days_list, reverse=False):
            b = day_buckets.get(d, {"requests": 0, "mask_events": 0, "restored": 0, "alerts": 0})
            tk = token_map.get(d, {"prompt": 0, "completion": 0})
            ab = audit_map.get(d, {"audit_signals": 0, "audit_high": 0})
            # 把日期字符串转时间戳（当天 0 点）
            try:
                t_struct = time.strptime(d, "%Y-%m-%d")
                ts = int(time.mktime(t_struct))
            except Exception:
                ts = 0
            result.append({
                "ts": ts,
                "label": d[5:],  # MM-DD
                "day": d,
                **b,
                "tokens_prompt": tk["prompt"],
                "tokens_completion": tk["completion"],
                "audit_signals": ab["audit_signals"],
                "audit_high": ab["audit_high"],
            })
    return {"ok": True, "granularity": granularity, "days": days, "data": result}


def _today_stats_legacy_range(now=None, since=None):
    """旧库回退：摘要表为空时全量扫描时间范围（stats_range 用）。"""
    now = time.time() if now is None else float(now)
    if since is None:
        since = now - 86400
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT type, COUNT(*) AS events, COALESCE(SUM(count), 0) AS count_sum FROM events WHERE ts >= ? GROUP BY type",
            (since,),
        ).fetchall()
        status_rows = conn.execute(
            "SELECT status, COUNT(*) FROM events WHERE ts >= ? AND type = 'RESTORE' GROUP BY status",
            (since,),
        ).fetchall()
    by_type = {
        str(typ or ""): {"events": int(events or 0), "count_sum": int(count_sum or 0)}
        for typ, events, count_sum in rows
    }

    def _ev(typ):
        return by_type.get(typ, {}).get("events", 0)

    def _sum(typ):
        return by_type.get(typ, {}).get("count_sum", 0)

    requests = _ev("MASK") + _ev("PASS") + _ev("BYPASS") + _ev("BLOCK")
    alerts = _ev("BLOCK") + _ev("ERR") + _ev("SCAN_WARN")
    status_map = {str(s or ""): int(n or 0) for s, n in status_rows}
    restore_ok = status_map.get("restored", 0)
    restore_failed = status_map.get("unresolved", 0)
    alerts += restore_failed
    return {
        "ok": True,
        "day_start": since,
        "range_days": int((now - since) / 86400) if since < now else 1,
        "masked_items": _sum("MASK"),
        "mask_events": _ev("MASK"),
        "restored": _ev("RESTORE"),
        "restore_ok": restore_ok,
        "restore_failed": restore_failed,
        "requests": requests,
        "alerts": alerts,
        "blocked": _ev("BLOCK"),
        "errs": _ev("ERR"),
        "scan_warns": _ev("SCAN_WARN"),
        "tokens": {"prompt": 0, "completion": 0},
        "by_type": by_type,
        "restore_by_status": dict(status_map),
        "by_label": {},
        "by_label_words": {},
        "top_words": [],
    }


def _today_stats_legacy(now=None, day_start=None):
    """旧库回退路径：摘要表为空时全量扫当日 payload（口径与摘要一致）。"""
    now = time.time() if now is None else float(now)
    if day_start is None:
        day_start = _day_start(now)
    with closing(_connect()) as conn:
        rows = conn.execute(
            """
            SELECT type,
                   COUNT(*) AS events,
                   COALESCE(SUM(count), 0) AS count_sum
            FROM events
            WHERE ts >= ?
            GROUP BY type
            """,
            (day_start,),
        ).fetchall()
        status_rows = conn.execute(
            """
            SELECT status, COUNT(*) FROM events
            WHERE ts >= ? AND type = 'RESTORE'
            GROUP BY status
            """,
            (day_start,),
        ).fetchall()
        mask_payloads = conn.execute(
            "SELECT payload FROM events WHERE ts >= ? AND type = 'MASK'",
            (day_start,),
        ).fetchall()
    by_type = {
        str(typ or ""): {"events": int(events or 0), "count_sum": int(count_sum or 0)}
        for typ, events, count_sum in rows
    }

    def _ev(typ):
        return by_type.get(typ, {}).get("events", 0)

    def _sum(typ):
        return by_type.get(typ, {}).get("count_sum", 0)

    requests = _ev("MASK") + _ev("PASS") + _ev("BYPASS") + _ev("BLOCK")
    alerts = _ev("BLOCK") + _ev("ERR") + _ev("SCAN_WARN")
    status_map = {str(s or ""): int(n or 0) for s, n in status_rows}
    restore_ok = status_map.get("restored", 0)
    restore_failed = status_map.get("unresolved", 0)
    alerts += restore_failed
    restore_by_status = dict(status_map)
    by_label = {}
    top_words = {}
    for (pl,) in mask_payloads:
        try:
            rec = json.loads(pl)
        except Exception:
            continue
        for it in rec.get("items") or []:
            lbl = str(it.get("label") or "其他")
            by_label[lbl] = by_label.get(lbl, 0) + 1
            word = it.get("original")
            if not word:
                word = str(it.get("preview") or "") or "?"
            key = (lbl, word)
            top_words[key] = top_words.get(key, 0) + 1
    by_label_words = {}
    for (lbl, w), c in top_words.items():
        by_label_words.setdefault(lbl, []).append({"word": w, "count": c})
    for lst in by_label_words.values():
        lst.sort(key=lambda x: -x["count"])
    top_list = sorted(
        ({"label": lbl, "word": w, "count": c} for (lbl, w), c in top_words.items()),
        key=lambda x: -x["count"],
    )[:20]
    # legacy 路径（升级前事件无 daily_tokens 摘要）：扫当日 RESTORE payload 累加
    tokens = {"prompt": 0, "completion": 0}
    try:
        with closing(_connect()) as conn:
            rows = conn.execute(
                "SELECT payload FROM events WHERE ts >= ? AND type = 'RESTORE'",
                (day_start,),
            ).fetchall()
        for (pl,) in rows:
            rec = json.loads(pl)
            u = rec.get("usage")
            if not isinstance(u, dict):
                continue
            tokens["prompt"] += int(u.get("prompt_tokens") or 0)
            tokens["completion"] += int(u.get("completion_tokens") or 0)
    except Exception:
        pass
    return {
        "ok": True,
        "day_start": day_start,
        "masked_items": _sum("MASK"),
        "mask_events": _ev("MASK"),
        "restored": _ev("RESTORE"),
        "restore_ok": restore_ok,
        "restore_failed": restore_failed,
        "requests": requests,
        "alerts": alerts,
        "tokens": tokens,
        "by_type": by_type,
        "restore_by_status": restore_by_status,
        "by_label": by_label,
        "by_label_words": by_label_words,
        "top_words": top_list,
    }


def import_legacy_jsonl_once():
    _ensure_db()
    if not LEGACY_JSONL_PATH.exists():
        return {"ok": True, "imported": 0}
    with closing(_connect()) as conn:
        done = conn.execute(
            "SELECT value FROM meta WHERE key='legacy_jsonl_imported'"
        ).fetchone()
        if done:
            return {"ok": True, "imported": 0}

    imported = 0
    for line in LEGACY_JSONL_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
            if isinstance(rec, dict):
                append_event(rec)
                imported += 1
        except Exception:
            pass
    with closing(_connect()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('legacy_jsonl_imported', ?)",
            (str(time.time()),),
        )
        conn.commit()
    return {"ok": True, "imported": imported}


def stats_models(days=7, now=None):
    """按模型聚合使用量（「模型排行」+ 费用估算数据源）。

    读 daily_models 摘要表（写线程增量维护，只收 RESTORE 事件=成功调用）。

    Args:
        days: 统计窗口（1-90）
        now: 基准时间（测试注入）

    返回 [{model, requests, prompt, completion}]，按 requests 降序。
    """
    _ensure_db()
    now = time.time() if now is None else float(now)
    days = max(1, min(int(days), 90))
    # 按本地自然日列出窗口中的日期，避免 days=1 使用 now-86400 的日期
    # 把昨天整天也算进来；调用方的「今日费用估算」必须只包含今天。
    days_list = [
        time.strftime("%Y-%m-%d", time.localtime(now - i * 86400))
        for i in range(days)
    ]
    placeholders = ",".join("?" * len(days_list))
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT model, SUM(requests) AS req, SUM(prompt) AS p, SUM(completion) AS c, SUM(errors) AS err "
            "FROM daily_models WHERE day IN (" + placeholders + ") GROUP BY model "
            "ORDER BY req DESC, err DESC, model",
            days_list,
        ).fetchall()
    out = []
    for model, req, p, c, err in rows:
        out.append({
            "model": model,
            "requests": int(req or 0),
            "prompt": int(p or 0),
            "completion": int(c or 0),
            "errors": int(err or 0),
        })
    return out
