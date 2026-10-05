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
import onboarding
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
from credential_labels import (CREDENTIAL_ECHO_KINDS, CREDENTIAL_ECHO_REAL_MARKER,
                               CREDENTIAL_ECHO_SAMPLE_MARKER)


ROOT = Path(__file__).parent.resolve()
# 数据目录：打包后从 LLM_SHIELD_DATA_DIR 读，开发时回退脚本目录
_DATA_ROOT = Path(os.environ.get("LLM_SHIELD_DATA_DIR") or str(ROOT)).resolve()
DB_PATH = _DATA_ROOT / "shield-events.sqlite3"
LEGACY_JSONL_PATH = _DATA_ROOT / "shield-events.jsonl"
RETENTION_DAYS = 7
EVENT_QUEUE_MAX = 5000
# 入口维度（ingress）的**合法取值集合**：`proxy`=CLI 代理链路（含老数据 / legacy 导入），
# `ext`=浏览器扩展桥接链路。放在模块级是为了让写入侧的归一化与读取侧的过滤**引用同一份
# 定义**——曾经读取侧硬编码 `'proxy'`、写入侧"有值就原样存"，两边不一致时脏值会落进
# 一个永远筛不出来的隐形分组（详见 `_normalize_ingress`）。
INGRESS_PROXY = "proxy"
INGRESS_EXT = "ext"
INGRESS_VALUES = (INGRESS_PROXY, INGRESS_EXT)

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
            ingress TEXT,
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
    # 入口维度列（浏览器扩展链路）：proxy=CLI 代理链路，ext=浏览器扩展链路。
    # 老库平滑迁移（幂等）：结构化列走的是**显式列清单**，不加列会让两条 INSERT
    # 直接报「no such column」——那样连事件都写不进去了。
    # 老数据留空，读取侧按 'proxy' 解读（见 _normalize_ingress / fetch_events），
    # 避免出现 NULL 分组。
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
        if "ingress" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN ingress TEXT")
    except Exception:
        pass
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
            probe_id TEXT,
            -- A-1：本条审计的成本与降级留痕。
            -- 这三个字段此前**发了但从没落库**（表结构里没有对应列），于是
            -- "排障时不必再猜这条告警是不是扫描被削过的产物"这句注释是空头支票；
            -- 而测试打桩打在入队边界之前，看不见落库失败。
            audit_ms REAL,
            audit_scan_bytes INTEGER,
            audit_scan_truncated INTEGER
        )
        """
    )
    # 老库补列（新增列必须走这条：`CREATE TABLE IF NOT EXISTS` 对已存在的表不生效，
    # 否则升级用户的审计表永远缺这三列 → 写入一直失败）
    audit_cols = [r[1] for r in conn.execute("PRAGMA table_info(audit_events)").fetchall()]
    for col, ddl in (("audit_ms", "REAL"),
                     ("audit_scan_bytes", "INTEGER"),
                     ("audit_scan_truncated", "INTEGER")):
        if col not in audit_cols:
            conn.execute(f"ALTER TABLE audit_events ADD COLUMN {col} {ddl}")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_events(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_signal ON audit_events(signal_type)")
    # 日统计摘要表（审计性能项）：写线程增量维护，today_stats 不再全量扫当日 payload。
    # daily_words.word 只存非凭据原文（凭据 items 无 original，落 preview 打码），
    # 与旧口径一致：有 original 用明文，无则用 preview 兜底。
    # ⚠️ daily_words 的主键**含 ingress**：同一明文在代理链路与扩展链路都会命中，
    #    三列主键会让两者被 ON CONFLICT 合并成一行，ingress 取谁都错 = 一个会撒谎的
    #    维度。改主键 SQLite 不支持，所以老库要在 init_db 里**重建表**（见那段注释）。
    # daily_stats / daily_status **不拆入口**：总量口径是「过网关必有日志」，
    # 拆开再求和等于没拆，反而给首页数字引入第二套口径。
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
            ingress TEXT NOT NULL DEFAULT 'proxy',
            PRIMARY KEY (day, label, word, ingress)
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
    # 前缀保真度日摘要：只收 MASK 事件（只有它带 body_rewritten /
    # first_diff_byte / suffix_reused 三个诊断字段，见 transparent.request）。
    # 回答「上游 Prompt Cache 命中率归零，是我们改了请求字节还是上游自己 miss」：
    #   masks/rewritten → 零改写透传占比（rewritten=0 表示一个字节都没动）；
    #   reused          → 占位符后缀复用次数（沿用旧 token 上游前缀才有机会命中）；
    #   diff_sum/diff_n → 首个差异字节的均值（越接近敏感值真实位置越不伤前缀）。
    # 不做历史回填：升级前的 MASK 事件 payload 里压根没有这三个字段，
    # 硬算会把「零改写率」算高。本表升级当天为空、只累积新事件，故口径天然干净。
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_prefix (
            day TEXT PRIMARY KEY,
            masks INTEGER DEFAULT 0,
            rewritten INTEGER DEFAULT 0,
            reused INTEGER DEFAULT 0,
            diff_sum INTEGER DEFAULT 0,
            diff_n INTEGER DEFAULT 0
        )
        """
    )
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

    ⚠️ 重放必须传 replay=True：这些事件早已计入过摘要，daily_prefix 这类
    「只进不退」的计数器再写一次就是翻倍（daily_stats 的翻倍属历史既有行为，
    不在本次范围内）。
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
            _update_stats(conn, rec, replay=True)
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


# ========== 日志写入分级（§D1：少存、找得到、删得明白）==========
# 三种模式的差别落在**写侧**，不是读取裁剪。
#   为什么必须写侧：升级前的 `slim` 只是列表接口的读取裁剪，明文照样躺在库里，
#   任何绕过列表的读取都能捞回原文（`/api/logs/detail` 按 id 原样回源、导出、
#   诊断包、直接打开 sqlite）。「最小模式」如果只在 UI 上少显示几列，等于没做。
#   summary  最小：只留时间/入口/状态/原因/类别数量/耗时。不存对话正文、敏感原值、
#            业务路径元数据；词统计也只保留类别计数。
#   detailed 本地详细：保持既有全部能力（普通 PII「脱敏 ↔ 原文」对照 + 词榜明文），
#            凭据仍恒不落原文。老用户缺字段时迁移到这里，不静默改变既有功能。
#   trace    临时排障：detailed 去掉全部 `items[].original` 明文、正文片段截断到上限。
#            由面板限时开启（默认关、重启后关，见 log_trace_state/start_log_trace）。
LOG_MODE_SUMMARY = "summary"
LOG_MODE_DETAILED = "detailed"
LOG_MODE_TRACE = "trace"
LOG_MODE_DEFAULT = LOG_MODE_DETAILED
LOG_MODE = LOG_MODE_DEFAULT

# 运行期信号文件：面板写、引擎读（两个进程通过它传递**纯运行时**控制）。
# 为什么不用 config.json：引擎进程不该去写配置文件（两进程写同一份配置会互相覆盖），
# 而这些信号（限时排障截止时间、映射重置代号）都是运行期状态，不是持久配置项。
# 为什么共用一个文件：两个信号用同一套「节流读 + 原子写」机制就够了；各开一个文件
# 只会多一份读盘节流与一个容易漂移的命名约定。
#
# 【已知局限（已评估、有意接受）】合并写是「读→改→写」，两个进程同时写会丢更新
# （lost update）。两个写入者及其频率：面板（仅在用户点击时）、引擎（仅在 `load()`
# 时把 `trace_until` 归零一次）。频率差好几个数量级，且面板的 `engine_applied=pending`
# 已如实告知「无法确认是否生效」，用户再点一次即可。不上文件锁：跨平台语义不一，
# 成本大于这个窗口的收益。
SIGNALS_FILE = _DATA_ROOT / "engine-signals.json"
# 信号缓存：`log_trace_state()` 与 `mapping_reset_generation()` 都在请求路径上被调，
# 不能每条事件/每个请求都 stat 一次文件。5s 窗口内的多次读共用一次解析结果。
_SIGNALS_CACHE = {"ts": 0.0, "data": {}}
_SIGNALS_LOCK = threading.Lock()
_SIGNALS_CACHE_TTL_S = 5.0


def _read_signals(now=None) -> dict:
    """读取运行期信号（带 5s 缓存）。文件缺失/损坏一律返回空字典。

    返回**副本**：调用方不会意外改到缓存（改缓存会让另一个进程看不到真实值）。
    """
    now = time.time() if now is None else float(now)
    with _SIGNALS_LOCK:
        if now - _SIGNALS_CACHE["ts"] < _SIGNALS_CACHE_TTL_S:
            return dict(_SIGNALS_CACHE["data"])
    data = {}
    try:
        loaded = json.loads(SIGNALS_FILE.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            data = loaded
    except Exception:
        data = {}
    with _SIGNALS_LOCK:
        _SIGNALS_CACHE["ts"] = now
        _SIGNALS_CACHE["data"] = data
    return dict(data)


def _write_signals(patch: dict, now=None) -> dict:
    """合并写入运行期信号（原子替换：读者不会看到半截 JSON）。

    合并而不是整份覆盖：两个信号由不同动作写入（开排障 / 重置映射），
    整份覆盖会让后写的那个把另一个静默抹掉。以**文件当前内容**为基准合并，
    而不是用本进程缓存，否则缓存过期时会把对方刚写的字段抹掉。
    """
    now = time.time() if now is None else float(now)
    cur = {}
    try:
        loaded = json.loads(SIGNALS_FILE.read_text(encoding="utf-8"))
        cur = dict(loaded) if isinstance(loaded, dict) else {}
    except Exception:
        cur = {}
    cur.update(patch)
    # 暂存名带 pid：面板与引擎是**两个进程**，用同一个 `.tmp` 名字时，A 写完刚要
    # `os.replace` 而 B 把它截断重写 → 先 replace 的那个会搬走对方的半成品，
    # 后 replace 的拿到 FileNotFoundError（实测风险，不是假想）。
    tmp = SIGNALS_FILE.with_name("%s.%d.tmp" % (SIGNALS_FILE.name, os.getpid()))
    tmp.write_text(json.dumps(cur, ensure_ascii=False), encoding="utf-8")
    os.replace(str(tmp), str(SIGNALS_FILE))
    with _SIGNALS_LOCK:
        _SIGNALS_CACHE["ts"] = now
        _SIGNALS_CACHE["data"] = cur
    return dict(cur)


def set_log_mode(mode) -> None:
    """同步「日志写入模式」基值（配置热重载时调用，两个写入进程各调各的）。

    只接受 summary/detailed 两个**可持久化**值：trace 是限时运行时状态，
    由 `start_log_trace()` 单独控制，不能从配置文件里长期打开。
    """
    global LOG_MODE
    m = str(mode or "").strip().lower()
    LOG_MODE = m if m in (LOG_MODE_SUMMARY, LOG_MODE_DETAILED) else LOG_MODE_DEFAULT


def log_trace_state(now=None) -> dict:
    """当前限时排障状态：{"active": bool, "until": epoch}。

    读盘按 5s 节流：本函数会被请求路径上的事件写入调用，不能每条事件都 stat
    一次文件（`_log` 与 `enqueue_event` 都在请求路径上）。
    """
    now = time.time() if now is None else float(now)
def log_trace_state(now=None) -> dict:
    """当前限时排障状态：{"active": bool, "until": epoch}。

    读盘按 5s 节流（`_read_signals`）：本函数会被请求路径上的事件写入调用，
    不能每条事件都 stat 一次文件（`_log` 与 `enqueue_event` 都在请求路径上）。
    """
    now = time.time() if now is None else float(now)
    try:
        until = float(_read_signals(now).get("trace_until") or 0.0)
    except Exception:
        until = 0.0
    return {"active": until > now, "until": until}


def start_log_trace(minutes=15, now=None) -> dict:
    """开启限时排障（默认 15 分钟，上限 60）。到点后自动回到基模式。

    `minutes` 由面板做一次钳制后写文件；这里再钳一次，避免任何调用方
    （含测试与脚本）写进一个「永不回退」的超长窗口。
    """
    now = time.time() if now is None else float(now)
    try:
        minutes = max(1, min(int(minutes or 15), 60))
    except Exception:
        minutes = 15
    until = now + minutes * 60
    try:
        _write_signals({"trace_until": until, "trace_started_at": now, "trace_minutes": minutes}, now)
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    return {"ok": True, "until": until, "minutes": minutes}


def stop_log_trace() -> dict:
    """关闭限时排障。用户手动关闭与进程启动都会调用。

    只把 `trace_until` 写成 0，不删文件：同一文件里还有「映射重置代号」这类
    别的信号，删文件会把它们一起抹掉。残留的 `trace_until=0` 不含任何正文。
    """
    try:
        _write_signals({"trace_until": 0.0})
    except Exception:
        return {"ok": False}
    return {"ok": True, "until": 0.0}


def mapping_reset_generation() -> int:
    """「清空内存映射」的代号（单调递增）。

    面板与引擎是两个进程，面板无法直接清引擎里的映射表，所以面板只把代号 +1，
    引擎在请求路径上发现代号变了就清一次（见 `transparent.reset_mappings`）。
    代号语义是「变化即重置」，不是「大于多少才重置」——用单调值而不是布尔标记，
    是因为布尔标记需要「消费后清零」，而清零又要二次同步（多一层竞态）。
    """
    try:
        return int(_read_signals().get("mapping_reset_gen") or 0)
    except Exception:
        return 0


def request_mapping_reset(now=None) -> int:
    """请求清空内存映射（面板端点调用）。返回新的代号。"""
    now = time.time() if now is None else float(now)
    cur = 0
    try:
        cur = int(_read_signals(now).get("mapping_reset_gen") or 0)
    except Exception:
        cur = 0
    new = cur + 1
    try:
        _write_signals({"mapping_reset_gen": new, "mapping_reset_at": now}, now)
    except Exception as e:
        return -1
    return new


def effective_log_mode(now=None) -> str:
    """当前**生效**模式：排障窗口内恒为 trace，否则为配置基模式。

    降级方向是保守的：排障窗口只可能让记录**更多**（trace 仍不含明文原文、
    不含凭据），不会让 summary 变成 detailed —— 所以 summary 用户开排障
    也不会把正文原值落盘，只会拿到打码片段。
    """
    if log_trace_state(now)["active"]:
        return LOG_MODE_TRACE
    return LOG_MODE


# summary 允许落盘的字段（**白名单，fail-closed**）。
# 为什么是白名单而不是「正文黑名单」：黑名单漏一个字段就是一次原文落盘，
# 而漏判的代价是不可逆的。白名单的代价只是「将来新增的诊断字段在 summary 下
# 看不到」——用户想看就切 detailed/trace，方向安全。
# 收录口径：DB 结构化列 + 枚举/原因码 + 纯数字计数 + 耗时。
_SUMMARY_KEEP_FIELDS = frozenset({
    "verification",  # bounded marker digests only; omitted from diagnostic exports
    # 结构化列（列表筛选与排序依赖，与 events 表列同源）
    "ts", "type", "sid", "host", "method", "path", "count", "restored",
    "status", "restore_status", "http_status", "ingress",
    # 归因：谁、走哪条链路、什么协议形态
    "model", "upstream", "client_app", "stream_mode", "stream_actual", "body_shape",
    # 检测结论与原因码（§B 状态通道；枚举/数字，不含正文）
    "decision", "completeness", "reasons", "reason_codes", "blocked", "failed",
    "reason", "block_source", "ner_truncated", "ner_skip_reasons",
    "signed_blocks_skipped", "bytes", "error_code", "failure_phase",
    # 失败归因（批次 8 / P0-5）：责任方与异常类名。前者让用户一眼看出该查谁
    # （引擎/上游/客户端/DNS/出口代理），后者让同一类断开能聚合计数。
    # 两者都是短枚举字符串，不含正文。
    "failure_owner", "error_type",
    "upstream_may_have_executed", "engine_busy", "engine_queue_bytes", "engine_queue_depth",
    # 还原结果计数
    "restored_unique", "unresolved", "degraded", "success", "usage",
    # 耗时（毫秒）、前缀保真诊断、扫描范围计数
    "mask_ms", "upstream_ms", "first_byte_ms", "queue_wait_ms", "aux_wait_ms",
    "body_rewritten", "first_diff_byte", "suffix_reused", "short_hits", "scan_scope",
    # 语义识别/审计阶段计数
    "ner_init_ms", "ner_infer_ms", "ner_budget_wait_ms", "ner_calls", "ner_windows",
    "ner_cache_hits", "ner_cache_misses", "ner_global_throttled", "ner_sem_wait_ms",
    "audit_ms", "audit_scan_bytes", "audit_scan_truncated",
    "stream_degraded_reason", "resp_ts", "total_ms",
})
# 单字段最大保留长度（summary/trace 共用）。超长一律截断：即便某个新加的正文型
# 字段被误纳入白名单，也不会整段落盘。
_TEXT_FIELD_MAX = 160
# trace 模式下正文片段的上限（「受控脱敏片段」）。
_TRACE_TEXT_MAX = 1000


def _bounded_meta(raw, max_keys=24):
    """把「标签→计数」这类字典投影成有界标量字典：非数字/超长值一律丢弃。

    用在 summary。宁可少几个诊断计数，也不让将来新增的正文型字典字段整段落盘。
    """
    out = {}
    try:
        items = list(raw.items())[:max_keys]
    except Exception:
        return out
    for k, v in items:
        key = str(k)[:64]
        if isinstance(v, bool) or isinstance(v, (int, float)):
            out[key] = v
        elif isinstance(v, str):
            out[key] = v[:_TEXT_FIELD_MAX]
    return out


def _project_summary(rec):
    """最小记录投影：只放行白名单字段，items 只保留类别标签。"""
    out = {}
    for k, v in rec.items():
        if k not in _SUMMARY_KEEP_FIELDS:
            continue
        if v is None or isinstance(v, bool) or isinstance(v, (int, float)):
            out[k] = v
        elif isinstance(v, str):
            out[k] = v[:_TEXT_FIELD_MAX]
        elif isinstance(v, dict):
            out[k] = _bounded_meta(v)
        elif isinstance(v, (list, tuple)):
            out[k] = [x[:_TEXT_FIELD_MAX] if isinstance(x, str) else x
                      for x in list(v)[:32]]
    # 类别数量：只留 label，**不留 preview/digest/original**。
    # preview（如 `1**@***.com`）看着像脱敏，但它仍是可识别的部分信息，
    # 与「最小模式只留类别数量」的口径不符。
    items = rec.get("items")
    if isinstance(items, list):
        labels = [{"label": str(it.get("label") or "")}
                  for it in items if isinstance(it, dict)]
        if labels:
            out["items"] = labels
    return out


def _project_trace(rec):
    """限时排障投影：去掉全部 `items[].original` 明文，正文片段截断到上限。

    trace 的定位是「比 detailed 更克制的一次性排障」：保留结构的可读性
    （对话/预览片段，便于定位是脱敏没生效还是上游改写），但不保留**任何**
    精确原文——所以逐项剔除 `original`，只留 preview/digest/label。
    """
    out = dict(rec)
    items = out.get("items")
    if isinstance(items, list):
        out["items"] = [
            {k: v for k, v in it.items() if k != "original"} if isinstance(it, dict) else it
            for it in items
        ]
    for k in ("dialog", "dialog_req", "dialog_resp", "req_preview", "resp_preview",
              "prompt", "answer", "msg", "hint"):
        v = out.get(k)
        if isinstance(v, str) and len(v) > _TRACE_TEXT_MAX:
            out[k] = v[:_TRACE_TEXT_MAX] + "…(已截断)"
    return out


def project_event_for_log(rec):
    """按当前生效模式投影一条事件（DB 与 stdout 两个出口共用同一函数）。

    为什么要给 stdout 也用：引擎的 `SHIELD\t...` 行会被桌面壳原样追加进
    `engine-stdout.log`，那是磁盘上的第二份正文副本。只在 DB 侧裁剪的话，
    最小模式下明文照样躺在日志文件里（§D1 明确把 stdout 列为必须覆盖的出口）。
    """
    rec = onboarding.scrub(rec)
    mode = effective_log_mode()
    if mode == LOG_MODE_SUMMARY:
        return _project_summary(rec)
    if mode == LOG_MODE_TRACE:
        return _project_trace(rec)
    return rec


def _update_stats(conn, rec, replay=False):
    """增量维护日统计摘要（与 events 同事务提交，失败静默——事件照常落库）。

    `replay=True` 表示这次调用是**重放已入过库的事件**（目前只有
    `_migrate_daily_stats` 会传）。重放不能喂给「只进不退」的计数器：
    daily_prefix 就是这样一个计数器，回填条件 `ts < daily_stats_created`
    会把 ts 早于建表时刻的事件再算一遍（实测：today_stats 触发一次回填，
    昨天那行 masks 从 1 变 2）。daily_stats 有同样的隐患但属历史既有行为，
    不在本次范围内 —— 本函数只保证 daily_prefix 不被重放污染。

    口径与旧实现完全一致（审计 DATA-001）：
    - daily_stats：所有事件类型计数（MASK/RESTORE/PASS/BLOCK/...）；
    - daily_status：只收 RESTORE 事件的状态分布；
    - daily_words：只收 MASK 事件 items（旧 today_stats 只扫 MASK payload，
      若 RESTORE 也收会把同一脱敏项记两次——实测 MASK+RESTORE 计为 PHONE=2）。
    - daily_prefix：只收 MASK 事件的前缀诊断字段（同前一条理由：RESTORE 不带
      body_rewritten/first_diff_byte，收进来只会把分母撑大）。
    """
    try:
        ts = float(rec.get("ts") or time.time())
        day = time.strftime("%Y-%m-%d", time.localtime(ts))
        typ = str(rec.get("type") or "")
        if not typ:
            return
        # 入口维度：写侧按 rec 取，缺省 'proxy'。**归一化不依赖写入路径**——
        # _migrate_daily_stats 会用 payload 反查重放（老 payload 没有 ingress 键），
        # 在这里兜一次底，重放回填出来的历史行也就自动标成 'proxy'（正确）。
        ingress = str(rec.get("ingress") or "proxy")
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
        # 词级明细随写入模式收敛（§D1）：最小模式只保留**类别计数**（词位固定 "?"，
        # 排行榜的 label 分布照常），trace/detailed 才保留词级明细；明文词只在
        # detailed + 用户显式开启时落盘。凭据类任何模式都只走 preview。
        mode = effective_log_mode()
        keep_plain = RECORD_PLAINTEXT_WORDS and mode == LOG_MODE_DETAILED
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
            # 凭据类 items 强制绝不落原文（防 legacy 数据重放/历史残留）：恒只走 preview。
            is_cred = bool(it.get("cred")) or lbl in CREDENTIAL_LABELS
            if mode == LOG_MODE_SUMMARY:
                word = "?"
            elif keep_plain and not is_cred:
                word = str(it.get("original") or it.get("preview") or "")
            else:
                word = str(it.get("preview") or "")
            if not word:
                word = "?"
            conn.execute(
                "INSERT INTO daily_words(day, label, word, cnt, ingress) VALUES(?,?,?,1,?) "
                "ON CONFLICT(day,label,word,ingress) DO UPDATE SET cnt=cnt+1",
                (day, lbl, word, ingress),
            )
        # 前缀保真度：MASK 事件的三个诊断字段聚合（口径见 daily_prefix 建表注释）。
        # 两个前置条件缺一不可：
        #   · 事件自己带 body_rewritten —— 老代码写的 MASK 事件没有这个键，
        #     导入它们（import_legacy_jsonl_once 导 legacy jsonl）会把 masks 撑大
        #     却把 rewritten 记 0，凭空拉低零改写率；
        #   · 不是重放 —— 重放的事件早已计入过一次，再写就是翻倍。
        # first_diff_byte 为 -1 表示超上限没算（transparent._FIRST_DIFF_MAX），
        # 只跳过均值、不影响分母。
        if "body_rewritten" in rec and not replay:
            rewritten = 1 if rec.get("body_rewritten") else 0
            reused = 1 if rec.get("suffix_reused") else 0
            diff = _int_or_none(rec.get("first_diff_byte"))
            has_diff = diff is not None and diff >= 0
            conn.execute(
                "INSERT INTO daily_prefix(day, masks, rewritten, reused, diff_sum, diff_n) "
                "VALUES(?,1,?,?,?,?) "
                "ON CONFLICT(day) DO UPDATE SET "
                "masks=masks+1, rewritten=rewritten+excluded.rewritten, "
                "reused=reused+excluded.reused, "
                "diff_sum=diff_sum+excluded.diff_sum, diff_n=diff_n+excluded.diff_n",
                (day, rewritten, reused, diff if has_diff else 0, 1 if has_diff else 0),
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
        # 入口维度重建（浏览器扩展链路）：daily_words 主键原本是 (day,label,word)。
        # 同一明文经两条链路都会命中，`ON CONFLICT` 会把两行**合并成一行**，ingress
        # 写谁都错——那等于买了一个会撒谎的维度。SQLite 改不了主键，只能重建表：
        # 建新表 → `INSERT … SELECT … 'proxy'` 迁移（历史行标 'proxy' 是对的：当时
        # 还没有扩展链路）→ drop 旧表 → rename。
        # 幂等判据用**结构**（daily_words 有没有 ingress 列），不靠 meta 标记：
        # 标记只作留痕/可观测。绝不复用 `daily_words_pii_purged`——那属另一次语义，
        # 混用会让那次 PII 清洗被跳过。
        # 与既有清理的交互：保留期裁剪（DELETE … WHERE day <= ?）与 clear_events 的
        # 清空分支都只按 day / 全表操作，重建后语义不变。
        dw_cols = [r[1] for r in conn.execute("PRAGMA table_info(daily_words)").fetchall()]
        if dw_cols and "ingress" not in dw_cols:
            conn.execute("ALTER TABLE daily_words RENAME TO daily_words_pre_ingress")
            conn.execute(
                """
                CREATE TABLE daily_words (
                    day TEXT NOT NULL,
                    label TEXT NOT NULL,
                    word TEXT NOT NULL,
                    cnt INTEGER DEFAULT 0,
                    ingress TEXT NOT NULL DEFAULT 'proxy',
                    PRIMARY KEY (day, label, word, ingress)
                )
                """
            )
            conn.execute(
                "INSERT INTO daily_words(day, label, word, cnt, ingress) "
                "SELECT day, label, word, cnt, 'proxy' FROM daily_words_pre_ingress"
            )
            conn.execute("DROP TABLE daily_words_pre_ingress")
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('daily_words_ingress_migrated', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(time.time()),),
            )
        conn.commit()


# 是否发生过"损坏→隔离重建"（一键自检 S33 读它）。
# 用进程内标志而不是 meta 表：重建后的新库不该背着旧库的历史，而"本次启动
# 是否发生过隔离"恰好是用户排查时要的那个事实。
_LAST_QUARANTINE = None


def _quarantine_corrupt_db(reason):
    """把损坏的事件库挪到一边，返回新路径（失败返回 ""）。调用方随后重建空库。

    只处理**真正的损坏**（`sqlite3.DatabaseError` 且非 `OperationalError`——后者是
    锁竞争 / 路径不可写，重试或改权限即可，挪文件只会白丢数据）。

    旧文件一律保留为 `<name>.corrupt-<时间戳>`，绝不删除：事件库是本地唯一副本，
    宁可占盘也不能替用户做「删掉」的决定。用户还能拿它去 sqlite3 里抢救数据。
    """
    global _LAST_QUARANTINE
    try:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = DB_PATH.with_name(f"{DB_PATH.name}.corrupt-{stamp}")
        for suffix in ("", "-wal", "-shm"):
            src = DB_PATH.with_name(DB_PATH.name + suffix)
            if not src.exists():
                continue
            dst = base if not suffix else base.with_name(base.name + suffix)
            src.replace(dst)
        _LAST_QUARANTINE = {"at": time.time(), "reason": str(reason)[:200], "path": str(base)}
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


def _normalize_ingress(rec):
    """入口维度归一化：`proxy`=CLI 代理链路（含老数据 / legacy 导入），`ext`=浏览器扩展链路。

    事件写入有**两条** INSERT（`append_event` 的同步路径、`_append_many` 的写线程批量
    路径），两条都在 `_enrich_source` 之后调本函数——这是天然的**唯一汇合点**，
    归一化只做一次，保证老数据、legacy 导入、代理链路**不写也有值**，
    读取侧不会冒出 NULL 分组。

    单独成函数而不是塞进 `_enrich_source`：后者的语义是「按客户端端口反查进程写入
    client_app」，与入口维度正交（SPEC §5.2(2) 的命名理由）。
    也**不要**把这个字段叫 `source`：本仓库里 `source` 已被占用为「客户端 peer 信息」
    （transparent.py 的 `_client_source` → `{client, client_host, client_port}`，
    会被 `_emit_skip` 的 `**src` 摊平进 payload），再引入一个 source 必然出事。
    """
    if not rec.get("ingress"):
        rec["ingress"] = "proxy"
        return rec
    # **白名单归一化（不是"有值就原样存"）**：读取侧的入口过滤是
    # `COALESCE(ingress,'proxy') = ?` 的**精确等值**匹配，所以任何非 `proxy`/`ext`
    # 的值（大小写不一致、`"EXTING"` 之类的笔误、上游塞进来的脏值）都会落进一个
    # **永远筛不出来、也永远不出现在任何分组里**的隐形分组——比报错更难查。
    # 写入是唯一汇合点，所以在这里一次性收口：不认识的值一律按 `proxy` 记
    # （默认/多数路径），并 `lower()` 容错大小写。
    value = str(rec.get("ingress")).strip().lower()
    rec["ingress"] = value if value in INGRESS_VALUES else "proxy"
    return rec


def append_event(record):
    _ensure_db()
    rec = _normalize_ingress(_enrich_source(onboarding.scrub(record)))
    rec.setdefault("ts", time.time())
    # 统计永远用**完整** rec（口径不变：请求数/告警数/费用不受记录模式影响），
    # 只有落库的 payload 按写入模式投影。反过来的话，「最小模式」会把统计一起改小，
    # 用户看到的是「脱敏次数掉了一半」，而实际只是不记正文了。
    payload = json.dumps(project_event_for_log(rec), ensure_ascii=False)
    with closing(_connect()) as conn:
        cur = conn.execute(
            """
            INSERT INTO events
            (ts, type, sid, host, method, path, count, restored, status, http_status, ingress, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                str(rec.get("ingress") or "proxy"),
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
                (ts, sid, host, method, path, signal_type, severity, evidence, request_hash, response_hash, probe_id,
                 audit_ms, audit_scan_bytes, audit_scan_truncated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    # bool 要转 0/1：sqlite3 不接受 bool（会报 InterfaceError）
                    (lambda v: None if v is None else float(v))(rec.get("audit_ms")),
                    (lambda v: None if v is None else int(v))(rec.get("audit_scan_bytes")),
                    (lambda v: None if v is None else int(bool(v)))(rec.get("audit_scan_truncated")),
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
    # 凭据回流的历史噪音（W1-2，2026-09-22 审批）：W1-1 上线前，credential_echo 一律
    # MEDIUM 且无形态标记，把「AI 在代码块里写 .env / CI 密钥示例」报成「响应投毒」。
    # 谓词命中整类 `credential_echo:<kind>` 证据，只隐藏**旧的无标记存量**：
    # W1-1 之外的两种新记录都带标记（`[示例形态]` / `[疑似真实凭据]`），
    # 由下面 `_audit_visibility_filter` 的 NOT LIKE 保护子句守死。
    #
    # ⚠️ 前缀必须与 **evidence 列的真实形态**一致：落库的是
    # `<kind> len=<n> sha256=<摘要>`（`audit_signals._redact_evidence` 的产物）。
    # `credential_echo:` 只出现在扫描结果 dict 的 `kind` 字段上，而 `audit_events`
    # 表**没有 kind 列**（见本模块建表语句）——按它写前缀会恒不匹配、降噪静默空转，
    # 用户视角是「升级了，但历史噪音一条都没少」。
    # 由 `tests/test_audit.py::CredentialEchoReadSideFilterTests` 拿引擎真实产出守死。
    *(("response_poison", f"{kind} len=%") for kind in CREDENTIAL_ECHO_KINDS),
)

# 读侧降噪的**保护标记**：带任一标记的证据都是本版规则主动产出的、档位正确的新记录，
# 任何已撤销判定谓词都不允许隐藏它。两个标记各有分工：
#   · CREDENTIAL_ECHO_REAL_MARKER —— 非代码块 + 高熵的**真阳性**（隐藏它是安全事故）；
#   · CREDENTIAL_ECHO_SAMPLE_MARKER —— 代码块内/低熵的**示例形态**（LOW）。它虽属噪音类，
#     但隐藏它就违背了分档设计自己的承诺「门槛调到 LOW 仍可查，不丢可查性」
#     （见 audit_signals.scan_response_poison 的分档注释）——用户主动调低门槛后
#     一条都看不到，是静默失效。降噪对象应该是**旧的无标记存量**，不是新写的正确记录。
# 谓词全部是 LIKE 前缀匹配，无法表达「以某某结尾」，所以保护必须在 SQL 里
# 显式写出（而不是靠证据形态碰巧不匹配）。
_AUDIT_NEVER_HIDE_MARKERS = (CREDENTIAL_ECHO_REAL_MARKER, CREDENTIAL_ECHO_SAMPLE_MARKER)


def _audit_visibility_filter():
    """返回审计历史读侧过滤 SQL 子句与参数（不删除数据库记录）。"""
    clauses, params = [], []
    marker_like = [f"%{m}%" for m in _AUDIT_NEVER_HIDE_MARKERS]
    for signal_type, evidence_pattern in _DEPRECATED_AUDIT_EVIDENCE_PREFIXES:
        clause = "NOT (signal_type = ? AND COALESCE(evidence, '') LIKE ?"
        args = [signal_type, evidence_pattern]
        for like in marker_like:
            clause += " AND COALESCE(evidence, '') NOT LIKE ?"
            args.append(like)
        clause += ")"
        clauses.append(clause)
        params.extend(args)
    return clauses, params


def fetch_audit_events(since=0, limit=500, severity_floor=None, signal_filter=None,
                       include_deprecated=False):
    """读取审计事件。since=id（返回 id>since 的）。severity_floor=LOW/MEDIUM/HIGH/CRITICAL。

    include_deprecated=False（默认）按 `_audit_visibility_filter` 隐藏已撤销的判定，
    这只适用于**给人看的列表**。安全检测的读路径（audit_engine 的探针结果聚合）
    必须传 True：过滤加在检测路径上等于「某个信号被降噪隐藏后，风险矩阵永远看不到
    它」，而矩阵仍会渲染成绿色——这是个假阴性。
    """
    _ensure_db()
    since = int(since or 0)
    limit = max(1, min(int(limit or 500), 1000))
    where = ["id > ?"]
    params = [since]
    if not include_deprecated:
        visibility_clauses, visibility_params = _audit_visibility_filter()
        where.extend(visibility_clauses)
        params.extend(visibility_params)
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
        "request_hash, response_hash, probe_id, audit_ms, audit_scan_bytes, "
        "audit_scan_truncated FROM audit_events WHERE "
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
            # A-1：审计成本与截断（老行为 NULL → 前端按"无此信息"处理，不假装是 0）
            "audit_ms": r["audit_ms"],
            "audit_scan_bytes": r["audit_scan_bytes"],
            "audit_scan_truncated": (None if r["audit_scan_truncated"] is None
                                     else bool(r["audit_scan_truncated"])),
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
            rec = _normalize_ingress(_enrich_source(onboarding.scrub(rec)))
            rec.setdefault("ts", time.time())
            # 与 append_event 同口径：统计用完整 rec，落库 payload 按模式投影。
            payload = json.dumps(project_event_for_log(rec), ensure_ascii=False)
            conn.execute(
                """
                INSERT INTO events
                (ts, type, sid, host, method, path, count, restored, status, http_status, ingress, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    str(rec.get("ingress") or "proxy"),
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


def db_max_event_id():
    """当前库最大事件 id（清空/隔离重建后归 0）。供 /api/logs 的游标重置检测。"""
    _ensure_db()
    with closing(_connect()) as conn:
        row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
    try:
        return int(row[0] or 0)
    except Exception:
        return 0


def _sync_clear_cutoff_from_db():
    """从 meta 表对齐清空 cutoff（跨进程：面板进程清空时写入，引擎写线程消费）。

    只升不降：本进程内存值更新（如自己也刚清空过）不受影响。读失败静默——
    对齐不到最多退化回单进程防护，不能让清空竞态修复反过来打断写线程。
    """
    global _clear_cutoff
    try:
        with closing(_connect()) as conn:
            row = conn.execute("SELECT value FROM meta WHERE key='clear_cutoff'").fetchone()
        if row:
            stored = float(row[0] or 0)
            if stored > _clear_cutoff:
                _clear_cutoff = stored
    except Exception:
        pass


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
            # 清空 cutoff：面板进程与本进程（mitmdump 引擎）各自有内存值，面板
            # 清空时把 cutoff 落进 meta，这里每批对齐一次——否则引擎队列里积压
            # 的旧事件会在清空完成后"复活"（跨进程竞态，审计 P2）。
            _sync_clear_cutoff_from_db()
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


def fetch_sibling_event(sid, exclude_id=None):
    """根据 sid 取同一会话下的配对事件（例如 RESTORE 查同 sid 的 MASK，或 MASK 查 RESTORE）。"""
    if not sid or not isinstance(sid, str):
        return None
    _ensure_db()
    with closing(_connect()) as conn:
        conn.row_factory = sqlite3.Row
        sql = "SELECT id, payload FROM events WHERE sid = ?"
        params = [sid]
        if exclude_id is not None:
            try:
                params.append(int(exclude_id))
                sql += " AND id != ?"
            except (ValueError, TypeError):
                pass
        sql += " ORDER BY id DESC LIMIT 1"
        row = conn.execute(sql, params).fetchone()
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


def _event_filters(since=None, before_seq=None, before_ts=None, sensitive_only=False,
                   query="", fulltext=False, event_type=None, ingress=None):
    """构造事件列表的 WHERE 子句与参数（向前/向后游标、导出、计数共用一份）。

    共用是必须的：正向「拉新」与反向「看更早」如果各写一套筛选，同一个筛选条件下
    的两页会给出不同口径的行（漏筛/漏重），用户看到的是「翻页后条数对不上」。
    `since` 与 `before_seq` 为 None 表示不加该侧游标；两者可同时给（取交集）。
    """
    where = []
    params = []
    if since is not None:
        where.append("id > ?")
        params.append(int(since or 0))
    if before_seq is not None:
        where.append("id < ?")
        params.append(int(before_seq or 0))
    if before_ts is not None:
        where.append("ts < ?")
        params.append(float(before_ts))
    if event_type:
        where.append("type = ?")
        params.append(str(event_type).strip().upper())
    elif sensitive_only:
        # 「隐藏透传」：隐藏 PASS/SKIP（过网关但未脱敏的只读/非LLM）
        # MASK/RESTORE/BLOCK/BYPASS 即使 count=0 也显示
        where.append("type NOT IN ('SKIP', 'PASS')")
    ing = str(ingress or "").strip().lower()
    if ing in INGRESS_VALUES:
        # COALESCE：老数据/legacy 导入的 ingress 为 NULL，按 'proxy' 解读。
        # 没有 ingress 索引，但它总是与 id 游标条件同用，扫描面已被游标限住。
        where.append("COALESCE(ingress, 'proxy') = ?")
        params.append(ing)
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
    return where, params


def fetch_events(since=0, limit=500, sensitive_only=False, query="", fulltext=False,
                 event_type=None, max_limit=1000, ascending=False, ingress=None):
    """读取事件列表。

    since=id（返回 id>since 的，供增量轮询）；limit 约束返回条数；
    ascending=True 按游标之后最早的记录分页，避免增量积压时跳过中间记录。
    默认仍取最新记录，保持首次加载、导出和历史调用的语义。
    sensitive_only 隐藏 PASS/SKIP；query 搜索主机/路径/方法/状态/类型等结构化列。
    event_type 按事件类型精确过滤（下推到 SQL，命中 idx_events_type_id：
        本查询按 id 游标分页 + ORDER BY id，`(type, id)` 才是匹配的复合索引）。
        它与 sensitive_only 互斥且优先级更高：显式指定类型时以类型为准，否则
        「只看 SKIP」这类查询会被 sensitive_only 的 NOT IN ('SKIP','PASS') 判成空集。
    ingress 按入口维度过滤（'proxy' / 'ext'，见 _normalize_ingress）。**老数据该列为
        NULL 时按 'proxy' 解读**，否则升级后「只看代理链路」会漏掉升级前的全部历史。
        过滤值非法（None/空/其它）时不过滤，保持旧调用方语义不变。
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
    where, params = _event_filters(
        since=since, sensitive_only=sensitive_only, query=query, fulltext=fulltext,
        event_type=event_type, ingress=ingress)
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


def fetch_events_before(before_seq=None, limit=500, sensitive_only=False, query="",
                        fulltext=False, event_type=None, max_limit=1000, ingress=None,
                        before_ts=None):
    """反向游标：取 `id < before_seq` 的一页历史事件（页内按 id 升序返回）。

    与 `fetch_events` 的 `since` 互补：`since` 只能向前增量轮询（看「打开页面之后」
    的新事件），历史一旦超过首屏上限就再翻不回来（实测超过列表上限后「加载更多」
    失效，用户只能看到最近一批）。`before_ts` 是可选时间上界（id 与 ts 同序，
    供按时间区间回看）。筛选条件与向前翻**同源**（`_event_filters`）。

    返回 `(events, has_more)`：has_more=True 表示更早处还有符合筛选的行。
    """
    _ensure_db()
    limit = max(1, min(int(limit or 500), int(max_limit or 1000)))
    where, params = _event_filters(
        before_seq=int(before_seq or 0) if before_seq else None,
        before_ts=before_ts, sensitive_only=sensitive_only, query=query,
        fulltext=fulltext, event_type=event_type, ingress=ingress)
    sql = ("SELECT id, payload FROM events WHERE " + " AND ".join(where)
           + " ORDER BY id DESC LIMIT ?")
    params.append(limit + 1)
    with closing(_connect()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    return [_row_to_event(row) for row in reversed(rows)], has_more


def count_events(sensitive_only=False, query="", fulltext=False, event_type=None, ingress=None):
    """当前筛选下的匹配行数（导出的截断提示用：只返回数字，不读 payload）。"""
    _ensure_db()
    where, params = _event_filters(sensitive_only=sensitive_only, query=query,
                                   fulltext=fulltext, event_type=event_type, ingress=ingress)
    sql = "SELECT COUNT(*) FROM events" + ((" WHERE " + " AND ".join(where)) if where else "")
    with closing(_connect()) as conn:
        return int(conn.execute(sql, params).fetchone()[0] or 0)


def clear_stats():
    """清空**数字统计摘要**（daily_stats/status/tokens/prefix/models）。

    与 `clear_events()` 是两个独立动作（§D3.3）：清日志不动统计，清统计不动日志。
    合并成一个「彻底清除」按钮会让只想清对话日志的用户把几个月的趋势图一起抹掉。
    本函数不删 `events`，也不删 `daily_words`（后者属日志明细，随 `clear_events` 走）。
    """
    _ensure_db()
    with closing(_connect()) as conn:
        for table in ("daily_stats", "daily_status", "daily_tokens", "daily_prefix", "daily_models"):
            try:
                conn.execute(f"DELETE FROM {table}")
            except Exception:
                pass  # 老库可能缺某张摘要表：少清一张不影响其余口径
        # 摘要表清空后**保留** daily_stats_migrated 标记：它的作用是防重复回填，
        # 不是“允许重新回填”。删掉它会让下一次 today_stats() 触发
        # `_migrate_daily_stats` 把 ts < daily_stats_created 的历史事件再灌回一遍，
        # 用户会看到“刚清完统计又冒出数字”（历史导入过的库尤其明显）。
        conn.commit()
    return {"ok": True}


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
        #   daily_stats / daily_status / daily_tokens / daily_prefix：纯数字计数，
        #   永久保留，不随保留期裁剪。
        #   daily_words：存 PII 打码 preview，随保留期裁剪（与事件明细一致，防词级 PII 超期留存）。
        # 曾统一按 day_cutoff 裁剪四张表 → 7 天后统计卡/图表全部归零，用户以为数据丢了。
        day_cutoff = time.strftime("%Y-%m-%d", time.localtime(cutoff))
        # conn.execute("DELETE FROM daily_stats WHERE day <= ?", (day_cutoff,))
        # conn.execute("DELETE FROM daily_status WHERE day <= ?", (day_cutoff,))
        conn.execute("DELETE FROM daily_words WHERE day <= ?", (day_cutoff,))
        # conn.execute("DELETE FROM daily_tokens WHERE day <= ?", (day_cutoff,))
        conn.commit()
        return {"ok": True, "removed": removed}


# ── 死空间回收 ───────────────────────────────────────────────────────────────
# 保留策略每天 DELETE 明细，但 SQLite 只是把这些页放进 freelist，**文件永不缩小**：
# 实测线上库 249MB 里有 84MB 是这种"已删除但仍占盘"的死空间（33%），而此前全仓
# 没有任何一处执行 VACUUM。
#
# 阈值刻意不低：VACUUM 会重写整个文件（临时占用约等于库大小），不能每次
# prune 都做。只在这两件事同时成立时压一次。
_RECLAIM_MIN_FREE_BYTES = 32 * 1024 * 1024
_RECLAIM_MIN_FREE_RATIO = 0.25


def db_stats(conn=None):
    """事件库体积快照：文件大小 / 死空间 / 明细行数（面板与自检用，不含任何原文）。"""
    try:
        _ensure_db()
        own = conn is None
        conn = conn if conn is not None else _connect()
        try:
            page_count = int(conn.execute("PRAGMA page_count").fetchone()[0] or 0)
            page_size = int(conn.execute("PRAGMA page_size").fetchone()[0] or 0)
            free_pages = int(conn.execute("PRAGMA freelist_count").fetchone()[0] or 0)
            rows = int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] or 0)
        finally:
            if own:
                conn.close()
        size = page_count * page_size
        free = free_pages * page_size
        return {"ok": True, "bytes": size, "free_bytes": free, "rows": rows,
                "free_ratio": (float(free) / size) if size else 0.0}
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}


def reclaim_space(min_free_bytes=_RECLAIM_MIN_FREE_BYTES,
                  min_free_ratio=_RECLAIM_MIN_FREE_RATIO):
    """prune 之后按需回收死空间（VACUUM）。返回是否真的压缩以及前后体积。

    ⚠️ 引擎（mitmdump）与面板是两个连接，VACUUM 要独占写锁：`_connect` 已设
    `busy_timeout=5000`，引擎正在写事件时会等一会儿；仍拿不到锁就**放弃本次**
    （返回 ok=False），留给下一轮保留策略 —— 为了清理空间让写入长时间阻塞不划算。
    """
    before = db_stats()
    if not before.get("ok"):
        return {"ok": False, "vacuumed": False,
                "error": before.get("error") or "db_stats failed"}
    if (int(before.get("free_bytes") or 0) < int(min_free_bytes)
            or float(before.get("free_ratio") or 0.0) < float(min_free_ratio)):
        return {"ok": True, "vacuumed": False, "bytes": before.get("bytes"),
                "free_bytes": before.get("free_bytes"), "rows": before.get("rows")}
    try:
        _ensure_db()
        with closing(_connect()) as conn:
            conn.execute("VACUUM")
            try:
                # WAL 文件同样只会涨：重写完成后把日志截断回 0，否则 -wal 会一直留着。
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
    except Exception as e:
        return {"ok": False, "vacuumed": False, "bytes": before.get("bytes"),
                "free_bytes": before.get("free_bytes"),
                "error": "%s: %s" % (type(e).__name__, e)}
    after = db_stats()
    saved = max(0, int(before.get("bytes") or 0) - int(after.get("bytes") or 0))
    return {"ok": True, "vacuumed": True, "bytes": after.get("bytes"),
            "free_bytes": after.get("free_bytes"), "rows": after.get("rows"),
            "reclaimed_bytes": saved}


def clear_events():
    """清空事件库（含清空竞态防护，审计 P1-5 / SHIELD-CLEAR-001）。

    1) 置 cutoff（cutoff 前入队的事件由写线程丢弃）；2) 排空当前未写队列；
    3) 同一事务删除 `events` + `daily_words`——**数字摘要表一律保留**
    （用户明确要求「清日志不清统计」）。判据是含不含 PII：daily_words 存词级
    打码 preview 属于日志明细，daily_stats/daily_status/daily_tokens/daily_prefix
    是纯数字计数，清掉等于把用户几个月的趋势图归零，而他只是想清日志；
    4) 按 cutoff 补删一次兜住写线程正在写旧事件的窗口。清空之后的新事件正常写入。
    5) cutoff 落 meta 表：事件写方是另一个进程（mitmdump 引擎，有自己的内存
    cutoff=0），不落库的话引擎队列里积压的旧事件会在清空完成后"复活"
    （跨进程竞态，审计 P2）；写线程每批从 meta 对齐一次（_sync_clear_cutoff_from_db）。

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
        #   daily_prefix   前缀保真度计数（纯数字，无 PII）
        # 仅删 daily_words：它存 PII 打码 preview（曾存原文，已迁移为 preview），
        # 清日志时一并清掉词级明细，与「清空日志=真删除」语义一致。
        # conn.execute("DELETE FROM daily_stats")
        # conn.execute("DELETE FROM daily_status")
        conn.execute("DELETE FROM daily_words")
        # conn.execute("DELETE FROM daily_tokens")  # 不删
        conn.execute("DELETE FROM sqlite_sequence WHERE name='events'")
        # 摘要表清空后迁移标记失效：后续事件重新增量累积
        conn.execute("DELETE FROM meta WHERE key='daily_stats_migrated'")
        # cutoff 落库：引擎进程（另一进程）的写线程据此丢弃清空前的积压事件
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('clear_cutoff', ?)",
            (_clear_cutoff,),
        )
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


def _prefix_payload(masks, rewritten, reused, diff_sum, diff_n):
    """前缀保真度摘要（MASK 事件三个诊断字段的聚合，仪表盘「前缀保真度」卡数据源）。

    返回 None 表示本区间没有任何 MASK 事件——老库刚升级、或用户还没跑过脱敏请求
    时就是这个状态。**不返回全 0 的字典**：一排 0 会被读成「一次都没零改写」，
    而真相是「还没有样本」，两者对用户的意义完全相反。

    clean_rate：`body_rewritten=false` 的占比，即请求体一个字节都没被改动的比例。
    这正是上游 Prompt Cache 能命中的前提，也是这张卡的主指标。
    reuse_rate：在**改写过的请求**里，沿用了复用表旧 token 的比例（全为新签 → 上游
    前缀必然从这个位置起失效）。分母是 rewritten 不是 masks：零改写透传的请求一个
    敏感词都没命中，压根没签发占位符，算进分母只会把指标稀释（实测：100 次请求
    10 次有命中、8 次复用，用 masks 当分母显示 8%，真实是 80%）。
    rewritten=0 时为 None —— 一个占位符都没签发，比率无从谈起，前端显示「—」。
    avg_first_diff：回写后与客户端原始字节首个差异位置的平均值，越小说明前缀被
    改动得越靠前、越伤缓存；样本全被上限挡掉（first_diff_byte=-1）时为 None，
    此时 diff_samples 为 0（前端把它和 masks 一起显示，避免「均值看着很好、
    其实只有一个样本」）。
    """
    masks = int(masks or 0)
    if masks <= 0:
        return None
    rewritten = max(0, min(int(rewritten or 0), masks))
    reused = max(0, int(reused or 0))
    n = int(diff_n or 0)
    return {
        "masks": masks,
        "rewritten": rewritten,
        "clean": masks - rewritten,
        "clean_rate": round((masks - rewritten) / masks, 4),
        "suffix_reused": reused,
        # 分母用 rewritten：没签发票据的请求不可能「复用」，算进来只会稀释。
        # reused ≤ rewritten 恒成立（复用发生在 _remember 里，而它只在有命中时调用）。
        "reuse_rate": round(reused / rewritten, 4) if rewritten > 0 else None,
        "avg_first_diff": round(int(diff_sum or 0) / n, 1) if n > 0 else None,
        "diff_samples": n,
    }


def _pack_word_counter(counter):
    """把 {(label,word): cnt} 打包成 (by_label, by_label_words, top_words)。"""
    by_label = {}
    by_label_words = {}
    for (lbl, w), c in counter.items():
        by_label[lbl] = by_label.get(lbl, 0) + c
        by_label_words.setdefault(lbl, []).append({"word": w, "count": c})
    for lst in by_label_words.values():
        lst.sort(key=lambda x: -x["count"])
    top = sorted(
        ({"label": lbl, "word": w, "count": c} for (lbl, w), c in counter.items()),
        key=lambda x: -x["count"],
    )[:20]
    return by_label, by_label_words, top


def _word_groups(rows):
    """把 daily_words 行（label, word, cnt, ingress）拆成「全量 + 按入口分组」两套视图。

    **分组同屏而不是过滤**（SPEC §5.2(3)、v2.5 拍板）：污染的根因是**量级不对称**
    （浏览器里发的请求体 ≫ CLI 流量），不是「混在一起」这个动作本身。
    各组各取 Top N，代理组的业务词（公司名/客户名/密钥）就不会被浏览器流量里的
    邮箱/电话刷榜挤下去，同时两组都可见——默认只显示代理等于「我拦了但不告诉你拦了什么」。

    返回 (by_label, by_label_words, top_words, by_ingress)：
    前三个是**全量**视图（保持既有调用方语义不变），by_ingress 形如
    {"proxy": {"by_label":…, "by_label_words":…, "top_words":…, "label_total":N}, "ext": …}。
    ingress 为空的旧行按 'proxy' 解读，不产生 NULL 分组。
    """
    buckets = {}
    for row in rows:
        lbl = str(row[0] or "其他")
        w = str(row[1] or "?")
        c = int(row[2] or 0)
        ing = str(row[3] or "proxy") or "proxy"
        counter = buckets.setdefault(ing, {})
        counter[(lbl, w)] = counter.get((lbl, w), 0) + c

    by_ingress = {}
    for ing, counter in buckets.items():
        bl, blw, top = _pack_word_counter(counter)
        by_ingress[ing] = {
            "by_label": bl,
            "by_label_words": blw,
            "top_words": top,
            "label_total": sum(bl.values()),
        }

    total_counter = {}
    for counter in buckets.values():
        for key, c in counter.items():
            total_counter[key] = total_counter.get(key, 0) + c
    by_label, by_label_words, top_list = _pack_word_counter(total_counter)
    return by_label, by_label_words, top_list, by_ingress


def _audit_high_count(since_ts):
    """区间内 HIGH/CRITICAL 审计信号条数（首页/统计页「告警」口径的一部分）。

    换芯、投毒、凭据外发这类发现原本只落在审计页：用户不主动翻页就永远发现不了，
    等于白检测（2026-09-19）。这里与列表读侧用同一套降噪过滤，保证「计数里算进去的，
    点开审计页一定看得到」——只计数不展示会让人找不到来源。
    """
    try:
        _ensure_db()
        clauses, params = _audit_visibility_filter()
        where = " AND ".join(["ts >= ?", "severity IN ('HIGH', 'CRITICAL')", *clauses])
        with closing(_connect()) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE " + where,
                (float(since_ts), *params),
            ).fetchone()
        return int((row or [0])[0] or 0)
    except Exception:
        return 0


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
            "SELECT label, word, cnt, ingress FROM daily_words WHERE day=?", (day,)
        ).fetchall()
        token_row = conn.execute(
            "SELECT prompt, completion FROM daily_tokens WHERE day=?", (day,)
        ).fetchone()
        prefix_row = conn.execute(
            "SELECT masks, rewritten, reused, diff_sum, diff_n FROM daily_prefix WHERE day=?",
            (day,),
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
    # 审计高危并入告警口径（口径与审计页一致，见 _audit_high_count）
    audit_high = _audit_high_count(day_start)
    alerts += audit_high
    restore_by_status = dict(status_map)
    by_label, by_label_words, top_list, words_by_ingress = _word_groups(word_rows)
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
        "audit_high": audit_high,
        "tokens": tokens,
        "prefix": _prefix_payload(*(prefix_row or (0, 0, 0, 0, 0))),
        "by_type": by_type,
        "restore_by_status": restore_by_status,
        "by_label": by_label,
        "by_label_words": by_label_words,
        "top_words": top_list,
        "words_by_ingress": words_by_ingress,
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
            f"SELECT label, word, SUM(cnt), ingress FROM daily_words WHERE day IN ({placeholders}) "
            f"GROUP BY label, word, ingress",
            days_list,
        ).fetchall()
        token_row = conn.execute(
            f"SELECT SUM(prompt), SUM(completion) FROM daily_tokens WHERE day IN ({placeholders})",
            days_list,
        ).fetchone()
        prefix_row = conn.execute(
            f"SELECT SUM(masks), SUM(rewritten), SUM(reused), SUM(diff_sum), SUM(diff_n) "
            f"FROM daily_prefix WHERE day IN ({placeholders})",
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
    # 审计高危并入告警口径（口径与审计页一致，见 _audit_high_count）
    audit_high = _audit_high_count(now - days * 86400)
    alerts += audit_high
    restore_by_status = dict(status_map)
    by_label, by_label_words, top_list, words_by_ingress = _word_groups(word_rows)
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
        "audit_high": audit_high,
        "blocked": _ev("BLOCK"),
        "errs": _ev("ERR"),
        "scan_warns": _ev("SCAN_WARN"),
        "tokens": tokens,
        "prefix": _prefix_payload(*(prefix_row or (0, 0, 0, 0, 0))),
        "by_type": by_type,
        "restore_by_status": restore_by_status,
        "by_label": by_label,
        "by_label_words": by_label_words,
        "top_words": top_list,
        "words_by_ingress": words_by_ingress,
    }


def label_summary(days=7):
    """近 N 天按规则标签聚合的命中量（战绩卡片数据源）。

    直接读 daily_words 摘要表求和——它由写线程增量维护，
    不用扫 events 的 payload。**只读 label 与 cnt，不碰 word 列**：
    word 是命中的原文（公司名、客户名等），卡片是要拿去分享的，
    一个字都不能带上去。

    **只统计代理链路（ingress='proxy'）**（SPEC §5.2(3)）：这是全仓唯一「只看代理」
    成立的地方——卡片是发给同行的公网物，「我拦了多少窗口里的邮箱」没有说服力，
    而「浏览器全量拦截」曝光出去还会引出「你还在看我浏览器？」的观感与隐私误读。
    代价是卡面总量 ≠ 首页总量，**所以卡面必须标注口径**（前端 i18n
    `stats.shareScopeProxyOnly`），否则就是新的「数字对不上」。

    返回 {label: 次数}，按次数降序。
    """
    _ensure_db()
    days = max(1, min(int(days), 90))
    since_day = time.strftime("%Y-%m-%d", time.localtime(time.time() - (days - 1) * 86400))
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT label, SUM(cnt) AS n FROM daily_words "
            "WHERE day >= ? AND COALESCE(ingress, 'proxy') = 'proxy' "
            "GROUP BY label ORDER BY n DESC",
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
            # 审计信号事件按小时聚合（含 HIGH/CRITICAL 计数，供告警口径与审计高危曲线）
            audit_hours = conn.execute(
                "SELECT CAST(ts / 3600 AS INTEGER) * 3600, COUNT(*), "
                "SUM(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) "
                "FROM audit_events WHERE ts >= ?"
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
        audit_hour_map = {hb: (int(n or 0), int(hi or 0)) for hb, n, hi in audit_hours}
        for hb in sorted(buckets.keys()):
            b = buckets[hb]
            audit_n, audit_hi = audit_hour_map.get(hb, (0, 0))
            # 审计高危并入「告警」：与 today_stats/stats_range 同口径，
            # 否则同一天的曲线点数与首页卡片对不上。
            b["alerts"] += audit_hi
            result.append({
                "ts": hb,
                "label": time.strftime("%m-%d %H:00", time.localtime(hb)),
                "hour": int(hb),
                **b,
                "tokens_prompt": 0,  # 小时粒度无 token 摘要
                "tokens_completion": 0,
                "audit_signals": audit_n,
                "audit_high": audit_hi,
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
            # 与 today_stats/stats_range 同口径：审计高危计入当日「告警」
            b["alerts"] += ab["audit_high"]
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
    # 审计高危并入告警口径（口径与审计页一致，见 _audit_high_count）
    audit_high = _audit_high_count(since)
    alerts += audit_high
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
        "audit_high": audit_high,
        "blocked": _ev("BLOCK"),
        "errs": _ev("ERR"),
        "scan_warns": _ev("SCAN_WARN"),
        "tokens": {"prompt": 0, "completion": 0},
        # legacy 路径读的是升级前写的事件，payload 里没有前缀诊断字段
        # → 明确给 None（前端显示「暂无样本」），不冒充 0。
        "prefix": None,
        "by_type": by_type,
        "restore_by_status": dict(status_map),
        "by_label": {},
        "by_label_words": {},
        "top_words": [],
        # 该分支根本不聚合词表（连全量 top_words 都是空的），分组视图同样是空；
        # 给空 dict 而不是缺席，前端不必为回退路径写第二个分支。
        "words_by_ingress": {},
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
    # 审计高危并入告警口径（口径与审计页一致，见 _audit_high_count）
    audit_high = _audit_high_count(day_start or _day_start(now))
    alerts += audit_high
    restore_by_status = dict(status_map)
    # 回退路径也按入口分组：payload 里带 ingress 的新事件同样要走同屏分组，
    # 否则「摘要表没数据」这一天里前端会因为拿不到分组而退回混算口径。
    counters = {}
    for (pl,) in mask_payloads:
        try:
            rec = json.loads(pl)
        except Exception:
            continue
        ing = str(rec.get("ingress") or "proxy") or "proxy"
        counter = counters.setdefault(ing, {})
        for it in rec.get("items") or []:
            lbl = str(it.get("label") or "其他")
            is_cred = bool(it.get("cred")) or lbl in CREDENTIAL_LABELS
            word = str(it.get("preview") or "") if is_cred else (it.get("original") or str(it.get("preview") or ""))
            if not word:
                word = "?"
            key = (lbl, str(word))
            counter[key] = counter.get(key, 0) + 1
    by_ingress = {}
    for ing, counter in counters.items():
        bl, blw, top = _pack_word_counter(counter)
        by_ingress[ing] = {
            "by_label": bl, "by_label_words": blw, "top_words": top,
            "label_total": sum(bl.values()),
        }
    total_counter = {}
    for counter in counters.values():
        for key, c in counter.items():
            total_counter[key] = total_counter.get(key, 0) + c
    by_label, by_label_words, top_list = _pack_word_counter(total_counter)
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
        "audit_high": audit_high,
        "tokens": tokens,
        # 同 _today_stats_legacy_range：legacy 事件没有前缀诊断字段。
        "prefix": None,
        "by_type": by_type,
        "restore_by_status": restore_by_status,
        "by_label": by_label,
        "by_label_words": by_label_words,
        "top_words": top_list,
        "words_by_ingress": by_ingress,
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


# ══════════════════════════════════════════════════════════════════════════
# C-1 / §16：只读聚合（面板 /api/engine/metrics 与一键自检共用）
# ══════════════════════════════════════════════════════════════════════════
# 为什么放在本模块而不是新开文件：事件库的连接、建表与迁移都在这里，
# 聚合读的也是同一个库（`_connect` / `_ensure_db`）；另起一个模块只会让
# 「谁能碰这个库」多一处入口。
#
# 三条硬约束（与库的隐私口径一致）：
#   ① **只读**：不写、不改、不迁移；
#   ② **不返回正文**：只回计数/分位/状态码，调用方拿不到 payload 原文，
#      也就没机会把它带进界面或诊断包 —— 隐私面靠"拿不到"，不靠"记得过滤"；
#   ③ **任何一步失败只降级、不抛**：自检恰恰在系统半死不活时才用得上，
#      聚合失败不该让整份结论消失（失败原因记在 `errors` 里）。
# 超过这个条数就不再逐行解 payload 做归因（只回总量/速率）。
# 取 5 万的理由：按每条 1.5~3KB payload 估算，逐行解一次就是 ~100MB 级读取，
# 而 /api/selfcheck 是一次点击触发的 UI 动作，不该在 Flask 线程上做这种量级的工作。
_AGGREGATE_DETAIL_MAX = 50000


def _percentiles(values):
    """返回 (p50, p95, n)；无数据时全 0。"""
    vals = sorted(v for v in values if isinstance(v, (int, float)))
    if not vals:
        return 0.0, 0.0, 0
    def at(p):
        idx = min(len(vals) - 1, max(0, int(round(p / 100.0 * (len(vals) - 1)))))
        return round(float(vals[idx]), 1)
    return at(50), at(95), len(vals)


def aggregate_recent(seconds=3600, now=None, sample_limit=2000):
    """最近 N 秒的事件聚合（只读）。

    返回结构固定（缺数据时给 0/空 dict），调用方不必到处判 None：
        by_type / by_status / by_block_source / by_reason 计数，
        mask_ms / upstream_ms 的 p50、p95，
        unresolved 合计、每分事件数、最后一条事件时间、疑似重试风暴。
    """
    out = {
        "window_s": int(seconds), "total": 0, "per_minute": 0.0, "last_event_ts": 0.0,
        "by_type": {}, "by_status": {}, "by_block_source": {}, "by_reason": {},
        "unresolved": 0, "retry_storms": [],
        "mask_ms": {"p50": 0.0, "p95": 0.0, "n": 0},
        "upstream_ms": {"p50": 0.0, "p95": 0.0, "n": 0},
        "errors": [],
    }
    try:
        _ensure_db()
    except Exception as e:                                  # pragma: no cover
        out["errors"].append("connect: %s: %s" % (type(e).__name__, e))
        return out

    window = max(60.0, float(seconds))
    now = float(now or time.time())
    since = now - window

    def _grouped(conn, sql, params):
        rows = conn.execute(sql, params).fetchall()
        return {str(r[0]): int(r[1]) for r in rows if r[0] not in (None, "")}

    try:
        with closing(_connect()) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT COUNT(*) AS n, MAX(ts) AS last FROM events WHERE ts >= ?", (since,)
            ).fetchone()
            out["total"] = int(row["n"] or 0)
            out["last_event_ts"] = float(row["last"] or 0.0)
            out["per_minute"] = round(out["total"] / (window / 60.0), 2)
            if not out["total"]:
                return out

            # 全窗口扫描（http_status / json_extract(payload) / SUM(unresolved)）都要
            # 逐行解 payload，而窗口上限是 7 天保留期 —— 窗口内事件量很大时（重试风暴
            # 可以到 10 万/小时量级）一次点击就是几百 MB 的行读，还跑在 Flask 线程上。
            # 所以给一个**总量闸**：超过就不再逐行归因，只回总量并把差额说清楚
            # （调用方与 UI 都能区分"没有异常"与"太大了没细分"）。
            if out["total"] > _AGGREGATE_DETAIL_MAX:
                out["detail_skipped"] = True
                out["detail_skipped_reason"] = (
                    "窗口内事件 %d 条，超过逐行归因上限 %d：仅返回总量与速率"
                    % (out["total"], _AGGREGATE_DETAIL_MAX))
                return out

            out["by_type"] = _grouped(
                conn, "SELECT type, COUNT(*) FROM events WHERE ts >= ? GROUP BY type", (since,))
            out["by_status"] = _grouped(
                conn, "SELECT http_status, COUNT(*) FROM events WHERE ts >= ? "
                      "AND http_status IS NOT NULL GROUP BY http_status", (since,))
            # 5xx 汇总（自检 S11 用；单独一档是因为用户关心的不是具体 500/502/503 的分布）
            r5 = conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ? AND http_status >= 500", (since,)
            ).fetchone()
            out["by_status"]["5xx"] = int(r5[0] or 0)

            # payload 里的归因字段：block_source（A-7）/ reason（既有）
            for key, col in (("by_block_source", "block_source"), ("by_reason", "reason")):
                try:
                    out[key] = _grouped(
                        conn,
                        "SELECT json_extract(payload, '$." + col + "') AS k, COUNT(*) "
                        "FROM events WHERE ts >= ? AND k IS NOT NULL GROUP BY k", (since,))
                except sqlite3.Error as e:
                    out["errors"].append("%s: %s" % (col, e))

            try:
                r = conn.execute(
                    "SELECT COALESCE(SUM(CAST(json_extract(payload, '$.unresolved') AS INTEGER)), 0) "
                    "FROM events WHERE ts >= ?", (since,)).fetchone()
                out["unresolved"] = int(r[0] or 0)
            except sqlite3.Error as e:
                out["errors"].append("unresolved: %s" % e)

            for key, field, etype in (("mask_ms", "mask_ms", "MASK"),
                                      ("upstream_ms", "upstream_ms", None)):
                # 注意口径：p50/p95 取自**最新 `sample_limit` 行**，而计数覆盖整个窗口。
                # 把两者混着读会失真（例如拿样本的 p50 去对比全窗口的 5xx 计数），
                # 所以把 n 一并回给调用方。
                try:
                    cond = "AND type = ?" if etype else ""
                    params = (since, etype) if etype else (since,)
                    rows = conn.execute(
                        "SELECT json_extract(payload, '$." + field + "') AS v FROM events "
                        "WHERE ts >= ? " + cond + " ORDER BY id DESC LIMIT ?",
                        params + (int(sample_limit),)).fetchall()
                    p50, p95, n = _percentiles([r[0] for r in rows])
                    out[key] = {"p50": p50, "p95": p95, "n": n}
                except sqlite3.Error as e:
                    out["errors"].append("%s: %s" % (field, e))

            # 疑似重试风暴：同一路径 60 秒内出现 ≥5 次 5xx
            try:
                rows = conn.execute(
                    "SELECT path, COUNT(*) AS c FROM events WHERE ts >= ? AND http_status >= 500 "
                    "AND path IS NOT NULL GROUP BY path HAVING c >= 5 ORDER BY c DESC LIMIT 5",
                    (max(since, now - 60.0),)).fetchall()
                out["retry_storms"] = [{"path": r["path"], "count": int(r["c"])} for r in rows]
            except sqlite3.Error as e:
                out["errors"].append("retry_storms: %s" % e)
    except Exception as e:                                  # pragma: no cover
        out["errors"].append("aggregate: %s: %s" % (type(e).__name__, e))
    return out
