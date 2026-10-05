"""
Data Maskit - 本地高精度 ONNX 实体识别（NER）引擎
基于经典中文 BERT-Base 量化模型（~98MB，基于 OntoNotes 5.0 中研院权威预训练模型），本地 CPU 毫秒级推理。
负责从非结构化中文文本中高召回率提取人名 (NAME)、企事业单位/机构/医院 (ORG)、详细地址与建筑 (ADDR)。

成本模型（实测，2026-09-19）：耗时随字数近似线性，约 0.25ms/字
（30 字 8ms / 120 字 19ms / 500 字 81ms / 2000 字 500ms）。
本模块跑在脱敏主链路上、且 mask() 会对请求体每个字符串叶子各调一次，
所以这里必须自己带硬边界（长度上限 + 时间预算 + 结果缓存），
且**任何失败都必须可见**——静默降级等于「用户以为开了、实际没脱」。
"""

from __future__ import annotations
import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 日志名与引擎其余部分一致（transparent 的 _log 用 llm_shield）。曾写成 "maskit"，
# 而全仓没有任何 basicConfig，那条唯一的初始化失败告警实际上无处可见。
_logger = logging.getLogger("llm_shield")


def _env_int(name, default):
    """读整数环境变量；非法值回落默认（不抛异常）。

    必须定义在模块级常量之前：MASKIT_NER_CONCURRENCY / MASKIT_NER_BUDGET /
    MASKIT_NER_CACHE_MAX / MASKIT_NER_CACHE_CHARS 都是在**导入时**求值的
    （进程级治理器与缓存容量），放后面会直接 NameError（实测踩过）。
    """
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return int(default)
    try:
        return int(raw)
    except ValueError:
        return int(default)


_MODEL_DIR = Path(__file__).parent / "models" / "ner_mini_zh"
# 公开别名：engine_entry 的启动预检（C-3）要把它写进告警文案，
# 让用户知道"该往哪儿放模型"。下划线名保留给模块内既有引用。
MODEL_DIR = _MODEL_DIR
_SESSION = None
_TOKENIZER = None
_ID2LABEL = {}
_INITIALIZED = False
_INIT_FAILED = False
_LAST_ERROR = ""
# 启动预热是否已跑过（批次 8）：只决定「还要不要再预热一次」，不影响懒加载路径。
_WARMED = False
# 实际使用的 ONNX 推理线程数（初始化时确定；C-1 的指标要能看到它）
_INTRA_THREADS = 0

# ── 成本护栏 ──────────────────────────────────────────────────────────────────
# 名字保留 MAX_TEXT_CHARS 是因为它同时是**单次调用**的规模上限（分段粒度），
# 以及 `tests/measure_ner_coverage.py` 的标定基准。
#
# ⚠️ 曾有 2000 字上限，超过就**整条不做 NER**（且只在全局日志里留一行）。实测用户
# 真实流量里出现过 6208 字的单条正文（会话被拼成一个大字符串），那条里的中文人名
# 全部明文上行 —— 比总预算更容易咬人，因为它是「整条不认」而不是「后面的不认」。
# 20000 字是一次止血、2026-09-28 起超长改为**分段识别**（「整条跳过」这条路径彻底
# 消失）；2026-09-30 把段长从 20000 收到 4000，实测（tests/measure_segment_granularity.py）：
#
#   1. **总耗时不变**：窗口总数 = 文本长度 / STRIDE，分段前后一样。20000 字整段冷推，
#      两种段长都是 3.7~4.3s（顺序敏感，差异在噪声内）。段长只改「粒度」，不改「总量」，
#      别指望靠调它提速。
#   2. 收益在**粒度**上：段级缓存变细 —— 客户端每轮重发历史时正文只要有一行变化，
#      旧粒度整叶重推、新粒度只重推变化的那一段。实测 12000 字正文改 1 个字后的
#      第二轮：段长 4000 = 778ms，段长 20000 = 2308ms（3.0 倍）。
#   3. 单段成本从 ≈5.6s 降到 ≈0.5~1.1s（4000 字实测 484ms @4 线程 / 1696ms @1 线程），
#      deadline 收手也不再整段白扔。
MAX_TEXT_CHARS = 4000
# 分段时的相邻重叠字数：实体正好落在切点上时，靠重叠区在**别的段**里被完整识别。
# 64 字足以覆盖中文人名/机构/地址的最长形态（实测最长实体 <30 字）。
_LONG_SEG_OVERLAP = 64
# 长文本切段的边界策略（批次 8）：**固定网格 + 吸附**。
# 吸附：每个网格切点向后找最近的换行/句末，切在它之后 —— 固定偏移会把实体劈成
# 两半（窗口边界落在实体中间时，两侧窗口各看到半个，两侧都识别不出）。
# 为什么不用滚动哈希 CDC：CDC 的卖点是「中间插入内容后，后面每段的**内容**不变
# （缓存照常命中）」，但撑住长会话缓存命中的是**叶子级**结果缓存（历史消息每轮
# 逐字节重发，键完全一致），切段只影响单条超长叶子内部；而锚定窗口的 CDC 实现
# 实测在「前置插入」下并不能重同步（窗口锚点会跟着漂），收益未证实。
# 网格间距 = MAX - 回看量 - 吸附量：三段相加正好等于 MAX_TEXT_CHARS，
# 保证每一段都 ≤ MAX（否则 extract_entities 会把这一段再递归切一次）。
_SEG_SNAP = 64
_SEG_GRID = max(1, MAX_TEXT_CHARS - _LONG_SEG_OVERLAP - _SEG_SNAP)
_SEG_BOUNDARY_RX = re.compile("[\n。！？；]")
# 单次调用时间预算（秒）：长度在上限内但推理异常变慢时按时收手，只返回已收集实体。
# 单次调用的推理时间上限（秒）。
#
# ⚠️ 它必须 ≥「一条长度达到 MAX_TEXT_CHARS 的文本能跑完」的耗时**并留出余量**，否则会
# 形成一个很贵的稳态：超时 → `complete=False` → 负缓存**不写**（见 extract_entities
# 里的注释）→ 下一轮同一段文本又从头冷推。
# 实测（`tests/measure_ner_coverage.py`）：20000 字/60KB 需 5588ms；旧的 2.0s 上限下
# 是每轮 2123/2013/2049ms 且缓存条数恒为 0。取 10.0s = 约 1.8 倍余量，因为余量不足时
# 闸门之间就是不自洽的：6.0s 虽然在本机能跑完（5588ms），但机器稍慢或 CPU 受争就退回
# 那个陷阱（实测单位成本 93µs/字节，与机器负载直接相关）。
# 总量仍由请求级预算 `transparent._ner_req_budget` 兜住，单次上限放大更需它兜底。
CALL_BUDGET_S = 10.0
# 结果缓存：同一条文本在长会话里反复出现（系统提示词、重复的历史消息），
# 不缓存就是每次重新推理。键是文本本身，容量固定（OrderedDict LRU），命中即零成本。
#
# ⚠️ 容量值得够**装下一条长会话的全部可识别叶子**（2026-09-24 事故）。
# `mask()` 对每个字符串叶子各调一次，而客户端每轮都把整段历史重发；一条 300+ 条
# 消息的会话叶子数会超过 256，LRU 于是每轮把上一轮的结果整批挤出 → 命中率≈0 →
# 每轮都按冷启动全量重推（实测同一条 6.6MB 会话：冷启 24.7 秒，缓存装得下时第二轮
# 只要 0.7 秒）。代价是一条长会话单个请求 20+ 秒，且脱敏是同步跑在 mitmproxy
# 事件循环上的，整机连接一起冻结。
# 条数与字数是**双重**上限，两者都可配（批次 8：MASKIT_NER_CACHE_MAX /
# MASKIT_NER_CACHE_CHARS）：
# - 条数默认 32768（旧值 4096）：一条 300+ 消息的长会话，每个字符串叶子各占一条，
#   再加上 tool_result 里长正文分段后的段数，4096 条在真实长会话里会被打满，
#   然后 LRU 把上一轮的结果整批挤出 → 命中率≈0 → 每轮按冷启动全量重推。
# - 字数默认 2000 万（旧值 400 万）：值是位置三元组、**不保留原文**（§G1），
#   所以「字数」只是记账口径（缓存覆盖了多少原文长度的识别结果），内存成本远低于
#   字数本身。含中文的长会话总量超过旧上限时，每轮顺序扫描会把上一轮结果全部挤掉。
_CACHE_MAX = max(256, _env_int("MASKIT_NER_CACHE_MAX", 32768))
_CACHE_MAX_CHARS = max(1_000_000, _env_int("MASKIT_NER_CACHE_CHARS", 20_000_000))
_CACHE = OrderedDict()
_CACHE_CHARS = 0
# 缓存会被多个线程同时碰：代理链路的 `_MASK_POOL` 专职线程 + panel 扩展桥接的
# Flask 线程（两者都会走到 `mask()` → `extract_entities`）。`_CACHE_CHARS` 的
# 读-改-写、以及命中后的 `move_to_end`（查完再动）都不是原子的：前者会漂到与实际
# 内容不符（计数偏高会让缓存被自己挤空，反而废掉这个修复），后者可能撞上并发的
# `popitem` 抛 KeyError。锁只护这两处缓存操作，推理本身不持锁。
_CACHE_LOCK = threading.Lock()
# 缓存命中/未命中计数（与 `_CACHE` 共用 `_CACHE_LOCK`）。
# 为什么要外发：实测同一条内容「冷缓存 58548.9ms / 热缓存 422.7ms」差 138 倍，
# 而在此之前没有任何一处能看见冷热比例 —— 只能人肉翻事件库对比两条 mask_ms。
# 只统计**真的查了缓存**的调用：长度守卫、无汉字早返回、模型不可用都不计入，
# 否则命中率的分母会被这些早返回灌水，读起来像「缓存没用」。
_CACHE_STATS = {"hit": 0, "miss": 0}
# 缓存键改成**进程密钥摘要**（§G1）：以前键是原文本身，等于把原文在内存里的
# 保留窗口延长到整个缓存生命周期（一条长会话动辄几 MB）。现在键是
# HMAC(进程密钥, 检测版本|模型身份|文本)，值只存 (start, end, type) 三元组，
# 命中时用当前文本即时切出 `text` —— 既不保留原文，又保证命中即字节一致。
# 密钥每次进程启动重新生成、不落盘：摘要在本进程外不可逆推，也不给跨进程关联留口子。
_CACHE_KEY = os.urandom(32)
# 检测版本：任何会改变实体的改动（模型/分词/分段/规则口径）都必须 +1，
# 否则进程内会错误复用旧口径的坐标（§G1：“模型更换不得错误复用”）。
# 键里同时含模型目录名，所以换一个 `_MODEL_DIR` 的部署也天然不复用。
_CACHE_DETECT_VERSION = "ner-v1"


def _cache_fingerprint(text: str) -> str:
    """缓存键（也用于负缓存）：进程密钥摘要，不包含原文。"""
    try:
        model_id = str(_MODEL_DIR)
    except Exception:
        model_id = ""
    payload = "%s\x00%s\x00" % (_CACHE_DETECT_VERSION, model_id) + text
    return hmac.new(_CACHE_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()
# 超长文本被分段识别的次数与总字数（进程级）。
# 它**不是降级**，所以刻意不进 `_SKIP_STATS`（进那里会被设置页读成「跳过原因」，
# 而分段识别的覆盖范围比旧的整条跳过更全）。只为可观测性留一个出口。
_LONG_SPLIT = {"n": 0, "chars": 0}
# 初始化锁：`_init_ner()` 的双检**不是**原子的，两个线程可以同时通过检查、
# 各建一个 InferenceSession（模型内存与 ONNX 线程双双翻倍，实测过）。
_INIT_LOCK = threading.Lock()


# 含汉字判定（编译一次）：整叶早返回与窗口级跳过共用，别在热路径上重复写字符比较。
_CJK_RX = re.compile("[\u4e00-\u9fff]")


def _cgroup_cpu_quota():
    """容器 CPU 配额（核数，可为小数）；无配额或读不到返回 None。只读 /sys，不抛异常。"""
    try:
        with open("/sys/fs/cgroup/cpu.max", "r", encoding="ascii") as f:      # cgroup v2
            parts = f.read().split()
        if parts and parts[0] != "max":
            quota = float(parts[0])
            period = float(parts[1]) if len(parts) > 1 else 100000.0
            return quota / period if quota > 0 and period > 0 else None
        return None
    except (OSError, ValueError, IndexError):
        pass
    try:                                                                      # cgroup v1
        with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "r", encoding="ascii") as f:
            quota = float(f.read().strip())
        with open("/sys/fs/cgroup/cpu/cpu.cfs_period_us", "r", encoding="ascii") as f:
            period = float(f.read().strip())
        return quota / period if quota > 0 and period > 0 else None
    except (OSError, ValueError):
        return None


def effective_cpu_count():
    """本进程**实际可用**的核数：亲和性掩码与 cgroup 配额取小，至少 1。

    为什么不用 `os.cpu_count()`：它报的是宿主机核数。`docker run --cpus=2` 跑在 16 核
    宿主上时它返回 16，于是 ONNX 开 4 线程、脱敏池开 4 个 worker、预算按 4 核给 ——
    容器被 CFS 限流成"2 核持续 100%"（2c4g VPS 用户报障的形态之一）。
    `os.process_cpu_count()`（3.13）只认亲和性、不认配额，所以两者都要看。
    配额向上取整（1.5 核按 2 算）：向下取整会让 1.5 核的容器只开 1 线程，白丢半核。
    """
    getter = getattr(os, "process_cpu_count", None) or os.cpu_count
    cores = getter() or os.cpu_count() or 2
    quota = _cgroup_cpu_quota()
    if quota:
        cores = min(cores, max(1, int(-(-quota // 1))))
    return max(1, int(cores))


def _intra_threads():
    """每次推理的 ONNX 线程数（A-4）。

    硬编码 4 在弱机 / 小容器上是灾难：4 个线程抢 1~2 个核，比单线程还慢，
    而"看起来开了 NER"的用户完全无从归因。默认按核数自适应，可覆盖。
    """
    # 用 effective_cpu_count()：容器里 `--cpus=1.5` 时按宿主核数开 4 个 ONNX 线程
    # 只会互相抢核（比单线程还慢），还会把 CFS 配额吃满。
    default = min(4, max(1, effective_cpu_count()))
    return max(1, min(16, _env_int("MASKIT_NER_THREADS", default)))


# ── B-2：进程级治理器 ────────────────────────────────────────────────────────
# 为什么需要：每个 InferenceSession 自带 `intra_op_num_threads` 个 ONNX 线程，
# 多请求并发推理 = 线程数乘性叠加。请求级预算（transparent._ner_req_budget）
# 只管"单个请求能用多久"，管不住"同时有几个请求在推理"，于是长会话 + 重试风暴
# 下会把 CPU 吃满（本次故障的 CPU 归因之一）。
#
# 并发上限：CPU 少的机器上并发推理只是互相抢核（弱机 / 小容器恒为 1）。
# 判据是 effective_cpu_count()（亲和性掩码 ∩ cgroup 配额），不是 os.cpu_count()：
# 16 核宿主上 `docker run --cpus=2` 时后者返回 16，于是并发被开成 2、ONNX 线程被
# 开成 4，容器被 CFS 限流成「2 核持续 100%」—— 正是 2c4g VPS 用户报障的形态。
_NER_CONCURRENCY = max(1, _env_int("MASKIT_NER_CONCURRENCY",
                                  1 if effective_cpu_count() <= 4 else 2))
_SEM = threading.Semaphore(_NER_CONCURRENCY)
_SEM_STATS = {"inflight": 0, "peak_inflight": 0, "waits": 0,
              "wait_ms_total": 0.0, "wait_ms_max": 0.0, "timeouts": 0}
# `_SEM` 只限"同时在推理的数量"，不保护这几个计数器的读改写：`inflight += 1` 是
# 三步，并发下会丢更新，于是 `inflight` 会漂（明明没人在推理却显示 >0，或峰值偏低），
# 而它正是 `/api/engine/metrics` 与自检拿来判断"语义识别吃不吃满"的依据。
# 这组计数器是**诊断口径**，漂了不会影响脱敏正确性，所以只加一把轻量锁，不上原子库。
_SEM_STATS_LOCK = threading.Lock()

# 预算容量 = 「NER 线程池最多能吃多少 CPU」的 75%，即
# `并发 × ONNX 线程数 × 1000 × 0.75`。
# ⚠️ 不是「物理核数 × 750」：旧口径是把**墙钟**记成容量（并发 × 750），等价的实际
# CPU 就是 `并发 × 线程数 × 750`；改成 CPU 毫秒后容量必须同步换算，否则 16 核机器
# 上的允许量会平白翻倍。弱机 / 容器上的效果与旧口径**完全一致**（2 核：1×2×750=1500）。
_NER_BUDGET_MS_PER_S = max(50, _env_int(
    "MASKIT_NER_BUDGET",
    int(_NER_CONCURRENCY * _intra_threads() * 1000 * 0.75)))
_BUCKET_LOCK = threading.Lock()
_BUCKET = {"tokens": float(_NER_BUDGET_MS_PER_S), "ts": time.monotonic()}
# 额度不足时的**有界等待**上限（毫秒，0 = 退回“直接跳过”的旧行为）。
#
# 为什么从“绝不等待”改成“有界等待”：桶的语义是**长期速率**，持续过载时无界
# 等待会让请求永不返回；而等待会占住脱敏 worker（正是 0.6.0 要消的队头阻塞）。
# 所以只在短窗口内等（默认 2s，且不超过本轮剩余 deadline）：等到就照常推理，
# 等不到仍按原策略降级（记 global_throttled、不阻断、不断链）。
_NER_BUDGET_WAIT_MS = max(0, min(10000, _env_int("MASKIT_NER_WAIT_MS", 2000)))
# 单位成本（**CPU** 毫秒/字符）：实测 1204 字一次推理墙钟 168ms × 4 线程 = 672 CPU-ms
# → 0.56 CPU-ms/字（本机 16 核、ONNX intra-op 4）。取 0.6 略偏保守。
# 用途只有一个 —— **动手前估个价**，好决定桶里的余额够不够；估错不影响正确性，
# 结算时按实际 CPU 开销追平（见 `_bucket_settle`）。
# ⚠️ 估值偏大不是“更安全”：估大了 `_bucket_take` 会频繁失败，于是短叶子明明
# 能跑也被拉去等待（用户看到的是“开了 NER 却经常没生效”）；偏小才是安全的，
# 因为超支会被结算追缴。所以这里用**实测值**而不是拍一个上界。
_EST_CPU_MS_PER_CHAR = 0.6
_SEM_WAIT_MAX_S = 2.0


def _bucket_take(est_ms, now=None):
    """尝试预支 est_ms 的推理额度；余额不足返回 False（本函数**不等待**）。

    等多久由调用方决定（见 `_bucket_wait`）：等待会把压力转成用户可见的延迟，
    而语义识别是“尽力而为”的增强项，确定性规则（正则 + 词表）才是脱敏的底线。
    所以只能按“本轮还剩多少时间”给一个小的等待窗口，不能在这里盲等。
    """
    now = time.monotonic() if now is None else now
    with _BUCKET_LOCK:
        elapsed = now - _BUCKET["ts"]
        if elapsed > 0:
            _BUCKET["tokens"] = min(float(_NER_BUDGET_MS_PER_S),
                                    _BUCKET["tokens"] + elapsed * _NER_BUDGET_MS_PER_S)
            _BUCKET["ts"] = now
        if _BUCKET["tokens"] < est_ms:
            return False
        _BUCKET["tokens"] -= est_ms
        return True


def _bucket_wait(est_ms, timeout_s):
    """在有界时间内等够 est_ms 额度：等到就取走并返回 True，超时返回 False。

    有界是硬约束：桶的语义是长期速率，持续过载时“等到有额度”可能永远不成立，
    而无界等待会占住脱敏 worker（正是 0.6.0 要消除的队头阻塞）。所以只在调用方
    给的小窗口（默认 2s，且不超过本轮剩余 deadline）内小步轮询。
    """
    end = time.monotonic() + max(0.0, float(timeout_s))
    while True:
        left = end - time.monotonic()
        if left <= 0 or _cancelled() or _current_deadline() is None:
            return False
        if _bucket_take(est_ms):
            return True
        time.sleep(min(0.05, left))


def _bucket_refund(ms):
    """全额退还一次预支（拿到额度后没跑成：取消、等不到槽位、初始化失败）。"""
    if ms <= 0:
        return
    with _BUCKET_LOCK:
        _BUCKET["tokens"] = min(float(_NER_BUDGET_MS_PER_S), _BUCKET["tokens"] + float(ms))


# 结算时允许余额为负（欠账），但下限钳在 -容量：一次推理的真实 CPU 开销可能远超
# 预估价，不欠账的话「超用」永远不体现在后续准入上，预算就又变回纸面上的数字。
# 钳一个下限是为了避免一次极端超时（CALL_BUDGET_S × 多线程）把桶压到很深的负数，
# 让后续请求长时间完全拿不到语义识别。
_BUCKET_DEBT_FLOOR = -float(_NER_BUDGET_MS_PER_S)


def _cpu_threads():
    """本次推理实际会占用的 CPU 线程数（未初始化时按配置推算，不加载模型）。"""
    return max(1, int(_INTRA_THREADS or _intra_threads()))
def _bucket_settle(est_ms, actual_ms):
    """按实际 CPU 开销结算：估高了退还，估低了**追缴**（允许余额为负）。

    与「只退不追」的旧口径的区别就在这里：旧实现写的是 `max(0, est - actual)`，
    于是「预估价被夹到桶容量」之后的那部分超支永远不记账 —— 长文本连续准入、
    桶看起来一直是满的，而机器早就跑满了（批次 8 的 CPU 归因）。
    """
    delta = float(est_ms) - float(actual_ms)
    with _BUCKET_LOCK:
        if delta >= 0:
            _BUCKET["tokens"] = min(float(_NER_BUDGET_MS_PER_S),
                                    _BUCKET["tokens"] + delta)
        else:
            _BUCKET["tokens"] = max(_BUCKET_DEBT_FLOOR, _BUCKET["tokens"] + delta)


def _empty_metrics():
    return {"init_ms": 0.0, "infer_ms": 0.0, "budget_wait_ms": 0.0,
            "sem_wait_ms": 0.0, "global_throttled": 0, "sem_timeout": 0,
            "calls": 0, "windows": 0, "cache_hit": 0, "cache_miss": 0}


def request_metrics(reset=False):
    """取（或取完清空）本线程的 NER 运行指标。

    `init_ms` includes initialization-lock waiting; `infer_ms` is decode wall time
    (tokenization + ONNX + label decoding), not CPU time. `calls` counts decode
    attempts and `windows` counts ONNX run attempts. Cache counters count lookups,
    including complete negative hits. Wait metrics include unsuccessful waits.
    All values are numeric; no request text or model paths are included.
    """
    m = dict(getattr(_local, "metrics", None) or {})
    if reset:
        _local.metrics = _empty_metrics()
    return m


def _metric_add(key, value):
    try:
        m = getattr(_local, "metrics", None)
        if m is None:
            m = _local.metrics = _empty_metrics()
        m[key] = m.get(key, 0) + value
    except Exception:
        pass


def governor_status():
    """治理器快照（C-1：面板看得见并发数、限流次数与桶余量）。"""
    with _BUCKET_LOCK:
        tokens = round(float(_BUCKET["tokens"]), 1)
    with _SKIP_LOCK:
        throttled = int(_SKIP_STATS.get("global_throttled", 0))
        sem_timeouts = int(_SKIP_STATS.get("sem_timeout", 0))
        waited = int(_BUDGET_WAITED["n"])
    with _SEM_STATS_LOCK:
        out = dict(_SEM_STATS)
    out.update({
        "concurrency": _NER_CONCURRENCY,
        "budget_ms_per_s": _NER_BUDGET_MS_PER_S,
        # 批次 8：预算单位从「墙钟毫秒/秒」改成「CPU 毫秒/秒」，同时把实际生效的
        # 核数与线程数外发 —— 用户问「为什么 2 核跑满」时，这三个数就是答案。
        "budget_unit": "cpu_ms_per_s",
        "cpu_cores": effective_cpu_count(),
        "cpu_threads": _cpu_threads(),
        "bucket_tokens_ms": tokens,
        "skipped_throttled": throttled,
        "skipped_sem_timeout": sem_timeouts,
        "budget_waited": waited,
        "intra_threads": _INTRA_THREADS,
    })
    out["wait_ms_total"] = round(float(out.get("wait_ms_total") or 0.0), 1)
    out["wait_ms_max"] = round(float(out.get("wait_ms_max") or 0.0), 1)
    return out


def _cache_put(key, entities, text_len=0):
    """写入结果缓存（含负缓存：`entities` 为空表示「这段确实没有实体」）。

    只接受**完整**跑完的结果 —— 预算超时/推理异常返回的残缺列表不进缓存，
    否则该文本此后命中缓存就一直欠脱敏（审计 M6）。
    负缓存解决的是同源问题：无实体的长文本此前每次请求都重跑推理
    （≤2000 字约 500ms/次）。它与「没跑完」必须区分开，所以调用方只在
    `_decode_chunks` 报 complete 时才调这里。

    `key` 是 `_cache_fingerprint(text)`；值只存 `(start, end, type)` 三元组，
    **不存原文与 `text` 切片**（§G1）。命中时由调用方从当前文本即时切出，
    所以缓存里不再有任何原文副本。

    淘汰按「条数超限 **或** 字符总量超限」两者任一触发，取更长历史给新增让路。
    字符记账仍是**所代表的文本长度**（不是实际保留的字节）：保留原意是「这个缓存
    覆盖了多少原文长度的识别结果」，用来保住长会话整批叶子不被 LRU 挤空
    （2026-09-24 事故），与是否保留原文无关。
    """
    global _CACHE_CHARS
    # 同键覆盖要先扣掉旧值，否则字符计数只增不减，缓存会被自己挤空。
    with _CACHE_LOCK:
        old = _CACHE.pop(key, None)
        if old is not None:
            _CACHE_CHARS -= int(old[0]) if isinstance(old, tuple) and len(old) == 2 else 0
        _CACHE[key] = (int(text_len or 0), [(e["start"], e["end"], e["type"]) for e in entities])
        _CACHE_CHARS += int(text_len or 0)
        while _CACHE and (len(_CACHE) > _CACHE_MAX or _CACHE_CHARS > _CACHE_MAX_CHARS):
            old_key, old_val = _CACHE.popitem(last=False)
            _CACHE_CHARS -= int(old_val[0]) if isinstance(old_val, tuple) else 0


def cache_stats() -> Dict:
    """结果缓存的命中/未命中快照（含容量水位与命中率）。

    出口：`status()["cache"]` → 引擎 `engine-runtime.json` → 面板
    `/api/engine/metrics` → 自检/设置页。
    冷热差实测 138 倍（同一条内容 58548.9ms vs 422.7ms），没有这组计数就只能
    靠人肉翻事件库 —— 而「缓存命中率掉到 0」恰恰是长会话每轮都慢几十秒的直接原因。
    `hit_rate` 在没有任何一次查询时返回 None（而不是 0.0）：0.0 会被读成
    「查了但一次都没命中」，与「还没查过」是不同结论。
    """
    with _CACHE_LOCK:
        hit = int(_CACHE_STATS.get("hit", 0))
        miss = int(_CACHE_STATS.get("miss", 0))
        size = len(_CACHE)
        chars = _CACHE_CHARS
        split_n = int(_LONG_SPLIT.get("n", 0))
        split_chars = int(_LONG_SPLIT.get("chars", 0))
    total = hit + miss
    return {
        "hit": hit,
        "miss": miss,
        "hit_rate": round(hit / total, 4) if total else None,
        "size": size,
        "max": _CACHE_MAX,
        "chars": chars,
        "chars_max": _CACHE_MAX_CHARS,
        # `chars` 是缓存**所代表的文本长度**（不是实际保留的字节）：值为位置三元组，
        # 不再存原文（§G1），但记账保留原口径，因为「缓存能装下多少原文长度的结果」
        # 决定长会话能否避免整批 LRU 挤出（2026-09-24 事故）。
        # 超长文本分段识别（非降级，见 _LONG_SPLIT 注释）
        "long_split_calls": split_n,
        "long_split_chars": split_chars,
    }

# 调用方给「一串调用」设的总预算（threading.local：只对本线程生效）。
_local = threading.local()
# 跳过原因计数 + 「只记一次」集合：失败必须可见，但每个请求都刷日志同样不可接受。
_SKIP_STATS = {}
# 全局跳过计数的锁：蒙版专职线程与扩展链路的 Flask 线程会并发 read-modify-write
# （此前无锁，极端情况下会丢计数）。只在真发生跳过时拿，不是热路径。
_SKIP_LOCK = threading.Lock()
_SKIP_LOGGED = set()
# 「曾经缺额度、但等到补上了」的进程级计数（与 `_SKIP_STATS` 共用 `_SKIP_LOCK`）。
# 它与跳过计数是**不同结论**（补上了 vs 降级），混进 skip 表会让面板把它读成降级；
# 但它同样必须有个出口 —— 只写进线程本地的 request_metrics 就等于没有（实测：写入后
# 无任何消费者，而 CHANGELOG / SECURITY 已经把它当卖点写上了）。
_BUDGET_WAITED = {"n": 0}


def _bump_skip_stat(key):
    """进程级跳过计数 +1（设置页读 status().skips）。"""
    with _SKIP_LOCK:
        _SKIP_STATS[key] = _SKIP_STATS.get(key, 0) + 1


def _log_skip_once(key, msg):
    """同类原因每个进程只写一条日志（长会话会把日志刷满）。"""
    if key in _SKIP_LOGGED:
        return
    _SKIP_LOGGED.add(key)
    try:
        _logger.warning("[ner_engine] %s（同类问题后续不再重复记录）", msg)
    except Exception:
        pass


def _warn_once(key, msg):
    """记一次**进程级**跳过原因（计数 + 首条日志）。

    ⚠️ 叶子级跳过请用 `_note_skip(key, msg)`：它同时记「按请求」那份账，而事件与
    详情弹窗里的降级标记完全依赖那份（只调本函数 = 界面上永远是静默降级）。
    """
    _bump_skip_stat(key)
    _log_skip_once(key, msg)


def record_skip(key: str, msg: str = "") -> None:
    """记录一次跳过原因（计数 + 首条日志 + 按请求记账），供外部如 transparent 的坐标降级调用。"""
    _note_skip(key, msg or f"NER 跳过: {key}")


# 会让「本次识别结果残缺」的原因：这些原因下不能把结果写进上游的叶子缓存
# （否则残缺结果会被永久固化，与 NER 负缓存同一类坑）。
# `model_unavailable` 不算：模型缺失是**进程级常量**（同一进程内不可能自己变好），
# 此时 NER 本来就不产生任何替换，规则结果是完整的。
_CACHE_POISON_SKIPS = frozenset({
    "global_throttled", "sem_timeout", "deadline", "cancelled",
    "budget_exhausted", "infer_failed", "init_failed",
})
_SKIP_EPOCH = 0


def skip_epoch() -> int:
    """「结果残缺」事件的自增计数。

    给上游（transparent 的叶子结果缓存）判断「本次这个叶子是不是完整跑完的」：
    只比前后两个整数，不需要在这段热路径上加任何锁或取指标快照。
    并发请求会互相抬这个计数（导致对方保守地不写缓存），方向是安全的。
    """
    return _SKIP_EPOCH


def _note_skip(key: str, msg: str = "") -> None:
    """记录一次**叶子级**跳过：按请求记账 + 进程级计数 +（给了 msg 时）首条日志。

    按请求那份写在 threading.local 里，调用方（transparent 的脱敏管线跑在专职线程）
    用 `request_skips()` 取出，写进 MASK/RESTORE 事件 —— 静默降级等于「以为开了、
    其实没脱」。进程级那份供设置页展示。
    """
    global _SKIP_EPOCH
    if key in _CACHE_POISON_SKIPS:
        _SKIP_EPOCH += 1
    try:
        s = getattr(_local, "skips", None)
        if s is None:
            s = _local.skips = {}
        s[key] = s.get(key, 0) + 1
    except Exception:
        pass
    _bump_skip_stat(key)
    if msg:
        _log_skip_once(key, msg)


@contextlib.contextmanager
def prefetch_scope():
    """预取阶段的**叶子级跳过不计入本请求**（进程级计数照常累计）。

    为什么必须隔离（2026-10-04 评审发现）：预取的结论是**推测性**的 —— 它可能只是
    撞上了瞬时额度不足/槽位超时，而正常遍历随后会在同一份预算内对同一段文本重新
    裁定一次。把预取的降级写进请求记录，等于让「猜测」参与最终结论：
      · `request_skips()` 会带上一条其实已被推翻的原因（事件与导出里误报降级）；
      · 严格模式（`ner_require_complete`）下这些码是**阻断判据**（见
        `inspection.BLOCKING_CATEGORIES`）—— 一个其实完整扫完的请求会被 503。
        方向正好反了：fail-closed 应当拦住「没扫到」，而不是拦住「扫完了」。

    进程级的 `_SKIP_STATS` / `_bump_skip_stat` **不隔离**：那不是阻断判据，
    而且预取确实降级过，设置页与自检应当看得到。
    目前只有 transparent 的「最新消息优先预取」用它；以后凡是在正式扫描之前
    做“试探性”推理的路径都应包上。
    """
    saved = getattr(_local, "skips", None)
    _local.skips = {}
    try:
        yield
    finally:
        # 还原**原对象**而不是把临时字典的内容倒回去：`_note_skip` 是就地累加，
        # 指向同一字典的其它引用（若未来有）不该看到预取阶段的内容。
        _local.skips = saved if saved is not None else {}


def request_skips(reset: bool = False) -> Dict:
    """取（或取完清空）本线程自上次 `begin_budget` 以来的跳过计数。

    返回形如 `{"budget_exhausted": 3, "deadline": 1}`；空字典 = 本轮语义识别全程生效。
    （`too_long` 是 2026-09-28 前的旧键：那之前超长文本整条跳过；现在改为分段识别，
    因此新事件不会再出现它 —— 旧库里的事件仍可能带。）
    """
    s = dict(getattr(_local, "skips", None) or {})
    if reset:
        _local.skips = {}
    return s


def begin_budget(seconds, *, deadline=None, cancel_event=None):
    """Begin a thread-local request budget; always pair with end_budget in finally.

    deadline is an optional absolute time.monotonic() processing deadline (including
    upstream worker queue time). cancel_event is an optional threading.Event owned
    by the caller. Checks are cooperative: running initialization/ONNX cannot be
    interrupted. Expiry never implicitly ends or renews a request budget.
    """
    effective = time.monotonic() + float(seconds)
    if deadline is not None:
        effective = min(effective, float(deadline))
    _local.doc_active = True
    _local.deadline = effective
    _local.cancel_event = cancel_event
    _local.skips = {}
    _local.metrics = _empty_metrics()


def end_budget():
    _local.doc_active = False
    _local.deadline = None
    _local.cancel_event = None


def _cancelled():
    event = getattr(_local, "cancel_event", None)
    return event is not None and event.is_set()


def _current_deadline():
    """Absolute cooperative deadline; None means exhausted or cancelled."""
    now = time.monotonic()
    if _cancelled():
        return None
    dl = getattr(_local, "deadline", None)
    if getattr(_local, "doc_active", False) and dl is not None:
        return min(dl, now + CALL_BUDGET_S) if now < dl else None
    return now + CALL_BUDGET_S


def _stopped(deadline, reason="deadline"):
    if _cancelled():
        _note_skip("cancelled")
        return True
    if deadline is None or time.monotonic() >= deadline:
        if reason == "budget_exhausted":
            _note_skip("budget_exhausted")
        else:
            _note_skip("deadline")
        return True
    return False


def _acquire_until(lock, deadline):
    """Poll a lock without granting fresh time after expiry or cancellation."""
    while not _cancelled():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        if lock.acquire(timeout=min(0.05, remaining)):
            return True
    return False


ADDR_TAGS = frozenset({"GPE", "LOC", "FAC"})
# 行政区后缀：整段以此结尾且无门牌细节 → 只是「地名」不是「地址」（审计 L3）。
_ADMIN_SUFFIXES = (
    "自治区", "特别行政区", "自治州", "自治县", "地区", "省", "市", "县", "区", "国",
)
# 门牌/街道/楼栋细节后缀：出现任一即认为这是**具体地址**，必须打码。
_ADDR_DETAIL_CHARS = (
    "路", "街", "道", "巷", "弄", "号", "楼", "室", "栋", "幢", "座", "单元",
    "院", "园", "村", "镇", "乡", "大厦", "广场", "小区", "花园", "公馆", "层", "段",
)


def _is_bare_region(s: str) -> bool:
    """整段只是一个行政区名（无门牌/街道细节）→ 不当地址处理。

    GPE 会把「北京」「中国」「广东省」这类高熵为零的地名标出来。脱敏它们
    保护不了任何东西（几千万人共用一个地名），却会把词榜灌满噪声 ——
    审计 L3 实测的过度脱敏。判据刻意收得很紧：含数字、含街道/楼栋细节、
    或长度超过 10 字，一律不算「裸地名」，照常当地址打码。
    """
    if not s or len(s) > 10:
        return False
    if any(ch.isdigit() for ch in s):
        return False
    if any(c in s for c in _ADDR_DETAIL_CHARS):
        return False
    if s.endswith(_ADMIN_SUFFIXES):
        return True
    # 「北京」「上海」这类不带后缀的裸城市名：只有足够短才算地名，
    # 再长就可能是「海淀中关村」这种需要打码的具体片区。
    return len(s) <= 4
ORG_SUFFIXES = (
    "医院", "诊所", "卫生院", "妇幼保健院", "中医院", "大学", "学院", "学校",
    "分公司", "支行", "分行", "有限责任公司", "有限公司", "公司", "集团",
    "委员会", "事务所", "局", "厅", "处", "部", "院", "所", "中心", "实验室"
)
ADDR_SUFFIXES = (
    "路", "街", "大道", "巷", "弄", "里", "胡同", "桥", "段", "村", "镇", "乡",
    "区", "县", "市", "省", "大厦", "广场", "大楼", "中心", "园区",
    "花园", "小区", "城", "苑", "府", "公馆", "号", "栋", "幢", "层", "楼", "室", "单元", "座"
)


def is_ner_available() -> bool:
    """检查 NER 模型文件是否就绪（只看文件；依赖是否可导入由 status() 反映）。"""
    return (
        (_MODEL_DIR / "model_quantized.onnx").exists()
        and (_MODEL_DIR / "tokenizer.json").exists()
        and (_MODEL_DIR / "config.json").exists()
    )


def status() -> Dict:
    """运行状态（面板/健康检查用）。

    available 只代表模型文件齐备；真正能否推理要看 initialized。
    这两者都不成立时必须让用户看得见，否则「开了 NER 却没打码」无从归因。
    """
    # 快照必须在锁内取：skip 计数由蒙版线程与 Flask 线程并发累加，口径与
    # `governor_status()` 一致（不要一个持锁、一个不持）。
    with _SKIP_LOCK:
        skips = dict(_SKIP_STATS)
    return {
        "available": is_ner_available(),
        "initialized": bool(_INITIALIZED),
        "failed": bool(_INIT_FAILED),
        "last_error": _LAST_ERROR,
        "model_dir": str(_MODEL_DIR),
        "max_text_chars": MAX_TEXT_CHARS,
        "call_budget_s": CALL_BUDGET_S,
        "cache_size": len(_CACHE),
        "cache_max": _CACHE_MAX,
        "cache_chars": _CACHE_CHARS,
        # C-2：冷热命中比例（旧字段保留是为了不破坏已有前端/诊断包读取方）
        "cache": cache_stats(),
        "skips": skips,
        # B-2/A-4：并发与限流可见性（面板与自检都读这里）
        "governor": governor_status(),
    }


def _init_ner():
    global _SESSION, _TOKENIZER, _ID2LABEL, _INITIALIZED, _INIT_FAILED, _LAST_ERROR
    if _INITIALIZED:
        return True
    if _INIT_FAILED:
        return False

    deadline = _current_deadline()
    if deadline is None or not _acquire_until(_INIT_LOCK, deadline):
        return False
    try:
        if _cancelled() or time.monotonic() >= deadline:
            return False
        # 双检：拿到锁之后再确认一次，否则两个线程仍会各建一个 session
        if _INITIALIZED:
            return True
        if _INIT_FAILED:
            return False
        return _init_ner_locked()
    finally:
        _INIT_LOCK.release()


def warmup(timeout_s: float = 60.0) -> bool:
    """启动预热：把模型加载与首窗推理从「第一个用户请求」挪到进程启动阶段。

    为什么需要（批次 8）：模型是**懒加载**的，第一个请求要额外承担
    InferenceSession 构建 + 图优化 + 首窗推理，实测冷启动数秒。那段耗时落在
    某个倒霉请求的 `mask_ms` 里，长会话下还会直接撞 `CALL_BUDGET_S`，
    表现为「刚启动那几轮特别慢、还可能漏码」。

    幂等；只做一次；失败不抛异常也不阻断（模型缺失/依赖缺失由既有告警路径说明）。
    """
    global _WARMED
    if _WARMED:
        return bool(_INITIALIZED)
    if not is_ner_available():
        return False
    if not _init_ner():
        return False
    _WARMED = True
    try:
        # 只建 session 不推理时，首次 run 仍要付图优化与内存池分配的钱。
        # 这里跑一个短窗（含汉字，不会被无汉字早返回跳过）把这份钱花在启动阶段。
        _decode_chunks("预热", time.monotonic() + max(1.0, float(timeout_s)))
    except Exception as e:                                   # noqa: BLE001
        _warn_once("warmup", f"语义识别预热推理失败（不影响后续请求）：{type(e).__name__}: {e}")
    return True


def _init_ner_locked():
    global _SESSION, _TOKENIZER, _ID2LABEL, _INITIALIZED, _INIT_FAILED, _LAST_ERROR
    global _INTRA_THREADS
    if not is_ner_available():
        _INIT_FAILED = True
        _LAST_ERROR = f"模型文件缺失（应为 {_MODEL_DIR} 下的 model_quantized.onnx / tokenizer.json / config.json）"
        _warn_once("model_missing", _LAST_ERROR + "，语义实体识别未启用")
        return False

    try:
        import onnxruntime as ort
        from tokenizers import Tokenizer

        tok_path = _MODEL_DIR / "tokenizer.json"
        cfg_path = _MODEL_DIR / "config.json"
        model_path = _MODEL_DIR / "model_quantized.onnx"

        _TOKENIZER = Tokenizer.from_file(str(tok_path))
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        _ID2LABEL = cfg.get("id2label", {})

        # CPU 推理线程数按核数自适应（A-4），实测约 0.25ms/字，见模块头部成本模型。
        _INTRA_THREADS = _intra_threads()
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = _INTRA_THREADS
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        # 关掉 ONNX 线程池的**空转**（批次 8 实测，这是「2 核跑满」的第三个来源）。
        # onnxruntime 的 intra-op 线程池默认在每次推理结束后继续忙等约 1 秒才挂起：
        # 实测一次推理完再空闲 1s，进程 CPU 又多了 1173ms（≈1.2 个核秒白烧）。
        # 真实负载里请求之间本来就有间隔，于是**每轮都白烧一次** —— 长会话下就是
        # “明明没在推理，CPU 却一直有底噪”。关掉后同一测试的空闲 CPU 为 0ms，
        # 而连续推理的墙钟/CPU 不变（83→90ms / 333→338ms，同量级）。
        # 老版本 onnxruntime 可能不认这个键：认不出就跳过，绝不因此让初始化失败。
        if _env_int("MASKIT_NER_SPINNING", 0) == 0:
            try:
                opts.add_session_config_entry("session.intra_op.allow_spinning", "0")
            except Exception:
                pass

        _SESSION = ort.InferenceSession(str(model_path), sess_options=opts, providers=["CPUExecutionProvider"])
        _INITIALIZED = True
        return True
    except Exception as e:
        _INIT_FAILED = True
        _LAST_ERROR = f"{type(e).__name__}: {e}"
        # 依赖缺失（onnxruntime/tokenizers 未安装）会走到这里，必须给出可执行的提示：
        # 正式包缺少依赖时只会打到这里，否则用户只看到「开了没效果」。
        _warn_once("init_failed",
                   f"初始化失败，语义实体识别不可用：{_LAST_ERROR}"
                   f"（缺少 onnxruntime/tokenizers 依赖或模型文件损坏；依赖见 requirements-dev.txt）")
        return False


def _map_category(tag: str) -> Optional[str]:
    """将 OntoNotes 细粒度标签映射到统一的标准脱敏标签。"""
    if tag == "PERSON":
        return "NAME"
    if tag == "ORG":
        return "ORG"
    if tag in ADDR_TAGS:
        return "ADDR"
    return None


def _decode_chunks(text: str, deadline: float) -> Tuple[List[Dict], bool]:
    """分块滑窗推理，返回 (原始实体片段, 是否完整跑完)。

    `complete` 必须如实回报：预算超时或单块推理异常都会 `break` 并带着**残缺**的
    实体列表返回，调用方据此决定要不要写缓存（审计 M6）。
    """
    import numpy as np

    CHUNK_SIZE = 400
    STRIDE = 350
    text_len = len(text)
    raw_entities = []
    complete = True

    pos = 0
    while pos < text_len:
        if _stopped(deadline):
            complete = False
            break
        chunk = text[pos:pos + CHUNK_SIZE]
        if not chunk:
            break

        # 纯英文/代码窗口直接跳过推理（P0 性能，2026-09-30）：本模型只识中文实体，
        # 不含汉字的窗口不可能产出中文实体；而 CHUNK_SIZE(400)/STRIDE(350) 有 50 字
        # 重叠，跨窗口的实体一定会在相邻窗口里被完整看到 —— 跳过不会漏码。
        # 收益取决于内容形态（实测见 tests/measure_segment_granularity.py）：中文段落越稀疏
        # 省得越多 —— 每 ~1500 字一段中文时省 74%；中文密到每个窗口都有汉字时基本不省。
        if _CJK_RX.search(chunk) is None:
            if pos + CHUNK_SIZE >= text_len:
                break
            pos += STRIDE
            continue

        if _stopped(deadline):
            complete = False
            break
        encoded = _TOKENIZER.encode(chunk)
        input_ids = np.array([encoded.ids], dtype=np.int64)
        attention_mask = np.array([encoded.attention_mask], dtype=np.int64)
        token_type_ids = np.zeros_like(input_ids, dtype=np.int64)

        inputs = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "token_type_ids": token_type_ids,
        }

        if _stopped(deadline):
            complete = False
            break
        try:
            _metric_add("windows", 1)
            outputs = _SESSION.run(None, inputs)
            logits = outputs[0][0]
            preds = np.argmax(logits, axis=-1)
        except Exception as e:
            # 单块推理失败：记一次日志后收手，返回已收集的部分实体。
            # 曾完全静默 break，用户侧只表现为「部分文本没打码」。
            _note_skip("infer_failed", f"推理异常，本段仅返回已识别结果：{type(e).__name__}: {e}")
            complete = False
            break

        offsets = encoded.offsets
        curr = None

        for pred, (s, e) in zip(preds, offsets):
            lbl = _ID2LABEL.get(str(pred), "O")
            if s == e:
                continue
            abs_s = pos + s
            abs_e = pos + e

            if lbl == "O":
                if curr:
                    raw_entities.append(curr)
                    curr = None
                continue

            # 标签形态守卫（审计 L4）：下面按 `lbl[0]` 取 BIO 前缀、`lbl[2:]` 取类别，
            # 隐含要求 "B-NAME" 这种长度 ≥3 且第 2 位是 '-' 的形态。
            # `config.json` 被换成含空标签的模型时 `lbl[0]` 直接 IndexError；
            # "B" 这类短标签则会让 tag 变成 ""，_map_category 返回 None 后
            # 同样把 curr 冲掉。两种都按「无法识别的标签」收尾并跳过 ——
            # 宁可漏一个实体，也不能让整条 NER 抛异常。
            if len(lbl) < 3 or lbl[1] != "-":
                if curr:
                    raw_entities.append(curr)
                    curr = None
                continue

            prefix = lbl[0]  # B, I, E, S
            tag = lbl[2:]
            cat = _map_category(tag)

            if not cat:
                if curr:
                    raw_entities.append(curr)
                    curr = None
                continue

            if prefix in ("B", "S"):
                if curr:
                    raw_entities.append(curr)
                curr = {"type": cat, "start": abs_s, "end": abs_e, "text": text[abs_s:abs_e]}
                if prefix == "S":
                    raw_entities.append(curr)
                    curr = None
            elif prefix in ("I", "E"):
                if curr and curr["type"] == cat:
                    curr["end"] = abs_e
                    curr["text"] = text[curr["start"]:abs_e]
                    if prefix == "E":
                        raw_entities.append(curr)
                        curr = None
                else:
                    if curr:
                        raw_entities.append(curr)
                    curr = {"type": cat, "start": abs_s, "end": abs_e, "text": text[abs_s:abs_e]}
                    if prefix == "E":
                        raw_entities.append(curr)
                        curr = None

        if curr:
            raw_entities.append(curr)

        if _stopped(deadline):
            complete = False
            break
        if pos + CHUNK_SIZE >= text_len:
            break
        pos += STRIDE

    return raw_entities, complete


def extract_entities(text: str) -> List[Dict]:
    """提取文本中的命名实体（人名、机构名、地址）。

    返回: [{"type": "NAME"|"ORG"|"ADDR", "start": int, "end": int, "text": str}]
    返回的 dict 允许调用方读取，改动不会污染缓存（每次返回独立副本）。
    """
    if not text or not isinstance(text, str) or len(text.strip()) < 2:
        return []

    # 纯英文/代码/无汉字文本直接跳过：本引擎基于中文 BERT（OntoNotes 5.0），
    # 仅负责人名 (NAME)、机构 (ORG)、详细地址 (ADDR) 三类中文实体。
    # 纯英文或代码中无中文实体，反而会被 BERT subword 切碎产生误报（如将英文参数误报为人名）。
    if _CJK_RX.search(text) is None:
        return []

    if _cancelled():
        _note_skip("cancelled")
        return []

    # 超长文本 → 分段识别（旧行为是整条跳过并记 too_long，见 MAX_TEXT_CHARS 的注释）。
    if len(text) > MAX_TEXT_CHARS:
        return _extract_long(text)

    with _CACHE_LOCK:
        _fp = _cache_fingerprint(text)
        cached = _CACHE.get(_fp)
        if cached is not None:
            _CACHE.move_to_end(_fp)
            _CACHE_STATS["hit"] = _CACHE_STATS.get("hit", 0) + 1
        else:
            _CACHE_STATS["miss"] = _CACHE_STATS.get("miss", 0) + 1
    _metric_add("cache_hit" if cached is not None else "cache_miss", 1)
    if _cancelled():
        _note_skip("cancelled")
        return []
    # Completed cache entries need no inference budget. Cancellation still wins.
    if cached is not None:
        # 值只有位置与类别，`text` 从**当前文本**即时切出：命中即摘要相等，
        # 也就意味着文本逐字节相同，重建结果与当初完全一致。
        return [{"type": t, "start": s, "end": e, "text": text[s:e]}
                for (s, e, t) in cached[1]]
    deadline = _current_deadline()
    if _stopped(deadline, "budget_exhausted"):
        return []

    t_init = time.monotonic()
    try:
        initialized = _init_ner()
    finally:
        _metric_add("init_ms", max(0.0, time.monotonic() - t_init) * 1000)
    if _stopped(deadline):
        return []
    if not initialized:
        _note_skip("model_unavailable")
        return []

    # 单次调用超时（`deadline` 键）与推理异常（`infer_failed` 键）由 `_decode_chunks`
    # 在发生处自己记账，这里**不要**再补一个笼统的键：同一个现象挂两个名字会让
    # 设置页与弹窗各显示一半，且会把异常误报成超时。
    # B-2：先拿"速率额度"，再拿"并发槽位"，最后才推理。
    # 顺序不能反：先占槽位再发现没额度，会把槽位白占一会儿，放大排队。
    # ⚠️ 估价必须**夹到桶容量**（0.6.0 修）：桶的容量是"每秒额度"
    # （`_NER_BUDGET_MS_PER_S` = 并发 × ONNX 线程数 × 750 CPU 毫秒），而单条长文本的
    # 线性估价可以远大于它（4000 字 ≈ 2400 CPU-ms，远超 2 核机器的 1500）。不夹的话
    # `_bucket_take` 永远失败 —— 于是超过容量的文本**永久**进不了语义识别，
    # 而且是"确定性漏码"而不是"负载降级"：用户只看到 global_throttled 计数上涨。
    # 桶的职责是限**速率**，不是限**单条大小**（单条大小由 CALL_BUDGET_S 与
    # 分段长度上限兜住）。
    # ⚠️ 批次 8：估价与结算都改成 **CPU 毫秒**（墙钟 × 线程数）—— 旧口径按墙钟计费，
    # 等于把「两个核全占满」记成「占了大半个核」，预算从不是真正的 CPU 上限。
    threads = _cpu_threads()
    est_ms = max(1.0, len(text) * _EST_CPU_MS_PER_CHAR)
    est_ms = min(est_ms, float(_NER_BUDGET_MS_PER_S))
    if not _bucket_take(est_ms):
        # 额度不足：先在**有界**窗口内等一等（默认 2s，且不超过本轮剩余 deadline）。
        # 等到就照常推理（记 budget_waited，“曾经缺额度但补上了”可见）；
        # 等不到仍按原策略降级 —— 不阻断、不断链，只如实记原因。
        # 保留既有策略：给并发槽位预留等待窗口，避免额度等待吃光剩余预算。
        # 后续每道检查仍以绝对 deadline 为准，绝不续给最小等待时间。
        budget_wait_s = min(_NER_BUDGET_WAIT_MS / 1000.0,
                            max(0.0, deadline - time.monotonic() - _SEM_WAIT_MAX_S))
        t_budget = time.monotonic()
        try:
            got_tokens = budget_wait_s > 0 and _bucket_wait(est_ms, budget_wait_s)
        finally:
            budget_wait_ms = max(0.0, time.monotonic() - t_budget) * 1000
            _metric_add("budget_wait_ms", budget_wait_ms)
        if _stopped(deadline):
            if got_tokens:
                _bucket_refund(est_ms)
            return []
        if got_tokens:
            _metric_add("budget_waited", 1)
            with _SKIP_LOCK:
                _BUDGET_WAITED["n"] += 1
        else:
            _metric_add("global_throttled", 1)
            _note_skip("global_throttled",
                       f"语义识别的全局 CPU 预算已用尽（{_NER_BUDGET_MS_PER_S} CPU 毫秒/秒，"
                       f"已等 {budget_wait_ms / 1000:.1f}s），本条未做实体识别")
            return []
    if _stopped(deadline):
        _bucket_refund(est_ms)
        return []
    remaining = min(_SEM_WAIT_MAX_S, deadline - time.monotonic())
    t_wait0 = time.monotonic()
    got_slot = _acquire_until(_SEM, min(deadline, t_wait0 + remaining))
    wait_ms = max(0.0, time.monotonic() - t_wait0) * 1000
    _metric_add("sem_wait_ms", wait_ms)
    if _stopped(deadline):
        if got_slot:
            _SEM.release()
        _bucket_refund(est_ms)
        return []
    if not got_slot:
        # 槽位等不到 = 已经有人在推理且迟迟不放手：跳过而不是无限排队。
        _bucket_refund(est_ms)
        with _SEM_STATS_LOCK:
            _SEM_STATS["timeouts"] += 1
        _metric_add("sem_timeout", 1)
        _note_skip("sem_timeout",
                   f"语义识别并发槽位等待超过 {remaining:.1f}s，本条未做实体识别")
        return []
    with _SEM_STATS_LOCK:
        _SEM_STATS["waits"] += 1
        _SEM_STATS["wait_ms_total"] += wait_ms
        _SEM_STATS["wait_ms_max"] = max(_SEM_STATS["wait_ms_max"], wait_ms)
    t_infer0 = time.monotonic()
    with _SEM_STATS_LOCK:
        _SEM_STATS["inflight"] += 1
    with _SEM_STATS_LOCK:
        if _SEM_STATS["inflight"] > _SEM_STATS["peak_inflight"]:
            _SEM_STATS["peak_inflight"] = _SEM_STATS["inflight"]
    try:
        raw_entities, complete = _decode_chunks(text, deadline)
    finally:
        with _SEM_STATS_LOCK:
            _SEM_STATS["inflight"] -= 1
        _SEM.release()
        actual_ms = max(0.0, time.monotonic() - t_infer0) * 1000
        _metric_add("infer_ms", actual_ms)
        _metric_add("calls", 1)
        # 按**实际 CPU 开销**结算（墙钟 × 线程数）：估高了退还，估低了追缴
        # （允许余额为负）。旧实现只退不追，超支永远不记账，预算形同虚设。
        _bucket_settle(est_ms, actual_ms * threads)
    # Even the last ONNX window can outlive cancellation/deadline. Never publish
    # that attempt as a complete cache entry; running calls release their own slot.
    if complete and _stopped(deadline):
        complete = False
    if not raw_entities:
        # 负缓存（审计 M6 同源问题）：无实体的长文本此前**每次请求都重跑推理**
        # （≤2000 字约 500ms/次，实测成本模型 0.25ms/字）。
        # ⚠️ 只在 `complete` 时才写：预算超时 / 推理异常返回的空结果是「没跑完」，
        # 缓存下来会让这段文本在此后永久不再被识别（该打码的不打）。
        if complete:
            _cache_put(_fp, [], len(text))
        return []

    # 去重与区间排序。重叠时**裁剪**而不是整条丢弃（审计 L2）：
    # 旧写法 `if ent["start"] < last_end: continue` 会把「起点落在前一个实体内、
    # 但终点更远」的那条整个丢掉，于是 [last_end, ent_end) 这段既不属于任何实体、
    # 也不被打码 —— 注释里「不会漏明文」的断言并不严格成立。
    raw_entities.sort(key=lambda x: (x["start"], -x["end"]))
    deduped = []
    last_end = -1
    for ent in raw_entities:
        if ent["start"] < last_end:
            if ent["end"] <= last_end:
                continue                      # 完全被前一个覆盖：真丢
            ent = dict(ent, start=last_end, text=text[last_end:ent["end"]])
        deduped.append(ent)
        last_end = ent["end"]

    # 实体精炼与边界平滑
    refined = []
    for ent in deduped:
        etype = ent["type"]
        start, end = ent["start"], ent["end"]

        # 后缀贪婪扩充
        if etype == "ORG":
            tail = text[end:end + 12]
            for sfx in ORG_SUFFIXES:
                if tail.startswith(sfx):
                    end += len(sfx)
                    break
        elif etype == "ADDR":
            tail = text[end:end + 20]
            # 门牌与楼栋吸附。注意：字符类里的连续数字串靠「结构化规则先跑」才安全
            # （卡号那时已变成 {{...}}，`{` 不在字符类里），改执行顺序要重新评估。
            m = re.match(r"^([0-9A-Za-z一二三四五六七八九十\-号栋幢层楼室单元座段]+)", tail)
            if m:
                end += len(m.group(1))

        ent_text = text[start:end]
        # 过滤极短或无意义实体（人名需至少 2 字；机构和地址需至少 2 字）
        if len(ent_text) <= 1:
            continue
        if any(c in ent_text for c in ("\n", "\r", "\t")):
            continue
        # 纯行政区名不当地址（审计 L3）：GPE 会把「北京」「中国」这类高熵为零的
        # 地名标出来，脱敏它们只是把高频词换成占位符、把词榜灌满噪声，保护不了
        # 任何东西。判据要求**整段**都是行政区名（无门牌/街道/楼栋细节）——
        # 「北京市朝阳区建国路88号」有数字和街道后缀，照常打码。
        if etype == "ADDR" and _is_bare_region(ent_text):
            continue

        refined.append({
            "type": etype,
            "start": start,
            "end": end,
            "text": ent_text,
        })

    # 后缀扩充发生在去重**之后**，可能越过下一个实体的起点（前一个把后一个吞掉）。
    # 这里按起点重排并裁剪与前一个已接受实体重叠的项（审计 L2）：
    # 旧写法整条 `continue`，注释断言「被吞掉的文本仍在前一个实体区间内」——
    # 这只在被吞的那条**完全落在**前一个区间内时成立。若它的终点更远
    # （前一个 end 被后缀扩充推过了它的 start），[前一个 end, 它的 end) 这段
    # 就既不属于任何实体、也不被打码，是实打实的漏明文。改成保留尾部区间。
    refined.sort(key=lambda x: (x["start"], -x["end"]))
    trimmed = []
    for ent in refined:
        if trimmed and ent["start"] < trimmed[-1]["end"]:
            if ent["end"] <= trimmed[-1]["end"]:
                continue                      # 完全被覆盖：丢弃
            ent = dict(ent, start=trimmed[-1]["end"],
                       text=text[trimmed[-1]["end"]:ent["end"]])
        trimmed.append(ent)

    # 相邻同类型实体合并（特别是相邻切碎的地址块）
    final_merged = []
    for ent in trimmed:
        if not final_merged:
            final_merged.append(ent)
            continue
        prev = final_merged[-1]
        if prev["type"] == ent["type"] and ent["type"] == "ADDR":
            gap = text[prev["end"]:ent["start"]]
            # 如果两个地址块相距不足 6 字符且没有标点中断，直接缝合
            if len(gap) <= 6 and not any(p in gap for p in ("，", "。", "！", "？", ";", ",")):
                prev["end"] = ent["end"]
                prev["text"] = text[prev["start"]:ent["end"]]
                continue
        final_merged.append(ent)

    # 只有**完整**跑完的结果才入缓存（审计 M6）：预算超时（`deadline` 分支）与
    # 单块推理异常都会带着残缺实体列表走到这里，缓存下来等于让该文本此后每次
    # 命中缓存都返回同一份残缺结果——即使系统空闲也不再补全，持续欠脱敏。
    if complete and not _stopped(deadline):
        _cache_put(_fp, final_merged, len(text))
    return [dict(e) for e in final_merged]


def _long_seg_cuts(text: str) -> List[int]:
    """长文本切点列表（升序，不含 0 与 len(text)）。纯函数，不抛异常。

    切点只由**前缀**决定（网格锚在绝对偏移上、吸附只看切点附近的字符），
    所以「尾部追加新内容」不会移动已有切点 —— 客户端每轮重发整段历史时，
    前面各段的内容逐字节不变，段级缓存照常命中。

    代价：`re.search` 扫的是吸附窗口（最多 64 字）而不是全篇（C 层），
    比逐字符滚动哈希便宜得多（后者 1MB 要 ~100ms 的 Python 循环，
    而这一段跑在脱敏 worker 的热路径上）。
    """
    cuts: List[int] = []
    total = len(text)
    if total <= MAX_TEXT_CHARS:
        return cuts
    pos = _SEG_GRID
    while pos < total:
        m = _SEG_BOUNDARY_RX.search(text, pos, min(total, pos + _SEG_SNAP))
        cut = m.end() if m is not None else pos
        if cut >= total:
            break
        cuts.append(cut)
        pos = cut + _SEG_GRID
    return cuts


def _extract_long(text: str) -> List[Dict]:
    """超长文本的分段识别：按 `MAX_TEXT_CHARS` 切窗口后逐段走正常路径，再平移偏移。

    存在的理由（P1，2026-09-28）：真实长会话里单条 6208~几万字的正文很常见
    （tool 输出、贴进 prompt 的日志/源码），而旧行为是**整条不做 NER**（too_long）——
    那一段里的中文人名/机构/地址全部明文上行。分段后要么全识别，要么受预算约束
    只识别前若干段（并记 `budget_exhausted`），不再有「静默的整条跳过」。

    为什么不是简单放大 MAX_TEXT_CHARS：单次成本线性（0.28ms/字），5 万字单次要 14s，
    会长期占着推理槽位并撞 `CALL_BUDGET_S`；分段后每段 ≤MAX_TEXT_CHARS（≈0.5~1.1s），
    且每段单独进缓存 —— 长会话反复重发同一段时第二轮接近零成本。

    重叠窗口（`_LONG_SEG_OVERLAP`）保证落在切点上的实体能在相邻段里被完整看到；
    重叠区产生的重要实体由 `_merge_overlaps` 去重裁剪。
    """
    out: List[Dict] = []
    # 重叠量不能超过窗口的一半：否则回看起点会跨过前一段，段长失控。
    overlap = min(_LONG_SEG_OVERLAP, max(0, MAX_TEXT_CHARS // 2))
    total = len(text)
    segs = 0
    prev = 0
    for cut in _long_seg_cuts(text) + [total]:
        if cut <= prev:
            continue
        # 起点回看 overlap 字：切点上的实体能在**前一段**里被完整看到（切点已吸附到
        # 换行/句末，回看只是第二道保险）。段长上界仍是 MAX_TEXT_CHARS：
        # `_SEG_GRID + _SEG_SNAP` 已经把 overlap 的量预留出来了。
        start = 0 if prev == 0 else max(0, prev - overlap)
        seg = text[start:cut]
        segs += 1
        assert len(seg) <= MAX_TEXT_CHARS, len(seg)
        ents = extract_entities(seg)
        for e in ents:
            # 平移回整条文本的坐标系；`text` 字段与段内一致，无需重取。
            out.append({
                "type": e["type"],
                "start": e["start"] + start,
                "end": e["end"] + start,
                "text": e["text"],
            })
        prev = cut
        # Continue cheap cache lookups after inference budget expiry; a miss will
        # not start inference. A cancelled whole request must stop immediately.
        if _cancelled():
            break
    if segs > 1:
        with _CACHE_LOCK:
            _LONG_SPLIT["n"] = int(_LONG_SPLIT.get("n", 0)) + 1
            _LONG_SPLIT["chars"] = int(_LONG_SPLIT.get("chars", 0)) + total
    return _merge_overlaps(out, text)


def _merge_overlaps(ents: List[Dict], text: str) -> List[Dict]:
    """分段结果的去重与重叠裁剪（口径与 `extract_entities` 内的一致）。

    重叠窗口让同一个实体可能在相邻两段各被识别一次（起终点一致或小幅漂移）；
    跨切点的实体会以两段各一半的形态出现 —— 保留更靠前、更长的那条，
    后面的重叠部分裁剪而不是整条丢弃（丢弃会漏掉尾部那一段）。
    """
    if not ents:
        return []
    ents.sort(key=lambda x: (x["start"], -x["end"]))
    out: List[Dict] = []
    for ent in ents:
        if out and ent["start"] < out[-1]["end"]:
            if ent["end"] <= out[-1]["end"]:
                continue
            ent = dict(ent, start=out[-1]["end"], text=text[out[-1]["end"]:ent["end"]])
        out.append(ent)
    return out
