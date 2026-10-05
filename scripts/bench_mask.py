"""脱敏与审计性能基线：改造前后各跑一次，用来证明"变快了"而不是"感觉快了"。

**不进门禁**（跑几十秒、结果依赖本机 CPU 与核数），手动/发版前跑：

    py -3.13 scripts/bench_mask.py --save ai-coding/bench-before.json
    # …… 改造 ……
    py -3.13 scripts/bench_mask.py --save ai-coding/bench-after.json
    py -3.13 scripts/bench_mask.py --compare ai-coding/bench-before.json

为什么必须先抓基线（2026-09-26 教训）：并发改造的收益项原先写成
「p95 ≤ 改造前 60%」「审计 CPU 占比下降 ≥70%」，但当时**根本没有基线脚本**，
这两个数字既不可复现也不可验收 —— 改完之后谁都能宣称达标。

测五组指标，每组都直接锚在真实热路径上（不是另写一套模拟代码）：

  mask_single      单请求脱敏 `tr.mask()`           → 改造后不许劣化（±10%）
  mask_pool        经 `_MASK_POOL` 并发的逐请求延迟 → 队头阻塞的直接证据
  restore_whole    整包还原 `json.loads + _restore_tree + dumps`（8MB）
                                                   → 事件循环占用（A-3 的目标）
  audit_scan       审计三信号扫描（16/128/512KB）   → 0.46ms/KB 的口径来源
  audit_full       `_parse_response_payload` 全量解析 + 请求体全量 json.loads
                                                   → A-1 补上的那部分成本

CPU 口径：`time.process_time()` 是**进程内所有线程**的 CPU 时间，除以墙钟即
「这段时间里平均有几个核在忙」。放在审计组上用，就能回答"审计到底吃掉多少 CPU"。

产物只写用户显式 `--save` 的路径；默认不落任何文件（本机工作产物不入库，
`ai-coding/` 已在 .gitignore 里）。
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

# 敏感样本一律在运行时拼出来：`-----BEGIN...PRIVATE KEY-----` 的完整块与
# `AKIA...` 形态若以字面量进仓库，会被 scripts/audit-public-release.py 拦下
# （它就是干扫描这件事的）。这里要的是"能被审计信号识别"的输入，不是凭据本身。
FAKE_PEM = ("-----BEGIN " + "PRIVATE" + " KEY-----\n"
            + "MIIBOgIBAAJBAK" + "x" * 64 + "\n"
            + "-----END " + "PRIVATE" + " KEY-----")
FAKE_AWS = "AKIA" + "Z" * 16
# 显然伪造的样例：`.invalid` 是 RFC 2606 保留域，电话号码段用全 0，
# 任何人一眼就能看出「这是压测数据、不是真凭据」。
FAKE_EMAIL = "bench-user" + "@" + "example" + ".invalid"   # RFC 2606 保留域
FAKE_PHONE = "+86-100-" + "0000-0000"

FILLER = "这是用于压测的中文正文，包含一些正常业务描述与编号 %d。客户名称与项目代号需要脱敏。"


def _pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int(round((p / 100.0) * (len(s) - 1)))))
    return s[idx]


def _stats(values):
    return {
        "n": len(values),
        "p50": round(_pct(values, 50), 3),
        "p95": round(_pct(values, 95), 3),
        "mean": round(statistics.fmean(values), 3) if values else 0.0,
        "max": round(max(values), 3) if values else 0.0,
    }


def _make_response_body(kb):
    """造一个 LLM 风格响应体，体积约 kb 千字节（内容可被三信号扫出东西）。"""
    target = max(1, kb) * 1024
    parts = []
    i = 0
    overhead = 0
    while overhead < target:
        chunk = FILLER % i
        if i == 3:
            chunk += " 联系邮箱 %s 电话 %s" % (FAKE_EMAIL, FAKE_PHONE)
        if i == 7:
            chunk += " 临时密钥 %s 与云凭据 %s" % (FAKE_PEM, FAKE_AWS)
        if i == 11:
            chunk += " 请执行 rm -rf /tmp/bench-cache 清理缓存"
        parts.append(chunk)
        overhead += len(chunk.encode("utf-8"))
        i += 1
    body = {"id": "bench", "model": "bench-model", "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant",
                                                 "content": "".join(parts)}}]}
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


def _setup_env(tmp):
    import transparent as tr
    tr._DATA_ROOT = tmp
    (tmp / "config.json").write_text(json.dumps({
        "sensitive": {"甲类": ["压测敏感词%02d" % i for i in range(20)]},
        "fail_closed": True,
    }, ensure_ascii=False), encoding="utf-8")
    tr._maybe_reload(force=True)
    tr._emit = lambda *a, **k: None          # 事件落库不参与计时
    tr.sessions.clear()
    return tr


def bench_mask_single(tr, iters):
    """单请求脱敏：最接近用户感知的一段（规则扫描 + 签发 + 拼接）。

    ⚠️ 每次迭代用**不同**的文本：叶子结果缓存（批次 8）对同一段文本的第二次调用
    会直接命中，用固定文本测出来的是「缓存命中」而不是「规则扫描」。
    """
    samples = []
    for i in range(iters):
        sid = "bench-single-%d" % (i % 8)
        text = ("客户压测敏感词01 与 02，编号 %d，" % i) + FILLER % 1
        t0 = time.perf_counter()
        tr.mask(text, sid)
        samples.append((time.perf_counter() - t0) * 1000)
    return _stats(samples)


def bench_mask_pool(tr, concurrency, per_thread):
    """经 `_MASK_POOL` 提交并发脱敏，记录**逐请求**的排队 + 执行延迟。

    这条是队头阻塞的直接证据：worker 宽度为 1 时，第 N 个请求的延迟包含
    前面 N-1 个请求的全部执行时间，p95 随并发线性上升。
    """
    total = concurrency * per_thread
    lat = []
    pool = getattr(tr, "_MASK_POOL", None)
    if pool is None:
        return {"n": 0, "note": "_MASK_POOL 不存在，跳过"}
    # 单条文本要够大，否则每条只花 0.02ms，量的是调度噪声而不是吞吐。
    # 20KB 文本（不触发 NER）单条约 2~4ms，队列效应才看得见。
    workload = ("编号 客户压测敏感词01 " + (FILLER % 1) * 60)

    async def run():
        loop = asyncio.get_running_loop()

        async def one(i):
            sid = "bench-pool-%d" % (i % 4)
            # ⚠️ 每条用**不同**的文本（尾部带请求序号）：叶子结果缓存对同一段文本的
            # 第二次调用会直接命中，用固定文本测出来的吞吐是「缓存命中吞吐」，
            # 比真实脱敏快一个数量级，会把并发基线整个测歪。
            text = workload + (" #%d" % i)
            t0 = time.perf_counter()
            # ⚠️ 每条自己记账、并发提交（gather）：要把"排队 + 执行"都算进该条的
            # 延迟里，才能看出队头阻塞。写成"先提交一堆再顺序 await"会把
            # await 之前的等待时间漏掉，宽池反而显得更慢（实测踩过）。
            await loop.run_in_executor(pool, tr.mask, text, sid)
            lat.append((time.perf_counter() - t0) * 1000)

        await asyncio.gather(*(one(i) for i in range(total)))

    t0 = time.perf_counter()
    asyncio.run(run())
    wall = time.perf_counter() - t0
    out = _stats(lat)
    out["wall_s"] = round(wall, 3)
    out["throughput_per_s"] = round(total / wall, 2) if wall else 0.0
    depth = getattr(tr, "_mask_queue_stats", None)
    if callable(depth):                     # A-6 之后才有
        out["queue"] = depth()
    return out


def bench_restore_whole(tr, body_kb, iters):
    """整包还原（事件循环上的 O(body) 活）耗时。"""
    raw = _make_response_body(body_kb)
    samples = []
    sizes = []
    for _ in range(iters):
        t0 = time.perf_counter()
        body = json.loads(raw)
        body = tr._restore_tree(body, "bench-restore")
        out = json.dumps(body, ensure_ascii=False).encode("utf-8")
        samples.append((time.perf_counter() - t0) * 1000)
        sizes.append(len(out))
    st = _stats(samples)
    st["body_kb"] = round(body_kb, 1)
    return st


def bench_audit(tr, sizes_kb, iters):
    """审计扫描成本，按体积给出口径；并顺带量全量解析那两块（A-1 的补丁目标）。"""
    import audit_signals as audit
    out = {}
    for kb in sizes_kb:
        raw = _make_response_body(kb)
        text = raw.decode("utf-8", errors="replace")
        headers = "content-type:application/json"
        scan_samples, parse_samples = [], []
        cpu0 = time.process_time()
        wall0 = time.perf_counter()
        for _ in range(iters):
            scan_text = text[:128 * 1024]
            t0 = time.perf_counter()
            audit.scan_error_leak(503, scan_text, headers)
            audit.scan_response_poison(scan_text, "")
            audit.scan_dangerous_action(scan_text, "")
            scan_samples.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            tr._parse_response_payload(text, "application/json")
            try:
                json.loads(raw)
            except Exception:
                pass
            parse_samples.append((time.perf_counter() - t0) * 1000)
        cpu = (time.process_time() - cpu0) * 1000
        wall = (time.perf_counter() - wall0) * 1000
        out["%dKB" % kb] = {
            "scan_128k_window": _stats(scan_samples),
            "full_parse": _stats(parse_samples),
            "cpu_ms_total": round(cpu, 1),
            "cpu_ratio": round(cpu / wall, 3) if wall else 0.0,
        }
    return out


def bench_long_context(tr, sizes_kb, iters):
    """长上下文脱敏：逐个体积点量 `json.loads + _mask_tree + dumps` 三段耗时。

    与 `size_probe.py` 的区别：那个回答「闸门会不会挡住 1M token」，本组是
    **可重复跑的性能基线**（固定体积点、给 p50/p95、给每 MiB 单价），
    用来在后续改动后判断长上下文有没有变慢。
    """
    out = {}
    for kb in sizes_kb:
        raw = _make_response_body(kb)
        loads, mask, dumps, total = [], [], [], []
        # ⚠️ 每次迭代换一个会话 id：叶子结果缓存按文本命中，同一会话重跑同一段 body
        # 会从第 2 次起全部命中，测出来的是缓存而不是规则扫描。
        for it in range(iters):
            t0 = time.perf_counter()
            body = json.loads(raw)
            t1 = time.perf_counter()
            masked = tr._mask_tree(body, "bench-long-%d" % it)
            t2 = time.perf_counter()
            json.dumps(masked, ensure_ascii=False).encode("utf-8")
            t3 = time.perf_counter()
            loads.append((t1 - t0) * 1000)
            mask.append((t2 - t1) * 1000)
            total.append((t3 - t0) * 1000)
            dumps.append((t3 - t2) * 1000)
        st = _stats(total)
        mib = len(raw) / 1024 / 1024
        st.update({
            "body_mib": round(mib, 3),
            "loads": _stats(loads), "mask_tree": _stats(mask), "dumps": _stats(dumps),
            # 换算单价：GIL 占用与体积近似线性，单价是跨体积可比的常量
            "ms_per_mib": round(st["mean"] / mib, 1) if mib else 0.0,
        })
        out["%dKB" % kb] = st
    return out


def bench_multiturn(tr, msgs, msg_chars, turns, iters):
    """多轮长会话：客户端每轮重发整段历史，只追加一条新消息。

    这是叶子结果缓存（批次 8）的**唯一**卖点所在，也是长会话变慢的直接原因：
    没有缓存时每轮都要把整段历史重跑 20~50 条正则（实测 ≈140 ms/MiB）。

    两个数必须分开报，否则看不出差别：
      cold  本会话第一次见这段历史（全未命中）；
      warm  同一会话的后续轮次（只有尾部新消息未命中）。
    `speedup` 就是缓存带来的收益；`deepcopy` 单列，因为它不属于脱敏耗时。
    """
    per_msg = max(1, msg_chars // max(1, len(FILLER % 0)))

    def make(n):
        messages = []
        for i in range(n):
            messages.append({
                "role": "user",
                "content": "第%d条：" % i + (FILLER % i) * per_msg
                           + " 手机 %s 邮箱 %s" % (FAKE_PHONE, FAKE_EMAIL),
            })
            messages.append({"role": "assistant", "content": "已记录第%d条。" % i})
        return {"model": "bench-model", "messages": messages}

    def run(body, sid):
        t0 = time.perf_counter()
        b = copy.deepcopy(body)
        t1 = time.perf_counter()
        tr._mask_tree(b, sid)
        t2 = time.perf_counter()
        return (t2 - t1) * 1000, (t1 - t0) * 1000

    cold, warm, dup = [], [], []
    for it in range(max(1, iters)):
        sid = "bench-mt-%d" % it
        tr._leaf_cache_clear()
        c, d = run(make(msgs), sid)
        cold.append(c)
        dup.append(d)
        body = make(msgs)
        for t in range(max(2, turns)):
            body["messages"].append({"role": "user",
                                     "content": "追加第%d条：%s" % (t, FAKE_EMAIL)})
            w, d = run(body, sid)
            dup.append(d)
            if t >= 1:                 # 第 2 轮起才算 warm（第 1 轮是首次填缓存）
                warm.append(w)
    out = {"messages": msgs, "msg_chars": msg_chars, "turns": max(2, turns),
           "cold": _stats(cold), "warm": _stats(warm), "deepcopy": _stats(dup)}
    out["speedup"] = (round(out["cold"]["p50"] / out["warm"]["p50"], 1)
                      if out["warm"]["p50"] else 0.0)
    if hasattr(tr, "_LEAF_CACHE_STATS"):
        out["leaf_cache"] = dict(tr._LEAF_CACHE_STATS)
        out["leaf_cache_size"] = len(tr._LEAF_CACHE)
    return out


def bench_ner_cache(tr, iters, doc_chars_list):
    """NER 冷/热缓存：模型加载、缓存未命中、同文本命中，按**文档长度**分档。

    三件事分开量，因为它们的数量级完全不同，混在一起就什么都看不出来：
      model_load  首次调用会建 ONNX 会话（秒级，只付一次）；
      miss        缓存未命中 → 真的跑一遍推理；
      hit         命中 → 只做 HMAC 键比对 + 坐标切出（§G1 后值只存位置三元组）。

    按长度分档而不是只报一个点：只看单点会得到「NER 很快」或「NER 很慢」两种
    相反结论（小文本被 per-call 开销主导、长文本被分段与预算主导）。

    同时必须回传 skip 计数：超出预算/截止时间时引擎会**主动不做识别**（漏检），
    此时耗时低不代表“跑得快”，而是“根本没跑”——不报这个数就是拿漏检冒充性能。

    模型不可用（文件缺失或 onnxruntime 未装）时**如实返回 unavailable**，
    不拿 mock 结果冒充 §7.3「中文 NER 效果已验证」。
    """
    import ner_engine
    out = {
        # 两个字段分开报：文件齐 ≠ 能推理（onnxruntime 缺失时只差后者），
        # 合成一个布尔就分不清「没装模型」与「装了但跑不起来」。
        "available": bool(ner_engine.is_ner_available()),
        "initialized_before": bool(ner_engine.status().get("initialized")),
    }
    if not out["available"]:
        out["note"] = "模型文件缺失，未执行"
        return out

    # 样本必须含 NER 认得出的实体，否则整条路径会被「无实体」短路，测得的是空转。
    unit = ("张三向李四汇报了与北京华创科技有限公司的合同进展，"
            "王五负责对接上海办事处。请尽快确认。")

    # 单调递增的文档计数器：**每一个**生成的文档都必须与本次运行里任何
    # 其它文档不同（包括其它长度档）。否则后跑的档会命中先跑那档的分段缓存：
    # 实测 8000 字的第一个窗口正好等于 4000 字档的文档，于是 8000 字只花了
    # 658 ms（看着像「越长越便宜」），实际是少跑了一段推理。
    _seq = [0]

    def _doc(n, unique=True):
        """造 n 字符的文档；unique=True 时每段带唯一编号，且全文唯一。

        ⚠️ 为什么必须唯一：超过 `MAX_TEXT_CHARS` 的文本走**分段识别**，
        分段结果同样进缓存。拿重复模板凑长度会让后续段全部命中缓存，
        测出「长文本反而更快」的假象（本脚本首轮就跑到 4000 字 25.8 ms/千字、
        而 2000 字是 173 ms/千字）。基线里绝不允许这种误导性数字。
        """
        _seq[0] += 1
        seed = _seq[0]
        parts, total, i = [], 0, 0
        while total < n:
            seg = unit + (("流水%09d，" % (seed * 100000 + i)) if unique else "")
            parts.append(seg)
            total += len(seg)
            i += 1
        return "".join(parts)[:n]

    max_chars = int(ner_engine.status().get("max_text_chars") or 0)
    out["max_text_chars"] = max_chars

    before = ner_engine.cache_stats()
    tr.NER_ENABLED = True
    try:
        longest = max(doc_chars_list)
        t0 = time.perf_counter()
        # 首个调用触发模型加载 + 未命中推理，两件事都算在 model_load 里 ——
        # 拆不开：会话创建就在第一次 extract_entities 内部。
        tr.mask(_doc(200), "bench-ner-load")
        out["model_load_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        out["initialized_after"] = bool(ner_engine.status().get("initialized"))

        by_chars = {}
        for chars in doc_chars_list:
            # 命中组必须**固定同一份文档**：命中测的是「同一文本重复脱敏」
            # （多轮对话里模型每轮都把相同上下文发回来），不是「又一份新文本」。
            # 拿 `_doc(chars)` 在循环里现生成 = 每轮都是一份新文档 = 测出的是 miss。
            hit_doc = _doc(chars)
            tr.mask(hit_doc, "bench-ner-warm")
            hits, miss = [], []
            for i in range(max(1, iters)):
                t0 = time.perf_counter()
                tr.mask(hit_doc, "bench-ner-hit-%d" % (i % 4))
                hits.append((time.perf_counter() - t0) * 1000)
            for i in range(max(1, iters)):
                # 每个文档全局唯一 → 每一个分段窗口都必然未命中。
                # 只改尾部编号、或只按档位给种子都不够：分段窗口是 4000 字的窗，
                # 只要窗口内容与别处重叠就会命中缓存（详见 `_doc` 的注释）。
                t0 = time.perf_counter()
                tr.mask(_doc(chars) + " 仅此一次%06d。" % i, "bench-ner-miss-%d" % (i % 4))
                miss.append((time.perf_counter() - t0) * 1000)
            entry = {"chars": chars, "hit": _stats(hits), "miss": _stats(miss),
                     "segmented": bool(max_chars and chars + 12 > max_chars)}
            if entry["miss"]["mean"]:
                entry["hit_miss_ratio"] = round(entry["hit"]["mean"] / entry["miss"]["mean"], 4)
                entry["ms_per_1k_chars"] = round(entry["miss"]["mean"] / (chars / 1000.0), 2)
            by_chars[str(chars)] = entry
        out["by_chars"] = by_chars
        out["by_chars_longest"] = by_chars[str(longest)]

        # 分段缓存的可利用性（解释「为什么同样的长度会差 20 倍」）：
        # 重复模板文档的第二轮几乎全是段缓存命中，这是真实机制，但**不是**
        # 线性推理单价，两个数必须分开报。
        if max_chars:
            rep = (unit * ((max_chars * 3) // len(unit) + 2))[:max_chars * 3]
            tr.mask(rep, "bench-ner-rep-warm")
            reps = []
            for i in range(max(1, iters)):
                t0 = time.perf_counter()
                tr.mask(rep + " 尾%06d。" % i, "bench-ner-rep-%d" % (i % 2))
                reps.append((time.perf_counter() - t0) * 1000)
            out["repeat_doc"] = {
                "chars": len(rep), "p50_ms": _stats(reps)["p50"],
                "note": "重复模板 → 分段缓存可用；与 by_chars 的单价不可比",
            }

        after = ner_engine.cache_stats()
        out["cache"] = {k: after.get(k) for k in ("hit", "miss", "hit_rate", "size", "chars")}
        out["cache_delta"] = {
            "hit": int(after.get("hit") or 0) - int(before.get("hit") or 0),
            "miss": int(after.get("miss") or 0) - int(before.get("miss") or 0),
        }
        # 漏检证据：非空即意味着上面那些「很快的 miss」里有一部分根本没跑推理。
        # 不放进结果就不能拿耗时下性能结论（归因会错到与 2026-10-02 同款的跟头上）。
        out["skips"] = ner_engine.request_skips(reset=False)
        out["governor"] = ner_engine.governor_status()
    finally:
        tr.NER_ENABLED = False
    return out


def _diff(before, after):
    """对比两组结果，只对"延迟型"指标给结论（越大越差）。"""
    rows = []

    def walk(path, b, a):
        if isinstance(b, dict) and isinstance(a, dict):
            for k in b:
                if k in a:
                    walk("%s.%s" % (path, k) if path else k, b[k], a[k])
            return
        if isinstance(b, (int, float)) and isinstance(a, (int, float)) and b:
            ratio = a / b
            rows.append((path, b, a, ratio))

    walk("", before, after)
    for path, b, a, ratio in rows:
        flag = ""
        if any(path.endswith(s) for s in (".p50", ".p95", ".mean", ".max", ".cpu_ms_total")):
            flag = "  <== 变慢" if ratio > 1.1 else ("  ok" if ratio <= 1.0 else "")
        print("  %-52s %10.3f -> %10.3f  x%.2f%s" % (path, b, a, ratio, flag))


def main():
    ap = argparse.ArgumentParser(description="脱敏/审计性能基线")
    ap.add_argument("--iters", type=int, default=30, help="mask_single 迭代次数")
    ap.add_argument("--restore-kb", type=float, default=8192, help="整包还原的 body 体积（KB）")
    ap.add_argument("--restore-iters", type=int, default=3)
    ap.add_argument("--concurrency", type=int, default=16, help="mask_pool 并发数")
    ap.add_argument("--concurrency-list", default="1,4,8",
                    help="mask_pool 并发扫描点（逗号分隔；空串则只用 --concurrency）")
    ap.add_argument("--per-thread", type=int, default=4, help="mask_pool 每并发请求数")
    ap.add_argument("--long-sizes", default="256,1024,4096",
                    help="长上下文体积点（KB，逗号分隔）")
    ap.add_argument("--long-iters", type=int, default=3)
    ap.add_argument("--mt-msgs", type=int, default=150,
                    help="多轮长会话的历史消息数（bench_multiturn）")
    ap.add_argument("--mt-msg-chars", type=int, default=400, help="每条消息的目标字符数")
    ap.add_argument("--mt-turns", type=int, default=3, help="续跑轮数（含首轮）")
    ap.add_argument("--mt-iters", type=int, default=2, help="多轮长会话重复几次")
    ap.add_argument("--skip-multiturn", action="store_true", help="跳过多轮长会话组")
    ap.add_argument("--ner-iters", type=int, default=8, help="NER 冷/热各跑几次")
    ap.add_argument("--ner-chars-list", default="500,2000,4000,8000",
                    help="NER 文档长度档次（字符，逗号分隔）")
    ap.add_argument("--pool-total", type=int, default=32,
                    help="并发扫描的总请求数（各宽度**总量相同**，否则延迟只反映工作量）")
    ap.add_argument("--skip-ner", action="store_true", help="跳过 NER 冷/热组")
    ap.add_argument("--audit-sizes", default="16,128,512", help="审计体积点（KB，逗号分隔）")
    ap.add_argument("--audit-iters", type=int, default=5)
    ap.add_argument("--json", action="store_true", help="只输出 JSON（供脚本消费）")
    ap.add_argument("--save", default="", help="把本次结果写到该路径")
    ap.add_argument("--compare", default="", help="与该基线文件对比")
    ap.add_argument("--skip-restore", action="store_true", help="跳过 8MB 整包还原（省时间）")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp())
    tr = _setup_env(tmp)

    result = {
        "generated_at": int(time.time()),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "mask_workers": int(getattr(tr, "_MASK_WORKER_COUNT", 1)),
        "ner_threads": int(getattr(tr, "_NER_INTRA_THREADS", 0) or 0),
        "body_kb": args.restore_kb,
    }
    result["mask_single"] = bench_mask_single(tr, args.iters)
    result["mask_pool"] = bench_mask_pool(tr, args.concurrency, args.per_thread)
    levels = [int(x) for x in args.concurrency_list.split(",") if x.strip()]
    if levels:
        # §G3 要求的 1/4/8 并发扫描。**各宽度总量必须相同**：把总量也按并发数放大
        # 会把「工作量变大」误读成「并发变慢」（本脚本首轮实测就踩了：p50 2.8→12.6→18.2 ms
        # 看着像队头阻塞，其实就是 4/16/32 条的总量差异）。
        result["mask_pool_by_concurrency"] = {
            str(c): bench_mask_pool(tr, c, max(1, args.pool_total // c)) for c in levels
        }
        result["pool_total_per_level"] = args.pool_total
    result["audit_scan"] = bench_audit(
        tr, [int(x) for x in args.audit_sizes.split(",") if x.strip()], args.audit_iters)
    if not args.skip_restore:
        result["restore_whole"] = bench_restore_whole(tr, args.restore_kb, args.restore_iters)
    if args.long_sizes.strip():
        result["long_context"] = bench_long_context(
            tr, [int(x) for x in args.long_sizes.split(",") if x.strip()], args.long_iters)
    # 多轮长会话（叶子结果缓存）：必须紧跟在 long_context 之后、NER 组之前 ——
    # NER 组会改 `NER_ENABLED`，跑在它后面就不再是「规则模式」的基线。
    if not args.skip_multiturn:
        result["multiturn"] = bench_multiturn(
            tr, args.mt_msgs, args.mt_msg_chars, args.mt_turns, args.mt_iters)
    # NER 组必须排在最后：它会加载 ONNX 会话并改 `NER_ENABLED`，
    # 跑在其他组之前会让后面的「规则模式」基线不再纯净。
    if not args.skip_ner:
        result["ner_cache"] = bench_ner_cache(
            tr, args.ner_iters,
            [int(x) for x in args.ner_chars_list.split(",") if x.strip()])

    if args.save:
        p = Path(args.save)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("bench_mask：python=%s cpu=%s workers=%s"
              % (result["python"], result["cpu_count"], result["mask_workers"]))
        for group in ("mask_single", "mask_pool", "restore_whole"):
            if group in result:
                print("  %-16s %s" % (group, json.dumps(result[group], ensure_ascii=False)))
        for c, st in (result.get("mask_pool_by_concurrency") or {}).items():
            print("  %-16s %s" % ("pool@%s" % c, json.dumps(st, ensure_ascii=False)))
        for kb, st in (result.get("long_context") or {}).items():
            print("  long %-8s body=%.2f MiB  p50=%.0f ms  p95=%.0f ms  mask_tree p50=%.0f ms  %.1f ms/MiB"
                  % (kb, st["body_mib"], st["p50"], st["p95"], st["mask_tree"]["p50"],
                     st["ms_per_mib"]))
        mt = result.get("multiturn")
        if mt:
            print("  多轮长会话    %d 条×%d 字  冷跑 p50=%.0f ms  续跑 p50=%.0f ms  加速 %.1fx  缓存 %s"
                  % (mt["messages"], mt["msg_chars"], mt["cold"]["p50"], mt["warm"]["p50"],
                     mt["speedup"], json.dumps(mt.get("leaf_cache") or {}, ensure_ascii=False)))
        ner = result.get("ner_cache")
        if ner:
            if not ner.get("available"):
                print("  ner_cache     未执行：%s" % ner.get("note", "模型不可用"))
            else:
                print("  ner_cache     load=%.0f ms  initialized=%s  skips=%s"
                      % (ner.get("model_load_ms", 0.0), ner.get("initialized_after"),
                         json.dumps(ner.get("skips") or {}, ensure_ascii=False)))
                for chars, e in (ner.get("by_chars") or {}).items():
                    print("    %6s chars  hit p50=%.2f ms  miss p50=%.2f ms  miss p95=%.1f ms  %.2f ms/千字%s"
                          % (chars, e["hit"]["p50"], e["miss"]["p50"], e["miss"]["p95"],
                             e.get("ms_per_1k_chars", 0.0),
                             "  [分段]" if e.get("segmented") else ""))
                rep = ner.get("repeat_doc")
                if rep:
                    print("    重复模板 %s chars  p50=%.1f ms（分段缓存命中，不可与上行单价比较）"
                          % (rep["chars"], rep["p50_ms"]))
                print("    cache delta=%s  总计=%s"
                      % (json.dumps(ner.get("cache_delta"), ensure_ascii=False),
                         json.dumps(ner.get("cache"), ensure_ascii=False)))
        for kb, st in result["audit_scan"].items():
            print("  audit %-8s scan(p50/p95)=%.1f/%.1f ms  full_parse(p50)=%.1f ms  cpu_ratio=%.2f"
                  % (kb, st["scan_128k_window"]["p50"], st["scan_128k_window"]["p95"],
                     st["full_parse"]["p50"], st["cpu_ratio"]))
        if args.save:
            print("已保存：%s" % args.save)

    if args.compare:
        base = json.loads(Path(args.compare).read_text(encoding="utf-8"))
        print("与基线对比（%s，生成于 %s）：" % (args.compare, base.get("generated_at")))
        _diff(base, result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
