"""并发改造的契约：并发宽度（A-5）、准入与背压（A-6/B-4）、端到端 deadline（B-5）、
以及会话态的并发读改写（B-1a ③）。

这些断言针对的都是"限制"类改动 —— 它们出错的形态不是崩溃，而是**悄悄放过**：
队列不封顶（内存爆）、限流不生效（CPU 爆）、计数丢更新（数字对不上）。
功能测试对这三类全绿，所以必须单独锁。
"""
import ast
import asyncio
import concurrent.futures
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import transparent as tr

FAKE_EMAIL = "bench-user" + "@" + "example" + ".invalid"


class WorkerWidthTests(unittest.TestCase):
    def test_adaptive_width(self):
        # 判据是 `_available_cpu_count()`（cgroup 配额 ∩ 亲和性掩码），不是
        # `os.cpu_count()`：`--cpus=2` 的容器跑在 16 核宿主上时后者报 16，
        # 会给出 4 个 worker（2 个核上撐 4 个线程）。2026-10-04 改为同源判据。
        with mock.patch.object(tr, "MASKIT_MASK_WORKERS_ENV", 0):
            with mock.patch.object(tr, "_available_cpu_count", lambda: 2):
                self.assertEqual(tr._default_mask_workers(), 1, "弱机必须为 1")
            with mock.patch.object(tr, "_available_cpu_count", lambda: 4):
                self.assertEqual(tr._default_mask_workers(), 2)
            with mock.patch.object(tr, "_available_cpu_count", lambda: 8):
                self.assertEqual(tr._default_mask_workers(), 4)
            with mock.patch.object(tr, "_available_cpu_count", lambda: 64):
                self.assertEqual(tr._default_mask_workers(), 4, "上限 4（再多只是互相抢核）")

    def test_width_follows_cgroup_quota_not_host_cores(self):
        """容器配额优先于宿主核数（否则 2c4g 容器会拿到 4 个脱敏 worker + 4 个 aux）。"""
        import ner_engine as ner
        with mock.patch.object(ner, "_cgroup_cpu_quota", lambda: 2.0), \
             mock.patch.object(ner.os, "process_cpu_count", lambda: 16, create=True):
            self.assertEqual(tr._available_cpu_count(), 2)
            with mock.patch.object(tr, "MASKIT_MASK_WORKERS_ENV", 0):
                self.assertEqual(tr._default_mask_workers(), 1)
                self.assertEqual(tr._aux_pool_width(), 1)

    def test_available_cpu_count_falls_back_without_ner_engine(self):
        """拿不到 ner_engine（拆包运行）时不能让池宽计算直接抛异常。"""
        with mock.patch.dict(sys.modules, {"ner_engine": None}):
            self.assertGreaterEqual(tr._available_cpu_count(), 1)

    def test_env_override_wins_and_is_clamped(self):
        with mock.patch.object(tr, "MASKIT_MASK_WORKERS_ENV", 1):
            with mock.patch.object(tr, "_available_cpu_count", lambda: 32):
                self.assertEqual(tr._default_mask_workers(), 1, "MASKIT_MASK_WORKERS=1 必须能压回去")
        with mock.patch.object(tr, "MASKIT_MASK_WORKERS_ENV", 999):
            with mock.patch.object(tr, "_available_cpu_count", lambda: 32):
                self.assertEqual(tr._default_mask_workers(), 16)

    def test_set_mask_workers_swaps_pool(self):
        old = tr._MASK_WORKER_COUNT
        try:
            n = tr.set_mask_workers(3)
            self.assertEqual(n, 3)
            self.assertEqual(tr.mask_pool_stats()["workers"], 3)
            self.assertIsNotNone(tr._MASK_POOL)
        finally:
            tr.set_mask_workers(old)


class AdmissionTests(unittest.TestCase):
    """A-6/B-4：按字节准入 + 条数上限 + 全程归还。"""

    def setUp(self):
        self._snap = dict(tr._MASK_ADMISSION)

    def tearDown(self):
        with tr._MASK_ADMISSION_LOCK:
            tr._MASK_ADMISSION.clear()
            tr._MASK_ADMISSION.update(self._snap)

    def test_byte_budget_rejects_and_counts(self):
        limit = tr._MASK_QUEUE_BYTES
        self.assertTrue(tr._mask_admit(limit // 2))
        self.assertFalse(tr._mask_admit(limit // 2 + 1), "超出字节预算必须拒绝")
        self.assertGreaterEqual(tr.mask_pool_stats()["busy_total"], 1)
        tr._mask_release(limit // 2)

    def test_count_bound_even_for_tiny_bodies(self):
        """字节都很小也不能无限排队：条数同样要有界。"""
        max_inflight = tr._MASK_MAX_INFLIGHT
        for _ in range(max_inflight):
            self.assertTrue(tr._mask_admit(1))
        self.assertFalse(tr._mask_admit(1), "条数上限未生效")
        for _ in range(max_inflight):
            tr._mask_release(1)

    def test_cannot_go_negative(self):
        tr._mask_release(1 << 30)          # 多还也不会把计数压成负数
        st = tr.mask_pool_stats()
        self.assertGreaterEqual(st["inflight"], 0)
        self.assertGreaterEqual(st["queued_bytes"], 0)

    def test_real_worker_releases_quota(self):
        """真跑一次 worker：名额必须自己还回来（否则一次失败就永久少一个槽位）。"""
        tmp = Path(tempfile.mkdtemp())
        # ⚠️ 必须恢复 `_DATA_ROOT`：它是**模块级全局**，测试之间会互相污染
        # （实测：把临时数据目录留给后面的用例，ext_bridge 那一组会连锁失败）。
        orig_root, orig_emit = tr._DATA_ROOT, tr._emit
        try:
            tr._DATA_ROOT = tmp
            (tmp / "config.json").write_text(json.dumps({"fail_closed": True}), encoding="utf-8")
            tr._maybe_reload(force=True)
            tr._emit = lambda *a, **k: None
            before = tr.mask_pool_stats()
            body = {"messages": [{"role": "user", "content": "hello"}]}
            raw = json.dumps(body).encode("utf-8")
            self.assertTrue(tr._mask_admit(len(raw)))
            tr._mask_pipeline_worker(body, "adm-sid", raw, False, False, True,
                                     time.perf_counter())
            after = tr.mask_pool_stats()
            self.assertEqual(after["inflight"], before["inflight"])
            self.assertEqual(after["queued_bytes"], before["queued_bytes"])
        finally:
            tr._DATA_ROOT, tr._emit = orig_root, orig_emit
            tr._maybe_reload(force=True)

    def test_worker_releases_quota_on_exception(self):
        """worker 抛异常也必须归还（异常路径最容易漏，实测就是漏在这）。"""
        before = tr.mask_pool_stats()
        # 准入与归还用的是**同一个字节数**（生产里两边都是 len(raw_content)），
        # 所以这里构造等长的 body，否则测的是自己的参数不一致而不是归还逻辑。
        raw = b"x" * 64
        self.assertTrue(tr._mask_admit(len(raw)))
        with mock.patch.object(tr, "_ner_doc_budget",
                               side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                tr._mask_pipeline_worker({}, "adm-err", raw, False, False, True, 0.0)
        after = tr.mask_pool_stats()
        self.assertEqual(after["inflight"], before["inflight"], "异常路径漏还名额")
        self.assertEqual(after["queued_bytes"], before["queued_bytes"])


class QueueByteAccountingTests(unittest.TestCase):
    """排队字节必须**恰好**扣一次。

    为什么单独一组：旧用例的基线是 0，而 `max(0, …)` 会把"多扣一次"夹回 0，
    于是「双重扣减」在旧用例里**看起来是通过的**（Reviewer 实测指出）。
    要抓住它，必须让另一个请求的字节留在池子里当"证人"。
    """

    def setUp(self):
        self._snap = dict(tr._MASK_ADMISSION)

    def tearDown(self):
        with tr._MASK_ADMISSION_LOCK:
            tr._MASK_ADMISSION.clear()
            tr._MASK_ADMISSION.update(self._snap)

    def test_queued_bytes_not_double_subtracted(self):
        # A 排队 1000 字节，B 排队 2000 字节
        self.assertTrue(tr._mask_admit(1000))
        self.assertTrue(tr._mask_admit(2000))
        self.assertEqual(tr.mask_pool_stats()["queued_bytes"], 3000)
        # A 开跑：排队字节里只该去掉 A
        tr._mask_dequeued(1000)
        self.assertEqual(tr.mask_pool_stats()["queued_bytes"], 2000,
                         "出队后应只剩 B 的 2000")
        # A 结束：B 还在排队，它的字节**一个也不能少**
        tr._mask_release(1000)
        self.assertEqual(tr.mask_pool_stats()["queued_bytes"], 2000,
                         "释放把别人的排队字节也扣掉了（双重扣减回归，B-4 防线失效）")
        self.assertEqual(tr.mask_pool_stats()["inflight"], 1, "B 仍在飞")

    def test_never_started_request_returns_everything(self):
        """从未开跑的请求（提交线程池失败）必须把 inflight 与排队字节都还回来。"""
        before = tr.mask_pool_stats()
        self.assertTrue(tr._mask_admit(4096))
        tr._mask_abandon(4096)
        after = tr.mask_pool_stats()
        self.assertEqual(after["inflight"], before["inflight"])
        self.assertEqual(after["queued_bytes"], before["queued_bytes"])

    def test_dequeue_then_release_is_net_zero(self):
        """单请求完整生命周期：入队 → 开跑 → 结束，两个计数都回到基线。"""
        before = tr.mask_pool_stats()
        self.assertTrue(tr._mask_admit(777))
        tr._mask_dequeued(777)
        tr._mask_release(777)
        after = tr.mask_pool_stats()
        self.assertEqual(after["queued_bytes"], before["queued_bytes"])
        self.assertEqual(after["inflight"], before["inflight"])


class SubmitFailureTests(unittest.TestCase):
    """提交进线程池失败必须归还名额（否则准入池被永久锁死）。"""

    def setUp(self):
        self._snap = dict(tr._MASK_ADMISSION)

    def tearDown(self):
        with tr._MASK_ADMISSION_LOCK:
            tr._MASK_ADMISSION.clear()
            tr._MASK_ADMISSION.update(self._snap)
        tr._maybe_reload(force=True)

    def test_source_guards_submit_call(self):
        """静态守卫：`run_in_executor` 必须被 try/except 包着并归还名额。

        为什么用静态检查：跑真实 `request()` 需要构造 mitmproxy flow（成本高），
        而这条回归的形态很固定 —— 后人重构提交段时把 try 去掉。扫源码能立刻拦住。
        """
        src = (ROOT / "engine" / "transparent.py").read_text(encoding="utf-8")
        i = src.index("_MASK_POOL, _mask_pipeline_worker")
        window = src[max(0, i - 900):i + 400]
        self.assertIn("_mask_abandon(", window,
                      "提交段没归还名额：worker 没跑时 finally 不会执行（名额永久泄漏）")
        self.assertIn("except Exception", window)

    def test_admission_helpers_are_consistent(self):
        """`_mask_release` 不许碰 queued_bytes（职责单一），`_mask_abandon` 必须两个都还。"""
        src = (ROOT / "engine" / "transparent.py").read_text(encoding="utf-8")
        i_release = src.index("def _mask_release(")
        i_abandon = src.index("def _mask_abandon(")
        body_release = src[i_release:src.index("def ", i_release + 10)]
        body_abandon = src[i_abandon:src.index("def ", i_abandon + 10)]
        self.assertNotIn('["queued_bytes"] = max', body_release,
                         "_mask_release 又去扣 queued_bytes 了（双重扣减会回来）")
        self.assertIn('["queued_bytes"] = max', body_abandon)
        self.assertIn('["inflight"] = max', body_abandon)


class RetryAfterTests(unittest.TestCase):
    def test_retry_after_is_jittered_and_bounded(self):
        """固定 Retry-After 会让被拒客户端同一时刻一起重试（放大风暴）。"""
        vals = [tr._retry_after_seconds() for _ in range(40)]
        self.assertTrue(all(1.0 <= v <= 3.0 for v in vals), vals[:5])
        self.assertGreater(len(set(vals)), 1, "必须带抖动，不能是固定值")


class DeadlineTests(unittest.TestCase):
    def test_timeout_raises_without_killing_the_worker(self):
        """B-5：等待超时抛 TimeoutError，但**不取消**已经在跑的 worker。"""
        started = threading.Event()
        finished = threading.Event()

        def slow():
            started.set()
            time.sleep(0.25)
            finished.set()
            return "done"

        async def main():
            loop = asyncio.get_running_loop()
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                fut = loop.run_in_executor(pool, slow)
                with self.assertRaises(asyncio.TimeoutError):
                    await tr._await_with_deadline(fut, 0.05)
                self.assertFalse(fut.cancelled(), "shield 必须保护 worker 不被取消")
                return True
            finally:
                pool.shutdown(wait=False)

        self.assertTrue(asyncio.run(main()))
        self.assertTrue(started.is_set(), "worker 必须真的开跑了")
        time.sleep(0.4)
        self.assertTrue(finished.is_set(), "worker 必须能跑完（超时不得中断线程）")

    def test_deadline_is_positive_and_configurable(self):
        self.assertGreater(tr._ENGINE_DEADLINE_S, 0)
        self.assertIn("deadline_s", tr.mask_pool_stats())


class SourceGuardTests(unittest.TestCase):
    """静态守卫：这类"分支里少写一个字段"的错误，只有扫源码才抓得住。"""

    def setUp(self):
        self.src = (ROOT / "engine" / "transparent.py").read_text(encoding="utf-8")
        self.tree = ast.parse(self.src)

    def _block_emits(self):
        out = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name) or node.func.id != "_emit":
                continue
            kws = {kw.arg: kw.value for kw in node.keywords}
            if isinstance(kws.get("reason"), ast.Constant) and kws["reason"].value in (
                    "engine_busy", "engine_timeout"):
                out.append(kws)
        return out

    def test_busy_and_timeout_are_emitted_with_source(self):
        found = {kw["reason"].value for kw in self._block_emits()}
        self.assertEqual(found, {"engine_busy", "engine_timeout"},
                         "busy/timeout 两条路径的 BLOCK 事件缺一个（实测集合 %r）" % found)
        for kws in self._block_emits():
            self.assertIn("block_source", kws)

    def test_admission_happens_before_submit(self):
        """准入必须排在提交之前：先提交再拒绝会留下"签发了却没上行"的污染。"""
        i_admit = self.src.index("if not _mask_admit(")
        i_submit = self.src.index("_MASK_POOL, _mask_pipeline_worker,")
        self.assertLess(i_admit, i_submit, "准入判定跑到了提交之后")

    def test_worker_releases_in_finally(self):
        """worker 的归还必须在 finally 里（异常路径也要还）。"""
        i = self.src.index("def _mask_pipeline_worker")
        body = self.src[i:i + 12000]
        self.assertIn("finally:", body)
        j_finally = body.index("finally:")
        self.assertIn("_mask_release(", body[j_finally:j_finally + 200])


class SameSessionRestoreTests(unittest.TestCase):
    """B-1a ③：同一会话被并发还原时，计数不得丢更新（读改写必须进锁）。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig_root = tr._DATA_ROOT        # 全局态，必须还回去
        tr._DATA_ROOT = self.tmp
        (self.tmp / "config.json").write_text(json.dumps({
            "sensitive": {"甲类": ["测试敏感词"]}, "fail_closed": True,
        }, ensure_ascii=False), encoding="utf-8")
        tr._maybe_reload(force=True)
        self._emit = tr._emit
        tr._emit = lambda *a, **k: None
        tr.sessions.clear()

    def tearDown(self):
        tr._emit = self._emit
        tr._DATA_ROOT = self._orig_root
        tr._maybe_reload(force=True)
        tr.sessions.clear()

    def test_concurrent_restore_counts_are_not_lost(self):
        sid = "sync-count"
        tr._new_session(sid)
        # 只放**一个**占位符：计数与调用次数一一对应，丢更新才看得清楚
        # （放两个的话每次调用 +2，断言得跟着乘，反而掩盖问题）。
        masked = tr.mask("联系人 " + FAKE_EMAIL, sid)
        self.assertIn("{{", masked, "脱敏没命中，用例前提不成立")

        n_threads, rounds = 8, 50
        errors = []

        def worker():
            try:
                for _ in range(rounds):
                    tr.restore(masked, sid, final=True)
            except Exception as e:                       # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(errors, [])
        s = tr.sessions[sid]
        total = n_threads * rounds
        self.assertEqual(s["restored"], total,
                         "restored 计数丢了更新（实际 %d，期望 %d）——读改写没进锁"
                         % (s["restored"], total))


class CrossThreadStateGuardTests(unittest.TestCase):
    """跨线程共享状态的读改写必须走带锁入口（0.6.0 的并发口径要前后一致）。

    这两处原先都是裸 `dict[k] += 1` / `dict[k] = ...`，与另一线程的
    `dict(_STATS)` 快照并发就撞 `RuntimeError: dictionary changed size during
    iteration`，而异常被宽 except 吞掉（表现为“审计/指标静默少一条”）。
    写成源码守卫，免得下次又有人图省事直接写回去。
    """

    def test_aux_stats_writes_are_locked(self):
        src = (ROOT / "engine" / "transparent.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        allowed = {"_aux_stat_add", "_aux_stat_max"}
        bad = []
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            if fn.name in allowed:
                continue
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, ast.AugAssign):
                    targets = [node.target]
                else:
                    continue
                for tgt in targets:
                    if (isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name)
                            and tgt.value.id == "_AUX_STATS"):
                        bad.append("%s:%d" % (fn.name, node.lineno))
        self.assertEqual(bad, [],
                         "这些位置绕过带锁入口直接改 _AUX_STATS：%s" % bad)

    def test_mask_timeouts_reads_and_writes_are_locked(self):
        """`_MASK_TIMEOUTS` 的每个读写点都要持 `_MASK_ADMISSION_LOCK`。

        `count` 与 `peak_wait_ms` 分别由事件循环线程与 worker 线程更新，锁外读会
        拿到半更新快照（面板上表现为“计数已增、峰值还是旧的”这种对不上的数字）。
        """
        src = (ROOT / "engine" / "transparent.py").read_text(encoding="utf-8")
        lines = src.splitlines()
        bad = []
        for i, ln in enumerate(lines):
            if "_MASK_TIMEOUTS[" not in ln:
                continue
            indent = len(ln) - len(ln.lstrip())
            inside = False
            # 沿缩进链向上找宿主块：逐层回退到缩进更小的那几行，只要其中某一层是
            # `with _MASK_ADMISSION_LOCK` 就算锁内（`if` 嵌在 `with` 里时最近的一层
            # 是 `if`，只看最近一行会把锁内的代码误判成锁外）。
            probe = indent
            for j in range(i - 1, max(-1, i - 60), -1):
                prev = lines[j]
                if not prev.strip():
                    continue
                pind = len(prev) - len(prev.lstrip())
                if pind < probe:
                    if prev.strip().startswith("with _MASK_ADMISSION_LOCK:"):
                        inside = True
                        break
                    probe = pind
                    if pind == 0:
                        break
            if not inside:
                bad.append("L%d: %s" % (i + 1, ln.strip()))
        self.assertEqual(bad, [],
                         "这些位置直接读/写 _MASK_TIMEOUTS 却不在锁内：%s" % bad)

    def test_canary_registry_access_is_locked(self):
        """`_AUDIT_CANARY_REGISTRY` 的迭代与写入必须持锁（注册/读取/回收在三个线程上）。"""
        src = (ROOT / "engine" / "transparent.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        unchecked = []
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            uses = [n for n in ast.walk(fn)
                    if isinstance(n, ast.Name) and n.id == "_AUDIT_CANARY_REGISTRY"]
            if not uses:
                continue
            has_lock = any(
                isinstance(n, ast.With) and any(
                    getattr(item, "context_expr", None) is not None
                    and isinstance(item.context_expr, ast.Name)
                    and item.context_expr.id == "_AUDIT_CANARY_LOCK"
                    for item in n.items)
                for n in ast.walk(fn))
            if not has_lock:
                unchecked.append(fn.name)
        self.assertEqual(unchecked, [],
                         "这些函数访问 _AUDIT_CANARY_REGISTRY 却没有持锁：%s" % unchecked)


if __name__ == "__main__":
    unittest.main()
