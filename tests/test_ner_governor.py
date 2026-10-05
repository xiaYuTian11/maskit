"""B-2：NER 进程级治理器（初始化原子化 + 信号量 + 令牌桶）+ A-4（推理线程自适应）。

为什么这些测试必须有：治理器的作用是**限制消耗**，而限错了方向（限太狠/限错位置）
在功能测试里完全看不出来 —— 脱敏结果照样正确，只是悄悄少识别了一些实体。
所以这里逐条锁住：什么情况下该跳过、跳过记在哪个键上、指标有没有落到事件里。
"""
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import ner_engine as ner


class InitAtomicityTests(unittest.TestCase):
    """`_init_ner()` 的双检必须是原子的（并发下只能建一个 InferenceSession）。"""

    def setUp(self):
        self.old = (ner._SESSION, ner._TOKENIZER, ner._ID2LABEL,
                    ner._INITIALIZED, ner._INIT_FAILED, ner._LAST_ERROR, ner._INTRA_THREADS)
        ner._SESSION = None
        ner._TOKENIZER = None
        ner._ID2LABEL = {}
        ner._INITIALIZED = False
        ner._INIT_FAILED = False
        ner._LAST_ERROR = ""
        ner._INTRA_THREADS = 0
        # 造一份「模型文件齐备」的临时目录。只 mock onnxruntime/tokenizers 不够：
        # `_init_ner_locked` 会在模型文件齐备后 open(config.json) 读 id2label，而
        # CI 与任何不带 engine/models/（gitignore）的环境会在 open() 处抛
        # FileNotFoundError 落到「初始化失败」分支，于是这两个原子性用例变成
        # 「本机绿、CI 红」。用真实存在的占位文件走通「文件齐备 → 建会话」这条路，
        # 用例测的仍是双检原子性与线程数推导，不依赖真实语义模型。
        self._model_tmp = tempfile.TemporaryDirectory()
        model_dir = Path(self._model_tmp.name)
        (model_dir / "tokenizer.json").write_text("{}", encoding="utf-8")
        (model_dir / "model_quantized.onnx").write_bytes(b"")
        (model_dir / "config.json").write_text('{"id2label": {"0": "O"}}', encoding="utf-8")
        self._model_dir_patch = mock.patch.object(ner, "_MODEL_DIR", model_dir)
        self._model_dir_patch.start()

    def tearDown(self):
        self._model_dir_patch.stop()
        self._model_tmp.cleanup()
        (ner._SESSION, ner._TOKENIZER, ner._ID2LABEL,
         ner._INITIALIZED, ner._INIT_FAILED, ner._LAST_ERROR, ner._INTRA_THREADS) = self.old

    def _fake_modules(self, created, opts_seen):
        def make_session(path, sess_options=None, providers=None):
            created.append(path)
            time.sleep(0.02)              # 放大竞态窗口，让"双检非原子"必然暴露
            opts_seen.append(sess_options)
            return object()

        class _Opts:
            def __init__(self):
                self.intra_op_num_threads = 1
                self.graph_optimization_level = None

        fake_ort = types.SimpleNamespace(
            SessionOptions=_Opts,
            GraphOptimizationLevel=types.SimpleNamespace(ORT_ENABLE_ALL=99),
            InferenceSession=make_session,
        )
        tok = types.SimpleNamespace(from_file=lambda p: object())
        fake_tok = types.SimpleNamespace(Tokenizer=tok)
        return fake_ort, fake_tok

    def test_concurrent_init_creates_exactly_one_session(self):
        created, opts_seen = [], []
        fake_ort, fake_tok = self._fake_modules(created, opts_seen)
        errs = []

        def worker():
            try:
                ner._init_ner()
            except Exception as e:                       # pragma: no cover
                errs.append(e)

        with mock.patch.object(ner, "is_ner_available", lambda: True), \
             mock.patch.dict(sys.modules, {"onnxruntime": fake_ort, "tokenizers": fake_tok}):
            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
        self.assertEqual(errs, [])
        self.assertEqual(len(created), 1,
                         "并发初始化建了 %d 个 session（模型内存与 ONNX 线程会翻倍）" % len(created))
        self.assertTrue(ner._INITIALIZED)

    def test_intra_threads_are_adaptive_and_reported(self):
        """A-4：ONNX 推理线程按核数自适应，并且能被 status/指标看到。"""
        created, opts_seen = [], []
        fake_ort, fake_tok = self._fake_modules(created, opts_seen)
        with mock.patch.object(ner, "is_ner_available", lambda: True), \
             mock.patch.dict(os.environ, {"MASKIT_NER_THREADS": "2"}), \
             mock.patch.dict(sys.modules, {"onnxruntime": fake_ort, "tokenizers": fake_tok}):
            self.assertTrue(ner._init_ner())
        self.assertEqual(opts_seen[0].intra_op_num_threads, 2, "MASKIT_NER_THREADS 未生效")
        self.assertEqual(ner._INTRA_THREADS, 2)
        self.assertEqual(ner.status()["governor"]["intra_threads"], 2)

    def test_intra_threads_default_is_bounded_by_cpu(self):
        """默认线程数按**实际可用**核数取，上限 4。

        判据从 os.cpu_count() 换成 effective_cpu_count() 是 2026-10-04 批次 8 的
        有意改动：容器 `--cpus=2` 跑在 16 核宿主上时前者报 16（于是开 4 个 ONNX
        线程把 CFS 配额吃满），后者报 2。测试跟着钉住新判据。
        """
        with mock.patch.object(ner, "effective_cpu_count", lambda: 2):
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("MASKIT_NER_THREADS", None)
                self.assertEqual(ner._intra_threads(), 2)
        with mock.patch.object(ner, "effective_cpu_count", lambda: 64):
            os.environ.pop("MASKIT_NER_THREADS", None)
            self.assertEqual(ner._intra_threads(), 4, "不该超过 4 线程（再多只会互相抢核）")
        with mock.patch.object(ner, "effective_cpu_count", lambda: 0):
            os.environ.pop("MASKIT_NER_THREADS", None)
            self.assertGreaterEqual(ner._intra_threads(), 1)

    def test_missing_model_fails_once_and_is_reported(self):
        """模型缺失：初始化失败要记在案，且不得反复重试（否则每次请求都 stat + 建锁）。"""
        with mock.patch.object(ner, "is_ner_available", lambda: False):
            self.assertFalse(ner._init_ner())
            self.assertTrue(ner._INIT_FAILED)
            self.assertIn("model_missing", ner._SKIP_STATS)
            before = len(ner._SKIP_LOGGED)
            self.assertFalse(ner._init_ner())      # 第二次直接返回 False
            self.assertEqual(len(ner._SKIP_LOGGED), before, "重复告警了")


class _AlwaysAcquire:
    """槽位替身：总是立刻拿到（让用例只测"桶"这一条路径）。"""

    def acquire(self, timeout=None):
        return True

    def release(self):
        pass


class GovernorTests(unittest.TestCase):
    def setUp(self):
        ner.request_metrics(reset=True)
        ner._SKIP_STATS.pop("global_throttled", None)
        ner._SKIP_STATS.pop("sem_timeout", None)
        self._deadline_patch = mock.patch.object(ner, "_init_ner", lambda: True)
        self._deadline_patch.start()

    def tearDown(self):
        self._deadline_patch.stop()
        ner.request_metrics(reset=True)

    def _fill_bucket(self, tokens):
        with ner._BUCKET_LOCK:
            ner._BUCKET["tokens"] = float(tokens)
            ner._BUCKET["ts"] = time.monotonic()

    def test_bucket_skips_when_out_of_budget(self):
        """额度耗尽**且不等待**时：跳过 + 记 global_throttled。

        默认行为已改为「有界等待」（见 BudgetWaitTests）；本用例固定
        `MASKIT_NER_WAIT_MS=0` 回到“立即跳过”，锁住的仍是降级路径本身。
        """
        self._fill_bucket(0)
        with mock.patch.object(ner, "_NER_BUDGET_MS_PER_S", 1), \
             mock.patch.object(ner, "_NER_BUDGET_WAIT_MS", 0):
            out = ner.extract_entities("客户张大锤在杭州西湖区上班" * 3)
        self.assertEqual(out, [])
        self.assertGreaterEqual(ner._SKIP_STATS.get("global_throttled", 0), 1)
        self.assertEqual(ner.request_metrics()["global_throttled"], 1)

    def test_bucket_refills_over_time(self):
        self._fill_bucket(0)
        with mock.patch.object(ner, "_NER_BUDGET_MS_PER_S", 1000):
            time.sleep(0.02)
            self.assertTrue(ner._bucket_take(5.0), "额度应按时间补充")
        self._fill_bucket(0)

    def test_bucket_refund_never_exceeds_capacity(self):
        self._fill_bucket(0)
        ner._bucket_refund(10_000_000)
        with ner._BUCKET_LOCK:
            self.assertLessEqual(ner._BUCKET["tokens"], float(ner._NER_BUDGET_MS_PER_S))

    def test_semaphore_timeout_skips_and_refunds_budget(self):
        """槽位等不到 → 跳过 + 记 sem_timeout，并且把预支的额度还回去。"""
        self._fill_bucket(100000)                       # 额度充足，确保测的是槽位这条路
        grabbed = ner._SEM.acquire(timeout=1)           # 占满（并发数可能是 2）
        extra = []
        while ner._SEM.acquire(blocking=False):
            extra.append(1)
        try:
            with mock.patch.object(ner, "_SEM_WAIT_MAX_S", 0.05):
                t0 = time.perf_counter()
                out = ner.extract_entities("客户张大锤在杭州西湖区上班" * 3)
                took = time.perf_counter() - t0
            self.assertEqual(out, [])
            self.assertLess(took, 1.0, "不应长时间阻塞（实测 %.2fs）" % took)
            self.assertGreaterEqual(ner._SKIP_STATS.get("sem_timeout", 0), 1)
            self.assertEqual(ner.request_metrics()["sem_timeout"], 1)
            # 桶容量就是 _NER_BUDGET_MS_PER_S，退还后应回到接近满桶
            # （退款会被容量钳制，所以判"接近满"而不是"大于预支量"）
            self.assertGreater(ner._BUCKET["tokens"], ner._NER_BUDGET_MS_PER_S * 0.9,
                               "没跑成就必须退还预支额度")
        finally:
            for _ in extra:
                ner._SEM.release()
            if grabbed:
                ner._SEM.release()

    def test_long_leaf_still_reaches_inference_on_a_full_bucket(self):
        """长文本叶子**必须**能进入推理（0.6.0 修的关键回归点）。

        背景：单条估价 = 字数 × `_EST_CPU_MS_PER_CHAR`（CPU 毫秒/字），而桶容量 = 每秒
        补充量。若拿**未夹的**估价去 `_bucket_take`，那么超过容量/单价的叶子**永远**
        拿不到额度 —— 不是"负载降级"，而是"这些文本永久不做语义识别"，用户只看到
        计数上涨。

        用例刻意不绑定 `MAX_TEXT_CHARS` 与桶容量这两个常量的具体取值（2026-09-30
        分段粒度从 20000 收到 4000 时，旧写法靠"18000 字"同时满足两个前提，一改就红）：
        改为①文本取满一个段，②把每秒额度压到"估价必然超过容量"的水位。
        """
        self._fill_bucket(ner._NER_BUDGET_MS_PER_S)          # 满桶
        text = "项目进度记录与联系人信息说明，含机构名称、详细地址与业务备注等内容。" * 200
        text = text[: ner.MAX_TEXT_CHARS]
        with mock.patch.object(ner, "_NER_BUDGET_MS_PER_S", 300):
            self.assertGreater(len(text) * ner._EST_CPU_MS_PER_CHAR,
                               ner._NER_BUDGET_MS_PER_S, "用例前提：估价必须超过桶容量")
            reached = []
            # 注意：`_decode_chunks` 返回二元组 (entities, complete)，桩必须同形状
            # （第一版只回列表，用例自己报 ValueError，等于白测）。
            stub = lambda *a, **k: (reached.append(1), ([], True))[1]  # noqa: E731
            with mock.patch.object(ner, "_decode_chunks", stub), \
                    mock.patch.object(ner, "_init_ner", lambda: True), \
                    mock.patch.object(ner, "_SEM", _AlwaysAcquire()):
                out = ner.extract_entities(text)
        self.assertEqual(out, [])
        self.assertTrue(reached,
                        "长文本叶子在满桶时仍未进入推理：估价未被夹到桶容量"
                        "（长文本永久漏码，且只在计数上看得到）")
        self.assertEqual(ner.request_metrics().get("global_throttled", 0), 0,
                         "不该被记为预算耗尽")

    def test_metrics_are_cleared_per_request(self):
        """指标按请求记账、取完即清（否则事件里会出现上一轮的等待时长）。"""
        self._fill_bucket(0)
        with mock.patch.object(ner, "_NER_BUDGET_MS_PER_S", 1), \
             mock.patch.object(ner, "_NER_BUDGET_WAIT_MS", 0):
            ner.extract_entities("客户张大锤" * 3)
        first = ner.request_metrics(reset=True)
        self.assertEqual(first["global_throttled"], 1)
        second = ner.request_metrics(reset=True)
        self.assertEqual(second.get("global_throttled", 0), 0)

    def test_governor_status_shape(self):
        st = ner.governor_status()
        for key in ("concurrency", "budget_ms_per_s", "bucket_tokens_ms", "inflight",
                    "peak_inflight", "waits", "wait_ms_total", "wait_ms_max", "timeouts",
                    "skipped_throttled", "skipped_sem_timeout", "intra_threads"):
            self.assertIn(key, st)
        self.assertIn("governor", ner.status(), "status() 必须带上治理器（面板读它）")


class BudgetWaitTests(unittest.TestCase):
    """额度不足时的**有界等待**（不是无界排队，也不是立刻跳过）。

    桶的语义是长期速率：持续过载时“等到有额度”可能永远不成立，而无界等待会占住
    脱敏 worker（正是 0.6.0 消掉的队头阻塞）。所以等待必须有上限，超时仍降级。
    """

    def setUp(self):
        self._saved = dict(ner._BUCKET)
        with ner._CACHE_LOCK:
            ner._CACHE.clear()
        ner.request_metrics(reset=True)
        ner._SKIP_STATS.pop("global_throttled", None)
        self.addCleanup(self._restore)
        self.addCleanup(ner.request_metrics, True)

    def _restore(self):
        with ner._BUCKET_LOCK:
            ner._BUCKET.update(self._saved)

    def _drain_bucket(self):
        with ner._BUCKET_LOCK:
            ner._BUCKET["tokens"] = 0.0
            ner._BUCKET["ts"] = time.monotonic()

    def test_bucket_wait_succeeds_when_budget_recovers(self):
        self._drain_bucket()
        self.assertTrue(ner._bucket_wait(1.0, 0.8), "额度会随时间恢复，应当等到")

    def test_bucket_wait_is_bounded(self):
        """等不到就必须返回 False，且耗时接近给定上限（不是无限等）。"""
        self._drain_bucket()
        huge = float(ner._NER_BUDGET_MS_PER_S) * 1000.0    # 远超桶容量 → 永远等不到
        t0 = time.monotonic()
        self.assertFalse(ner._bucket_wait(huge, 0.15), "等不到就该返回")
        self.assertLess(time.monotonic() - t0, 1.5, "等待时间远超上限")

    def test_extract_entities_waits_instead_of_degrading(self):
        """桶空但额度会恢复：应当等到并照常推理，只记 budget_waited、不记降级。"""
        self._drain_bucket()
        with mock.patch.object(ner, "_init_ner", lambda: True), \
             mock.patch.object(ner, "_current_deadline",
                               lambda: time.monotonic() + 30.0), \
             mock.patch.object(ner, "_decode_chunks", lambda text, deadline: ([], True)):
            out = ner.extract_entities("张三在北京工作，联系李四")
        self.assertEqual(out, [])
        m = ner.request_metrics()
        self.assertGreaterEqual(m.get("budget_waited", 0), 1, "等到额度却没记账")
        self.assertEqual(m.get("global_throttled", 0), 0, "能等到就不该降级")
        self.assertNotIn("global_throttled", ner._SKIP_STATS)

    def test_zero_wait_falls_back_to_old_skip_behaviour(self):
        """`MASKIT_NER_WAIT_MS=0`：退回“立即跳过”的旧行为（可回退开关）。"""
        self._drain_bucket()
        with mock.patch.object(ner, "_NER_BUDGET_WAIT_MS", 0), \
             mock.patch.object(ner, "_init_ner", lambda: True), \
             mock.patch.object(ner, "_current_deadline",
                               lambda: time.monotonic() + 30.0), \
             mock.patch.object(ner, "_decode_chunks", lambda text, deadline: ([], True)):
            out = ner.extract_entities("张三在北京工作")
        self.assertEqual(out, [])
        self.assertGreaterEqual(ner.request_metrics().get("global_throttled", 0), 1,
                                "不等待时就该如实记降级")
        self.assertIn("global_throttled", ner._SKIP_STATS)

    def test_budget_waited_is_visible_in_governor_status(self):
        """等到额度的次数必须有一个出口（只写线程本地等于没写）。

        回归背景：`budget_waited` 写入后无任何消费者，而 CHANGELOG / SECURITY 已把
        “它能区分补上了与真降级”当卖点写上——指标不可见就不算存在。
        """
        before = int(ner.governor_status().get("budget_waited") or 0)
        self._drain_bucket()
        with mock.patch.object(ner, "_init_ner", lambda: True), \
             mock.patch.object(ner, "_current_deadline",
                               lambda: time.monotonic() + 30.0), \
             mock.patch.object(ner, "_decode_chunks", lambda text, deadline: ([], True)):
            ner.extract_entities("张三在北京工作，联系李四")
        after = int(ner.governor_status().get("budget_waited") or 0)
        self.assertGreater(after, before,
                           "budget_waited 未进入 governor_status（面板/自检看不到）")

    def test_budget_wait_leaves_room_for_the_slot(self):
        """deadline 只够槽位等待时，预算等待必须收缩为 0。

        否则净效果是：先白等 2 秒、再因槽位窗口只剩 50ms 而 sem_timeout 跳过——
        多花时间、仍不做识别，还占住一个脱敏 worker。
        """
        self._drain_bucket()
        with mock.patch.object(ner, "_init_ner", lambda: True), \
             mock.patch.object(ner, "_current_deadline",
                               lambda: time.monotonic() + 1.0), \
             mock.patch.object(ner, "_decode_chunks", lambda text, deadline: ([], True)):
            t0 = time.monotonic()
            out = ner.extract_entities("张三在北京工作")
            elapsed = time.monotonic() - t0
        self.assertEqual(out, [])
        self.assertLess(elapsed, 0.5,
                        "deadline 剩余不足槽位上限时不该先花时间等预算（实测 %.2fs）" % elapsed)
        self.assertIn("global_throttled", ner._SKIP_STATS)

    def test_extract_entities_still_uses_bounded_wait(self):
        """源码守卫：额度不足的分支必须走 `_bucket_wait`（别退回“立刻跳过”）。"""
        src = Path(ner.__file__).read_text(encoding="utf-8")
        self.assertIn("_bucket_wait(est_ms", src,
                      "额度不足时不再等待（是不是退回立刻跳过了？）")


if __name__ == "__main__":
    unittest.main()
