"""Deterministic cooperative NER lifecycle tests; no model or network required."""
import sys
import threading
import unittest
from collections import OrderedDict
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import ner_engine as ner


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class BudgetLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.addCleanup(ner.end_budget)
        self.clock = Clock()
        self.stack.enter_context(mock.patch.object(ner.time, "monotonic", self.clock))
        self.stack.enter_context(mock.patch.object(ner.time, "sleep", self.clock.advance))
        self.stack.enter_context(mock.patch.object(ner, "_CACHE", OrderedDict()))
        self.stack.enter_context(mock.patch.object(ner, "_CACHE_CHARS", 0))
        self.stack.enter_context(mock.patch.object(ner, "_CACHE_STATS", {"hit": 0, "miss": 0}))
        self.stack.enter_context(mock.patch.object(ner, "_SEM", threading.Semaphore(1)))
        self.init = self.stack.enter_context(mock.patch.object(ner, "_init_ner", return_value=True))
        self.take = self.stack.enter_context(mock.patch.object(ner, "_bucket_take", return_value=True))
        self.refund = self.stack.enter_context(mock.patch.object(ner, "_bucket_refund"))
        self.decode = self.stack.enter_context(mock.patch.object(ner, "_decode_chunks", return_value=([], True)))
        ner.begin_budget(10)

    def test_expired_request_never_renews_and_new_begin_resets(self):
        ner.begin_budget(1)
        for now in (102, 162, 221, 10000):
            self.clock.now = now
            self.assertIsNone(ner._current_deadline())
            self.assertTrue(ner._local.doc_active)
            self.assertEqual(ner.extract_entities("测试文本"), [])
        self.init.assert_not_called()
        ner.begin_budget(2)
        self.assertEqual(ner._current_deadline(), 10002)
        self.assertEqual(ner.request_skips(), {})
        self.assertEqual(ner.request_metrics()["cache_miss"], 0)

    def test_absolute_deadline_is_earlier_and_end_clears_cancel(self):
        event = threading.Event()
        ner.begin_budget(10, deadline=101, cancel_event=event)
        self.assertEqual(ner._current_deadline(), 101)
        event.set()
        self.assertIsNone(ner._current_deadline())
        ner.end_budget()
        self.assertEqual(ner._current_deadline(), 110)
        self.assertIsNone(ner._local.cancel_event)

    def test_initialization_crosses_deadline_no_inference(self):
        def initialize():
            self.clock.advance(2)
            return True
        self.init.side_effect = initialize
        ner.begin_budget(1)
        ner.extract_entities("测试文本")
        self.decode.assert_not_called()
        self.take.assert_not_called()
        self.assertEqual(ner.request_metrics()["init_ms"], 2000)
        self.assertEqual(ner.request_skips(), {"deadline": 1})

    def test_token_wait_crosses_deadline_refunds_no_inference(self):
        self.take.return_value = False
        def wait(*args):
            self.clock.advance(11)
            return True
        with mock.patch.object(ner, "_bucket_wait", side_effect=wait):
            ner.extract_entities("测试文本")
        self.decode.assert_not_called()
        self.refund.assert_called_once()
        self.assertEqual(ner.request_metrics()["budget_wait_ms"], 11000)

    def test_token_wait_records_actual_failure_time(self):
        self.take.return_value = False
        def wait(*args):
            self.clock.advance(0.25)
            return False
        with mock.patch.object(ner, "_bucket_wait", side_effect=wait):
            ner.extract_entities("测试文本")
        self.assertEqual(ner.request_metrics()["budget_wait_ms"], 250)
        self.assertEqual(ner.request_metrics()["global_throttled"], 1)

    def test_semaphore_acquired_after_deadline_released_without_infer(self):
        def acquire(**kwargs):
            self.assertGreater(kwargs["timeout"], 0)
            self.clock.advance(2)
            return True
        sem = mock.Mock()
        sem.acquire.side_effect = acquire
        ner.begin_budget(1)
        with mock.patch.object(ner, "_SEM", sem):
            ner.extract_entities("测试文本")
        self.decode.assert_not_called()
        sem.release.assert_called_once()
        self.refund.assert_called_once()
        self.assertEqual(ner.request_metrics()["sem_wait_ms"], 2000)

    def test_semaphore_failed_wait_is_measured(self):
        def acquire(**kwargs):
            self.clock.advance(kwargs["timeout"])
            return False
        sem = mock.Mock()
        sem.acquire.side_effect = acquire
        with mock.patch.object(ner, "_SEM", sem):
            ner.extract_entities("测试文本")
        self.assertAlmostEqual(ner.request_metrics()["sem_wait_ms"], 2000)
        self.assertEqual(ner.request_metrics()["sem_timeout"], 1)
        sem.release.assert_not_called()

    def test_cancelled_complete_decode_is_not_cached_and_slot_is_held(self):
        event = threading.Event()
        ner.begin_budget(10, cancel_event=event)
        def decode(*args):
            self.assertFalse(ner._SEM.acquire(blocking=False))
            event.set()
            self.clock.advance(0.5)
            return [], True
        self.decode.side_effect = decode
        ner.extract_entities("测试文本")
        self.assertNotIn("测试文本", ner._CACHE)
        self.assertEqual(ner.request_metrics()["infer_ms"], 500)
        self.assertEqual(ner.request_metrics()["calls"], 1)
        self.assertTrue(ner._SEM.acquire(blocking=False))
        ner._SEM.release()

    def test_cancelled_partial_positive_result_never_poison_cache(self):
        event = threading.Event()
        ner.begin_budget(10, cancel_event=event)
        entity = {"type": "NAME", "start": 0, "end": 2, "text": "测试"}
        def decode(*args):
            event.set()
            return [entity], False
        self.decode.side_effect = decode
        self.assertEqual(ner.extract_entities("测试文本"), [entity])
        # §G1：缓存键是进程密钥摘要，不再是原文本身（键里不得留原文）。
        self.assertNotIn(ner._cache_fingerprint("测试文本"), ner._CACHE)
        ner.begin_budget(10)
        self.decode.side_effect = None
        self.decode.return_value = ([entity], True)
        self.assertEqual(ner.extract_entities("测试文本"), [entity])
        self.assertIn(ner._cache_fingerprint("测试文本"), ner._CACHE)
        self.assertEqual(self.decode.call_count, 2)

    def test_complete_cache_hit_survives_inference_expiry_but_not_cancellation(self):
        ner.extract_entities("测试文本")
        ner.extract_entities("测试文本")
        self.assertEqual(ner.request_metrics()["cache_hit"], 1)
        self.assertEqual(ner.request_metrics()["cache_miss"], 1)
        self.assertEqual(ner.request_metrics()["calls"], 1)
        self.decode.assert_called_once()
        self.clock.advance(11)
        ner.extract_entities("测试文本")
        self.assertEqual(ner.request_metrics()["cache_hit"], 2)
        self.decode.assert_called_once()
        event = threading.Event()
        event.set()
        ner.begin_budget(10, cancel_event=event)
        ner.extract_entities("测试文本")
        self.assertEqual(ner.request_metrics()["cache_hit"], 0)
        self.assertEqual(ner.request_skips(), {"cancelled": 1})

    def test_cancel_during_token_wait_stops_polling(self):
        event = threading.Event()
        ner.begin_budget(10, cancel_event=event)
        self.take.side_effect = lambda _: event.set() or False
        self.assertFalse(ner._bucket_wait(1, 2))
        self.assertLessEqual(self.clock.now, 100.05)
        self.assertEqual(self.take.call_count, 1)


class DecodeBoundaryTests(unittest.TestCase):
    def test_tokenization_and_each_onnx_window_obey_deadline_and_cancel(self):
        # Lightweight fake numpy lets these boundary tests run with stdlib only.
        np = SimpleNamespace(array=lambda value, **kw: value,
                             zeros_like=lambda value, **kw: value,
                             argmax=lambda *a, **kw: [0], int64=int)
        original_decode = ner._decode_chunks
        for stop_at in ("before", "tokenize", "run", "second_window"):
            with self.subTest(stop_at=stop_at), ExitStack() as stack:
                clock = Clock()
                event = threading.Event()
                stack.enter_context(mock.patch.object(ner.time, "monotonic", clock))
                stack.enter_context(mock.patch.dict(sys.modules, {"numpy": np}))
                encoded = SimpleNamespace(ids=[1], attention_mask=[1], offsets=[(0, 1)])
                tokenizer = mock.Mock()
                def encode(text):
                    if stop_at == "tokenize":
                        clock.advance(11)
                    return encoded
                tokenizer.encode.side_effect = encode
                session = mock.Mock()
                def run(*args):
                    if stop_at in ("run", "second_window"):
                        event.set()
                    return [[[0]]]
                session.run.side_effect = run
                stack.enter_context(mock.patch.object(ner, "_TOKENIZER", tokenizer))
                stack.enter_context(mock.patch.object(ner, "_SESSION", session))
                stack.enter_context(mock.patch.object(ner, "_ID2LABEL", {"0": "O"}))
                ner.begin_budget(10, cancel_event=event)
                try:
                    if stop_at == "before":
                        clock.advance(11)
                    text = "测试" * (400 if stop_at == "second_window" else 2)
                    _, complete = original_decode(text, 110)
                    self.assertFalse(complete)
                    expected = 1 if stop_at in ("run", "second_window") else 0
                    self.assertEqual(session.run.call_count, expected)
                    self.assertEqual(ner.request_metrics()["windows"], expected)
                    if stop_at == "before":
                        tokenizer.encode.assert_not_called()
                finally:
                    ner.end_budget()


if __name__ == "__main__":
    unittest.main()
