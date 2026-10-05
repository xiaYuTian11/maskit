"""Request-hook integration of cooperative cancellation and transport safety."""
import asyncio
import concurrent.futures
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import transparent as tr
import ner_engine as ner


class RequestLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        for patch in (
            mock.patch.object(tr, "_maybe_reload", lambda *a, **k: None),
            mock.patch.object(tr, "write_runtime_metrics", lambda *a, **k: None),
            mock.patch.object(tr, "_emit", lambda typ, **kw: self.events.append((typ, kw))),
            mock.patch.object(tr, "CAPTURE_MODE", "reverse"),
            mock.patch.object(tr, "FILTER_ENABLED", True),
            mock.patch.object(tr, "UPSTREAMS", [{"name": "test", "port": 18701,
                "base_path": "/test", "target": "https://example.invalid", "paths": ["/v1"]}]),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.baseline = tr.mask_pool_stats()["inflight"]

    def flow(self):
        return SimpleNamespace(
            request=tr.http.Request.make("POST", "http://127.0.0.1:18701/v1/chat/completions",
                json.dumps({"model": "local-test", "messages": [{"role": "user", "content": "测试内容"}]}).encode(),
                {"content-type": "application/json"}),
            client_conn=SimpleNamespace(id="test-client", sockname=("127.0.0.1", 18701)),
            response=None, metadata={})

    async def wait(self, predicate):
        async with asyncio.timeout(3):
            while not predicate():
                await asyncio.sleep(.001)

    def test_queued_timeout_never_starts_mask_work_and_releases_when_dequeued(self):
        release, occupied = threading.Event(), threading.Event()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        def occupy():
            occupied.set()
            release.wait(4)
        pool.submit(occupy)
        self.assertTrue(occupied.wait(2))
        flow = self.flow()
        async def exercise():
            await tr.request(flow)
            self.assertEqual(flow.response.status_code, 503)
            self.assertIn(b"engine_timeout", flow.response.content)
            self.assertEqual(tr.mask_pool_stats()["inflight"], self.baseline + 1)
            release.set()
            await self.wait(lambda: tr.mask_pool_stats()["inflight"] == self.baseline)
            await self.wait(lambda: not flow.metadata.get("shield_mask_pending"))
            self.assertNotIn(flow.metadata["session_id"], tr.sessions)
        with mock.patch.object(tr, "_MASK_POOL", pool), \
             mock.patch.object(tr, "_ENGINE_DEADLINE_S", .03), \
             mock.patch.object(tr, "_mask_tree") as mask:
            try:
                asyncio.run(exercise())
                mask.assert_not_called()
            finally:
                release.set()
                pool.shutdown(wait=True)
        self.assertFalse(any(typ == "MASK" for typ, _ in self.events))
        self.assertNotIn("test-client", tr._MASK_CANCEL_BY_CLIENT)

    def test_client_disconnect_is_propagated_to_running_worker(self):
        entered, release = threading.Event(), threading.Event()
        flow = self.flow()
        def blocked(value, *args, **kwargs):
            entered.set()
            release.wait(3)
            return value
        async def exercise():
            task = asyncio.create_task(tr.request(flow))
            await self.wait(entered.is_set)
            tr.client_disconnected(flow.client_conn)
            self.assertTrue(flow._shield_mask_cancel.is_set())
            self.assertNotIn("shield_mask_cancel", flow.metadata)
            release.set()
            await task  # normal hook completion lets mitmproxy drain the stream error
            self.assertEqual(flow.response.status_code, 503)
            self.assertIn(b"shield_request_cancelled", flow.response.content)
            await self.wait(lambda: tr.mask_pool_stats()["inflight"] == self.baseline)
        with mock.patch.object(tr, "_mask_tree", blocked):
            try:
                asyncio.run(exercise())
            finally:
                release.set()
        self.assertFalse(any(typ == "MASK" for typ, _ in self.events))
        self.assertNotIn("test-client", tr._MASK_CANCEL_BY_CLIENT)

    def test_complete_positive_cache_survives_inference_budget_exhaustion(self):
        text = "语义缓存回归专用名字"
        entity = {"type": "NAME", "start": 0, "end": 2, "text": text[:2]}
        # §G1：键是进程密钥摘要，值只有 (start,end,type)，原文不留在缓存里。
        ner._cache_put(ner._cache_fingerprint(text), [entity], len(text))
        event = threading.Event()
        try:
            ner.begin_budget(-120, cancel_event=event)
            with mock.patch.object(ner, "_init_ner") as init:
                self.assertEqual(ner.extract_entities(text), [entity])
                init.assert_not_called()
                event.set()
                self.assertEqual(ner.extract_entities(text), [])
        finally:
            ner.end_budget()
            with ner._CACHE_LOCK:
                popped = ner._CACHE.pop(ner._cache_fingerprint(text), None)
                if popped is not None:
                    ner._CACHE_CHARS -= int(popped[0])

    def test_recursive_leaf_boundary_stops_large_message_array_after_cancel(self):
        event = threading.Event()
        old = getattr(tr._MASK_WORK_CONTEXT, "control", None)
        tr._MASK_WORK_CONTEXT.control = (None, event)
        def first_leaf(value, *args, **kwargs):
            event.set()
            return value
        try:
            with mock.patch.object(tr, "_mask_hit", side_effect=first_leaf) as hit:
                with self.assertRaises(asyncio.CancelledError):
                    tr._mask_tree(["测试内容"] * 10000, "cancel-tree")
                self.assertEqual(hit.call_count, 1)
        finally:
            tr._MASK_WORK_CONTEXT.control = old

    def test_unsafe_request_streaming_is_rejected_before_body_forwarding(self):
        flow = self.flow()
        with mock.patch.object(tr.ctx, "options", SimpleNamespace(stream_large_bodies="1m"), create=True):
            tr.requestheaders(flow)
            self.assertEqual(flow.response.status_code, 503)
            with self.assertRaises(tr.exceptions.OptionsError):
                tr.configure({"stream_large_bodies"})


if __name__ == "__main__":
    unittest.main()
