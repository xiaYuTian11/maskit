"""§G1：NER 结果缓存改为「进程密钥摘要」作键、值只保留位置/类别。

为什么单独立测试：缓存原先以**原文**为键、值里还带 `text` 切片，等于把原文在内存
里的保留窗口延长到整个缓存生命周期。改法必须同时满足两条互相拉扯的性质：
  1) 缓存里不再有任何原文副本（键是 HMAC 摘要，值只有 `(start, end, type)`）；
  2) 命中后返回的实体与冷跑**完全一致**（位置与 `text` 从当前文本即时切出）。
只测 1 会漏掉「命中返回错位实体」，只测 2 会漏掉「原文还留着」。

这些用例**不依赖本机 NER 模型**：命中路径在 `_init_ner()` 之前就返回，
所以预置缓存 + 带汉字的文本即可覆盖；无模型时冷跑也不会写缓存，这本身也要断言。
"""
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import ner_engine as ner


class _CacheIsolation(unittest.TestCase):
    def setUp(self):
        self._saved_ver = ner._CACHE_DETECT_VERSION
        with ner._CACHE_LOCK:
            ner._CACHE.clear()
            ner._CACHE_CHARS = 0
            ner._CACHE_STATS["hit"] = 0
            ner._CACHE_STATS["miss"] = 0
        self.addCleanup(self._restore)

    def _restore(self):
        ner._CACHE_DETECT_VERSION = self._saved_ver
        with ner._CACHE_LOCK:
            ner._CACHE.clear()
            ner._CACHE_CHARS = 0

    def _put(self, text, entities):
        fp = ner._cache_fingerprint(text)
        ner._cache_put(fp, entities, len(text))
        return fp


class CacheKeyTests(_CacheIsolation):
    def test_key_is_a_digest_and_never_the_text(self):
        text = "张三在北京朝阳区建国路88号上班"
        fp = ner._cache_fingerprint(text)
        self.assertRegex(fp, re.compile(r"^[0-9a-f]{64}$"))
        self.assertNotIn(text, fp)
        self.assertEqual(fp, ner._cache_fingerprint(text), "同文本必须稳定同键")

    def test_key_separates_texts_and_detect_versions(self):
        a = ner._cache_fingerprint("文本一")
        b = ner._cache_fingerprint("文本二")
        self.assertNotEqual(a, b)
        ner._CACHE_DETECT_VERSION = "ner-v2"
        self.assertNotEqual(a, ner._cache_fingerprint("文本一"),
                            "检测版本变了必须换键，否则会错误复用旧口径的坐标")

    def test_key_includes_model_identity(self):
        """换模型目录必须换键（§G1：模型更换不得错误复用结果）。"""
        with mock.patch.object(ner, "_MODEL_DIR", Path("/models/ner_a")):
            a = ner._cache_fingerprint("同一段文本")
        with mock.patch.object(ner, "_MODEL_DIR", Path("/models/ner_b")):
            b = ner._cache_fingerprint("同一段文本")
        self.assertNotEqual(a, b)


class CacheStorageTests(_CacheIsolation):
    def test_cache_holds_positions_only_no_plaintext(self):
        text = "张三在北京朝阳区建国路88号上班"
        ents = [{"type": "NAME", "start": 0, "end": 2, "text": text[0:2]},
                {"type": "ADDR", "start": 3, "end": 13, "text": text[3:13]}]
        self._put(text, ents)
        dumped = repr(ner._CACHE)
        self.assertNotIn(text, dumped)
        self.assertNotIn(text[0:2], dumped)
        self.assertNotIn(text[3:13], dumped)
        with ner._CACHE_LOCK:
            (stored_len, triples) = next(iter(ner._CACHE.values()))
        self.assertEqual(stored_len, len(text))
        self.assertEqual(triples, [(0, 2, "NAME"), (3, 13, "ADDR")])

    def test_char_accounting_tracks_represented_text_length(self):
        """记账保留「所代表的文本长度」口径（决定长会话能否避免整批被 LRU 挤出）。"""
        text = "x" * 500
        self._put(text, [])
        self.assertEqual(ner.cache_stats()["chars"], 500)

    def test_hits_are_reconstructed_from_current_text(self):
        text = "张三在北京朝阳区建国路88号上班"
        ents = [{"type": "NAME", "start": 0, "end": 2, "text": text[0:2]}]
        self._put(text, ents)
        got = ner.extract_entities(text)
        self.assertEqual(got, ents, "命中返回必须与冷跑逐字节一致（含 text 切片）")
        self.assertEqual(ner.cache_stats()["hit"], 1)

    def test_negative_cache_returns_empty(self):
        text = "这段文字里没有实体"
        self._put(text, [])
        self.assertEqual(ner.extract_entities(text), [])
        self.assertEqual(ner.cache_stats()["hit"], 1)

    def test_overwrite_does_not_inflate_char_accounting(self):
        text = "张三"
        self._put(text, [{"type": "NAME", "start": 0, "end": 2, "text": text}])
        self._put(text, [])
        self.assertEqual(ner.cache_stats()["chars"], len(text), "同键覆盖必须先扣旧值")
        self.assertEqual(ner.cache_stats()["size"], 1)

    def test_entries_are_evicted_when_over_capacity(self):
        with mock.patch.object(ner, "_CACHE_MAX", 3):
            for i in range(5):
                self._put("文本" + str(i), [])
            self.assertEqual(ner.cache_stats()["size"], 3)

    def test_no_cache_write_when_model_is_unavailable(self):
        """没跑完/模型不可用一律不写缓存：写下来会让这段此后永久不再被识别。"""
        with mock.patch.object(ner, "_init_ner", return_value=False):
            self.assertEqual(ner.extract_entities("张三在北京上班"), [])
        with ner._CACHE_LOCK:
            self.assertEqual(len(ner._CACHE), 0)


if __name__ == "__main__":
    unittest.main()
