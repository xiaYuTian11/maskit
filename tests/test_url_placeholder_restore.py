"""URL 百分号编码占位符还原测试（2026-11-18）。

背景：模型生成 Markdown `file:///` 或网页链接时，会把路径中的占位符做 URL 编码，
例如将 `{{编号_xxxxxx}}` 输出成 `%7B%7B%E7%BC%96%E5%8F%B7_xxxxxx%7D%7D`。
旧版 `restore()` 只认花括号与反斜杠转义，导致：
1. 链接中的目录名/参数无法还原；
2. UTF-8 编码末字节（如 `%B7`）与 `_xxxxxx` 拼成 `B7_xxxxxx`，被宽松遍误算成
   大量 `unresolved`。
"""
import sys
import time
import unittest
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import transparent as tr  # noqa: E402


class UrlEncodedPlaceholderRestoreTests(unittest.TestCase):
    def setUp(self):
        self._orig_custom = dict(tr.CUSTOM_WORDS)
        self._orig_disabled = set(tr.SENSITIVE_DISABLED)
        self._orig_word_disabled = dict(tr.SENSITIVE_WORD_DISABLED)
        self._orig_whole = set(tr.SENSITIVE_WORD_WHOLE)

    def tearDown(self):
        tr.CUSTOM_WORDS = self._orig_custom
        tr.SENSITIVE_DISABLED = self._orig_disabled
        tr.SENSITIVE_WORD_DISABLED = self._orig_word_disabled
        tr.SENSITIVE_WORD_WHOLE = self._orig_whole
        tr._refresh_custom_words_sorted()
        tr._sync_custom_word_mappings()

    def _mint(self, sid, text, custom=None):
        tr.sessions.pop(sid, None)
        if custom:
            tr.CUSTOM_WORDS = dict(custom)
            tr.SENSITIVE_DISABLED = set()
            tr.SENSITIVE_WORD_DISABLED = {}
            tr.SENSITIVE_WORD_WHOLE = set()
            tr._refresh_custom_words_sorted()
            tr._sync_custom_word_mappings()
        masked = tr.mask(text, sid)
        m = tr._PLACEHOLDER_RX.search(masked)
        self.assertIsNotNone(m, f"预期生成占位符，实际: {masked!r}")
        return m.group(0), masked

    def test_cjk_markdown_file_link_restores_without_unresolved(self):
        """复现真实故障：file:/// 链接里 `%7B%7B%E7%BC%96%E5%8F%B7_xxxxxx%7D%7D` 必须还原且不计 unresolved。"""
        sid = "url-cjk-link"
        try:
            tok, _ = self._mint(sid, "目录 proj-alpha", custom={"proj-alpha": "编号"})
            encoded = quote(tok, safe="_")
            self.assertIn("%7B%7B", encoded)
            md = f"[App.kt](file:///D:/work/{encoded}/src/App.kt#L10-L20)"
            out = tr.restore(md, sid, final=True)
            self.assertEqual(out, "[App.kt](file:///D:/work/proj-alpha/src/App.kt#L10-L20)")
            s = tr.sessions[sid]
            self.assertEqual(s.get("unresolved", 0), 0, "UTF-8 尾字节不得被宽松遍误计为 unresolved")
            self.assertEqual(s.get("restored", 0), 1)
            self.assertEqual(s.get("degraded", 0), 1)
            self.assertIn(tok, s.get("restored_tokens", set()))
        finally:
            tr.sessions.pop(sid, None)

    def test_ascii_lowercase_spaced_and_encoded_underscore_variants(self):
        """覆盖小写 %7b/%7d、%20 空格填充、%5F 编码下划线以及标签大小写/下划线改写。"""
        sid = "url-variants"
        try:
            tok, _ = self._mint(sid, "连到 host-internal", custom={"host-internal": "IPPRIVATE"})
            body = tok[2:-2]
            label, suffix = body.rsplit("_", 1)
            variants = [
                quote(tok, safe="_"),
                quote(tok, safe="_").lower(),
                f"%7B%7B%20{label.lower()}%20_{suffix}%20%7D%7D",
                f"%7B%7B{label}%5F{suffix}%7D%7D",
                f"%7B%7B{label[:2]}%5f{label[2:]}_{suffix}%7D%7D",
            ]
            for i, frag in enumerate(variants):
                with self.subTest(i=i, frag=frag):
                    tr.sessions[sid]["pending"].clear()
                    out = tr.restore(f"http://{frag}/api", sid, final=True)
                    self.assertEqual(out, "http://host-internal/api")
                    self.assertEqual(tr.sessions[sid].get("unresolved", 0), 0)
        finally:
            tr.sessions.pop(sid, None)

    def test_streaming_survives_every_split_point(self):
        """流式下任意切点切开 `%7B%7B...%7D%7D`（含中文标签和末尾 %），拼接后仍完整还原。"""
        sid = "url-stream-cuts"
        try:
            tok, _ = self._mint(sid, "项目 proj-beta", custom={"proj-beta": "项目名"})
            encoded = quote(tok, safe="_")
            text = f"进度 50% 路径 file:///D:/{encoded}/a.py 完成 100%"
            expected = "进度 50% 路径 file:///D:/proj-beta/a.py 完成 100%"
            self.assertEqual(tr.restore(text, sid, final=True), expected)

            for cut in range(1, len(text)):
                with self.subTest(cut=cut):
                    tr.sessions[sid]["pending"].clear()
                    head = tr.restore(text[:cut], sid, channel="c0")
                    tail = tr.restore(text[cut:], sid, channel="c0", final=True)
                    self.assertEqual(head + tail, expected, f"切点 {cut} 处还原失败")
        finally:
            tr.sessions.pop(sid, None)

    def test_unresolved_url_token_not_double_counted_by_loose_pass(self):
        """查不到原文时按单次 unresolved/foreign 记账，不得被宽松遍再对 `%B7_suffix` 复计一次。"""
        sid = "url-unresolved"
        try:
            tok, _ = self._mint(sid, "编号 proj-gamma", custom={"proj-gamma": "编号"})
            suffix = tr._token_suffix(tok)
            encoded = quote(tok, safe="_")
            # 清空所有映射，模拟过期/重启后映射丢失（但 _ISSUED_SUFFIXES 仍保留该后缀）
            tr.sessions[sid]["rev"].clear()
            tr.sessions[sid]["fwd"].clear()
            tr._RECENT_REV.pop(tok, None)
            tr._CUSTOM_WORD_REV.pop(tok, None)
            tr._tables().suffix.pop(suffix, None)

            out = tr.restore(f"file:///{encoded}", sid, final=True)
            self.assertEqual(out, f"file:///{encoded}")
            s = tr.sessions[sid]
            self.assertEqual(s.get("unresolved", 0), 1, "只应计 1 次，不得与 %B7_suffix 重复计数")
            self.assertEqual(s.get("unresolved_samples"), [encoded])

            # 非本机签发的随机辅音后缀走 foreign，不进 unresolved
            foreign_tok = "{{" + "编号_" + "bcdfgh}}"
            foreign_enc = quote(foreign_tok, safe="_")
            out2 = tr.restore(f"file:///{foreign_enc}", sid, final=True)
            self.assertEqual(out2, f"file:///{foreign_enc}")
            self.assertEqual(s.get("unresolved", 0), 1)
            self.assertEqual(s.get("foreign", 0), 1)
        finally:
            tr.sessions.pop(sid, None)

    def test_invalid_decoded_label_and_missing_session_safety(self):
        """解码后含非法字符（如 `/`）的片段不得误认；无会话时绝不借全局表还原且计数正确。"""
        sid = "url-safety"
        try:
            tok, _ = self._mint(sid, "编号 proj-delta", custom={"proj-delta": "编号"})
            encoded = quote(tok, safe="_")
            # 1) 含 %2F（斜杠）解码后不是合法标签，直接放行且不计入异常
            bogus = "%7B%7Bfoo%2Fbar_bcdfgh%7D%7D"
            self.assertEqual(tr.restore(bogus, sid, final=True), bogus)
            self.assertEqual(tr.sessions[sid].get("unresolved", 0), 0)
            self.assertEqual(tr.sessions[sid].get("foreign", 0), 0)

            # 2) 会话不存在时安全门禁止还原，并如实记录孤儿计数
            missing_sid = "ext:url-missing-session"
            tr.sessions.pop(missing_sid, None)
            tr._NO_SESSION_ORPHANS.pop(missing_sid, None)
            out = tr.restore(f"file:///{encoded}", missing_sid, final=True)
            self.assertEqual(out, f"file:///{encoded}", "无会话时不得借全局复用表还原")
            cnt, samples, _f, _fs = tr._take_orphans_without_session(missing_sid)
            self.assertEqual(cnt, 1)
            self.assertEqual(samples, [encoded])
        finally:
            tr.sessions.pop(sid, None)

    def test_escape_json_for_url_encoded_placeholder(self):
        """tool 参数等 escape=True 路径下，URL 编码占位符还原出的引号仍须做 JSON 转义。"""
        sid = "url-escape"
        try:
            tok, _ = self._mint(sid, '代号 a"b', custom={'a"b': "编号"})
            encoded = quote(tok, safe="_")
            payload = f'{{"url": "file:///D:/{encoded}/x"}}'
            out = tr.restore(payload, sid, escape=True, final=True)
            self.assertEqual(out, r'{"url": "file:///D:/a\"b/x"}')
        finally:
            tr.sessions.pop(sid, None)

    def test_partial_and_url_regex_linear_on_long_percent_noise(self):
        """海量 `%` / `%7B` 噪声输入不得触发正则回溯退化。"""
        noise = "%7B%7B" + ("%" * 8000) + ("%7B" * 2000) + ("a" * 8000)
        t0 = time.perf_counter()
        self.assertIsNone(tr._URL_PLACEHOLDER_RX.search(noise))
        tr._PARTIAL_RX.search(noise)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        self.assertLess(elapsed_ms, 50.0, f"正则耗时过高: {elapsed_ms:.2f}ms")


if __name__ == "__main__":
    unittest.main()
