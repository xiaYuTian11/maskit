"""C1 配置链路测试：config.json → `_read_settings()` → 路由 / sidecar 换代。

这条链是 C1 的真开关：面板把 `takeover` 与 `egress_proxy` 写进 config.json，引擎侧
必须原样读出来（形状也要对）才能驱动 sidecar。链子断在哪一环，用户看到的现象都
一样——「开关开了但没加速」，所以每个环节单独断言。

2026-10-10 审计查明过两处断链，本文件把它们钉住：
- 引擎读侧原先不取 `takeover` → `up.get("takeover")` 恒 False，整个 C1 是哑开关；
- `egress_proxy` 在 `_read_settings()` 里已收成 ServerSpec 元组，而 sidecar 按
  config.json 的 `{"enabled":…, "url":…}` 形状去读，`tuple.get(...)` 当场炸。
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))

import transparent as tr
from shield_defaults import egress_proxy_url, parse_egress_proxy


def _write_config(root, **overrides):
    """把一份最小可用配置写进临时配置根。"""
    cfg = {
        "capture_mode": "reverse",
        "upstreams": [{"name": "a", "base_path": "/a", "port": 18701,
                       "target": "https://x.example.com"}],
    }
    cfg.update(overrides)
    (root / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cfg


class TestC1ConfigChain(unittest.TestCase):
    """config.json 的取值必须逐项走到引擎侧。"""

    def setUp(self):
        self._old_root = tr._DATA_ROOT
        self._tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: setattr(tr, "_DATA_ROOT", self._old_root))
        tr._DATA_ROOT = self._tmp

    def test_takeover_flag_reaches_upstreams(self):
        """takeover=true 必须出现在 `_read_settings()` 的 upstreams 里。

        引擎读侧漏取这个键时，面板开得再多也是哑开关——而且失败是静默的。
        """
        _write_config(self._tmp, upstreams=[{
            "name": "a", "base_path": "/a", "port": 18701,
            "target": "https://x.example.com", "takeover": True,
        }])
        s = tr._read_settings()
        self.assertTrue(s["upstreams"][0]["takeover"])
        with mock.patch.object(tr, "UPSTREAMS", s["upstreams"]):
            self.assertTrue(tr._c1_any_takeover_enabled())

    def test_string_bool_never_reads_as_true(self):
        """手改 config.json 写成字符串时，判据必须严格：`"false"` 不能读成开启。

        接管会改转发路径，判反不是小事——宁可少开不可误开。
        """
        cases = [("true", True), ("True", True), ("1", True),
                 ("false", False), ("no", False), ("", False), ("0", False)]
        for raw, expect in cases:
            with self.subTest(raw=raw):
                _write_config(self._tmp, upstreams=[{
                    "name": "a", "base_path": "/a", "port": 18701,
                    "target": "https://x.example.com", "takeover": raw,
                }])
                s = tr._read_settings()
                self.assertEqual(s["upstreams"][0]["takeover"], expect)

    def test_egress_proxy_spec_is_httpx_ready(self):
        """`_read_settings()` 交出 ServerSpec，`egress_proxy_url()` 必须能转回 httpx 文本。

        两个消费方（mitmproxy 的 `via` 与 sidecar 的 `proxy=`）共用一份形状判据，
        这里锁的就是它们之间那次转换。
        """
        _write_config(self._tmp, egress_proxy={
            "enabled": True, "url": "http://127.0.0.1:7890"})
        s = tr._read_settings()
        spec = s["egress_proxy"]
        self.assertEqual(spec, parse_egress_proxy("http://127.0.0.1:7890"))
        self.assertEqual(egress_proxy_url(spec), "http://127.0.0.1:7890")
        self.assertEqual(tr._c1_egress_proxy_url(s), "http://127.0.0.1:7890")

    def test_egress_proxy_off_or_invalid_is_none(self):
        """关闭/非法地址在两侧都归一成 None（不是空串、也不是原样透传）。"""
        for raw in ({"enabled": False, "url": "http://127.0.0.1:7890"},
                    {"enabled": True, "url": "socks5://127.0.0.1:1080"},
                    {"enabled": True, "url": ""}):
            with self.subTest(raw=raw):
                _write_config(self._tmp, egress_proxy=raw)
                s = tr._read_settings()
                self.assertIsNone(s["egress_proxy"])
                self.assertIsNone(tr._c1_egress_proxy_url(s))

    def test_egress_proxy_url_rejects_malformed_spec(self):
        """形状不对一律 None——包括 config.json 的 dict 形状（第一版就是照它读的）。

        返回值是给 httpx 的，猜错形状比返回 None 危险得多。
        """
        for bad in ({}, {"enabled": True, "url": "http://127.0.0.1:7890"},
                    ("http",), ("http", ("127.0.0.1",)), ("http", ("", 0)),
                    ("http", ("127.0.0.1", 70000)), None, "http://x:1"):
            with self.subTest(bad=bad):
                self.assertIsNone(egress_proxy_url(bad))


class TestC1Reconcile(unittest.TestCase):
    """配置热重载后，sidecar 必须跟着配置换代（否则面板说了不算）。"""

    def setUp(self):
        self._old_sidecar = tr._C1_SIDECAR
        self._old_task = tr._C1_SIDECAR_TASK
        self._old_failed = tr._C1_SIDECAR_FAILED
        self._old_upstreams = tr.UPSTREAMS
        self.addCleanup(self._restore)
        tr._C1_SIDECAR = None
        tr._C1_SIDECAR_TASK = None
        tr._C1_SIDECAR_FAILED = False

    def _restore(self):
        tr._C1_SIDECAR = self._old_sidecar
        tr._C1_SIDECAR_TASK = self._old_task
        tr._C1_SIDECAR_FAILED = self._old_failed
        tr.UPSTREAMS = self._old_upstreams

    def _fake_sidecar(self, egress_url):
        fake = mock.MagicMock()
        fake.egress_url = egress_url
        return fake

    def test_takeover_all_off_retires_sidecar(self):
        """全部上游关掉接管 → 旧连接池必须被摘掉（监听不该继续存在）。"""
        tr.UPSTREAMS = [{"name": "a", "takeover": False}]
        tr._C1_SIDECAR = self._fake_sidecar(None)
        tr._c1_reconcile({"egress_proxy": None})
        self.assertIsNone(tr._C1_SIDECAR)

    def test_egress_change_retires_sidecar(self):
        """改了出口代理 → 旧池停用，下一条请求按新配置重建（代理变更不当没发生）。"""
        tr.UPSTREAMS = [{"name": "a", "takeover": True}]
        tr._C1_SIDECAR = self._fake_sidecar("http://127.0.0.1:7890")
        tr._c1_reconcile({"egress_proxy": parse_egress_proxy("http://127.0.0.1:7891")})
        self.assertIsNone(tr._C1_SIDECAR)

    def test_unchanged_config_keeps_sidecar(self):
        """配置没变就不要动连接池——重建等于把跨客户端复用的池子白白扔掉。"""
        tr.UPSTREAMS = [{"name": "a", "takeover": True}]
        fake = self._fake_sidecar("http://127.0.0.1:7890")
        tr._C1_SIDECAR = fake
        tr._c1_reconcile({"egress_proxy": parse_egress_proxy("http://127.0.0.1:7890")})
        self.assertIs(tr._C1_SIDECAR, fake)

    def test_failed_start_is_retried_after_config_change(self):
        """此前启动失败过的配置，改完配置必须能重试（失败标记清零）。"""
        tr.UPSTREAMS = [{"name": "a", "takeover": True}]
        tr._C1_SIDECAR = None
        tr._C1_SIDECAR_FAILED = True
        tr._c1_reconcile({"egress_proxy": None})
        self.assertFalse(tr._C1_SIDECAR_FAILED)


if __name__ == "__main__":
    unittest.main()
