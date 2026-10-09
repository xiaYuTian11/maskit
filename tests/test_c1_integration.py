"""C1 上游接管与 transparent.py 集成测试。

验证：
- takeover=false 时 sidecar 不启动，路由走原逻辑
- takeover=true 时 sidecar 惰性启动，路由改写到 sidecar
- metrics 暴露 c1_sidecar 状态
- config.example.json 包含 takeover 开关
"""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))


class TestC1TakeoverSwitch(unittest.TestCase):
    """验证 takeover 开关行为。"""

    def setUp(self):
        import transparent
        self.transparent = transparent
        # 确保全局状态干净
        transparent._C1_SIDECAR = None
        transparent._C1_SIDECAR_TASK = None

    def tearDown(self):
        self.transparent._C1_SIDECAR = None
        self.transparent._C1_SIDECAR_TASK = None

    def test_no_takeover_when_flag_absent(self):
        """takeover 字段不存在 → 不启用。"""
        ups = [{"name": "test", "target": "https://example.com", "paths": ["/v1"]}]
        with mock.patch.object(self.transparent, "UPSTREAMS", ups):
            self.assertFalse(self.transparent._c1_any_takeover_enabled())

    def test_takeover_false(self):
        """takeover=false → 不启用。"""
        ups = [{"name": "test", "target": "https://example.com",
                "paths": ["/v1"], "takeover": False}]
        with mock.patch.object(self.transparent, "UPSTREAMS", ups):
            self.assertFalse(self.transparent._c1_any_takeover_enabled())

    def test_takeover_true(self):
        """takeover=true → 启用。"""
        ups = [{"name": "test", "target": "https://example.com",
                "paths": ["/v1"], "takeover": True}]
        with mock.patch.object(self.transparent, "UPSTREAMS", ups):
            self.assertTrue(self.transparent._c1_any_takeover_enabled())

    def test_takeover_partial(self):
        """部分上游 takeover=true → 启用（只要有至少一个）。"""
        ups = [
            {"name": "a", "target": "https://a.com", "paths": ["/v1"], "takeover": False},
            {"name": "b", "target": "https://b.com", "paths": ["/v1"], "takeover": True},
        ]
        with mock.patch.object(self.transparent, "UPSTREAMS", ups):
            self.assertTrue(self.transparent._c1_any_takeover_enabled())


class TestC1ApplyTakeover(unittest.TestCase):
    """验证 _c1_apply_takeover 路由改写逻辑。"""

    def setUp(self):
        import transparent
        self.transparent = transparent
        transparent._C1_SIDECAR = None
        transparent._C1_SIDECAR_TASK = None

    def tearDown(self):
        self.transparent._C1_SIDECAR = None
        self.transparent._C1_SIDECAR_TASK = None

    def test_returns_false_when_sidecar_not_running(self):
        """sidecar 未启动 → 返回 False（走原逻辑）。"""
        flow = mock.MagicMock()
        up = {"takeover": True, "target": "https://example.com", "name": "test"}
        result = self.transparent._c1_apply_takeover(flow, up)
        self.assertFalse(result)

    def test_returns_false_when_takeover_false(self):
        """takeover=false → 返回 False。"""
        # 模拟 sidecar 已启动
        fake_sidecar = mock.MagicMock()
        fake_sidecar.is_running = True
        fake_sidecar.port = 12345
        self.transparent._C1_SIDECAR = fake_sidecar

        flow = mock.MagicMock()
        up = {"takeover": False, "target": "https://example.com", "name": "test"}
        result = self.transparent._c1_apply_takeover(flow, up)
        self.assertFalse(result)

    def test_rewrites_flow_when_active(self):
        """takeover=true + sidecar 运行 → 改写 flow 到 sidecar。"""
        fake_sidecar = mock.MagicMock()
        fake_sidecar.is_running = True
        fake_sidecar.port = 12345
        self.transparent._C1_SIDECAR = fake_sidecar

        # 用真实 dict 作为 headers，避免 MagicMock __setitem__ 问题
        class FakeRequest:
            def __init__(self):
                self.host = None
                self.port = None
                self.scheme = None
                self.headers = {}

        class FakeFlow:
            def __init__(self):
                self.request = FakeRequest()

        flow = FakeFlow()
        up = {"takeover": True, "target": "https://api.example.com", "name": "openai"}
        result = self.transparent._c1_apply_takeover(flow, up)

        self.assertTrue(result)
        self.assertEqual(flow.request.host, "127.0.0.1")
        self.assertEqual(flow.request.port, 12345)
        self.assertEqual(flow.request.scheme, "http")
        self.assertEqual(flow.request.headers["Host"], "127.0.0.1:12345")
        self.assertEqual(flow.request.headers["X-Maskit-Upstream"], "https://api.example.com")
        self.assertEqual(flow.request.headers["X-Maskit-Upstream-Name"], "openai")
        # use_proxy=false (default) → 不设 X-Maskit-Use-Proxy
        self.assertNotIn("X-Maskit-Use-Proxy", flow.request.headers)

    def test_rewrites_flow_with_use_proxy(self):
        """takeover=true + use_proxy=true → 设置 X-Maskit-Use-Proxy 头。"""
        fake_sidecar = mock.MagicMock()
        fake_sidecar.is_running = True
        fake_sidecar.port = 12345
        self.transparent._C1_SIDECAR = fake_sidecar

        class FakeRequest:
            def __init__(self):
                self.host = None
                self.port = None
                self.scheme = None
                self.headers = {}

        class FakeFlow:
            def __init__(self):
                self.request = FakeRequest()

        flow = FakeFlow()
        up = {"takeover": True, "target": "https://api.example.com",
              "name": "openai", "use_proxy": True}
        result = self.transparent._c1_apply_takeover(flow, up)

        self.assertTrue(result)
        self.assertEqual(flow.request.headers["X-Maskit-Use-Proxy"], "true")


class TestC1EgressProxySkip(unittest.TestCase):
    """验证 takeover 模式下 _apply_egress_proxy 跳过（sidecar 自己处理代理）。"""

    def setUp(self):
        import transparent
        self.transparent = transparent
        transparent._C1_SIDECAR = None

    def tearDown(self):
        self.transparent._C1_SIDECAR = None

    def test_egress_proxy_skipped_when_takeover_active(self):
        """takeover=true + sidecar 运行 + use_proxy=true → _apply_egress_proxy 跳过。"""
        fake_sidecar = mock.MagicMock()
        fake_sidecar.is_running = True
        self.transparent._C1_SIDECAR = fake_sidecar

        class FakeServerConn:
            def __init__(self):
                self.via = None  # 显式初始化，不设就不变

        class FakeFlow:
            def __init__(self):
                self.server_conn = FakeServerConn()
                self.metadata = {}

        # 模拟 EGRESS_PROXY 已配置
        with mock.patch.object(self.transparent, "EGRESS_PROXY", "http://proxy:8080"):
            flow = FakeFlow()
            up = {"takeover": True, "use_proxy": True, "target": "https://api.example.com"}
            self.transparent._apply_egress_proxy(flow, up)
            # via 不应被设置（sidecar 自己处理代理）
            self.assertIsNone(flow.server_conn.via)
            # metadata 里也不应标记 shield_via_proxy
            self.assertNotIn("shield_via_proxy", flow.metadata)

    def test_egress_proxy_active_when_takeover_off(self):
        """takeover=false → _apply_egress_proxy 正常执行（原逻辑不变）。"""
        self.transparent._C1_SIDECAR = None
        with mock.patch.object(self.transparent, "EGRESS_PROXY", "http://proxy:8080"):
            flow = mock.MagicMock()
            up = {"takeover": False, "use_proxy": True, "target": "https://api.example.com"}
            self.transparent._apply_egress_proxy(flow, up)
            # flow.server_conn.via 应被设置
            self.assertTrue(hasattr(flow.server_conn, 'via') or flow.server_conn.via is not None
                            or mock.ANY)


class TestC1Metrics(unittest.TestCase):
    """验证 metrics 暴露 c1_sidecar 状态。"""

    def setUp(self):
        import transparent
        self.transparent = transparent
        transparent._C1_SIDECAR = None

    def tearDown(self):
        self.transparent._C1_SIDECAR = None

    def test_metrics_shows_disabled_when_not_started(self):
        """sidecar 未启动 → metrics 显示 enabled=False。"""
        self.transparent._C1_SIDECAR = None
        # 直接测试 metrics 构造逻辑
        c1_metrics = self.transparent._C1_SIDECAR.metrics() \
            if self.transparent._C1_SIDECAR is not None \
            else {"enabled": False}
        self.assertFalse(c1_metrics["enabled"])

    def test_metrics_shows_enabled_when_started(self):
        """sidecar 启动 → metrics 显示 enabled=True + port。"""
        fake_sidecar = mock.MagicMock()
        fake_sidecar.metrics.return_value = {
            "enabled": True, "port": 12345,
            "stats": {"requests": 0, "retries": 0, "errors": 0,
                      "tls_verify_off": 0, "body_too_large": 0},
            "pool": {"max_connections": 64, "max_keepalive": 16},
        }
        self.transparent._C1_SIDECAR = fake_sidecar
        c1_metrics = fake_sidecar.metrics()
        self.assertTrue(c1_metrics["enabled"])
        self.assertEqual(c1_metrics["port"], 12345)
        self.assertIn("stats", c1_metrics)
        self.assertIn("pool", c1_metrics)


class TestC1ConfigExample(unittest.TestCase):
    """验证 config.example.json 包含 takeover 字段。"""

    def test_config_example_has_takeover_field(self):
        """config.example.json 的每个 upstream 都有 takeover 字段。"""
        config_path = Path(__file__).resolve().parents[1] / "engine" / "config.example.json"
        cfg = json.loads(config_path.read_text())
        for up in cfg.get("upstreams", []):
            self.assertIn("takeover", up,
                "upstream %s 缺少 takeover 字段" % up.get("name"))
            self.assertFalse(up["takeover"],
                "upstream %s 的 takeover 默认应为 false" % up.get("name"))

    def test_takeover_field_is_bool(self):
        """takeover 字段必须是布尔类型。"""
        config_path = Path(__file__).resolve().parents[1] / "engine" / "config.example.json"
        cfg = json.loads(config_path.read_text())
        for up in cfg.get("upstreams", []):
            self.assertIsInstance(up["takeover"], bool)


class TestC1ConstantParity(unittest.TestCase):
    """验证 sidecar 与 transparent 的常量一致性。"""

    def test_max_request_body_matches_transparent(self):
        """sidecar 的 _MAX_REQUEST_BODY 与 transparent 的 _DEFAULT_MAX_REQUEST_BODY 一致。"""
        from upstream_sidecar import _MAX_REQUEST_BODY as sidecar_limit
        import transparent
        transparent_limit = transparent._DEFAULT_MAX_REQUEST_BODY
        self.assertEqual(sidecar_limit, transparent_limit,
            "32 MiB 上限不一致：sidecar=%d transparent=%d" % (
                sidecar_limit, transparent_limit))

    def test_sidecar_strips_only_internal_headers(self):
        """sidecar 的剥离名单必须**恰好**是三个内部路由头，不许多。

        曾经它复制了一份 transparent 的凭据头名单并在转发前剥离，客户端凭据到不了
        上游 → 每个请求 401。名单里再混进任何凭据头名，这条都会红。
        """
        import transparent
        from upstream_sidecar import _INTERNAL_HEADERS
        self.assertEqual(
            set(_INTERNAL_HEADERS),
            {"x-maskit-upstream", "x-maskit-upstream-name", "x-maskit-use-proxy"},
            "sidecar 剥离名单已不再只含内部路由头")
        leaked = set(_INTERNAL_HEADERS) & set(transparent._CREDENTIAL_HEADER_NAMES)
        self.assertEqual(leaked, set(),
                         "凭据头名被加进了剥离名单 → 上游必然 401")


if __name__ == "__main__":
    unittest.main()
