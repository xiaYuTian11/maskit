"""Panel connection policy compatibility and public evidence projection."""
import copy
import json
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import panel


class ConnectionConfigTests(unittest.TestCase):
    def config(self):
        cfg = copy.deepcopy(panel.default_config())
        cfg["upstreams"] = [{"name": "test", "port": 18701,
                             "target": "https://example.test", "paths": ["/v1"]}]
        return cfg

    def test_absent_policy_stays_absent(self):
        self.assertNotIn("connection_policy", panel.normalize_config(self.config())["upstreams"][0])

    def test_http2_default_is_consistent_and_explicit_true_survives(self):
        template = json.loads((Path(__file__).resolve().parents[1] / "engine/config.example.json").read_text())
        self.assertIs(template["http2"], False)
        self.assertIs(panel.default_config()["http2"], False)
        self.assertIs(panel.normalize_config({})["http2"], False)
        self.assertIs(panel.normalize_config({"http2": True})["http2"], True)

    def test_real_unsupported_control_is_rejected(self):
        cfg = self.config()
        cfg["upstreams"][0]["connection_policy"] = {"reuse": "never"}
        with self.assertRaises(ValueError):
            panel.normalize_config(cfg)

    def test_engine_parser_preserves_explicit_policy_for_request_rejection(self):
        import transparent
        cfg = self.config()
        cfg["upstreams"][0]["connection_policy"] = {"reuse": "never"}
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            (data / "config.json").write_text(json.dumps(cfg))
            with mock.patch.object(transparent, "_DATA_ROOT", data):
                settings = transparent._read_settings()
        self.assertEqual(settings["upstreams"][0]["connection_policy"], {"reuse": "never"})

    def test_shared_validator_receives_http2_and_policy(self):
        cfg = self.config()
        policy = {"reuse": "never"}
        cfg["upstreams"][0]["connection_policy"] = policy
        validator = mock.Mock(return_value=policy)
        module = types.SimpleNamespace(validate_connection_policy=validator)
        with mock.patch.dict(sys.modules, {"connection_policy": module}):
            self.assertEqual(panel.normalize_config(cfg)["upstreams"][0]["connection_policy"], policy)
        validator.assert_called_once_with(policy, http2=cfg["http2"])

    def test_unsupported_policy_rejected_before_save(self):
        cfg = self.config()
        cfg["upstreams"][0]["connection_policy"] = {"reuse": "never"}
        module = types.SimpleNamespace(validate_connection_policy=mock.Mock(side_effect=ValueError("unsupported")))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            original = json.dumps(self.config())
            path.write_text(original)
            with mock.patch.dict(sys.modules, {"connection_policy": module}), mock.patch.object(panel, "CONFIG_PATH", path):
                with self.assertRaises(ValueError):
                    panel.save_config(cfg)
            self.assertEqual(path.read_text(), original)
            self.assertEqual(list(Path(tmp).iterdir()), [path])

    def test_old_form_rename_preserves_policy_and_null_resets(self):
        cfg = self.config()
        cfg["upstreams"][0]["connection_policy"] = {"reuse": "never"}
        value = dict(cfg["upstreams"][0], name="renamed")
        del value["connection_policy"]
        panel._apply_config_patch(cfg, "upstreams", "list_upsert", [], value, match="test")
        self.assertEqual(cfg["upstreams"][0]["connection_policy"], {"reuse": "never"})
        panel._apply_config_patch(cfg, "upstreams", "list_upsert", [], dict(value, connection_policy=None))
        self.assertNotIn("connection_policy", panel.normalize_config(cfg)["upstreams"][0])

    def test_invalid_policy_not_silently_ignored_when_module_missing(self):
        cfg = self.config()
        cfg["upstreams"][0]["connection_policy"] = "bad"
        with mock.patch.dict(sys.modules, {"connection_policy": None}):
            with self.assertRaises(ValueError):
                panel.normalize_config(cfg)


class ConnectionDiskConfigTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "config.json"
        patcher = mock.patch.object(panel, "CONFIG_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(panel._sync_runtime_config, panel.default_config())
        # Small enough that the structural-shrink guard would NOT save these
        # words/upstreams from an accidental fallback to the defaults.
        self.original = {
            "upstreams": [
                {"name": "custom", "base_path": "/custom", "port": 18741,
                 "target": "https://custom.example.test", "paths": ["/custom/v1"],
                 "extra_headers": {"X-Test-Mode": "custom"}, "connection_policy": {}},
                {"name": "other", "port": 18742, "target": "https://other.example.test"},
            ],
            "sensitive": {"公司": ["本地业务词", "另一个业务词"]},
            "target_domains": ["custom.example.test"],
            "auto_start_proxy": False, "record_plaintext_words": False,
            "stop_mode": "block", "response_scan": False, "stream_response": False,
            "audit": {"enabled": False}, "http2": True,
        }
        self.write_original()

    def write_original(self):
        self.original_text = json.dumps(self.original, ensure_ascii=False)
        self.path.write_text(self.original_text, encoding="utf-8")

    def assert_untouched(self):
        self.assertEqual(self.path.read_text(encoding="utf-8"), self.original_text)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def post(self, endpoint, payload):
        with panel.app.test_client() as client:
            return client.post(endpoint, json=payload, headers={"X-Shield-Token": panel.API_TOKEN})

    def test_load_preserves_unrelated_settings_and_unsupported_raw_policy(self):
        warnings = []
        cfg = panel.load_config(warnings)
        self.assertEqual(cfg["sensitive"], self.original["sensitive"])
        self.assertEqual(cfg["target_domains"], self.original["target_domains"])
        self.assertEqual([u["target"] for u in cfg["upstreams"]],
                         [u["target"] for u in self.original["upstreams"]])
        self.assertEqual(cfg["upstreams"][0]["connection_policy"], {})
        self.assertNotIn("connection_policy", cfg["upstreams"][1])
        for key in ("http2", "stop_mode", "auto_start_proxy", "record_plaintext_words",
                    "response_scan", "stream_response"):
            self.assertEqual(cfg[key], self.original[key], key)
        self.assertIs(cfg["audit"]["enabled"], False)
        self.assertEqual(cfg["meta"], {})  # No pretend migration of an unwritable config.
        self.assertEqual(warnings, [panel._CONNECTION_POLICY_LOAD_WARNING])
        self.assert_untouched()

    def test_bad_policy_types_stay_visible_with_bounded_metadata(self):
        for policy in ({}, [], False, 42, "bad", {"private": "raw-private-data" * 10000}):
            with self.subTest(policy_type=type(policy).__name__):
                self.original["upstreams"][0]["connection_policy"] = policy
                self.write_original()
                with panel.app.test_client() as client:
                    response = client.get("/api/config", headers={"X-Shield-Token": panel.API_TOKEN})
                self.assertEqual(response.status_code, 200)
                cfg = response.get_json()
                # Config readback intentionally retains the raw value for repair;
                # diagnostics must not copy it into public capability/warning data.
                self.assertEqual(cfg["upstreams"][0]["connection_policy"], policy)
                self.assertEqual(cfg["_meta"]["warnings"], [panel._CONNECTION_POLICY_LOAD_WARNING])
                self.assertLess(len(json.dumps(cfg["_meta"]["warnings"])), 500)
                self.assertNotIn("raw-private-data", json.dumps(cfg["_meta"]))
                self.assertIs(cfg["_meta"]["transport_capabilities"]["supported"], False)
                self.assert_untouched()

    def test_unrelated_post_and_patch_reject_without_backup_or_write(self):
        for endpoint, payload in (
            ("/api/config", {"record_plaintext_words": True}),
            ("/api/config/patch", {"key": "sensitive", "op": "list_add",
                                   "path": ["公司"], "value": ["新业务词"]}),
        ):
            with self.subTest(endpoint=endpoint):
                response = self.post(endpoint, payload)
                self.assertEqual(response.status_code, 400)
                self.assertIs(response.get_json()["ok"], False)
                self.assert_untouched()

    def test_enable_attempt_rejected_before_legacy_read_migrations(self):
        del self.original["upstreams"][0]["connection_policy"]
        self.write_original()
        proposed = dict(self.original["upstreams"][0], connection_policy={})
        for endpoint, payload in (
            ("/api/config", {"upstreams": [proposed]}),
            ("/api/config/patch", {"key": "upstreams", "op": "list_upsert", "value": proposed}),
            ("/api/config/patch", {"key": "upstreams", "op": "set", "value": [proposed]}),
        ):
            with self.subTest(endpoint=endpoint, op=payload.get("op")):
                response = self.post(endpoint, payload)
                self.assertEqual(response.status_code, 400)
                self.assert_untouched()

    def test_policy_only_null_reset_preserves_rest_and_backs_up_original(self):
        before = panel.load_config()
        response = self.post("/api/config/patch", {
            "key": "upstreams", "op": "list_upsert", "match": "custom",
            "value": {"connection_policy": None},
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        expected = copy.deepcopy(before)
        del expected["upstreams"][0]["connection_policy"]
        self.assertEqual(response.get_json()["config"], expected)
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8")), expected)
        backups = list(self.path.parent.glob("config.json.bak-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(encoding="utf-8"), self.original_text)

    def test_shrink_guard_cannot_restore_an_unvalidated_disk_policy(self):
        for i in range(2):
            self.original["upstreams"].append({"name": f"extra{i}", "port": 18743 + i,
                                               "target": "https://extra.example.test"})
        self.write_original()
        reduced = copy.deepcopy(self.original)
        reduced["upstreams"] = [self.original["upstreams"][1]]
        with self.assertRaises(ValueError):
            panel.save_config(reduced)
        self.assert_untouched()

    def test_missing_validator_preserves_disk_policy_but_still_rejects_write(self):
        with mock.patch.dict(sys.modules, {"connection_policy": None}):
            warnings = []
            cfg = panel.load_config(warnings)
            self.assertEqual(cfg["sensitive"], self.original["sensitive"])
            self.assertEqual(cfg["upstreams"][0]["connection_policy"], {})
            self.assertEqual(warnings, [panel._CONNECTION_POLICY_LOAD_WARNING])
            with self.assertRaises(ValueError):
                panel.save_config(cfg)
        self.assert_untouched()

    def test_unparseable_json_keeps_existing_default_fallback(self):
        self.original_text = '{"sensitive":'
        self.path.write_text(self.original_text, encoding="utf-8")
        warnings = []
        self.assertEqual(panel.load_config(warnings), panel.default_config())
        self.assertEqual(warnings, [])
        self.assert_untouched()


class TransportProjectionTests(unittest.TestCase):
    def evidence(self):
        return {"phase": "tls_handshake", "reused": None, "idle_s": None,
                "connect_ms": 0, "tls_ms": 1.5, "via_proxy": False,
                "evidence_complete": False, "server_conn_id": "local-test-id",
                "actual_endpoint": "https://user:password@example.test/path",
                "headers": {"Authorization": "sk-test-000000000000"},
                "raw_connection": {"private": "never export"}}

    def test_nested_whitelist_preserves_unknown_and_false(self):
        result = panel._project_transport(self.evidence())
        self.assertIsNone(result["reused"])
        self.assertIsNone(result["idle_s"])
        self.assertEqual(result["connect_ms"], 0)
        self.assertIs(result["via_proxy"], False)
        for key in ("actual_endpoint", "headers", "raw_connection"):
            self.assertNotIn(key, result)
        self.assertNotIn("connect_ms", panel._project_transport({"connect_ms": float("nan")}))

    def test_tail_uses_nested_whitelist(self):
        line = "SHIELD\tERR\t" + json.dumps({"transport": self.evidence(), "dialog": "private"})
        result = json.loads(panel._tail_line_sanitize(line).split("\t", 2)[2])
        self.assertEqual(result, {"transport": panel._project_transport(self.evidence())})

    def test_metrics_keep_observation_without_inventing_missing_values(self):
        result = panel._project_engine_metrics({
            "transport": {"inflight": 0, "oldest_request_age_s": None, "raw_connection": "private",
                          "capabilities": {"deadlines": False, "http1_reuse_policy": False, "private": "secret"}},
            "heartbeat": {"generated_at": 123, "loop_lag_ms": 0, "private": "secret"}})
        self.assertEqual(result["heartbeat"], {"generated_at": 123, "loop_lag_ms": 0})
        self.assertIsNone(result["transport"]["oldest_request_age_s"])
        self.assertNotIn("connections", result["transport"])
        self.assertNotIn("raw_connection", result["transport"])
        self.assertNotIn("private", result["transport"]["capabilities"])

    def test_capabilities_share_bounded_observation_projection(self):
        caps = {"supported": False, "deadlines": False, "http1_reuse_policy": False,
                "observation": False, "observation_reason": "unsupported observation " * 1000,
                "stream_cancellation": False, "stream_cancellation_reason": "unknown version",
                "version": "unknown", "reason": "controls unavailable", "private": {"raw": "never export"}}
        module = types.SimpleNamespace(transport_capabilities=lambda: caps)
        with mock.patch.dict(sys.modules, {"connection_policy": module}):
            meta_caps = panel._connection_capabilities()
        metrics_caps = panel._project_engine_metrics({"transport": {"capabilities": caps}})["transport"]["capabilities"]
        self.assertEqual(meta_caps, metrics_caps)
        self.assertIs(meta_caps["observation"], False)
        self.assertIs(meta_caps["stream_cancellation"], False)
        self.assertEqual(meta_caps["stream_cancellation_reason"], "unknown version")
        self.assertLessEqual(len(meta_caps["observation_reason"]), 160)
        self.assertNotIn("private", meta_caps)
        self.assertEqual(panel._project_connection_capabilities({
            "supported": {"raw": "private"}, "observation": "yes", "version": [],
            "reason": {"raw": "private"}, "stream_cancellation_reason": ["private"],
        }), {})

    def test_capability_import_failure_does_not_claim_observation(self):
        with mock.patch.dict(sys.modules, {"connection_policy": None}):
            caps = panel._connection_capabilities()
        for key in ("supported", "deadlines", "http1_reuse_policy", "observation", "stream_cancellation"):
            self.assertIs(caps[key], False)
        self.assertEqual(caps["observation_reason"], "connection_policy_unavailable")
        self.assertEqual(caps["stream_cancellation_reason"], "connection_policy_unavailable")


class TransportI18nTests(unittest.TestCase):
    def test_known_phase_and_reason_codes_have_both_labels(self):
        source = (Path(__file__).resolve().parents[1] / "frontend/src/lib/i18n.tsx").read_text(encoding="utf-8")
        phases = ("unknown", "connecting", "tcp_connected", "tls_handshake", "tls_established",
                  "awaiting_response", "response_stream", "complete", "local_response")
        reasons = ("unknown", "connect_failed", "tls_failed", "connection_selection_failed",
                   "server_disconnected", "request_failed", "client_cancelled", "client_disconnected",
                   "client_protocol_error", "response_offload_timeout", "response_offload_failed",
                   "response_offload_wait", "stream_finish_wait", "stream_finish_failed",
                   "unsupported_connection_policy")
        for kind, codes in (("phase", phases), ("reason", reasons)):
            for code in codes:
                with self.subTest(kind=kind, code=code):
                    labels = re.findall(r"'transport\." + kind + r"\." + code + r"': '([^']+)'", source)
                    self.assertEqual(len(labels), 2, "Must have Chinese and English labels")
                    self.assertRegex(labels[0], r"[一-鿿]")
                    self.assertNotRegex(labels[1], r"[一-鿿]")
                    self.assertNotEqual(labels[1], code)

    def test_event_details_translate_all_enum_surfaces_and_preserve_unknown(self):
        source = (Path(__file__).resolve().parents[1] /
                  "frontend/src/components/events/EventDetailDialog.tsx").read_text(encoding="utf-8")
        for expression in ("transportLabel('phase', event.transport?.phase)",
                           "transportLabel('reason', event.transport?.reason)",
                           "transportLabel('phase', event.failure_phase)",
                           "transportLabel('reason', event.reason)"):
            self.assertIn(expression, source)
        self.assertIn("if (!value) return t('transport.unknown')", source)
        self.assertIn("return label === key ? value : label", source)


class TakeoverBooleanPredicateTests(unittest.TestCase):
    """接管/代理这两个开关都会改**转发路径**，布尔判据只能有一份实现。

    `bool("false")` 是 True：手改 config.json 想关掉接管，裸 `bool()` 会把它读成开启，
    而面板随后按「开启」存回去——用户视角是「我明明关了」。存配置的面板与读配置的
    引擎若各写一份判据，两份可以各自漂移，所以这里钉**函数身份**而不是行为相似。
    """

    def cfg(self, takeover=True, use_proxy=True):
        cfg = copy.deepcopy(panel.default_config())
        cfg["upstreams"] = [{"name": "t", "port": 18701,
                             "target": "https://x.example.test", "paths": ["/v1"],
                             "takeover": takeover, "use_proxy": use_proxy}]
        return cfg

    def test_panel_and_engine_share_one_predicate(self):
        import transparent
        from shield_defaults import is_true
        self.assertIs(panel.is_true, is_true)
        self.assertIs(transparent.is_true, is_true,
                      "引擎自己又写了一份布尔判据：存与读可能读出两种意思")

    def test_hand_written_values_store_as_the_obvious_bool(self):
        for raw, expected in (("false", False), ("0", False), ("off", False),
                              ("no", False), ("", False), ("true", True), ("1", True),
                              ("on", True), ("YES", True), (1, True), (0, False),
                              (None, False), ([], False), ({}, False), (True, True),
                              (False, False)):
            got = panel.normalize_config(self.cfg(raw, raw))["upstreams"][0]
            with self.subTest(raw=raw):
                self.assertIs(got["takeover"], expected)
                self.assertIs(got["use_proxy"], expected)
                self.assertIsInstance(got["takeover"], bool,
                                      "存盘的必须是真 bool，否则下一次读取又靠猜形状")

    def test_engine_reads_the_same_answer(self):
        """面板存成什么，引擎就得读出什么（同一条 `"false"` 走两遍）。"""
        import transparent
        cfg = self.cfg("false", "false")
        stored = panel.normalize_config(cfg)["upstreams"][0]
        self.assertFalse(stored["takeover"])
        self.assertFalse(transparent.is_true(stored["takeover"]))


class TakeoverPreflightTests(unittest.TestCase):
    """「存了但永远不会生效」必须当场说，而不是留到指标里让人猜。

    C1 接管成立的两条前提都写死在别处：`_c1_apply_takeover` 只被
    `apply_reverse_routing` 调用（非 reverse 模式这个键被完全忽略），而 sidecar 的
    目标白名单按 origin 建（规范化不出 origin 的上游会被自己拒转）。两种情况以前
    都毫无提示：面板显示开关已开，runtime metrics 里 `caller_connections` 永远是 0。
    """

    def cfg(self, mode="reverse", takeover=True, target="https://x.example.test"):
        cfg = copy.deepcopy(panel.default_config())
        cfg["capture_mode"] = mode
        cfg["upstreams"] = [{"name": "t", "port": 18701, "target": target,
                             "paths": ["/v1"], "takeover": takeover}]
        return cfg

    def test_healthy_reverse_config_says_nothing(self):
        self.assertEqual(panel._takeover_preflight_advice(self.cfg()), [],
                         "正常配置不该被唠叨，否则警告会变成噪声")

    def test_switch_off_is_silent_even_in_a_bad_setup(self):
        bad = self.cfg(mode="explicit", takeover=False, target="https://a:b@x.test")
        self.assertEqual(panel._takeover_preflight_advice(bad), [])

    def test_non_reverse_mode_is_named(self):
        advice = panel._takeover_preflight_advice(self.cfg(mode="explicit"))
        self.assertEqual(len(advice), 1)
        self.assertIn("explicit", advice[0])
        self.assertIn("反向代理", advice[0])
        self.assertIn("reverse mode", advice[0])

    def test_local_mode_is_also_caught(self):
        self.assertEqual(len(panel._takeover_preflight_advice(self.cfg(mode="local"))), 1)

    def test_target_without_origin_is_refused_by_the_sidecar_allowlist(self):
        advice = panel._takeover_preflight_advice(
            self.cfg(takeover=True, target="https://user:secretpw@x.example.test"))
        self.assertEqual(len(advice), 1)
        self.assertIn("「t」", advice[0], "得说清是哪一条上游，用户才知道去改哪个")
        # 凭据红线：target 里写了 userinfo 也不能回显出来（走 _safe_target 剥净）
        self.assertNotIn("secretpw", advice[0])
        self.assertNotIn("user:", advice[0])

    def test_advice_uses_the_sidecars_own_normalizer(self):
        """判据必须来自建白名单的那份实现，两边各写一份就会漂移。"""
        import upstream_sidecar
        self.assertIs(panel._takeover_origin_normalizer(), upstream_sidecar.normalize_origin)
        for target in ("https://x.example.test", "http://127.0.0.1:18000/prefix",
                       "https://x.test:8443?api-version=2024"):
            with self.subTest(target=target):
                self.assertEqual(
                    panel._takeover_preflight_advice(self.cfg(takeover=True, target=target)),
                    [])

    def test_string_false_never_triggers_advice(self):
        """存储判据与预检判据同源：`"false"` 既存成 False，也不该被当成「开了接管」。"""
        advice = panel._takeover_preflight_advice(
            self.cfg(mode="explicit", takeover="false"))
        self.assertEqual(advice, [])

    def test_missing_sidecar_module_degrades_instead_of_breaking_the_save(self):
        """预检自己坏了不能拖累保存：跳过 target 这项，模式那条照说。"""
        with mock.patch.object(panel, "_takeover_origin_normalizer", lambda: None):
            self.assertEqual(panel._takeover_preflight_advice(
                self.cfg(takeover=True, target="https://a:b@x.test")), [])
            self.assertEqual(len(panel._takeover_preflight_advice(
                self.cfg(mode="explicit", takeover=True))), 1)

    def test_non_dict_config_is_not_a_crash(self):
        for bad in (None, [], "x", {"upstreams": "not-a-list"}):
            with self.subTest(cfg=bad):
                self.assertEqual(panel._takeover_preflight_advice(bad), [])


class TakeoverAdviceReachesTheUserTests(unittest.TestCase):
    """预检必须真的走到用户眼前：前端把 warnings 逐条 toast，函数里返回等于没说。"""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "config.json"
        patcher = mock.patch.object(panel, "CONFIG_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(panel._sync_runtime_config, panel.default_config())
        # 磁盘上就摆好「将要保存的那份」上游，避免撞上结构收缩守卫（少一项会被拒）。
        cfg = panel.default_config()
        cfg["capture_mode"] = "explicit"
        cfg["upstreams"] = [{"name": "t", "port": 18701, "base_path": "/t",
                             "target": "https://x.example.test", "paths": ["/v1"],
                             "takeover": False}]
        panel.save_config(cfg)

    def post(self, endpoint, payload):
        with panel.app.test_client() as client:
            return client.post(endpoint, json=payload,
                               headers={"X-Shield-Token": panel.API_TOKEN})

    def test_full_save_returns_the_advice(self):
        cfg = panel.load_config()
        cfg["upstreams"][0]["takeover"] = True
        response = self.post("/api/config", cfg)
        self.assertEqual(response.status_code, 200)
        warnings = response.get_json()["warnings"]
        self.assertTrue(any("takeover" in w or "接管" in w for w in warnings), warnings)
        self.assertIn("explicit", warnings[0])

    def test_incremental_patch_returns_the_advice_too(self):
        """两个保存通道都要说：前端改一个上游的开关走的是 patch，不是全量 POST。"""
        response = self.post("/api/config/patch", {
            "key": "upstreams", "op": "list_upsert",
            "value": {"name": "t", "port": 18701, "base_path": "/t",
                      "target": "https://x.example.test", "paths": ["/v1"],
                      "takeover": True}})
        self.assertEqual(response.status_code, 200)
        warnings = response.get_json()["warnings"]
        self.assertTrue(any("接管" in w or "takeover" in w for w in warnings), warnings)
        self.assertTrue(panel.load_config()["upstreams"][0]["takeover"])

    def test_healthy_save_stays_quiet(self):
        cfg = panel.load_config()
        cfg["capture_mode"] = "reverse"
        response = self.post("/api/config", cfg)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([w for w in response.get_json()["warnings"]
                          if "接管" in w or "takeover" in w], [])

    def test_advice_survives_the_log_path(self):
        """warnings 除了回传前端还要进面板日志：只有 toast 的话，用户切走页面就没了。"""
        logs = []
        with mock.patch.object(panel, "_emit_log", side_effect=lambda m, *a: logs.append(m)):
            cfg = panel.load_config()
            cfg["upstreams"][0]["takeover"] = True
            self.post("/api/config", cfg)
        self.assertTrue(any("接管" in m or "takeover" in m for m in logs), logs[-5:])


if __name__ == "__main__":
    unittest.main()
