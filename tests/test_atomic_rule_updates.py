"""Rule changes from independent UI snapshots must not replace one another."""
from concurrent.futures import ThreadPoolExecutor
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import panel


class AtomicRuleUpdateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(panel, "CONFIG_PATH", Path(tmp.name) / "config.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        panel.save_config(panel.default_config())
        self.headers = {"X-Shield-Token": panel.API_TOKEN}

    def update(self, changes):
        with panel.app.test_client() as client:
            return client.post("/api/config/builtin_rules", json=changes, headers=self.headers)

    def test_independent_rule_edits_preserve_both_changes(self):
        before = panel.load_config()
        for rule in ("EMAIL", "PHONE"):
            response = self.update({rule: False})
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json["proxy_restarted"])
        after = panel.load_config()
        self.assertFalse(after["builtin_rules"]["EMAIL"])
        self.assertFalse(after["builtin_rules"]["PHONE"])
        self.assertEqual(after["upstreams"], before["upstreams"])

    def test_concurrent_edits_do_not_lose_updates(self):
        barrier = threading.Barrier(2)
        def edit(rule):
            barrier.wait(timeout=5)
            return self.update({rule: False}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(edit, ("EMAIL", "PHONE"))), [200, 200])
        rules = panel.load_config()["builtin_rules"]
        self.assertFalse(rules["EMAIL"])
        self.assertFalse(rules["PHONE"])

    def test_bulk_and_repeated_updates_are_supported_and_invalid_updates_are_atomic(self):
        off = dict.fromkeys(panel.DEFAULT_BUILTIN_RULES, False)
        self.assertEqual(self.update(off).status_code, 200)
        self.assertEqual(panel.load_config()["builtin_rules"], off)
        for value in (True, False, True):
            self.assertEqual(self.update({"EMAIL": value}).status_code, 200)
        expected = dict(off, EMAIL=True)
        for invalid in ([], {}, {"EMAIL": False, "UNKNOWN_RULE": True}, {"EMAIL": "false"}, {"EMAIL": 0}):
            with self.subTest(invalid=invalid):
                self.assertEqual(self.update(invalid).status_code, 400)
                self.assertEqual(panel.load_config()["builtin_rules"], expected)

    def test_rule_endpoint_uses_existing_control_plane_guards(self):
        with panel.app.test_client() as client:
            for headers in ({}, {**self.headers, "Host": "example.invalid"},
                            {**self.headers, "Origin": "https://example.invalid"}):
                with self.subTest(headers=list(headers)):
                    response = client.post("/api/config/builtin_rules", json={"EMAIL": False}, headers=headers)
                    self.assertEqual(response.status_code, 403)
        self.assertTrue(panel.load_config()["builtin_rules"]["EMAIL"])
