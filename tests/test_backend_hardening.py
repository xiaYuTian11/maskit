"""后端跨平台与安全边界回归测试。

这些用例不启动真实代理或修改系统信任库；外部进程和平台能力均通过 mock
验证，避免测试套件误杀宿主进程或打开浏览器。
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import audit_engine  # noqa: E402
import panel  # noqa: E402


class UrlBoundaryTests(unittest.TestCase):
    def test_external_url_requires_exact_host_and_path_boundary(self):
        allowed = (
            "https://github.com/xiaYuTian11/maskit",
            "https://github.com/xiaYuTian11/maskit/releases/latest",
            "https://linux.do/t/123",
        )
        denied = (
            "https://github.com/xiaYuTian11/maskit.evil",
            "https://github.com/xiaYuTian11/maskit@evil.example/",
            "https://github.com.evil/xiaYuTian11/maskit",
            "https://github.com/xiaYuTian11/maskit:443/",
            "https://user:pass@linux.do/",
            "http://linux.do/",
            "https://linux.do.evil/",
            "https://github.com/xiaYuTian11/maskit?next=https://evil.example",
            "https://github.com/xiaYuTian11/maskit#fragment",
        )
        for url in allowed:
            self.assertTrue(panel._is_allowed_external_url(url), url)
        for url in denied:
            self.assertFalse(panel._is_allowed_external_url(url), url)

    def test_safe_target_removes_all_url_credentials_and_query(self):
        self.assertEqual(
            panel._safe_target("https://alice:secret@example.com:8443/api?token=sk-live-secret#x"),
            "https://example.com:8443/api",
        )
        self.assertTrue(panel._safe_target("javascript:alert(1)").startswith("<redacted"))

    def test_forwarded_origin_is_used_only_when_explicitly_trusted(self):
        old_remote = panel.REMOTE_MODE
        try:
            panel.REMOTE_MODE = True
            with mock.patch.dict(panel.os.environ, {panel.TRUST_PROXY_ENV: "1"}, clear=False):
                with panel.app.test_request_context(
                    "/",
                    base_url="http://internal:5801",
                    headers={
                        "Origin": "https://public.example",
                        "X-Forwarded-Proto": "https",
                        "X-Forwarded-Host": "public.example",
                    },
                ):
                    self.assertTrue(panel._origin_ok())
            # 多值头不是单跳代理语义，必须拒绝而不能取第一个值。
            with mock.patch.dict(panel.os.environ, {panel.TRUST_PROXY_ENV: "1"}, clear=False):
                with panel.app.test_request_context(
                    "/",
                    base_url="http://internal:5801",
                    headers={
                        "Origin": "https://public.example",
                        "X-Forwarded-Proto": "https",
                        "X-Forwarded-Host": "public.example, evil.example",
                    },
                ):
                    self.assertFalse(panel._origin_ok())
            # 默认关闭信任时，合法公网 Origin 也不能伪造内部 scheme/host。
            with mock.patch.dict(panel.os.environ, {panel.TRUST_PROXY_ENV: "0"}, clear=False):
                with panel.app.test_request_context(
                    "/",
                    base_url="http://internal:5801",
                    headers={"Origin": "https://public.example"},
                ):
                    self.assertFalse(panel._origin_ok())
        finally:
            panel.REMOTE_MODE = old_remote


class PosixProcessTests(unittest.TestCase):
    def test_process_exists_uses_kill_zero_on_posix(self):
        with mock.patch.object(panel.sys, "platform", "linux"), \
             mock.patch.object(panel.os, "kill") as kill:
            self.assertTrue(panel._process_exists(os.getpid()))
            kill.assert_called_once_with(os.getpid(), 0)

    def test_taskkill_refuses_current_process(self):
        with mock.patch.object(panel.os, "kill") as kill:
            ok, detail = panel._taskkill_pid(os.getpid())
        self.assertFalse(ok)
        self.assertIn("current", detail)
        kill.assert_not_called()

    def test_posix_port_fallback_does_not_fabricate_pid(self):
        # 若只能通过 TCP connect 判断端口存在，返回空 PID 集合，不能伪造 PID 1。
        old_cache = panel._netstat_cache.copy()
        with mock.patch.object(panel.sys, "platform", "linux"), \
             mock.patch.object(panel.Path, "is_dir", return_value=False), \
             mock.patch.object(panel.socket, "socket") as sock_cls:
            sock = sock_cls.return_value.__enter__.return_value
            sock.connect_ex.return_value = 0
            out = panel._listening_port_pids({18701}, fresh=True)
        panel._netstat_cache = old_cache
        self.assertEqual(out, {18701: set()})


class SidecarAndReportTests(unittest.TestCase):
    def test_sidecar_uses_engine_entry_prefix_and_posix_session(self):
        fake = mock.Mock()
        old_argv = panel._mitmdump_argv0
        old_popen = panel.subprocess.Popen
        try:
            panel._mitmdump_argv0 = lambda: ["maskit-engine", "--mitmdump"]
            panel.subprocess.Popen = mock.Mock(return_value=fake)
            with mock.patch.object(panel.sys, "platform", "linux"):
                panel._spawn_mitmdump_sidecar(["-p", "0"])
            args, kwargs = panel.subprocess.Popen.call_args
        finally:
            panel._mitmdump_argv0 = old_argv
            panel.subprocess.Popen = old_popen
        self.assertEqual(args[0], ["maskit-engine", "--mitmdump", "-p", "0"])
        self.assertTrue(kwargs["start_new_session"])
        self.assertNotIn("creationflags", kwargs)

    def test_cert_endpoint_accepts_json_confirmation_and_does_not_call_certutil_on_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_cert = panel.CA_CERT
            panel.CA_CERT = Path(tmp) / "mitmproxy-ca-cert.cer"
            panel.CA_CERT.write_text("dummy", encoding="ascii")
            try:
                with mock.patch.object(panel.sys, "platform", "linux"), \
                     panel.app.test_client() as client:
                    response = client.post(
                        "/api/cert",
                        json={"confirm": True},
                        headers={"X-Shield-Token": panel.API_TOKEN},
                    )
            finally:
                panel.CA_CERT = old_cert
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["installed"])
        self.assertEqual(payload["scope"], "manual")
        self.assertNotIn("certutil", str(payload).lower())

    def test_cert_endpoint_rejects_string_confirmation(self):
        with panel.app.test_client() as client:
            response = client.post(
                "/api/cert",
                json={"confirm": "false"},
                headers={"X-Shield-Token": panel.API_TOKEN},
            )
        self.assertEqual(response.status_code, 400)

    def test_report_scrubs_target_and_evidence_before_writing(self):
        matrix = audit_engine.aggregate_matrix({step: [] for step in audit_engine._ALL_STEPS})
        findings = {step: [] for step in audit_engine._ALL_STEPS}
        findings["step9_error"] = [{
            "severity": "HIGH",
            "signal": "error_leak",
            "evidence": "Authorization: Bearer abcdefghijklmnop12345; sk-live-abcdefghijklmnop",
        }]
        text = audit_engine.render_markdown_report(
            "https://user:password@relay.example/v1?token=sk-live-secret",
            "model-x",
            matrix,
            findings,
        )
        self.assertNotIn("password", text)
        self.assertNotIn("sk-live-abcdefghijklmnop", text)
        self.assertNotIn("abcdefghijklmnop12345", text)
        self.assertIn("https://relay.example/v1", text)

        with tempfile.TemporaryDirectory() as tmp:
            path = audit_engine.save_report(text, tmp, generated_at="20260101-000000")
            saved = Path(path).read_text(encoding="utf-8")
            self.assertNotIn("sk-live", saved)


if __name__ == "__main__":
    unittest.main()
