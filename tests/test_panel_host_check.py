"""面板 Host 校验：IPv6 回环必须与 127.0.0.1 同等放行。

为什么单独立一组：`_host_allowed()` 是防 DNS rebinding 的一道闸，改它的方向
必须始终是「只放行等价回环」，不能为了放过 `[::1]` 把校验放宽。

2026-11 实测：`request.host` 对 IPv6 是 `[::1]:5801`，而旧实现
`split(":", 1)[0]` 得到 `[`，于是用 IPv6 回环访问面板的请求全部 403
（IPv4 正常，极难联想到 Host 校验）。
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import panel


class HostAllowedTests(unittest.TestCase):
    def test_ipv4_loopback_allowed(self):
        for host in ("127.0.0.1:5801", "localhost:5801", "127.0.0.1",
                     "LOCALHOST:5801", " 127.0.0.1:5801 "):
            self.assertTrue(panel._host_allowed(host), host)

    def test_ipv6_loopback_allowed(self):
        # 旧实现（split(":", 1)[0]）下这三条全部 False
        for host in ("[::1]:5801", "[::1]", "[::1]:80"):
            self.assertTrue(panel._host_allowed(host), host)

    def test_other_hosts_still_rejected(self):
        for host in ("evil.com:5801", "127.0.0.2:5801", "[::2]:5801",
                     "[2001:db8::1]:5801", "0.0.0.0:5801", "", None):
            self.assertFalse(panel._host_allowed(host), "不得放行：%r" % (host,))

    def test_bracketed_host_without_closing_bracket_rejected(self):
        for host in ("[::1", "[::1]extra", "[evil.com]:5801"):
            self.assertFalse(panel._host_allowed(host), host)


class HostOkTests(unittest.TestCase):
    """`_host_ok()` 的接线：远程模式直通，本机模式走 `_host_allowed`。"""

    def test_remote_mode_allows_any_host(self):
        with mock.patch.object(panel, "REMOTE_MODE", True):
            with panel.app.test_request_context("/", headers={"Host": "example.com"}):
                self.assertTrue(panel._host_ok())

    def test_local_mode_reads_request_host(self):
        with mock.patch.object(panel, "REMOTE_MODE", False):
            with panel.app.test_request_context("/", headers={"Host": "127.0.0.1:5801"}):
                self.assertTrue(panel._host_ok())


if __name__ == "__main__":
    unittest.main()
