"""服务端版本更新探测（`/api/update/check`）的行为约束。

为什么这个端点必须由服务端出网（而不是前端 fetch）：Web / Docker 部署下，出网能力
属于**服务器**，而原实现是拿**访问者的浏览器**去请求 api.github.com。国内用户/内网
部署的浏览器到 GitHub 不通，于是「检查更新」稳定报
`TypeError: NetworkError when attempting to fetch resource.`——和服务器能否联网无关。

本文件锁四件事：
1. 两种响应格式都能归一化（GitHub API 的 tag_name/body/published_at
   与 latest.json 的 version/notes/pub_date）——这是「换源不用改前端」的前提，
   少认一种就会静默显示「已是最新」（版本号读成空串）；
2. 多源回退顺序：自定义源 → 静态 latest.json → GitHub API，第一个成功即用；
3. TTL 缓存命中后不再出网（GitHub 匿名 API 限流 60 次/小时/IP，多人共用出口
   每次点击都打一次必然打满）；
4. 全部源失败时返回可读错误 + 502，而不是把原始异常抛给用户。
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import panel


class _FakeResponse:
    """最小 urlopen 替身：支持 context manager 与 read()。"""

    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self, _n=None):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(payloads, calls):
    """按 URL 返回预设响应；未预设的 URL 抛 URLError（模拟连不上）。"""
    import urllib.error

    def _open(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        calls.append(url)
        if url in payloads:
            value = payloads[url]
            if isinstance(value, Exception):
                raise value
            return _FakeResponse(value)
        raise urllib.error.URLError("unreachable")

    return _open


class NormalizeUpdateCheckUrlTests(unittest.TestCase):
    """更新检查源只做形态校验（不锁域名，否则「填自己的镜像」这个功能就废了）。"""

    def test_accepts_https_and_http_mirror(self):
        for url in (
            "https://gh-proxy.com/https://github.com/xiaYuTian11/maskit/releases/latest/download/latest.json",
            "http://192.168.1.10:8080/latest.json",
        ):
            self.assertEqual(panel._normalize_update_check_url(url), url)

    def test_rejects_non_http_scheme_and_empty(self):
        for bad in ("", None, "   ", "ftp://host/x", "javascript:alert(1)", "file:///etc/passwd"):
            self.assertEqual(panel._normalize_update_check_url(bad), "", f"应拒绝 {bad!r}")

    def test_rejects_userinfo_so_credentials_never_leak(self):
        """带账号密码的地址必须拒绝：它会被日志/状态接口回显出去。"""
        self.assertEqual(
            panel._normalize_update_check_url("https://user:secret@mirror.example/x"), "")

    def test_rejects_bad_port_and_control_chars(self):
        self.assertEqual(panel._normalize_update_check_url("https://host:99999/x"), "")
        self.assertEqual(panel._normalize_update_check_url("https://host/x\nEvil"), "")

    def test_normalize_config_falls_back_silently(self):
        """非法值静默回落 ""，不把整份配置卡在 400。"""
        cfg = panel.normalize_config({"update_check_url": "not-a-url"})
        self.assertEqual(cfg.get("update_check_url"), "")


class FetchUpdateSourceTests(unittest.TestCase):
    """两种上游格式 → 统一 {version, notes, pub_date}。"""

    def _fetch(self, payload_obj):
        raw = json.dumps(payload_obj).encode("utf-8")
        with mock.patch("urllib.request.urlopen", _fake_urlopen({"https://s/x": raw}, [])):
            return panel._fetch_update_source("https://s/x")

    def test_github_api_format(self):
        data, err = self._fetch({
            "tag_name": "v1.2.3", "body": "notes here", "published_at": "2026-09-24T11:16:23Z",
        })
        self.assertEqual(err, "")
        self.assertEqual(data["version"], "v1.2.3")
        self.assertEqual(data["notes"], "notes here")
        self.assertEqual(data["pub_date"], "2026-09-24T11:16:23Z")

    def test_latest_json_format(self):
        """静态 latest.json 用 version/notes/pub_date，与 API 字段名不同。"""
        data, err = self._fetch({
            "version": "v0.5.0", "notes": "Data Maskit v0.5.0", "pub_date": "2026-09-24T11:16:23Z",
        })
        self.assertEqual(err, "")
        self.assertEqual(data["version"], "v0.5.0")
        self.assertEqual(data["notes"], "Data Maskit v0.5.0")

    def test_missing_version_is_an_error_not_a_silent_empty(self):
        """版本字段缺失必须报错：静默返回空串会让前端一直显示「已是最新」。"""
        data, err = self._fetch({"notes": "no version"})
        self.assertIsNone(data)
        self.assertTrue(err)

    def test_non_json_body_is_an_error(self):
        with mock.patch("urllib.request.urlopen",
                        _fake_urlopen({"https://s/x": b"<html>proxy error</html>"}, [])):
            data, err = panel._fetch_update_source("https://s/x")
        self.assertIsNone(data)
        self.assertIn("JSON", err)


class UpdateCheckEndpointTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(panel, "CONFIG_PATH", Path(tmp.name) / "config.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        panel.save_config(panel.default_config())
        self.headers = {"X-Shield-Token": panel.API_TOKEN}
        # 每个用例都从空缓存开始，避免相互串味
        panel._update_check_cache.update({"data": None, "at": 0.0})

    def _get(self):
        with panel.app.test_client() as client:
            return client.get("/api/update/check", headers=self.headers)

    def _set_source(self, url):
        cfg = panel.load_config()
        cfg["update_check_url"] = url
        panel.save_config(cfg)

    def test_falls_back_to_static_then_api_and_reports_source(self):
        calls = []
        static = json.dumps({"version": "v9.9.9", "notes": "n"}).encode()
        with mock.patch("urllib.request.urlopen", _fake_urlopen(
                {panel.DEFAULT_UPDATE_STATIC_URL: static}, calls)):
            r = self._get()
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["version"], "v9.9.9")
        self.assertEqual(body["source"], panel.DEFAULT_UPDATE_STATIC_URL)
        # 静态源成功即停，不该再打 API（省下匿名限流额度）
        self.assertEqual(calls, [panel.DEFAULT_UPDATE_STATIC_URL])

    def test_falls_through_to_api_when_static_missing(self):
        """latest.json 只在已签名正式版上产出，拿不到时必须回落 API。"""
        calls = []
        api = json.dumps({"tag_name": "v1.0.0", "body": "b",
                          "published_at": "2026-01-01T00:00:00Z"}).encode()
        with mock.patch("urllib.request.urlopen", _fake_urlopen(
                {panel.DEFAULT_UPDATE_API_URL: api}, calls)):
            r = self._get()
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["version"], "v1.0.0")
        self.assertEqual(body["source"], panel.DEFAULT_UPDATE_API_URL)
        self.assertEqual(calls, [panel.DEFAULT_UPDATE_STATIC_URL, panel.DEFAULT_UPDATE_API_URL])

    def test_custom_source_wins_and_is_tried_first(self):
        custom = "https://mirror.example/latest.json"
        self._set_source(custom)
        calls = []
        payload = json.dumps({"version": "v2.0.0"}).encode()
        with mock.patch("urllib.request.urlopen", _fake_urlopen({custom: payload}, calls)):
            r = self._get()
        self.assertEqual(r.get_json()["version"], "v2.0.0")
        self.assertEqual(calls, [custom])

    def test_all_sources_down_returns_readable_502(self):
        with mock.patch("urllib.request.urlopen", _fake_urlopen({}, [])):
            r = self._get()
        self.assertEqual(r.status_code, 502)
        body = r.get_json()
        self.assertFalse(body["ok"])
        # 给用户看的是人话，不是 TypeError/URLError 原文
        self.assertIn("无法连接更新服务", body["error"])

    def test_cache_prevents_second_outbound_call(self):
        calls = []
        static = json.dumps({"version": "v9.9.9"}).encode()
        with mock.patch("urllib.request.urlopen", _fake_urlopen(
                {panel.DEFAULT_UPDATE_STATIC_URL: static}, calls)):
            first = self._get()
            second = self._get()
        self.assertEqual(len(calls), 1, "10 分钟内第二次点击不应再出网")
        self.assertFalse(first.get_json()["cached"])
        self.assertTrue(second.get_json()["cached"])

    def test_expired_cache_refetches(self):
        calls = []
        static = json.dumps({"version": "v9.9.9"}).encode()
        with mock.patch("urllib.request.urlopen", _fake_urlopen(
                {panel.DEFAULT_UPDATE_STATIC_URL: static}, calls)):
            self._get()
            # 把缓存时间戳推到 TTL 之外
            panel._update_check_cache["at"] -= panel.UPDATE_CHECK_TTL + 1
            self._get()
        self.assertEqual(len(calls), 2)

    def test_failure_is_not_cached(self):
        """失败不能进缓存：否则一次网络抖动会让后续 10 分钟都返回同一个失败。"""
        calls = []
        static = json.dumps({"version": "v9.9.9"}).encode()
        with mock.patch("urllib.request.urlopen", _fake_urlopen({}, calls)):
            self._get()
        with mock.patch("urllib.request.urlopen", _fake_urlopen(
                {panel.DEFAULT_UPDATE_STATIC_URL: static}, calls)):
            r = self._get()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

    def test_requires_token(self):
        with panel.app.test_client() as client:
            r = client.get("/api/update/check")
        self.assertEqual(r.status_code, 403)


class PanelCspAllowsGitHubApiTests(unittest.TestCase):
    """面板 CSP 必须放行 api.github.com（本次 NetworkError 的**根因**）。

    原 `connect-src 'self'` 把「检查更新」与「更新日志」两条浏览器直连 GitHub 的
    fetch 一起挡掉了。CSP 拦截在 Firefox 里抛的正是
    `TypeError: NetworkError when attempting to fetch resource.` —— 与真的网络不通
    表现完全一致，所以「浏览器能打开 GitHub 网页」和「面板里检查更新报 NetworkError」
    会同时成立，极易误判成网络/服务器问题。

    这里锁死：面板页面（含 SPA 兜底响应）的 CSP 必须允许 api.github.com，
    且不得因此放开 script-src（放行只该发生在 connect-src 上）。
    """

    def _csp(self, path="/"):
        with panel.app.test_client() as client:
            r = client.get(path, headers={"X-Shield-Token": panel.API_TOKEN})
        return r.headers.get("Content-Security-Policy", "")

    def test_spa_page_csp_allows_github_api(self):
        csp = self._csp("/")
        self.assertIn("connect-src", csp)
        connect = csp.split("connect-src", 1)[1].split(";", 1)[0]
        self.assertIn("https://api.github.com", connect,
                      "CSP connect-src 未放行 api.github.com，浏览器直连会被拦截")

    def test_csp_still_restricts_scripts_to_self(self):
        """放行只该加在 connect-src：script-src 必须仍是 'self'（审计 P2-2 的收口）。"""
        csp = self._csp("/")
        script = csp.split("script-src", 1)[1].split(";", 1)[0]
        self.assertIn("'self'", script)
        self.assertNotIn("unsafe-inline", script)
        self.assertNotIn("github.com", script)

    def test_csp_does_not_open_wildcard(self):
        """不能图省事写成 `connect-src *` —— 那等于关掉整条 CSP 的出口约束。"""
        csp = self._csp("/")
        connect = csp.split("connect-src", 1)[1].split(";", 1)[0]
        self.assertNotIn("*", connect)


if __name__ == "__main__":
    unittest.main()
