"""控制面 Origin 校验开关（origin_check + MASKIT_DISABLE_ORIGIN_CHECK）与静态资源放行回归测试。

设计依据（实测 Nginx 反代白屏与 EdgeOne 场景）：
1. 静态资源防白屏：浏览器加载 <script type="module" crossorigin> 时会强制附带 Origin 头，
   非 /api/ 路径（/、/assets/*、/favicon.ico 等）绝不可被 Origin/Host 校验误拦 403；
2. API 接口安全防线：/api/* 接口必须在开启校验时严格拦截外站跨源调用（403）；
3. 逃生与配置闭环：配置开关（origin_check=false）或环境变量（MASKIT_DISABLE_ORIGIN_CHECK=1）
   生效时放行，确保反代/CDN 用户可正常使用。
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import panel  # noqa: E402


class OriginCheckTest(unittest.TestCase):
    """控制面 Origin 校验开关与静态资源免检行为。"""

    def setUp(self):
        self.client = panel.app.test_client()
        # 隔离模块级状态：不继承真实配置/其他测试的残留值
        self._saved_env = panel._DISABLE_ORIGIN_CHECK_ENV
        self._saved_check = panel._origin_check_enabled
        self._saved_remote = panel.REMOTE_MODE
        self._saved_config_path = panel.CONFIG_PATH
        self._tmp_dir = tempfile.TemporaryDirectory(prefix="maskit-test-origin-")
        panel.CONFIG_PATH = Path(self._tmp_dir.name) / "config.json"
        panel._DISABLE_ORIGIN_CHECK_ENV = False
        panel._origin_check_enabled = True
        panel.REMOTE_MODE = False

    def tearDown(self):
        panel._DISABLE_ORIGIN_CHECK_ENV = self._saved_env
        panel._origin_check_enabled = self._saved_check
        panel.REMOTE_MODE = self._saved_remote
        panel.CONFIG_PATH = self._saved_config_path
        try:
            self._tmp_dir.cleanup()
        except Exception:
            pass

    def _get(self, origin, path="/api/status"):
        headers = {"X-Shield-Token": panel.API_TOKEN}
        if origin:
            headers["Origin"] = origin
        return self.client.get(path, headers=headers)

    def test_static_assets_never_blocked_by_origin_check(self):
        """防白屏关键测试：静态文件与页面带任何 Origin 都绝不应被 403 误杀。"""
        # 模拟浏览器加载带 crossorigin 的 JS/CSS 静态脚本
        r_page = self._get("https://maskit.ubuntu.test", path="/")
        self.assertNotEqual(r_page.status_code, 403, "SPA HTML 页面不能被 Origin 校验拦截 403")

        r_asset = self._get("https://maskit.ubuntu.test", path="/assets/index-sample.js")
        self.assertNotEqual(r_asset.status_code, 403, "JS 静态资源不能被 Origin 校验拦截 403 导致白屏")

    def test_default_rejects_foreign_origin_on_api(self):
        """本地模式默认：/api/* 接口收到外站 Origin 必须拦截 -> 403。"""
        r = self._get("https://evil.example.com")
        self.assertEqual(r.status_code, 403)

    def test_default_allows_same_origin_on_api(self):
        """本地模式默认：/api/* 接口收到面板自身同源 Origin 放行。"""
        r = self._get(f"http://127.0.0.1:{panel.PANEL_PORT}")
        self.assertNotEqual(r.status_code, 403)

    def test_default_allows_no_origin_on_api(self):
        """默认：/api/* 接口无 Origin 头（服务端直接调用）放行。"""
        r = self._get(None)
        self.assertNotEqual(r.status_code, 403)

    def test_save_config_syncs_runtime_immediately(self):
        """关键时序测试：save_config() 保存后必须立即同步内存全局变量，无需等待下次读盘。"""
        cfg = panel.default_config()
        cfg["origin_check"] = False
        panel.save_config(cfg)
        self.assertFalse(panel._origin_check_enabled, "save_config 后 _origin_check_enabled 必须立即为 False")

        # 校验已关闭 -> API 接口外站 Origin 放行
        r = self._get("https://evil.example.com")
        self.assertNotEqual(r.status_code, 403)

        # 再次打开开关
        cfg["origin_check"] = True
        panel.save_config(cfg)
        self.assertTrue(panel._origin_check_enabled, "save_config 后 _origin_check_enabled 必须立即恢复 True")

        # 校验已恢复 -> API 接口外站 Origin 再次被拦截
        r = self._get("https://evil.example.com")
        self.assertEqual(r.status_code, 403)

    def test_env_escape_hatch_disables_check(self):
        """环境变量逃生舱（MASKIT_DISABLE_ORIGIN_CHECK=1）-> 外站 Origin 放行。"""
        panel._DISABLE_ORIGIN_CHECK_ENV = True
        r = self._get("https://evil.example.com")
        self.assertNotEqual(r.status_code, 403)

    def test_remote_mode_default_rejects_mismatched_origin(self):
        """远程部署模式默认（REMOTE_MODE=True）：反代回源 Origin 不匹配时 API 报 403。"""
        panel.REMOTE_MODE = True
        r = self._get("https://maskit.example.com")
        self.assertEqual(r.status_code, 403)

    def test_remote_mode_origin_check_disabled_allows_mismatched(self):
        """远程部署模式下（REMOTE_MODE=True）：关闭 origin_check 允许 EdgeOne/Nginx 等反代放行 API。"""
        panel.REMOTE_MODE = True
        panel._origin_check_enabled = False
        r = self._get("https://maskit.example.com")
        self.assertNotEqual(r.status_code, 403)

    def test_remote_mode_env_escape_hatch_allows_mismatched(self):
        """远程部署模式下（REMOTE_MODE=True）：环境变量 MASKIT_DISABLE_ORIGIN_CHECK=1 允许放行 API。"""
        panel.REMOTE_MODE = True
        panel._DISABLE_ORIGIN_CHECK_ENV = True
        r = self._get("https://maskit.example.com")
        self.assertNotEqual(r.status_code, 403)

    def test_emergency_disable_origin_check_with_valid_token(self):
        """自救能力测试：即使在外部 Origin 拦截态下，持合法 Token 调用自救接口必须放行并成功关闭校验。"""
        panel.REMOTE_MODE = True
        panel._origin_check_enabled = True
        # 常规 API 接口被拦且返回精准错误码
        r_blocked = self._get("https://maskit.example.com", path="/api/status")
        self.assertEqual(r_blocked.status_code, 403)
        self.assertEqual(r_blocked.get_json().get("error"), "origin_rejected")

        # 调用自救接口关闭 Origin 校验
        headers = {"X-Shield-Token": panel.API_TOKEN, "Origin": "https://maskit.example.com"}
        r_rescue = self.client.post("/api/config/disable_origin_check", headers=headers)
        self.assertEqual(r_rescue.status_code, 200)
        self.assertTrue(r_rescue.get_json().get("ok"))
        self.assertFalse(panel._origin_check_enabled, "自救后 _origin_check_enabled 必须立即为 False")

        # 校验已解除，后续 API 顺利放行
        r_after = self._get("https://maskit.example.com", path="/api/status")
        self.assertEqual(r_after.status_code, 200)

    def test_emergency_disable_origin_check_rejects_invalid_token(self):
        """安全基线：即便调用自救接口，若未提供合法 Token，仍坚决 403 阻断。"""
        panel.REMOTE_MODE = True
        headers = {"X-Shield-Token": "bad-token-12345", "Origin": "https://maskit.example.com"}
        r = self.client.post("/api/config/disable_origin_check", headers=headers)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json().get("error"), "invalid_token")


if __name__ == "__main__":
    unittest.main()
