"""本地试验台（`/api/demo/lab` + `transparent.demo_store_scope`）的隔离契约。

试验台要同时满足两件互相拉扯的事：演示结果必须**与真实请求同口径**（同一原文在
本机已有存活 token 时要显示那个 token），演示期间又**不能给真实链路留任何痕迹**。
只靠 sid 做不到后者——sid 只隔离 `sessions`，签发 token 用的复用表是进程级全局的。

因此这里锁的不是"功能能跑"，而是三条可被证伪的性质：
1. **真实映射零写入**：演示前后真实表逐项相等（含时间戳），演示样本不出现在里面；
2. **零事件**：`enqueue_event` 一次都不该被调用，演示会话用后即删；
3. **零残留**：无论正常结束还是抛异常，表组覆盖与会话都要还原（`finally` 兜住）。

样例一律分片拼接（AGENTS.md §3.9）：直接写字面量的真实形态号码会被本机网关在
落盘时还原成真实值 —— 本仓库的样例里真的发生过这件事。
"""
import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import transparent as tr  # noqa: E402

# 明显伪造、且仍命中内置规则的样例（分片拼接，源码里不存在完整号码）
PHONE = "1" + "3" + "0" + "0" * 8
MAIL = "zhangsan" + "@" + "example.com"
KEY = "sk" + "-" + "demo" + "0" * 12
SAMPLE = "电话 " + PHONE + "，邮箱 " + MAIL + "，key " + KEY


class FakeStoreScopeTests(unittest.TestCase):
    """表组隔离本身（不经 HTTP）。"""

    def setUp(self):
        self._snap = {n: copy.deepcopy(getattr(tr, n)) for n in
                      ("_RECENT_FWD", "_RECENT_REV", "_RECENT_SUFFIX",
                       "_CUSTOM_WORD_FWD", "_CUSTOM_WORD_REV")}
        tr.sessions.clear()

    def tearDown(self):
        tr.sessions.clear()

    def test_default_tables_follow_module_globals(self):
        """默认表组必须**动态**读模块全局：词表重载会整体换对象（_sync_custom_words）。"""
        self.assertIs(tr._tables().fwd, tr._RECENT_FWD)
        self.assertIs(tr._tables().rev, tr._RECENT_REV)
        self.assertIs(tr._tables().suffix, tr._RECENT_SUFFIX)
        swapped = {}
        with mock.patch.object(tr, "_RECENT_FWD", swapped):
            self.assertIs(tr._tables().fwd, swapped, "换对象后必须立刻可见")

    def test_scope_swaps_and_restores(self):
        before = tr._tables()
        with tr.demo_store_scope() as store:
            self.assertIsNot(tr._tables(), before, "作用域内必须切到演示仓")
            self.assertIs(tr._tables(), store)
        self.assertIs(tr._tables(), before, "退出后必须还原")

    def test_nested_scopes_restore_outer(self):
        outer = None
        with tr.demo_store_scope() as a:
            outer = a
            with tr.demo_store_scope() as b:
                self.assertIs(tr._tables(), b)
            self.assertIs(tr._tables(), outer, "内层退出必须回到外层，而不是全局")

    def test_scope_restores_on_exception(self):
        before = tr._tables()
        with self.assertRaises(RuntimeError):
            with tr.demo_store_scope():
                raise RuntimeError("boom")
        self.assertIs(tr._tables(), before)

    def test_demo_mask_writes_nothing_to_real_tables(self):
        """核心断言：演示脱敏真实表零变化（含时间戳）。"""
        with tr.demo_store_scope():
            tr._new_session("demo-x")
            masked = tr.mask(SAMPLE, "demo-x")
        self.assertTrue(tr._PLACEHOLDER_RX.search(masked), "样例应当被真的脱敏")
        for name, snapshot in self._snap.items():
            self.assertEqual(getattr(tr, name), snapshot,
                             "%s 在演示期间被改动（演示样本不得进入真实映射）" % name)

    def test_demo_reuses_live_token_without_touching_it(self):
        """同口径：真实窗口里已有 token 时演示要复用它，且真实记录逐字节不变。"""
        real_sid = "real-session"
        tr._new_session(real_sid)
        real_masked = tr.mask("电话 " + PHONE, real_sid)
        real_token = tr._RECENT_FWD.get(PHONE)
        self.assertIsNotNone(real_token, "前置条件：真实脱敏应登记复用表")
        # 取**值快照**而不是引用：直接拿 `real_token` 去和后面对比是拿同一对象和
        # 自己比，`hit[2] = now` 这种就地续期永远比不出来（写过一次假绿）。
        real_snapshot = [list(x) for x in (real_token, tr._RECENT_REV[real_token[0]])]
        with tr.demo_store_scope():
            tr._new_session("demo-y")
            demo_masked = tr.mask("电话 " + PHONE, "demo-y")
            demo_token = tr._tables().fwd.get(PHONE)
        self.assertEqual(demo_token[0], real_token[0],
                         "演示必须与真实请求同口径（复用同一个 token）")
        self.assertIn(real_token[0], demo_masked)
        self.assertIn(real_token[0], real_masked)
        self.assertEqual([list(x) for x in (tr._RECENT_FWD[PHONE],
                                            tr._RECENT_REV[real_token[0]])],
                         real_snapshot, "演示的续期/写入不得落回真实表")

    def test_demo_restore_uses_demo_store(self):
        """往返还原在演示仓内成立（否则「脱敏后能不能还原」就演示不出来）。"""
        with tr.demo_store_scope():
            tr._new_session("demo-z")
            masked = tr.mask(SAMPLE, "demo-z")
            restored = tr.restore(masked, "demo-z")
        self.assertEqual(restored, SAMPLE)


class DemoLabEndpointTests(unittest.TestCase):
    def setUp(self):
        import panel
        self.panel = panel
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = {"config": panel.CONFIG_PATH,
                      "origin": panel._origin_check_enabled, "remote": panel.REMOTE_MODE}
        panel.CONFIG_PATH = self.tmp / "config.json"
        panel._origin_check_enabled = False
        panel.REMOTE_MODE = False
        panel.save_config(panel.default_config())
        tr.sessions.clear()
        self.client = panel.app.test_client()
        self.addCleanup(self._restore)

    def _restore(self):
        self.panel.CONFIG_PATH = self._orig["config"]
        self.panel._origin_check_enabled = self._orig["origin"]
        self.panel.REMOTE_MODE = self._orig["remote"]
        tr.sessions.clear()

    def _lab(self, text=None):
        body = {"text": text} if text is not None else {}
        return self.client.post("/api/demo/lab", json=body,
                                headers={"X-Shield-Token": self.panel.API_TOKEN})

    def test_default_sample_gets_masked_and_roundtrips(self):
        r = self._lab()
        self.assertEqual(r.status_code, 200)
        j = r.get_json()
        self.assertTrue(j["ok"])
        self.assertTrue(j["changed"])
        self.assertGreaterEqual(j["count"], 3, "样例应命中电话/邮箱/凭据三类")
        self.assertEqual(j["unresolved"], 0)
        self.assertTrue(j["roundtrip_ok"], "还原结果必须与输入逐字相同")
        for item in j["items"]:
            self.assertNotIn("original", item, "不得回传原文")
            self.assertIn("original_len", item)
            self.assertIn(item["label"], j["by_label"])

    def test_unique_entities_vs_occurrences(self):
        """同一个值出现两次 = 1 个实体、2 次出现（把"脱敏几千还原几十"讲清楚）。"""
        r = self._lab("电话 " + PHONE + " 再一遍 " + PHONE)
        self.assertEqual(r.status_code, 200)
        j = r.get_json()
        self.assertEqual(j["count"], 1)
        self.assertEqual(j["occurrences"], 2)
        self.assertEqual(len(j["items"]), 1)
        self.assertEqual(j["items"][0]["occurrences"], 2)

    def test_too_long_rejected(self):
        r = self._lab("x" * (self.panel._DEMO_LAB_MAX_CHARS + 1))
        self.assertEqual(r.status_code, 400)
        j = r.get_json()
        self.assertEqual(j["error"], "text_too_long")
        self.assertEqual(j["limit"], self.panel._DEMO_LAB_MAX_CHARS)

    def test_busy_is_bounded_not_queued(self):
        """槽位耗尽必须立即 503：排队会让 UI 看着卡住。"""
        panel = self.panel
        acquired = [panel._DEMO_LAB_SLOTS.acquire(blocking=False),
                    panel._DEMO_LAB_SLOTS.acquire(blocking=False)]
        self.assertEqual(acquired, [True, True], "前置条件：能占满槽位")
        try:
            r = self._lab("电话 " + PHONE)
            self.assertEqual(r.status_code, 503)
            self.assertEqual(r.get_json()["error"], "busy")
        finally:
            panel._DEMO_LAB_SLOTS.release()
            panel._DEMO_LAB_SLOTS.release()
        # 槽位释放后必须立刻可用（不能因为一次 503 就永久占住）
        self.assertEqual(self._lab("电话 " + PHONE).status_code, 200)

    def test_no_events_and_no_session_left(self):
        captured = []
        with mock.patch.object(tr, "enqueue_event", lambda rec: captured.append(rec)):
            r = self._lab("电话 " + PHONE)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(captured, [], "试验台不得写事件库（样本只在本机内存里）")
        demos = [s for s in tr.sessions if s.startswith("demo-")]
        self.assertEqual(demos, [], "演示会话必须清理干净")

    def test_slot_released_and_scope_restored_on_failure(self):
        """抛异常也要还原：槽位、会话、表组三者都不能留残留。"""
        panel, before = self.panel, tr._tables()
        with mock.patch.object(tr, "mask", side_effect=RuntimeError("boom")):
            r = self._lab("电话 " + PHONE)
        self.assertEqual(r.status_code, 500)
        self.assertFalse(r.get_json()["ok"])
        self.assertIs(tr._tables(), before, "异常路径必须还原表组")
        self.assertEqual([s for s in tr.sessions if s.startswith("demo-")], [],
                         "异常路径必须清理演示会话")
        # 槽位已释放：修好 mask 后同一客户端立即可用
        self.assertEqual(self._lab("电话 " + PHONE).status_code, 200)
        self.assertEqual(panel._DEMO_LAB_SLOTS._value, 2, "信号量必须回到满值")

    def test_real_tables_untouched_through_http_path(self):
        # 快照对比而不是 `== {}`：整仓跑测时别的用例已经在真实表里留了条目，
        # 断言“空”会把测试之间的残留当成演示污染（假红）。
        fwd_before = copy.deepcopy(tr._RECENT_FWD)
        rev_before = copy.deepcopy(tr._RECENT_REV)
        r = self._lab(SAMPLE)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(tr._RECENT_FWD, fwd_before)
        self.assertEqual(tr._RECENT_REV, rev_before)


if __name__ == "__main__":
    unittest.main()