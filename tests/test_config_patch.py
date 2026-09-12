"""配置增量端点（POST /api/config/patch）的行为约束。

POST /api/config 只在顶层做浅合并，凡是「值本身是容器」的字段，前端只能提交整份
快照；快照一过期就会把并发写入整对象覆盖掉。本文件守住增量端点的两条底线：
1) 局部修改必须只影响被点名的那个位置；
2) 非法请求必须原子拒绝，绝不能留下半改状态。
"""
from concurrent.futures import ThreadPoolExecutor
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import panel


class ConfigPatchEndpointTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(panel, "CONFIG_PATH", Path(tmp.name) / "config.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        panel.save_config(panel.default_config())
        self.headers = {"X-Shield-Token": panel.API_TOKEN}

    def patch(self, body):
        with panel.app.test_client() as client:
            return client.post("/api/config/patch", json=body, headers=self.headers)

    def cfg(self):
        return panel.load_config()

    # ---- 局部性 ----------------------------------------------------------

    def test_nested_set_touches_only_the_named_path(self):
        before = self.cfg()
        response = self.patch({"key": "audit", "op": "set",
                               "path": ["signals", "error_leak"], "value": False})
        self.assertEqual(response.status_code, 200)
        after = self.cfg()
        self.assertFalse(after["audit"]["signals"]["error_leak"])
        # 同一对象的兄弟键必须原样保留（这正是整对象提交会破坏的部分）
        self.assertEqual(
            {k: v for k, v in after["audit"]["signals"].items() if k != "error_leak"},
            {k: v for k, v in before["audit"]["signals"].items() if k != "error_leak"},
        )
        self.assertEqual({k: v for k, v in after["audit"].items() if k != "signals"},
                         {k: v for k, v in before["audit"].items() if k != "signals"})

    def test_list_add_and_remove_only_affect_listed_items(self):
        self.assertEqual(self.patch({"key": "target_domains", "op": "list_add",
                                     "value": ["a.example.com", "b.example.com"]}).status_code, 200)
        self.assertIn("a.example.com", self.cfg()["target_domains"])
        self.assertIn("b.example.com", self.cfg()["target_domains"])
        self.assertEqual(self.patch({"key": "target_domains", "op": "list_remove",
                                     "value": ["a.example.com"]}).status_code, 200)
        domains = self.cfg()["target_domains"]
        self.assertNotIn("a.example.com", domains)
        self.assertIn("b.example.com", domains)
        # 原有域名一个都不能掉
        for original in panel.default_config()["target_domains"]:
            self.assertIn(original, domains)

    def test_list_add_is_idempotent(self):
        for _ in range(3):
            self.assertEqual(self.patch({"key": "target_domains", "op": "list_add",
                                         "value": ["dup.example.com"]}).status_code, 200)
        self.assertEqual(self.cfg()["target_domains"].count("dup.example.com"), 1)

    def test_list_add_creates_missing_sensitive_category(self):
        self.assertEqual(self.patch({"key": "sensitive", "op": "list_add",
                                     "path": ["新分类"], "value": ["代号甲"]}).status_code, 200)
        self.assertEqual(self.cfg()["sensitive"]["新分类"], ["代号甲"])

    def test_map_del_removes_only_listed_keys(self):
        self.patch({"key": "sensitive", "op": "list_add", "path": ["待删"], "value": ["x"]})
        self.patch({"key": "sensitive", "op": "list_add", "path": ["保留"], "value": ["y"]})
        self.assertEqual(self.patch({"key": "sensitive", "op": "map_del", "value": ["待删"]}).status_code, 200)
        sensitive = self.cfg()["sensitive"]
        self.assertNotIn("待删", sensitive)
        self.assertEqual(sensitive["保留"], ["y"])

    def test_merge_updates_only_given_keys(self):
        self.assertEqual(self.patch({"key": "egress_proxy", "op": "set",
                                     "path": ["url"], "value": "http://127.0.0.1:7890"}).status_code, 200)
        self.assertEqual(self.patch({"key": "egress_proxy", "op": "merge",
                                     "value": {"enabled": True}}).status_code, 200)
        proxy = self.cfg()["egress_proxy"]
        self.assertTrue(proxy["enabled"])
        self.assertEqual(proxy["url"], "http://127.0.0.1:7890")

    # ---- 客户端按 name 就地更新 -------------------------------------------

    def test_upstream_upsert_appends_then_updates_in_place(self):
        original = self.cfg()["upstreams"]
        self.assertGreaterEqual(len(original), 1)
        added = dict(original[0], name="added", port=18999, base_path="/added")
        self.assertEqual(self.patch({"key": "upstreams", "op": "list_upsert",
                                     "value": added}).status_code, 200)
        names = [u["name"] for u in self.cfg()["upstreams"]]
        self.assertEqual(names[:len(original)], [u["name"] for u in original])
        self.assertEqual(names[-1], "added")

        renamed = dict(added, name="renamed", port=18998)
        self.assertEqual(self.patch({"key": "upstreams", "op": "list_upsert",
                                     "value": renamed, "match": "added"}).status_code, 200)
        ups = self.cfg()["upstreams"]
        self.assertEqual(len(ups), len(original) + 1)
        self.assertEqual([u["name"] for u in ups].count("added"), 0)
        self.assertEqual([u for u in ups if u["name"] == "renamed"][0]["port"], 18998)

        # 带 match 但 value 未显式提供 name 时，必须继承目标条目名，防止变成无名对象被 normalize 丢弃
        self.assertEqual(self.patch({"key": "upstreams", "op": "list_upsert",
                                     "value": {"port": 18997, "target": "https://api.example.com"},
                                     "match": "renamed"}).status_code, 200)
        ups2 = self.cfg()["upstreams"]
        renamed_entry = [u for u in ups2 if u.get("name") == "renamed"]
        self.assertEqual(len(renamed_entry), 1)
        self.assertEqual(renamed_entry[0]["port"], 18997)
        self.assertEqual(renamed_entry[0]["name"], "renamed")

    def test_upstream_delete_keeps_others(self):
        original = self.cfg()["upstreams"]
        target = original[0]["name"]
        self.assertEqual(self.patch({"key": "upstreams", "op": "list_del",
                                     "value": target}).status_code, 200)
        remaining = [u["name"] for u in self.cfg()["upstreams"]]
        self.assertNotIn(target, remaining)
        self.assertEqual(remaining, [u["name"] for u in original[1:]])

    # ---- 并发 ------------------------------------------------------------

    def test_concurrent_list_adds_do_not_lose_updates(self):
        barrier = threading.Barrier(2)

        def add(domain):
            barrier.wait(timeout=5)
            return self.patch({"key": "target_domains", "op": "list_add", "value": [domain]}).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(add, ("x.example.com", "y.example.com"))), [200, 200])
        domains = self.cfg()["target_domains"]
        self.assertIn("x.example.com", domains)
        self.assertIn("y.example.com", domains)

    def test_set_creates_missing_leaf_but_not_missing_intermediate(self):
        # 末段允许新建（「新建一个敏感词分类」靠的就是这个语义）
        before = self.cfg()
        self.assertEqual(self.patch({"key": "sensitive", "op": "set",
                                     "path": ["新建"], "value": []}).status_code, 200)
        self.assertEqual(self.cfg()["sensitive"]["新建"], [])
        # 中间段缺失必须报错，不能静默建出一串空对象
        self.assertEqual(self.patch({"key": "audit", "op": "set",
                                     "path": ["不存在", "更深"], "value": 1}).status_code, 400)
        # 兄弟键保持原样
        self.assertEqual({k: v for k, v in self.cfg()["audit"].items()},
                         {k: v for k, v in before["audit"].items()})

    # ---- 非法请求必须原子拒绝 ---------------------------------------------

    def test_invalid_requests_are_rejected_and_config_unchanged(self):
        before = self.cfg()
        invalid = [
            {},
            {"key": "audit"},                                            # 缺 op / value
            {"key": "audit", "op": "set"},                               # 缺 value
            {"key": "", "op": "set", "value": 1},                        # 空 key
            {"key": "no_such_key", "op": "set", "value": 1},             # 未知配置项
            {"key": "audit", "op": "nope", "value": 1},                  # 未知操作
            {"key": "audit", "op": "set", "path": ["不存在", "更深"], "value": 1},  # 中间路径缺失
            {"key": "audit", "op": "set", "path": [1], "value": 1},      # 路径段非字符串
            {"key": "audit", "op": "set", "path": [""], "value": 1},     # 路径段为空串
            {"key": "target_domains", "op": "list_add", "value": "x"},   # 非数组取值
            {"key": "audit", "op": "merge", "value": [1]},               # merge 取值非对象
            {"key": "audit", "op": "map_del", "value": ["x", 1]},        # map_del 取值含非字符串
            {"key": "upstreams", "op": "list_upsert", "value": {"port": 1}},  # 缺 name
            {"key": "upstreams", "op": "list_del", "value": ""},         # 空 name
            {"key": "target_domains", "op": "list_remove", "value": [None]},
            {"key": "target_domains", "op": "list_add", "value": [123]},
        ]
        for body in invalid:
            with self.subTest(body=body):
                self.assertEqual(self.patch(body).status_code, 400)
                self.assertEqual(self.cfg(), before)

    def test_explicit_null_value_is_a_legal_set(self):
        # value 显式为 null 是合法的 set（是否被 normalize 改写成默认值由 save_config 决定），
        # 但「没有 value 字段」不是（见上一个用例）
        self.assertEqual(self.patch({"key": "egress_proxy", "op": "set",
                                     "path": ["url"], "value": None}).status_code, 200)
        self.assertFalse(self.cfg()["egress_proxy"]["url"])

    # ---- 控制面防线 -------------------------------------------------------

    def test_patch_endpoint_uses_existing_control_plane_guards(self):
        with panel.app.test_client() as client:
            for headers in ({}, {**self.headers, "Host": "example.invalid"},
                            {**self.headers, "Origin": "https://example.invalid"}):
                with self.subTest(headers=list(headers)):
                    response = client.post("/api/config/patch",
                                           json={"key": "audit", "op": "set", "value": 1},
                                           headers=headers)
                    self.assertEqual(response.status_code, 403)

    def test_api_guard_is_the_registered_before_request_hook(self):
        """钉死钩子接线：`api_guard` 才是 before_request 处理器。

        背景（真实事故）：给 `api_guard` 加拒绝日志时，新增的 `_guard_reject(reason, resp)`
        被插到了 `@app.before_request` 与 `api_guard` 之间，装饰器于是挂到了 `_guard_reject`
        头上 —— Flask 按无参调用它 → TypeError → **所有**请求 500（含非 /api/ 静态资源）。
        整套用例能抓到（61 项失败），但报错信息只会说「403 != 500」，指向不了根因，
        所以这里单独锁一条：注册的钩子必须是 `api_guard`，且它可无参调用。
        """
        handlers = [
            fn
            for funcs in panel.app.before_request_funcs.values()
            for fn in funcs
        ]
        self.assertIn(panel.api_guard, handlers)
        self.assertNotIn(panel._guard_reject, handlers)
        # 无参可调用 = 签名与 Flask 的调用约定一致（回归时这里是 TypeError）
        import inspect
        self.assertEqual(
            len([p for p in inspect.signature(panel.api_guard).parameters.values()
                 if p.default is inspect.Parameter.empty
                 and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]),
            0,
        )


if __name__ == "__main__":
    unittest.main()
