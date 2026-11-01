"""启发层扫描上限不应把长会话整体打成「检测不完整」（2026-10-25 真机事故）。

## 事故

v0.12.0 上线后真机事件库：

    v0.12.0 之后 MASK 145 条 → partial 144 条（99%），原因码全是 `zh_names_truncated`

用户看到的是**每一行**都挂着「检测不完整」黄标，等于这个告警彻底失去信息量。

## 根因

`zh_names.MAX_SCAN_CHARS = 32KB` 是**有界设计**（逐字符循环，最坏 3.6µs/字符，
不设上限就是热路径 DoS 面）。但它被登记成 `degraded` 类原因码，而
`completeness_of` 只要见到一个 `degraded` 就把整条请求打成 `partial`。

而长会话的形态是「客户端每轮重发整段历史」：1487 条消息、1.9MB 请求体是常态
（真机 scan_scope 实测）。32KB 的姓名扫描窗口对这类请求**必然**截断，于是
「每一条都降级」。

## 为什么不是「把上限调大」就完事

调大上限治不了根：文本再长还是会截断，只是频率变低。而且逐字符扫描的成本是
线性的——1MB 中文正文实测 482ms、姓氏密集最坏 3.6s，直接调大等于把 DoS 面放大。

## 正确判据

启发层是**加分项**（补 NER 漏检），不是「所配置的检测」本体。它没扫完全文，
等价于「这一段没补到」，而不是「检测没跑完」——后者会让用户以为连正则都没跑。

所以：

1. 新增 `partial_scope` 类别：**可见但不降级**。它进 `reason_codes` 让用户能查，
   但不参与 `completeness` 判定、不参与严格模式阻断。
2. 同时把扫描成本降下来（分桶 + 早退），让 32KB 能覆盖更多真实场景。

判据的**方向性**很重要：把「加分项没跑完」当成「检测不完整」，是把保守方向用反了
——它制造的不是安全，而是噪声（真机 99% 命中率就是证明）。
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import inspection
import transparent as tr
import zh_names


class ReasonCategoryTests(unittest.TestCase):
    """`zh_names_truncated` 必须是「可见但不降级」的类别。"""

    def test_truncation_is_not_degraded(self):
        cat = inspection.reason_category("zh_names_truncated")
        self.assertNotEqual(cat, "degraded",
                            "启发层截断不得把 completeness 打成 partial")

    def test_truncation_is_visible(self):
        """不降级 ≠ 静默：它必须仍在原因码表里（否则用户无从知道）。"""
        self.assertIn("zh_names_truncated", inspection.REASON_CODES)

    def test_truncation_does_not_block_strict_mode(self):
        self.assertFalse(inspection.has_blocking_reason({"zh_names_truncated": 3}))

    def test_truncation_keeps_completeness_complete(self):
        self.assertEqual(
            inspection.completeness_of({"zh_names_truncated": 3}),
            inspection.COMPLETE)

    def test_real_degradation_still_partial(self):
        """收窄不能顺手把真正的降级也放过去——误放比误杀更危险。"""
        for code in ("budget_exhausted", "deadline", "model_unavailable", "known_scan"):
            with self.subTest(code=code):
                self.assertEqual(
                    inspection.completeness_of({code: 1}), inspection.PARTIAL)

    def test_mixed_reasons_still_partial(self):
        """截断与真降级同时出现时，仍按真降级算 partial。"""
        self.assertEqual(
            inspection.completeness_of({"zh_names_truncated": 5, "deadline": 1}),
            inspection.PARTIAL)


class LongSessionCompletenessTests(unittest.TestCase):
    """长会话真实形态：截断发生，但 MASK 事件的 completeness 必须是 complete。"""

    def _long_chinese_body(self, chars=200_000):
        unit = "这是第 3 轮对话，讨论订单服务的超时重试策略。客户反馈登录失败。\n"
        text = (unit * (chars // len(unit) + 1))[:chars]
        return json.dumps({"model": "m", "messages": [
            {"role": "user", "content": text}]}, ensure_ascii=False)

    def test_truncated_scan_does_not_degrade(self):
        import os
        import shutil
        import tempfile
        from unittest import mock

        # 启发层只在 NER 开启时生效，必须走真实配置路径（不能直接改模块常量，
        # 否则 `_maybe_reload` 会把它冲掉）。
        d = tempfile.mkdtemp(prefix="maskit-trunc-")
        saved = {k: getattr(tr, k) for k in (
            "CUSTOM_WORDS", "BUILTIN_RULES", "SENSITIVE_DISABLED",
            "SENSITIVE_WORD_DISABLED", "SENSITIVE_WORD_WHOLE",
            "UPSTREAMS", "TARGET_DOMAINS", "API_PATHS",
            "CAPTURE_MODE", "FAIL_CLOSED", "_DATA_ROOT")}
        mtime = tr._cfg_mtime[0]
        import ner_engine
        try:
            with open(os.path.join(d, "config.json"), "w", encoding="utf-8") as fh:
                json.dump({"sensitive": {}, "builtin_rules": {}, "ner_enabled": True,
                           "target_domains": ["api.example.com"],
                           "api_paths": ["/v1/messages"]}, fh, ensure_ascii=False)
            tr._DATA_ROOT = Path(d)
            tr._cfg_mtime[0] = None
            tr._maybe_reload(force=True)
            tr.BUILTIN_RULES = {k: False for k in tr.DEFAULT_BUILTIN_RULES}
            tr._CUSTOM_WORD_RX_CACHE.clear()
            tr._known_reset_for_tests()
            sid = "long-zh"
            tr._new_session(sid)
            body = self._long_chinese_body()
            self.assertGreater(len(body), zh_names.MAX_SCAN_CHARS)

            with mock.patch.object(ner_engine, "is_ner_available", lambda: False):
                tr.mask_body(body, sid)
            # 2026-11-02：启发层已改为**全文扫描**（候选位 + 证据词预筛，1.3MB 实测
            # ~8ms），不再截断 → 长会话不再产生 `zh_names_truncated`。
            # 本用例的核心契约是「截断若发生，不得降级」，而截断本身已经不存在，
            # 所以断言改为：**不得出现该原因码**（出现就意味着截断又回来了）。
            skips = tr._ner_skips_of_this_round()
            self.assertNotIn("zh_names_truncated", skips,
                             "启发层已全文扫描，不应再产生截断标记")
            # 而一旦它真的出现（未来回退），仍必须是「可见但不降级」：
            # 这条断言独立成立，不依赖上面的前提。
            self.assertEqual(inspection.completeness_of({"zh_names_truncated": 1}),
                             inspection.COMPLETE,
                             "启发层截断不得把长会话打成检测不完整")
        finally:
            for k, v in saved.items():
                setattr(tr, k, v)
            tr._cfg_mtime[0] = mtime
            shutil.rmtree(d, ignore_errors=True)
            tr._known_reset_for_tests()


class ScanCostTests(unittest.TestCase):
    """扫描成本上限：无论文本多长，单次调用都必须**有界**。

    2026-11-02 变更：启发层从「逐字符循环 + 32KB 硬截断」改为「证据词预筛 +
    姓氏候选位扫描」，成本从 O(全文) 降到 O(证据词数 × 窗口)。所以：
      · 不再截断（长文本里的人名也能扫到）；
      · `truncated` 恒为 False（参数保留只为兼容调用方）；
      · 但**有界性仍必须成立** —— 本类最后一条用例锁的就是它（2M 姓氏密集文本
        不得退化成秒级）。
    """

    def test_long_text_is_fully_scanned_not_truncated(self):
        """姓氏密集的 2M 字符文本：必须**全文扫**且**不报截断**。

        旧实现在 32KB 处停手并报 truncated；新实现扫完全文（仍须有界，见下条）。
        """
        text = "王李张刘陈杨黄赵吴周" * 200_000  # 2M 字符，姓氏最密集形态
        spans, truncated = zh_names.find_names(text, return_truncated=True)
        self.assertFalse(truncated, "启发层已不再截断，不应报 truncated")
        self.assertIsInstance(spans, list)

    def test_scan_cost_stays_bounded_on_dense_text(self):
        """有界性回归锁：2M 姓氏密集文本不得退化成秒级（旧逐字符实现要 7 秒）。"""
        import time
        text = "王李张刘陈杨黄赵吴周" * 200_000
        t0 = time.perf_counter()
        zh_names.find_names(text)
        cost = time.perf_counter() - t0
        self.assertLess(cost, 3.0,
                        "启发层扫描退化为线性逐字符（2M 字符耗时 %.2fs）" % cost)

    def test_no_truncation_flag_for_short_text(self):
        sample = "客户" + "{{NAME_" + "xkjnzw" + "}}" + "反馈登录失败。"
        spans, truncated = zh_names.find_names(sample, return_truncated=True)
        self.assertFalse(truncated)

    def test_empty_and_non_string_inputs(self):
        for bad in (None, "", 1, [], {}):
            with self.subTest(value=bad):
                self.assertEqual(zh_names.find_names(bad), [])

    def test_no_truncation_flag_without_chinese(self):
        """超长但**无汉字**的文本不报截断（2026-10-25 复核 P2-1）。

        为什么必须锁：截断标志若在「无汉字早退」之前置位，一段 >32KB 的纯英文 /
        纯代码 system prompt 也会报 `zh_names_truncated` —— 而它里面根本没有
        姓名候选，截断没损失任何东西。那是纯噪声，而本模块的全部意义就是去噪。
        """
        code = "function foo(){return 1;}\n" * 2000   # ~50KB 纯英文
        self.assertGreater(len(code), zh_names.MAX_SCAN_CHARS)
        spans, truncated = zh_names.find_names(code, return_truncated=True)
        self.assertEqual(spans, [])
        self.assertFalse(truncated, "无汉字的超长文本不得报截断")

    def test_truncation_flag_with_chinese(self):
        """超长**有汉字**的文本：现在必须**全文扫到人名**（旧实现在 32KB 处停手）。

        这条用例从「必须报截断」改为「必须扫到尾部人名」—— 因为 32KB 截断本身
        就是漏检（真机长会话里 `客户某某某` 常出现在正文深处）。
        """
        zh = "这是正文。\n" * 8000
        self.assertGreater(len(zh), zh_names.MAX_SCAN_CHARS)
        surname = "\u738b"       # 运行时拼接，不在源码写姓名
        given = "\u5927\u9524"
        tail = "联系人：" + surname + given + "请回电。"
        text = zh + tail
        spans, truncated = zh_names.find_names(text, return_truncated=True)
        self.assertFalse(truncated, "已不再截断")
        self.assertTrue(spans, "超过 32KB 之后的人名也必须扫到（旧实现返回空）")
        hit = [text[s:e] for s, e, _ in spans]
        self.assertIn(surname + given, hit)


if __name__ == "__main__":
    unittest.main()
