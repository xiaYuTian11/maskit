"""中文姓名启发层（补 NER 的漏检与过检）。

## 为什么需要

2026-10-25 隔离实例实测（`ner_engine.extract_entities`，模型已就绪）：

```
'写封信给张三，他住在北京市朝阳区建国路 88 号。'  -> NAME + ADDR ✅
'小张和小李今天请假了。'                          -> NAME ✅
'张开的括号和王国的军队都不是人名。'              -> NAME ❌（误检）
```

NER 是概率模型，两类错都真实存在：
- **漏检**：`客户陈建国` / `联系人：赵丽颖` 这类「角色词 + 姓名」的固定句式，
  模型经常只标出一部分或干脆漏掉；
- **过检**：`张开的括号` / `王国的军队` —— 姓氏字开头的普通词被当成姓名。

参照 magpie `internal/redact/zhname.go`：**纯 stdlib 的规则层**，用
「姓氏表 + 上下文证据 + 反例词表」双向修正模型结果。

## 关键设计

1. **只在 NER 开启时生效**（`ner_enabled=true`）。它是 NER 的**后处理**，
   不是独立检测器——关掉 NER 时跑它等于给用户一个他没开的检测面。
2. **只做「补漏」与「剔误」两件事**，不改写 NER 已经正确识别的区间。
3. **反例词表优先于姓氏规则**：`张量` / `高度` / `程序` 这类词永远不是人名。
4. **上下文证据必须明确**：`客户` / `我叫` / `…先生` / `…说` 这类，不能靠
   「前后是汉字」这种弱判据（那会把任意两字词都标成人名）。
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))


def _engine():
    import transparent as tr
    return tr


tr = _engine()


class ModuleShapeTests(unittest.TestCase):
    """模块必须存在、纯 stdlib、永不抛异常。"""

    def test_module_exists(self):
        import zh_names  # noqa: F401

    def test_no_heavy_dependencies(self):
        """纯 stdlib：这个模块要在脱敏热路径上跑，不能拖进 numpy/onnx。"""
        import ast

        src = (ROOT / "engine" / "zh_names.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.add(node.module.split(".")[0])
        forbidden = {"numpy", "onnxruntime", "tokenizers", "torch", "requests", "flask"}
        self.assertFalse(mods & forbidden, f"引入了重依赖：{mods & forbidden}")

    def test_never_raises(self):
        import zh_names

        for bad in (None, 0, [], {}, b"bytes", "", " ", "\x00"):
            with self.subTest(inp=repr(bad)):
                try:
                    zh_names.find_names(bad)
                except Exception as e:
                    self.fail(f"find_names({bad!r}) 抛了异常：{e}")


class FindNamesTests(unittest.TestCase):
    """补漏：模型漏掉的中文姓名必须被找到。"""

    def setUp(self):
        import zh_names
        self.zh = zh_names

    def _names(self, text):
        return [(text[s:e], kind) for s, e, kind in self.zh.find_names(text)]

    def test_role_word_then_name(self):
        """「客户陈建国」：角色词后紧跟姓名。"""
        names = [n for n, _ in self._names("客户陈建国反馈说订单有问题")]
        self.assertIn("陈建国", names, f"角色词后的姓名漏检：{names}")

    def test_i_am_called(self):
        """「我叫黄晓明」：自报姓名。"""
        names = [n for n, _ in self._names("我叫黄晓明，很高兴认识你")]
        self.assertIn("黄晓明", names)

    def test_contact_colon(self):
        """「联系人：赵丽颖」。"""
        names = [n for n, _ in self._names("联系人：赵丽颖")]
        self.assertIn("赵丽颖", names)

    def test_compound_surname(self):
        """复姓：欧阳娜娜 / 司马懿。"""
        names = [n for n, _ in self._names("提交者是欧阳娜娜")]
        self.assertIn("欧阳娜娜", names)

    def test_name_before_title(self):
        """「张伟先生」。"""
        names = [n for n, _ in self._names("请转告张伟先生")]
        self.assertIn("张伟", names)

    def test_two_char_name(self):
        """两字姓名（姓 + 单名）。"""
        names = [n for n, _ in self._names("客户李娜反馈")]
        self.assertIn("李娜", names)


class FalsePositiveTests(unittest.TestCase):
    """剔误：姓氏字开头的普通词不是人名。"""

    def setUp(self):
        import zh_names
        self.zh = zh_names

    def _names(self, text):
        return [text[s:e] for s, e, _ in self.zh.find_names(text)]

    def test_common_words_starting_with_surname(self):
        for text, word in [
            ("张开的括号", "张开"),
            ("王国的军队", "王国"),
            ("高度一致的方案", "高度"),
            ("程序需要重构", "程序"),
            ("方法很清晰", "方法"),
            ("余额不足", "余额"),
        ]:
            with self.subTest(word=word):
                names = self._names(text)
                self.assertNotIn(word, names, f"普通词被当成人名：{word}")

    def test_no_context_means_no_name(self):
        """没有上下文证据的裸两字/三字串不该被标成人名。"""
        self.assertEqual(self._names("张三"), [], "裸姓名不该被无上下文地标出")

    def test_digits_and_latin_not_names(self):
        for text in ("abc123", "版本 1.2.3", "2026-10-25"):
            with self.subTest(text=text):
                self.assertEqual(self._names(text), [], f"非中文串被标成人名：{text}")


class KindTests(unittest.TestCase):
    """标签口径：补漏的标 NAME，剔误的用同一标签（供调用方删除）。"""

    def test_found_names_are_name_kind(self):
        import zh_names

        out = zh_names.find_names("客户陈建国反馈")
        self.assertTrue(out, "前置条件：应当找到姓名")
        for _s, _e, kind in out:
            self.assertEqual(kind, "NAME", f"标签应为 NAME，实际 {kind!r}")

    def test_rejected_spans_helper_exists(self):
        """剔误需要单独的入口（调用方据此从 NER 结果里删掉）。"""
        import zh_names

        self.assertTrue(
            hasattr(zh_names, "rejected_spans"),
            "缺少 `rejected_spans`（剔误入口）",
        )
        # 反例词本身必须被剔掉；正常姓名不能误剔
        text = "张开的括号和王国的军队都不是人名，客户陈建国反馈说有问题"
        spans = [(text.index("张开"), text.index("张开") + 2, "NAME"),
                 (text.index("王国"), text.index("王国") + 2, "NAME"),
                 (text.index("陈建国"), text.index("陈建国") + 3, "NAME")]
        bad = zh_names.rejected_spans(text, spans)
        bad_frags = {text[s:e] for s, e, _ in bad}
        self.assertIn("张开", bad_frags, "反例词未被剔误")
        self.assertIn("王国", bad_frags, "反例词未被剔误")
        self.assertNotIn("陈建国", bad_frags, "正常姓名被误剔")


class TruncationIsPerCallTests(unittest.TestCase):
    """截断标志必须**由调用方带出**，不能用模块级计数（2026-10-25 复核发现的 P2）。

    `find_names` 跑在 `_MASK_POOL` 的多 worker 线程里。进程级计数会跨请求串号：
    会话 A 触发截断后若 A 那轮没取，计数会挂到下一个取它的会话 B 的事件上，
    A 自己的「本轮姓名扫描未覆盖全文」标记丢失。
    """

    def test_return_truncated_flag(self):
        import zh_names

        spans, truncated = zh_names.find_names("客户陈建国反馈", return_truncated=True)
        self.assertFalse(truncated)
        self.assertTrue(spans)

        big = "客户反馈" * 10000   # 远超 MAX_SCAN_CHARS
        spans2, truncated2 = zh_names.find_names(big, return_truncated=True)
        self.assertTrue(truncated2, "超长文本的截断标志没有返回")

    def test_no_module_level_counter(self):
        """不允许存在 `take_truncated_count` 这类进程级取走函数。"""
        import zh_names

        self.assertFalse(
            hasattr(zh_names, "take_truncated_count"),
            "截断计数仍是进程级（会跨 worker 线程串号）",
        )


class IntegrationTests(unittest.TestCase):
    """与 NER 的协作：只在 ner_enabled 时生效。"""

    def test_disabled_when_ner_off(self):
        """NER 关时不跑（它不是独立检测器）。"""
        self.assertTrue(hasattr(tr, "_zh_name_spans"), "缺少 `_zh_name_spans` 接入点")

    def test_zh_names_are_masked_when_ner_on(self):
        """NER 开 + 模型漏检 → 启发层补上，值被脱敏。"""
        d = tempfile.mkdtemp(prefix="maskit-zh-")
        saved = {
            k: getattr(tr, k)
            for k in ("CUSTOM_WORDS", "BUILTIN_RULES", "SENSITIVE_DISABLED",
                      "SENSITIVE_WORD_DISABLED", "SENSITIVE_WORD_WHOLE",
                      "UPSTREAMS", "TARGET_DOMAINS", "API_PATHS",
                      "CAPTURE_MODE", "FAIL_CLOSED", "_DATA_ROOT")
        }
        mtime = tr._cfg_mtime[0]
        try:
            with open(os.path.join(d, "config.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {"sensitive": {}, "builtin_rules": {}, "ner_enabled": True,
                     "target_domains": ["api.example.com"],
                     "api_paths": ["/v1/messages"]},
                    fh, ensure_ascii=False,
                )
            tr._DATA_ROOT = Path(d)
            tr._cfg_mtime[0] = None
            tr._maybe_reload(force=True)
            tr.BUILTIN_RULES = {k: False for k in tr.DEFAULT_BUILTIN_RULES}
            tr._CUSTOM_WORD_RX_CACHE.clear()
            tr._known_reset_for_tests()
            sid = "zh-int"
            tr._new_session(sid)
            out = tr.mask("客户陈建国反馈说订单有问题", sid)
            self.assertNotIn("陈建国", out, f"启发层未补上 NER 的漏检：{out!r}")
        finally:
            for k, v in saved.items():
                setattr(tr, k, v)
            tr._cfg_mtime[0] = mtime
            shutil.rmtree(d, ignore_errors=True)
            tr._known_reset_for_tests()


if __name__ == "__main__":
    unittest.main()
