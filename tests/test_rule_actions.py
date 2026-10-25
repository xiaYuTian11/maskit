"""per-kind 三态（mask / warn / block）与值级白名单。

## 为什么需要

现在规则只有「开 / 关」两态，用户遇到两种需求都无解：

1. **误报**（`secretName: Uint8Array` 被 SECRET 规则遮了）：只能整条规则关掉，
   漏检面立刻扩大；或者加整词（对凭据类值不适用）。需要的是「**这个值**放行」。
2. **想先观察再决定**（新规则上线，不确定误报率）：只能开或关。需要的是
   「**只提醒、不改写**」——`warn` 语义（参照 magpie `settings/masking.go`）。
3. **高风险类型**（私钥、连接串口令）：希望命中就直接拦下这个请求。需要
   `block` 语义。

## 三条必须守住的契约

1. **`warn` = 明文出网**。它只是记账，不改写、不阻断。UI 文案与 SECURITY.md
   必须明说，否则用户会以为「设成 warn 就安全了」——那是本方案最危险的一种
   误解。
2. **`allow_values` 是整值精确匹配**，不是子串。`Uint8Array` 放行，不等于
   `Uint8ArrayFoo` 也放行。
3. **向后兼容**：`builtin_rules` 仍接受 bool（老配置/老前端），缺省 `mask`。
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

SECRET_VAL = "Qq" + "Val" + "3z8y"
ALLOW_VAL = "Aa" + "Bb" + "1c2d"


def _engine():
    import transparent as tr
    return tr


tr = _engine()


class _IsolatedCase(unittest.TestCase):
    CONFIG = {"sensitive": {}, "builtin_rules": {"SECRET": True}}

    def setUp(self):
        self._saved = {
            k: getattr(tr, k)
            for k in (
                "CUSTOM_WORDS", "BUILTIN_RULES", "RULE_ACTIONS", "ALLOW_VALUES",
                "SENSITIVE_DISABLED", "SENSITIVE_WORD_DISABLED",
                "SENSITIVE_WORD_WHOLE", "UPSTREAMS", "TARGET_DOMAINS", "API_PATHS",
                "CAPTURE_MODE", "FAIL_CLOSED", "_DATA_ROOT",
            )
        }
        self._mtime = tr._cfg_mtime[0]
        self._dir = tempfile.mkdtemp(prefix="maskit-actions-")
        with open(os.path.join(self._dir, "config.json"), "w", encoding="utf-8") as fh:
            json.dump(
                dict(
                    self.CONFIG,
                    target_domains=["api.example.com"],
                    api_paths=["/v1/messages"],
                ),
                fh,
                ensure_ascii=False,
            )
        tr._DATA_ROOT = Path(self._dir)
        tr._cfg_mtime[0] = None
        tr._maybe_reload(force=True)
        tr.BUILTIN_RULES = {k: True for k in tr.DEFAULT_BUILTIN_RULES}
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr._known_reset_for_tests()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(tr, k, v)
        tr._cfg_mtime[0] = self._mtime
        shutil.rmtree(self._dir, ignore_errors=True)
        tr._known_reset_for_tests()

    def mask(self, text, sid="a1"):
        """跑一次脱敏。

        ⚠️ 必须先 `_maybe_reload(force=True)`：`mask()` 内部会调 `_maybe_reload`，
        而 mtime 一旦命中就把 `RULE_ACTIONS` / `ALLOW_VALUES` 覆盖回配置文件里的值。
        用例若直接给全局赋值（测试的常规做法），不先 reload 就会被静默冲掉 ——
        实测这个坑让「白名单」用例全部假红。
        """
        tr._maybe_reload(force=True)
        tr._new_session(sid)
        return tr.mask(text, sid)

    def set_actions(self, mapping):
        """设置三态**并且**写进配置文件（否则下一次 reload 会冲掉）。"""
        tr.RULE_ACTIONS = dict(mapping)
        self._write_config(rule_actions=dict(mapping))

    def set_allow(self, values):
        tr.ALLOW_VALUES = {v.lower() for v in values}
        self._write_config(allow_values=list(values))

    def _write_config(self, **overrides):
        cfg = dict(
            self.CONFIG,
            target_domains=["api.example.com"],
            api_paths=["/v1/messages"],
        )
        cfg.update(overrides)
        with open(os.path.join(self._dir, "config.json"), "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False)
        tr._cfg_mtime[0] = None


class ConfigTests(_IsolatedCase):
    """配置结构与兼容性。"""

    def test_default_actions_exist(self):
        self.assertTrue(hasattr(tr, "RULE_ACTIONS"), "缺少 RULE_ACTIONS（三态配置）")
        self.assertEqual(tr.RULE_ACTIONS, {}, "缺省应为空 = 全部 mask")

    def test_bool_config_still_works(self):
        """老配置 `{"SECRET": true}` 必须继续可用（向后兼容）。"""
        tr.BUILTIN_RULES = dict(tr.BUILTIN_RULES, SECRET=True)
        out = self.mask(f"DB_PASSWORD={SECRET_VAL}")
        self.assertIn("{{SECRET_", out, "bool 开关失效了")

    def test_action_lookup_defaults_to_mask(self):
        self.assertTrue(hasattr(tr, "_rule_action"), "缺少 `_rule_action`")
        self.assertEqual(tr._rule_action("PHONE"), "mask")
        tr.RULE_ACTIONS = {"PHONE": "warn"}
        self.assertEqual(tr._rule_action("PHONE"), "warn")

    def test_invalid_action_falls_back_to_mask(self):
        """非法取值必须回退 mask（不能变成「什么都不做」）。"""
        tr.RULE_ACTIONS = {"PHONE": "banana"}
        self.assertEqual(tr._rule_action("PHONE"), "mask")


class WarnActionTests(_IsolatedCase):
    """`warn` = 只提醒、**明文出网**。"""

    def test_warn_does_not_modify_text(self):
        self.set_actions({"SECRET": "warn"})
        text = f"DB_PASSWORD={SECRET_VAL}"
        out = self.mask(text)
        self.assertEqual(out, text, "warn 模式改写了文本（它只该提醒）")

    def test_warn_is_counted(self):
        """必须计数：否则用户设了 warn 之后完全看不到任何信息。"""
        self.set_actions({"SECRET": "warn"})
        self.mask(f"DB_PASSWORD={SECRET_VAL}")
        s = tr._session_get("a1", {})
        self.assertGreater(
            int(s.get("warned") or 0), 0,
            "warn 命中未计数（用户设了 warn 却什么都看不到）",
        )

    def test_warn_is_visible_in_events(self):
        """warn 计数必须能**发出**（不能只累加不用）。

        2026-10-25 复核发现的真实缺口：`warned` / `warned_labels` 只累加，
        从未进入任何事件 —— 用户设了 warn 之后在日志页什么都看不到，
        那和关掉规则没区别，却还留着「我设了 warn」的误解。
        """
        self.set_actions({"SECRET": "warn"})
        self.mask(f"DB_PASSWORD={SECRET_VAL}")
        n, labels = tr._take_warned("a1")
        self.assertGreater(n, 0, "warn 计数取不到（没进事件就是不可见）")
        self.assertIn("SECRET", labels)
        # 取走即清（请求级语义，与 `_take_rule_block` 同口径）
        self.assertEqual(tr._take_warned("a1"), (0, []),
                         "warn 计数取走后未清零，会串到下一个请求")

    def test_warn_still_reports_label(self):
        """warn 也要把 label 记进 warned_labels（供前端展示「哪种值被放行」）。"""
        self.set_actions({"SECRET": "warn"})
        self.mask(f"DB_PASSWORD={SECRET_VAL}")
        s = tr._session_get("a1", {})
        labels = s.get("warned_labels") or set()
        self.assertIn("SECRET", labels, "warn 未记录 label")


class BlockActionTests(_IsolatedCase):
    """`block` = 遮 + 阻断该请求。"""

    def test_block_marks_session_for_blocking(self):
        self.set_actions({"SECRET": "block"})
        out = self.mask(f"DB_PASSWORD={SECRET_VAL}")
        self.assertIn("{{SECRET_", out, "block 也应当脱敏（遮 + 拦）")
        s = tr._session_get("a1", {})
        self.assertTrue(s.get("rule_blocked"), "block 未置阻断标记")

    def test_block_records_reason(self):
        self.set_actions({"SECRET": "block"})
        self.mask(f"DB_PASSWORD={SECRET_VAL}")
        s = tr._session_get("a1", {})
        self.assertIn("SECRET", (s.get("rule_blocked_labels") or set()))


class BlockMarkerIsPerRequestTests(_IsolatedCase):
    """`block` 标记是**请求级**语义，不能串到同一会话的后续请求。

    2026-10-25 复核发现的真实缺陷：标记累加在会话上且从不清理，
    于是同一 sid 的后续请求被前一个请求的标记误拦
    （实测：req1 命中 `DB_PASSWORD` → req2 只是 `hello world` 也被 503）。
    """

    def test_marker_is_cleared_after_take(self):
        self.set_actions({"SECRET": "block"})
        self.mask(f"DB_PASSWORD={SECRET_VAL}")
        blocked, labels = tr._take_rule_block("a1")
        self.assertTrue(blocked)
        self.assertIn("SECRET", labels)
        # 再取一次必须是空的（取走即清）
        self.assertEqual(tr._take_rule_block("a1"), (False, []),
                         "标记取走后未清零，会串到下一个请求")

    def test_second_request_in_same_session_is_not_blocked(self):
        self.set_actions({"SECRET": "block"})
        self.mask(f"DB_PASSWORD={SECRET_VAL}", "same")
        tr._take_rule_block("same")          # 模拟 req1 的阻断处理
        out = self.mask("hello world", "same")   # req2
        self.assertEqual(out, "hello world")
        self.assertEqual(tr._take_rule_block("same"), (False, []),
                         "req2 被 req1 的 block 标记误拦")


class ActionCoversAllHitPathsTests(_IsolatedCase):
    """三态必须在**所有**命中路径上生效，不能只在 RULES 循环里。

    2026-10-25 复核发现的真实缺陷：三态最初只加在 `for rx, label, group_idx in RULES`
    循环里，而**前缀规则**（`sk-` / `ghp_` …）走的是另一条路径
    （`_prefix_secret_regex` + `_prefix_sub`）——用户把 `API_KEY` 设成 `block`，
    发现 `sk-xxx` 照常放行，而 UI 显示「拦截」。

    修法：三态与值级白名单都统一在 `_hit` 里判（所有命中路径的必经点）。
    """

    def test_prefix_rule_respects_block(self):
        tr.SECRET_PREFIXES = ["sk-"]
        self.set_actions({"API_KEY": "block"})
        tr._prefix_rx_cache = None
        tr._prefix_rx_key = None
        out = self.mask("key sk-" + "A" * 20)
        self.assertIn("{{", out, "block 也应当脱敏")
        self.assertTrue(tr._session_get("a1", {}).get("rule_blocked"),
                        "前缀规则命中的 API_KEY 绕过了 block 三态")

    def test_prefix_rule_respects_warn(self):
        tr.SECRET_PREFIXES = ["sk-"]
        self.set_actions({"API_KEY": "warn"})
        tr._prefix_rx_cache = None
        tr._prefix_rx_key = None
        text = "key sk-" + "A" * 20
        out = self.mask(text)
        self.assertEqual(out, text, "warn 不该改写前缀规则命中的值")
        self.assertGreater(int(tr._session_get("a1", {}).get("warned") or 0), 0,
                           "前缀规则命中的 warn 未计数")

    def test_custom_word_actions_are_not_configurable(self):
        """自定义词（TERM 等）**不能**配三态 —— 这是有意的。

        三态的键是「内置规则名」（`DEFAULT_BUILTIN_RULES` 的键），因为只有内置
        规则有统一的校验与边界。自定义词的开关由词表本身管（加/删/禁用），
        再叠一层三态只会让「这个词为什么没被遮」有两个互相矛盾的答案。

        `_parse_rule_actions` 会把非内置规则名丢弃并告警，本用例锁这条。
        """
        # 必须走**配置读盘**路径（`_parse_rule_actions` 是唯一判据），
        # 直接赋 `tr.RULE_ACTIONS` 会绕过它、测不到丢弃逻辑。
        self._write_config(rule_actions={"TERM": "warn", "PHONE": "warn"})
        tr._maybe_reload(force=True)
        self.assertNotIn("TERM", tr.RULE_ACTIONS,
                         "自定义词标签被收进了 rule_actions（应当被丢弃）")
        self.assertEqual(tr.RULE_ACTIONS.get("PHONE"), "warn",
                         "内置规则的三态被连累丢弃了")


class AllowValuesTests(_IsolatedCase):
    """值级白名单：整值精确匹配，不是子串。"""

    def test_allowed_value_is_not_masked(self):
        self.set_allow([ALLOW_VAL])
        out = self.mask(f"DB_PASSWORD={ALLOW_VAL}")
        self.assertEqual(out, f"DB_PASSWORD={ALLOW_VAL}", "白名单值仍被脱敏")

    def test_allow_is_exact_not_substring(self):
        self.set_allow([ALLOW_VAL])
        longer = ALLOW_VAL + "Extra9"
        out = self.mask(f"DB_PASSWORD={longer}")
        self.assertIn("{{SECRET_", out, "白名单被当子串匹配了（放行了更长的值）")

    def test_allow_is_case_insensitive(self):
        """大小写不敏感（与 `_custom_words` 的大小写折叠口径一致）。"""
        self.set_allow([ALLOW_VAL])
        out = self.mask(f"DB_PASSWORD={ALLOW_VAL.upper()}")
        self.assertNotIn("{{SECRET_", out, "白名单大小写不敏感失效")

    def test_allow_does_not_affect_other_values(self):
        self.set_allow([ALLOW_VAL])
        out = self.mask(f"DB_PASSWORD={SECRET_VAL}")
        self.assertIn("{{SECRET_", out, "白名单把别的值也放行了")

    def test_allow_rejects_non_strings(self):
        """非字符串项必须被丢弃（2026-10-25 复核）。

        `str(None)` → `"None"`、`str(123)` → `"123"`，那会让白名单凭空多出
        `None` / `123` 这种值 —— 文本里出现 `None` 这个词就被放行。
        白名单的语义是「用户明确钉住的那个**值**」，只有字符串才是值。
        """
        self._write_config(allow_values=[123, None, {"a": 1}, ALLOW_VAL])
        tr._maybe_reload(force=True)
        self.assertEqual(len(tr.ALLOW_VALUES), 1, f"非字符串项被收进白名单：{tr.ALLOW_VALUES}")
        self.assertIn(ALLOW_VAL.lower(), tr.ALLOW_VALUES)
        self.assertNotIn("none", tr.ALLOW_VALUES)
        self.assertNotIn("123", tr.ALLOW_VALUES)

    def test_allow_has_bounds(self):
        self.assertTrue(hasattr(tr, "ALLOW_VALUES_MAX"))
        self.assertTrue(hasattr(tr, "ALLOW_VALUE_MAX_LEN"))


class LoadFromConfigTests(_IsolatedCase):
    """配置读盘路径：`rule_actions` / `allow_values` 必须真的被读进来。"""

    def test_config_actions_are_loaded(self):
        with open(os.path.join(self._dir, "config.json"), "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "sensitive": {},
                    "builtin_rules": {"SECRET": True},
                    "rule_actions": {"SECRET": "warn"},
                    "allow_values": [ALLOW_VAL],
                    "target_domains": ["api.example.com"],
                    "api_paths": ["/v1/messages"],
                },
                fh,
                ensure_ascii=False,
            )
        tr._cfg_mtime[0] = None
        tr._maybe_reload(force=True)
        self.assertEqual(tr._rule_action("SECRET"), "warn", "rule_actions 未被读入")
        self.assertIn(ALLOW_VAL.lower(), {v.lower() for v in tr.ALLOW_VALUES},
                      "allow_values 未被读入")

    def test_invalid_action_in_config_is_ignored(self):
        """配置里写错的动作名必须被忽略并回退 mask（不能整份配置作废）。"""
        with open(os.path.join(self._dir, "config.json"), "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "sensitive": {},
                    "builtin_rules": {"SECRET": True},
                    "rule_actions": {"SECRET": "nonsense", "NOT_A_RULE": "warn"},
                    "target_domains": ["api.example.com"],
                    "api_paths": ["/v1/messages"],
                },
                fh,
                ensure_ascii=False,
            )
        tr._cfg_mtime[0] = None
        tr._maybe_reload(force=True)
        self.assertEqual(tr._rule_action("SECRET"), "mask", "非法动作名未回退 mask")
        self.assertNotIn("NOT_A_RULE", tr.RULE_ACTIONS, "未知规则名被收进了配置")


class ConstantParityTests(unittest.TestCase):
    """panel 与 transparent 各写一份的上界必须相等。

    panel 端**有意不 import transparent**（见 `panel._EXT_MAX_BODY` 的注释），
    所以数值只能各写一份 —— 那就必须靠测试防漂移：改了一边忘了另一边，
    引擎与面板的白名单上界就静默不一致了。
    """

    def test_allow_limits_match(self):
        import panel

        self.assertEqual(
            panel._ALLOW_VALUES_MAX, tr.ALLOW_VALUES_MAX,
            "panel._ALLOW_VALUES_MAX 与 transparent.ALLOW_VALUES_MAX 已漂移",
        )
        self.assertEqual(
            panel._ALLOW_VALUE_MAX_LEN, tr.ALLOW_VALUE_MAX_LEN,
            "panel._ALLOW_VALUE_MAX_LEN 与 transparent.ALLOW_VALUE_MAX_LEN 已漂移",
        )

    def test_allow_limits_have_sane_defaults(self):
        """默认值本身也钉住：两边一起被改成别的值时，至少还需要有人明确改这条。"""
        self.assertEqual(tr.ALLOW_VALUES_MAX, 200)
        self.assertEqual(tr.ALLOW_VALUE_MAX_LEN, 256)


if __name__ == "__main__":
    unittest.main()
