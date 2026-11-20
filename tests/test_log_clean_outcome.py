"""G701~G704：「无敏感词」必须与「脱敏成功」分开，且只由处置结论 `decision` 判定。

真机背景（2026-11-20）：用户贴几万字代码做分析时，日志页满屏绿色「成功」，但其中绝大多数
是 **0 命中**（请求里压根没有敏感词）。用户想验证「脱敏到底生效了没」时，无法从列表上区分
「保护生效了」和「这次没东西可保护」——`deriveOutcome` 的 success 判据只看
`http_status / unresolved / degraded / completeness`，**完全不看是否命中敏感词**。

引擎其实早就算出了这个结论（`decision: 'masked' | 'scanned_clean' | …`，见
`frontend/src/types/api.ts`），且随合并行带到了前端（`MergedEvent = ShieldEvent & {…}`，
`log-events.ts` 的 `rows.push({...base})` 保留了它）。前端从来没用它区分结论。

## 为什么用源码断言

运行时行为（`clean` 真的产出、告警真的优先、筛选真的互不串）由
`scripts/check-log-outcome.mjs` 的用例覆盖 —— 它用 `node --experimental-strip-types`
直接跑 TS 源码，已进 `verify-all.py` 的 frontend 组。

本文件守的是「代码形态」：判据顺序、判据来源、键集合一致、下拉去重。这些没法用行为断言
表达（例如「`count` 不得参与判定」只能在源码上抓），而它们出错的形态是「界面上看不出来」。
理由与 `tests/test_event_flagged_explain.py` 同源。

错误码是本仓既定格式：`<MODULE>_<4位>`，仅作台账标识（展示层守卫不产生 HTTP 响应）。
"""

import re
import unittest
from pathlib import Path

from tests.test_event_flagged_explain import _block, _read

ROOT = Path(__file__).resolve().parents[1]
LOG_OUTCOME = ROOT / "frontend" / "src" / "lib" / "log-outcome.ts"
OUTCOME_BADGE = ROOT / "frontend" / "src" / "components" / "events" / "OutcomeBadge.tsx"
LOG_EVENTS = ROOT / "frontend" / "src" / "lib" / "log-events.ts"
I18N = ROOT / "frontend" / "src" / "lib" / "i18n.tsx"
LOGS_PAGE = ROOT / "frontend" / "src" / "pages" / "Logs.tsx"

# 四条告警判据：顺序写错 = 未还原 / 兜底还原 / NER 截断 / HTTP 报错的请求被标成「无敏感词」。
WARN_GUARDS = (
    "http_status ?? 0) >= 400",
    "unresolved ?? 0) > 0",
    "degraded ?? 0) > 0",
    "completeness === 'partial'",
)

# 四处映射的键集合必须逐一相等，漏一处徽标就渲染 undefined。
# OUTCOME_ORDER 的 header 必须写到 `= [`：类型注解里的 `OutcomeKey[]` 也含 `[`，
# 只写到变量名的话 `_block` 会把类型里的中括号当成数组起点，取到空块。
KEY_SURFACES = (
    ("OUTCOME_ORDER", LOG_OUTCOME, "export const OUTCOME_ORDER: readonly OutcomeKey[] = [", "[", "]"),
    ("OUTCOME_LABEL_KEY", LOG_OUTCOME, "export const OUTCOME_LABEL_KEY", "{", "}"),
    ("OUTCOME_HINT_KEY", LOG_OUTCOME, "export const OUTCOME_HINT_KEY", "{", "}"),
    ("OUTCOME_META", OUTCOME_BADGE, "export const OUTCOME_META", "{", "}"),
)


def _strip_comments(src):
    """去掉块注释与行注释 —— 注释里讨论判据不算「参与判定」。"""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"^\s*//.*$", "", src, flags=re.M)


def _derive_body():
    return _strip_comments(_block(_read(LOG_OUTCOME), "export function deriveOutcome"))


def _keys(path, header, opener, closer):
    body = _block(_read(path), header, opener=opener, closer=closer)
    if opener == "[":
        return sorted(re.findall(r"'([a-z]+)'", body))
    return sorted(re.findall(r"^\s{2}([A-Za-z_]\w*):", body, re.M))


class G701WarnBeforeCleanOrderTests(unittest.TestCase):
    """G701 / LOG_7101：`clean` 只能落在四条告警判据之后。"""

    def test_g701_error_code_is_fixed(self):
        self.assertEqual("LOG_7101", "LOG_7101")

    def test_g701_clean_branch_exists(self):
        self.assertIn("decision === 'scanned_clean'", _derive_body())

    def test_g701_warn_guards_precede_clean(self):
        body = _derive_body()
        clean_at = body.find("decision === 'scanned_clean'")
        for guard in WARN_GUARDS:
            at = body.find(guard)
            self.assertGreaterEqual(at, 0, "deriveOutcome 缺少告警判据：%s（LOG_7101）" % guard)
            self.assertLess(at, clean_at, "告警判据必须排在 clean 之前：%s（LOG_7101）" % guard)


class G702DecisionOnlyTests(unittest.TestCase):
    """G702 / LOG_7102：判据只能是 `decision`，`count` 不得参与结论判定。"""

    def test_g702_error_code_is_fixed(self):
        self.assertEqual("LOG_7102", "LOG_7102")

    def test_g702_no_count_in_derivation(self):
        self.assertNotRegex(
            _derive_body(),
            r"\bcount\b",
            "deriveOutcome 体内不得出现 count —— 它是派生量，NER 截断时也可能为 0（LOG_7102）",
        )


class G703KeySetParityTests(unittest.TestCase):
    """G703 / LOG_7103：四处键集合逐一相等且含 clean，中英文案成对。"""

    def test_g703_error_code_is_fixed(self):
        self.assertEqual("LOG_7103", "LOG_7103")

    def test_g703_four_surfaces_share_one_key_set(self):
        baseline = None
        for name, path, header, opener, closer in KEY_SURFACES:
            keys = _keys(path, header, opener, closer)
            self.assertIn("clean", keys, "%s 缺 clean 键（LOG_7103）" % name)
            if baseline is None:
                baseline = keys
            else:
                self.assertEqual(keys, baseline, "%s 的键集合与 OUTCOME_ORDER 不一致（LOG_7103）" % name)

    def test_g703_i18n_keys_exist_in_both_languages(self):
        source = _read(I18N)
        for key in ("logs.outcome.clean", "logs.outcomeHint.clean"):
            values = re.findall(r"'%s': '([^']*)'" % re.escape(key), source)
            self.assertEqual(len(values), 2, "%s 必须中英各一条（LOG_7103）" % key)
            for value in values:
                self.assertTrue(value.strip(), "%s 的文案不得为空（LOG_7103）" % key)


class G704FilterAndIngressDedupTests(unittest.TestCase):
    """G704 / LOG_7104：clean 可筛出、大写回填可解析、EXT_ALL 判据保留、下拉重复项已删。"""

    def test_g704_error_code_is_fixed(self):
        self.assertEqual("LOG_7104", "LOG_7104")

    def test_g704_filter_accepts_clean_case_insensitively(self):
        source = _read(LOG_OUTCOME)
        self.assertIn(
            "OUTCOME_ORDER as readonly string[]",
            source,
            "outcomeFromFilter 必须按 OUTCOME_ORDER 校验，新 key 才能自动可筛（LOG_7104）",
        )
        self.assertIn(
            "raw.slice(OUTCOME_FILTER_PREFIX.length).toLowerCase()",
            source,
            "outcomeFromFilter 必须大小写不敏感 —— URL 回填会整体 toUpperCase（LOG_7104）",
        )

    def test_g704_ingress_judgement_survives_menu_removal(self):
        self.assertIn(
            "if (filterType === EXT_ALL) return e.ingress === 'ext'",
            _read(LOG_EVENTS),
            "EXT_ALL 的入口过滤判据被删了，老书签会静默失效（LOG_7104）",
        )

    def test_g704_duplicate_dropdown_item_is_gone(self):
        source = _read(LOGS_PAGE)
        self.assertNotIn('value="EXT_ALL"', source, "首个下拉里仍有与入口下拉重复的 EXT_ALL 项（LOG_7104）")
        self.assertIn("@guard G704", source, "Logs.tsx 缺少 G704 标注（LOG_7104）")


if __name__ == "__main__":
    unittest.main()