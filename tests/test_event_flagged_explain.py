"""G601~G603：「有残留（已放行）」的处置结论与残留明细必须可见。

真机背景（2026-11-10）：事件库 47 条 `BLOCK` + `reason=egress_verify` + `decision=flagged`，
用户在界面上只看到「有残留（已放行）」，点开详情只有一个英文裸词 `flagged` 和一句通用描述——
引擎早就把 `leaked[{label,length,count,preview}]` 写进 payload 了，前端从来没读过这个字段。
于是用户无法判断「这是真漏了敏感值，还是口径差造的噪音」，只能回放事件库。

三条守卫都是**展示层**的，不产生任何拒绝；这里用源码断言钉住，理由与
`tests/test_connection_config.py::test_event_details_translate_all_enum_surfaces_and_preserve_unknown`
同源：面板文案与枚举映射没有运行时单测可写（前端组件不跑在 Python 里），
而它们出错的形态是「界面上看不见」，只有源码契约能守住。

错误码是本仓既定格式：`<MODULE>_<4位>`，仅作台账标识（展示层守卫不产生 HTTP 响应）。
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DETAIL_TSX = ROOT / "frontend" / "src" / "components" / "events" / "EventDetailDialog.tsx"
TYPES_TS = ROOT / "frontend" / "src" / "types" / "api.ts"
I18N_TSX = ROOT / "frontend" / "src" / "lib" / "i18n.tsx"

# 引擎的一切处置结论（`engine/inspection.py` 的 DECISION_*，与 types/api.ts 的联合类型同步）。
DECISION_VALUES = {"masked", "scanned_clean", "blocked", "flagged", "passthrough"}

# G603 要求成对存在的三条新文案键（`detail.leakedHint` 是附加说明，不单独设守卫）。
REQUIRED_I18N_KEYS = (
    "detail.decisionFlagged",
    "detail.leakedTitle",
    "detail.leakedItem",
)


def _read(path):
    return Path(path).read_text(encoding="utf-8")


def _block(source, header, opener="{", closer="}"):
    """取出 `header` 之后第一个配对块的正文（花括号配平，跳过字符串内的括号）。

    用配平而不是正则 `\\{[^}]*\\}`：块内既有模板字符串 `{label}`、又有对象字面量，
    正则会在第一个 `}` 处截断，于是断言看着通过、实际漏掉后半段。
    """
    start = source.find(header)
    if start < 0:
        raise AssertionError("找不到代码块锚点：%s" % header)
    # header 本身可能就以 opener 结尾（如 `const zh: … = {`），此时块起点就是它，
    # 不能再往后搜一个 —— 会跳过真正的起始括号，拿到空块。
    if header.rstrip().endswith(opener):
        i = start + len(header.rstrip()) - 1
    else:
        i = source.find(opener, start + len(header))
        if i < 0:
            raise AssertionError("锚点后没有 %s：%s" % (opener, header))
    depth = 0
    quote = ""
    j = i
    while j < len(source):
        ch = source[j]
        if quote:
            if ch == "\\":
                j += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return source[i + 1:j]
        j += 1
    raise AssertionError("代码块没有闭合：%s" % header)


def _decision_label_keys(source):
    """`DECISION_LABELS` 的键集合。"""
    body = _block(source, "const DECISION_LABELS", opener="{", closer="}")
    return set(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*:", body))


def _decision_label_map(source):
    """`DECISION_LABELS` 的 键 → i18n 键 映射。"""
    body = _block(source, "const DECISION_LABELS", opener="{", closer="}")
    return dict(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*'([^']+)'", body))


def _i18n_section(source, lang):
    """取 i18n 字典的某一语言段（`const zh: Record<string, string> = {` … 收尾）。"""
    header = "const %s: Record<string, string> = {" % lang
    body = _block(source, header, opener="{", closer="}")
    return set(re.findall(r"^\s*'([^']+)'\s*:", body, re.MULTILINE))


class G601DecisionLabelCoverageTests(unittest.TestCase):
    """G601 的台账错误码（展示层守卫不产生 HTTP 响应，码只用于追溯）。"""
    ERROR_CODE = "LOG_6001"
    """G601 / LOG_6001：处置结论必须每个取值都有可读文案，不得回退成英文裸词。

    判据是**键集合相等**而不是「包含 flagged」：引擎将来新增第 6 种结论时，
    相等断言会立刻提醒补文案；包含断言会静默放行，详情页又开始显示裸英文。
    """

    def test_g601_error_code_literal(self):
        self.assertEqual(self.ERROR_CODE, "LOG_6001")

    def test_g601_decision_labels_cover_every_engine_value(self):
        keys = _decision_label_keys(_read(DETAIL_TSX))
        self.assertEqual(keys, DECISION_VALUES,
                         "DECISION_LABELS 与引擎处置结论不一致（多/少键都会让详情回退成裸英文）")

    def test_g601_every_decision_label_key_exists_in_both_languages(self):
        source = _read(I18N_TSX)
        zh = _i18n_section(source, "zh")
        en = _i18n_section(source, "en")
        for value, key in _decision_label_map(_read(DETAIL_TSX)).items():
            self.assertIn(key, zh, "中文缺文案：%s（%s）" % (key, value))
            self.assertIn(key, en, "英文缺文案：%s（%s）" % (key, value))


class G602LeakedDetailRenderingTests(unittest.TestCase):
    """G602 的台账错误码。"""
    ERROR_CODE = "LOG_6002"
    """G602 / LOG_6002：flagged 的残留明细必须可见，且不得渲染任何原文。

    两件事一起守：① 只加结论不加证据（用户仍然只能猜）；② 为了「看得更清楚」把
    `original` 渲染出来——payload 里本来就没有这个键，写进来等于自己开一个明文渲染口。
    """

    def test_g602_error_code_literal(self):
        self.assertEqual(self.ERROR_CODE, "LOG_6002")

    def test_g602_detail_reads_leaked_from_the_event(self):
        source = _read(DETAIL_TSX)
        self.assertRegex(source, r"event\??\.leaked",
                         "详情弹窗没有读 leaked：引擎写了证据也没有任何地方展示")

    def test_g602_leaked_rows_render_four_fields_and_never_original(self):
        source = _read(DETAIL_TSX)
        start = source.find("@guard G602")
        self.assertGreaterEqual(start, 0, "找不到 @guard G602 标记的残留明细构建块")
        end = source.find("const stageInfo", start)
        self.assertGreaterEqual(end, 0, "G602 块之后应当紧跟 stageInfo 定义（插入点约定）")
        body = source[start:end]
        # 注释行允许提到 original（那里正是解释「为什么不渲染它」），
        # 守卫要拦的是**代码**引用：真的去读 items/original 才算开了明文渲染口。
        code = "\n".join(line for line in body.splitlines()
                          if not line.strip().startswith("//"))
        for field in ("label", "length", "count", "preview"):
            self.assertIn(field, code, "残留明细缺字段：%s" % field)
        self.assertNotIn("original", code,
                         "残留明细不得引用 original：事件 payload 没有这个键，渲染它等于自造原文渲染口")

    def test_g602_empty_leaked_does_not_render_a_block(self):
        source = _read(DETAIL_TSX)
        self.assertIn("leaked.length > 0", source,
                      "leaked 为空时必须整块不渲染，否则每一条 flagged 详情都会多一张空卡片")


class G603TypeAndCopyAlignmentTests(unittest.TestCase):
    """G603 的台账错误码。"""
    ERROR_CODE = "LOG_6003"
    """G603 / LOG_6003：字段名必须与引擎输出一致，新文案在中英两份都必须存在。

    字段名漂移（引擎 `count` / 前端 `times`）不会报错，只会让那一列恒显示 `undefined`——
    这类静默失配只能靠源码契约拦。
    """

    def test_g603_error_code_literal(self):
        self.assertEqual(self.ERROR_CODE, "LOG_6003")

    def test_g603_event_leaked_type_matches_engine_keys(self):
        body = _block(_read(TYPES_TS), "leaked?:", opener="{", closer="}")
        for field in ("label", "length", "count", "preview"):
            self.assertIn(field, body, "Event.leaked 缺字段：%s" % field)
        self.assertNotIn("original", body,
                         "Event.leaked 不得声明 original：引擎的 _leaked_values 不输出它")

    def test_g603_new_copy_keys_exist_in_both_languages(self):
        source = _read(I18N_TSX)
        zh = _i18n_section(source, "zh")
        en = _i18n_section(source, "en")
        for key in REQUIRED_I18N_KEYS:
            self.assertIn(key, zh, "中文缺文案：%s" % key)
            self.assertIn(key, en, "英文缺文案：%s" % key)


if __name__ == "__main__":
    unittest.main()
