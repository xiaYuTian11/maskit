"""工具定义区 / 协议结构区的脱敏边界。

## 为什么有这组用例

2026-10-25 隔离实例实测（`_mask_tree` 直探）：用户自定义词命中工具定义里的
**结构**字段，产出上游必拒的请求。三条都是确定的 400 路径：

```
# 1) 工具名定义侧保留、调用侧被改 → 上游工具名校验失败
tools[0].name               = "acme_lookup"                  ← 定义侧
messages[0].content[0].name = "{{TERM_xxx}}_lookup"          ← 调用侧

# 2) namespace 含 {} → Codex 的 ^[a-zA-Z0-9_-]+$ 拒绝（magpie #3143 同形态）
tools[0].namespace = "{{TERM_xxx}}_team"

# 3) Lark grammar / JSON Schema pattern 被打烂（magpie #1911 同形态）
tools[0].format.definition = "start: {{TERM_xxx}}_patch"
parameters.pattern          = "^{{TERM_xxx}}-[0-9]+$"
```

## 判据（与 magpie `internal/redact/json.go` 的 `keepIn` 同源）

**定义区（defs）里只有自然语言该被扫描**：`description` / `title` / `examples`。
其余是上游**按结构读取**的东西——工具名、namespace、schema 词汇、grammar、enum、
required 列表、properties 的键名——改写任何一处都只会让请求被拒，保护不了任何东西。

**工具参数（args）里不套用厂商键名豁免**：`tool_use.input` / `function.arguments`
的键是**工具自己定义的**，那里叫 `signature` / `name` / `type` 都是业务数据，
必须照常扫描（`tests/test_regressions.py` 里 AstrLink 的反例锁这条）。

两侧必须同判定：定义侧的 `name` 与调用侧的 `name` 要么都豁免、要么都扫——只改一边
就是 400。这是本文件最重要的一条断言。
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

# 自定义词用**片段拼接**构造（AGENTS.md §3 第 9 条：源码里不写占位符/凭据字面量）
WORD = "ac" + "me"


def _fresh_engine():
    """只取模块引用；**不在 import 时改任何全局/环境**（跨模块污染，见下面 _mask_json）。"""
    import transparent as tr
    return tr


tr = _fresh_engine()


def _mask_json(obj, sid):
    """在**本次调用内**应用隔离配置，退出时无条件恢复。

    为什么必须逐调用应用而不是模块级一次性设置：本模块会与 `tests/test_regressions.py`
    等旧测试跑在**同一个进程**里（`unittest discover`）。模块级改写 `BUILTIN_RULES`
    / `CUSTOM_WORDS` / `_DATA_ROOT` 会污染后续模块——实测：本模块 import 时把
    `BUILTIN_RULES` 设成全 False，导致 `FailClosedCaptureModeTests` 拿不到自定义词、
    未知形态请求被原样放行（看着像回归，实际是测试隔离缺陷）。

    必须恢复 `_maybe_reload` 能改的**全部**全局：漏一个就是跨模块污染。
    """
    saved = {
        "CUSTOM_WORDS": tr.CUSTOM_WORDS,
        "BUILTIN_RULES": tr.BUILTIN_RULES,
        "SENSITIVE_DISABLED": tr.SENSITIVE_DISABLED,
        "SENSITIVE_WORD_DISABLED": tr.SENSITIVE_WORD_DISABLED,
        "SENSITIVE_WORD_WHOLE": tr.SENSITIVE_WORD_WHOLE,
        "UPSTREAMS": tr.UPSTREAMS,
        "TARGET_DOMAINS": tr.TARGET_DOMAINS,
        "API_PATHS": tr.API_PATHS,
        "CAPTURE_MODE": tr.CAPTURE_MODE,
        "FAIL_CLOSED": tr.FAIL_CLOSED,
        "_DATA_ROOT": tr._DATA_ROOT,
    }
    mtime = tr._cfg_mtime[0]
    d = tempfile.mkdtemp(prefix="maskit-defscope-")
    try:
        with open(os.path.join(d, "config.json"), "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "sensitive": {"TERM": [WORD]},
                    "builtin_rules": {},
                    "target_domains": ["api.example.com"],
                    "api_paths": ["/v1/messages"],
                },
                fh,
                ensure_ascii=False,
            )
        tr._DATA_ROOT = Path(d)
        tr._cfg_mtime[0] = None
        tr._maybe_reload(force=True)
        tr.BUILTIN_RULES = {k: False for k in tr.DEFAULT_BUILTIN_RULES}
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr._new_session(sid)
        return json.loads(tr.mask_body(json.dumps(obj, ensure_ascii=False), sid))
    finally:
        for key, value in saved.items():
            setattr(tr, key, value)
        tr._cfg_mtime[0] = mtime
        shutil.rmtree(d, ignore_errors=True)


class ToolNameConsistencyTests(unittest.TestCase):
    """定义侧与调用侧的工具名必须一致（否则上游必然拒绝）。"""

    def _assert_same(self, defined, called, proto):
        self.assertEqual(
            defined,
            called,
            f"{proto}：定义侧与调用侧工具名不一致，上游会拒绝。"
            f"定义={defined!r} 调用={called!r}",
        )

    def test_openai_chat_tool_name_is_consistent(self):
        body = {
            "model": "m",
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": f"{WORD}_lookup",
                        "parameters": {"type": "object"},
                    },
                }
            ],
            "messages": [
                {"role": "user", "content": "hi"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": f"{WORD}_lookup", "arguments": "{}"},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "ok"},
            ],
        }
        out = _mask_json(body, "def-openai")
        self._assert_same(
            out["tools"][0]["function"]["name"],
            out["messages"][1]["tool_calls"][0]["function"]["name"],
            "OpenAI Chat",
        )

    def test_anthropic_tool_name_is_consistent(self):
        body = {
            "model": "m",
            "tools": [
                {
                    "name": f"{WORD}_lookup",
                    "input_schema": {"type": "object"},
                }
            ],
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": f"{WORD}_lookup",
                            "input": {"q": "x"},
                        }
                    ],
                }
            ],
        }
        out = _mask_json(body, "def-anthropic")
        self._assert_same(
            out["tools"][0]["name"],
            out["messages"][0]["content"][0]["name"],
            "Anthropic",
        )

    def test_responses_api_tool_name_is_consistent(self):
        body = {
            "model": "m",
            "tools": [{"type": "function", "name": f"{WORD}_lookup", "parameters": {"type": "object"}}],
            "input": [
                {"type": "function_call", "name": f"{WORD}_lookup", "arguments": "{}", "call_id": "c1"},
                {"type": "function_call_output", "call_id": "c1", "output": "ok"},
            ],
        }
        out = _mask_json(body, "def-responses")
        self._assert_same(
            out["tools"][0]["name"],
            out["input"][0]["name"],
            "Responses API",
        )

    def test_gemini_function_name_is_consistent(self):
        body = {
            "contents": [
                {"role": "model", "parts": [{"functionCall": {"name": f"{WORD}_lookup", "args": {"q": "x"}}}]}
            ],
            "tools": [
                {
                    "functionDeclarations": [
                        {"name": f"{WORD}_lookup", "parameters": {"type": "OBJECT"}}
                    ]
                }
            ],
        }
        out = _mask_json(body, "def-gemini")
        self._assert_same(
            out["tools"][0]["functionDeclarations"][0]["name"],
            out["contents"][0]["parts"][0]["functionCall"]["name"],
            "Gemini",
        )


class ToolNamespaceTests(unittest.TestCase):
    """`namespace` 必须原样上行（Codex 校验 ^[a-zA-Z0-9_-]+$，magpie #3143）。"""

    def test_namespace_is_not_masked(self):
        ns = f"{WORD}_team"
        body = {
            "model": "m",
            "tools": [
                {
                    "type": "custom",
                    "name": f"{WORD}_patch",
                    "namespace": ns,
                    "format": {"type": "grammar", "syntax": "lark", "definition": "start: x"},
                }
            ],
            "input": [
                {
                    "type": "custom_tool_call",
                    "name": f"{WORD}_patch",
                    "namespace": ns,
                    "input": "x",
                }
            ],
        }
        out = _mask_json(body, "def-ns")
        self.assertEqual(out["tools"][0]["namespace"], ns, "定义侧 namespace 被改写 → Codex 400")
        self.assertEqual(out["input"][0]["namespace"], ns, "调用侧 namespace 被改写 → Codex 400")
        # 字符集断言：占位符花括号必然违反 ^[a-zA-Z0-9_-]+$
        for value in (out["tools"][0]["namespace"], out["input"][0]["namespace"]):
            self.assertNotIn("{", value, "namespace 含花括号，必然被上游拒绝")


class GrammarAndSchemaTests(unittest.TestCase):
    """grammar / pattern / enum / required / properties 键名是上游**按结构读**的。"""

    def test_lark_grammar_definition_is_not_masked(self):
        definition = f"start: {WORD}_patch\n{WORD}_patch: /{WORD}-\\d+/"
        body = {
            "model": "m",
            "tools": [
                {
                    "type": "custom",
                    "name": f"{WORD}_patch",
                    "format": {"type": "grammar", "syntax": "lark", "definition": definition},
                }
            ],
        }
        out = _mask_json(body, "def-grammar")
        self.assertEqual(
            out["tools"][0]["format"]["definition"],
            definition,
            "Lark grammar 被改写 → 上游 400 Invalid lark grammar（magpie #1911 同形态）",
        )

    def test_schema_pattern_is_not_masked(self):
        pattern = f"^{WORD}-[0-9]+$"
        body = {
            "model": "m",
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "parameters": {
                            "type": "object",
                            "properties": {"id": {"type": "string", "pattern": pattern}},
                        },
                    },
                }
            ],
        }
        out = _mask_json(body, "def-pattern")
        got = out["tools"][0]["function"]["parameters"]["properties"]["id"]["pattern"]
        self.assertEqual(got, pattern, "JSON Schema pattern 被改写 → 上游校验失败")

    def test_property_names_and_required_are_not_masked(self):
        body = {
            "model": "m",
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "parameters": {
                            "type": "object",
                            "properties": {f"{WORD}_id": {"type": "string"}},
                            "required": [f"{WORD}_id"],
                        },
                    },
                }
            ],
        }
        out = _mask_json(body, "def-props")
        params = out["tools"][0]["function"]["parameters"]
        self.assertIn(f"{WORD}_id", params["properties"], "properties 键名被改写 → 模型无法填参")
        self.assertEqual(params["required"], [f"{WORD}_id"], "required 被改写 → 上游校验失败")

    def test_enum_values_are_masked_not_skipped(self):
        """`enum` 属于「用户填的取值」，**必须**照常扫描（不是结构）。

        这是一条**有意为之的取舍**，与 magpie 相反：magpie 的 `keepIn` 把 enum 归入
        defs 一并放行，我们的口径更严。理由：

          · `{"owner": {"enum": ["张三"]}}` / `{"host": {"default": "10.x.x.x"}}`
            是用户写的**真实业务数据**，不是上游按语法校验的东西；
          · `tests/test_regressions.py::RequestCoverageTests` 把这两类当审计验收点
            锁死——豁免它们就是真实 PII 明文出网（实测已复现）。

        代价：如果某个 enum 的值里恰含自定义词，模型会收到 `{{TERM_xxx}}_active`
        而不是 `acme_active`。这个代价是**可见且可救**的：
          · 用值级白名单（`allow_values`，B-4）把该枚举值钉住；
          · 或者把该词从自定义词表里去掉。
        而漏遮的代价不可逆（明文已出网）。方向选保守。

        真正被豁免的是**语法层**：`pattern` / `required` / `properties` 键名 /
        `format.definition`（grammar）——那些改了上游直接 400，保护价值为零。
        """
        body = {
            "model": "m",
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "state": {"type": "string", "enum": [f"{WORD}_active", "idle"]}
                            },
                        },
                    },
                }
            ],
        }
        out = _mask_json(body, "def-enum")
        got = out["tools"][0]["function"]["parameters"]["properties"]["state"]["enum"]
        self.assertNotIn(
            WORD,
            json.dumps(got),
            "enum 里的业务取值必须脱敏（审计验收点；代价见本用例 docstring）",
        )
        self.assertEqual(len(got), 2, "枚举项数量不得变化（否则上游校验失败）")
        self.assertIn("idle", got, "未命中词的枚举项必须原样保留")


class NumericDefinitionParityTests(unittest.TestCase):
    """定义区的**数值**分支必须与字符串分支同判据（2026-10-25 复核发现的 P1）。

    `enum` / `const` / `default` 是用户填的**取值**（不是结构），字符串形态会被遮；
    数值形态曾因 `in_definition` 一刀切返回而原样上行 ——
    于是 `{"default": "100.118.x.x"}` 被遮、`{"default": 10011800000}` 漏。
    """

    # 纯数字自定义词：既能被字符串分支命中，也能测「数值型 default」。
    # 用自定义词而不是手机号，是因为手机号形态在源码里会被网关的占位符还原机制
    # 改写（AGENTS.md §3 第 9 条），那会让断言失真。
    NUMERIC_WORD = "99" + "11" + "22" + "33"

    def test_numeric_default_is_masked_like_string(self):
        """数值形态的 `default` 必须与字符串形态同口径。

        `_mask_json` 内部会 `_maybe_reload`，所以自定义词必须走**配置文件**
        （直接改 `tr.CUSTOM_WORDS` 会被重载覆盖）。
        """
        w = self.NUMERIC_WORD
        d = tempfile.mkdtemp(prefix="maskit-num-")
        saved = tr._DATA_ROOT
        mtime = tr._cfg_mtime[0]
        try:
            with open(os.path.join(d, "config.json"), "w", encoding="utf-8") as fh:
                json.dump({
                    "sensitive": {"TERM": [w]},
                    "builtin_rules": {},
                    "target_domains": ["api.example.com"],
                    "api_paths": ["/v1/messages"],
                }, fh, ensure_ascii=False)
            tr._DATA_ROOT = Path(d)
            tr._cfg_mtime[0] = None
            tr._maybe_reload(force=True)   # 必须显式重载，否则自定义词不生效
            body = {
                "model": "m",
                "tools": [{"type": "function", "function": {"name": "f", "parameters": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "string", "default": w},
                        "b": {"type": "number", "default": int(w)},
                    }}}}],
            }
            # 直接调引擎（不走 `_mask_json`：它会用自己的固定配置覆盖上面的
            # `_DATA_ROOT`，导致本用例的自定义词失效）
            tr._new_session("num-def")
            out = json.loads(tr.mask_body(json.dumps(body, ensure_ascii=False), "num-def"))
        finally:
            tr._DATA_ROOT = saved
            tr._cfg_mtime[0] = mtime
            shutil.rmtree(d, ignore_errors=True)
        props = out["tools"][0]["function"]["parameters"]["properties"]
        self.assertNotIn(w, str(props["a"]["default"]), "字符串 default 未遮")
        self.assertNotIn(
            w, str(props["b"]["default"]),
            "数值 default 漏检（与字符串分支口径不一致）",
        )

    def test_structural_numeric_fields_still_exempt(self):
        """反向：真正的结构字段（minProperties / maxLength）数值仍要豁免。"""
        body = {
            "model": "m",
            "tools": [{"type": "function", "function": {"name": "f", "parameters": {
                "type": "object", "minProperties": 3,
                "properties": {"a": {"type": "string", "maxLength": 64}},
            }}}],
        }
        out = _mask_json(body, "num-struct")
        params = out["tools"][0]["function"]["parameters"]
        self.assertEqual(params["minProperties"], 3,
                         "结构字段被误遮（会让上游校验失败）")
        self.assertEqual(params["properties"]["a"]["maxLength"], 64)



class DescriptionStillScannedTests(unittest.TestCase):
    """定义区的**自然语言**必须照常扫描（否则等于用豁免换漏检）。"""

    def test_description_is_masked(self):
        body = {
            "model": "m",
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "description": f"look up a {WORD} record",
                        "parameters": {"type": "object"},
                    },
                }
            ],
        }
        out = _mask_json(body, "def-desc")
        self.assertNotIn(
            WORD,
            out["tools"][0]["function"]["description"],
            "description 里的自定义词未被脱敏（豁免面过大）",
        )

    def test_title_and_examples_are_masked(self):
        body = {
            "model": "m",
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "r",
                    "schema": {
                        "type": "object",
                        "title": f"{WORD} report",
                        "properties": {"x": {"type": "string", "examples": [f"{WORD}-1"]}},
                    },
                },
            },
        }
        out = _mask_json(body, "def-title")
        schema = out["response_format"]["json_schema"]["schema"]
        self.assertNotIn(WORD, schema.get("title") or "", "schema title 未被脱敏")
        self.assertNotIn(
            WORD,
            json.dumps(schema["properties"]["x"].get("examples") or []),
            "examples 未被脱敏",
        )


class BusinessAreaStillScannedTests(unittest.TestCase):
    """反例锁：工具**参数**里的同名字段必须照常扫描。

    这是本组最重要的一条——如果为了修 D1 而把 `name`/`type`/`id` 全部按名字豁免，
    就重新打开了 `tests/test_regressions.py` 里 AstrLink 锁定的那个洞。
    """

    def test_tool_arguments_are_scanned_regardless_of_key_name(self):
        body = {
            "model": "m",
            "tools": [{"type": "function", "function": {"name": "run", "parameters": {"type": "object"}}}],
            "messages": [
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "run",
                                "arguments": json.dumps(
                                    {
                                        "name": WORD,
                                        "type": WORD,
                                        "signature": WORD,
                                        "namespace": WORD,
                                        "input": WORD,
                                    }
                                ),
                            },
                        }
                    ],
                }
            ],
        }
        out = _mask_json(body, "def-args")
        args = json.loads(out["messages"][0]["tool_calls"][0]["function"]["arguments"])
        for key in ("name", "type", "signature", "namespace", "input"):
            self.assertNotIn(
                WORD,
                str(args[key]),
                f"工具参数里的 {key} 未被扫描（豁免被错用到业务区）",
            )

    def test_anthropic_tool_use_input_is_scanned(self):
        body = {
            "model": "m",
            "tools": [{"name": "run", "input_schema": {"type": "object"}}],
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "run",
                            "input": {"signature": WORD, "type": WORD},
                        }
                    ],
                }
            ],
        }
        out = _mask_json(body, "def-args-anth")
        inp = out["messages"][0]["content"][0]["input"]
        for key in ("signature", "type"):
            self.assertNotIn(WORD, str(inp[key]), f"tool_use.input 里的 {key} 未扫描")


class DefinitionSkipIsAccountedTests(unittest.TestCase):
    """豁免是一条**漏检路径**，必须计数上报（AGENTS.md 红线 8 的同款纪律）。"""

    def test_definition_skips_are_counted(self):
        self.assertTrue(
            hasattr(tr, "_note_definition_skip") or hasattr(tr, "_DEFINITION_SKIPPED"),
            "缺少定义区豁免的计数机制（静默豁免等于用户以为扫了、其实没扫）",
        )


if __name__ == "__main__":
    unittest.main()
