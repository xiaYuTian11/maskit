"""协议不可改写状态契约表（批次 3，§A2 + §8 R12）契约测试。

设计依据：`ai-coding/plans/maskit-personal-upgrade-plan.md` §A1/§A2 与 §8 R12。
把批次 1 的 Anthropic 窄热修升级成「协议 + 路径 + 角色 + 真实数组」判据表后，
下面六条口径不得放松：

1. **判据只认结构与角色**：容器位置 + 协议指定角色 + 块类型 + 不可改写字段非空。
   **禁止**裸字段名豁免——无关位置与工具参数里的同名键必须照常扫描
   （AstrLink `continuation_test.go:134` 锁定的反例）。
2. **五个批次 3 载体全部覆盖**：Responses `input[].encrypted_content`（`input` 在业务区
   集合里，该子树此前零豁免）、Gemini `contents[].parts[].thoughtSignature`、LiteLLM
   `messages[].thinking_blocks[]`、OpenRouter `message.reasoning_details[]`、Anthropic
   `web_search_tool_result.content[].encrypted_content`。
3. **每个负结果都要有同请求内的正向对照**（R10）：对照没被打码说明规则压根没生效，
   该负结果作废。
4. **不越界**：只有签名/密文状态本身受保护。`reasoning.summary`、没有
   `encrypted_content` 的 reasoning 项、`functionCall.args` 里的同名键，全部照常扫描。
5. **请求/响应共用同一份判据表**：响应侧不还原的块类型集合必须由契约表导出。
6. **豁免必须计数**：`signed_blocks_skipped` 如实上报（不新增静默路径）。
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import transparent as tr  # noqa: E402

# 合成样例：明显伪造的号码（全零中段）。分片拼接 + **不写成占位符字面量**——本机在
# 脱敏网关之后，占位符字面量落盘时会被还原（见方案 §8 R11）。
PHONE = "139" + "0000" + "0000"
# 自定义词：保证「应当扫描的位置」确实会命中（默认规则的数字边界校验会放过被字母
# 包住的号码，只有词表命中才能证明该位置没被豁免）。
WORD = "acme"
# 不可改写状态样例：**故意内嵌自定义词**。E2c 实测 base64 载体在默认规则下本来就
# 不被改写（靠相邻字符边界侥幸），不塞命中面就只能测出假绿。
SIG = "Aq" + WORD + "BcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/=="
ENC = "EN" + WORD + "cRyPteD0123456789abcdef=="


class ContractTestBase(unittest.TestCase):
    """公共夹具：临时数据根 + 只放自定义词的配置（不让内置规则干扰判据）。"""

    SID = "protocol-contracts"

    def setUp(self):
        self._old_root = tr._DATA_ROOT
        self._old_emit = tr._emit
        self.tmp = Path(tempfile.mkdtemp())
        cfg = {"builtin_rules": {}, "sensitive": {"CUSTOMER": [WORD]}}
        (self.tmp / "config.json").write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
        tr._DATA_ROOT = self.tmp
        tr._emit = lambda *a, **k: None
        tr._maybe_reload(force=True)
        tr._new_session(self.SID)

    def tearDown(self):
        tr._drop(self.SID)
        tr.sessions.pop(self.SID, None)
        tr._DATA_ROOT = self._old_root
        tr._emit = self._old_emit

    def mask_body(self, body):
        """按生产路径入口形态脱敏（深拷贝，避免测试自身持有被改对象）。"""
        return tr._mask_tree(json.loads(json.dumps(body, ensure_ascii=False)), self.SID)

    # ── 对照判定：`acme` 被替换成占位符 = 该位置确实被扫描过 ──────────────────
    @staticmethod
    def scanned(value):
        return isinstance(value, str) and "{{" in value and WORD not in value

    def assert_scanned(self, value, where):
        self.assertTrue(self.scanned(value),
                        f"{where} 必须照常扫描（预期被替换成占位符，实际 {value!r}）")

    def assert_untouched(self, value, expected, where):
        self.assertEqual(value, expected, f"{where} 属协议不可改写状态，必须一字不改")


class CarrierRegistryTests(ContractTestBase):
    """契约表自身的完整性：每条载体都是结构判据 + 带来源引用。"""

    @staticmethod
    def registry():
        import protocol_contracts as pc
        return pc

    def test_every_carrier_is_structural_and_sourced(self):
        pc = self.registry()
        self.assertTrue(pc.CARRIERS, "契约表不能为空")
        for c in pc.CARRIERS:
            with self.subTest(carrier=c.name):
                self.assertTrue(c.key, "载体必须声明所在容器的键名（真实数组位置）")
                self.assertTrue(c.roles, "载体必须声明协议角色判据")
                self.assertTrue(c.types or c.slots,
                                "载体必须声明块类型或不可改写字段，不能只靠字段名")
                self.assertTrue(c.source.startswith("https://"), "R12 要求每条载体带来源引用")
                self.assertIn(c.scope, ("block", "slot"))

    def test_five_known_carriers_are_registered(self):
        """R12 点名的五个载体必须逐个在表里（漏一个就等于留下一条破坏路径）。"""
        pc = self.registry()
        names = {c.name for c in pc.CARRIERS}
        for expected in ("anthropic_thinking", "responses_reasoning", "gemini_thought_signature",
                         "litellm_thinking_blocks", "openrouter_reasoning_details",
                         "anthropic_web_search_result"):
            self.assertIn(expected, names, f"契约表缺少载体 {expected}")

    def test_restore_skip_set_is_shared_with_contract_table(self):
        """响应侧不还原的块类型必须由契约表导出（请求/响应共用一套判据）。"""
        pc = self.registry()
        derived = set(pc.restore_skip_types())
        self.assertTrue(derived, "契约表必须导出响应侧不还原的块类型")
        self.assertTrue(derived.issubset(set(tr._RESTORE_SKIP_BLOCK_TYPES)),
                        "transparent 的不还原集合必须包含契约表导出的全部块类型")
        self.assertIn("thinking", derived, "Anthropic/LiteLLM 思考块必须在列")

    def test_bare_field_names_are_not_exempted_anywhere(self):
        """反例锁：同名键出现在无关位置时必须照常扫描（禁止全局字段名豁免）。"""
        out = self.mask_body({"payload": {"signature": SIG, "data": SIG,
                                          "encrypted_content": ENC, "thoughtSignature": SIG,
                                          "text": "账号 " + WORD}})
        for field in ("signature", "data", "encrypted_content", "thoughtSignature"):
            with self.subTest(field=field):
                self.assert_scanned(out["payload"][field], f"无关位置上的 {field}")
        self.assert_scanned(out["payload"]["text"], "无关位置上的正文（同请求正向对照）")


class ResponsesCarrierTests(ContractTestBase):
    """载体 1：OpenAI Responses `input[].encrypted_content`。"""

    def test_reasoning_encrypted_content_is_untouched(self):
        body = {"model": "gpt-5", "input": [
            {"type": "reasoning", "id": "rs_1", "encrypted_content": ENC},
            {"type": "message", "role": "user",
             "content": [{"type": "input_text", "text": "账号 " + WORD}]},
        ]}
        out = self.mask_body(body)
        self.assert_untouched(out["input"][0]["encrypted_content"], ENC,
                              "Responses reasoning.encrypted_content")
        self.assert_scanned(out["input"][1]["content"][0]["text"],
                            "Responses input[].message 正文（同请求正向对照）")

    def test_reasoning_without_encrypted_content_is_scanned(self):
        """无密文的 reasoning 项上游无从校验，照常扫描（不白丢一个漏检面）。"""
        body = {"model": "gpt-5", "input": [
            {"type": "reasoning", "id": "rs_1",
             "summary": [{"type": "summary_text", "text": "账号 " + WORD}]},
            {"type": "message", "role": "user",
             "content": [{"type": "input_text", "text": "账号 " + WORD}]},
        ]}
        out = self.mask_body(body)
        self.assert_scanned(out["input"][0]["summary"][0]["text"],
                            "无 encrypted_content 的 reasoning 摘要")
        self.assert_scanned(out["input"][1]["content"][0]["text"], "同请求正向对照")

    def test_input_as_object_instead_of_array_is_scanned(self):
        """位置反例：`input` 不是真实数组时不豁免（判据必须走真实数组）。"""
        body = {"model": "gpt-5",
                "input": {"type": "reasoning", "encrypted_content": ENC},
                "note": "账号 " + WORD}
        out = self.mask_body(body)
        self.assert_scanned(out["input"]["encrypted_content"], "非数组 input 内的同名键")
        self.assert_scanned(out["note"], "同请求正向对照")

    def test_function_call_arguments_are_scanned(self):
        """业务区反例：工具参数里的同名键是业务数据，不得借名豁免。"""
        body = {"model": "gpt-5", "input": [
            {"type": "function_call", "call_id": "call_1", "name": "f",
             "arguments": json.dumps({"encrypted_content": ENC})},
        ]}
        out = self.mask_body(body)
        args = json.loads(out["input"][0]["arguments"])
        self.assert_scanned(args["encrypted_content"], "function_call.arguments 内的同名键")


    def test_production_entry_shape_is_also_protected(self):
        """生产代理链路按顶层键逐个进 `_mask_tree`：顶层键留在 `key` 里、`path` 从下标开始。

        判据必须同时认两种入口形态（整包 vs 逐顶层键），否则"同一条请求走两条链路结果
        不同"的老问题会再来一次。
        """
        body = {"input": [{"type": "reasoning", "encrypted_content": ENC},
                          {"type": "message", "role": "user", "content": "账号 " + WORD}]}
        flag = [False]
        out = tr._mask_tree(json.loads(json.dumps(body["input"])), self.SID, "input", flag=flag)
        self.assert_untouched(out[0]["encrypted_content"], ENC,
                              "生产链路形态下的 reasoning 密文")
        self.assert_scanned(out[1]["content"], "同请求正向对照")
        self.assertTrue(flag[0], "对照被改写时脏标记必须置位")


class GeminiCarrierTests(ContractTestBase):
    """载体 2：Gemini `contents[].parts[].thoughtSignature`。"""

    def gemini_body(self, *parts, role="model"):
        return {"contents": [{"role": role, "parts": list(parts)}]}

    def test_thought_signature_is_untouched(self):
        out = self.mask_body(self.gemini_body(
            {"text": "想一下", "thoughtSignature": SIG},
            {"text": "账号 " + WORD}))
        parts = out["contents"][0]["parts"]
        self.assert_untouched(parts[0]["thoughtSignature"], SIG, "Gemini thoughtSignature")
        self.assert_scanned(parts[1]["text"], "Gemini parts[] 普通正文（同请求正向对照）")

    def test_snake_case_thought_signature_is_untouched(self):
        """企业版 / Vertex 的 JSON 里字段写作 `thought_signature`，同属不可改写状态。"""
        out = self.mask_body(self.gemini_body(
            {"text": "想一下", "thought_signature": SIG},
            {"text": "账号 " + WORD}))
        parts = out["contents"][0]["parts"]
        self.assert_untouched(parts[0]["thought_signature"], SIG, "Gemini thought_signature")
        self.assert_scanned(parts[1]["text"], "同请求正向对照")

    def test_function_call_args_same_name_key_is_scanned(self):
        """业务区反例：`functionCall.args` 里的同名键与普通字段都必须照常扫描。"""
        out = self.mask_body(self.gemini_body({
            "functionCall": {"name": "f",
                             "args": {"thoughtSignature": SIG, "text": "账号 " + WORD}},
            "thoughtSignature": SIG,
        }))
        part = out["contents"][0]["parts"][0]
        self.assert_untouched(part["thoughtSignature"], SIG, "Part 上的 thoughtSignature")
        args = part["functionCall"]["args"]
        self.assert_scanned(args["thoughtSignature"], "functionCall.args 内的同名键")
        self.assert_scanned(args["text"], "functionCall.args 内的普通业务字段")

    def test_user_role_thought_signature_is_scanned(self):
        """角色反例：签名只出现在 model 轮，user 轮的同名键不得豁免。"""
        out = self.mask_body(self.gemini_body(
            {"text": "账号 " + WORD, "thoughtSignature": SIG}, role="user"))
        part = out["contents"][0]["parts"][0]
        self.assert_scanned(part["thoughtSignature"], "user 轮的 thoughtSignature")
        self.assert_scanned(part["text"], "user 轮的正文（同请求正向对照）")


class LiteLlmCarrierTests(ContractTestBase):
    """载体 3：LiteLLM `messages[].thinking_blocks[]`。"""

    def test_thinking_blocks_are_untouched(self):
        body = {"messages": [
            {"role": "assistant", "content": "", "thinking_blocks": [
                {"type": "thinking", "thinking": "看 " + WORD, "signature": SIG}]},
            {"role": "user", "content": "账号 " + WORD},
        ]}
        out = self.mask_body(body)
        blk = out["messages"][0]["thinking_blocks"][0]
        self.assert_untouched(blk["thinking"], "看 " + WORD, "LiteLLM thinking_blocks 正文")
        self.assert_untouched(blk["signature"], SIG, "LiteLLM thinking_blocks 签名")
        self.assert_scanned(out["messages"][1]["content"], "同请求的 user 正文")

    def test_redacted_thinking_blocks_are_untouched(self):
        out = self.mask_body({"messages": [
            {"role": "assistant", "thinking_blocks": [
                {"type": "redacted_thinking", "data": ENC}]},
            {"role": "user", "content": "账号 " + WORD},
        ]})
        self.assert_untouched(out["messages"][0]["thinking_blocks"][0]["data"], ENC,
                              "LiteLLM redacted_thinking.data")
        self.assert_scanned(out["messages"][1]["content"], "同请求正向对照")

    def test_unsigned_thinking_blocks_are_scanned(self):
        out = self.mask_body({"messages": [
            {"role": "assistant", "thinking_blocks": [{"type": "thinking", "thinking": WORD}]},
            {"role": "user", "content": "账号 " + WORD},
        ]})
        self.assert_scanned(out["messages"][0]["thinking_blocks"][0]["thinking"],
                            "无签名的 thinking_block")
        self.assert_scanned(out["messages"][1]["content"], "同请求正向对照")

    def test_user_role_thinking_blocks_are_scanned(self):
        """角色反例：user 消息上的同名容器不得豁免。"""
        out = self.mask_body({"messages": [
            {"role": "user", "thinking_blocks": [
                {"type": "thinking", "thinking": WORD, "signature": SIG}]},
            {"role": "user", "content": "账号 " + WORD},
        ]})
        blk = out["messages"][0]["thinking_blocks"][0]
        self.assert_scanned(blk["thinking"], "user 角色的 thinking_blocks 正文")
        self.assert_scanned(blk["signature"], "user 角色的 thinking_blocks 签名")


class OpenRouterCarrierTests(ContractTestBase):
    """载体 4：OpenRouter `message.reasoning_details[]`。"""

    def body(self, role="assistant"):
        return {"messages": [
            {"role": role, "reasoning_details": [
                {"type": "reasoning.encrypted", "data": ENC, "index": 0},
                {"type": "reasoning.text", "text": "看 " + WORD, "signature": SIG, "index": 1},
                {"type": "reasoning.summary", "summary": "摘要 " + WORD, "index": 2},
            ]},
            {"role": "user", "content": "账号 " + WORD},
        ]}

    def test_reasoning_details_are_untouched(self):
        out = self.mask_body(self.body())
        details = out["messages"][0]["reasoning_details"]
        self.assert_untouched(details[0]["data"], ENC, "reasoning.encrypted.data")
        self.assert_untouched(details[1]["text"], "看 " + WORD, "reasoning.text.text")
        self.assert_untouched(details[1]["signature"], SIG, "reasoning.text.signature")
        self.assert_scanned(out["messages"][1]["content"], "同请求的 user 正文")

    def test_summary_detail_is_still_scanned(self):
        """不越界：没有签名的摘要不是不可改写状态，必须照常扫描。"""
        out = self.mask_body(self.body())
        self.assert_scanned(out["messages"][0]["reasoning_details"][2]["summary"],
                            "reasoning.summary.summary")

    def test_user_role_details_are_scanned(self):
        """角色反例：user 消息上的 reasoning_details 不得豁免。"""
        out = self.mask_body(self.body(role="user"))
        detail = out["messages"][0]["reasoning_details"][1]
        self.assert_scanned(detail["text"], "user 角色的 reasoning.text")
        self.assert_scanned(detail["signature"], "user 角色的 reasoning.text 签名")


class AnthropicWebSearchCarrierTests(ContractTestBase):
    """载体 5：Anthropic `web_search_tool_result.content[].encrypted_content`。"""

    def body(self, role="assistant"):
        return {"messages": [{"role": role, "content": [
            {"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search",
             "input": {"query": "claude shannon"}},
            {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1", "content": [
                {"type": "web_search_result", "url": "https://example.com",
                 "title": "标题 " + WORD, "encrypted_content": ENC}]},
            {"type": "text", "text": "看 " + WORD},
        ]}]}

    def test_encrypted_content_is_untouched(self):
        out = self.mask_body(self.body())
        record = out["messages"][0]["content"][1]["content"][0]
        self.assert_untouched(record["encrypted_content"], ENC,
                              "web_search_result.encrypted_content")
        self.assert_scanned(record["title"], "搜索结果标题（同请求正向对照）")
        self.assert_scanned(out["messages"][0]["content"][2]["text"], "同请求的正文块")

    def test_user_turn_replay_is_still_protected(self):
        """有些客户端把服务器工具结果回放在 user 轮。

        判据主体是嵌套 typed record（`content[].type == "web_search_result"`），
        角色只是必要条件而非唯一依据，所以两种回放形态都受保护。
        """
        out = self.mask_body(self.body(role="user"))
        record = out["messages"][0]["content"][1]["content"][0]
        self.assert_untouched(record["encrypted_content"], ENC, "user 轮回放的检索结果密文")
        self.assert_scanned(record["title"], "同请求正向对照")

    def test_embedded_json_string_is_scanned(self):
        """字符串里内嵌 JSON（AstrLink `continuation_test.go:134` 夹具）不是协议结构。"""
        payload = json.dumps({"type": "web_search_result", "encrypted_content": ENC})
        out = self.mask_body({"messages": [{"role": "assistant", "content": [
            {"type": "text", "text": payload}]}]})
        self.assert_scanned(out["messages"][0]["content"][0]["text"], "内嵌 JSON 的正文")


class AstrLinkAdversarialTests(ContractTestBase):
    """AstrLink `continuation_test.go:134` 的对抗夹具：这些形态一律不得豁免。"""

    def test_user_role_thinking_block_is_scanned(self):
        out = self.mask_body({"messages": [{"role": "user", "content": [
            {"type": "thinking", "thinking": WORD, "signature": SIG},
            {"type": "text", "text": "账号 " + WORD}]}]})
        blocks = out["messages"][0]["content"]
        self.assert_scanned(blocks[0]["thinking"], "user 角色的 thinking 正文")
        self.assert_scanned(blocks[0]["signature"], "user 角色的 thinking 签名")
        self.assert_scanned(blocks[1]["text"], "同请求正向对照")

    def test_tool_result_nested_redacted_thinking_is_scanned(self):
        out = self.mask_body({"messages": [{"role": "user", "content": [
            {"type": "tool_result", "content": [
                {"type": "redacted_thinking", "data": ENC}]},
            {"type": "text", "text": "账号 " + WORD}]}]})
        blocks = out["messages"][0]["content"]
        self.assert_scanned(blocks[0]["content"][0]["data"],
                            "tool_result 内嵌的 redacted_thinking")
        self.assert_scanned(blocks[1]["text"], "同请求正向对照")

    def test_tool_use_input_same_name_fields_are_scanned(self):
        out = self.mask_body({"messages": [{"role": "assistant", "content": [
            {"type": "tool_use", "input": {"type": "thinking", "signature": SIG,
                                           "thinking": WORD, "data": ENC}},
            {"type": "text", "text": "账号 " + WORD}]}]})
        blocks = out["messages"][0]["content"]
        for field in ("signature", "thinking", "data"):
            with self.subTest(field=field):
                self.assert_scanned(blocks[0]["input"][field], f"tool_use.input 内的 {field}")
        self.assert_scanned(blocks[1]["text"], "同请求正向对照")

    def test_embedded_json_string_is_scanned(self):
        payload = json.dumps({"type": "thinking", "thinking": WORD, "signature": SIG})
        out = self.mask_body({"messages": [{"role": "assistant", "content": [
            {"type": "text", "text": payload},
            {"type": "text", "text": "账号 " + WORD}]}]})
        blocks = out["messages"][0]["content"]
        self.assert_scanned(blocks[0]["text"], "内嵌 JSON 的正文")
        self.assert_scanned(blocks[1]["text"], "同请求正向对照")

    def test_unknown_protocol_container_is_scanned(self):
        """未知协议继续保守扫描：容器键不吻合就不豁免。"""
        out = self.mask_body({"custom_payload": [
            {"type": "reasoning", "encrypted_content": ENC},
            {"type": "thinking", "thinking": WORD, "signature": SIG}]})
        items = out["custom_payload"]
        self.assert_scanned(items[0]["encrypted_content"], "未知容器内的 encrypted_content")
        self.assert_scanned(items[1]["signature"], "未知容器内的 signature")


class ResponseSideSharedRuleTests(ContractTestBase):
    """响应侧：不还原的块类型与请求侧同源（E3：base64 无需另建逻辑）。"""

    def setUp(self):
        super().setUp()
        # 由引擎签发真实 token（**不写死占位符字面量**：本机网关会把字面量还原）
        self.token = tr.mask(PHONE, self.SID)
        self.assertTrue(self.token.startswith("{{"), "前置：token 必须由引擎签发")

    def test_whole_body_restore_skips_reasoning_details(self):
        body = {"choices": [{"message": {
            "reasoning_details": [
                {"type": "reasoning.text", "text": "看 " + self.token,
                 "signature": "Aq" + self.token + "=="},
                {"type": "reasoning.encrypted", "data": self.token},
                {"type": "reasoning.summary", "summary": "看 " + self.token},
            ],
            "content": "看 " + self.token,
        }}]}
        out = tr._restore_tree(body, self.SID)
        details = out["choices"][0]["message"]["reasoning_details"]
        self.assertIn(self.token, details[0]["text"], "签名推理文本不得还原")
        self.assertIn(self.token, details[0]["signature"], "签名不得还原")
        self.assertIn(self.token, details[1]["data"], "密文推理块不得还原")
        self.assertIn(PHONE, details[2]["summary"], "对照：无签名的摘要仍要还原")
        self.assertIn(PHONE, out["choices"][0]["message"]["content"], "对照：正文仍要还原")

    def test_whole_body_restore_skips_litellm_thinking_blocks(self):
        body = {"choices": [{"message": {
            "thinking_blocks": [{"type": "thinking", "thinking": "看 " + self.token,
                                 "signature": "Aq" + self.token + "=="}],
            "content": "看 " + self.token,
        }}]}
        out = tr._restore_tree(body, self.SID)
        msg = out["choices"][0]["message"]
        self.assertIn(self.token, msg["thinking_blocks"][0]["thinking"], "思考块不得还原")
        self.assertIn(PHONE, msg["content"], "对照：正文仍要还原")

    def test_sse_reasoning_details_delta_is_not_restored(self):
        ev = {"choices": [{"index": 0, "delta": {"reasoning_details": [
            {"type": "reasoning.text", "text": "看 " + self.token}]}}]}
        tr._restore_sse_data(ev, self.SID)
        kept = ev["choices"][0]["delta"]["reasoning_details"][0]["text"]
        self.assertIn(self.token, kept, "SSE 上的签名推理增量不得还原")

    def test_sse_content_delta_is_restored(self):
        """对照组：正文增量必须照常还原，证明还原管线本身是活的。"""
        ev = {"choices": [{"index": 0, "delta": {"content": "看 " + self.token}}]}
        tr._restore_sse_data(ev, self.SID)
        self.assertIn(PHONE, ev["choices"][0]["delta"]["content"])

    def test_restore_skip_types_cover_new_carriers(self):
        import protocol_contracts as pc
        for block_type in ("reasoning.text", "reasoning.encrypted", "thinking",
                           "redacted_thinking"):
            with self.subTest(block_type=block_type):
                self.assertIn(block_type, tr._RESTORE_SKIP_BLOCK_TYPES)
        self.assertEqual(set(pc.restore_skip_types()),
                         set(tr._RESTORE_SKIP_BLOCK_TYPES),
                         "两套集合必须同源（由契约表导出，不在别处再写硬编码）")
        self.assertIn("thinking_delta", pc.restore_skip_types(),
                      "SSE 增量形态由响应侧并入同一集合")


class SkipAccountingTests(ContractTestBase):
    """豁免计数：每个新载体都要计入 `signed_blocks_skipped`，不得静默。"""

    def carrier_bodies(self):
        return {
            "anthropic_thinking": {"messages": [{"role": "assistant", "content": [
                {"type": "thinking", "thinking": WORD, "signature": SIG}]}]},
            "responses_reasoning": {"input": [
                {"type": "reasoning", "encrypted_content": ENC}]},
            "gemini_thought_signature": {"contents": [{"role": "model", "parts": [
                {"text": WORD, "thoughtSignature": SIG}]}]},
            "litellm_thinking_blocks": {"messages": [{"role": "assistant", "thinking_blocks": [
                {"type": "thinking", "thinking": WORD, "signature": SIG}]}]},
            "openrouter_reasoning_details": {"messages": [{"role": "assistant",
                                                           "reasoning_details": [
                {"type": "reasoning.text", "text": WORD, "signature": SIG}]}]},
            "anthropic_web_search_result": {"messages": [{"role": "assistant", "content": [
                {"type": "web_search_tool_result", "content": [
                    {"type": "web_search_result", "encrypted_content": ENC}]}]}]},
        }

    def test_every_carrier_is_counted_exactly_once(self):
        for label, body in self.carrier_bodies().items():
            with self.subTest(carrier=label):
                tr._new_session(self.SID)
                self.mask_body(body)
                self.assertEqual(tr._take_signed_skips(self.SID), 1,
                                 f"{label} 必须计入本轮豁免块数")

    def test_plain_request_is_not_counted(self):
        """对照：没有任何载体的请求必须计数为 0（否则计数无法用于归因）。"""
        tr._new_session(self.SID)
        self.mask_body({"messages": [{"role": "user", "content": "账号 " + WORD}]})
        self.assertEqual(tr._take_signed_skips(self.SID), 0)
        self.assertEqual(tr._take_signed_skips(self.SID), 0, "取走即清零")

    def test_count_reaches_inspection_report(self):
        """计数必须走既有上报通道（批次 2 的 `report_for_mask`）。"""
        import inspection as ins
        tr._new_session(self.SID)
        self.mask_body(self.carrier_bodies()["responses_reasoning"])
        skipped = tr._take_signed_skips(self.SID)
        rpt = ins.report_for_mask(changed=True, signed_skipped=skipped)
        self.assertEqual(rpt["reason_codes"]["signed_blocks_skipped"], 1)
        self.assertEqual(rpt["completeness"], ins.COMPLETE, "契约内豁免不降完整度")


if __name__ == "__main__":
    unittest.main()
