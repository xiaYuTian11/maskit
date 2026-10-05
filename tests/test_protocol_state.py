"""签名/密文思考块只读化（批次 1）契约测试。

设计依据：`ai-coding/plans/maskit-personal-upgrade-plan.md` §A1（v3 定稿）。
四条不可违反的口径：

1. **请求侧豁免只认「协议位置 + 角色 + 块类型 + 不可改写字段非空」**：只有
   Anthropic assistant 消息 `content[]` 里带 `signature`/`data` 的
   `thinking`/`redacted_thinking` 块整块不扫描；角色错（user）、位置错（业务区
   `tool_use.input`）、无签名，一律照常扫描——这几条正是 AstrLink
   `continuation_test.go:134` 锁死的对抗用例，防「同名业务字段借名豁免」。
2. **响应侧 Anthropic 思考通道一律不还原**：SSE 增量、`content_block_start`
   快照、`message_start` 快照、整包/回退的整树还原，四条路径同口径；
   `text_delta` / `text` 块等其它通道继续还原（对照组）。
3. **每个负结果必须带正向对照**（R10）：同一段文本放在 `text` 块里必须被打码
   （请求侧）或被还原（响应侧），否则说明规则压根没生效，该条负结果作废。
4. **豁免必须计数**：整块跳过是漏检路径，`signed_blocks_skipped` 要如实上报。
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import transparent as tr  # noqa: E402
import inspection  # noqa: E402
import ner_engine  # noqa: E402
import protocol_contracts as pc  # noqa: E402

# 合成样例：明显伪造的号码（全零中段，不指向任何真实用户）。
# 分片拼接 + **不写成占位符字面量**——本机在脱敏网关之后，写成占位符字面量会在落盘时
# 被还原成真实号码（见方案 §8 R11；本文件是随包分发的跟踪文件，绝不能带真实号码）。
PHONE = "139" + "0000" + "0000"
# 自定义词：用来保证"应当扫描的位置"确实会命中（默认规则的数字边界校验会
# 放过被字母包住的号码，用词表才能证明该位置没被豁免）。
WORD = "acme"
SIG = "AqBcDeFgHiJkLmNoPqRsTuVwXyZ012345=="


class ProtocolStateTestBase(unittest.TestCase):
    SID = "protocol-state"

    def setUp(self):
        self._old_root = tr._DATA_ROOT
        self._old_emit = tr._emit
        self.tmp = Path(tempfile.mkdtemp())
        cfg = {
            "builtin_rules": {},
            "sensitive": {"CUSTOMER": [WORD]},
        }
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
        """按生产路径的入口形态脱敏（深拷贝，避免测试自身持有被改对象）。"""
        return tr._mask_tree(json.loads(json.dumps(body, ensure_ascii=False)), self.SID)

    @staticmethod
    def assistant(*blocks):
        return {"messages": [{"role": "assistant", "content": list(blocks)}]}

    @staticmethod
    def user(*blocks):
        return {"messages": [{"role": "user", "content": list(blocks)}]}

    def block_of(self, out, msg=0, blk=0):
        return out["messages"][msg]["content"][blk]


class RequestSideSignedBlockTests(ProtocolStateTestBase):
    """§A1 请求侧：签名块整块只读，其它位置照常扫描。"""

    def test_signed_thinking_block_is_untouched(self):
        body = self.assistant(
            {"type": "thinking", "thinking": WORD + " 的手机号 " + PHONE, "signature": SIG},
            {"type": "text", "text": WORD + " 的手机号 " + PHONE},
        )
        out = self.mask_body(body)
        blk = self.block_of(out)
        # 负结果 + 正向对照：块内逐字节不变，对照块必须被改写
        self.assertEqual(blk["thinking"], WORD + " 的手机号 " + PHONE)
        self.assertEqual(blk["signature"], SIG)
        self.assertNotEqual(out["messages"][0]["content"][1]["text"], WORD + " 的手机号 " + PHONE)
        self.assertTrue(out["messages"][0]["content"][1]["text"].startswith("{{CUSTOMER_"))

    def test_redacted_thinking_block_is_untouched(self):
        body = self.assistant(
            {"type": "redacted_thinking", "data": "Bx" + WORD + "Cdef=="},
            {"type": "text", "text": WORD},
        )
        out = self.mask_body(body)
        self.assertEqual(self.block_of(out)["data"], "Bx" + WORD + "Cdef==")
        self.assertNotEqual(out["messages"][0]["content"][1]["text"], WORD, "对照块必须被改写")

    def test_user_role_thinking_is_still_scanned(self):
        """角色反例：user 消息里的同名块不得豁免（AstrLink `continuation_test.go:134`）。

        断言必须用**含敏感词的**签名值：扫描 ≠ 必然改写，拿一个本来就不会命中的值
        做"应当被改写"的断言是假断言。
        """
        out = self.mask_body(self.user(
            {"type": "thinking", "thinking": WORD, "signature": "Aq" + WORD + "Zz=="},
        ))
        self.assertNotEqual(self.block_of(out)["thinking"], WORD, "user 角色的思考块必须照常扫描")
        self.assertNotEqual(self.block_of(out)["signature"], "Aq" + WORD + "Zz==",
                            "user 角色块内的签名值也必须扫描（同名键不得借名豁免）")

    def test_tool_result_nested_redacted_thinking_is_still_scanned(self):
        """位置反例：`tool_result` 不在业务区集合里，块类型判据必须自己挡住它。"""
        out = self.mask_body(self.user(
            {"type": "tool_result", "content": [{"type": "redacted_thinking", "data": WORD}]},
        ))
        self.assertNotEqual(self.block_of(out)["content"][0]["data"], WORD)

    def test_business_area_signature_field_is_still_scanned(self):
        """业务区反例：tool_use.input 里的同名键是业务数据，必须照常扫描。"""
        out = self.mask_body(self.assistant(
            {"type": "tool_use", "input": {"type": "thinking", "signature": WORD}},
        ))
        self.assertNotEqual(self.block_of(out)["input"]["signature"], WORD)

    def test_unsigned_thinking_block_is_still_scanned(self):
        """无签名的思考块上游无从校验，照常脱敏（不白丢一个漏检面）。"""
        out = self.mask_body(self.assistant(
            {"type": "thinking", "thinking": WORD},
        ))
        self.assertNotEqual(self.block_of(out)["thinking"], WORD)

    def test_signed_block_signature_with_custom_word_hit_is_untouched(self):
        """E2b 回归：签名串里出现自定义词命中面时，签名块整体一字不改。

        实测（signed_block_probe.py E2b）：用户只要在 UI 加一个 2 字符词，签名里的
        大小写不敏感命中就会把 `signature`/`data` 打烂。豁免必须盖住整个块。
        """
        out = self.mask_body(self.assistant(
            {"type": "thinking", "thinking": WORD, "signature": "Aq" + WORD + "Zz=="},
            {"type": "text", "text": WORD},
        ))
        self.assertEqual(self.block_of(out)["signature"], "Aq" + WORD + "Zz==")
        self.assertEqual(self.block_of(out)["thinking"], WORD)
        self.assertNotEqual(out["messages"][0]["content"][1]["text"], WORD, "对照块必须被改写")

    def test_exempt_skips_are_counted_and_taken_once(self):
        body = self.assistant(
            {"type": "thinking", "thinking": "x", "signature": SIG},
            {"type": "redacted_thinking", "data": "abc"},
        )
        self.mask_body(body)
        self.assertEqual(tr._take_signed_skips(self.SID), 2)
        self.assertEqual(tr._take_signed_skips(self.SID), 0, "取走即清零，不能冒充下一轮数字")

    def test_placeholder_form_body_is_idempotent(self):
        """E4：占位符形态再走一遍脱敏必须逐字节不变（D6-B 的可行性前提）。"""
        once = self.mask_body(self.assistant(
            {"type": "text", "text": WORD + " 的手机号 " + PHONE},
            {"type": "thinking", "thinking": "x", "signature": SIG},
        ))
        twice = tr._mask_tree(json.loads(json.dumps(once, ensure_ascii=False)), self.SID)
        self.assertEqual(json.dumps(twice, ensure_ascii=False), json.dumps(once, ensure_ascii=False))


class ResponseSideSignedBlockTests(ProtocolStateTestBase):
    """§A1 + D6-B 响应侧：思考通道不还原，其它通道继续还原。"""

    def setUp(self):
        super().setUp()
        # 让引擎签发一个真实 token（**不写死占位符字面量**：本机网关会把字面量还原）
        self.token = tr.mask(PHONE, self.SID)
        self.assertTrue(self.token.startswith("{{"), "前置：token 必须由引擎签发")

    def test_thinking_delta_is_not_restored(self):
        ev = {"type": "content_block_delta", "index": 0,
              "delta": {"type": "thinking_delta", "thinking": "看 " + self.token + " 结束"}}
        tr._restore_sse_data(ev, self.SID)
        self.assertIn(self.token, ev["delta"]["thinking"], "思考增量不得还原")

    def test_text_delta_is_restored(self):
        """对照组：正文通道必须照常还原，证明还原管线本身是活的。"""
        ev = {"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": "看 " + self.token + " 结束"}}
        tr._restore_sse_data(ev, self.SID)
        self.assertIn(PHONE, ev["delta"]["text"])

    def test_thinking_snapshot_and_signature_are_not_restored(self):
        ev = {"type": "content_block_start", "index": 0,
              "content_block": {"type": "thinking", "thinking": self.token,
                                "signature": "Aq" + self.token + "Zz=="}}
        tr._restore_sse_data(ev, self.SID)
        self.assertIn(self.token, ev["content_block"]["thinking"])
        self.assertIn(self.token, ev["content_block"]["signature"])

    def test_message_start_snapshot_is_not_restored(self):
        ev = {"type": "message_start",
              "message": {"role": "assistant", "content": [
                  {"type": "thinking", "thinking": "看 " + self.token, "signature": "Aq" + self.token + "=="},
                  {"type": "text", "text": "看 " + self.token},
              ]}}
        tr._restore_sse_data(ev, self.SID)
        blocks = ev["message"]["content"]
        self.assertIn(self.token, blocks[0]["thinking"])
        self.assertIn(self.token, blocks[0]["signature"])
        self.assertIn(PHONE, blocks[1]["text"], "对照：同快照里的 text 块仍要还原")

    def test_whole_body_restore_skips_signed_blocks(self):
        body = {"content": [
            {"type": "thinking", "thinking": "看 " + self.token, "signature": "Aq" + self.token + "=="},
            {"type": "redacted_thinking", "data": "Bx" + self.token},
            {"type": "text", "text": "看 " + self.token},
        ]}
        out = tr._restore_tree(body, self.SID)
        blocks = out["content"]
        self.assertIn(self.token, blocks[0]["thinking"])
        self.assertIn(self.token, blocks[0]["signature"])
        self.assertIn(self.token, blocks[1]["data"])
        self.assertIn(PHONE, blocks[2]["text"], "对照：整包里 text 块仍要还原")

    def test_signature_delta_has_no_restore_slot(self):
        slots = tr._sse_text_slots({"type": "content_block_delta", "index": 0,
                                    "delta": {"type": "signature_delta", "signature": self.token}})
        self.assertEqual(slots, [])

    def test_reasoning_channels_still_restored(self):
        """无签名约束的推理通道继续还原（否则等于把可读性白送出去）。"""
        ev = {"choices": [{"index": 0, "delta": {"reasoning_content": "看 " + self.token}}]}
        tr._restore_sse_data(ev, self.SID)
        self.assertIn(PHONE, ev["choices"][0]["delta"]["reasoning_content"])


# 含命中面的不可改写状态样例：签名里内嵌自定义词，这样「原样保留」才不是
# 靠"签名里没有可命中的东西"侥幸得到（§A1 E2c 的教训：不塞命中面就只能测出假绿）。
SIG_HIT = "Aq" + WORD + "BcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/=="
# 当前契约表里 scope="block" 的载体名单（漂移检测用，见下）。
# block = 「签名覆盖兄弟明文」——改写它会让会话**永久不可发送**，是本项目
# 唯一需要「绝不阻断」硬约束的载体类别。
_BLOCK_CARRIERS = frozenset({
    "anthropic_thinking",
    "litellm_thinking_blocks",
    "openrouter_reasoning_details",
})


def _block_carrier_bodies():
    """逐个 block 载体的**命中体**（键名与父键按契约表，形态扳自 `test_protocol_contracts.py`）。

    有意逐载体手写而不是按契约表字段通用生成：契约表一旦新增 block 载体，
    这里**不会自动多出一条**，`test_block_scope_carrier_list_is_fully_covered`
    就会红 —— 这正是想要的提醒。
    """
    return {
        "anthropic_thinking": {
            "messages": [{"role": "assistant", "content": [
                {"type": "thinking", "thinking": "看 " + WORD, "signature": SIG_HIT}]}],
        },
        "litellm_thinking_blocks": {
            "messages": [{"role": "assistant", "content": "", "thinking_blocks": [
                {"type": "thinking", "thinking": "看 " + WORD, "signature": SIG_HIT}]}],
        },
        "openrouter_reasoning_details": {
            "messages": [{"role": "assistant", "reasoning_details": [
                {"type": "reasoning.text", "text": "看 " + WORD,
                 "signature": SIG_HIT, "index": 0}]}],
        },
    }


class NoPermanentBlockTests(ProtocolStateTestBase):
    """D2 硬约束 / §A3 第 1 条：协议不可改写位置命中，**永不**阻断。

    为什么单列一类而不是并进上面：它是**治理约束**，不是协议细节。
    D2 定案原文：「阻断一个用户无法编辑的历史字段（Anthropic `signature`）=
    该会话**永久不可发送**，每次重试再阻断一次，用户无法自救」—— 所以这条一旦
    被将来的改动破坏，会表现成「功能看来更严格」，而用户永久卡死且无 UI 可自救。

    钉住它用三层，从真值源到端到端：
      ① 原因码类别（`inspection` 是阻断判据的唯一真值源）；
      ② 判据函数（`has_blocking_reason` / `completeness_of`）；
      ③ 结构隔离（豁免计数住会话字段，**不进入**阻断判据的唯一输入 `ner_skips`）
         + 每个 block 载体的真实脱敏路径。
    """

    def test_exempt_is_not_a_blocking_category(self):
        """① 豁免类原因码不在阻断类别里。"""
        self.assertEqual(inspection.reason_category("signed_blocks_skipped"), "exempt")
        self.assertNotIn("exempt", inspection.BLOCKING_CATEGORIES)
        # 钉住整个集合而不是只钉「exempt 不在里面」：放宽到别的类别同样危险，
        # 而 D2 只授权「检测没跑完」类降级作为阻断依据。
        self.assertEqual(inspection.BLOCKING_CATEGORIES, frozenset({"degraded"}),
                         "阻断类别集合被改动了。D2 只允许「检测没跑完」类降级阻断；"
                         "把协议豁免或 info 类加进来 = 新增「永久不可发送」路径")

    def test_exempt_reason_neither_blocks_nor_degrades_completeness(self):
        """② 即使豁免发生多次，严格模式也不阻断、完整度也不降级。"""
        reasons = {"signed_blocks_skipped": 7}
        self.assertFalse(inspection.has_blocking_reason(reasons))
        self.assertEqual(inspection.completeness_of(reasons), inspection.COMPLETE,
                         "豁免是契约内的显式不扫面，不该把完整度降成 partial")

    def test_signed_block_skip_does_not_enter_the_blocking_input(self):
        """③ 结构隔离：豁免计数不进 `ner_skips`（阻断判据的**唯一**输入）。

        严格模式闸门的判据是 `NER_REQUIRE_COMPLETE and
        inspection.has_blocking_reason(ner_skips)`；而豁免计数写的是
        `sess["signed_skipped"]`。两者是不同存储，所以「豁免导致阻断」在结构上
        就不可能发生 —— 这比断言某个函数返回 False 更靠前一层。
        """
        self.mask_body({"messages": [{"role": "assistant", "content": [
            {"type": "thinking", "thinking": "看 " + WORD, "signature": SIG_HIT}]}]})
        self.assertEqual(ner_engine.request_skips(), {},
                         "签名块豁免写进了 NER 跳过记账 —— 那正是严格模式的阻断判据，"
                         "会让含思考块的长会话在严格模式下永久 503")

    def test_block_scope_carrier_list_is_fully_covered(self):
        """漂移检测：契约表新增 block 载体时，必须同步补下面的端到端用例。"""
        actual = frozenset(c.name for c in pc.CARRIERS if c.scope == "block")
        self.assertEqual(actual, _BLOCK_CARRIERS,
                         "scope=\"block\" 的载体名单变了。新增一个而不补用例，"
                         "等于新载体没有任何「不阻断」约束；确属有意新增时请同步本集合"
                         "与 _block_carrier_bodies()")

    def test_every_block_scope_carrier_is_exempt_and_never_blocks(self):
        """端到端：逐个 block 载体走真实脱敏路径 —— 整块只读 + 计数 + 不阻断。

        「不阻断」在脱敏层没有可直接观察的返回值，所以这里用**排除法**：
        命中后既没产生阻断原因码（上一条已钉），也没写进 `ner_skips`
        （上一条已钉），且计数确实发生了（证明它真的命中了而不是判据失效）。
        """
        for name, body in _block_carrier_bodies().items():
            with self.subTest(carrier=name):
                out = self.mask_body(body)
                carrier = next(c for c in pc.CARRIERS if c.name == name)
                blk = (out["messages"][0][carrier.key][0]
                       if carrier.key != "content"
                       else out["messages"][0]["content"][0])
                field = carrier.types[0][1]
                # 签名内嵌了自定义词 —— 改了它就是 400，所以这一条同时证明
                # 「命中面真的存在」与「豁免真的生效」
                self.assertEqual(blk[field], SIG_HIT,
                                 f"{name}:{field} 被改写了（上游会 400）")
                body_key = "thinking" if "thinking" in blk else "text"
                self.assertEqual(blk[body_key], "看 " + WORD,
                                 f"{name} 是 block 作用域，正文必须整块只读")
                self.assertGreaterEqual(
                    tr._take_signed_skips(self.SID), 1,
                    f"{name} 命中后未计数 —— 豁免是漏检路径，静默豁免不可接受")
                # 同一请求的正向对照：user 正文必须照常打码，否则说明规则没生效，
                # 上面两条「原样保留」的负结果全部作废（R10）。
                pos = self.mask_body(self.user({"type": "text", "text": "账号 " + WORD}))
                self.assertNotIn(WORD, pos["messages"][0]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
