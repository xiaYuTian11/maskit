import re
import json
import io
import os
import shutil
import sys
import time
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import panel
import transparent as tr
import event_store


class ShieldEngineTests(unittest.TestCase):
    def setUp(self):
        tr.sessions.clear()
        # 跨请求占位符复用表：不清会串到下一个用例（同一原文会复用上一用例的占位符）
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update({"张三": "NAME", "李四": "NAME"})
        # 禁用状态与规则开关是全局的，前一个用例设置后不重置会串到下一个用例
        tr.SENSITIVE_DISABLED = set()
        tr.SENSITIVE_WORD_DISABLED = {}
        tr.BUILTIN_RULES = {l: True for l in tr.DEFAULT_BUILTIN_RULES}
        tr.BUILTIN_RULES["IP_INTERNAL"] = False
        tr.BUILTIN_RULES["USCC"] = False
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr.TARGET_DOMAINS = ["api.openai.com", "anthropic.com"]
        tr.DOMAINS_DISABLED = set()
        tr.API_PATHS = ["/v1/chat/completions", "/v1/completions", "/v1/messages", "/v1/responses"]
        tr.SECRET_PREFIXES = ["sk-", "ah-"]
        tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
        # 旧引擎测试用 explicit 模式（按 host+path 判定目标），不走 reverse 路由
        tr.CAPTURE_MODE = "explicit"

    def _flow(self, host, path, body, headers=None):
        req_headers = {"content-type": "application/json"}
        if headers:
            req_headers.update(headers)
        return SimpleNamespace(
            request=SimpleNamespace(
                pretty_host=host,
                path=path,
                headers=req_headers,
                content=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            ),
            response=None,
            metadata={},
        )

    def _with_no_reload(self, fn):
        old_reload = tr._maybe_reload
        old_emit = tr._emit
        try:
            tr._maybe_reload = lambda force=False: None
            tr._emit = lambda *args, **kwargs: None
            return fn()
        finally:
            tr._maybe_reload = old_reload
            tr._emit = old_emit

    def test_builtin_rules_match_chinese_context(self):
        sid = "rules"
        tr._new_session(sid)
        masked = tr.mask("电话13812345678，身份证110101199003074514，IP是192.168.1.1", sid)
        self.assertEqual(masked.count("{{"), 3)
        self.assertNotIn("13812345678", masked)

    def test_phone_rule_matches_separated_numbers(self):
        sid = "phone-sep"
        tr._new_session(sid)
        masked = tr.mask("电话138-1234-5678，备用138 1234 5678", sid)
        self.assertEqual(masked.count("{{"), 2)
        self.assertNotIn("138-1234-5678", masked)
        self.assertNotIn("138 1234 5678", masked)

    def test_phone_rule_matches_plus86_prefix(self):
        """+86 前缀整体脱敏（曾只脱 138... 部分，国家码原文残留）。"""
        sid = "phone-86"
        tr._new_session(sid)
        masked = tr.mask("电话+86 13812345678，备用+8613912345678", sid)
        self.assertEqual(masked.count("{{"), 2)
        self.assertNotIn("+86", masked)
        self.assertNotIn("13812345678", masked)
        self.assertNotIn("13912345678", masked)

    def test_email_rule_matches_chinese_local_part(self):
        """中文邮箱用户名（张三@qq.com 曾整体漏检）。"""
        sid = "email-cn"
        tr._new_session(sid)
        masked = tr.mask("联系张三@qq.com 或张san@example.com", sid)
        self.assertEqual(masked.count("{{"), 2)
        self.assertNotIn("张三@qq.com", masked)
        self.assertNotIn("张san@example.com", masked)
        # 还原后应完整回来
        restored = tr.restore(masked, sid, final=True)
        self.assertIn("张三@qq.com", restored)

    def test_email_rule_does_not_match_conn_string(self):
        """EMAIL 连接串回归：user:pass@host 形态不再误伤。
        曾把 postgres://user:secret123@db.internal 的 secret123@db.internal
        当邮箱脱敏（连接串 password 部分）。
        新增 CONNSTR 规则后，连接串密码应被 CONNSTR 脱敏，但 host/user/scheme 保留。"""
        sid = "email-conn"
        tr._new_session(sid)
        masked = tr.mask("连接串 postgres://user:secret123@db.internal:5432/app", sid)
        self.assertNotIn("secret123", masked, "连接串密码应被脱敏")
        self.assertNotIn("{{EMAIL_", masked, "连接串 pass@host 不应被当邮箱")
        self.assertIn("postgres://", masked)
        self.assertIn("db.internal", masked)
        # 真邮箱仍命中
        sid2 = "email-real"
        tr._new_session(sid2)
        masked2 = tr.mask("邮箱 li.si@company.com.cn", sid2)
        self.assertNotIn("li.si@company.com.cn", masked2)

    def test_email_rule_does_not_match_short_local(self):
        """本地部分最小 2 字符：x@y.z 伪邮箱不误伤。"""
        sid = "email-short"
        tr._new_session(sid)
        masked = tr.mask("版本号 a@b.c 无意义，但 ab@cd.ef 是邮箱", sid)
        self.assertIn("a@b.c", masked)
        self.assertNotIn("ab@cd.ef", masked)

    def test_landline_rule_matches_with_prefix_zero(self):
        """座机：区号 2-3 位 + 分隔 7-8 位或无分隔 8 位。"""
        sid = "land"
        tr._new_session(sid)
        masked = tr.mask("座机010-52345678 或 0755-5234567 或 021 87654321", sid)
        self.assertEqual(masked.count("{{"), 3)
        self.assertNotIn("010-12345678", masked)
        self.assertNotIn("021 87654321", masked)
        # 全连写 11 位数字串不再误伤（id=02012345678 曾误判为座机）
        sid3 = "land-fp2"
        tr._new_session(sid3)
        masked3 = tr.mask("id=02012345678", sid3)
        self.assertIn("02012345678", masked3)
        # 10 位短号（不带分隔）不误伤：0123456789 是订单号形态
        sid2 = "land-fp"
        tr._new_session(sid2)
        masked2 = tr.mask("单号0123456789 结束", sid2)
        self.assertIn("0123456789", masked2)

    def test_plate_rule_matches_cn_plates(self):
        """车牌：汉字省份 + 5 位普通 / 6 位新能源。"""
        sid = "plate"
        tr._new_session(sid)
        masked = tr.mask("车辆京A12345 和新能源京AD12345", sid)
        self.assertEqual(masked.count("{{"), 2)
        self.assertNotIn("京A12345", masked)
        self.assertNotIn("京AD12345", masked)

    def test_hkid_rule_matches_hk_id(self):
        """港澳通行证：仅 H 开头 8 位（M 开头与日期/变量名 M20260805 无法区分，
        C 是回乡证且订单号误伤面大，均已去掉）。"""
        old = tr.BUILTIN_RULES.get("HKID")
        tr.BUILTIN_RULES["HKID"] = True
        try:
            sid = "hk"
            tr._new_session(sid)
            masked = tr.mask("证件H12345678", sid)
            self.assertIn("{{", masked)
            self.assertNotIn("H12345678", masked)
            # M 开头日期/变量不再命中（M20260805 曾误伤）
            sid2 = "hk-fp"
            tr._new_session(sid2)
            masked2 = tr.mask("编号M20260805", sid2)
            self.assertIn("M20260805", masked2)
            # C 开头不再命中（订单号 C12345678 曾误伤）
            sid3 = "hk-fp2"
            tr._new_session(sid3)
            masked3 = tr.mask("订单C12345678", sid3)
            self.assertIn("C12345678", masked3)
        finally:
            if old is None: tr.BUILTIN_RULES.pop("HKID", None)
            else: tr.BUILTIN_RULES["HKID"] = old

    def test_jwt_rule_verifies_header(self):
        """JWT：header 解码含 alg 才脱敏（长 base64 串不误伤）。"""
        import base64 as b64
        header = b64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        real = f"{header}.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        sid = "jwt-ok"
        tr._new_session(sid)
        masked = tr.mask("token " + real, sid)
        self.assertIn("{{", masked)
        self.assertNotIn("SflKxw", masked)
        # 非 JSON header 的 eyJ 形态不误伤
        fake_head = b64.urlsafe_b64encode(b"not-json-at-all").decode().rstrip("=")
        fake = f"{fake_head}.abcdefgh.uvwxyz123456"
        sid2 = "jwt-fp"
        tr._new_session(sid2)
        masked2 = tr.mask("code " + fake, sid2)
        self.assertIn(fake, masked2)

    def test_secret_rule_no_nested_placeholder(self):
        """SECRET 嵌套占位符回归：api_key=sk-xxx 只产生 1 个占位符，
        还原后无 {{ 残留（曾前缀规则先换、SECRET 再包一层，嵌套残留）。"""
        tr.SECRET_PREFIXES = ["sk-", "ah-"]
        sid = "secret-nest"
        tr._new_session(sid)
        masked = tr.mask('config api_key="sk-abcdefghijklmnop123456"', sid)
        self.assertNotIn("sk-abcdefghijklmnop123456", masked)
        self.assertEqual(masked.count("{{"), 1, "只能有一个占位符，不得嵌套")
        restored = tr.restore(masked, sid, final=True)
        self.assertNotIn("{{", restored)
        self.assertIn("sk-abcdefghijklmnop123456", restored)

    def test_ip_internal_does_not_match_version_numbers(self):
        """IP_INTERNAL（10.x/172.16-31）默认关：版本号不再被脱敏。
        曾把 version 10.2.3.4 脱敏成占位符，用户问版本号时模型看不到数字。"""
        tr.BUILTIN_RULES["IP_INTERNAL"] = False
        sid = "ip-ver"
        tr._new_session(sid)
        masked = tr.mask("version 10.2.3.4 released 和 chrome/10.15.7.3", sid)
        self.assertIn("10.2.3.4", masked, "10.x 版本号不应被脱敏（默认关）")
        self.assertIn("10.15.7.3", masked)
        # 打开后应命中
        tr.BUILTIN_RULES["IP_INTERNAL"] = True
        sid2 = "ip-ver-on"
        tr._new_session(sid2)
        masked2 = tr.mask("内网地址 10.1.2.3", sid2)
        self.assertNotIn("10.1.2.3", masked2)
        tr.BUILTIN_RULES["IP_INTERNAL"] = False

    def test_ip_private_matches_internal_networks(self):
        """IP_PRIVATE（192.168/169.254）开启时命中。"""
        tr.BUILTIN_RULES["IP_PRIVATE"] = True
        sid = "ip-priv"
        tr._new_session(sid)
        masked = tr.mask("内网192.168.1.1 和链路本地169.254.1.2", sid)
        self.assertNotIn("192.168.1.1", masked)
        self.assertNotIn("169.254.1.2", masked)

    def test_secret_rule_does_not_match_code_snippets(self):
        """SECRET 误报回归：代码片段/说明文案不再当凭据。
        曾把 pattern\nimport、m.group(0)、/token=/api_key= 误脱敏（system prompt
        里的代码示例词）。真实凭据是 ASCII 无空白单 token。"""
        sid = "secret-code"
        tr._new_session(sid)
        masked = tr.mask("regex pattern\nimport re\n用 m.group(0) 取值\n说明: /token=/api_key= 赋值", sid)
        self.assertIn("pattern", masked, "代码片段不应被 SECRET 规则误伤")
        self.assertIn("m.group(0)", masked)
        self.assertIn("/token=/api_key=", masked)
        # 真实凭据仍命中
        masked2 = tr.mask("password=Hn8x!qW2zLm9pR", sid)
        self.assertNotIn("Hn8x!qW2zLm9pR", masked2)

    def test_idcard15_requires_province_prefix(self):
        """15 位身份证省份前缀校验：065217391304348（首位 0）不再误伤。"""
        # IDCARD 默认关，测试显式开启
        old = tr.BUILTIN_RULES.get("IDCARD")
        tr.BUILTIN_RULES["IDCARD"] = True
        try:
            sid = "id15-prefix"
            tr._new_session(sid)
            masked = tr.mask("编号065217391304348 和证件110101900307451", sid)
            self.assertIn("065217391304348", masked, "首位 0 不是合法身份证省份，不脱敏")
            self.assertNotIn("110101900307451", masked)
        finally:
            tr.BUILTIN_RULES["IDCARD"] = old

    def test_secret_rule_does_not_match_code_identifiers(self):
        """SECRET 误报回归：代码方法名/成员访问不再当凭据。
        曾把 const secret = ModelUtils.toStringSafe(foo)、obj.secret = getSecret()
        脱敏（值字符集含 .、纯字母标识符被当凭据）。现在值必须含数字/特殊符号
        且不含 .——真实凭据几乎必含数字/符号，代码标识符几乎都是纯字母。"""
        sid = "sec-code2"
        tr._new_session(sid)
        masked = tr.mask("const secret = ModelUtils.toStringSafe(foo) 和 obj.secret = getSecret() 和 token = abcdefgh", sid)
        self.assertIn("ModelUtils.toStringSafe", masked, "方法名不应被 SECRET 误伤")
        self.assertIn("getSecret", masked)
        self.assertIn("abcdefgh", masked)
        # 真实凭据仍命中
        sid2 = "sec-real"
        tr._new_session(sid2)
        masked2 = tr.mask("token = Abc12345XYZ", sid2)
        self.assertNotIn("Abc12345XYZ", masked2)

    def test_dialog_extracts_reasoning_content_sse(self):
        """dialog 摘要把思考和正文分段，不能混成一段或重复 reasoning 副本。"""
        sse = 'data: {"choices":[{"delta":{"reasoning_content":"让我想想"}}]}\n\n' \
               'data: {"choices":[{"delta":{"content":"结论"}}]}\n\ndata: [DONE]\n\n'
        out = tr._extract_chat_dialog(sse.encode("utf-8"), 4000)
        self.assertEqual(out, "【助手思考】\n让我想想\n\n【助手】\n结论")
        # 同时有 reasoning_content/reasoning 时优先前者，避免同一思考重复两遍
        both = 'data: {"choices":[{"delta":{"reasoning_content":"思考A","reasoning":"思考A","content":"正文A"}}]}\n\n'
        out_both = tr._extract_chat_dialog(both.encode("utf-8"), 4000)
        self.assertEqual(out_both.count("思考A"), 1)
        self.assertEqual(out_both, "【助手思考】\n思考A\n\n【助手】\n正文A")
        # JSON 整包响应：仅有 reasoning 时仍显示为思考，不冒充正文
        js = '{"choices":[{"message":{"reasoning_content":"纯思考无正文"}}]}'
        out2 = tr._extract_chat_dialog(js.encode("utf-8"), 4000)
        self.assertEqual(out2, "【助手思考】\n纯思考无正文")
        # content 与 reasoning 同时存在时分段显示
        js3 = '{"choices":[{"message":{"reasoning":"思考","content":"正文"}}]}'
        out3 = tr._extract_chat_dialog(js3.encode("utf-8"), 4000)
        self.assertEqual(out3, "【助手思考】\n思考\n\n【助手】\n正文")

    def test_error_hook_classifies_cancel_and_dns(self):
        """error() 分类回归：Client disconnected→CANCEL（非故障）；getaddrinfo→DNS_ERROR；
        其余→ERR。曾全部记 ERR 计入 alerts，正常取消也被当异常。"""
        class _Err:
            def __init__(self, msg): self._msg = msg
            def __str__(self): return self._msg
        emitted = []
        old_emit = tr._emit
        try:
            tr._emit = lambda typ, **kw: emitted.append(typ)
            for msg in ("Client disconnected.", "[Errno 11001] getaddrinfo failed", "server closed connection"):
                flow = SimpleNamespace(
                    request=SimpleNamespace(method="POST", host="api.openai.com", pretty_host="api.openai.com", path="/v1/chat/completions"),
                    metadata={}, error=_Err(msg), response=None,
                )
                tr.error(flow)
        finally:
            tr._emit = old_emit
        self.assertEqual(emitted, ["CANCEL", "DNS_ERROR", "ERR"],
                         "三类错误应分别归 CANCEL/DNS_ERROR/ERR")

    def test_timing_fields_on_mask_and_restore(self):
        """耗时字段回归：MASK 带 mask_ms；RESTORE 带 mask_ms/upstream_ms（perf_counter 精度）。"""
        def run():
            captured = []
            old_emit = tr._emit
            try:
                tr._emit = lambda typ, **kw: captured.append((typ, kw))
                tr.CUSTOM_WORDS.clear()
                tr.CUSTOM_WORDS.update({"张三": "PERSON"})
                tr._CUSTOM_WORD_RX_CACHE.clear()
                flow = self._flow("api.openai.com", "/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "联系人张三"}]
                })
                tr.request(flow)
                sid = flow.metadata.get("session_id")
                self.assertTrue(sid)
                flow.response = SimpleNamespace(
                    headers={"content-type": "application/json"}, status_code=200,
                    content=json.dumps({"choices": [{"message": {"content": "好的"}}]}).encode("utf-8"))
                tr.response(flow)
            finally:
                tr._emit = old_emit
            evs = {t: kw for t, kw in captured}
            mk = evs.get("MASK") or {}
            rs = evs.get("RESTORE") or {}
            self.assertIn("mask_ms", mk, "MASK 事件必须带脱敏耗时")
            self.assertGreaterEqual(mk.get("mask_ms", 0), 0)
            self.assertIn("upstream_ms", rs, "RESTORE 事件必须带上游耗时")
            self.assertGreaterEqual(rs.get("upstream_ms", 0), 0)
        self._with_no_reload(run)

    def test_ip_rule_matches_link_local(self):
        """链路本地 169.254.x.x 命中（127.0.0.1 不脱敏——本地地址）。"""
        sid = "ip-ll"
        tr._new_session(sid)
        masked = tr.mask("地址169.254.1.2 与 127.0.0.1", sid)
        self.assertNotIn("169.254.1.2", masked)
        self.assertIn("127.0.0.1", masked)

    def test_sensitive_label_and_word_disable(self):
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update({"重庆": "地域", "张三": "人名", "李四": "人名"})
        tr.SENSITIVE_DISABLED = {"地域"}
        tr.SENSITIVE_WORD_DISABLED = {"人名": {"张三"}}
        sid = "disable"
        tr._new_session(sid)
        masked = tr.mask("重庆的张三和李四", sid)
        self.assertIn("重庆", masked)
        self.assertIn("张三", masked)
        self.assertNotIn("李四", masked)
        self.assertIn("{{", masked)

    def test_builtin_rule_toggle_skips_email(self):
        tr.BUILTIN_RULES = dict(tr.DEFAULT_BUILTIN_RULES)
        tr.BUILTIN_RULES["EMAIL"] = False
        sid = "rule-off"
        tr._new_session(sid)
        masked = tr.mask("邮箱 test@example.com 电话13812345678", sid)
        self.assertIn("test@example.com", masked)
        self.assertNotIn("13812345678", masked)
        tr.BUILTIN_RULES["EMAIL"] = True

    def test_card_rule_requires_bin_prefix_and_luhn(self):
        sid = "card"
        tr._new_session(sid)
        # 00 开头的 16 位数字不是真卡，不应命中（即使 luhn 通过）
        masked = tr.mask("序列0000000000000026", sid)
        self.assertNotIn("{{", masked, "00 开头 16 位数字不应被误判为卡号")
        # 4 开头且 luhn 通过的真卡应命中
        masked2 = tr.mask("卡号4111111111111111", sid)  # Visa 测试卡号，luhn 通过
        self.assertIn("{{", masked2)
        self.assertNotIn("4111111111111111", masked2)
        # 4 开头但 luhn 不通过的不命中
        masked3 = tr.mask("卡号4111111111111112", sid)
        self.assertNotIn("{{", masked3)

    def test_builtin_rules_match_15digit_idcard(self):
        # IDCARD(15位) 默认关（审计规则专项 P1：旧证1999停发，20xx业务数字串误伤）
        # 测试显式开启验证规则本身仍有效
        old = tr.BUILTIN_RULES.get("IDCARD")
        tr.BUILTIN_RULES["IDCARD"] = True
        try:
            sid = "idcard15"
            tr._new_session(sid)
            # 15位身份证号
            masked = tr.mask("身份证110101900307451", sid)
            self.assertIn("{{", masked)
            self.assertNotIn("110101900307451", masked)
        finally:
            tr.BUILTIN_RULES["IDCARD"] = old
        # 18位身份证号，校验位正确（GB11643: 11010119900307451 -> 校验位4）才脱敏
        sid = "idcard18"
        tr._new_session(sid)
        masked = tr.mask("身份证110101199003074514", sid)
        self.assertIn("{{", masked)
        self.assertNotIn("110101199003074514", masked)

    def test_idcard18_checksum_invalid_is_skipped(self):
        sid = "idcard18bad"
        tr._new_session(sid)
        # 18位但校验位错误：视为普通数字串，不脱敏（避免误杀长数字）
        masked = tr.mask("身份证11010119900307451X", sid)
        self.assertNotIn("{{", masked)
        self.assertIn("11010119900307451X", masked)

    def test_iban_rule_requires_mod97(self):
        sid = "iban"
        tr._new_session(sid)
        # 合法 IBAN（GB82WEST12345698765432，mod-97 通过）
        masked = tr.mask("账号GB82WEST12345698765432", sid)
        self.assertIn("{{", masked)
        self.assertNotIn("GB82WEST12345698765432", masked)
        # 改一位数字导致 mod-97 失败：不脱敏
        masked2 = tr.mask("账号GB82WEST12345698765433", sid)
        self.assertNotIn("{{", masked2)

    def test_builtin_rules_mask_common_credentials(self):
        sid = "creds"
        tr._new_session(sid)
        text = (
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456 "
            "OPENAI=sk-proj-abcdefghijklmnopqrstuvwxyz123456 "
            "AXON=ah-abcdefghijklmnopqrstuvwxyz123456 "
            "password=ServerPass123!"
        )
        masked = tr.mask(text, sid)
        self.assertIn("Bearer {{", masked)
        self.assertIn("OPENAI={{", masked)
        self.assertIn("AXON={{", masked)
        self.assertIn("password={{", masked)
        # 占位符只带类型标签和随机 id，不得携带原值的任何片段
        for tok in re.findall(tr._PLACEHOLDER_RX, masked):
            self.assertNotIn("abcdef", tok)
            self.assertNotIn("ServerPass", tok)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", masked)
        self.assertNotIn("ServerPass123", masked)

    def test_key_prefix_rules_do_not_mask_short_words(self):
        sid = "short"
        tr._new_session(sid)
        masked = tr.mask("sk-demo ah-test sk-1234567890 ah-1234567890", sid)
        self.assertEqual(masked, "sk-demo ah-test sk-1234567890 ah-1234567890")

    def test_key_prefix_rules_are_configurable(self):
        tr.SECRET_PREFIXES = ["ak-"]
        sid = "prefix"
        tr._new_session(sid)
        masked = tr.mask("ak-abcdefghijklmnopqrstuvwxyz123456 sk-abcdefghijklmnopqrstuvwxyz123456", sid)
        self.assertIn("{{", masked)
        self.assertNotIn("ak-abcdefghijklmnopqrstuvwxyz123456", masked)
        self.assertIn("sk-abcdefghijklmnopqrstuvwxyz123456", masked)

    def test_target_matching_uses_domain_and_path_boundaries(self):
        self.assertTrue(tr.is_target("api.openai.com", "/v1/chat/completions"))
        self.assertTrue(tr.is_target("x.anthropic.com", "/v1/messages"))
        self.assertFalse(tr.is_target("api.openai.com.evil.test", "/v1/chat/completions"))
        self.assertFalse(tr.is_target("evil-anthropic.com", "/v1/messages"))
        self.assertFalse(tr.is_target("api.openai.com", "/x/v1/chat/completions-bak"))

    def test_diagnostic_unmatched_emits_metadata_only_for_skipped_request(self):
        captured = []
        old_diag = tr.DIAGNOSTIC_UNMATCHED
        old_emit = tr._emit
        old_reload = tr._maybe_reload
        try:
            tr.DIAGNOSTIC_UNMATCHED = True
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            tr._maybe_reload = lambda force=False: None
            flow = self._flow("codex.example.test", "/backend-api/conversation", {
                "messages": [{"role": "user", "content": "张三"}]
            })
            tr.request(flow)
        finally:
            tr.DIAGNOSTIC_UNMATCHED = old_diag
            tr._emit = old_emit
            tr._maybe_reload = old_reload
        self.assertEqual(captured[0][0], "SKIP")
        self.assertEqual(captured[0][1]["reason"], "host_not_configured")
        self.assertNotIn("body", captured[0][1])
        self.assertNotIn("张三", json.dumps(captured[0][1], ensure_ascii=False))

    def test_non_target_request_is_not_modified(self):
        def run():
            body = {"messages": [{"role": "user", "content": "客户张三 电话13812345678"}]}
            flow = self._flow("example.com", "/v1/chat/completions", body)
            before = flow.request.content
            tr.request(flow)
            self.assertEqual(flow.request.content, before)
            self.assertNotIn("session_id", flow.metadata)
        self._with_no_reload(run)

    def test_auth_headers_are_preserved_for_upstream_auth(self):
        def run():
            auth = "Bearer sk-proj-abcdefghijklmnopqrstuvwxyz123456"
            api_key = "ah-abcdefghijklmnopqrstuvwxyz123456"
            flow = self._flow(
                "api.openai.com",
                "/v1/chat/completions",
                {"messages": [{"role": "user", "content": "客户张三"}]},
                headers={"authorization": auth, "x-api-key": api_key},
            )
            tr.request(flow)
            self.assertEqual(flow.request.headers["authorization"], auth)
            self.assertEqual(flow.request.headers["x-api-key"], api_key)
            sent = json.loads(flow.request.content)
            self.assertNotIn("张三", sent["messages"][0]["content"])
        self._with_no_reload(run)

    def test_custom_words_prefer_longest_match(self):
        tr.CUSTOM_WORDS.update({"张三": "PERSON", "张三公司": "COMPANY"})
        sid = "words"
        tr._new_session(sid)
        masked = tr.mask("张三公司", sid)
        self.assertIn("{{", masked)
        self.assertNotIn("公司", masked)

    def test_last_hits_accumulates_across_mask_calls(self):
        """Bug A 回归：mask() 被 _mask_tree 对每个叶子各调一次，
        last_hits 必须累积而非覆盖，否则 count 只反映最后一个叶子。"""
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update({"张三": "PERSON", "李四": "PERSON"})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        sid = "accum"
        tr._new_session(sid)
        tr.mask("联系人张三", sid)           # 命中 张三
        tr.mask("联系李四", sid)             # 命中 李四（不同叶子）
        s = tr.sessions[sid]
        self.assertEqual(len(s["last_hits"]), 2, "两个叶子命中都应累积进 last_hits")
        self.assertEqual(len(s["new_orig"]), 2, "new_orig 应累积本次全部新增")
        self.assertIn("张三", s["last_hits"])
        self.assertIn("李四", s["last_hits"])
        # 第二次调用同词不重复计新增
        tr.mask("张三", sid)
        self.assertEqual(len(s["last_hits"]), 2, "重复命中不重复计数")
        self.assertEqual(len(s["new_orig"]), 2, "重复命中不算新增")

    def test_restore_event_has_restore_status_and_items(self):
        """Bug B/C 回归：RESTORE 事件必须带 restore_status 键和 items 明细，
        前端读 restore_status 才不是死代码；items 让详情弹窗有内容。"""
        def run():
            captured = {}
            old_emit = tr._emit
            try:
                tr._emit = lambda typ, **kw: captured.update({typ: kw})
                tr.CUSTOM_WORDS.clear()
                tr.CUSTOM_WORDS.update({"张三": "PERSON"})
                tr._CUSTOM_WORD_RX_CACHE.clear()
                flow = self._flow("api.openai.com", "/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "联系人张三"}]
                })
                tr.request(flow)
                # request() 内部会生成新 sid，从 flow.metadata 取
                sid = flow.metadata.get("session_id")
                self.assertTrue(sid, "request 应设置 session_id")
                s = tr.sessions.get(sid) or {}
                fwd = s.get("fwd", {})
                self.assertTrue(fwd, "请求脱敏后应有 fwd 映射")
                s["restored"] = 1
                s["restored_tokens"] = {list(fwd.values())[0]}
                tr._emit_restore_summary(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {}, ok=True)
            finally:
                tr._emit = old_emit
            ev = captured.get("RESTORE") or {}
            self.assertEqual(ev.get("restore_status"), "restored", "RESTORE 事件必须带 restore_status 键")
            self.assertEqual(ev.get("status"), "restored", "status 键保留兼容 SQLite")
            self.assertTrue(ev.get("items"), "RESTORE 事件必须带 items 明细")
            self.assertTrue(any(it.get("restored") for it in ev["items"]), "items 里应标注已还原项")
        self._with_no_reload(run)

    def test_mask_new_count_counts_only_new_hits(self):
        """Bug A 回归：new_count 统计本次新增（_remember 之前 fwd 里没有的）。"""
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update({"张三": "PERSON", "李四": "PERSON"})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        sid = "newcount"
        tr._new_session(sid)
        tr.mask("张三", sid)                     # 新增 张三
        s = tr.sessions[sid]
        new1 = len(s["last_hits"] & s["new_orig"])
        tr.mask("张三 李四", sid)                # 张三已存在，新增 李四
        s = tr.sessions[sid]
        new2 = len(s["last_hits"] & s["new_orig"])
        self.assertEqual(new1, 1)
        self.assertEqual(new2, 2, "交集口径：会话累计新增 张三+李四")

    def test_single_char_custom_word_requires_boundary(self):
        """单字词只在独立出现时命中，避免「密」打中「密码」。"""
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update({"密": "密级", "张三": "人名"})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        sid = "short-bound"
        tr._new_session(sid)
        masked = tr.mask("文件密级是公开，联系人张三", sid)
        self.assertIn("密级", masked)  # 「密」不该吃掉「密级」
        self.assertNotIn("张三", masked)
        # 独立单字仍命中
        sid2 = "short-alone"
        tr._new_session(sid2)
        masked2 = tr.mask("密 与 公开", sid2)
        self.assertNotIn("密 与", masked2)
        self.assertIn("{{", masked2)

    def test_mask_event_includes_scan_scope_and_roles(self):
        captured = []
        old_emit = tr._emit
        old_reload = tr._maybe_reload
        try:
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            tr._maybe_reload = lambda force=False: None
            body = {
                "model": "gpt-test",
                "messages": [
                    {"role": "system", "content": "系统里有邮箱 admin@example.com"},
                    {"role": "user", "content": "旧问"},
                    {"role": "assistant", "content": "旧答"},
                    {"role": "user", "content": "继续"},
                ],
            }
            flow = SimpleNamespace(
                request=SimpleNamespace(
                    pretty_host="api.openai.com",
                    path="/v1/chat/completions",
                    headers={"content-type": "application/json"},
                    content=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                ),
                metadata={},
            )
            tr.request(flow)
        finally:
            tr._emit = old_emit
            tr._maybe_reload = old_reload
        self.assertEqual(captured[0][0], "MASK")
        kw = captured[0][1]
        self.assertIn("继续", kw.get("dialog") or "")
        self.assertNotIn("admin@example.com", kw.get("dialog") or "")
        scope = kw.get("scan_scope") or {}
        self.assertEqual(scope.get("msg_count"), 4)
        self.assertTrue(scope.get("has_system"))
        self.assertEqual(scope.get("latest_user_len"), 2)
        # EMAIL 命中应归因到 system
        email_items = [it for it in (kw.get("items") or []) if it.get("label") == "EMAIL"]
        self.assertTrue(email_items)
        self.assertIn("system", email_items[0].get("roles") or [])

    def test_mask_event_does_not_include_original_value(self):
        captured = []
        old_emit = tr._emit
        old_reload = tr._maybe_reload
        try:
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            tr._maybe_reload = lambda force=False: None
            body = {"messages": [{"role": "user", "content": "电话13812345678"}]}
            flow = SimpleNamespace(
                request=SimpleNamespace(
                    pretty_host="api.openai.com",
                    path="/v1/chat/completions",
                    headers={"content-type": "application/json"},
                    content=json.dumps(body).encode("utf-8"),
                ),
                metadata={},
            )
            tr.request(flow)
        finally:
            tr._emit = old_emit
            tr._maybe_reload = old_reload
        self.assertEqual(captured[0][0], "MASK")
        item = captured[0][1]["items"][0]
        self.assertNotIn("orig", item)
        self.assertEqual(item["label"], "PHONE")
        self.assertEqual(item["length"], 11)
        self.assertIn("preview", item)
        self.assertNotIn("13812345678", item["preview"])

    def test_credential_preview_does_not_expose_usable_secret(self):
        """凭据预览：可识别（前缀+末4位），但拿不到可用的 key。

        原来断言 preview == "****"。那样确实安全，但用户看到告警却不知道是哪一把
        泄露了、没法去吊销——安全能力等于零。改成分档后，这里守住的是真正的red line：
        中段绝不出现、预览绝不等于原文。
        """
        sid = "cred-preview"
        tr._new_session(sid)
        masked = tr.mask("key是sk-1234567890abcdefghijklmnopqrst", sid)
        s = tr.sessions[sid]
        orig = next(k for k in s["fwd"] if k.startswith("sk-"))
        self.assertIn("{{", masked)
        pv = tr._preview(orig, s["labels"][orig])
        self.assertNotEqual(pv.replace("…", ""), orig, "预览不得等于原文")
        self.assertNotIn(orig[6:-6], pv, "中段绝不能出现在预览里")
        self.assertTrue(pv.startswith("sk-") and pv.endswith(orig[-4:]),
                        f"应保留可识别的前缀与末 4 位，实际 {pv!r}")

    def test_placeholders_are_random_not_derived_from_secret_value(self):
        """占位符后缀必须来自 CSPRNG，绝不能由原文推导出来。

        这条是安全性质：后缀一旦可由原文推出，上游就能反查/枚举实体。
        它同时也是 0.1.13 删掉「幻觉 IP 智能自愈」的依据——后缀与原文无关，
        拿后缀做算术推出来的 IP 只能是编的。
        原用例 mock 的是 secrets.token_hex，0.1.13 起后缀改用 secrets.choice
        逐字符生成（纯辅音，见 tr._TOKEN_ALPHABET），故改为 mock choice。
        """
        old_choice = tr.secrets.choice
        try:
            tr.secrets.choice = lambda seq: "k"
            sid = "random-token"
            tr._new_session(sid)
            masked = tr.mask("电话13812345678", sid)
        finally:
            tr.secrets.choice = old_choice
        self.assertIn("{{PHONE_kkkkkk}}", masked)
        self.assertNotIn("13812345678", masked)

        # 真随机：清空复用表后对同一原文两次脱敏，占位符必须不同。
        # 若后缀由原文推导（例如取 hash），这里会拿到同一个 token。
        toks = []
        for i in range(2):
            tr._RECENT_FWD.clear()
            tr._RECENT_REV.clear()
            sid2 = f"rand-{i}"
            tr._new_session(sid2)
            m = tr._PLACEHOLDER_RX.search(tr.mask("电话13812345678", sid2))
            toks.append(m.group(0))
        self.assertNotEqual(toks[0], toks[1], "同一原文两次脱敏不该得到相同占位符")
        # 后缀里不得出现原文的任何 3 位连续片段
        suffix = tr._PLACEHOLDER_PARTS_RX.match(toks[0]).group(2)
        for i in range(len("13812345678") - 2):
            self.assertNotIn("13812345678"[i:i + 3], suffix)

    def test_chat_completions_json_roundtrip_preserves_semantics(self):
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "客户张三的电话是13812345678"}]
            })
            tr.request(flow)
            sent = json.loads(flow.request.content)
            masked_prompt = sent["messages"][0]["content"]
            self.assertNotIn("张三", masked_prompt)
            self.assertNotIn("13812345678", masked_prompt)
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                content=json.dumps({"choices": [{"message": {"content": "收到：" + masked_prompt}}]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
            got = json.loads(flow.response.content)
            self.assertEqual(got["choices"][0]["message"]["content"], "收到：客户张三的电话是13812345678")
        self._with_no_reload(run)

    def test_restore_event_reports_counts_and_status(self):
        captured = []
        old_emit = tr._emit
        old_reload = tr._maybe_reload
        try:
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            tr._maybe_reload = lambda force=False: None
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "客户张三"}]
            })
            tr.request(flow)
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                status_code=200,
                content=json.dumps({"choices": [{"message": {"content": "收到：" + masked}}]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
        finally:
            tr._emit = old_emit
            tr._maybe_reload = old_reload
        restores = [kw for typ, kw in captured if typ == "RESTORE"]
        self.assertEqual(len(restores), 1)
        self.assertEqual(restores[0]["count"], 1)
        self.assertEqual(restores[0]["restored"], 1)
        self.assertEqual(restores[0]["status"], "restored")
        self.assertTrue(restores[0]["success"])

    def test_completions_prompt_json_roundtrip_preserves_semantics(self):
        def run():
            flow = self._flow("api.openai.com", "/v1/completions", {
                "prompt": "请总结李四的邮箱lisi@example.com"
            })
            tr.request(flow)
            masked_prompt = json.loads(flow.request.content)["prompt"]
            self.assertNotIn("李四", masked_prompt)
            self.assertNotIn("lisi@example.com", masked_prompt)
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                content=json.dumps({"choices": [{"text": "摘要：" + masked_prompt}]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
            got = json.loads(flow.response.content)
            self.assertEqual(got["choices"][0]["text"], "摘要：请总结李四的邮箱lisi@example.com")
        self._with_no_reload(run)

    def test_anthropic_messages_json_roundtrip_preserves_semantics(self):
        def run():
            flow = self._flow("anthropic.com", "/v1/messages", {
                "system": "你会保护password=ServerPass123!",
                "messages": [{"role": "user", "content": "账号root，token=abcdefghijklmnopqrstuvwxyz123456"}],
            })
            tr.request(flow)
            sent = json.loads(flow.request.content)
            self.assertNotIn("ServerPass123", sent["system"])
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", sent["messages"][0]["content"])
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                content=json.dumps({"content": [{"type": "text", "text": sent["system"] + "|" + sent["messages"][0]["content"]}]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
            got = json.loads(flow.response.content)["content"][0]["text"]
            self.assertIn("password=ServerPass123!", got)
            self.assertIn("token=abcdefghijklmnopqrstuvwxyz123456", got)
        self._with_no_reload(run)

    def test_responses_api_json_roundtrip_preserves_semantics(self):
        def run():
            flow = self._flow("api.openai.com", "/v1/responses", {
                "instructions": "不要泄露sk-proj-abcdefghijklmnopqrstuvwxyz123456",
                "input": [{"role": "user", "content": [{"type": "input_text", "text": "联系张三"}]}],
            })
            tr.request(flow)
            sent = json.loads(flow.request.content)
            masked = sent["instructions"] + "|" + sent["input"][0]["content"][0]["text"]
            self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwxyz123456", masked)
            self.assertNotIn("张三", masked)
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                content=json.dumps({"output_text": masked, "output": [{"content": [{"type": "output_text", "text": masked}]}]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
            got = json.loads(flow.response.content)
            self.assertIn("sk-proj-abcdefghijklmnopqrstuvwxyz123456", got["output_text"])
            self.assertIn("联系张三", got["output"][0]["content"][0]["text"])
        self._with_no_reload(run)

    def test_history_tool_call_arguments_are_masked(self):
        """多轮历史里 assistant 的 tool_calls 参数必须脱敏，否则上一轮真实值直接上云。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [
                    {"role": "user", "content": "查一下"},
                    {"role": "assistant", "tool_calls": [
                        {"id": "call_1", "type": "function", "function": {
                            "name": "lookup",
                            "arguments": json.dumps({"name": "张三", "phone": "13812345678"}, ensure_ascii=False),
                        }},
                    ]},
                    {"role": "tool", "tool_call_id": "call_1", "content": "张三的电话是13812345678"},
                ],
            })
            tr.request(flow)
            sent = json.dumps(json.loads(flow.request.content), ensure_ascii=False)
            self.assertNotIn("张三", sent)
            self.assertNotIn("13812345678", sent)
            # 协议字段不能被改写
            msgs = json.loads(flow.request.content)["messages"]
            self.assertEqual(msgs[1]["tool_calls"][0]["function"]["name"], "lookup")
            self.assertEqual(msgs[1]["tool_calls"][0]["id"], "call_1")
            self.assertEqual(msgs[2]["role"], "tool")
        self._with_no_reload(run)

    def test_anthropic_tool_use_input_is_masked_and_restored(self):
        """Anthropic tool_use.input 双向覆盖：脱敏上行、还原下行。"""
        def run():
            flow = self._flow("anthropic.com", "/v1/messages", {
                "messages": [{"role": "user", "content": "客户张三"}],
            })
            tr.request(flow)
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            token = re.search(tr._PLACEHOLDER_RX, masked).group(0)
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                status_code=200,
                content=json.dumps({"content": [
                    {"type": "tool_use", "id": "tu_1", "name": "search",
                     "input": {"query": token}},
                ]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
            got = json.loads(flow.response.content)
            self.assertEqual(got["content"][0]["input"]["query"], "张三")
            self.assertEqual(got["content"][0]["name"], "search")
        self._with_no_reload(run)

    def test_placeholder_reused_across_requests_and_orphan_is_restored(self):
        """同一原文跨请求复用占位符；历史里遗留的占位符仍能还原（自愈）。"""
        def run():
            f1 = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "客户张三"}]
            })
            tr.request(f1)
            tok1 = re.search(tr._PLACEHOLDER_RX, json.loads(f1.request.content)["messages"][0]["content"]).group(0)

            # 第二轮：历史里带着上一轮的占位符（客户端没还原干净的情况）
            f2 = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [
                    {"role": "assistant", "content": "已记录 " + tok1},
                    {"role": "user", "content": "张三的电话呢"},
                ]
            })
            tr.request(f2)
            tok2 = re.search(tr._PLACEHOLDER_RX, json.loads(f2.request.content)["messages"][1]["content"]).group(0)
            self.assertEqual(tok1, tok2, "同一原文应复用同一占位符")

            f2.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                status_code=200,
                content=json.dumps({"choices": [{"message": {"content": "关于" + tok1}}]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(f2)
            self.assertIn("关于张三", json.loads(f2.response.content)["choices"][0]["message"]["content"])
        self._with_no_reload(run)

    def test_invalid_json_body_is_blocked_when_fail_closed(self):
        """声明 JSON 却解析失败：无法确认不含原文，fail-closed 下必须拦。"""
        def run():
            old = tr.FAIL_CLOSED
            try:
                tr.FAIL_CLOSED = True
                flow = self._flow("api.openai.com", "/v1/chat/completions", {})
                flow.request.content = b'{"messages": [bad json'
                tr.request(flow)
                self.assertEqual(flow.response.status_code, 400)
                self.assertIn(b"shield_invalid_json", flow.response.content)
            finally:
                tr.FAIL_CLOSED = old
        self._with_no_reload(run)

    def test_sse_stream_callback_emits_incrementally(self):
        """流式回调必须边收边吐：第一个事件到达就要有输出，不能等整段收完。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "客户张三"}]
            })
            tr.request(flow)
            sid = flow.metadata["session_id"]
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            token = re.search(tr._PLACEHOLDER_RX, masked).group(0)
            flow.response = SimpleNamespace(
                headers={"content-type": "text/event-stream"},
                status_code=200,
                content=b"",
            )
            stream = tr._sse_stream_factory(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
            half = len(token) // 2
            first = stream(('data: %s\n\n' % json.dumps(
                {"choices": [{"delta": {"content": "你好" + token[:half]}}]}, ensure_ascii=False)).encode("utf-8"))
            # 第一个事件立刻返回（流式生效），半截占位符被扣住不外泄
            self.assertIn("你好", first.decode("utf-8"))
            self.assertNotIn(token[:half], first.decode("utf-8"))
            second = stream(('data: %s\n\n' % json.dumps(
                {"choices": [{"delta": {"content": token[half:] + "在"}}]}, ensure_ascii=False)).encode("utf-8"))
            self.assertIn("张三在", second.decode("utf-8"))
            tail = stream(b"data: [DONE]\n\n")
            self.assertIn("[DONE]", tail.decode("utf-8"))
            stream(b"")
        self._with_no_reload(run)

    def test_sse_stream_never_returns_empty_bytes_midstream(self):
        """中途块无完整事件时必须返回空列表，绝不能返回 b""。

        mitmproxy 的 ResponseData 分支不过滤空块：返回 b"" 会被按 chunked 语法写成
        b"0\\r\\n\\r\\n"，那正是**终止块**，客户端据此判定响应结束、停止读取并关连接
        （引擎侧只看到 CANCEL Client disconnected）。上游把一个 SSE 事件按 TCP 边界
        切成多段时必然触发——opencode.ai 实测每 2-3 个回调就出现一次，整条流在首字节
        后 0.3s 内即断。返回空列表则 mitmproxy 的 for 循环零次迭代，不写任何字节。
        末块（data=b""）不受此限：它走 ResponseEndOfMessage 分支，那里对 b"" 有过滤。
        """
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "客户张三"}]
            })
            tr.request(flow)
            sid = flow.metadata["session_id"]
            flow.response = SimpleNamespace(
                headers={"content-type": "text/event-stream"},
                status_code=200,
                content=b"",
            )
            stream = tr._sse_stream_factory(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
            event = ('data: %s\n\n' % json.dumps(
                {"choices": [{"delta": {"content": "你好"}}]}, ensure_ascii=False)).encode("utf-8")
            # 把单个事件切成三段：前两段都凑不出完整事件（缺 \n\n）
            a, b, c = event[:20], event[20:40], event[40:]
            for part in (a, b):
                out = stream(part)
                self.assertEqual(out, [], "半个事件必须返回空列表，返回 b'' 会写出 chunked 终止块")
                self.assertNotEqual(out, b"")
            done = stream(c)
            self.assertIsInstance(done, bytes)
            self.assertIn("你好", done.decode("utf-8"))
            stream(b"")
        self._with_no_reload(run)

    def test_sse_stream_restores_partial_placeholder_in_reasoning_field(self):
        """上游同时下发 reasoning_content 与 reasoning 两份增量，reasoning 字段
        的半截占位符也必须跨 chunk 还原（曾漏槽位，{{TESTNAME 残片原样透传）。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "客户张三"}]
            })
            tr.request(flow)
            sid = flow.metadata["session_id"]
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            token = re.search(tr._PLACEHOLDER_RX, masked).group(0)
            flow.response = SimpleNamespace(
                headers={"content-type": "text/event-stream"},
                status_code=200,
                content=b"",
            )
            stream = tr._sse_stream_factory(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
            half = len(token) // 2
            chunk1 = stream(('data: %s\n\n' % json.dumps(
                {"choices": [{"delta": {"content": "思考",
                                        "reasoning_content": "思考" + token[:half],
                                        "reasoning": "思考" + token[:half]}}]},
                ensure_ascii=False)).encode("utf-8")).decode("utf-8")
            chunk2 = stream(('data: %s\n\n' % json.dumps(
                {"choices": [{"delta": {"content": "完毕",
                                        "reasoning_content": token[half:] + "想好",
                                        "reasoning": token[half:] + "想好"}}]},
                ensure_ascii=False)).encode("utf-8")).decode("utf-8")
            # reasoning 与 reasoning_content 各自独立缓冲还原，无残片外泄
            self.assertNotIn("{{", chunk1, "半截占位符不得透传")
            self.assertNotIn(token[:half], chunk1)
            self.assertIn("张三", chunk2, "跨 chunk 半截应拼合还原")
            self.assertNotIn("{{", chunk2)
            stream(b"")
        self._with_no_reload(run)

    def test_reasoning_restore_survives_tcp_split_events(self):
        """reasoning 半截占位符 + 事件被 TCP 边界切开：两个缺陷必须同时不复发。

        Gemini 系列原生下发 reasoning_content 增量，且中转站常把单个 SSE 事件切成
        多段（实测 opencode.ai 每事件 3-4 段）。此前中途块返回 b"" 会被写成 chunked
        终止块直接断流，用户侧表现为「Gemini 经常断流」。这里同时施加两种压力：
        每个事件切两半投喂，且占位符跨事件切开。
        """
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "客户张三"}]
            })
            tr.request(flow)
            sid = flow.metadata["session_id"]
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            token = re.search(tr._PLACEHOLDER_RX, masked).group(0)
            flow.response = SimpleNamespace(
                headers={"content-type": "text/event-stream"},
                status_code=200,
                content=b"",
            )
            stream = tr._sse_stream_factory(
                flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
            half = len(token) // 2
            events = [
                ('data: {"choices":[{"delta":{"reasoning_content":"思考%s"}}]}\n\n' % token[:half]).encode(),
                ('data: {"choices":[{"delta":{"reasoning_content":"%s"}}]}\n\n' % token[half:]).encode(),
                ('data: {"choices":[{"delta":{"content":"客户%s已签约"}}]}\n\n' % token).encode(),
                b'data: [DONE]\n\n',
            ]
            acc, empties = "", 0
            for ev in events:
                for part in (ev[:18], ev[18:]):
                    out = stream(part)
                    if isinstance(out, list):
                        empties += 1          # 中途无完整事件：必须是空列表
                    else:
                        acc += out.decode("utf-8")
            tail = stream(b"")
            acc += tail.decode("utf-8") if isinstance(tail, bytes) else ""

            self.assertGreater(empties, 0, "切片投喂必然产生中途空返回，应为空列表")
            # reasoning 分散在多个事件里，需按事件抽取后拼接才是完整思考文本
            reason = "".join(
                (json.loads(line[6:]).get("choices") or [{}])[0].get("delta", {}).get("reasoning_content") or ""
                for line in acc.splitlines()
                if line.startswith("data: ") and line[6:].strip() != "[DONE]"
            )
            self.assertEqual(reason, "思考张三", "跨事件半截占位符必须拼合还原")
            self.assertIn("客户张三已签约", acc)
            self.assertNotIn("{{", acc, "占位符不得残留")
            self.assertIn("[DONE]", acc, "流必须完整收尾，不得被终止块截断")
        self._with_no_reload(run)

    def test_stream_request_declares_identity_encoding(self):
        """流式请求必须向上游声明 accept-encoding: identity。
        压缩后的 SSE 在 responseheaders 阶段是压缩字节、无法按事件切分，只能退回
        整包路径 —— 客户端就此失去流式（首字延迟=整段生成时长）。非流式请求不动。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "客户张三"}], "stream": True,
            }, headers={"accept-encoding": "gzip, br"})
            tr.request(flow)
            self.assertEqual(flow.request.headers["accept-encoding"], "identity")
            # 非流式：保留客户端原始压缩协商，省带宽
            flow2 = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "客户张三"}],
            }, headers={"accept-encoding": "gzip, br"})
            tr.request(flow2)
            self.assertEqual(flow2.request.headers["accept-encoding"], "gzip, br")
        self._with_no_reload(run)

    def test_stream_request_keeps_encoding_for_excluded_host(self):
        """黑名单上游本就走整包路径，没有剥压缩的理由，保持客户端原始协商。"""
        def run():
            old = set(tr.STREAM_EXCLUDE_HOSTS)
            try:
                tr.STREAM_EXCLUDE_HOSTS = {"api.openai.com"}
                flow = self._flow("api.openai.com", "/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "客户张三"}], "stream": True,
                }, headers={"accept-encoding": "gzip"})
                tr.request(flow)
                self.assertEqual(flow.request.headers["accept-encoding"], "gzip")
            finally:
                tr.STREAM_EXCLUDE_HOSTS = old
        self._with_no_reload(run)

    def test_compressed_sse_degrades_without_crash_and_leaves_trace(self):
        """上游无视 identity 仍返回压缩 SSE：退回整包路径且留痕，不得抛异常。
        曾在该分支引用尚未赋值的 host → UnboundLocalError（无单测覆盖压缩场景）。"""
        def run():
            old = tr.STREAM_RESPONSE
            try:
                tr.STREAM_RESPONSE = True
                flow = self._flow("api.openai.com", "/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "客户张三"}], "stream": True,
                })
                tr.request(flow)
                flow.response = SimpleNamespace(
                    headers={"content-type": "text/event-stream", "content-encoding": "gzip"},
                    status_code=200, content=b"", stream=None,
                )
                tr.responseheaders(flow)
                self.assertEqual(flow.metadata.get("shield_stream_degraded"), "gzip")
                # 未接管：stream 回调没装，交回 response() 整包路径
                self.assertIsNone(flow.response.stream)
                self.assertNotIn("shield_streamed", flow.metadata)
            finally:
                tr.STREAM_RESPONSE = old
        self._with_no_reload(run)

    def test_stream_usage_survives_text_retention_cap(self):
        """usage 只在流末 chunk 出现，而文本留存有 256KB 上限：长回答（实测单次
        1 万+ token）会把带 usage 的尾部整个丢掉，「今日 Token 用量」永久少计。
        usage 必须逐块单独采集，不受留存上限影响。"""
        def run():
            captured = {}
            old_emit = tr._emit
            old_cap = tr._SSE_KEEP_MAX
            old_reload = tr._maybe_reload
            try:
                tr._maybe_reload = lambda force=False: None
                tr._emit = lambda typ, **kw: captured.update({typ: kw})
                # 缩小留存上限，用少量数据确定性地越过它（真实上限 256KB）
                tr._SSE_KEEP_MAX = 200
                flow = self._flow("api.openai.com", "/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "客户张三"}], "stream": True,
                })
                tr.request(flow)
                sid = flow.metadata["session_id"]
                flow.response = SimpleNamespace(
                    headers={"content-type": "text/event-stream"}, status_code=200, content=b"",
                )
                stream = tr._sse_stream_factory(
                    flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
                # 正文远超留存上限：后续块不再累积进 state["text"]
                for _ in range(5):
                    stream(('data: %s\n\n' % json.dumps(
                        {"choices": [{"delta": {"content": "字" * 100}}]},
                        ensure_ascii=False)).encode("utf-8"))
                # usage 只在流末出现，此时留存已截断
                stream(('data: %s\n\n' % json.dumps(
                    {"choices": [{"delta": {}}],
                     "usage": {"prompt_tokens": 11, "completion_tokens": 22}})).encode("utf-8"))
                stream(b"data: [DONE]\n\n")
                stream(b"")
                ev = captured.get("RESTORE") or {}
                self.assertEqual(ev.get("usage"),
                                 {"prompt_tokens": 11, "completion_tokens": 22},
                                 "留存截断后仍须采到流末 usage")
            finally:
                tr._emit = old_emit
                tr._SSE_KEEP_MAX = old_cap
                tr._maybe_reload = old_reload
        run()

    def test_sse_stream_restores_partial_placeholder_in_responses_reasoning(self):
        """OpenAI Responses API 流：response.reasoning_text.delta 的半截占位符
        必须跨 chunk 还原（曾漏槽位，{{ 残片透传），正文与思考分段。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/responses", {
                "input": [{"role": "user", "content": [{"type": "input_text", "text": "客户张三"}]}],
                "stream": True,
            })
            tr.request(flow)
            sid = flow.metadata["session_id"]
            masked_text = flow.request.content.decode("utf-8", errors="replace")
            token = re.search(tr._PLACEHOLDER_RX, masked_text).group(0)
            flow.response = SimpleNamespace(
                headers={"content-type": "text/event-stream"},
                status_code=200,
                content=b"",
            )
            stream = tr._sse_stream_factory(flow, sid, "api.openai.com", "POST", "/v1/responses", {})
            half = len(token) // 2
            chunk1 = stream(('event: response.reasoning_text.delta\ndata: %s\n\n' % json.dumps(
                {"type": "response.reasoning_text.delta", "output_index": 0, "delta": "想想" + token[:half]},
                ensure_ascii=False)).encode("utf-8")).decode("utf-8")
            chunk2 = stream(('event: response.reasoning_text.delta\ndata: %s\n\n' % json.dumps(
                {"type": "response.reasoning_text.delta", "output_index": 0, "delta": token[half:] + "想完"},
                ensure_ascii=False)).encode("utf-8")).decode("utf-8")
            chunk3 = stream(('event: response.output_text.delta\ndata: %s\n\n' % json.dumps(
                {"type": "response.output_text.delta", "output_index": 0, "delta": "正文完毕"},
                ensure_ascii=False)).encode("utf-8")).decode("utf-8")
            self.assertNotIn("{{", chunk1, "reasoning 半截占位符不得透传")
            self.assertNotIn(token[:half], chunk1)
            self.assertIn("张三", chunk2, "同通道跨 chunk 半截应拼合还原")
            self.assertNotIn("{{", chunk2)
            self.assertIn("正文完毕", chunk3, "正文通道不受 reasoning 缓冲影响")
            stream(b"")
            # dialog 分段：reasoning_text 与 output_text 分开
            raw = 'event: response.reasoning_text.delta\ndata: {"type":"response.reasoning_text.delta","delta":"想"}\n\n' \
                  'event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"答"}\n\n'
            dlg = tr._extract_chat_dialog(raw.encode("utf-8"), 4000)
            self.assertEqual(dlg, "【助手思考】\n想\n\n【助手】\n答")
        self._with_no_reload(run)

    def test_sse_stream_finish_emits_restore_scan_and_cleans_session(self):
        """流式接管收尾：流末必须发 RESTORE、跑响应侧扫描（模型回复新 PII → SCAN_WARN）、
        清理会话——只逐块还原不收尾会丢日志且会话泄漏。"""
        def run():
            emitted = []
            old_emit = tr._emit
            old_scan = tr.RESPONSE_SCAN
            try:
                tr.RESPONSE_SCAN = True
                tr._emit = lambda typ, **kw: emitted.append((typ, kw))
                tr.CUSTOM_WORDS.clear()
                tr.CUSTOM_WORDS.update({"张三": "PERSON"})
                tr._CUSTOM_WORD_RX_CACHE.clear()
                flow = self._flow("api.openai.com", "/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "联系人张三"}]
                })
                tr.request(flow)
                sid = flow.metadata["session_id"]
                masked = json.loads(flow.request.content)["messages"][0]["content"]
                token = re.search(tr._PLACEHOLDER_RX, masked).group(0)
                flow.response = SimpleNamespace(
                    headers={"content-type": "text/event-stream"},
                    status_code=200,
                    content=b"",
                )
                stream = tr._sse_stream_factory(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
                event = 'data: %s\n\ndata: [DONE]\n\n' % json.dumps(
                    {"choices": [{"delta": {"content": "好的" + token + "新号码13900001111"}}]},
                    ensure_ascii=False,
                )
                stream(event.encode("utf-8"))
                stream(b"")
                restores = [kw for t, kw in emitted if t == "RESTORE"]
                self.assertEqual(len(restores), 1, "流末必须发 RESTORE")
                self.assertEqual(restores[0].get("restore_status"), "restored")
                warns = [kw for t, kw in emitted if t == "SCAN_WARN"]
                self.assertTrue(warns, "流式收尾必须执行响应侧扫描")
                self.assertNotIn(sid, tr.sessions, "流末必须清理会话")
            finally:
                tr._emit = old_emit
                tr.RESPONSE_SCAN = old_scan
        self._with_no_reload(run)

    def test_stream_mode_recorded_per_request(self):
        """请求方式字段：请求体 stream:true → 'stream'，缺省 → 'non_stream'；
        MASK 与 RESTORE 事件都带，前端日志列数据源。"""
        def run():
            captured = []
            old_emit = tr._emit
            try:
                tr._emit = lambda typ, **kw: captured.append((typ, kw))
                tr.CUSTOM_WORDS.clear()
                tr.CUSTOM_WORDS.update({"张三": "PERSON"})
                tr._CUSTOM_WORD_RX_CACHE.clear()
                flow = self._flow("api.openai.com", "/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "联系人张三"}], "stream": True,
                })
                tr.request(flow)
                sid = flow.metadata.get("session_id")
                flow.response = SimpleNamespace(
                    headers={"content-type": "application/json"}, status_code=200,
                    content=json.dumps({"choices": [{"message": {"content": "好的"}}]}).encode("utf-8"))
                tr.response(flow)
                flow2 = self._flow("api.openai.com", "/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "联系人张三"}],
                })
                tr.request(flow2)
                sid2 = flow2.metadata.get("session_id")
                flow2.response = SimpleNamespace(
                    headers={"content-type": "application/json"}, status_code=200,
                    content=json.dumps({"choices": [{"message": {"content": "好的"}}]}).encode("utf-8"))
                tr.response(flow2)
            finally:
                tr._emit = old_emit
            mk = {kw["sid"]: kw for t, kw in captured if t == "MASK"}
            rs = {kw["sid"]: kw for t, kw in captured if t == "RESTORE"}
            self.assertEqual(mk[sid]["stream_mode"], "stream")
            self.assertEqual(rs[sid]["stream_mode"], "stream")
            self.assertEqual(mk[sid2]["stream_mode"], "non_stream")
            self.assertEqual(rs[sid2]["stream_mode"], "non_stream")
        self._with_no_reload(run)

    def test_sse_stream_callback_accepts_crlf_event_separator(self):
        """真实上游常用 CRLF；首个事件必须立即下发，不能缓存到流结束。"""
        def run():
            sid = "sse-crlf"
            tr._new_session(sid)
            flow = SimpleNamespace(
                request=SimpleNamespace(method="POST", path="/v1/chat/completions", host="api.openai.com", headers={}),
                response=SimpleNamespace(headers={"content-type": "text/event-stream"}, status_code=200, content=b""),
                metadata={},
            )
            stream = tr._sse_stream_factory(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
            event = "data: " + json.dumps(
                {"choices": [{"delta": {"content": "第一段"}}]}, ensure_ascii=False
            ) + "\r\n\r\n"
            out = stream(event.encode("utf-8")).decode("utf-8")
            self.assertIn("第一段", out)
            self.assertIn("data:", out)
            stream(b"")
        self._with_no_reload(run)

    def test_log_dialog_keeps_all_user_messages(self):
        """SHIELD-DIALOG-001：命中常在 system/更早历史，dialog 保留全部用户
        消息（曾只取末条，用户看不到自己发送的内容）；system 指令仍跳过。"""
        body = {
            "messages": [
                {"role": "system", "content": "very long system prompt"},
                {"role": "user", "content": "旧问题"},
                {"role": "assistant", "content": "旧回答"},
                {"role": "user", "content": "最新问题"},
            ]
        }
        got = tr._extract_chat_dialog(json.dumps(body, ensure_ascii=False))
        self.assertIn("最新问题", got)
        self.assertIn("旧问题", got)
        self.assertNotIn("system prompt", got)
        self.assertLess(got.index("旧问题"), got.index("最新问题"), "用户消息应按发送顺序展示")

    def test_sse_stream_flushes_trailing_partial_token(self):
        """流在半截占位符处结束：残留文本必须补发，不能吞字。"""
        def run():
            sid = "sse-tail"
            tr._new_session(sid)
            tr.sessions[sid]["rev"] = {"{{NAME_abcdef}}": "张三"}
            flow = SimpleNamespace(
                request=SimpleNamespace(method="POST", path="/v1/chat/completions", host="api.openai.com", headers={}),
                response=SimpleNamespace(headers={"content-type": "text/event-stream"}, status_code=200, content=b""),
                metadata={},
            )
            stream = tr._sse_stream_factory(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
            out1 = stream(('data: %s\n\n' % json.dumps(
                {"id": "c1", "model": "gpt", "choices": [{"delta": {"content": "结尾{{NAME_ab"}}]}, ensure_ascii=False)).encode("utf-8"))
            self.assertNotIn("{{NAME_ab", out1.decode("utf-8"))
            out2 = stream(b"").decode("utf-8")
            # 补发事件带回残留文本，且保留原事件结构
            self.assertIn("{{NAME_ab", out2)
            evt = json.loads([l for l in out2.splitlines() if l.startswith("data: ")][0][6:])
            self.assertEqual(evt["id"], "c1")
            self.assertEqual(evt["choices"][0]["delta"]["content"], "{{NAME_ab")
        self._with_no_reload(run)

    def test_tool_call_arguments_roundtrip_preserves_json_shape(self):
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "查询张三"}]
            })
            tr.request(flow)
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            args = json.dumps({"name": masked, "phone": "{{PHONE_abcdef}}"}, ensure_ascii=False)
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                content=json.dumps({"choices": [{"message": {"tool_calls": [{"function": {"arguments": args}}]}}]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
            restored_args = json.loads(json.loads(flow.response.content)["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])
            self.assertEqual(restored_args["name"], "查询张三")
        self._with_no_reload(run)

    def test_responses_function_call_arguments_roundtrip_preserves_json_shape(self):
        def run():
            flow = self._flow("api.openai.com", "/v1/responses", {
                "input": [{"role": "user", "content": [{"type": "input_text", "text": "查询张三"}]}],
            })
            tr.request(flow)
            masked = json.loads(flow.request.content)["input"][0]["content"][0]["text"]
            args = json.dumps({"name": masked}, ensure_ascii=False)
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                content=json.dumps({
                    "output": [{"type": "function_call", "name": "lookup", "arguments": args}]
                }, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
            got = json.loads(flow.response.content)["output"][0]["arguments"]
            self.assertEqual(json.loads(got)["name"], "查询张三")
        self._with_no_reload(run)

    def test_responses_sse_completed_function_call_arguments_roundtrip(self):
        def run():
            flow = self._flow("api.openai.com", "/v1/responses", {
                "input": [{"role": "user", "content": [{"type": "input_text", "text": "查询张三"}]}],
            })
            tr.request(flow)
            masked = json.loads(flow.request.content)["input"][0]["content"][0]["text"]
            args = json.dumps({"name": masked}, ensure_ascii=False)
            event = {
                "type": "response.completed",
                "response": {"output": [{"type": "function_call", "name": "lookup", "arguments": args}]},
            }
            flow.response = SimpleNamespace(
                headers={"content-type": "text/event-stream"},
                content=("data: " + json.dumps(event, ensure_ascii=False) + "\ndata: [DONE]\n").encode("utf-8"),
            )
            tr.response(flow)
            line = next(line for line in flow.response.content.decode("utf-8").splitlines() if line.startswith("data: {"))
            got = json.loads(line[6:])["response"]["output"][0]["arguments"]
            self.assertEqual(json.loads(got)["name"], "查询张三")
        self._with_no_reload(run)

    def test_responses_sse_output_item_done_restores_nested_text(self):
        def run():
            flow = self._flow("api.openai.com", "/v1/responses", {
                "input": [{"role": "user", "content": [{"type": "input_text", "text": "我是张三又是李四"}]}],
            })
            tr.request(flow)
            masked = json.loads(flow.request.content)["input"][0]["content"][0]["text"]
            event = {
                "type": "response.output_item.done",
                "item": {"type": "message", "content": [{"type": "output_text", "text": "明白：" + masked}]},
            }
            flow.response = SimpleNamespace(
                headers={"content-type": "text/event-stream"},
                content=("data: " + json.dumps(event, ensure_ascii=False) + "\ndata: [DONE]\n").encode("utf-8"),
            )
            tr.response(flow)
            line = next(line for line in flow.response.content.decode("utf-8").splitlines() if line.startswith("data: {"))
            got = json.loads(line[6:])["item"]["content"][0]["text"]
            self.assertEqual(got, "明白：我是张三又是李四")
        self._with_no_reload(run)

    def test_responses_sse_content_part_done_restores_text(self):
        def run():
            flow = self._flow("api.openai.com", "/v1/responses", {
                "input": [{"role": "user", "content": [{"type": "input_text", "text": "我是张三"}]}],
            })
            tr.request(flow)
            masked = json.loads(flow.request.content)["input"][0]["content"][0]["text"]
            event = {"type": "response.content_part.done", "part": {"type": "output_text", "text": "收到：" + masked}}
            flow.response = SimpleNamespace(
                headers={"content-type": "text/event-stream"},
                content=("data: " + json.dumps(event, ensure_ascii=False) + "\ndata: [DONE]\n").encode("utf-8"),
            )
            tr.response(flow)
            line = next(line for line in flow.response.content.decode("utf-8").splitlines() if line.startswith("data: {"))
            got = json.loads(line[6:])["part"]["text"]
            self.assertEqual(got, "收到：我是张三")
        self._with_no_reload(run)

    def test_sse_split_token_roundtrip_preserves_semantics(self):
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "客户张三"}]
            })
            tr.request(flow)
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            a, b = masked[:4], masked[4:]
            chunks = [
                {"choices": [{"delta": {"content": "回复：" + a}}]},
                {"choices": [{"delta": {"content": b}}]},
            ]
            raw = "\n".join("data: " + json.dumps(c, ensure_ascii=False) for c in chunks) + "\ndata: [DONE]\n"
            flow.response = SimpleNamespace(
                headers={"content-type": "text/event-stream"},
                content=raw.encode("utf-8"),
            )
            tr.response(flow)
            lines = [line for line in flow.response.content.decode("utf-8").splitlines() if line.startswith("data: {")]
            text = "".join(json.loads(line[6:])["choices"][0]["delta"]["content"] for line in lines)
            self.assertEqual(text, "回复：客户张三")
        self._with_no_reload(run)

    def test_sse_token_split_across_three_chunks_multibyte_safe(self):
        """占位 token 被跨 3 个 SSE chunk 切开（含多字节字符），还原仍需正确。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "邮箱test@example.com"}]
            })
            tr.request(flow)
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            # 把整个回复（含占位 token）按字节切成 3 段，模拟真实流式分片
            full = "收到" + masked + "谢谢"
            b = full.encode("utf-8")
            # 切在多字节字符中间（b 是 bytes，任意切分点都可能切中多字节）
            cut1, cut2 = len(b) // 3, len(b) * 2 // 3
            # 用 surrogateescape-ish 还原成 str：逐段解码，末段可能不完整。
            # SSE 每行是完整 JSON，实际不会出现半字符；这里构造完整 JSON 行但 delta.content 跨行拼接。
            # 简化：直接按字符数切 3 段（保证每段是合法 str）
            s1, s2, s3 = full[:len(full)//3], full[len(full)//3:2*len(full)//3], full[2*len(full)//3:]
            chunks = [
                {"choices": [{"delta": {"content": s1}}]},
                {"choices": [{"delta": {"content": s2}}]},
                {"choices": [{"delta": {"content": s3}}]},
            ]
            raw = "\n".join("data: " + json.dumps(c, ensure_ascii=False) for c in chunks) + "\ndata: [DONE]\n"
            flow.response = SimpleNamespace(
                headers={"content-type": "text/event-stream"},
                content=raw.encode("utf-8"),
            )
            tr.response(flow)
            lines = [line for line in flow.response.content.decode("utf-8").splitlines() if line.startswith("data: {")]
            text = "".join(json.loads(line[6:])["choices"][0]["delta"]["content"] for line in lines)
            # 还原后应得到原文，占位 token 不应残留（masked 含“邮箱”前缀，还原后保留）
            self.assertEqual(text, "收到" + "邮箱test@example.com" + "谢谢")
            self.assertNotIn("{{", text)
        self._with_no_reload(run)

    def _reverse_flow(self, path, body, headers=None, listen_port=None):
        """构造 reverse 模式 flow：request 可写 host/scheme/port。
        listen_port 模拟多端口模式的入站端口（client_conn.sockname）。"""
        req_headers = {"content-type": "application/json"}
        if headers:
            req_headers.update(headers)
        req = SimpleNamespace(
            pretty_host="127.0.0.1",
            path=path,
            headers=req_headers,
            content=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            host="127.0.0.1",
            port=5802,
            scheme="http",
            method="POST",
        )
        # 模拟 mitmproxy client_conn.sockname = (host, port)
        client_conn = None
        if listen_port is not None:
            client_conn = SimpleNamespace(sockname=("127.0.0.1", listen_port))
        return SimpleNamespace(request=req, response=None, metadata={}, client_conn=client_conn)

    def test_reverse_routing_strips_base_path_and_rewrites_host(self):
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            flow = self._reverse_flow("/openai/v1/chat/completions", {
                "messages": [{"role": "user", "content": "你好"}]
            })
            tr.request(flow)
            # host/scheme 被改写为真实上游
            self.assertEqual(flow.request.host, "api.openai.com")
            self.assertEqual(flow.request.scheme, "https")
            # base_path 被剥掉
            self.assertEqual(flow.request.path, "/v1/chat/completions")
            self.assertEqual(flow.request.headers["Host"], "api.openai.com")
        self._with_no_reload(run)

    def test_reverse_routing_unknown_base_path_is_skipped(self):
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            skipped = {}
            old_skip = tr._emit_skip
            tr._emit_skip = lambda host, method, path, reason, content_type="", source=None, **kw: skipped.setdefault("reason", reason)
            try:
                flow = self._reverse_flow("/unknown/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "你好"}]
                })
                tr.request(flow)
            finally:
                tr._emit_skip = old_skip
            self.assertEqual(skipped.get("reason"), "no_reverse_route")
            self.assertEqual(flow.response.status_code, 404)
            self.assertEqual(flow.response.content, b'{"error":"no_reverse_route"}')
            # 未匹配时不改写 host
            self.assertEqual(flow.request.host, "127.0.0.1")
        self._with_no_reload(run)

    def test_restore_holds_then_flushes_partial_token_prefix(self):
        """跨 chunk 的半截占位符先缓冲、后还原；长到不可能是占位符时立即放行。"""
        sid = "lone-prefix"
        tr._new_session(sid)
        tr.sessions[sid]["rev"] = {"{{NAME_abcdef}}": "张三"}
        # 超长的 { 开头串不可能是占位符，不缓冲，原样输出
        out1 = tr.restore("普通文本{" + "a" * 65, sid)
        self.assertEqual(out1, "普通文本{" + "a" * 65)
        self.assertEqual(tr.sessions[sid]["pending"], {})
        out2 = tr.restore("继续输出", sid)
        self.assertEqual(out2, "继续输出")
        # 真被切开的占位符：前半截缓冲不外泄，后半截到达时还原
        out3 = tr.restore("你好{{NAME_ab", sid)
        self.assertEqual(out3, "你好")
        self.assertEqual(tr.sessions[sid]["pending"][""], "{{NAME_ab")
        out4 = tr.restore("cdef}}再见", sid)
        self.assertEqual(out4, "张三再见")

    def test_restore_channels_do_not_cross_contaminate(self):
        """不同 delta 字段各自缓冲：正文的半截占位符不能被拼进工具参数。"""
        sid = "channels"
        tr._new_session(sid)
        tr.sessions[sid]["rev"] = {"{{NAME_abcdef}}": "张三"}
        self.assertEqual(tr.restore("正文{{NAME_ab", sid, channel="c0.content"), "正文")
        # 另一个通道不受影响，原样输出
        self.assertEqual(tr.restore("工具参数", sid, channel="c0.tool0"), "工具参数")
        self.assertEqual(tr.restore("cdef}}", sid, channel="c0.content"), "张三")

    def test_restore_escapes_original_inside_json_string_field(self):
        """工具参数是 JSON 文本，原文含引号/换行时必须转义，否则客户端解析报错。"""
        sid = "escape"
        tr._new_session(sid)
        tr.sessions[sid]["rev"] = {"{{TERM_abcdef}}": '张"三\n李四'}
        args = tr.restore('{"name": "{{TERM_abcdef}}"}', sid, escape=True)
        self.assertEqual(json.loads(args)["name"], '张"三\n李四')

    def test_reverse_routing_mask_and_restore_roundtrip(self):
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            flow = self._reverse_flow("/anthropic/v1/messages", {
                "messages": [{"role": "user", "content": "联系人张三电话13812345678"}]
            })
            tr.request(flow)
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            self.assertNotIn("张三", masked)
            self.assertNotIn("13812345678", masked)
            self.assertIn("{{", masked)
            # 响应还原
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                content=json.dumps({"content": [{"type": "text", "text": "已记录" + masked}]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
            got = json.loads(flow.response.content)["content"][0]["text"]
            self.assertEqual(got, "已记录联系人张三电话13812345678")
        self._with_no_reload(run)

    def test_fail_closed_blocks_request_when_mask_errors(self):
        """脱敏管线异常：fail-closed（默认开）返回 503 BLOCK，原文绝不带上行。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            tr.FAIL_CLOSED = True
            emitted = []
            old_emit = tr._emit
            old_mask = tr.mask
            tr._emit = lambda typ, **kw: emitted.append((typ, kw))
            tr.mask = lambda text, sid: (_ for _ in ()).throw(RuntimeError("boom"))
            try:
                flow = self._reverse_flow("/openai/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "电话13812345678"}]
                })
                tr.request(flow)
            finally:
                tr._emit = old_emit
                tr.mask = old_mask
                tr.FAIL_CLOSED = True
            self.assertEqual(flow.response.status_code, 503)
            self.assertIn("shield_mask_failed", flow.response.content.decode("utf-8"))
            self.assertEqual(emitted[0][0], "BLOCK")
            self.assertEqual(emitted[0][1]["reason"], "mask_pipeline_failed")
            # 会话已清理，不留残留映射
            self.assertEqual(tr.sessions, {})
        self._with_no_reload(run)

    def test_fail_closed_off_emits_err_and_keeps_original_body(self):
        """fail-closed 关闭（仅排查用）：异常时记 ERR，body 保持原文（可能泄露，需警告）。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            tr.FAIL_CLOSED = False
            emitted = []
            old_emit = tr._emit
            old_mask = tr.mask
            tr._emit = lambda typ, **kw: emitted.append((typ, kw))
            tr.mask = lambda text, sid: (_ for _ in ()).throw(RuntimeError("boom"))
            try:
                flow = self._reverse_flow("/openai/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "电话13812345678"}]
                })
                tr.request(flow)
            finally:
                tr._emit = old_emit
                tr.mask = old_mask
                tr.FAIL_CLOSED = True
            self.assertIsNone(flow.response)
            self.assertEqual(emitted[0][0], "ERR")
            self.assertIn("mask:", emitted[0][1]["msg"])
        self._with_no_reload(run)

    def test_response_scan_warns_on_unmapped_pii(self):
        """响应侧扫描：模型回复含本会话未脱敏过的 PII -> SCAN_WARN，body 不被修改。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            tr.RESPONSE_SCAN = True
            emitted = []
            old_emit = tr._emit
            tr._emit = lambda typ, **kw: emitted.append((typ, kw))
            try:
                flow = self._reverse_flow("/openai/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "联系人张三电话13812345678"}]
                })
                tr.request(flow)
                masked = json.loads(flow.request.content)["messages"][0]["content"]
                # 回复还原本会话值 + 新出现一个未脱敏过的手机号（幻觉 PII）
                flow.response = SimpleNamespace(
                    headers={"content-type": "application/json"},
                    content=json.dumps({"choices": [{"message": {"content": "好的" + masked + "新号码13911112222"}}]}, ensure_ascii=False).encode("utf-8"),
                )
                tr.response(flow)
            finally:
                tr._emit = old_emit
                tr.RESPONSE_SCAN = False
            warns = [kw for typ, kw in emitted if typ == "SCAN_WARN"]
            self.assertEqual(len(warns), 1)
            self.assertEqual(warns[0]["count"], 1)
            # v1.5.0 起 items 带 original（明文，详情弹窗展示）+ preview（打码，列表行用）
            it = (warns[0].get("items") or [])[0]
            self.assertEqual(it.get("original"), "13911112222", "original 应含明文原文（用户要求详情可见）")
            self.assertNotIn("13911112222", it.get("preview") or "", "preview 必须打码")
            # 还原结果正确：占位符已还原
            got = json.loads(flow.response.content)["choices"][0]["message"]["content"]
            self.assertIn("联系人张三电话13812345678", got)
            self.assertIn("13911112222", got)
        self._with_no_reload(run)

    def test_filter_disabled_routes_but_does_not_mask(self):
        """过滤开关关闭：reverse 仍路由（改 host），但不脱敏，body 原样转发。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            tr.FILTER_ENABLED = False
            flow = self._reverse_flow("/anthropic/v1/messages", {
                "messages": [{"role": "user", "content": "联系人张三电话13812345678"}]
            }, listen_port=18703)
            tr.request(flow)
            # 路由仍生效：host 改写为真实上游
            self.assertEqual(flow.request.host, "api.anthropic.com")
            # 不脱敏：原文保留
            body = json.loads(flow.request.content)["messages"][0]["content"]
            self.assertEqual(body, "联系人张三电话13812345678")
            self.assertNotIn("{{", body)
            # 无 session_id（不脱敏就不建会话）
            self.assertIsNone(flow.metadata.get("session_id"))
            # 响应也不还原（session 不存在，response hook 直接 return）
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                content=json.dumps({"content": [{"type": "text", "text": "回复" + body}]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
            got = json.loads(flow.response.content)["content"][0]["text"]
            self.assertEqual(got, "回复联系人张三电话13812345678")
            tr.FILTER_ENABLED = True  # 恢复
        self._with_no_reload(run)

    def test_reverse_mask_and_restore_events_use_same_prefixed_path(self):
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            emitted = []
            old_emit = tr._emit
            tr._emit = lambda typ, **kw: emitted.append((typ, kw))
            try:
                flow = self._reverse_flow("/openai/v1/chat/completions", {
                    "messages": [{"role": "user", "content": "联系人张三"}]
                })
                tr.request(flow)
                masked = json.loads(flow.request.content)["messages"][0]["content"]
                flow.response = SimpleNamespace(
                    headers={"content-type": "application/json"},
                    content=json.dumps({"choices": [{"message": {"content": "收到" + masked}}]}, ensure_ascii=False).encode("utf-8"),
                )
                tr.response(flow)
            finally:
                tr._emit = old_emit
            paths = {typ: kw["path"] for typ, kw in emitted if typ in {"MASK", "RESTORE"}}
            self.assertEqual(paths["MASK"], "/openai/v1/chat/completions")
            self.assertEqual(paths["RESTORE"], "/openai/v1/chat/completions")
        self._with_no_reload(run)

    def test_reverse_routing_multiple_upstreams_route_independently(self):
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            # openai
            f1 = self._reverse_flow("/openai/v1/chat/completions", {"messages": [{"role": "user", "content": "a"}]})
            tr.request(f1)
            self.assertEqual(f1.request.host, "api.openai.com")
            self.assertEqual(f1.request.path, "/v1/chat/completions")
            # deepseek
            f2 = self._reverse_flow("/deepseek/v1/chat/completions", {"messages": [{"role": "user", "content": "b"}]})
            tr.request(f2)
            self.assertEqual(f2.request.host, "api.deepseek.com")
            self.assertEqual(f2.request.path, "/v1/chat/completions")
            # anthropic
            f3 = self._reverse_flow("/anthropic/v1/messages", {"messages": [{"role": "user", "content": "c"}]})
            tr.request(f3)
            self.assertEqual(f3.request.host, "api.anthropic.com")
            self.assertEqual(f3.request.path, "/v1/messages")
        self._with_no_reload(run)

    def test_reverse_routing_unlisted_path_with_llm_body_is_still_masked(self):
        """非白名单路径不再 404：请求体像 LLM 调用就照样脱敏转发。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            flow = self._reverse_flow("/openai/v1/beta/chat", {"messages": [{"role": "user", "content": "张三"}]})
            flow.request.method = "POST"
            tr.request(flow)
            self.assertIsNone(getattr(flow, "response", None), "不应再返回 404")
            self.assertEqual(flow.request.host, "api.openai.com")
            self.assertNotIn("张三", json.loads(flow.request.content)["messages"][0]["content"])
        self._with_no_reload(run)

    def test_reverse_routing_readonly_method_passes_through(self):
        """GET /v1/models 之类无请求体的调用直接转发（客户端初始化必打，拦了就像代理坏了）。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            skipped = {}
            old_skip = tr._emit_skip
            tr.DIAGNOSTIC_UNMATCHED = True
            tr._emit_skip = lambda host, method, path, reason, content_type="", source=None, **kw: skipped.setdefault("reason", reason)
            try:
                flow = self._reverse_flow("/openai/v1/models", {})
                flow.request.method = "GET"
                tr.request(flow)
            finally:
                tr._emit_skip = old_skip
                tr.DIAGNOSTIC_UNMATCHED = False
            self.assertIsNone(getattr(flow, "response", None), "只读方法不应被 404 拦下")
            self.assertEqual(flow.request.host, "api.openai.com")
            self.assertIn(skipped.get("reason"), ("passthrough_unlisted_path", "readonly_method"))
            self.assertIsNone(flow.metadata.get("session_id"))
        self._with_no_reload(run)

    def test_reverse_routing_unlisted_path_non_llm_body_passes_through(self):
        """非白名单路径 + 非 LLM 请求体：原样转发，不脱敏也不阻断。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            flow = self._reverse_flow("/openai/v1/files", {"purpose": "fine-tune"})
            flow.request.method = "POST"
            tr.request(flow)
            self.assertIsNone(getattr(flow, "response", None))
            self.assertEqual(json.loads(flow.request.content), {"purpose": "fine-tune"})
            self.assertIsNone(flow.metadata.get("session_id"))
        self._with_no_reload(run)

    def test_reverse_multiport_routes_by_listen_port_without_stripping(self):
        """多端口模式：按入站端口路由，不剥前缀，path 原样转发。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            # 打到 openai 的端口 18701，路径不带 /openai 前缀
            flow = self._reverse_flow("/v1/chat/completions", {
                "messages": [{"role": "user", "content": "你好"}]
            }, listen_port=18701)
            tr.request(flow)
            self.assertEqual(flow.request.host, "api.openai.com")
            self.assertEqual(flow.request.scheme, "https")
            # 多端口不剥前缀，path 保持 /v1/chat/completions
            self.assertEqual(flow.request.path, "/v1/chat/completions")
            self.assertEqual(flow.request.headers["Host"], "api.openai.com")
        self._with_no_reload(run)

    def test_reverse_multiport_different_ports_route_independently(self):
        """不同入站端口路由到不同上游，路径都不剥前缀。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            f1 = self._reverse_flow("/v1/chat/completions", {"messages": [{"role": "user", "content": "a"}]}, listen_port=18701)
            tr.request(f1)
            self.assertEqual(f1.request.host, "api.openai.com")
            self.assertEqual(f1.request.path, "/v1/chat/completions")
            f2 = self._reverse_flow("/v1/messages", {"messages": [{"role": "user", "content": "b"}]}, listen_port=18703)
            tr.request(f2)
            self.assertEqual(f2.request.host, "api.anthropic.com")
            self.assertEqual(f2.request.path, "/v1/messages")
        self._with_no_reload(run)

    def test_reverse_multiport_unknown_port_falls_back_to_prefix_mode(self):
        """未知端口回退到 base_path 前缀模式。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            # 端口 99999 不匹配任何 upstream，回退前缀模式，带 /openai 前缀
            flow = self._reverse_flow("/openai/v1/chat/completions", {
                "messages": [{"role": "user", "content": "x"}]
            }, listen_port=99999)
            tr.request(flow)
            self.assertEqual(flow.request.host, "api.openai.com")
            # 前缀模式剥掉 /openai
            self.assertEqual(flow.request.path, "/v1/chat/completions")
        self._with_no_reload(run)

    def test_rerank_request_and_response_masking(self):
        """测试 Rerank 请求体脱敏（同一请求内 query 和 documents 相同实体占位符一致）及响应直通还原。"""
        def run():
            tr.CAPTURE_MODE = "reverse"
            tr.UPSTREAMS = [
                {"name": "cohere", "base_path": "/cohere", "port": 18799, "target": "https://api.cohere.ai", "paths": ["/v1/rerank", "/rerank"]},
            ]
            tr.CUSTOM_WORDS = {"张三": "CUSTOMER"}
            tr._cw_rx_cache = None
            tr._cw_rx_key = None

            body = {
                "model": "rerank-v3.5",
                "query": "请问张三的联系电话是多少？",
                "documents": [
                    "张三的电话是13800138000，职位是技术负责人。",
                    "李四在市场部工作。",
                    {"text": "紧急情况下可联系张三或者拨打13800138000。"}
                ],
                "top_n": 2,
            }
            flow = self._reverse_flow("/cohere/v1/rerank", body, listen_port=18799)
            tr.request(flow)

            # 验证请求体已脱敏
            self.assertIsNone(getattr(flow, "response", None), "正常脱敏不阻断")
            masked_body = json.loads(flow.request.content)
            self.assertNotIn("张三", masked_body["query"])
            self.assertNotIn("13800138000", masked_body["documents"][0])
            self.assertNotIn("张三", masked_body["documents"][0])
            self.assertNotIn("13800138000", masked_body["documents"][2]["text"])

            # 验证 query 和 documents 中的“张三”使用了完全一致的占位符（Cross-Encoder 对齐）
            import re
            m_q = re.search(r"\{\{CUSTOMER_[a-z0-9]+\}\}", masked_body["query"])
            self.assertIsNotNone(m_q)
            customer_ph = m_q.group()
            self.assertIn(customer_ph, masked_body["documents"][0])
            self.assertIn(customer_ph, masked_body["documents"][2]["text"])

            # 模拟云端响应：带有 scores
            sid = flow.metadata["session_id"]
            flow.response = SimpleNamespace(
                status_code=200,
                headers={"content-type": "application/json"},
                content=json.dumps({
                    "id": "rerank-123",
                    "results": [
                        {"index": 0, "relevance_score": 0.98},
                        {"index": 2, "relevance_score": 0.85},
                    ],
                    "meta": {"tokens": {"input_tokens": 42}}
                }).encode("utf-8")
            )
            tr.response(flow)
            resp_data = json.loads(flow.response.content)
            self.assertEqual(resp_data["results"][0]["relevance_score"], 0.98)
        self._with_no_reload(run)


class PanelConfigTests(unittest.TestCase):
    def test_panel_event_store_uses_panel_data_root(self):
        self.assertEqual(panel.DB_PATH, panel.DATA_ROOT / "shield-events.sqlite3")

    def test_normalize_config_filters_unsafe_values(self):
        cfg = panel.normalize_config({
            "target_domains": ["https://API.OpenAI.com/v1", "api.openai.com.evil.test", "bad host"],
            "domains_disabled": ["api.openai.com"],
            "api_paths": ["/v1/chat/completions", "bad path"],
            "secret_prefixes": ["sk-", "ah-", "bad prefix", "bad*prefix", "ghp_", "x_"],
            "sensitive": {"PERSON": [" 张三 ", ""], "<bad>": ["x"]},
            "session_ttl": 1,
            "debug": True,
            "diagnostic_unmatched": True,
        })
        self.assertEqual(cfg["target_domains"], ["api.openai.com", "api.openai.com.evil.test"])
        self.assertEqual(cfg["domains_disabled"], ["api.openai.com"])
        self.assertEqual(cfg["api_paths"], ["/v1/chat/completions"])
        self.assertEqual(cfg["secret_prefixes"], ["sk-", "ah-", "ghp_", "x_"])
        self.assertEqual(cfg["sensitive"], {"PERSON": ["张三"]})
        self.assertEqual(cfg["session_ttl"], panel.MIN_TTL)
        self.assertEqual(cfg["capture_mode"], "reverse")
        self.assertTrue(cfg["debug"])
        self.assertTrue(cfg["diagnostic_unmatched"])

    def test_normalize_config_secret_prefixes_empty_allowed(self):
        cfg = panel.normalize_config({
            "secret_prefixes": [],
        })
        self.assertEqual(cfg["secret_prefixes"], [])

    def test_normalize_config_sensitive_group_and_builtin_rules(self):
        cfg = panel.normalize_config({
            "sensitive": {
                "地域": {"enabled": False, "words": ["重庆", "医院"], "disabled_words": ["医院"]},
                "人名": ["张三"],
            },
            "builtin_rules": {"EMAIL": False, "PHONE": True, "NOPE": False},
        })
        self.assertEqual(cfg["sensitive"]["地域"], ["重庆", "医院"])
        self.assertIn("地域", cfg["sensitive_disabled"])
        self.assertEqual(cfg["sensitive_word_disabled"].get("地域"), ["医院"])
        self.assertFalse(cfg["builtin_rules"]["EMAIL"])
        self.assertTrue(cfg["builtin_rules"]["PHONE"])
        self.assertNotIn("NOPE", cfg["builtin_rules"])

    def test_stream_exclude_hosts_default_and_normalize(self):
        """流式接管黑名单：默认空（全流式）；normalize 去重/小写/去尾点；空=全流式。"""
        d = panel.default_config()
        self.assertEqual(d["stream_exclude_hosts"], [])
        cfg = panel.normalize_config({"stream_exclude_hosts": ["Opencode.AI.", "example.com", "example.com", " ", "a,b"]})
        # normalize 只做归一化，不做迁移过滤：用户显式填的 host 一律保留
        self.assertEqual(cfg["stream_exclude_hosts"], ["opencode.ai", "example.com", "a", "b"])
        cfg2 = panel.normalize_config({"stream_exclude_hosts": ""})
        self.assertEqual(cfg2["stream_exclude_hosts"], [])
        # 引擎热重载：读配置覆盖默认黑名单
        old_root = tr._DATA_ROOT
        tmp = Path(tempfile.mkdtemp())
        try:
            tr._DATA_ROOT = tmp
            (tmp / "config.json").write_text(json.dumps(
                {"stream_exclude_hosts": ["example.com"]}, ensure_ascii=False), encoding="utf-8")
            s = tr._read_settings()
            self.assertEqual(s["stream_exclude_hosts"], {"example.com"})
        finally:
            tr._DATA_ROOT = old_root

    def test_stream_exclude_empty_list_is_respected_not_falling_back(self):
        """空黑名单=用户显式清空，必须原样生效；曾用 `or 默认` 让空列表回落 opencode.ai，
        导致清空后 opencode.ai 仍被永久排除，实测 2798 次流式请求 100% 退化整包。"""
        old_root = tr._DATA_ROOT
        old_excl = set(tr.STREAM_EXCLUDE_HOSTS)
        old_mtime = tr._cfg_mtime[0]
        tmp = Path(tempfile.mkdtemp())
        try:
            tr._DATA_ROOT = tmp
            # 键存在但为空 → _read_settings 返回空集（不是 None），引擎不排除任何 host
            (tmp / "config.json").write_text(json.dumps(
                {"stream_exclude_hosts": []}, ensure_ascii=False), encoding="utf-8")
            self.assertEqual(tr._read_settings()["stream_exclude_hosts"], set())
            tr._cfg_mtime[0] = None
            tr._maybe_reload(force=True)
            self.assertEqual(tr.STREAM_EXCLUDE_HOSTS, set())
            # 缺键 → 返回 None，上层回落内置默认（老配置兼容）
            (tmp / "config.json").write_text("{}", encoding="utf-8")
            self.assertIsNone(tr._read_settings()["stream_exclude_hosts"])
            tr._cfg_mtime[0] = None
            tr._maybe_reload(force=True)
            self.assertEqual(tr.STREAM_EXCLUDE_HOSTS, tr._DEFAULT_STREAM_EXCLUDE_HOSTS)
        finally:
            tr._DATA_ROOT = old_root
            tr.STREAM_EXCLUDE_HOSTS = old_excl
            tr._cfg_mtime[0] = old_mtime

    def test_secret_prefixes_empty_list_is_respected_not_falling_back(self):
        """用户显式清空 secret_prefixes 时必须保留空列表，不能用 or 默认回退。"""
        old_root = tr._DATA_ROOT
        old_prefixes = list(tr.SECRET_PREFIXES)
        tmp = Path(tempfile.mkdtemp())
        try:
            tr._DATA_ROOT = tmp
            (tmp / "config.json").write_text(json.dumps(
                {"secret_prefixes": []}, ensure_ascii=False), encoding="utf-8")
            s = tr._read_settings()
            self.assertEqual(s["prefixes"], [])
        finally:
            tr._DATA_ROOT = old_root
            tr.SECRET_PREFIXES = old_prefixes

    def test_legacy_opencode_exclude_is_cleared_once_then_respects_user(self):
        """历史误判清理：老配置里的 opencode.ai 被摘掉一次并落标记；

        v1.5.58 前会给老配置预置 opencode.ai，真因却是引擎自己返回 b"" 被写成
        chunked 终止块。修复后必须摘掉，否则升级用户永久走整包路径。清理只针对
        这一条历史值，用户自己加的 host 原样保留；标记落库后用户重新加回也不再动。
        """
        old_cfg = panel.CONFIG_PATH
        tmp = Path(tempfile.mkdtemp())
        try:
            panel.CONFIG_PATH = tmp / "config.json"
            panel.CONFIG_PATH.write_text(json.dumps(
                {"port": 18700,
                 "stream_exclude_hosts": ["opencode.ai", "keep.example.com"],
                 "meta": {"poison_scan_default_on": True}},
                ensure_ascii=False), encoding="utf-8")
            cfg = panel.load_config()
            self.assertEqual(cfg["stream_exclude_hosts"], ["keep.example.com"])
            self.assertTrue(cfg["meta"]["stream_exclude_opencode_cleared"])
            # 用户随后自己加回 opencode.ai → 已有标记，尊重用户，不再摘
            saved = json.loads(panel.CONFIG_PATH.read_text(encoding="utf-8"))
            saved["stream_exclude_hosts"] = ["opencode.ai"]
            panel.CONFIG_PATH.write_text(json.dumps(saved, ensure_ascii=False), encoding="utf-8")
            self.assertEqual(panel.load_config()["stream_exclude_hosts"], ["opencode.ai"])
        finally:
            panel.CONFIG_PATH = old_cfg

    def test_default_poison_scan_enabled_and_legacy_config_migrated_once(self):
        """投毒检测默认开启；老配置（无 meta 标记）强制迁移一次并落标记，之后尊重用户。"""
        old_cfg = panel.CONFIG_PATH
        old_load = panel.load_config
        try:
            d = panel.default_config()
            self.assertTrue(d["audit"]["enabled"], "audit.enabled 默认应开启")
            self.assertTrue(d["response_scan"], "response_scan 默认应开启")
            # 老配置：显式关闭 + 无 meta 标记 → load 时强制迁移
            tmp = Path(tempfile.mkdtemp()) / "config.json"
            panel.CONFIG_PATH = tmp
            panel.save_config({**d, "audit": {**d["audit"], "enabled": False}, "response_scan": False})
            panel.load_config()
            saved = json.loads(tmp.read_text(encoding="utf-8"))
            self.assertTrue(saved["audit"]["enabled"], "老配置应强制迁移为开启")
            self.assertTrue(saved["response_scan"], "老配置应强制迁移为开启")
            self.assertTrue(saved.get("meta", {}).get("poison_scan_default_on"))
            # 迁移标记已落：用户再手动关闭后 load 不得再次强制开启
            saved["audit"]["enabled"] = False
            tmp.write_text(json.dumps(saved, ensure_ascii=False), encoding="utf-8")
            panel.load_config()
            saved2 = json.loads(tmp.read_text(encoding="utf-8"))
            self.assertFalse(saved2["audit"]["enabled"], "有迁移标记后应尊重用户选择")
            # 新配置（无 audit 块）默认开启
            tmp.write_text(json.dumps({"target_domains": ["api.openai.com"]}, ensure_ascii=False), encoding="utf-8")
            cfg = panel.load_config()
            self.assertTrue(cfg["audit"]["enabled"])
            self.assertTrue(cfg["response_scan"])
        finally:
            panel.CONFIG_PATH = old_cfg

    def test_stream_response_auto_migrated_once(self):
        """stream_response 自动适配迁移：老配置显式关闭 → 强制迁移为 True 并落标记一次。"""
        old_cfg = panel.CONFIG_PATH
        try:
            d = panel.default_config()
            tmp = Path(tempfile.mkdtemp()) / "config.json"
            panel.CONFIG_PATH = tmp
            panel.save_config({**d, "stream_response": False})
            panel.load_config()
            saved = json.loads(tmp.read_text(encoding="utf-8"))
            self.assertTrue(saved["stream_response"], "老配置 stream_response=False 应强制迁移为 True")
            self.assertTrue(saved.get("meta", {}).get("stream_auto_migrated"))
            # 有标记后尊重后续变化（不再强制）
            saved["stream_response"] = False
            tmp.write_text(json.dumps(saved, ensure_ascii=False), encoding="utf-8")
            panel.load_config()
            saved2 = json.loads(tmp.read_text(encoding="utf-8"))
            self.assertFalse(saved2["stream_response"], "有迁移标记后应尊重配置")
        finally:
            panel.CONFIG_PATH = old_cfg

        self.assertEqual(panel.normalize_config({"capture_mode": "explicit"})["capture_mode"], "explicit")
        self.assertEqual(panel.normalize_config({"capture_mode": "reverse"})["capture_mode"], "reverse")
        self.assertEqual(panel.normalize_config({"capture_mode": "local"})["capture_mode"], "local")
        self.assertEqual(panel.normalize_config({"capture_mode": "bad"})["capture_mode"], "reverse")

    def test_normalize_config_chinese_upstreams_auto_dedup_base_path(self):
        """回归测试：多个纯中文名称客户端绝不可因内部 base_path 塌缩为 /up 而被当作重复条目忽略。"""
        warns = []
        raw = {
            "upstreams": [
                {"name": "通义千问", "target": "https://dashscope.aliyuncs.com"},
                {"name": "智谱清言", "target": "https://open.bigmodel.cn"},
                {"name": "百度文心", "target": "https://aip.baidubce.com"},
            ]
        }
        cfg = panel.normalize_config(raw, warns)
        self.assertEqual(len(cfg["upstreams"]), 3, f"3 个客户端必须全部保留，当前警告: {warns}")
        names = [u["name"] for u in cfg["upstreams"]]
        self.assertEqual(names, ["通义千问", "智谱清言", "百度文心"])
        base_paths = [u["base_path"] for u in cfg["upstreams"]]
        self.assertEqual(len(base_paths), len(set(base_paths)), "base_path 必须自动去重")
        self.assertEqual(warns, [])

    def test_load_config_persists_normalized_differences(self):
        """回归测试：load_config 发现磁盘数据与归一化结果不一致时，必须持久化写回磁盘。"""
        import tempfile
        old_cfg = panel.CONFIG_PATH
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = Path(f.name)
        try:
            panel.CONFIG_PATH = tmp_path
            # 写入一个包含重复 base_path 与冲突端口的原始配置
            raw_data = {
                "upstreams": [
                    {"name": "up1", "target": "https://api1.com", "base_path": "/same", "port": 18701},
                    {"name": "up2", "target": "https://api2.com", "base_path": "/same", "port": 18701},
                ]
            }
            tmp_path.write_text(json.dumps(raw_data), encoding="utf-8")
            loaded = panel.load_config()
            self.assertEqual(len(loaded["upstreams"]), 2)
            self.assertNotEqual(loaded["upstreams"][0]["base_path"], loaded["upstreams"][1]["base_path"])
            # 验证磁盘上的文件已经被持久化更新为归一化后的数据
            on_disk = json.loads(tmp_path.read_text(encoding="utf-8"))
            self.assertEqual(on_disk["upstreams"][0]["base_path"], loaded["upstreams"][0]["base_path"])
            self.assertEqual(on_disk["upstreams"][1]["base_path"], loaded["upstreams"][1]["base_path"])
            self.assertNotEqual(on_disk["upstreams"][0]["port"], on_disk["upstreams"][1]["port"])
        finally:
            panel.CONFIG_PATH = old_cfg
            tmp_path.unlink(missing_ok=True)

    def test_sidecar_read_settings_dedups_base_path(self):
        """回归测试：sidecar 读取包含冲突 base_path 的磁盘配置时必须自动消解冲突，且正确提取 extra_headers。"""
        import tempfile
        old_data_root = tr._DATA_ROOT
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            cfg_file = p / "config.json"
            cfg_file.write_text(json.dumps({
                "upstreams": [
                    {"name": "up1", "target": "https://api1.com", "base_path": "/same", "port": 18701, "extra_headers": {"x-api-key": "secret-1"}},
                    {"name": "up2", "target": "https://api2.com", "base_path": "/same", "port": 18701},
                ]
            }), encoding="utf-8")
            tr._DATA_ROOT = p
            try:
                s = tr._read_settings()
                self.assertIsNotNone(s)
                ups = s["upstreams"]
                self.assertEqual(len(ups), 2)
                self.assertNotEqual(ups[0]["base_path"], ups[1]["base_path"])
                self.assertNotEqual(ups[0]["port"], ups[1]["port"])
                self.assertEqual(ups[0].get("extra_headers"), {"x-api-key": "secret-1"}, "sidecar 必须正确解析并注入 extra_headers")
            finally:
                tr._DATA_ROOT = old_data_root

    def test_normalize_config_base_path_conflict_renames_and_warns(self):
        """用户显式填写的 base_path 撞车时：自动改名保命，且必须告警（单端口前缀模式契约变了）。"""
        warns = []
        raw = {
            "upstreams": [
                {"name": "openai", "target": "https://api.openai.com", "base_path": "/v1"},
                {"name": "relay", "target": "https://relay.example.com", "base_path": "/v1"},
            ]
        }
        cfg = panel.normalize_config(raw, warns)
        self.assertEqual(len(cfg["upstreams"]), 2, f"两条都必须保留，当前警告: {warns}")
        self.assertEqual(cfg["upstreams"][0]["base_path"], "/v1")
        self.assertEqual(cfg["upstreams"][1]["base_path"], "/v1_2", "冲突条目应自动追加序号而非被丢弃")
        self.assertEqual(len(warns), 1, f"改名必须告警一次，当前警告: {warns}")
        self.assertIn("/v1_2", warns[0])

    def test_normalize_config_generated_base_path_conflict_stays_silent(self):
        """自动生成的 /up_N 之间撞车（如名字本身就是 up_1）不应告警：用户没填过，无契约可破。"""
        warns = []
        raw = {
            "upstreams": [
                {"name": "通义千问", "target": "https://dashscope.aliyuncs.com"},
                {"name": "up_1", "target": "https://relay.example.com"},
            ]
        }
        cfg = panel.normalize_config(raw, warns)
        base_paths = [u["base_path"] for u in cfg["upstreams"]]
        self.assertEqual(len(base_paths), len(set(base_paths)), "base_path 必须唯一")
        self.assertEqual(warns, [], f"自动生成前缀的改名不该打扰用户，当前警告: {warns}")

    def test_parse_system_proxy_ignores_self_and_uses_http_segment(self):
        self.assertEqual(
            panel.parse_system_proxy("http=127.0.0.1:7890;https=127.0.0.1:7891"),
            "http://127.0.0.1:7890",
        )
        self.assertEqual(panel.parse_system_proxy("127.0.0.1:7890"), "http://127.0.0.1:7890")
        self.assertEqual(panel.parse_system_proxy(f"http=127.0.0.1:{panel.PROXY_PORT}"), "")

    def test_detect_upstream_only_uses_previous_system_proxy(self):
        old_upstream = panel.os.environ.get("LLM_SHIELD_UPSTREAM")
        old_port_listen = panel._port_listen

        try:
            panel.os.environ["LLM_SHIELD_UPSTREAM"] = "http://127.0.0.1:7890"
            open_ports = {7890}
            panel._port_listen = lambda port: port in open_ports

            self.assertEqual(panel.detect_upstream(), "http://127.0.0.1:7890")

            open_ports.clear()
            self.assertEqual(panel.detect_upstream(), "")

            open_ports.add(7892)
            self.assertEqual(panel.detect_upstream(), "")
        finally:
            panel._port_listen = old_port_listen
            if old_upstream is None:
                panel.os.environ.pop("LLM_SHIELD_UPSTREAM", None)
            else:
                panel.os.environ["LLM_SHIELD_UPSTREAM"] = old_upstream

    def test_api_token_is_only_accepted_in_header(self):
        with panel.app.test_client() as client:
            ok = client.get("/api/status", headers={"X-Shield-Token": panel.API_TOKEN})
            leaked = client.get(f"/api/status?token={panel.API_TOKEN}")
        self.assertNotEqual(ok.status_code, 403)
        self.assertEqual(leaked.status_code, 403)

    def test_api_stats_models_returns_cost_estimates(self):
        """模型排行路由：聚合数据 + 费用估算 + 未定价标记。"""
        from unittest.mock import patch
        fake_rows = [
            {"model": "claude-sonnet-4-5", "requests": 3, "prompt": 300, "completion": 150},
            {"model": "mimo-v2.5-pro", "requests": 1, "prompt": 100, "completion": 50},
        ]
        old_load = panel.load_config
        try:
            panel.load_config = lambda: {"model_prices": {"mimo-v2.5-pro": {"input": 1.0, "output": 2.0}}}
            with patch("event_store.stats_models", return_value=fake_rows):
                with panel.app.test_client() as client:
                    r = client.get("/api/stats/models?days=7", headers={"X-Shield-Token": panel.API_TOKEN})
            self.assertEqual(r.status_code, 200)
            d = r.get_json()
            self.assertTrue(d["ok"])
            by_model = {m["model"]: m for m in d["models"]}
            # claude-sonnet-4-5：内置价 3/15 → 300*3/1M + 150*15/1M
            self.assertAlmostEqual(by_model["claude-sonnet-4-5"]["cost_usd"], 0.0009 + 0.00225, places=6)
            self.assertTrue(by_model["claude-sonnet-4-5"]["priced"])
            # mimo-v2.5-pro：用户自配 1/2 → 100*1/1M + 50*2/1M
            self.assertAlmostEqual(by_model["mimo-v2.5-pro"]["cost_usd"], 0.0002, places=6)
            self.assertTrue(by_model["mimo-v2.5-pro"]["priced"])
            # 未配置价格的模型 → priced=False
            # 必须同时把在线价格目录也断掉：源码模式下 DATA_ROOT 就是仓库目录，
            # 只要跑过一次引擎，仓库里就会留下 model_prices_cache.json，
            # 里面有 mimo-v2.5-pro，这条断言会莫名其妙变红（实测踩过）。
            panel.load_config = lambda: {"model_prices": {}}
            old_cache = panel._load_price_cache_memory
            panel._load_price_cache_memory = lambda: None
            try:
                with patch("event_store.stats_models", return_value=fake_rows):
                    with panel.app.test_client() as client:
                        r2 = client.get("/api/stats/models", headers={"X-Shield-Token": panel.API_TOKEN})
            finally:
                panel._load_price_cache_memory = old_cache
            m2 = {m["model"]: m for m in r2.get_json()["models"]}
            self.assertFalse(m2["mimo-v2.5-pro"]["priced"])
            self.assertEqual(m2["mimo-v2.5-pro"]["cost_usd"], 0.0)
        finally:
            panel.load_config = old_load

    def test_start_proxy_does_not_disable_upstream_tls_verification(self):
        captured = {}
        old_port_listen = panel._port_listen
        old_load_config = panel.load_config
        old_enabled_domains = panel.enabled_domains
        old_is_admin = panel.is_admin
        old_detect_upstream = panel.detect_upstream
        old_popen = panel.subprocess.Popen
        old_sleep = panel.time.sleep
        old_thread = panel.threading.Thread
        old_emit = panel._emit_log

        class FakePopen:
            pid = 12345
            stdout = io.StringIO("")

            def poll(self):
                return None

        class FakeThread:
            def __init__(self, *args, **kwargs):
                pass

            def start(self):
                pass

        try:
            # 启动前端口空闲；start_proxy 起进程后轮询就绪需返回 True，
            # 否则会等满 _START_READY_TIMEOUT 判超时失败（FakePopen 不会真监听）。
            _listen_state = {"spawned": False}
            panel._port_listen = lambda port: _listen_state["spawned"]
            # 就绪判定用 netstat 快照覆盖**全部**待监听端口（不再是单端口
            # _port_listen）：曾只探 upstreams[0]，其余端口没绑上也报启动成功。
            _orig_lpp = panel._listening_port_pids
            self.addCleanup(lambda: setattr(panel, "_listening_port_pids", _orig_lpp))
            panel._listening_port_pids = lambda ports, fresh=False: (
                {int(x): {12345} for x in ports} if _listen_state["spawned"] else {})
            panel.load_config = lambda: {**panel.default_config(), "capture_mode": "local"}
            panel.enabled_domains = lambda cfg: ["api.openai.com"]
            panel.is_admin = lambda: True
            panel.detect_upstream = lambda: ""
            panel.time.sleep = lambda seconds: None
            panel.threading.Thread = FakeThread
            panel._emit_log = lambda line: None

            def fake_popen(args, **kwargs):
                captured["args"] = args
                _listen_state["spawned"] = True   # 进程起来后端口视为已监听
                return FakePopen()

            panel.subprocess.Popen = fake_popen
            ok, err = panel.start_proxy()
        finally:
            panel.proc["p"] = None
            panel.state["proxy_running"] = False
            panel.state["proxy_pid"] = None
            panel.PID_FILE.unlink(missing_ok=True)
            panel._port_listen = old_port_listen
            panel.load_config = old_load_config
            panel.enabled_domains = old_enabled_domains
            panel.is_admin = old_is_admin
            panel.detect_upstream = old_detect_upstream
            panel.subprocess.Popen = old_popen
            panel.time.sleep = old_sleep
            panel.threading.Thread = old_thread
            panel._emit_log = old_emit
        self.assertTrue(ok, err)
        self.assertNotIn("--ssl-insecure", captured["args"])
        self.assertIn("connection_strategy=lazy", captured["args"])
        # local 模式不使用 --allow-hosts，避免阻断非目标域名流量
        self.assertNotIn("--allow-hosts", captured["args"])

    def test_start_proxy_uses_local_capture_by_default(self):
        captured = {}
        old_port_listen = panel._port_listen
        old_load_config = panel.load_config
        old_enabled_domains = panel.enabled_domains
        old_is_admin = panel.is_admin
        old_popen = panel.subprocess.Popen
        old_sleep = panel.time.sleep
        old_thread = panel.threading.Thread
        old_emit = panel._emit_log

        class FakePopen:
            pid = 12345
            stdout = io.StringIO("")

            def poll(self):
                return None

        class FakeThread:
            def __init__(self, *args, **kwargs):
                pass

            def start(self):
                pass

        try:
            # 启动前端口空闲；start_proxy 起进程后轮询就绪需返回 True，
            # 否则会等满 _START_READY_TIMEOUT 判超时失败（FakePopen 不会真监听）。
            _listen_state = {"spawned": False}
            panel._port_listen = lambda port: _listen_state["spawned"]
            # 就绪判定用 netstat 快照覆盖**全部**待监听端口（不再是单端口
            # _port_listen）：曾只探 upstreams[0]，其余端口没绑上也报启动成功。
            _orig_lpp = panel._listening_port_pids
            self.addCleanup(lambda: setattr(panel, "_listening_port_pids", _orig_lpp))
            panel._listening_port_pids = lambda ports, fresh=False: (
                {int(x): {12345} for x in ports} if _listen_state["spawned"] else {})
            panel.load_config = lambda: {**panel.default_config(), "capture_mode": "local"}
            panel.enabled_domains = lambda cfg: ["api.openai.com"]
            panel.is_admin = lambda: True
            panel.time.sleep = lambda seconds: None
            panel.threading.Thread = FakeThread
            panel._emit_log = lambda line: None

            def fake_popen(args, **kwargs):
                captured["args"] = args
                _listen_state["spawned"] = True   # 进程起来后端口视为已监听
                return FakePopen()

            panel.subprocess.Popen = fake_popen
            ok, err = panel.start_proxy()
        finally:
            panel.proc["p"] = None
            panel.state["proxy_running"] = False
            panel.state["proxy_pid"] = None
            panel.PID_FILE.unlink(missing_ok=True)
            panel._port_listen = old_port_listen
            panel.load_config = old_load_config
            panel.enabled_domains = old_enabled_domains
            panel.is_admin = old_is_admin
            panel.subprocess.Popen = old_popen
            panel.time.sleep = old_sleep
            panel.threading.Thread = old_thread
            panel._emit_log = old_emit
        self.assertTrue(ok, err)
        self.assertIn("local", captured["args"])
        self.assertNotIn("-p", captured["args"])
        self.assertIn("connection_strategy=lazy", captured["args"])
        # local 模式不使用 --allow-hosts，避免阻断非目标域名流量
        self.assertNotIn("--allow-hosts", captured["args"])

    def test_local_capture_requires_admin(self):
        old_is_admin = panel.is_admin
        old_load_config = panel.load_config
        old_enabled_domains = panel.enabled_domains
        try:
            panel.is_admin = lambda: False
            panel.load_config = lambda: {**panel.default_config(), "capture_mode": "local"}
            panel.enabled_domains = lambda cfg: ["api.openai.com"]
            ok, err = panel.start_proxy()
        finally:
            panel.is_admin = old_is_admin
            panel.load_config = old_load_config
            panel.enabled_domains = old_enabled_domains
        self.assertFalse(ok)
        self.assertIn("管理员", err)

    def test_stop_proxy_preserves_configured_capture_mode(self):
        # 危险用例：stop_proxy 尾部会真实扫描 187xx 端口并 taskkill 占用者。
        # 单测运行时若用户代理正在运行，会真实杀掉它（实测发生：跑单测把
        # 正在服务的 mitmdump 和面板全杀了）。端口扫描/清残留/兜底必须全 mock。
        old_load_config = panel.load_config
        old_emit = panel._emit_log
        old_scan = panel._listening_port_pids
        old_free = panel._free_upstream_ports
        old_fallback = panel._start_fallback
        old_pidfile = panel._read_pid_file
        try:
            panel.load_config = lambda: {**panel.default_config(), "capture_mode": "explicit"}
            panel._emit_log = lambda line: None
            panel._listening_port_pids = lambda ports, fresh=False: {}
            panel._free_upstream_ports = lambda: []
            panel._start_fallback = lambda reason="": 0
            panel._read_pid_file = lambda: None
            panel.state["capture_mode"] = "local"
            ok, err = panel.stop_proxy()
        finally:
            panel.load_config = old_load_config
            panel._emit_log = old_emit
            panel._listening_port_pids = old_scan
            panel._free_upstream_ports = old_free
            panel._start_fallback = old_fallback
            panel._read_pid_file = old_pidfile
        self.assertTrue(ok, err)
        self.assertEqual(panel.state["capture_mode"], "explicit")

    def test_watchdog_skips_upstream_detection_in_local_mode(self):
        old_sleep = panel.time.sleep
        old_detect = panel.detect_upstream
        old_emit = panel._emit_log
        calls = {"detect": 0, "sleep": 0}

        class FakeProc:
            def poll(self):
                return None

        def fake_sleep(seconds):
            calls["sleep"] += 1
            if calls["sleep"] > 1:
                panel.state["stop_requested"] = True

        def fake_detect():
            calls["detect"] += 1
            return ""

        try:
            panel.proc["p"] = FakeProc()
            panel.state["proxy_running"] = True
            panel.state["stop_requested"] = False
            panel.state["capture_mode"] = "local"
            panel.time.sleep = fake_sleep
            panel.detect_upstream = fake_detect
            panel._emit_log = lambda line: None
            panel._dump_crash_context = lambda: None
            panel._watchdog()
        finally:
            panel.proc["p"] = None
            panel.state["proxy_running"] = False
            panel.state["stop_requested"] = False
            panel.time.sleep = old_sleep
            panel.detect_upstream = old_detect
            panel._emit_log = old_emit
        self.assertEqual(calls["detect"], 0)

    def test_passthrough_forwards_without_masking(self):
        """透传层：不启动 mitmdump 时端口仍转发（不脱敏直连）。"""
        import http.server
        import http.client
        old_cfg = panel.CONFIG_PATH
        old_emit = panel._emit_log
        upstream_captured = {}

        class FakeUp(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                ln = int(self.headers.get("content-length") or 0)
                upstream_captured["body"] = self.rfile.read(ln).decode("utf-8", errors="replace")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                resp_payload = json.dumps({"usage": {"prompt_tokens": 12, "completion_tokens": 34}}).encode()
                self.send_header("Content-Length", str(len(resp_payload)))
                self.end_headers()
                self.wfile.write(resp_payload)

        up_srv = http.server.HTTPServer(("127.0.0.1", 18990), FakeUp)
        threading.Thread(target=up_srv.serve_forever, daemon=True).start()
        try:
            tmp = Path(tempfile.mkdtemp()) / "config.json"
            # 深拷贝：default_config() 的 upstreams 是浅拷贝，直接改 u['target']
            # 会污染共享的 shield_defaults.DEFAULT_UPSTREAMS（tr/panel 同一对象）
            cfg = json.loads(json.dumps(panel.default_config()))
            for u in cfg["upstreams"]:
                u["name"] = "test-client"
                u["target"] = "http://127.0.0.1:18990"
                u["port"] = 18989
            tmp.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
            panel.CONFIG_PATH = tmp
            panel._emit_log = lambda line: None
            recorded_events = []
            old_enqueue = panel.enqueue_event
            panel.enqueue_event = lambda ev: recorded_events.append(ev) or old_enqueue(ev)
            panel._stop_passthrough()
            n = panel._start_passthrough()
            self.assertGreaterEqual(n, 1)
            time.sleep(0.3)
            body = json.dumps({"model": "gpt-4o-mini", "stream": True, "messages": [{"role": "user", "content": "电话13812345678"}]}).encode()
            conn = http.client.HTTPConnection("127.0.0.1", 18989, timeout=5)
            conn.request("POST", "/v1/chat/completions", body=body,
                         headers={"content-type": "application/json", "user-agent": "Tester/1.0"})
            r = conn.getresponse()
            r.read()
            conn.close()
            self.assertEqual(r.status, 200)
            # 透传不脱敏：原文应原样到达上游
            self.assertIn("13812345678", upstream_captured.get("body", ""))
            # 透传日志记录：upstream 名称与 model 字段必须与普通代理对齐
            self.assertTrue(len(recorded_events) >= 1)
            pt_ev = recorded_events[-1]
            self.assertEqual(pt_ev.get("upstream"), "test-client")
            self.assertEqual(pt_ev.get("model"), "gpt-4o-mini")
            self.assertEqual(pt_ev.get("http_status"), 200)
            self.assertEqual(pt_ev.get("usage"), {"prompt_tokens": 12, "completion_tokens": 34})
        finally:
            panel.enqueue_event = old_enqueue
            panel._stop_passthrough()
            panel.CONFIG_PATH = old_cfg
            panel._emit_log = old_emit
            up_srv.shutdown()
            up_srv.server_close()  # 关闭监听 socket，消除 ResourceWarning

    def test_watchdog_keeps_looping_when_proxy_dies_without_stop_request(self):
        """watchdog 循环条件不依赖 proxy_running（api_status 轮询会写它）：
        进程崩溃但没点停止时，必须继续循环而不是退出。"""
        old_sleep = panel.time.sleep
        old_emit = panel._emit_log
        old_dump = panel._dump_crash_context
        old_start = panel._start_fallback
        old_sp = panel.start_proxy
        old_wait = panel._sleep_interruptible
        old_free = panel._free_upstream_ports
        calls = {"start": 0, "dump": 0, "sleep": 0}

        class DeadProc:
            def poll(self):
                return 1  # 进程已退出

        def fake_sleep(seconds):
            calls["sleep"] += 1
            # 只应出现 5s 轮询周期；崩溃退避改走 _sleep_interruptible（已单独 mock）
            if seconds != 5:
                raise RuntimeError(f"watchdog 出现异常 sleep({seconds})")

        def fake_start_fallback(reason=""):
            calls["dump"] += 1
            return 0

        def fake_start_proxy():
            calls["start"] += 1
            return True, None

        try:
            panel.proc["p"] = DeadProc()
            panel.state["proxy_running"] = True
            panel.state["stop_requested"] = False
            panel.state["generation"] = 99
            panel.state["capture_mode"] = "local"
            panel.time.sleep = fake_sleep
            panel._emit_log = lambda line: None
            panel._dump_crash_context = lambda: None
            panel._start_fallback = fake_start_fallback
            panel.start_proxy = fake_start_proxy
            # 崩溃分支清理残留——必须 mock，否则真实 netstat+taskkill 会杀掉
            # 正在运行的 LLM Shield 代理（实测跑单测把用户代理杀了）
            panel._free_upstream_ports = lambda: []
            # 退避等待不真睡；返回 False = 期间没有停止请求，应继续重启
            panel._sleep_interruptible = lambda seconds, generation: False
            panel._watchdog(generation=99)
        finally:
            panel.proc["p"] = None
            panel.state["proxy_running"] = False
            panel.state["stop_requested"] = False
            panel.time.sleep = old_sleep
            panel._emit_log = old_emit
            panel._dump_crash_context = old_dump
            panel._start_fallback = old_start
            panel.start_proxy = old_sp
            panel._sleep_interruptible = old_wait
            panel._free_upstream_ports = old_free
        self.assertEqual(calls["start"], 1)

    def test_client_env_roundtrip_restores_previous_values(self):
        old_env = panel.os.environ.get("LLM_SHIELD_AUTO_ENV")
        old_upstream = panel.os.environ.get("LLM_SHIELD_UPSTREAM")
        old_path = panel.ENV_BACKUP_PATH
        old_read = panel._read_user_env
        old_write = panel._write_user_env
        old_read_proxy = panel._read_system_proxy_value
        old_write_proxy = panel._write_system_proxy_value
        old_broadcast = panel._broadcast_env_change
        old_broadcast_proxy = panel._broadcast_proxy_change
        store = {
            "HTTP_PROXY": "http://old-proxy:8888",
            "NODE_EXTRA_CA_CERTS": "C:\\old-ca.cer",
        }
        proxy_store = {
            "ProxyEnable": (1, 4),
            "ProxyServer": ("http=127.0.0.1:7890;https=127.0.0.1:7890", 1),
        }
        try:
            panel.os.environ["LLM_SHIELD_AUTO_ENV"] = "1"
            panel.ENV_BACKUP_PATH = ROOT / ".test-env-backup.json"
            panel.ENV_BACKUP_PATH.unlink(missing_ok=True)

            panel._read_user_env = lambda name: (name in store, store.get(name, ""))
            panel._read_system_proxy_value = lambda name: (
                name in proxy_store,
                proxy_store.get(name, ("", 0))[0],
                proxy_store.get(name, ("", 0))[1],
            )

            def write_user_env(name, value):
                if value is None:
                    store.pop(name, None)
                else:
                    store[name] = value

            def write_system_proxy(name, value, value_type=None):
                if value is None:
                    proxy_store.pop(name, None)
                else:
                    proxy_store[name] = (value, value_type)

            panel._write_user_env = write_user_env
            panel._write_system_proxy_value = write_system_proxy
            panel._broadcast_env_change = lambda: None
            panel._broadcast_proxy_change = lambda: None

            panel.apply_client_env()
            self.assertEqual(store["HTTP_PROXY"], panel.CLIENT_ENV["HTTP_PROXY"])
            self.assertEqual(store["HTTPS_PROXY"], panel.CLIENT_ENV["HTTPS_PROXY"])
            self.assertEqual(store["NODE_EXTRA_CA_CERTS"], panel.CLIENT_ENV["NODE_EXTRA_CA_CERTS"])
            self.assertEqual(proxy_store["ProxyEnable"][0], 1)
            self.assertIn(f"127.0.0.1:{panel.PROXY_PORT}", proxy_store["ProxyServer"][0])
            self.assertEqual(panel.os.environ["LLM_SHIELD_UPSTREAM"], "http://127.0.0.1:7890")

            panel.restore_client_env()
            self.assertEqual(store["HTTP_PROXY"], "http://old-proxy:8888")
            self.assertEqual(store["NODE_EXTRA_CA_CERTS"], "C:\\old-ca.cer")
            self.assertNotIn("HTTPS_PROXY", store)
            self.assertEqual(proxy_store["ProxyEnable"], (1, 4))
            self.assertEqual(proxy_store["ProxyServer"], ("http=127.0.0.1:7890;https=127.0.0.1:7890", 1))
            self.assertNotIn("ProxyOverride", proxy_store)
            self.assertFalse(panel.ENV_BACKUP_PATH.exists())
        finally:
            panel.ENV_BACKUP_PATH.unlink(missing_ok=True)
            panel.ENV_BACKUP_PATH = old_path
            panel._read_user_env = old_read
            panel._write_user_env = old_write
            panel._read_system_proxy_value = old_read_proxy
            panel._write_system_proxy_value = old_write_proxy
            panel._broadcast_env_change = old_broadcast
            panel._broadcast_proxy_change = old_broadcast_proxy
            if old_env is None:
                panel.os.environ.pop("LLM_SHIELD_AUTO_ENV", None)
            else:
                panel.os.environ["LLM_SHIELD_AUTO_ENV"] = old_env
            if old_upstream is None:
                panel.os.environ.pop("LLM_SHIELD_UPSTREAM", None)
            else:
                panel.os.environ["LLM_SHIELD_UPSTREAM"] = old_upstream

    def test_value_points_to_shield_accepts_localhost_variants(self):
        self.assertTrue(panel._value_points_to_shield(f"http://localhost:{panel.PROXY_PORT}"))
        self.assertTrue(panel._value_points_to_shield(f"http=127.0.0.1:{panel.PROXY_PORT};https=127.0.0.1:{panel.PROXY_PORT}"))
        self.assertTrue(panel._value_points_to_shield(f"http://[::1]:{panel.PROXY_PORT}/v1"))
        self.assertFalse(panel._value_points_to_shield("http://127.0.0.1:7890"))
        self.assertFalse(panel._value_points_to_shield(f"http://127.0.0.1:{panel.PROXY_PORT}0"))

    def test_health_check_allows_shield_settings_while_tracked_proxy_running(self):
        old_proc = panel.proc["p"]
        old_read_pid = panel._read_pid_file
        old_system = panel._system_proxy_points_to_shield
        old_env = panel._user_env_points_to_shield
        old_port = panel._port_listen
        old_process = panel._process_exists
        old_admin = panel.is_admin

        class FakeProc:
            pid = 24680

            def poll(self):
                return None

        try:
            panel.proc["p"] = FakeProc()
            panel._read_pid_file = lambda: None
            panel._system_proxy_points_to_shield = lambda: (True, f"http=127.0.0.1:{panel.PROXY_PORT}")
            panel._user_env_points_to_shield = lambda: ["HTTP_PROXY"]
            panel._port_listen = lambda port: port in {panel.PANEL_PORT, panel.PROXY_PORT}
            panel._process_exists = lambda pid: False
            panel.is_admin = lambda: False

            h = panel.health_check()
        finally:
            panel.proc["p"] = old_proc
            panel._read_pid_file = old_read_pid
            panel._system_proxy_points_to_shield = old_system
            panel._user_env_points_to_shield = old_env
            panel._port_listen = old_port
            panel._process_exists = old_process
            panel.is_admin = old_admin

        self.assertTrue(h["ok"])
        self.assertEqual(h["issues"], [])

    def test_recover_network_kills_pid_file_process_before_stop_removes_pid_file(self):
        old_pid_path = panel.PID_FILE
        old_stop = panel.stop_proxy
        old_process = panel._process_exists
        old_kill = panel._taskkill_pid
        old_system = panel._system_proxy_points_to_shield
        old_env = panel._user_env_points_to_shield
        old_admin = panel.is_admin
        old_health = panel.health_check
        old_restore = panel.restore_client_env
        killed = []

        try:
            panel.PID_FILE = ROOT / ".test-shield.pid"
            panel.PID_FILE.write_text("24680", encoding="utf-8")

            def fake_stop():
                panel.PID_FILE.unlink(missing_ok=True)
                return True, None

            def fake_kill(pid):
                killed.append(pid)
                return True, "killed"

            panel.stop_proxy = fake_stop
            panel._process_exists = lambda pid: int(pid) == 24680
            panel._taskkill_pid = fake_kill
            panel._system_proxy_points_to_shield = lambda: (False, "")
            panel._user_env_points_to_shield = lambda: []
            panel.is_admin = lambda: False
            panel.health_check = lambda: {"ok": True, "issues": []}
            panel.restore_client_env = lambda: None

            result = panel.recover_network()
        finally:
            panel.PID_FILE.unlink(missing_ok=True)
            panel.PID_FILE = old_pid_path
            panel.stop_proxy = old_stop
            panel._process_exists = old_process
            panel._taskkill_pid = old_kill
            panel._system_proxy_points_to_shield = old_system
            panel._user_env_points_to_shield = old_env
            panel.is_admin = old_admin
            panel.health_check = old_health
            panel.restore_client_env = old_restore

        self.assertTrue(result["ok"], result)
        self.assertEqual(killed, [24680])

    def test_recover_network_does_not_taskkill_tracked_pid_after_stop_proxy(self):
        old_pid_path = panel.PID_FILE
        old_proc = panel.proc["p"]
        old_stop = panel.stop_proxy
        old_process = panel._process_exists
        old_kill = panel._taskkill_pid
        old_system = panel._system_proxy_points_to_shield
        old_env = panel._user_env_points_to_shield
        old_admin = panel.is_admin
        old_health = panel.health_check
        old_restore = panel.restore_client_env
        killed = []

        class FakeProc:
            pid = 24680

        try:
            panel.PID_FILE = ROOT / ".test-shield.pid"
            panel.PID_FILE.write_text("24680", encoding="utf-8")
            panel.proc["p"] = FakeProc()

            def fake_stop():
                panel.PID_FILE.unlink(missing_ok=True)
                panel.proc["p"] = None
                return True, None

            def fake_kill(pid):
                killed.append(pid)
                return False, "not found"

            panel.stop_proxy = fake_stop
            panel._process_exists = lambda pid: int(pid) == 24680
            panel._taskkill_pid = fake_kill
            panel._system_proxy_points_to_shield = lambda: (False, "")
            panel._user_env_points_to_shield = lambda: []
            panel.is_admin = lambda: False
            panel.health_check = lambda: {"ok": True, "issues": []}
            panel.restore_client_env = lambda: None

            result = panel.recover_network()
        finally:
            panel.PID_FILE.unlink(missing_ok=True)
            panel.PID_FILE = old_pid_path
            panel.proc["p"] = old_proc
            panel.stop_proxy = old_stop
            panel._process_exists = old_process
            panel._taskkill_pid = old_kill
            panel._system_proxy_points_to_shield = old_system
            panel._user_env_points_to_shield = old_env
            panel.is_admin = old_admin
            panel.health_check = old_health
            panel.restore_client_env = old_restore

        self.assertTrue(result["ok"], result)
        self.assertEqual(killed, [])

    def test_prune_event_log_keeps_only_last_seven_days(self):
        old_db = event_store.DB_PATH
        old_panel_db = panel.DB_PATH
        try:
            event_store.DB_PATH = ROOT / ".test-shield-events.sqlite3"
            panel.DB_PATH = event_store.DB_PATH
            event_store.DB_PATH.unlink(missing_ok=True)
            now = 2_000_000_000
            event_store.append_event({"ts": now - 8 * 86400, "type": "MASK"})
            event_store.append_event({"ts": now - 2 * 86400, "type": "RESTORE"})

            result = panel.prune_event_log(now=now, retention_days=7)
            kept = event_store.fetch_events(since=0, sensitive_only=False)
        finally:
            event_store.DB_PATH.unlink(missing_ok=True)
            wal = event_store.DB_PATH.with_name(event_store.DB_PATH.name + "-wal")
            shm = event_store.DB_PATH.with_name(event_store.DB_PATH.name + "-shm")
            wal.unlink(missing_ok=True)
            shm.unlink(missing_ok=True)
            event_store.DB_PATH = old_db
            panel.DB_PATH = old_panel_db

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["removed"], 1)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["type"], "RESTORE")

    def test_clear_logs_clears_memory_and_event_store(self):
        old_db = event_store.DB_PATH
        old_panel_db = panel.DB_PATH
        old_legacy = event_store.LEGACY_JSONL_PATH
        try:
            event_store.DB_PATH = ROOT / ".test-shield-events.sqlite3"
            event_store.LEGACY_JSONL_PATH = ROOT / ".test-shield-events.jsonl"
            panel.DB_PATH = event_store.DB_PATH
            event_store.DB_PATH.unlink(missing_ok=True)
            event_store.LEGACY_JSONL_PATH.write_text('{"ts":1,"type":"MASK"}\n', encoding="utf-8")
            event_store.append_event({"ts": time.time(), "type": "MASK", "count": 1})
            with panel.buf_lock:
                panel.log_buf.append("line")
                panel.events.append({"seq": 1, "type": "MASK"})

            result = panel.clear_logs()

            with panel.buf_lock:
                log_len = len(panel.log_buf)
                event_len = len(panel.events)
            remaining = event_store.fetch_events(since=0, sensitive_only=False)
            legacy_content = event_store.LEGACY_JSONL_PATH.read_text(encoding="utf-8")
        finally:
            event_store._reset_writer()
            event_store.DB_PATH.unlink(missing_ok=True)
            event_store.DB_PATH.with_name(event_store.DB_PATH.name + "-wal").unlink(missing_ok=True)
            event_store.DB_PATH.with_name(event_store.DB_PATH.name + "-shm").unlink(missing_ok=True)
            event_store.LEGACY_JSONL_PATH.unlink(missing_ok=True)
            event_store.DB_PATH = old_db
            event_store.LEGACY_JSONL_PATH = old_legacy
            panel.DB_PATH = old_panel_db
            with panel.buf_lock:
                panel.log_buf.clear()
                panel.events.clear()

        self.assertTrue(result["ok"], result)
        self.assertEqual(log_len, 0)
        self.assertEqual(event_len, 0)
        self.assertEqual(remaining, [])
        self.assertEqual(legacy_content, "")

    def test_preload_events_imports_legacy_jsonl_once(self):
        old_db = event_store.DB_PATH
        old_legacy = event_store.LEGACY_JSONL_PATH
        old_panel_path = panel.EVENT_LOG_PATH
        try:
            event_store.DB_PATH = ROOT / ".test-shield-events.sqlite3"
            event_store.LEGACY_JSONL_PATH = ROOT / ".test-shield-events.jsonl"
            panel.EVENT_LOG_PATH = event_store.LEGACY_JSONL_PATH
            event_store.DB_PATH.unlink(missing_ok=True)
            event_store.LEGACY_JSONL_PATH.write_text(
                json.dumps({"ts": 123.0, "type": "MASK", "sid": "abc", "count": 2}) + "\n",
                encoding="utf-8",
            )
            with panel.buf_lock:
                panel.events.clear()

            result = panel.preload_events()
            loaded = event_store.fetch_events(since=0, sensitive_only=False)
        finally:
            event_store._reset_writer()
            event_store.DB_PATH.unlink(missing_ok=True)
            event_store.DB_PATH.with_name(event_store.DB_PATH.name + "-wal").unlink(missing_ok=True)
            event_store.DB_PATH.with_name(event_store.DB_PATH.name + "-shm").unlink(missing_ok=True)
            event_store.LEGACY_JSONL_PATH.unlink(missing_ok=True)
            event_store.DB_PATH = old_db
            event_store.LEGACY_JSONL_PATH = old_legacy
            panel.EVENT_LOG_PATH = old_panel_path
            with panel.buf_lock:
                panel.events.clear()

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["loaded"], 1)
        self.assertEqual(loaded[0]["type"], "MASK")
        self.assertEqual(loaded[0]["sid"], "abc")
        self.assertIn("seq", loaded[0])

    def test_api_logs_reads_sqlite_events(self):
        old_db = event_store.DB_PATH
        old_panel_db = panel.DB_PATH
        old_token = panel.API_TOKEN
        try:
            event_store.DB_PATH = ROOT / ".test-shield-events.sqlite3"
            panel.DB_PATH = event_store.DB_PATH
            event_store.DB_PATH.unlink(missing_ok=True)
            # 写线程可能已被同一进程内的其他用例在旧 DB 上启动过（连接已缓存），
            # 换路径后必须重置，否则建表跳过、后续查询报 no such table: events
            event_store._reset_writer()
            event_store.append_event({"ts": time.time(), "type": "RESTORE", "sid": "abc", "count": 1, "restored": 1})
            with panel.buf_lock:
                panel.events.clear()
                panel.log_buf.clear()
            with panel.app.test_client() as client:
                res = client.get("/api/logs?since=0", headers={"X-Shield-Token": panel.API_TOKEN})
                data = res.get_json()
        finally:
            event_store._reset_writer()
            event_store.DB_PATH.unlink(missing_ok=True)
            event_store.DB_PATH.with_name(event_store.DB_PATH.name + "-wal").unlink(missing_ok=True)
            event_store.DB_PATH.with_name(event_store.DB_PATH.name + "-shm").unlink(missing_ok=True)
            event_store.DB_PATH = old_db
            panel.DB_PATH = old_panel_db
            panel.API_TOKEN = old_token
            with panel.buf_lock:
                panel.events.clear()
                panel.log_buf.clear()

        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(data["events"]), 1)
        self.assertEqual(data["events"][0]["type"], "RESTORE")
        self.assertEqual(data["store"], "sqlite")

    def test_transparent_emit_writes_sqlite_event_store(self):
        old_db = event_store.DB_PATH
        old_log = tr._log
        try:
            event_store._reset_writer()  # 换 DB_PATH 前重置 writer/建表缓存
            event_store.DB_PATH = ROOT / ".test-transparent-events.sqlite3"
            event_store.DB_PATH.unlink(missing_ok=True)
            tr._log = lambda msg: None

            tr._emit("MASK", host="api.openai.com", count=1)
            event_store.flush_event_queue()

            rows = event_store.fetch_events(since=0, sensitive_only=False)
        finally:
            event_store._reset_writer()
            event_store.DB_PATH.unlink(missing_ok=True)
            event_store.DB_PATH.with_name(event_store.DB_PATH.name + "-wal").unlink(missing_ok=True)
            event_store.DB_PATH.with_name(event_store.DB_PATH.name + "-shm").unlink(missing_ok=True)
            event_store.DB_PATH = old_db
            tr._log = old_log

        self.assertEqual(rows[0]["type"], "MASK")
        self.assertEqual(rows[0]["host"], "api.openai.com")

    def test_start_proxy_waits_for_port_ready_not_fixed_sleep(self):
        """启动必须等端口真正监听，不能固定 sleep 就报成功。

        曾固定 time.sleep(0.8) 只判进程死活：mitmdump 冷启动加载 transparent.py +
        绑定全部 upstream 端口常超过 1s，面板报「已启动」时客户端连端口即
        「网络连接异常」。现在轮询就绪：端口一直不可用（进程还活着）要判失败并
        杀进程，不能拖满超时。
        """
        import io
        captured = {}
        old_port_listen = panel._port_listen
        old_load = panel.load_config
        old_admin = panel.is_admin
        old_up = panel.detect_upstream
        old_sleep = panel.time.sleep
        old_thread = panel.threading.Thread
        old_emit = panel._emit_log
        old_popen = panel.subprocess.Popen
        old_kill = panel._kill_proxy_tree
        old_lpp = panel._listening_port_pids
        killed = []

        class FakePopen:
            pid = 12345
            stdout = io.StringIO("")

            def poll(self):
                return None

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def communicate(self, *args, **kwargs):
                return (b"", b"")

        class FakeThread:
            def __init__(self, *args, **kwargs):
                pass

            def start(self):
                pass

        try:
            # 端口永远不可用 → 启动必须判失败（而不是假装成功）
            panel._port_listen = lambda port: False
            panel._listening_port_pids = lambda ports, fresh=False: {}
            panel.load_config = lambda: {**panel.default_config(), "capture_mode": "local"}
            panel.enabled_domains = lambda cfg: ["api.openai.com"]
            panel.is_admin = lambda: True
            panel.detect_upstream = lambda: ""
            panel.time.sleep = lambda seconds: None  # 轮询不真睡
            panel.threading.Thread = FakeThread
            panel._emit_log = lambda line: None
            panel.subprocess.Popen = lambda args, **kw: FakePopen()
            # 必须 mock 掉真实清理：FakePopen.pid=12345 是测试假值，失败分支若执行
            # 真实 taskkill /PID 12345 /T /F 可能误杀 Windows 上 PID 恰好复用的真实
            # 进程（含子进程树）。断言调用本身即验证「启动失败必须清理」语义。
            panel._kill_proxy_tree = lambda pid: killed.append(pid)
            panel._START_READY_TIMEOUT = 1.5  # 测试用小超时
            ok, err = panel.start_proxy()
            self.assertFalse(ok, "端口始终不可用必须判启动失败")
            self.assertIn("未监听端口", err, f"错误信息须说明端口未就绪: {err!r}")
            self.assertIsNone(panel.proc["p"], "判定失败后不得残留进程句柄")
            self.assertEqual(killed, [12345], "启动失败必须清理进程，防止占端口的僵尸")
        finally:
            panel._listening_port_pids = old_lpp
            panel.proc["p"] = None
            panel.state["proxy_running"] = False
            panel.state["proxy_pid"] = None
            panel.PID_FILE.unlink(missing_ok=True)
            panel._port_listen = old_port_listen
            panel.load_config = old_load
            panel.is_admin = old_admin
            panel.detect_upstream = old_up
            panel.time.sleep = old_sleep
            panel.threading.Thread = old_thread
            panel._emit_log = old_emit
            panel.subprocess.Popen = old_popen
            panel._kill_proxy_tree = old_kill
            panel._START_READY_TIMEOUT = 15


class TodayStatsTests(unittest.TestCase):
    def test_fetch_openrouter_prices_parses_per_token_and_filters_noise(self):
        """在线价格解析：每 token 美元 ×1e6 → $/1M；0 价/NaN/坏数据剔除。"""
        import json
        from unittest.mock import patch
        from shield_defaults import fetch_openrouter_prices
        payload = {
            "data": [
                {"id": "openai/gpt-4o", "pricing": {"prompt": "0.0000025", "completion": "0.00001"}},
                {"id": "free-model", "pricing": {"prompt": "0", "completion": "0"}},
                {"id": "nan-model", "pricing": {"prompt": "NaN", "completion": "0.1"}},
                {"id": "bad-pricing", "pricing": {"prompt": "abc", "completion": "x"}},
                {"no": "id"},
            ]
        }
        class _Resp:
            def read(self):
                return json.dumps(payload).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
        with patch("urllib.request.urlopen", return_value=_Resp()):
            prices = fetch_openrouter_prices()
        self.assertEqual(prices["openai/gpt-4o"], {"input": 2.5, "output": 10.0})
        self.assertNotIn("free-model", prices)
        self.assertNotIn("nan-model", prices)
        self.assertNotIn("bad-pricing", prices)

    def test_estimate_cost_priority_override_cache_builtin(self):
        """价格优先级：用户自配 > 在线缓存 > 内置表。"""
        from shield_defaults import estimate_cost
        cache = {"openai/gpt-4o": {"input": 2.5, "output": 10.0},
                 "custom-model-x": {"input": 1.0, "output": 2.0}}
        # 缓存命中（内置表没有的模型）
        cost, price = estimate_cost("custom-model-x", 1_000_000, 0, cache=cache)
        self.assertAlmostEqual(cost, 1.0)
        # 缓存优先于内置（缓存价 2.5 vs 内置 2.5 一致；改用覆盖验证）
        cost, _ = estimate_cost("openai/gpt-4o", 1_000_000, 1_000_000, cache=cache)
        self.assertAlmostEqual(cost, 12.5)
        # 用户自配优先于缓存
        cost, price = estimate_cost("openai/gpt-4o", 1_000_000, 1_000_000,
                                    overrides={"openai/gpt-4o": {"input": 99, "output": 99}},
                                    cache=cache)
        self.assertAlmostEqual(cost, 198.0)
        # 无缓存无覆盖 → 内置表兜底
        cost, _ = estimate_cost("gpt-4o", 0, 1_000_000)
        self.assertAlmostEqual(cost, 10.0)

    def test_today_stats_aggregates_by_local_day(self):
        import tempfile
        old_db = event_store.DB_PATH
        tmp = Path(tempfile.mkdtemp()) / "stats.sqlite3"
        event_store.DB_PATH = tmp
        event_store._reset_writer()
        try:
            event_store.init_db()
            now = time.time()
            event_store.append_event({"type": "MASK", "ts": now, "count": 3, "host": "a",
                                      "items": [{"label": "PHONE", "original": "13812345678"}, {"label": "PHONE", "original": "13812345678"}]})
            event_store.append_event({"type": "MASK", "ts": now, "count": 2, "host": "b",
                                      "items": [{"label": "EMAIL", "original": "z@ex.com"}]})
            event_store.append_event({"type": "RESTORE", "ts": now, "restored": 1})
            event_store.append_event({"type": "BLOCK", "ts": now})
            event_store.append_event({"type": "ERR", "ts": now})
            # 昨天的不计入
            event_store.append_event({"type": "MASK", "ts": now - 86400 * 2, "count": 9})
            stats = event_store.today_stats(now=now)
            self.assertTrue(stats["ok"])
            self.assertEqual(stats["masked_items"], 5)
            self.assertEqual(stats["mask_events"], 2)
            self.assertEqual(stats["restored"], 1)
            self.assertEqual(stats["requests"], 3)  # MASK*2 + BLOCK
            self.assertEqual(stats["alerts"], 2)  # BLOCK + ERR
            # by_label / top_words 聚合
            self.assertEqual(stats["by_label"].get("PHONE"), 2)
            self.assertEqual(stats["by_label"].get("EMAIL"), 1)
            top = stats["top_words"]
            self.assertTrue(any(w["word"] == "13812345678" and w["count"] == 2 for w in top), "高频词应聚合去重计数")
            self.assertTrue(any(w["word"] == "z@ex.com" and w["count"] == 1 for w in top))
            # by_label_words：按标签分组的具体词（用户要求展开看具体值）
            ph = stats["by_label_words"].get("PHONE") or []
            self.assertEqual(ph, [{"word": "13812345678", "count": 2}], "PHONE 下应列出具体词及次数")
            em = stats["by_label_words"].get("EMAIL") or []
            self.assertEqual(em, [{"word": "z@ex.com", "count": 1}])
        finally:
            event_store._reset_writer()
            for p in [tmp, Path(str(tmp) + "-wal"), Path(str(tmp) + "-shm")]:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
            event_store.DB_PATH = old_db

    def test_today_stats_aggregates_tokens_from_restore_usage(self):
        """RESTORE 事件的 usage 进 daily_tokens，MASK 不双计（每日 Token 卡数据源）。"""
        import tempfile
        old_db = event_store.DB_PATH
        tmp = Path(tempfile.mkdtemp()) / "tokens.sqlite3"
        event_store.DB_PATH = tmp
        event_store._reset_writer()
        try:
            event_store.init_db()
            now = time.time()
            event_store.append_event({"type": "RESTORE", "ts": now,
                                      "usage": {"prompt_tokens": 120, "completion_tokens": 30}})
            event_store.append_event({"type": "RESTORE", "ts": now,
                                      "usage": {"prompt_tokens": 40, "completion_tokens": 10}})
            # MASK 即使带 usage 也不计（只收 RESTORE，防双计）
            event_store.append_event({"type": "MASK", "ts": now, "count": 1,
                                      "usage": {"prompt_tokens": 999, "completion_tokens": 999}})
            # 无 usage 的 RESTORE 不产生行
            event_store.append_event({"type": "RESTORE", "ts": now})
            stats = event_store.today_stats(now=now)
            self.assertEqual(stats["tokens"], {"prompt": 160, "completion": 40})
        finally:
            event_store._reset_writer()
            for p in [tmp, Path(str(tmp) + "-wal"), Path(str(tmp) + "-shm")]:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
            event_store.DB_PATH = old_db

    def test_stats_models_aggregates_by_model(self):
        """daily_models 摘要：RESTORE 事件按模型聚合请求/token，窗口外不计。"""
        import tempfile
        old_db = event_store.DB_PATH
        tmp = Path(tempfile.mkdtemp()) / "models.sqlite3"
        event_store.DB_PATH = tmp
        event_store._reset_writer()
        try:
            event_store.init_db()
            now = time.time()
            for _ in range(3):
                event_store.append_event({"type": "RESTORE", "ts": now, "model": "claude-sonnet-4-5",
                                          "usage": {"prompt_tokens": 100, "completion_tokens": 50}})
            event_store.append_event({"type": "RESTORE", "ts": now, "model": "gpt-4o",
                                      "usage": {"prompt_tokens": 200, "completion_tokens": 80}})
            # 无 model 的 RESTORE 不计；昨天的不计（窗口 7 天）
            event_store.append_event({"type": "RESTORE", "ts": now})
            event_store.append_event({"type": "RESTORE", "ts": now - 86400 * 8, "model": "claude-sonnet-4-5",
                                      "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
            rows = event_store.stats_models(days=7, now=now)
            by_model = {r["model"]: r for r in rows}
            self.assertEqual(by_model["claude-sonnet-4-5"]["requests"], 3)
            self.assertEqual(by_model["claude-sonnet-4-5"]["prompt"], 300)
            self.assertEqual(by_model["claude-sonnet-4-5"]["completion"], 150)
            self.assertEqual(by_model["gpt-4o"]["requests"], 1)
            # 请求数降序：claude 3 次在 gpt 1 次前面
            self.assertEqual(rows[0]["model"], "claude-sonnet-4-5")
        finally:
            event_store._reset_writer()
            for p in [tmp, Path(str(tmp) + "-wal"), Path(str(tmp) + "-shm")]:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
            event_store.DB_PATH = old_db

    def test_stats_models_days_one_only_includes_local_today(self):
        """费用卡的 days=1 只统计本地自然日，不把昨天的模型用量混入。"""
        import tempfile
        old_db = event_store.DB_PATH
        tmp = Path(tempfile.mkdtemp()) / "models-today.sqlite3"
        event_store.DB_PATH = tmp
        event_store._reset_writer()
        try:
            event_store.init_db()
            now = time.time()
            event_store.append_event({
                "type": "RESTORE", "ts": now, "model": "gpt-4o",
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            })
            event_store.append_event({
                "type": "RESTORE", "ts": now - 86400, "model": "gpt-4o",
                "usage": {"prompt_tokens": 900, "completion_tokens": 800},
            })
            rows = event_store.stats_models(days=1, now=now)
            self.assertEqual(rows, [{
                "model": "gpt-4o", "requests": 1, "prompt": 100, "completion": 20, "errors": 0,
            }])
        finally:
            event_store._reset_writer()
            for p in [tmp, Path(str(tmp) + "-wal"), Path(str(tmp) + "-shm")]:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
            event_store.DB_PATH = old_db

    def test_stats_models_counts_errors_per_model(self):
        """模型排行成功率：ERR 事件按 model 正确累加到 errors 列。"""
        old_db = event_store.DB_PATH
        tmp = Path(tempfile.mktemp(suffix=".sqlite3"))
        try:
            event_store._reset_writer()
            event_store.DB_PATH = tmp
            event_store.init_db()
            now = time.time()
            # 2 次成功，1 次失败
            event_store.append_event({
                "type": "RESTORE", "ts": now, "model": "gemini-3.7-flash",
                "usage": {"prompt_tokens": 50, "completion_tokens": 10},
            })
            event_store.append_event({
                "type": "RESTORE", "ts": now, "model": "gemini-3.7-flash",
                "usage": {"prompt_tokens": 60, "completion_tokens": 20},
            })
            event_store.append_event({
                "type": "ERR", "ts": now, "model": "gemini-3.7-flash",
                "msg": "flow_error:server closed connection",
            })
            # 另 1 个纯失败模型
            event_store.append_event({
                "type": "ERR", "ts": now, "model": "broken-model",
                "msg": "passthrough: TimeoutError",
            })
            rows = event_store.stats_models(days=1, now=now)
            row_map = {r["model"]: r for r in rows}
            self.assertEqual(row_map["gemini-3.7-flash"]["requests"], 2)
            self.assertEqual(row_map["gemini-3.7-flash"]["errors"], 1)
            self.assertEqual(row_map["broken-model"]["requests"], 0)
            self.assertEqual(row_map["broken-model"]["errors"], 1)
        finally:
            event_store._reset_writer()
            for p in [tmp, Path(str(tmp) + "-wal"), Path(str(tmp) + "-shm")]:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
            event_store.DB_PATH = old_db

    def test_estimate_cost_prefix_match_and_override(self):
        """费用估算：最长前缀匹配 + 路由前缀剥离 + 用户自配覆盖 + 未收录不计。"""
        from shield_defaults import estimate_cost
        # 最长前缀：claude-sonnet-4-5 命中精确条目（3/15），不是 claude-3-5-sonnet
        cost, price = estimate_cost("claude-sonnet-4-5", 1_000_000, 1_000_000)
        self.assertAlmostEqual(cost, 18.0)
        self.assertEqual(price["input"], 3.0)
        # 路由前缀剥离
        cost, _ = estimate_cost("anthropic/claude-3-5-sonnet", 1_000_000, 0)
        self.assertAlmostEqual(cost, 3.0)
        # 未收录 → (0, None)
        cost, price = estimate_cost("mimo-v2.5-pro", 1_000_000, 1_000_000)
        self.assertEqual(cost, 0.0)
        self.assertIsNone(price)
        # 用户自配覆盖
        cost, price = estimate_cost("mimo-v2.5-pro", 1_000_000, 1_000_000,
                                    {"mimo-v2.5-pro": {"input": 1.0, "output": 2.0}})
        self.assertAlmostEqual(cost, 3.0)
        # 无 token 也安全
        cost, _ = estimate_cost("gpt-4o", 0, 0)
        self.assertEqual(cost, 0.0)
        cost, price2 = estimate_cost("", 100, 100)
        self.assertEqual(cost, 0.0)
        self.assertIsNone(price2)

    def test_today_stats_tokens_preserved_after_clear(self):
        """用户要求：统计永久保存——clear_events 不清 daily_tokens（token 用量保留）。"""
        import tempfile
        old_db = event_store.DB_PATH
        tmp = Path(tempfile.mkdtemp()) / "tokenkeep.sqlite3"
        event_store.DB_PATH = tmp
        event_store._reset_writer()
        try:
            event_store.init_db()
            now = time.time()
            event_store.append_event({"type": "RESTORE", "ts": now,
                                      "usage": {"prompt_tokens": 5, "completion_tokens": 5}})
            event_store.flush_event_queue()
            event_store.clear_events()
            event_store.flush_event_queue()
            stats = event_store.today_stats(now=now)
            self.assertEqual(stats["tokens"], {"prompt": 5, "completion": 5}, "清日志后 token 用量应保留")
        finally:
            event_store._reset_writer()
            for p in [tmp, Path(str(tmp) + "-wal"), Path(str(tmp) + "-shm")]:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
            event_store.DB_PATH = old_db


if __name__ == "__main__":
    unittest.main()


class AutoHealTests(unittest.TestCase):
    """v1.5.61 自动恢复三件套：崩溃留痕 / 残留端口自愈 / 恢复状态字段。

    注意：本类所有用例必须 mock 掉真实系统操作（netstat/tasklist/powershell/
    taskkill），单测运行时用户代理可能正在运行，真实 _free_upstream_ports 会
    把正在服务的代理/面板杀掉（实测发生过两次）。
    """

    def test_is_shield_panel_pid_recognizes_src_instance(self):
        """另一 LLM Shield 面板（源码 panel.py / 打包 LLMShield.exe）必须被识别，
        否则它的 503 占位监听占着端口时自动重启永远失败。"""
        old_run = panel._run_console
        self.addCleanup(lambda: setattr(panel, "_run_console", old_run))
        cmdlines = {}

        def fake_run(argv, timeout=None):
            if argv and argv[0] == "powershell":
                pid = argv[-1].split("ProcessId=")[1].split("'")[0]
                return 0, cmdlines.get(pid, "")
            return old_run(argv, timeout=timeout)

        panel._run_console = fake_run
        with mock.patch.object(panel.sys, "platform", "win32"):
            cmdlines["7777"] = r"C:\Python313\python.exe C:\Apps\shield\panel.py"
            self.assertTrue(panel._is_shield_panel_pid(7777), "源码面板必须被识别")
            cmdlines["8888"] = r'"C:\Apps\LLMShield\LLMShield.exe"'
            self.assertTrue(panel._is_shield_panel_pid(8888), "打包面板必须被识别")
            cmdlines["9999"] = r"C:\Python313\python.exe manage.py runserver"
            self.assertFalse(panel._is_shield_panel_pid(9999), "无关 python 不能误判")
            cmdlines["1111"] = r"C:\Python313\python.exe mitmdump.exe -s C:\Apps\shield\transparent.py"
            self.assertFalse(panel._is_shield_panel_pid(1111), "mitmdump 类进程归 _is_mitmdump_pid 管")
            self.assertFalse(panel._is_shield_panel_pid(os.getpid()), "本进程绝不识别")

    def test_free_upstream_ports_kills_stale_panel_listener(self):
        """残留端口清理必须覆盖「另一面板的 503 占位监听」：
        曾只杀 mitmdump 类进程，面板占位占端口时清理不掉 → 自动重启失败。"""
        old_scan = panel._listening_port_pids
        old_mit = panel._is_mitmdump_pid
        old_panel = panel._is_shield_panel_pid
        old_kill = panel._taskkill_pid
        killed = []
        self.addCleanup(lambda: setattr(panel, "_listening_port_pids", old_scan))
        self.addCleanup(lambda: setattr(panel, "_is_mitmdump_pid", old_mit))
        self.addCleanup(lambda: setattr(panel, "_is_shield_panel_pid", old_panel))
        self.addCleanup(lambda: setattr(panel, "_taskkill_pid", old_kill))

        panel._listening_port_pids = lambda ports, fresh=False: {18701: {7777}, 18702: {7777}}
        panel._is_mitmdump_pid = lambda pid: False
        panel._is_shield_panel_pid = lambda pid: pid == 7777
        panel._taskkill_pid = lambda pid: (killed.append(pid) or True, "ok")

        freed = panel._free_upstream_ports()
        self.assertEqual(killed, [7777], "残留面板监听必须被杀释放端口")
        self.assertTrue(any("18701,18702" in f for f in freed))

    def test_free_upstream_ports_ignores_unrelated_processes(self):
        """无关第三方进程（占 187xx 但非 Shield 相关）绝不能杀。"""
        old_scan = panel._listening_port_pids
        old_mit = panel._is_mitmdump_pid
        old_panel = panel._is_shield_panel_pid
        old_kill = panel._taskkill_pid
        killed = []
        self.addCleanup(lambda: setattr(panel, "_listening_port_pids", old_scan))
        self.addCleanup(lambda: setattr(panel, "_is_mitmdump_pid", old_mit))
        self.addCleanup(lambda: setattr(panel, "_is_shield_panel_pid", old_panel))
        self.addCleanup(lambda: setattr(panel, "_taskkill_pid", old_kill))

        panel._listening_port_pids = lambda ports, fresh=False: {18701: {4242}}
        panel._is_mitmdump_pid = lambda pid: False
        panel._is_shield_panel_pid = lambda pid: False
        panel._taskkill_pid = lambda pid: (killed.append(pid), True)[1]

        freed = panel._free_upstream_ports()
        self.assertEqual(killed, [], "无关进程绝不能被清理")
        self.assertEqual(freed, [])

    def test_dump_crash_context_writes_snapshot_file(self):
        """崩溃现场必须落盘独立文件：退出码、端口占用表、日志尾部。"""
        old_root = panel.DATA_ROOT
        old_scan = panel._listening_port_pids
        old_run = panel._run_console
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: setattr(panel, "DATA_ROOT", old_root))
        self.addCleanup(lambda: setattr(panel, "_listening_port_pids", old_scan))
        self.addCleanup(lambda: setattr(panel, "_run_console", old_run))
        shutil.rmtree(tmp, ignore_errors=True)

        panel.DATA_ROOT = tmp
        tmp.mkdir(parents=True, exist_ok=True)
        (tmp / "proxy-crash.log").write_text("TAIL-LOG-EXAMPLE", encoding="utf-8")
        panel._listening_port_pids = lambda ports, fresh=False: {18701: {4321}}
        panel._run_console = lambda argv, timeout=None: (
            0, r'"python.exe","4321","Console","1","20,000 K"' if argv[0] == "tasklist"
            else r'C:\Python313\python.exe mitmdump.exe -s C:\Apps\shield\transparent.py')
        panel._emit_log = lambda line: None
        panel.proc["p"] = None

        panel._dump_crash_context()
        dumps = list((tmp / "crash-dumps").glob("crash-*.txt"))
        self.assertEqual(len(dumps), 1, "崩溃现场文件必须生成")
        content = dumps[0].read_text(encoding="utf-8")
        self.assertIn("4321", content, "现场须含端口占用 PID")
        self.assertIn("TAIL-LOG-EXAMPLE", content, "现场须含日志尾部")
        self.assertIn("proxy_running", content)

    def test_restart_proxy_locked_sets_auto_recover_flags(self):
        """_restart_proxy_locked：成功记 auto_recovered_at、失败记 auto_recover_fail。"""
        old_stop = panel.stop_proxy
        old_sp = panel.start_proxy
        old_fb = panel._start_fallback
        old_emit = panel._emit_log
        old_thread = panel.threading.Thread
        old_dump = panel._dump_crash_context
        self.addCleanup(lambda: setattr(panel, "stop_proxy", old_stop))
        self.addCleanup(lambda: setattr(panel, "start_proxy", old_sp))
        self.addCleanup(lambda: setattr(panel, "_start_fallback", old_fb))
        self.addCleanup(lambda: setattr(panel, "_emit_log", old_emit))
        self.addCleanup(lambda: setattr(panel.threading, "Thread", old_thread))
        self.addCleanup(lambda: setattr(panel, "_dump_crash_context", old_dump))
        self.addCleanup(lambda: panel.state.update(
            {"auto_recovered_at": None, "auto_recover_fail": "", "stop_requested": False}))

        panel.stop_proxy = lambda: (True, None)
        panel._start_fallback = lambda reason="": 0
        panel._emit_log = lambda line: None
        panel._dump_crash_context = lambda reason="crash": None

        class FakeThread:
            def __init__(self, *a, **k):
                pass

            def start(self):
                pass

        panel.threading.Thread = FakeThread
        panel.state.update({"auto_recovered_at": None, "auto_recover_fail": ""})

        # 失败路径
        panel.start_proxy = lambda: (False, "端口被占用")
        panel.state["stop_requested"] = False
        ok = panel._restart_proxy_locked("端口失守")
        self.assertFalse(ok)
        self.assertIn("重启失败", panel.state.get("auto_recover_fail") or "",
                      "失败必须写告警字段供前端横幅显示")
        # 成功路径
        panel.start_proxy = lambda: (True, None)
        ok = panel._restart_proxy_locked("端口失守")
        self.assertTrue(ok)
        self.assertTrue(panel.state.get("auto_recovered_at"), "成功必须记恢复时间戳")
        self.assertEqual(panel.state.get("auto_recover_fail"), "", "成功后清失败告警")

    def test_status_exposes_auto_recover_fields(self):
        """/api/status 必须带 auto_recovered_at / auto_recover_fail / proxy_starting / proxy_stopping 供前端状态机。"""
        import panel as _p
        # 直接验证 api_status 返回字段存在（不真实调用，避免端口扫描）
        old = {k: getattr(_p, k) for k in ("_listening_port_pids", "load_config")}
        self.addCleanup(lambda: [setattr(_p, k, v) for k, v in old.items()])
        _p._listening_port_pids = lambda ports: {}
        _p.load_config = lambda: {**_p.default_config(), "upstreams": []}
        client = _p.app.test_client()
        s = client.get("/api/status",
                       headers={"X-Shield-Token": _p.API_TOKEN}).get_json()
        self.assertIn("auto_recovered_at", s)
        self.assertIn("auto_recover_fail", s)
        self.assertIn("proxy_starting", s)
        self.assertIn("proxy_stopping", s)
        self.assertIsInstance(s["proxy_starting"], bool)
        self.assertIsInstance(s["proxy_stopping"], bool)


class ReasoningEffortCleanTests(unittest.TestCase):
    """reasoning_effort 策略：透明代理不改下游请求，只标记可疑值供排查提示。

    实测根因：pi 在 thinking=off 时发 "none"，部分中转只认 low/medium/high →
    400。这是下游模型配置问题（thinkingLevelMap off→"none" 配错），已通过
    pi 侧改 off→None 修复；LLMShield 原样透传（不改用户显式思考配置，避免
    误伤支持 max 等扩展值的模型），仅在上游 4xx 时在事件里附加排查提示。
    """

    def test_suspicious_values_marked_not_removed(self):
        # 可疑值（none/minimal/max/非字符串）：请求原样保留，只返回标记
        for v in ("none", "minimal", "max", 123, True, {"x": 1}):
            body = {"model": "mimo-v2.5", "reasoning_effort": v}
            marked = tr._clean_reasoning_effort(body, "upstream-a")
            self.assertIn("reasoning_effort", body, f"请求必须原样透传 {v!r}")
            self.assertEqual(body.get("reasoning_effort"), v, "值不能被修改")
            self.assertTrue(marked, f"{v!r} 应标记为可疑值")

    def test_valid_values_not_marked(self):
        for v in ("low", "medium", "high"):
            body = {"model": "mimo-v2.5", "reasoning_effort": v}
            marked = tr._clean_reasoning_effort(body, "upstream-a")
            self.assertIsNone(marked, f"{v!r} 合法值不应标记")
            self.assertEqual(body.get("reasoning_effort"), v)

    def test_missing_or_non_dict_noop(self):
        body = {"model": "mimo-v2.5", "messages": []}
        self.assertIsNone(tr._clean_reasoning_effort(body, "upstream-a"))
        self.assertIsNone(tr._clean_reasoning_effort(None, "upstream-a"))
        self.assertIsNone(tr._clean_reasoning_effort("not-dict", "upstream-a"))

    def test_any_upstream_marked_identically(self):
        # 不做按渠道区分：所有渠道都原样透传 + 标记（误伤面为零）
        for up in ("upstream-a", "upstream-b", "openai", "anthropic"):
            body = {"model": "x", "reasoning_effort": "none"}
            marked = tr._clean_reasoning_effort(body, up)
            self.assertTrue(marked, f"{up} 渠道 none 应标记")
            self.assertIn("reasoning_effort", body)

    def test_hint_text_guides_downstream(self):
        hint = tr._reasoning_effort_hint("none")
        self.assertIn("none", hint)
        self.assertIn("可能不被上游支持", hint)
        self.assertIn("thinkingLevelMap", hint)
        self.assertEqual(tr._reasoning_effort_hint(""), "")
        self.assertEqual(tr._reasoning_effort_hint(None), "")


class WordLimitTests(unittest.TestCase):
    """敏感词长度/数量限制（审计 P1）：超大词表拖慢合并正则扫描。"""

    def test_custom_word_regex_skips_oversized(self):
        self.assertIsNone(tr._custom_word_regex("长" * 201), "超长词必须跳过")
        self.assertIsNone(tr._custom_word_regex(""), "空词跳过")
        rx = tr._custom_word_regex("正常词")
        self.assertIsNotNone(rx, "正常词正常编译")
        self.assertIs(rx, tr._custom_word_regex("正常词"), "缓存命中")

    def test_normalize_config_caps_total_words(self):
        # 超过 MAX_TOTAL_WORDS 的词被截断 + 产生 warning
        warnings = []
        big = {"敏感词A": [f"词{i}" for i in range(3000)], "敏感词B": [f"词B{i}" for i in range(3000)]}
        cfg = panel.normalize_config({**panel.default_config(), "sensitive": big}, warnings)
        total = sum(len(v) for v in cfg.get("sensitive", {}).values())
        self.assertLessEqual(total, panel.MAX_TOTAL_WORDS, "总词数必须受限")
        self.assertTrue(any("总数超过" in w for w in warnings), "超限必须有 warning")

    def test_normalize_config_keeps_word_len_limit(self):
        cfg = panel.normalize_config({**panel.default_config(), "sensitive": {"测试": ["短词", "长" * 300]}})
        words = cfg.get("sensitive", {}).get("测试", [])
        self.assertIn("短词", words)
        self.assertNotIn("长" * 300, words, "超长词被过滤")


class NewRulesTests(unittest.TestCase):
    """审计第四批 P2：新加规则回归测试（每条正例 + 反例）。"""

    def setUp(self):
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr.CUSTOM_WORDS.clear()
        tr.SENSITIVE_DISABLED = set()
        tr.SENSITIVE_WORD_DISABLED = {}
        tr.SENSITIVE_WORD_WHOLE = set()
        tr.BUILTIN_RULES = {l: True for l in tr.DEFAULT_BUILTIN_RULES}
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr._CUSTOM_COMBINED_CACHE["key"] = None
        tr._CUSTOM_COMBINED_CACHE["rx"] = None

    def _mask(self, text):
        sid = "nr" + str(hash(text))[-6:]
        tr._new_session(sid)
        tr.sessions[sid]["fwd"] = {}
        tr.sessions[sid]["labels"] = {}
        tr.sessions[sid]["rev"] = {}
        return tr.mask(text, sid)

    # ---- PEM 私钥 ----
    def test_pem_private_key_masked_whole(self):
        pem = ("-----BEGIN " + "RSA PRIVATE KEY-----\n"
               "MIIEowIBAAKCAQEAxxx\n"
               "-----END " + "RSA PRIVATE KEY-----")
        r = self._mask("私钥：" + pem)
        self.assertNotIn("MIIEow", r, "PEM 内容不应残留")
        self.assertIn("{{", r, "PEM 应整体替换成占位符")

    def test_pem_not_masked_for_certificate(self):
        # 证书不是私钥，不应被 PRIVATE_KEY 规则命中
        cert = "-----BEGIN CERTIFICATE-----\nMIIBtzCCAS+gAwIBAgIQ\n-----END CERTIFICATE-----"
        r = self._mask(cert)
        self.assertIn("BEGIN CERTIFICATE", r, "证书不应被当私钥脱敏")

    # ---- 连接串密码 ----
    def test_connstr_password_masked_keep_host(self):
        r = self._mask("postgres://user:secret123@db.internal:5432")
        self.assertNotIn("secret123", r, "连接串密码应脱敏")
        self.assertIn("postgres://", r, "scheme 保留")
        self.assertIn("db.internal", r, "host 保留")

    def test_connstr_no_match_without_at(self):
        r = self._mask("redis://localhost:6379")
        self.assertIn("localhost", r, "无密码连接串不应命中")

    # ---- 云厂商 AK ----
    def test_google_ak(self):
        google_ak = "AIza" + "SyA1234567890ABCDEFGHIJKLMNOPQRSTUV"
        r = self._mask("key=" + google_ak)
        self.assertNotIn("AIza", r, "Google AK 应脱敏")

    def test_aliyun_ak(self):
        r = self._mask("LTAI5tAbC123456789012")
        self.assertNotIn("LTAI", r, "阿里云 AK 应脱敏")

    def test_tencent_ak(self):
        r = self._mask("AKID1234567890123")
        self.assertNotIn("AKID", r, "腾讯云 AK 应脱敏")

    def test_slack_token(self):
        r = self._mask("xoxb-1234567890-abcdefghij")
        self.assertNotIn("xoxb", r, "Slack token 应脱敏")

    def test_stripe_key(self):
        stripe_live = "sk_" + "live_" + "51Abcdefghijklmnopqrstuvw"
        r = self._mask(stripe_live)
        self.assertNotIn("sk_live", r, "Stripe key 应脱敏")

    def test_feishu_cli(self):
        r = self._mask("cli_abc1234567890abcd")
        self.assertNotIn("cli_abc", r, "飞书 cli token 应脱敏")

    def test_dingtalk(self):
        r = self._mask("dingabc123456")
        self.assertNotIn("dingabc", r, "钉钉 token 应脱敏")

    # ---- MAC（默认关，手动开启验证）----
    def test_mac_masked_cleanly_when_enabled(self):
        tr.BUILTIN_RULES["MAC"] = True
        r = self._mask("设备 00:1A:2B:3C:4D:5E 已连接")
        self.assertNotIn("00:1A:2B:3C:4D:5E", r, "真 MAC 应完整脱敏")
        self.assertNotIn("M{{", r, "不应切碎 MAC 吃周围文本")
        self.assertIn("设备", r, "周围文本保留")

    def test_mac_space_separator_not_masked(self):
        # 空格分隔的序列不是 MAC（修复前会误伤）
        tr.BUILTIN_RULES["MAC"] = True
        r = self._mask("序列 12 34 56 78 90 ab")
        self.assertIn("12 34 56 78 90 ab", r, "空格分隔不应命中 MAC")

    # ---- USCC（默认关，手动开启验证）----
    def test_uscc_masked_when_enabled(self):
        tr.BUILTIN_RULES["USCC"] = True
        r = self._mask("信用代码 91110108MA01ABCD2E")
        self.assertNotIn("91110108MA01ABCD2E", r, "USCC 应脱敏")

    # ---- re: 正则词 ----
    def test_regex_word_matches(self):
        tr.CUSTOM_WORDS.update({r"re:EMP-\d{6}": "工号"})
        r = self._mask("我的工号是 EMP-123456")
        self.assertNotIn("EMP-123456", r, "正则词应命中")

    def test_bad_regex_word_skipped_not_crash(self):
        # 审计 P0：坏正则词不能导致整个词表崩溃（跳过坏词其余照常）
        tr.CUSTOM_WORDS.update({"re:EMP-[0-9": "坏词", "张三": "人名"})
        r = self._mask("EMP-123456 和张三")
        self.assertNotIn("张三", r, "普通词仍应生效（坏正则词被跳过）")

    # ---- 整词匹配 ----
    def test_whole_word_boundary(self):
        tr.CUSTOM_WORDS.update({"手机": "DEV"})
        tr.SENSITIVE_WORD_WHOLE.add("手机")
        r = self._mask("手机壳和手机")
        # 整词模式：两侧加边界，'手机壳'中的手机不应命中，单独的'手机'应命中
        self.assertIn("手机壳", r, "整词模式下子串不应误伤")
        self.assertNotIn(" 手机", r, "独立词应命中")

    # ---- 大小写不敏感 ----
    def test_case_insensitive_word(self):
        tr.CUSTOM_WORDS.update({"Acme": "ORG"})
        r = self._mask("ACME acme Acme")
        self.assertNotIn("ACME", r, "大写变体应命中")
        self.assertNotIn("acme", r, "小写变体应命中")

    # ---- 前缀 -/_ 等价 ----
    def test_prefix_dash_underscore_equivalent(self):
        tr.SECRET_PREFIXES = ["sk-"]
        r = self._mask("sk_live_1234567890abcdefgh")
        self.assertNotIn("sk_live", r, "sk- 前缀应覆盖 sk_ 形态")


class AuditFailClosedBlockTests(unittest.TestCase):
    """审计 fail-closed 阻断留痕（2026-08-18）：

    CRITICAL 审计信号命中且 AUDIT_FAIL_CLOSED 开启时，除返回 503
    shield_audit_blocked 外，必须写一条 BLOCK 主事件计入首页 alerts
    （此前只有一行 _log，Dashboard 告警数完全看不到）。
    全部 mock（_emit / enqueue_audit_event / 扫描函数），不碰真实端口、进程、DB。
    """

    def _run(self, body, status=500, ct="text/plain"):
        emitted = []
        old_emit, old_audit_ev = tr._emit, tr.enqueue_audit_event
        old_enabled, old_fc = tr.AUDIT_ENABLED, tr.AUDIT_FAIL_CLOSED
        old_floor = tr.AUDIT_SEVERITY_FLOOR
        old_probes = tr.AUDIT_ACTIVE_PROBES
        old_signals = tr.AUDIT_SIGNALS
        try:
            tr._emit = lambda typ, **kw: emitted.append((typ, kw))
            tr.enqueue_audit_event = lambda rec: None
            tr.AUDIT_ENABLED = True
            tr.AUDIT_FAIL_CLOSED = True
            tr.AUDIT_SEVERITY_FLOOR = "MEDIUM"
            tr.AUDIT_ACTIVE_PROBES = False
            tr.AUDIT_SIGNALS = dict(tr.DEFAULT_AUDIT_SIGNALS)
            flow = SimpleNamespace(
                request=SimpleNamespace(
                    method="POST", host="api.example.com", pretty_host="api.example.com",
                    path="/v1/chat/completions?x=1",
                    headers={"content-type": "application/json"},
                    content=b'{"messages":[]}',
                ),
                response=SimpleNamespace(
                    status_code=status,
                    headers={"content-type": ct},
                    content=body.encode("utf-8"),
                ),
                metadata={"shield_upstream": "test-up"},
            )
            tr._audit_response(flow, "sid-1", "api.example.com", "POST",
                               "/v1/chat/completions?x=1", {"client": "127.0.0.1:5"})
            return flow, emitted
        finally:
            tr._emit, tr.enqueue_audit_event = old_emit, old_audit_ev
            tr.AUDIT_ENABLED, tr.AUDIT_FAIL_CLOSED = old_enabled, old_fc
            tr.AUDIT_SEVERITY_FLOOR = old_floor
            tr.AUDIT_ACTIVE_PROBES = old_probes
            tr.AUDIT_SIGNALS = old_signals

    def test_critical_finding_emits_block_and_503(self):
        """真实 sk- 凭据形态（CRITICAL）→ BLOCK 主事件 + 503 shield_audit_blocked。

        凭据串含非十六进制字符（大写/小写字母超出 a-f），保证它不可能作为
        sha256 摘要的子串出现，从而确定性地断言 evidence 是掩码形态。
        """
        secret = "sk-AbC1xY9zQ2mN7vR5tE8wP3sL6dF4gH0jK"
        flow, emitted = self._run('{"err":"%s"}' % secret)
        blocks = [(typ, kw) for typ, kw in emitted if typ == "BLOCK"]
        self.assertEqual(len(blocks), 1, f"应恰好一条 BLOCK，实际 {emitted}")
        kw = blocks[0][1]
        self.assertEqual(kw["reason"], "audit_critical_signal")
        self.assertEqual(kw["signal"], "error_leak")
        self.assertEqual(kw["severity"], "CRITICAL")
        self.assertIn("sk_prefix_secret", kw["evidence"])
        self.assertIn("sha256=", kw["evidence"], "evidence 必须是摘要/掩码形态")
        self.assertNotIn(secret, kw["evidence"], "凭据原文不得进 BLOCK evidence")
        self.assertEqual(kw["sid"], "sid-1")
        self.assertEqual(kw["host"], "api.example.com")
        self.assertEqual(kw["method"], "POST")
        self.assertEqual(kw["path"], "/v1/chat/completions", "path 应剥掉 query")
        self.assertEqual(kw["upstream"], "test-up")
        self.assertEqual(kw.get("client"), "127.0.0.1:5", "source 应透传进 BLOCK")
        self.assertEqual(flow.response.status_code, 503)
        self.assertIn(b"shield_audit_blocked", flow.response.content)

    def test_medium_finding_no_block_no_503(self):
        """低于 CRITICAL（MEDIUM）→ 不阻断、不改响应、无 BLOCK。"""
        with mock.patch.object(tr._audit, "scan_error_leak", return_value=[{
            "signal": "error_leak", "severity": tr._audit.MEDIUM,
            "evidence": "upstream_host: relay.example", "kind": "upstream_host",
        }]):
            flow, emitted = self._run('{"err":"some body"}')
        self.assertFalse(any(typ == "BLOCK" for typ, _ in emitted),
                         f"MEDIUM 不应有 BLOCK: {emitted}")
        self.assertEqual(flow.response.status_code, 500, "MEDIUM 不应替换响应")
        self.assertNotIn(b"shield_audit_blocked", flow.response.content)

    def test_fail_closed_off_does_not_block(self):
        """AUDIT_FAIL_CLOSED=False 时即使 CRITICAL 命中也不阻断（默认安全语义）。"""
        old_fc = tr.AUDIT_FAIL_CLOSED
        emitted = []
        try:
            tr.AUDIT_FAIL_CLOSED = False
            with mock.patch.object(tr._audit, "scan_error_leak", return_value=[{
                "signal": "cross_request_pollution", "severity": tr._audit.CRITICAL,
                "evidence": "prior_canary_recur: CANARY_x", "kind": "prior_canary",
            }]):
                old_emit, old_ae = tr._emit, tr.enqueue_audit_event
                old_enabled, old_floor, old_probes = tr.AUDIT_ENABLED, tr.AUDIT_SEVERITY_FLOOR, tr.AUDIT_ACTIVE_PROBES
                old_signals = tr.AUDIT_SIGNALS
                try:
                    tr._emit = lambda typ, **kw: emitted.append(typ)
                    tr.enqueue_audit_event = lambda rec: None
                    tr.AUDIT_ENABLED = True
                    tr.AUDIT_SEVERITY_FLOOR = "MEDIUM"
                    tr.AUDIT_ACTIVE_PROBES = False
                    tr.AUDIT_SIGNALS = dict(tr.DEFAULT_AUDIT_SIGNALS)
                    flow = SimpleNamespace(
                        request=SimpleNamespace(
                            method="POST", host="api.example.com", pretty_host="api.example.com",
                            path="/v1/chat/completions", headers={"content-type": "application/json"},
                            content=b'{"messages":[]}'),
                        response=SimpleNamespace(
                            status_code=500, headers={"content-type": "text/plain"},
                            content=b'{"err":"boom"}'),
                        metadata={"shield_upstream": "test-up"},
                    )
                    tr._audit_response(flow, "sid-2", "api.example.com", "POST",
                                       "/v1/chat/completions", {"client": "127.0.0.1:5"})
                finally:
                    tr._emit, tr.enqueue_audit_event = old_emit, old_ae
                    tr.AUDIT_ENABLED, tr.AUDIT_SEVERITY_FLOOR, tr.AUDIT_ACTIVE_PROBES = old_enabled, old_floor, old_probes
                    tr.AUDIT_SIGNALS = old_signals
        finally:
            tr.AUDIT_FAIL_CLOSED = old_fc
        self.assertFalse(any(typ == "BLOCK" for typ in emitted), f"关掉 fail-closed 不应阻断: {emitted}")
        self.assertEqual(flow.response.status_code, 500)


if __name__ == "__main__":
    unittest.main()
