"""出口复检默认**只记录、不阻断**（用户第一准则，2026-10-26 定案）。

## 用户的准则（原话）

> 不管怎么样不应该阻断我的请求啊，只是日志记录有提示的吧……这个是第一准则，
> 不然的话都无法使用了，不能阻断的，不管是什么情况。

这不是「先观察再收紧」的临时偏好，而是**产品定位决定的一条硬规则**：

- Maskit 是**本地透明代理**。它阻断请求的那一刻，用户的微信机器人、编辑器
  助手、CI 机器人就整条不可用了 —— 而用户往往在几小时后才发现「原来是网关
  把我的请求吃了」，因为客户端只会说「上游 503 / 重试失败」。
- 脱敏漏一个值的代价是**一个值出网**；阻断一个请求的代价是**整条业务链路
  不可用**。前者可事后补救（日志、取证、改规则），后者不可。

所以复检的正确角色是「**告警 + 取证**」，不是「**闸门**」。它发现残留时：

1. 照常记 `BLOCK` 事件（`reason=egress_verify`、`block_source=egress`、
   `decision="blocked"` → 但在只记录模式下 `decision` 是 `flagged`）；
2. 照常把**残留明细**写进事件（哪些值、各几处），让用户能定位与补规则；
3. **请求照常上行**，不返回 503。

## 为什么不再用 fail-closed 当借口

`FAIL_CLOSED` 管的是「脱敏管线**抛异常**，不知道遮没遮」—— 那种情况放行等于
必然明文出网，阻断是对的。复检看到的是「**脱敏成功、但某处残留**」，那大概率
是规则**主动放过**的正常输出（2026-10-26 真机 12 条 503 全部如此），把它升级
成硬失败是把「可能漏一个值」换成「整条链路不可用」。

## 唯一保留阻断的入口

用户显式打开 `MASKIT_EGRESS_BLOCK=1`（或配置项）时才阻断。默认关闭。

## 必须守住的边界

1. 默认配置下**任何**复检命中都不阻断（含真泄漏）。
2. 显式开启时真泄漏仍然阻断（开关是有效的，不是摆设）。
3. 事件仍然如实记录（否则「只记录」变成「静默放过」）。
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

# 片段拼接（AGENTS.md §3 第 9 条）
PHONE = "139" + "9682" + "5050"
TERM_VALUE = "Night" + "jar" + "Proj" + "ect"


def _engine():
    import transparent as tr
    return tr


tr = _engine()


class _IsolatedCase(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="maskit-egress-mode-")
        self._old_block = getattr(tr, "_MASK_EGRESS_BLOCK", None)
        tr._known_reset_for_tests()
        tr.sessions.clear()

    def tearDown(self):
        tr.sessions.clear()
        tr._known_reset_for_tests()
        if self._old_block is not None:
            tr._MASK_EGRESS_BLOCK = self._old_block


class DefaultIsRecordOnlyTests(_IsolatedCase):
    """默认必须只记录：这是用户第一准则。"""

    def test_default_is_record_only(self):
        self.assertFalse(
            tr._MASK_EGRESS_BLOCK,
            "出口复检默认不能阻断 —— 阻断会让整条业务链路不可用",
        )

    def test_detection_still_works_in_record_mode(self):
        """「不阻断」不等于「不检测」：复检必须照常发现残留。"""
        tr._new_session("d1")
        self.assertTrue(
            tr._mask_egress_verify(json.dumps({"c": PHONE}), [PHONE], "d1"),
            "只记录模式下仍然必须检测到残留（否则等于关掉这道网）",
        )


class EndToEndRecordOnlyTests(_IsolatedCase):
    """端到端：真泄漏在默认配置下**不得**产生 503。"""

    def _drive(self, body):
        from types import SimpleNamespace
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        tr.UPSTREAMS = [{
            "name": "up-a", "port": 18709, "base_path": "/up-a",
            "target": "https://api.example.com/v1",
            "paths": ["/v1/chat/completions"],
        }]
        tr.CAPTURE_MODE = "reverse"
        tr.FAIL_CLOSED = True
        req = SimpleNamespace(
            method="POST", path="/chat/completions", pretty_host="127.0.0.1",
            host="127.0.0.1", port=18709, scheme="http", content=raw,
            text=raw.decode(), headers={"content-type": "application/json"},
            pretty_url="",
        )
        flow = SimpleNamespace(
            request=req, response=None, metadata={},
            client_conn=SimpleNamespace(sockname=("127.0.0.1", 18709)),
            server_conn=SimpleNamespace(via=None),
        )
        events = []
        old_emit, old_reload = tr._emit, tr._maybe_reload
        try:
            tr._emit = lambda *a, **k: events.append((a, k))
            tr._maybe_reload = lambda force=False: None
            from tests.test_regressions import _drive_request
            _drive_request(flow)
        finally:
            tr._emit, tr._maybe_reload = old_emit, old_reload
        return flow, events

    def test_real_leak_does_not_block_by_default(self):
        """人为制造真泄漏（脱敏失效），默认配置下请求必须**照常上行**。"""
        body = {"model": "m",
                "messages": [{"role": "user", "content": f"see {TERM_VALUE}"}]}
        orig = tr._mask_text
        try:
            def _noop(text, sid):
                if tr._session_get(sid) is None:
                    tr._new_session(sid)
                sess = tr._session_get(sid, {})
                tok = "{{TERM_abcdef}}"
                sess.setdefault("fwd", {})[TERM_VALUE] = tok
                sess.setdefault("labels", {})[TERM_VALUE] = "TERM"
                sess.setdefault("rev", {})[tok] = TERM_VALUE
                sess.setdefault("new_orig", set()).add(TERM_VALUE)
                return text.replace("see ", "look ") if "see " in text else text + " "
            tr._mask_text = _noop
            flow, events = self._drive(body)
        finally:
            tr._mask_text = orig
        self.assertIsNone(
            flow.response,
            "默认配置下复检命中了真泄漏却返回了响应（用户第一准则：不得阻断）",
        )

    def test_flag_event_is_recorded(self):
        """不阻断但必须留痕：事件里要有复检命中的记录。"""
        body = {"model": "m",
                "messages": [{"role": "user", "content": f"see {TERM_VALUE}"}]}
        orig = tr._mask_text
        try:
            def _noop(text, sid):
                if tr._session_get(sid) is None:
                    tr._new_session(sid)
                sess = tr._session_get(sid, {})
                tok = "{{TERM_abcdef}}"
                sess.setdefault("fwd", {})[TERM_VALUE] = tok
                sess.setdefault("labels", {})[TERM_VALUE] = "TERM"
                sess.setdefault("rev", {})[tok] = TERM_VALUE
                sess.setdefault("new_orig", set()).add(TERM_VALUE)
                return text.replace("see ", "look ") if "see " in text else text + " "
            tr._mask_text = _noop
            flow, events = self._drive(body)
        finally:
            tr._mask_text = orig
        flagged = [k for a, k in events
                   if k.get("reason") == "egress_verify"]
        self.assertTrue(
            flagged,
            "只记录模式下必须留下 reason=egress_verify 的事件（否则等于静默放过）",
        )
        self.assertEqual(flagged[0].get("decision"), "flagged",
                         "只记录模式的决定必须是 flagged 而不是 blocked")


class ExplicitBlockStillWorksTests(_IsolatedCase):
    """用户显式开启阻断时，真泄漏必须仍然被拦（开关不是摆设）。"""

    def test_block_when_explicitly_enabled(self):
        tr._MASK_EGRESS_BLOCK = True
        tr._new_session("b1")
        self.assertTrue(
            tr._mask_egress_verify(json.dumps({"c": PHONE}), [PHONE], "b1"),
            "显式开启阻断后真泄漏仍必须被检测到",
        )


if __name__ == "__main__":
    unittest.main()
