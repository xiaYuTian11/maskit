"""真实上游端到端验收（不是进程内 mock，每条都发真实 HTTP 请求）。

存在的理由：单测全绿但用户实际使用一直出问题。根因是单测只覆盖「模型原样回显
占位符」，而真实模型会加工输出——剥花括号、拆分、拼进命令、放进工具参数。
所以这里一律走真网络：客户端 -> Maskit 反代端口 -> 真实中转 -> 真实模型。

判定标准只有一条：**上游收到的字节里不许出现原文，客户端收到的字节里必须是原文**。

用法：
    python tests/e2e_real_upstream.py            # 全部场景
    python tests/e2e_real_upstream.py 工具        # 只跑名字含「工具」的场景

密钥从环境变量 LLM_SHIELD_API_KEY 读（与 real_proxy_check.py 同一套变量名），全程不打印；
反代端口用 LLM_SHIELD_E2E_PROXY 覆盖（默认 http://127.0.0.1:18709/v1/chat/completions）。
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

# Maskit 反代端口：指向你在面板里配置的任一客户端入口（端口 + 路径）
PROXY = os.environ.get("LLM_SHIELD_E2E_PROXY") or "http://127.0.0.1:18709/v1/chat/completions"
MODEL = os.environ.get("LLM_SHIELD_TEST_MODEL") or "deepseek-v4-flash"
# 每个场景换一组真值，避免上一轮的复用表命中掩盖本轮的脱敏失败
# 明显伪造的高熵串：形态够像凭据以触发 SECRET 规则，但不是任何真实系统的 key
SECRET = "sk-e2e-test-0000000000000000000000000000000000"
PHONE = "13800138000"
EMAIL = "zhang.san@internal-corp.com"


def _api_key() -> str:
    key = os.environ.get("LLM_SHIELD_API_KEY") or ""
    if not key:
        sys.exit("缺少环境变量 LLM_SHIELD_API_KEY（真实上游 key，不写死在代码里）")
    return key


def call(body: dict, stream: bool = False, timeout: int = 120):
    """走 Maskit 代理发一次真实请求，返回 (状态码, 原始文本)。

    带浏览器 UA：上游 Cloudflare 对裸 urllib 直接 1010 拒绝（实测），
    与 Maskit 无关但会污染判定。identity 编码是为了拿到未压缩的 SSE。
    """
    data = json.dumps(dict(body, model=MODEL, stream=stream), ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(PROXY, data=data, method="POST", headers={
        "content-type": "application/json",
        "authorization": f"Bearer {_api_key()}",
        "accept-encoding": "identity",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


PANEL = "http://127.0.0.1:5801"


def _panel_token() -> str:
    p = pathlib.Path(os.environ["APPDATA"]) / "Maskit" / "proxy_token"
    return p.read_text(encoding="utf-8").strip() if p.exists() else ""


def newest_mask_event(after_seq: int = 0):
    """取 seq 大于 after_seq 的最新一条 MASK 事件。

    这是本脚本的另一半判定，比「客户端拿到真值」更关键：如果脱敏根本没发生，
    原文原样穿过代理，客户端当然也能拿到真值——测试会假绿。必须回查引擎自己
    记录的 MASK 事件，确认这次请求确实产生了占位符。
    """
    req = urllib.request.Request(
        f"{PANEL}/api/logs?limit=60", headers={"X-Shield-Token": _panel_token()})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode("utf-8"))
    except Exception:
        return None
    evs = d.get("events") or d.get("logs") or []
    masks = [e for e in evs
             if (e.get("kind") or e.get("type")) == "MASK" and int(e.get("seq") or 0) > after_seq]
    return max(masks, key=lambda e: int(e.get("seq") or 0)) if masks else None


def find_mask_event(nonce: str, after_seq: int = 0):
    """按本次请求携带的唯一标记，精确定位属于它的 MASK 事件。

    不能简单取「最新一条 MASK」：本机的 Pi/编辑器等客户端同时在走同一个代理端口，
    最新事件很可能是别人的流量，导致「上游确实脱敏了」这条判定误判为通过。
    nonce 是一段普通字母数字串，不会被任何规则命中，因此会原样出现在脱敏后的
    req_preview 里，可以拿来做关联。
    """
    req = urllib.request.Request(
        f"{PANEL}/api/logs?limit=80&fulltext=1", headers={"X-Shield-Token": _panel_token()})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read().decode("utf-8"))
    except Exception:
        return None
    evs = d.get("events") or d.get("logs") or []
    for e in sorted(evs, key=lambda x: int(x.get("seq") or 0), reverse=True):
        if (e.get("kind") or e.get("type")) != "MASK":
            continue
        if int(e.get("seq") or 0) <= after_seq:
            break
        blob = f"{e.get('req_preview') or ''}{e.get('dialog') or ''}"
        if nonce in blob:
            return e
    return None


def current_seq() -> int:
    req = urllib.request.Request(
        f"{PANEL}/api/logs?limit=1", headers={"X-Shield-Token": _panel_token()})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode("utf-8"))
        evs = d.get("events") or d.get("logs") or []
        return max((int(e.get("seq") or 0) for e in evs), default=0)
    except Exception:
        return 0


def sse_text(raw: str) -> str:
    """把 SSE 流拼回完整文本（含工具参数增量）。"""
    out = []
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload in ("", "[DONE]"):
            continue
        try:
            ev = json.loads(payload)
        except Exception:
            continue
        for ch in ev.get("choices") or []:
            d = ch.get("delta") or {}
            if d.get("content"):
                out.append(d["content"])
            for tc in d.get("tool_calls") or []:
                fn = tc.get("function") or {}
                if fn.get("arguments"):
                    out.append(fn["arguments"])
    return "".join(out)


def body_text(raw: str) -> str:
    """非流式响应：把 content + 所有工具参数拼成一段可检查的文本。"""
    try:
        d = json.loads(raw)
    except Exception:
        return raw
    out = []
    for ch in d.get("choices") or []:
        m = ch.get("message") or {}
        if m.get("content"):
            out.append(str(m["content"]))
        if m.get("reasoning_content"):
            out.append(str(m["reasoning_content"]))
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function") or {}
            out.append(str(fn.get("name", "")))
            out.append(str(fn.get("arguments", "")))
    return "\n".join(out)


WEATHER_TOOL = {
    "type": "function",
    "function": {
        "name": "send_sms",
        "description": "给指定手机号发送短信",
        "parameters": {
            "type": "object",
            "properties": {
                "phone": {"type": "string", "description": "收件人手机号"},
                "body": {"type": "string", "description": "短信正文"},
            },
            "required": ["phone", "body"],
        },
    },
}
LOOKUP_TOOL = {
    "type": "function",
    "function": {
        "name": "lookup_user",
        "description": "按邮箱查用户资料",
        "parameters": {
            "type": "object",
            "properties": {"email": {"type": "string"}},
            "required": ["email"],
        },
    },
}


# ---- 场景定义：(名字, 构造请求, 是否流式, 本场景必须还原回来的真值列表) ----

def s_tool_single():
    return {"messages": [
        {"role": "user", "content": f"给手机号 {PHONE} 发条短信，内容是「验收通过」。直接调用工具。"},
    ], "tools": [WEATHER_TOOL], "tool_choice": "auto"}, False, [PHONE]


def s_tool_stream():
    return {"messages": [
        {"role": "user", "content": f"给手机号 {PHONE} 发条短信，内容是「流式验收」。直接调用工具。"},
    ], "tools": [WEATHER_TOOL], "tool_choice": "auto"}, True, [PHONE]


def s_tool_parallel():
    return {"messages": [
        {"role": "user", "content": (
            f"同时做两件事：1) 给手机号 {PHONE} 发短信「并行验收」；"
            f"2) 用邮箱 {EMAIL} 查用户资料。两个工具都要调用。")},
    ], "tools": [WEATHER_TOOL, LOOKUP_TOOL], "tool_choice": "auto"}, False, [PHONE, EMAIL]


def s_system_prompt():
    return {"messages": [
        {"role": "system", "content": f"运维联系人手机号是 {PHONE}，联系邮箱 {EMAIL}。"},
        {"role": "user", "content": "把 system 里给的运维联系人手机号和邮箱原样复述一遍，各占一行，不要加任何解释。"},
    ]}, False, [PHONE, EMAIL]


def s_multi_turn():
    """多轮：历史里已经带着上一轮的工具调用与工具结果，本轮要求复用。"""
    return {"messages": [
        {"role": "user", "content": f"给 {PHONE} 发短信"},
        {"role": "assistant", "tool_calls": [{
            "id": "call_e2e_1", "type": "function",
            "function": {"name": "send_sms",
                         "arguments": json.dumps({"phone": PHONE, "body": "第一轮"}, ensure_ascii=False)},
        }]},
        {"role": "tool", "tool_call_id": "call_e2e_1",
         "content": json.dumps({"ok": True, "sent_to": PHONE}, ensure_ascii=False)},
        {"role": "user", "content": "刚才发给哪个号码了？只回号码本身，不要别的字。"},
    ]}, False, [PHONE]


def s_embed_in_command():
    """模型加工输出：把值拼进 shell 命令。历史故障点——模型会剥掉花括号。"""
    return {"messages": [
        {"role": "user", "content": (
            f"这是安装令牌：{SECRET}\n"
            "写一条 curl 命令，把它放进 X-Setup-Token 请求头，"
            "打到 https://example.com/api/setup。只输出命令本身。")},
    ]}, False, [SECRET]


def s_json_output():
    """要求模型输出 JSON：值会被再套一层转义，还原要能穿过转义。"""
    return {"messages": [
        {"role": "user", "content": (
            f"手机号 {PHONE}，邮箱 {EMAIL}。"
            '输出一个 JSON 对象，形如 {"phone":"...","email":"..."}，只输出 JSON。')},
    ]}, False, [PHONE, EMAIL]


def s_tool_result_roundtrip():
    """工具结果里的真值：请求侧要脱敏，响应侧模型复述时要还原。"""
    return {"messages": [
        {"role": "user", "content": "查一下用户资料"},
        {"role": "assistant", "tool_calls": [{
            "id": "call_e2e_2", "type": "function",
            "function": {"name": "lookup_user",
                         "arguments": json.dumps({"email": EMAIL}, ensure_ascii=False)},
        }]},
        {"role": "tool", "tool_call_id": "call_e2e_2",
         "content": json.dumps({"email": EMAIL, "phone": PHONE, "name": "张三"}, ensure_ascii=False)},
        {"role": "user", "content": "把工具返回里的 email 和 phone 各复述一行，不要解释。"},
    ]}, False, [EMAIL, PHONE]


SCENARIOS = [
    ("工具调用-单个-非流式", s_tool_single),
    ("工具调用-单个-流式", s_tool_stream),
    ("工具调用-并行两个", s_tool_parallel),
    ("system 提示词", s_system_prompt),
    ("多轮历史复用", s_multi_turn),
    ("模型加工-拼进命令", s_embed_in_command),
    ("模型加工-输出JSON", s_json_output),
    ("工具结果回环", s_tool_result_roundtrip),
]


def main():
    flt = sys.argv[1] if len(sys.argv) > 1 else ""
    rows = []
    t_start = time.time()
    for idx, (name, build) in enumerate(SCENARIOS):
        if flt and flt not in name:
            continue
        body, stream, expects = build()
        # 给本次请求打一个不会被任何规则命中的唯一标记，用于在并发流量里认领自己的事件
        nonce = f"e2etag{idx:02d}x{int(t_start)%100000}"
        body = dict(body)
        body["messages"] = list(body["messages"]) + [
            {"role": "user", "content": f"(忽略这行标记 {nonce})"}
        ]
        seq0 = current_seq()
        t0 = time.time()
        code, raw = call(body, stream=stream)
        dt = time.time() - t0
        text = sse_text(raw) if stream else body_text(raw)
        time.sleep(1.5)  # 事件是异步批量落库，给写队列一点时间
        ev = find_mask_event(nonce, seq0)

        # 判定 1：客户端拿到的必须是真值（脱敏对使用者透明）
        got = [v for v in expects if v in text]
        missing = [v for v in expects if v not in text]
        # 判定 2：绝不能有残留占位符漏到客户端
        leaked_ph = "{{" in text or any(
            seg in text for seg in ("PHONE_", "EMAIL_", "SECRET_", "TOKEN_", "API_KEY_")
        )
        # 判定 3（关键）：引擎确实为本次请求的每个真值都铸了占位符。
        #
        # 这里不能用 req_preview 判断「上游字节里有没有原文」——面板在写事件时
        # 会对预览再做一次凭据打码，未脱敏的原文照样显示成 [REDACTED]，
        # 拿它做判定会把「脱敏根本没发生」判成通过（实测：关掉 SECRET 规则后
        # count=0、原文确实上行，而 preview 检查仍然是绿的）。
        #
        # 可靠且不依赖明文的信号是事件里的 items[].length：凭据类不落原文，
        # 但一定记了长度。逐个期望值按长度对账，就能确认它真的被铸成了占位符。
        items = (ev or {}).get("items") or []
        lengths = [int(i.get("length") or 0) for i in items]
        unmasked = []
        remaining = list(lengths)
        for v in expects:
            if len(v) in remaining:
                remaining.remove(len(v))
            else:
                unmasked.append(v)
        found_ev = ev is not None
        upstream_clean = found_ev and not unmasked

        ok = code == 200 and not missing and not leaked_ph and found_ev and upstream_clean
        rows.append((name, ok))
        status = "PASS" if ok else "FAIL"
        up = "全部脱敏" if upstream_clean else ("有漏网" if found_ev else "事件未找到")
        print(f"[{status}] {name:<20} HTTP {code}  客户端还原 {len(got)}/{len(expects)}"
              f"  上游={up}({len(items)}项)  残留占位符={'是' if leaked_ph else '否'}  {dt:.1f}s")
        if not ok:
            if missing:
                print(f"       未还原: {missing}")
            if found_ev and unmasked:
                print(f"       !! 未脱敏即上行: {unmasked}")
                print(f"       事件 count={ev.get('count')} items 长度={lengths}")
            elif not found_ev:
                print("       没找到本次请求的 MASK 事件（可能请求根本没进脱敏管线）")
            print(f"       客户端输出: {text[:300]!r}")
        time.sleep(1)  # 别把上游打出限流

    print("\n" + "=" * 70)
    passed = sum(1 for r in rows if r[1])
    print(f"合计 {passed}/{len(rows)} 通过")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
