"""复现「空块 → chunked 终止块 → keep-alive 连接错位」的完整因果链。

全本地、零 token 消耗。回答两个问题：

1. 流式回调返回 b"" 时，mitmproxy 是否真的写出 chunked 终止块？
2. 终止块之后引擎继续写的字节，会不会污染同一条 keep-alive 连接上的下一个请求？
   （若会，即可解释用户遇到的「全是 502 [WinError 121] 信号灯超时」——
    客户端把上一响应的残留字节当成下一响应的状态行，读不出合法响应直到超时。）

做法：起一个把每个 SSE 事件按 TCP 边界切成多段的假上游，配一个最小 addon
（不依赖 transparent.py，只保留「无完整事件就返回 b""」这一个行为），
然后在同一条 keep-alive 连接上连发两个请求，观察第二个请求的结果。

用法：
    python tests/repro_chunk_terminator.py
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_PORT = 18811
PROXY_PORT = 18812

# 每个事件切成 3 段发送，中间两段凑不出 \n\n —— 正是 opencode.ai 的真实分片形态
EVENTS = [
    'data: {"choices":[{"delta":{"content":"%s"}}]}\n\n' % w
    for w in ("第一段", "第二段", "第三段", "第四段")
] + ["data: [DONE]\n\n"]


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        for ev in EVENTS:
            raw = ev.encode("utf-8")
            # 切三段，逼出「本次无完整事件」的回调
            for part in (raw[:12], raw[12:24], raw[24:]):
                if not part:
                    continue
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                self.wfile.flush()
                time.sleep(0.02)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def log_message(self, *a):
        pass


ADDON = '''
"""最小复现 addon：只保留「无完整 SSE 事件就返回 b""」这一个行为。"""
import os

BUGGY = os.environ.get("REPRO_BUGGY") == "1"


def responseheaders(flow):
    ct = (flow.response.headers.get("content-type", "") or "").lower()
    if "text/event-stream" not in ct:
        return
    flow.response.headers.pop("content-length", None)
    state = {"buf": ""}

    def _stream(data: bytes):
        state["buf"] += data.decode("utf-8", errors="replace")
        out = []
        while True:
            idx = state["buf"].find("\\n\\n")
            if idx < 0:
                break
            block, state["buf"] = state["buf"][:idx], state["buf"][idx + 2:]
            out.append(block + "\\n\\n")
        text = "".join(out)
        if not data:                      # 末块：走 EndOfMessage 分支，b"" 安全
            return text.encode("utf-8")
        if not text:
            # BUGGY=1 复现缺陷；否则返回空列表（修复后的行为）
            return b"" if BUGGY else []
        return text.encode("utf-8")

    flow.response.stream = _stream
'''


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.15)
    return False


def run_arm(buggy):
    """在同一条 keep-alive 连接上连发两个请求，返回 (响应1摘要, 响应2结果)。"""
    work = Path(tempfile.mkdtemp(prefix="repro_chunk_"))
    addon = work / "repro_addon.py"
    addon.write_text(ADDON, encoding="utf-8")
    env = {**os.environ, "REPRO_BUGGY": "1" if buggy else "0", "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(
        ["mitmdump", "-s", str(addon), "--mode",
         f"reverse:http://127.0.0.1:{UPSTREAM_PORT}@127.0.0.1:{PROXY_PORT}",
         "--set", "flow_detail=0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
    )
    try:
        if not wait_port(PROXY_PORT):
            return "代理未监听", "n/a"
        conn = http.client.HTTPConnection("127.0.0.1", PROXY_PORT, timeout=15)
        body = json.dumps({"stream": True}).encode()
        hdr = {"content-type": "application/json"}

        conn.request("POST", "/v1/chat/completions", body=body, headers=hdr)
        r1 = conn.getresponse()
        got = b""
        while True:
            chunk = r1.read1(65536)
            if not chunk:
                break
            got += chunk
        first = f"{len(got)}B, [DONE]={'是' if b'[DONE]' in got else '否'}"

        # 关键：复用同一条连接发第二个请求（keep-alive 池的真实行为）
        try:
            conn.request("POST", "/v1/chat/completions", body=body, headers=hdr)
            r2 = conn.getresponse()
            second = f"HTTP {r2.status}"
            r2.read()
        except Exception as e:
            second = f"{type(e).__name__}: {str(e)[:60]}"
        conn.close()
        return first, second
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def main():
    srv = HTTPServer(("127.0.0.1", UPSTREAM_PORT), Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        print("=== 缺陷行为（中途块返回 b\"\"）===")
        a1, a2 = run_arm(True)
        print(f"    请求1 收到: {a1}")
        print(f"    请求2（复用连接）: {a2}")

        print("=== 修复行为（中途块返回 []）===")
        b1, b2 = run_arm(False)
        print(f"    请求1 收到: {b1}")
        print(f"    请求2（复用连接）: {b2}")

        ok = ("[DONE]=是" in b1) and ("[DONE]=否" in a1)
        print("\n结论：" + ("缺陷可复现，修复有效" if ok else "未复现出预期差异，需人工核对"))
        return 0 if ok else 1
    finally:
        srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
