#!/usr/bin/env python3
"""端到端冒烟：真实 mitmdump + takeover 上游，验证 C1 接管链路与连接复用。

与 `smoke_stream.py` 的分工：那个验透明层的脱敏/还原/流式；本脚本专验
「takeover=true 时请求真的走了 sidecar，且上游连接被复用」——这是 C1 声称的
核心收益（把每请求一次 TCP+TLS 握手换成按连接复用），也是单测证明不了的部分：
sidecar 单测用 mock 上游，路由单测根本不连 mitmproxy。

判据全部不经网关：
- 上游实例自己记录的 TCP 连接数（对照组与接管组各起一个独立实例，互不污染）
- mitmdump 日志里的 sidecar 启动行
- 客户端收到的还原文本（接管不能把脱敏/还原改坏）

跑两遍：takeover=false（对照）与 takeover=true（接管），各 3 次请求。
"""
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
TRANSPARENT_PY = ROOT / "engine" / "transparent.py"
sys.path.insert(0, str(ROOT / "engine"))

import transparent as TR  # noqa: E402  （占位符判据只认产品侧那一份正则）

PROXY_PORT = 18995
UPSTREAM_PORT_BASE = 18996      # 对照组 18996 / 接管组 18997（每遍独立实例）
CHUNK_DELAY = 0.15              # 上游每块间隔（够慢到能验跨块还原，又不拖长 CI）
CHUNKS = 5
REQUESTS = 3
ENTITY = "王大锤"
# 形如真实 SSE 的响应块数固定，便于客户端按块校验
STATE = {"conns": 0, "bodies": []}


class FakeUpstream(BaseHTTPRequestHandler):
    """假上游：慢速吐 SSE，并记录 TCP 连接数与收到的请求体。"""

    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        STATE["conns"] += 1

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length)
        STATE["bodies"].append(body.decode("utf-8", errors="replace"))
        masked = json.loads(body)["messages"][0]["content"]
        # 从脱敏后的请求里取出占位符，切成两半跨 chunk 回显（模拟模型复述）：
        # 用产品侧正则而不是自己写死格式，格式一改这里不会静默失效。
        tokens = re.findall(TR._PLACEHOLDER_RX, masked)
        token = tokens[0] if tokens else "NOPLACEHOLDER"
        half = len(token) // 2
        self._stream_sse(["联系人是", token[:half], token[half:], "，请周知。", ""])

    def _stream_sse(self, pieces):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for i in range(CHUNKS):
            piece = pieces[i] if i < len(pieces) else ""
            evt = {"id": "chatcmpl-x", "object": "chat.completion.chunk", "model": "m",
                   "choices": [{"index": 0, "delta": {"content": piece}}]}
            # CRLF 是真实服务常用形式，也顺带覆盖「只识别 LF」那个老坑
            data = ("data: " + json.dumps(evt, ensure_ascii=False) + "\r\n\r\n").encode("utf-8")
            self._write_chunk(data)
            time.sleep(CHUNK_DELAY)
        self._write_chunk(b"data: [DONE]\r\n\r\n")
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _write_chunk(self, payload):
        self.wfile.write(("%x\r\n" % len(payload)).encode("ascii"))
        self.wfile.write(payload)
        self.wfile.write(b"\r\n")
        self.wfile.flush()


def wait_port(port, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.4)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def run_pass(takeover, upstream_port):
    """跑一遍真实 mitmdump，返回 (是否起来, 客户端收到的文本列表, mitmdump 日志)。"""
    work = ROOT / "_smoke_data" / ("takeover_on" if takeover else "takeover_off")
    work.mkdir(parents=True, exist_ok=True)
    cfg = {
        "capture_mode": "reverse",
        "sensitive": {"人名": [ENTITY]},
        "upstreams": [{
            "name": "smoke", "base_path": "/smoke", "port": PROXY_PORT,
            "target": "http://127.0.0.1:%d" % upstream_port,
            "paths": ["/v1/chat/completions"],
            "takeover": takeover,
        }],
        "filter_enabled": True, "fail_closed": True, "session_ttl": 600,
    }
    (work / "config.json").write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")

    env = {**os.environ, "LLM_SHIELD_DATA_DIR": str(work), "PYTHONUTF8": "1",
           "PYTHONPATH": str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")}
    mitm_cmd = shutil.which("mitmdump") or str(pathlib.Path(sys.executable).parent / "mitmdump")
    proc = subprocess.Popen(
        [mitm_cmd, "-s", str(TRANSPARENT_PY), "--listen-host", "127.0.0.1",
         "--mode", "reverse:http://127.0.0.1:%d@%d" % (upstream_port, PROXY_PORT),
         "--set", "flow_detail=0", "--set", "connection_strategy=lazy"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", env=env,
    )
    logs = []
    threading.Thread(target=lambda: [logs.append(l) for l in proc.stdout], daemon=True).start()
    texts = []
    try:
        if not wait_port(PROXY_PORT):
            return False, texts, logs
        for _ in range(REQUESTS):
            payload = json.dumps({"model": "m", "stream": True,
                                  "messages": [{"role": "user",
                                                 "content": "客户%s请回电" % ENTITY}]},
                                 ensure_ascii=False).encode("utf-8")
            # connection: close = 真实客户端的「每请求新建 TCP」，这正是 C1 要治的形态
            req = Request("http://127.0.0.1:%d/v1/chat/completions" % PROXY_PORT,
                          data=payload,
                          headers={"content-type": "application/json",
                                   "connection": "close"}, method="POST")
            with urlopen(req, timeout=60) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            texts.append("".join(
                json.loads(l[6:])["choices"][0]["delta"].get("content", "")
                for l in body.splitlines() if l.startswith("data: {")))
        time.sleep(0.5)  # 让 mitmdump 把 sidecar 启动行刷进管道
        return True, texts, logs
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


def check_pass(label, texts, bodies, conns, logs, expect_takeover):
    ok = True
    for i, text in enumerate(texts):
        if ENTITY not in text:
            print("FAIL [%s] 第 %d 条响应未还原：%r" % (label, i + 1, text))
            ok = False
        elif "{{" in text:
            print("FAIL [%s] 第 %d 条响应残留占位符：%r" % (label, i + 1, text))
            ok = False
    if ok and texts:
        print("PASS [%s] %d 条响应全部还原（跨 chunk 占位符无残留）" % (label, len(texts)))
    for i, b in enumerate(bodies):
        if ENTITY in b:
            print("FAIL [%s] 第 %d 条请求未脱敏，原文泄漏到上游" % (label, i + 1))
            ok = False
    if ok and bodies:
        print("PASS [%s] 上游收到 %d 条请求，均无敏感原文" % (label, len(bodies)))

    started = any("[C1] sidecar started" in line for line in logs)
    if expect_takeover:
        if started:
            print("PASS [takeover] 日志确认 sidecar 已启动（接管真的生效）")
        else:
            print("FAIL [takeover] 日志里没有 sidecar 启动行 —— 接管没生效")
            ok = False
        if conns <= 2:
            print("PASS [takeover] %d 次请求只建了 %d 条上游连接（池已复用）"
                  % (len(bodies), conns))
        else:
            print("FAIL [takeover] %d 次请求建了 %d 条上游连接 —— 连接池没复用"
                  % (len(bodies), conns))
            ok = False
    else:
        print("INFO [baseline] %d 次请求建了 %d 条上游连接（对照组，不作断言："
              "mitmproxy 自身的复用行为不在本脚本保护范围）" % (len(bodies), conns))
        if conns <= 2:
            print("WARN [baseline] 对照组也复用了上游连接，本机 run 下 C1 的收益"
                  "无法从对比中体现（判据仍成立：接管组必须 ≤ 2）")
    return ok


def main():
    ok = True
    for takeover, label in ((False, "baseline"), (True, "takeover")):
        STATE["conns"] = 0
        STATE["bodies"] = []
        upstream_port = UPSTREAM_PORT_BASE + (1 if takeover else 0)
        srv = ThreadingHTTPServer(("127.0.0.1", upstream_port), FakeUpstream)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            print("--- 第 %d 遍：takeover=%s ---"
                  % (2 if takeover else 1, "true" if takeover else "false（对照）"))
            started, texts, logs = run_pass(takeover, upstream_port)
            if not started:
                print("FAIL: 代理端口未监听\n" + "".join(logs[-30:]))
                return 1
            ok &= check_pass(label, texts, STATE["bodies"], STATE["conns"],
                             logs, takeover)
        finally:
            srv.shutdown()
            srv.server_close()
    print("SMOKE TAKEOVER " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
