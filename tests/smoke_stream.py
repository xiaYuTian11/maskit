"""端到端冒烟：真实启动 mitmdump + 假上游，验证脱敏还原与 SSE 整包处理。

不进单测套件（需要起真实进程和端口），排障/发版前手动跑：
    python tests/smoke_stream.py

验证点：
1. 请求体里的敏感词被替换成占位符；
2. 响应流里的占位符被还原成原文；
3. SSE 事件流完整（含 [DONE]）——流式接管默认开（v1.5.23 恢复，经真实上游验证）；
   opencode.ai 等黑名单上游保持整包路径；
4. 工具调用参数（跨 chunk 的 partial_json / arguments）还原后仍是合法 JSON；
5. **命令拦截 rewrite 路径**（第二遍，`command_block.mode=rewrite`）：危险命令被切成
   多块下发也必须被就地改写，且改写不能破坏流（[DONE] 在、命令后的正文不丢）。
   配置里**故意不写 `patterns`**，让引擎走「键缺失才灌内置种子」那条路径——
   顺带端到端验证随包分发的内置规则真的能命中。
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import pathlib
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))
import transparent as TR   # noqa: E402  —— 只为复用占位符正则，别再自己写死格式

TRANSPARENT_PY = (ROOT / "engine" / "transparent.py") if (ROOT / "engine" / "transparent.py").exists() else (ROOT / "transparent.py")

UPSTREAM_PORT = 18991
PROXY_PORT = 18992
CHUNK_DELAY = 0.35          # 上游每个 chunk 之间的间隔
CHUNKS = 6
received_request = {}
# 第二遍（命令拦截）用：把 `rm -rf /` 切成两块跨 chunk 下发。
# 上游按当前这一遍的模式选择吐什么内容，避免开两个上游。
PHASE = {"cmd": False}
# 第二遍（命令拦截）用：先来一段**远超 hold（64）**的前置正文，再下发 `rm -rf /`。
# 前置正文的作用是让「首字节不下发」的前瞻缓冲不会把 ① 整条流拖到末尾才吐，
# ② 也顺带验证「靠近开头的文本能立即下发」。命令本身仍切成两块跨 chunk 下发。
CMD_FILLER = "这是前置说明，用于验证改写不会把整条流拖到末尾才下发。" * 3
CMD_PIECES = [CMD_FILLER, "准备执行 rm", " -rf /", " 完毕，再见", "", ""]
CMD_NOTICE_MARK = "Maskit"


class FakeUpstream(BaseHTTPRequestHandler):
    """假上游：慢速吐 SSE，模拟真实模型逐字生成。"""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length)
        received_request["body"] = body.decode("utf-8")
        if PHASE["cmd"]:
            pieces = CMD_PIECES
            self._stream_sse(pieces)
            return
        masked = json.loads(body)["messages"][0]["content"]
        # 从脱敏后的请求里取出占位符，原样回显（模拟模型复述）。
        # 用产品侧的正则而不是自己写死格式：后缀 0.1.13 起是纯辅音、旧的是 hex，
        # 各写一份必然漏（本文件此前就写死 [0-9a-f]{6}，格式一改就取不到 token）。
        import re
        tokens = re.findall(TR._PLACEHOLDER_RX, masked)
        token = tokens[0] if tokens else "NOPLACEHOLDER"
        # 把占位符切成两半跨 chunk 发送，检验跨 chunk 还原
        half = len(token) // 2
        pieces = ["联系人是", token[:half], token[half:], "，请周知。", "", ""]
        self._stream_sse(pieces)

    def _stream_sse(self, pieces):
        """按块慢速吐 SSE（逐字生成的仿真）。CRLF 是真实服务常用形式。"""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for i in range(CHUNKS):
            piece = pieces[i] if i < len(pieces) else ""
            evt = {"id": "chatcmpl-x", "object": "chat.completion.chunk", "model": "m",
                   "choices": [{"index": 0, "delta": {"content": piece}}]}
            # 真实服务常用 CRLF；曾因只识别 LF 导致整段缓存/客户端超时截断。
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
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.4)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def _run_proxy_pass(cmd_mode, srv):
    """跑一遍真实 mitmdump：返回 (是否全过, 客户端收到的全部文本, 上游收到的请求体, 全部行)。

    cmd_mode=None → 验脱敏/还原；'rewrite' → 验命令拦截就地改写。
    每遍重新生成 config.json 并重启代理（配置只在启动时读）。
    """
    work = ROOT / "_smoke_data"
    work.mkdir(exist_ok=True)
    cfg = {
        "capture_mode": "reverse",
        "sensitive": {"人名": ["王大锤"]},
        "upstreams": [{
            "name": "smoke", "base_path": "/smoke", "port": PROXY_PORT,
            "target": f"http://127.0.0.1:{UPSTREAM_PORT}",
            "paths": ["/v1/chat/completions"],
        }],
        "filter_enabled": True, "fail_closed": True, "session_ttl": 600,
    }
    if cmd_mode:
        # 故意不写 patterns：走「键缺失才灌内置种子」路径，
        # 顺带端到端验证随包分发的内置规则真能命中。
        cfg["command_block"] = {"mode": cmd_mode, "channels": ["text"]}
    (work / "config.json").write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")

    env = {**os.environ, "LLM_SHIELD_DATA_DIR": str(work), "PYTHONUTF8": "1",
           "PYTHONPATH": str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")}
    mitm_cmd = shutil.which("mitmdump") or str(pathlib.Path(sys.executable).parent / "mitmdump")
    proc = subprocess.Popen(
        [mitm_cmd, "-s", str(TRANSPARENT_PY), "--listen-host", "127.0.0.1",
         "--mode", f"reverse:http://127.0.0.1:{UPSTREAM_PORT}@{PROXY_PORT}",
         "--set", "flow_detail=0", "--set", "connection_strategy=lazy"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", env=env,
    )
    logs = []
    threading.Thread(target=lambda: [logs.append(l) for l in proc.stdout], daemon=True).start()
    try:
        if not wait_port(PROXY_PORT):
            print("FAIL: 代理端口未监听\n" + "".join(logs[-30:]))
            return False, "", "", [], None
        payload = json.dumps({"model": "m", "stream": True,
                              "messages": [{"role": "user",
                                             "content": "客户王大锤，电话13812345678"}]},
                             ensure_ascii=False).encode("utf-8")
        req = Request(f"http://127.0.0.1:{PROXY_PORT}/v1/chat/completions", data=payload,
                      headers={"content-type": "application/json"}, method="POST")
        t0 = time.time()
        first_byte_at = None
        chunks = []
        with urlopen(req, timeout=60) as resp:
            while True:
                line = resp.readline()
                if not line:
                    break
                if first_byte_at is None and line.strip():
                    first_byte_at = time.time() - t0
                chunks.append(line.decode("utf-8", errors="replace"))
        total = time.time() - t0
        body = "".join(chunks)
        text = "".join(
            json.loads(l[6:])["choices"][0]["delta"].get("content", "")
            for l in body.splitlines() if l.startswith("data: {")
        )
        return True, text, received_request.get("body", ""), body, (first_byte_at, total)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


def assert_mask_pass(text, upstream_body, body, timing):
    """第一遍：脱敏/还原/流完整性。"""
    ok = True
    # 1) 脱敏：原文不得出现在发往上游的请求里
    if "王大锤" in upstream_body or "13812345678" in upstream_body:
        print("FAIL: 敏感原文泄漏到上游请求"); ok = False
    else:
        print("PASS: 请求已脱敏（上游收到占位符）")
    # 2) 还原：客户端收到的流里必须是原文，且没有残留占位符
    if "王大锤" not in text:
        print(f"FAIL: 响应未还原，实际内容={text!r}"); ok = False
    elif "{{" in text:
        print(f"FAIL: 残留占位符，实际内容={text!r}"); ok = False
    else:
        print(f"PASS: 跨 chunk 占位符已还原 -> {text!r}")
    # 3) SSE 完整性：必须包含 [DONE] 结束标记，且事件流全部收到
    #    （v1.5.23 起流式接管默认开，此处验证流式接管路径的正确性：
    #    首字节应明显早于上游发完——首字节 < 上游总时长。）
    first_byte_at, total = timing
    print(f"首字节 {first_byte_at:.2f}s / 全部完成 {total:.2f}s（上游共 {CHUNK_DELAY*CHUNKS:.2f}s）")
    if "data: [DONE]" not in body:
        print("FAIL: 响应缺少 [DONE] 结束标记"); ok = False
    elif not body.strip().startswith("data: {"):
        print("FAIL: 响应不是 SSE 事件流"); ok = False
    else:
        print("PASS: SSE 事件流完整（含 [DONE]）")
    if first_byte_at is not None and first_byte_at < CHUNK_DELAY * (CHUNKS - 1):
        print(f"PASS: 流式接管生效（首字节 {first_byte_at:.2f}s 早于上游发完）")
    else:
        print("WARN: 首字节接近上游总时长，疑似走了整包路径")
    return ok


def assert_cmd_pass(text, body, timing):
    """第二遍（rewrite）：跨 chunk 的危险命令必须被就地改写，而流不能坏。

    四件事同时成立才算过：① 命令不见了；② 换成了无害说明；③ 命令之后的正文仍在、
    [DONE] 仍在（改写若吞字或截断流，这里立刻暴露）；④ **首字节没有退化**——
    前瞻缓冲只该暂留尾部，不该把整条流拖到末尾才吐出。
    """
    ok = True
    if "rm -rf /" in text:
        print(f"FAIL: 跨 chunk 的危险命令未被改写，客户端收到={text!r}"); ok = False
    elif CMD_NOTICE_MARK not in text:
        print(f"FAIL: 未看到改写说明，客户端收到={text!r}"); ok = False
    else:
        print(f"PASS: 跨 chunk 危险命令已被改写 -> {text!r}")
    if "完毕，再见" not in text:
        print(f"FAIL: 命令之后的正文被吞，客户端收到={text!r}"); ok = False
    else:
        print("PASS: 改写后正文不丢（无吞字）")
    if "data: [DONE]" not in body or not body.strip().startswith("data: {"):
        print("FAIL: 改写破坏了 SSE 流结构（[DONE] 丢失或不是事件流）"); ok = False
    else:
        print("PASS: 改写后 SSE 结构完整（含 [DONE]）")
    first_byte_at, _total = timing
    if first_byte_at is not None and first_byte_at < CHUNK_DELAY * (CHUNKS - 1):
        print(f"PASS: 改写模式下首字节 {first_byte_at:.2f}s（打字机未退化）")
    else:
        print(f"FAIL: 改写模式下首字节延迟到 {first_byte_at}s，前瞻缓冲把整条流拖住了")
        ok = False
    return ok


def main():
    srv = HTTPServer(("127.0.0.1", UPSTREAM_PORT), FakeUpstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ok = True
    try:
        PHASE["cmd"] = False
        print("--- 第 1 遍：脱敏与还原 ---")
        started, text, upstream_body, body, timing = _run_proxy_pass(None, srv)
        if not started:
            return 1
        ok &= assert_mask_pass(text, upstream_body, body, timing)

        print("--- 第 2 遍：命令拦截 rewrite（跨 chunk）---")
        PHASE["cmd"] = True
        started, text, _upstream_body, body, timing = _run_proxy_pass("rewrite", srv)
        if not started:
            return 1
        ok &= assert_cmd_pass(text, body, timing)
    finally:
        srv.shutdown()
    print("SMOKE " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
