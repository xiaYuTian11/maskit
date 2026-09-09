"""端到端冒烟：出口代理（Shield → 上游方向）。

不进单测套件（要起真实进程和端口），改出口代理相关代码后手动跑：
    python tests/smoke_egress.py

验证点：
1. 勾了 use_proxy 的 upstream，转发**经过**出口代理；
2. 没勾的 upstream 在同一个 mitmdump 进程里**保持直连**（逐 flow 生效是本方案的关键，
   一刀切的环境变量方案做不到）；
3. 走代理时脱敏链路照常工作（占位符替换、上游拿不到原文）；
4. 出口代理走的是 CONNECT 隧道 —— 即便目标是明文 http 也一样，所以上游代理必须
   支持 CONNECT（Clash / v2ray 的 HTTP 端口都支持，socks5 不走这条路径）。
"""
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))
import transparent as TR   # noqa: E402  —— 只为复用占位符正则，别再自己写死格式

TRANSPARENT_PY = (ROOT / "engine" / "transparent.py") if (ROOT / "engine" / "transparent.py").exists() else (ROOT / "transparent.py")

UPSTREAM_PORT = 18981
PROXY_PORT = 18982
PORT_DIRECT = 18983      # use_proxy=False
PORT_VIA = 18984         # use_proxy=True
SECRET = "王大锤"

proxy_events = []        # 出口代理收到的连接（CONNECT ...）
upstream_bodies = []     # 假上游收到的请求体（应已脱敏）

# 本地请求必须绕开系统代理：用户为别的工具设了 HTTP_PROXY 时，
# urllib 会把发往 127.0.0.1 的请求也塞进代理，冒烟就会假失败。
_opener = build_opener(ProxyHandler({}))


class FakeUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n).decode("utf-8", errors="replace")
        upstream_bodies.append(body)
        payload = json.dumps({
            "id": "x", "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": "收到"}}],
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


class FakeProxy(BaseHTTPRequestHandler):
    """假 HTTP 代理，支持 CONNECT 隧道（Clash / v2ray 的标准行为）。"""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_CONNECT(self):
        proxy_events.append(("CONNECT", self.path))
        host, _, port = self.path.rpartition(":")
        try:
            up = socket.create_connection((host, int(port)), timeout=10)
        except Exception as e:
            proxy_events.append(("DIALFAIL", str(e)))
            self.send_error(502)
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        try:
            self.wfile.flush()
        except Exception:
            pass
        self.close_connection = True
        t = threading.Thread(target=_pump, args=(up, self.connection), daemon=True)
        t.start()
        _pump(self.connection, up)
        t.join(timeout=10)
        try:
            up.close()
        except Exception:
            pass

    def do_POST(self):
        # 普通 HTTP 代理转发。实测 mitmproxy 一律用 CONNECT，走到这里说明行为变了
        proxy_events.append(("POST", self.path))
        self.send_error(501)


def wait_port(port, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def ask(port, text):
    payload = json.dumps({"model": "m", "messages": [{"role": "user", "content": text}]},
                         ensure_ascii=False).encode("utf-8")
    req = Request(f"http://127.0.0.1:{port}/v1/chat/completions", data=payload,
                  headers={"content-type": "application/json"}, method="POST")
    with _opener.open(req, timeout=30) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def main():
    work = ROOT / "_smoke_data"
    work.mkdir(exist_ok=True)
    cfg = {
        "capture_mode": "reverse",
        "sensitive": {"人名": [SECRET]},
        "egress_proxy": {"enabled": True, "url": f"http://127.0.0.1:{PROXY_PORT}"},
        "upstreams": [
            {"name": "direct", "base_path": "/direct", "port": PORT_DIRECT,
             "target": f"http://127.0.0.1:{UPSTREAM_PORT}",
             "paths": ["/v1/chat/completions"], "use_proxy": False},
            {"name": "viaproxy", "base_path": "/viaproxy", "port": PORT_VIA,
             "target": f"http://127.0.0.1:{UPSTREAM_PORT}",
             "paths": ["/v1/chat/completions"], "use_proxy": True},
        ],
        "filter_enabled": True, "fail_closed": True, "session_ttl": 600,
        "stream_response": True,
    }
    (work / "config.json").write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")

    # 必须是 ThreadingHTTPServer：CONNECT 隧道会一直占住处理线程直到连接结束，
    # 裸 HTTPServer 是单线程的，隧道一建立就再也接不了别的连接。
    for cls, port in ((FakeUpstream, UPSTREAM_PORT), (FakeProxy, PROXY_PORT)):
        srv = ThreadingHTTPServer(("127.0.0.1", port), cls)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.4)

    env = {**os.environ, "LLM_SHIELD_DATA_DIR": str(work), "PYTHONUTF8": "1",
           "PYTHONPATH": str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")}
    proc = subprocess.Popen(
        ["mitmdump", "-s", str(TRANSPARENT_PY),
         "--mode", f"regular@127.0.0.1:{PORT_DIRECT}",
         "--mode", f"regular@127.0.0.1:{PORT_VIA}",
         "--set", "flow_detail=0", "--set", "connection_strategy=lazy"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", env=env,
    )
    logs = []
    threading.Thread(target=lambda: [logs.append(l) for l in proc.stdout], daemon=True).start()

    fails = []
    try:
        for p in (PORT_DIRECT, PORT_VIA):
            if not wait_port(p):
                print(f"FAIL: 端口 {p} 未监听\n" + "".join(logs[-30:]))
                return 1

        # 1) 未勾选 use_proxy：必须直连，代理一条都收不到
        proxy_events.clear(); upstream_bodies.clear()
        status, _ = ask(PORT_DIRECT, f"客户{SECRET}，电话13812345678")
        if status != 200 or not upstream_bodies:
            fails.append(f"直连路径异常 status={status} 上游收到 {len(upstream_bodies)} 条")
        if proxy_events:
            fails.append(f"未勾选 use_proxy 却经过了代理: {proxy_events}")
        else:
            print("PASS: 未勾选的 upstream 保持直连（代理无记录）")

        # 2) 勾选 use_proxy：必须经过代理，且是 CONNECT 隧道
        proxy_events.clear(); upstream_bodies.clear()
        status, _ = ask(PORT_VIA, f"客户{SECRET}，电话13812345678")
        connects = [e for e in proxy_events if e[0] == "CONNECT"]
        if status != 200:
            fails.append(f"走代理路径 HTTP {status}")
        if not connects:
            fails.append(f"勾了 use_proxy 却没经过代理: {proxy_events}")
        else:
            print(f"PASS: 走代理生效，且为 CONNECT 隧道 {connects[0][1]}")
        if [e for e in proxy_events if e[0] == "POST"]:
            fails.append("出现普通 HTTP 代理转发（预期恒为 CONNECT），行为已变，需复核文档")

        # 3) 走代理时脱敏照常
        if not upstream_bodies:
            fails.append("走代理时上游没收到请求")
        else:
            body = upstream_bodies[-1]
            if SECRET in body:
                fails.append("走代理时敏感词原文上行（脱敏失效）")
            elif not re.search(TR._PLACEHOLDER_RX, body):
                fails.append(f"走代理时未见占位符: {body[:200]}")
            else:
                print("PASS: 走代理时脱敏链路正常（上游只拿到占位符）")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    if fails:
        print("\nFAILED:")
        for f in fails:
            print("  -", f)
        print("\nmitmdump 日志尾部:\n" + "".join(logs[-25:]))
        return 1
    print("\nEGRESS SMOKE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
