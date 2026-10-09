"""Local-only transport observation smoke test.

Uses one persistent downstream connection to exercise real upstream reuse and
retirement, plus a silent TLS peer. No credentials, installed ports, or public
upstreams are used. This tests observation, not unavailable transport controls.
"""
import argparse
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import sqlite3
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
SECRET = "MASKIT_SYNTHETIC_ENTITY"
SEMANTIC_TEXT = "请让陈阿明联系。"


class Upstream(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.accepts = 0
        self.requests = []
        self.guard = threading.Lock()

    def get_request(self):
        sock, addr = super().get_request()
        with self.guard:
            self.accepts += 1
        return sock, addr


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with self.server.guard:
            self.server.requests.append((self.path, self.client_address, body))
        text = json.loads(body)["messages"][0]["content"]
        if self.path.endswith("/stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for piece in (text[: len(text) // 2], text[len(text) // 2 :]):
                data = ("data: " + json.dumps({"choices": [{"delta": {"content": piece}}]}) + "\n\n").encode()
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()
                time.sleep(0.1)
            end = b"data: [DONE]\n\n"
            self.wfile.write(f"{len(end):x}\r\n".encode() + end + b"\r\n0\r\n\r\n")
            self.wfile.flush()
            return
        data = json.dumps({"choices": [{"message": {"content": text}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if self.path.endswith("/close"):
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()


class SilentTLS(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        try:
            record = self.request.recv(16384)
            if record and record[0] == 22:
                self.server.hello.set()
                # hold 必须明显长于握手预算：否则这一跳是被桩自己关掉的，
                # 熔断就没机会成为那条流的死因，归因断言会退化成「碰巧先谁后谁」。
                self.server.stop.wait(self.server.hold)
        except OSError:
            pass


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def chat(conn, path="/v1/chat/completions"):
    body = ('{ "model": "local-test", "messages": [{"role": "user", '
            '"content": "' + SECRET + '，' + SEMANTIC_TEXT + '"}], "stream": ' +
            ("true" if path.endswith("/stream") else "false") + ' }').encode()
    conn.request("POST", path, body, {"Content-Type": "application/json"})
    response = conn.getresponse()
    return response.status, response.read()


def events(data):
    db = data / "shield-events.sqlite3"
    if not db.exists():
        return []
    try:
        with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as conn:
            return [json.loads(row[0]) for row in conn.execute("SELECT payload FROM events")]
    except sqlite3.OperationalError:
        return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, help="Test a frozen MaskitEngine instead of source mitmdump")
    parser.add_argument("--ner", action="store_true", help="Require real local model initialization and inference")
    options = parser.parse_args()
    if options.engine:
        options.engine = options.engine.resolve()
        script = options.engine.parent / "_internal" / "transparent.py"
        if not options.engine.is_file() or not script.is_file():
            parser.error("--engine must point to a complete onedir MaskitEngine bundle")
        command = [str(options.engine), "--mitmdump"]
    else:
        mitmdump = shutil.which("mitmdump")
        if not mitmdump:
            parser.error("mitmdump is required")
        command = [mitmdump]
        script = ROOT / "engine/transparent.py"
    upstream = Upstream()
    silent = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SilentTLS)
    silent.daemon_threads = True
    silent.hello = threading.Event()
    silent.stop = threading.Event()
    silent.hold = 30
    for srv in (upstream, silent):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    ports = [free_port(), free_port()]
    while ports[0] == ports[1]:
        ports[1] = free_port()
    process = None
    client = None
    try:
        # ignore_cleanup_errors：Windows 上删临时目录会撞上还没释放的
        # shield-events.sqlite3 句柄（发版 CI 实测：断言全 PASS、TRANSPORT SMOKE OK
        # 已打印，退场时 WinError 32 把整条 Windows 打包线打红）。断言才是这里的信号，
        # runner 是一次性的，留个空临时目录不值得让发版失败。
        with tempfile.TemporaryDirectory(prefix="maskit-transport-smoke-",
                                         ignore_cleanup_errors=True) as temp:
            data = Path(temp)
            config = {
                "capture_mode": "reverse", "http2": False, "ner_enabled": options.ner,
                "sensitive": {"TEST": [SECRET]}, "filter_enabled": True,
                "stream_response": True, "response_scan": False, "debug": False,
                "audit": {"enabled": False},
                "upstreams": [
                    {"name": "local-http", "port": ports[0], "paths": ["/v1"],
                     "target": f"http://127.0.0.1:{upstream.server_port}", "use_proxy": False},
                    {"name": "silent-tls", "port": ports[1], "paths": ["/v1"],
                     "target": f"https://127.0.0.1:{silent.server_address[1]}", "use_proxy": False},
                ],
            }
            (data / "config.json").write_text(json.dumps(config), encoding="utf-8")
            env = {k: v for k, v in os.environ.items()
                   if not k.upper().endswith("_PROXY")
                   and not k.startswith(("LLM_SHIELD_", "MASKIT_"))}
            # 预算夹到下限 5 s：熔断在 5–7 s（心跳 2 s 一拍）之间落地，
            # 而静默桩会守到 30 s，所以「这一跳是我们掐的」在时间上是唯一解。
            env.update(LLM_SHIELD_DATA_DIR=temp, PYTHONIOENCODING="utf-8",
                       MASKIT_CONNECT_STALL_S="5")
            for var, subdir in (("HOME", "home"), ("XDG_DATA_HOME", "xdg-data"),
                                ("XDG_CONFIG_HOME", "xdg-config"), ("XDG_CACHE_HOME", "xdg-cache")):
                directory = data / subdir
                directory.mkdir()
                env[var] = str(directory)
            if options.engine:
                env.pop("PYTHONPATH", None)
                cwd = data
            else:
                env["PYTHONPATH"] = str(ROOT / "engine")
                cwd = ROOT / "engine"
            args = command + ["-s", str(script),
                    "--set", f"confdir={temp}", "--set", "connection_strategy=lazy",
                    "--set", "http2=false", "--set", "flow_detail=0",
                    "--set", "termlog_verbosity=warn"]
            for port in ports:
                args += ["--mode", f"regular@127.0.0.1:{port}"]
            unsafe = subprocess.run(args + ["--set", "stream_large_bodies=1m"],
                                    cwd=cwd, env=env, capture_output=True,
                                    text=True, timeout=8)
            assert unsafe.returncode != 0, "unsafe automatic request streaming was accepted"
            assert "Maskit requires stream_large_bodies" in unsafe.stdout + unsafe.stderr
            assert not upstream.requests, "unsafe startup sent an HTTP request"
            print("PASS: automatic request streaming rejected before serving traffic")
            log_path = data / "proxy.log"
            with log_path.open("w", encoding="utf-8") as log:
                process = subprocess.Popen(args, cwd=cwd, env=env,
                                           stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(log_path.read_text()[-3000:])
                    try:
                        with socket.create_connection(("127.0.0.1", ports[0]), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise TimeoutError("isolated proxy startup")
                        time.sleep(.1)
                client = http.client.HTTPConnection("127.0.0.1", ports[0], timeout=5)
                for _ in range(2):
                    status, body = chat(client)
                    assert status == 200 and SECRET.encode() in body
                    assert SEMANTIC_TEXT in json.loads(body)["choices"][0]["message"]["content"]
                with upstream.guard:
                    assert upstream.accepts == 1, "test did not exercise an actual reused connection"
                    assert len(upstream.requests) == 2
                    assert upstream.requests[0][2] == upstream.requests[1][2], "stable masked bytes changed"
                    assert all(SECRET.encode() not in r[2] for r in upstream.requests)
                print("PASS: persistent client reused one upstream connection; masking and byte stability preserved")

                chat(client, "/v1/close")
                chat(client)
                with upstream.guard:
                    assert upstream.accepts == 2, "normal upstream close was not retired"
                    assert len(upstream.requests) == 4, "unexpected POST replay"
                print("PASS: ordinary close obtains a new upstream connection without replay")

                def tls_wait():
                    conn = http.client.HTTPConnection("127.0.0.1", ports[1], timeout=1.5)
                    try:
                        chat(conn)
                        raise AssertionError("silent TLS peer unexpectedly completed")
                    except TimeoutError:
                        return
                    finally:
                        conn.close()

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    blocked = pool.submit(tls_wait)
                    assert silent.hello.wait(3), "TLS ClientHello never reached stub"
                    status, body = chat(client, "/v1/stream")
                    assert status == 200 and b"[DONE]" in body and SECRET.encode() in body
                    blocked.result(timeout=4)
                print("PASS: healthy SSE completes while another connection waits in TLS")
                until = time.monotonic() + 5
                rows = []
                while time.monotonic() < until:
                    rows = events(data)
                    if any(e.get("transport", {}).get("phase") == "tls_handshake"
                           for e in rows if e.get("type") in ("ERR", "CANCEL")):
                        break
                    time.sleep(.1)
                assert any(e.get("transport", {}).get("reused") is True for e in rows), "reuse evidence missing"
                assert any(e.get("transport", {}).get("phase") == "tls_handshake"
                           for e in rows if e.get("type") in ("ERR", "CANCEL")), "TLS failure phase missing"
                assert upstream.accepts == 2 and len(upstream.requests) == 5
                print("PASS: persisted evidence distinguishes actual reuse and TLS failure")

                # 握手熔断：这一次客户端不再等到自己超时，引擎在预算内掐掉这一跳，
                # 客户端拿到干净的 5xx —— 归因必须落在上游，不是客户端也不是引擎。
                kill_conn = http.client.HTTPConnection("127.0.0.1", ports[1], timeout=25)
                started = time.monotonic()
                try:
                    kill_status, _ = chat(kill_conn)
                finally:
                    kill_conn.close()
                bounded_in = time.monotonic() - started
                assert 500 <= kill_status < 600, f"stalled handshake returned {kill_status}"
                assert bounded_in < 12, f"handshake budget not enforced ({bounded_in:.1f}s)"
                print(f"PASS: stalled pre-send handshake bounded in {bounded_in:.1f}s -> {kill_status}")

                until = time.monotonic() + 8
                killed = []
                while time.monotonic() < until:
                    killed = [e for e in events(data)
                              if (e.get("transport") or {}).get("reason") == "handshake_timeout"]
                    if killed:
                        break
                    time.sleep(.1)
                assert killed, "handshake kill left no attributable evidence"
                owners = sorted({e.get("failure_owner") for e in killed})
                assert owners == ["upstream"], f"handshake kill attributed to {owners}"
                assert all((e.get("transport") or {}).get("phase") == "tls_handshake"
                           for e in killed), "kill evidence lost the pre-send phase"
                print("PASS: the kill is attributable to upstream with the pre-send phase kept")

                client.close()
                client = None
                observed_at = time.time()
                until = time.monotonic() + 6
                idle = False
                while time.monotonic() < until:
                    try:
                        metrics = json.loads((data / "engine-runtime.json").read_text())
                        idle = (metrics.get("generated_at", 0) > observed_at
                                and metrics.get("transport", {}).get("inflight") == 0
                                and metrics.get("aux_pool", {}).get("reserved_jobs") == 0)
                        if idle:
                            break
                    except (OSError, ValueError):
                        pass
                    time.sleep(.1)
                assert idle, "idle heartbeat did not refresh or resources did not return"
                assert metrics.get("transport", {}).get("observation_installed") is True
                connect = metrics.get("connect", {})
                # unmatched/ambiguous 必须为 0：那才是「task 名 + 客户端 peername」这套
                # 匹配在真实 mitmproxy 里真的认得出这一跳，而不是只在单测的假 task 里成立。
                assert connect.get("actuating") is True, connect
                assert connect.get("stall_after_s") == 5.0, connect
                assert connect.get("stalled") == 0, connect
                assert connect.get("kills", {}).get("killed", 0) >= 1, connect
                assert connect.get("kills", {}).get("no_conn") == 0, connect
                assert connect.get("kills", {}).get("no_task") == 0, connect
                assert connect.get("kills", {}).get("ambiguous") == 0, connect
                assert metrics.get("transport", {}).get("handshake_kills", 0) >= 1, metrics
                print("PASS: metrics report the gate, its budget and the hop it killed")
                if options.ner:
                    assert metrics.get("ner", {}).get("initialized") is True, "local NER model did not initialize"
                    assert any(e.get("ner_windows", 0) > 0 for e in rows), "NER smoke did not run an inference window"
                    print("PASS: local packaged/source NER initialized and performed inference")
                print("PASS: idle heartbeat refreshes and in-flight reservations return to zero")
                process.terminate()
                process.wait(timeout=5)
            print("TRANSPORT SMOKE OK")
    finally:
        if client is not None:
            client.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        silent.stop.set()
        for srv in (upstream, silent):
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    main()
