"""Probe a frozen POSIX panel in fresh data/home directories, without starting a proxy.

No installation, release, proxy start/stop call, model download, or production
configuration is performed. Windows panel startup also touches HKCU autostart;
use a clean Windows VM instead of this host-isolated probe there.
"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--expect-ner", action="store_true")
    opts = parser.parse_args()
    if os.name != "posix":
        parser.error("panel probe requires an isolated POSIX home; use a clean VM on Windows")
    engine = opts.engine.resolve()
    if not engine.is_file() or not (engine.parent / "_internal/transparent.py").is_file():
        parser.error("--engine must point to a complete frozen engine bundle")
    process = None
    with tempfile.TemporaryDirectory(prefix="maskit-panel-smoke-") as temp:
        root = Path(temp)
        data = root / "data"
        data.mkdir()
        panel_port, upstream_port = free_port(), free_port()
        while panel_port == upstream_port:
            upstream_port = free_port()
        # meta 标记必须带上：panel.load_config 的一次性迁移
        # （engine/panel.py 的 stop_mode_passthrough_default_v2 分支）在没有该标记时
        # 会把 auto_start_proxy 强制改写成 True。那时引擎启动即拉起代理，
        # 下面「启动时代理必须是关闭的」断言就只剩竞态窗口——快机器上必红。
        cfg = {
            "capture_mode": "reverse", "auto_start_proxy": False,
            "autostart": False, "stop_mode": "block", "price_sync_enabled": False,
            "upstreams": [{"name": "isolated", "port": upstream_port,
                           "target": "http://127.0.0.1:9", "paths": ["/v1"]}],
            "ner_enabled": False, "debug": False,
            "meta": {"stop_mode_passthrough_default_v2": True},
        }
        (data / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
        env = {k: v for k, v in os.environ.items()
               if not k.upper().endswith("_PROXY") and k != "PYTHONPATH"
               and not k.startswith(("LLM_SHIELD_", "MASKIT_"))}
        env.update(LLM_SHIELD_DATA_DIR=str(data), LLM_SHIELD_PANEL_PORT=str(panel_port),
                   MASKIT_PANEL_HOST="127.0.0.1", MASKIT_LISTEN_HOST="127.0.0.1")
        for key in ("HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"):
            path = root / key.lower()
            path.mkdir()
            env[key] = str(path)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = f"http://127.0.0.1:{panel_port}"
        def get(path, headers=None):
            try:
                with opener.open(urllib.request.Request(base + path, headers=headers or {}), timeout=3) as reply:
                    return reply.status, reply.read()
            except urllib.error.HTTPError as reply:
                return reply.code, reply.read()
        logs_path = root / "panel.log"
        try:
            with logs_path.open("w", encoding="utf-8") as logs:
                process = subprocess.Popen([str(engine)], cwd=root, env=env,
                                           stdout=logs, stderr=subprocess.STDOUT)
                end = time.monotonic() + 20
                while time.monotonic() < end:
                    if process.poll() is not None:
                        raise RuntimeError("frozen panel exited before readiness")
                    try:
                        status, body = get("/healthz")
                        if status == 200 and json.loads(body).get("ok"):
                            break
                    except (OSError, ValueError):
                        pass
                    time.sleep(.1)
                else:
                    raise TimeoutError("frozen panel readiness")
                token = (data / "proxy_token").read_text().strip()
                headers = {"X-Shield-Token": token}
                assert get("/api/config")[0] == 403
                assert get("/api/config", {**headers, "Host": "untrusted.invalid"})[0] == 403
                assert get("/api/config", {**headers, "Origin": "https://untrusted.invalid"})[0] == 403
                status, body = get("/api/status", headers)
                state = json.loads(body)
                assert status == 200 and not state["proxy_running"] and not state["passthrough"]
                assert state["panel_pid"] == process.pid
                if opts.expect_ner:
                    assert state["ner"]["available"] is True, "bundled model was not found"
                status, body = get("/api/config", headers)
                config = json.loads(body)
                assert status == 200 and config["upstreams"][0]["port"] == upstream_port
                assert config["_meta"]["transport_capabilities"]["observation"] is True
                status, html = get("/")
                assert status == 200
                scripts = re.findall(rb'src="(/assets/[^"?#]+\.js)"', html)
                assert scripts, "bundled SPA did not reference a JavaScript asset"
                for script in scripts:
                    assert get(script.decode(), {"Origin": "https://untrusted.invalid"})[0] == 200
                with socket.socket() as probe:
                    probe.settimeout(.2)
                    assert probe.connect_ex(("127.0.0.1", upstream_port)) != 0, "proxy/fallback started unexpectedly"
                print("PANEL SMOKE OK: frozen SPA/assets, health, token/Host/Origin guards, model discovery, proxy disabled")
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    main()
