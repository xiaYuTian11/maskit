"""实测：面板 CSP 是否拦掉浏览器对 api.github.com 的直连（本次 NetworkError 的根因）。

**不进 verify-all**（需要真浏览器，与 `tests/e2e_ext_bridge.py` 同规）。

## 为什么必须用 Firefox 验

Chrome 对 CSP 拦截报 `TypeError: Failed to fetch`，而 **Firefox 报的是**

    TypeError: NetworkError when attempting to fetch resource.

后者正是用户报上来的原文。也就是说，这个「看起来像网络不通」的错误，
其实是浏览器在请求**发出之前**就被 CSP 拦掉了——所以
「浏览器明明能打开 GitHub 网页」和「面板里检查更新报 NetworkError」会同时成立，
极易误判成网络/服务器问题。本脚本用真实浏览器把这个因果关系钉死。

## 判定

  - 旧 CSP `connect-src 'self'`  → fetch 抛 TypeError，控制台有 CSP 拦截日志；
  - 新 CSP（放行 api.github.com）→ fetch 能拿到 HTTP 状态（403 也算通，说明已出网）。

## 运行前提

    pip install playwright && playwright install chromium firefox
    python tests/repro_csp_blocks_github.py
"""
import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

OLD_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
NEW_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data:; connect-src 'self' https://api.github.com; frame-ancestors 'none'")

PROBE_JS = """
async () => {
  try {
    const r = await fetch('https://api.github.com/repos/xiaYuTian11/maskit/releases/latest',
                          { headers: { Accept: 'application/vnd.github.v3+json' } });
    return { ok: true, status: r.status };
  } catch (e) {
    return { ok: false, name: e.name, error: String(e) };
  }
}
"""

# 用户报上来的原文，用于断言 Firefox 侧能精确复现
REPORTED = "TypeError: NetworkError when attempting to fetch resource."


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve(csp, port, log):
    index = (ROOT / "frontend" / "dist" / "index.html").read_text(encoding="utf-8")

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = index.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", csp)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    log.append(srv)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def probe(browser, csp):
    """返回 (fetch 结果, 控制台 CSP 日志)。"""
    port = _free_port()
    holder = []
    _serve(csp, port, holder)
    time.sleep(0.3)
    logs = []
    try:
        pg = browser.new_page()
        pg.on("console", lambda m: logs.append(m.text) if "Content Security Policy" in m.text else None)
        pg.goto(f"http://127.0.0.1:{port}/", wait_until="domcontentloaded")
        res = pg.evaluate(PROBE_JS)
        pg.close()
    finally:
        holder[0].shutdown()
    return res, logs


def main():
    if not (ROOT / "frontend" / "dist" / "index.html").exists():
        print("缺少 frontend/dist/index.html，先跑 `cd frontend && npm run build`")
        return 1

    firefox_old_error = None
    with sync_playwright() as p:
        for name, launcher in (("chromium", p.chromium), ("firefox", p.firefox)):
            try:
                browser = launcher.launch()
            except Exception as e:
                print(f"\n[{name}] 未安装，跳过：{str(e).splitlines()[0]}")
                continue
            try:
                for label, csp in (("旧 CSP：connect-src 'self'（修复前）", OLD_CSP),
                                   ("新 CSP：放行 api.github.com（修复后）", NEW_CSP)):
                    res, logs = probe(browser, csp)
                    print(f"\n=== {name} | {label} ===")
                    print("  fetch:", json.dumps(res, ensure_ascii=False))
                    for line in logs:
                        print("  控制台:", line[:150])
                    if name == "firefox" and csp is OLD_CSP:
                        firefox_old_error = res.get("error")
            finally:
                browser.close()

    print("\n" + "=" * 68)
    if firefox_old_error == REPORTED:
        print("结论：Firefox + 旧 CSP 精确复现用户报错原文：")
        print(f"      {REPORTED}")
        print("      -> 根因确认为面板 CSP 拦截，与网络/服务器连通性无关。")
    elif firefox_old_error is not None:
        print(f"结论：Firefox + 旧 CSP 报错为 {firefox_old_error!r}（与用户原文不同，需复核）")
    else:
        print("结论：firefox 未运行，无法复现原文（请装 playwright firefox）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
