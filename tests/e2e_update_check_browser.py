"""端到端实测：真实面板 + 真实浏览器，走完整 checkUpdate 链路。

**不进 verify-all**（与 `tests/e2e_ext_bridge.py` 同规：需要真浏览器，CI 上又慢又脆）。
文件名刻意不叫 `test_*.py`，所以 `unittest discover -s tests` 不会带上它。

## 运行前提

1. `pip install playwright && playwright install chromium`
2. 引擎依赖已装（flask 等），且用装了依赖的那个解释器跑

## 它验证什么

不是 mock：起真实 panel.py（真实 CSP 响应头、真实 /api/update/check），
用真实浏览器加载面板页面，在页面上下文里按 checkUpdate 的逻辑发请求：

  [1] 浏览器直连 api.github.com —— 验证面板 CSP 是否放行（本次 NetworkError 的根因）；
  [2] 服务端 /api/update/check —— 验证浏览器直连失败时的兜底链路。

判定要点：`[1]` 拿到 HTTP 状态（哪怕 403 限流）就说明**已经出网**，
与「被 CSP 拦掉 / 网络不通」是两回事——后者会抛 TypeError 且无状态码。

用法：python tests/e2e_update_check_browser.py
"""
import json
import socket
import sys
import threading
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

# 与 frontend/src/lib/tauri.ts 的 fetchLatestFromGitHub 同逻辑
BROWSER_FIRST_JS = """
async () => {
  const out = {};
  try {
    const r = await fetch('https://api.github.com/repos/xiaYuTian11/maskit/releases/latest',
                          { headers: { Accept: 'application/vnd.github.v3+json' } });
    out.browser = { ok: r.ok, status: r.status };
    if (r.ok) { const d = await r.json(); out.version = d.tag_name; }
  } catch (e) {
    out.browser = { ok: false, error: String(e) };
  }
  return out;
}
"""

# 模拟「浏览器到 GitHub 不通」：CSP 不放行时那条 fetch 必失败，
# 此时前端应退到服务端 /api/update/check
SERVER_FALLBACK_JS = """
async (token) => {
  const r = await fetch('/api/update/check', { headers: { 'X-Shield-Token': token } });
  const body = await r.json();
  return { status: r.status, body };
}
"""


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    import panel

    port = _free_port()
    panel.PANEL_PORT = port

    def run():
        panel.app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)

    threading.Thread(target=run, daemon=True).start()
    # 等端口就绪
    for _ in range(60):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.25)
    time.sleep(0.5)

    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page()
        pg.goto(f"http://127.0.0.1:{port}/", wait_until="domcontentloaded")

        csp = pg.evaluate("() => document.querySelector('meta[http-equiv]')?.content || ''")
        # 用 fetch 拿一次真实响应头（面板所有响应都经 security_headers 加 CSP）
        hdr_csp = pg.evaluate("""async () => {
          const r = await fetch('/api/status', { headers: { 'X-Shield-Token': 'x' } });
          return r.headers.get('content-security-policy') || '';
        }""")

        print("面板页面 URL:", pg.url)
        print("CSP 响应头:", hdr_csp)
        print()

        res = pg.evaluate(BROWSER_FIRST_JS)
        print("[1] 浏览器直连 GitHub API:", json.dumps(res, ensure_ascii=False))

        fb = pg.evaluate(SERVER_FALLBACK_JS, panel.API_TOKEN)
        print("[2] 服务端 /api/update/check:", json.dumps(
            {"status": fb["status"], **{k: fb["body"].get(k) for k in ("ok", "version", "cached", "source", "error")}},
            ensure_ascii=False))

        b.close()

    print()
    bres = res.get("browser", {})
    status = bres.get("status")
    if bres.get("ok"):
        print(f"结论：浏览器直连成功（HTTP {status}，version={res.get('version')}）")
    elif isinstance(status, int):
        # 拿到 HTTP 状态就说明请求已经出网了（403 = GitHub 匿名限流打满），
        # 与「被 CSP 拦掉 / 网络不通」是两回事，必须区分开报。
        print(f"结论：浏览器直连已出网，但返回 HTTP {status}"
              f"{'（匿名限流）' if status == 403 else ''} → 前端会退到服务端")
    else:
        print("结论：浏览器直连未能出网 ->", bres.get("error"))
    print("     服务端兜底: HTTP %s ok=%s version=%s" % (
        fb["status"], fb["body"].get("ok"), fb["body"].get("version")))


if __name__ == "__main__":
    main()
