"""真实上游流式验证：确认流式接管确实生效，而非整包退化。

手动跑（消耗真实 token）：
    export LLM_SHIELD_API_KEY="ah-..."
    python tests/real_stream_check.py [upstream_name]

与 tests/real_proxy_check.py 的分工：那个测全功能（脱敏/阻断/过滤），这个只死盯
「流式到底有没有真的流起来」——因为面板显示的 stream_mode 是客户端请求的类型，
不代表引擎实际处理方式，两者背离时（黑名单/压缩体）用户看不出来。

判据（缺一不可）：
    1. stream_actual == "stream"        引擎确实走了 responseheaders 接管
    2. 首字节明显早于流结束            客户端拿到的是真打字机效果，不是整段
    3. chunk 到达时间分散              至少 3 个不同时刻收到数据
    4. 敏感词还原正确、无占位符残留    接管路径不能破坏还原
    5. 流完整（含 [DONE]）             接管不能截断或吞尾

前置：独立数据目录 + 独立端口，不读写项目 config.json / 事件库，不影响正在运行的实例。
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# 独占端口：避开 187xx 常规段与面板 5801，防止与正在运行的实例抢端口
PROBE_PORT = 18808
API_KEY = os.environ.get("LLM_SHIELD_API_KEY") or ""

# 上游候选：name -> (target, path, model)
# 开源仓库不含开发者自用渠道——运行前替换为你的真实上游
# （target 可用环境变量 LLM_SHIELD_TEST_TARGET 覆盖，model 用 LLM_SHIELD_TEST_MODEL）
UPSTREAMS = {
    "upstream-a": (os.environ.get("LLM_SHIELD_TEST_TARGET", "https://api.example.com"), "/v1/chat/completions", os.environ.get("LLM_SHIELD_TEST_MODEL", "deepseek-v4-flash")),
}

SENSITIVE_WORD = "王大锤"
results = []


def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


def wait_port(port, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.4)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def main():
    up_name = (sys.argv[1] if len(sys.argv) > 1 else "upstream-a").strip()
    if up_name not in UPSTREAMS:
        print(f"未知上游 {up_name}，可选：{list(UPSTREAMS)}")
        return 2
    if not API_KEY:
        print("需要环境变量 LLM_SHIELD_API_KEY")
        return 2
    target, api_path, model = UPSTREAMS[up_name]

    work = Path(tempfile.mkdtemp(prefix="shield_stream_"))
    cfg = {
        "capture_mode": "reverse",
        "sensitive": {"人名": [SENSITIVE_WORD]},
        "upstreams": [{
            "name": up_name, "base_path": "/" + up_name, "port": PROBE_PORT,
            "target": target, "paths": [api_path],
        }],
        "filter_enabled": True,
        "fail_closed": True,
        "session_ttl": 600,
        "stream_response": True,
        # 关键：空黑名单 = 不排除任何 host，验证接管在真实上游能否活下来。
        # 设 SHIELD_STREAM_EXCLUDE=<host> 可做对照实验（走整包路径）。
        "stream_exclude_hosts": [h for h in
                                 (os.environ.get("SHIELD_STREAM_EXCLUDE") or "").split(",") if h.strip()],
    }
    (work / "config.json").write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")

    env = {**os.environ, "LLM_SHIELD_DATA_DIR": str(work), "PYTHONUTF8": "1",
           # 子进程 stdout 默认块缓冲，管道读端在进程被 terminate 前基本收不到
           # 任何行——引擎日志通道形同虚设。强制行缓冲才能实时拿到诊断输出。
           "PYTHONUNBUFFERED": "1",
           "PYTHONPATH": str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")}
    if os.environ.get("SHIELD_KEEP_LOGS"):
        env["SHIELD_STREAM_DEBUG"] = "1"  # 打开逐回调日志，定位断流点
    # 与生产同构：panel.py 的 reverse 模式实际就是 --mode regular@<port>（每个
    # upstream 一个本地端口），由 transparent.py 的 apply_reverse_routing 按入站
    # 端口匹配 upstream 并改写 host/scheme/path。客户端只需把 base_url 指向该端口，
    # 发普通相对路径请求即可（无需绝对 URL，路由不看 Host 头）。
    proc = subprocess.Popen(
        ["mitmdump", "-s", str(ROOT / "transparent.py"),
         "--mode", f"regular@127.0.0.1:{PROBE_PORT}",
         # -v 提到 INFO 级：addon 的 _log 走标准 logging，默认 WARNING 看不到
         "-v",
         "--set", "flow_detail=0", "--set", "connection_strategy=lazy"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", env=env,
    )
    logs = []
    import threading
    threading.Thread(target=lambda: [logs.append(l) for l in proc.stdout], daemon=True).start()

    try:
        if not wait_port(PROBE_PORT):
            print("FAIL: 代理端口未监听\n" + "".join(logs[-40:]))
            return 1

        payload = json.dumps({
            "model": model,
            "stream": True,
            # 要求足够长的输出，短回答无法区分流式与整包
            #
            # 别写「逐字复述」：实测（2026-08-17）模型会照字面理解，把每个字符
            # 拆开加空格输出，占位符也一起被拆成 `{ { T E R M _ 7 b 5 a d 7 } }`，
            # 还原自然匹配不上 —— 这条断言于是**永远红**，而红的原因跟脱敏还原
            # 一点关系都没有。A/B 确认：改动前后一样红。
            # 明确要求原样不改，这条才测得到它真正想测的东西（流式路径下的还原）。
            "messages": [{"role": "user", "content":
                          f"请原样复述下面这句话（保持字符完全一致，不要加空格、不要改写、不要加粗）："
                          f"客户{SENSITIVE_WORD}已签约。复述完后从1数到30，每个数字单独一行。"}],
        }, ensure_ascii=False).encode("utf-8")

        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", PROBE_PORT, timeout=180)
        t0 = time.perf_counter()
        conn.request("POST", api_path, body=payload, headers={
            "content-type": "application/json",
            "authorization": "Bearer " + API_KEY,
            # Cloudflare 按 UA 拦 Python-urllib（AGENTS.md 约束 9）
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "accept": "text/event-stream",
            # 故意声明支持压缩：验证引擎是否强制 identity 以保住流式
            "accept-encoding": "gzip, deflate, br",
        })
        resp = conn.getresponse()
        status = resp.status
        ctype = resp.getheader("content-type") or ""
        cenc = resp.getheader("content-encoding") or "(none)"
        # 帧格式取证：客户端提前收到 EOF 时，必须能区分「chunked 终止块」
        # 「content-length 截断」「close-delimited」三种成因。
        print("    [framing] chunked=%r length=%r will_close=%r te=%r cl=%r conn=%r" % (
            resp.chunked, resp.length, resp.will_close,
            resp.getheader("transfer-encoding"), resp.getheader("content-length"),
            resp.getheader("connection")))

        arrivals = []       # 每个 chunk 的到达时刻
        body_parts = []
        while True:
            chunk = resp.read1(65536)
            if not chunk:
                break
            arrivals.append(time.perf_counter() - t0)
            body_parts.append(chunk.decode("utf-8", errors="replace"))
        total = time.perf_counter() - t0
        conn.close()
        body = "".join(body_parts)

        print(f"\n--- {up_name} status={status} ct={ctype[:40]} content-encoding={cenc} ---")
        if not arrivals:
            # 200 但 0 chunk（整包瞬发或空体）：arrivals 为空时后续索引会崩，
            # 直接按失败处理并留痕。
            log("有响应体", False, f"status={status} 0 chunk body[:200]={body[:200]!r}")
            return 1
        print(f"首字节 {arrivals[0]:.2f}s / 结束 {total:.2f}s / chunk 数 {len(arrivals)}")

        if status != 200:
            log("HTTP 200", False, f"status={status} body={body[:200]}")
            return 1
        log("HTTP 200", True)

        # 判据 5：流完整
        log("SSE 含 [DONE]", "data: [DONE]" in body or "[DONE]" in body,
            "" if "[DONE]" in body else f"尾部={body[-120:]!r}")

        # 判据 4：还原正确、无残留
        text = []
        for line in body.splitlines():
            if not line.startswith("data: "):
                continue
            raw = line[6:].strip()
            if raw == "[DONE]":
                continue
            try:
                d = json.loads(raw)
            except Exception:
                continue
            for ch in (d.get("choices") or []):
                delta = ch.get("delta") or {}
                text.append(delta.get("content") or "")
        joined = "".join(text)
        log("敏感词已还原", SENSITIVE_WORD in joined,
            f"回复片段={joined[:80]!r}" if SENSITIVE_WORD not in joined else "")
        log("无占位符残留", "{{" not in joined,
            f"残留={joined[:120]!r}" if "{{" in joined else "")

        # 判据 2/3：真流式 —— 不是「整段攒完一次性下发」。
        # 判据 A：首个 chunk 到达后，后续仍有 ≥2 个不同时刻的 chunk（上游在逐步吐字）。
        #   （注意不能用「首字节/总时长」占比：模型思考 10s 后 0.8s 吐完 51 chunk，
        #    首字节占比 93% 但确确实实是流式的。整包路径的特征是 distinct=1，即所有
        #    字节同一时刻到达。）
        # 判据 B：流式接管路径（stream_actual=stream）下首个 chunk 与最后一个
        #   chunk 之间有时间间隔，证明不是一次性 flush。
        distinct = len({round(a, 1) for a in arrivals})
        spread_s = (arrivals[-1] - arrivals[0]) if len(arrivals) > 1 else 0.0
        log("chunk 到达分散（≥3 个时刻）", distinct >= 3,
            f"distinct={distinct} chunks={len(arrivals)} 首字节 {arrivals[0]:.2f}s 总 {total:.2f}s")
        log("流式分散生效（跨时刻出字）", distinct >= 3 and spread_s > 0.05,
            f"出字窗口 {spread_s:.2f}s（首 chunk 到末 chunk）")

        # 判据 1：引擎自报的实际处理方式
        time.sleep(1.2)  # 等写线程落库
        sys.path.insert(0, str(ROOT))
        import importlib
        os.environ["LLM_SHIELD_DATA_DIR"] = str(work)
        import event_store
        importlib.reload(event_store)
        evs = event_store.fetch_events(limit=50)
        restore = [e for e in evs if e.get("type") == "RESTORE"]
        actual = restore[0].get("stream_actual") if restore else None
        log("stream_actual == stream", actual == "stream", f"实际={actual!r}")
        if restore:
            r = restore[0]
            print(f"    引擎记录：stream_mode={r.get('stream_mode')} "
                  f"first_byte_ms={r.get('first_byte_ms')} upstream_ms={r.get('upstream_ms')} "
                  f"usage={r.get('usage')}")
        # 没有 RESTORE 说明 _finish() 没跑到（流被中途切断）。此时唯一的现场是
        # error() 记的 ERR/CANCEL，msg 里带 stream calls/bytes，必须打出来。
        if not restore:
            for e in evs:
                if e.get("type") in ("ERR", "CANCEL", "DNS_ERROR", "SKIP"):
                    print(f"    [{e.get('type')}] {str(e.get('msg'))[:220]}")
        else:
            # 无 RESTORE = 流没走到 _finish()。断因只能从其他事件读：
            # transparent.error() 把 mitmproxy 层错误写成 ERR/CANCEL/DNS_ERROR
            # （msg=flow_error:...），_stream 内部异常写成 ERR(msg=sse_stream:...)。
            # 只查 RESTORE 会把这条唯一的断因线索丢掉。
            print(f"    [!] 无 RESTORE 事件，转储全部 {len(evs)} 条事件定位断因：")
            for e in evs[:20]:
                print(f"      {e.get('type')} host={e.get('host')} "
                      f"status={e.get('http_status')} msg={str(e.get('msg') or '')[:150]}")

        # 诊断：引擎是否记录了压缩退化
        degraded = [l for l in logs if "content-encoding" in l and "退回整包" in l]
        if degraded:
            print("    [!] 引擎报告压缩退化：" + degraded[0].strip())

        # 排障：SHIELD_KEEP_LOGS=1 打印引擎相关日志（定位接管断流用）。
        # 只捞 SHIELD/stream/异常行——mitmdump 自身的连接日志和无关子进程报错会刷屏。
        if os.environ.get("SHIELD_KEEP_LOGS"):
            kw = ("SHIELD", "stream", "sse", "Error", "error", "Traceback",
                  "Exception", "退回", "还原", "脱敏")
            hit = [l for l in logs if any(k in l for k in kw)]
            print(f"\n--- 引擎日志（{len(hit)}/{len(logs)} 行命中）---")
            for l in hit[:80]:
                print("    " + l.rstrip())

        ok = all(r[1] for r in results)
        print("\nREAL STREAM CHECK " + ("OK" if ok else "FAILED"))
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
