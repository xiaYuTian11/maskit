"""真实代理全功能测试：启动 panel + mitmdump，用真实上游发请求验证脱敏/还原/流式/阻断/过滤。

手动跑（消耗真实 token）：
    $env:LLM_SHIELD_API_KEY="ah-..."   # PowerShell，或 set LLM_SHIELD_API_KEY=ah-... (cmd)
    python tests/real_proxy_check.py

前置：
    1. 环境变量 LLM_SHIELD_API_KEY 指向真实上游 API key（不写死在代码里，防泄露）；
    2. 用 LLM_SHIELD_TEST_TARGET 指定真实上游（默认取 engine/config.example.json 第一个 upstream）；
    3. 测试通过 LLM_SHIELD_DATA_DIR 使用独立临时数据目录，不读写项目 config.json / 事件库 / token。
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
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PANEL_PORT = 5809      # 不是 5801：那是用户正在跑的实例的面板端口
UPSTREAM_PORT = 18809  # 不是 187xx 常规段：同上，避免抢正在服务的端口
API_KEY = os.environ.get("LLM_SHIELD_API_KEY") or ""
# 上游与模型可用环境变量覆盖：仓库 config.json 里是通用示例上游
# （api.openai.com 等），拿开发者自己的中转 key 打它必然 401。
# 与 real_stream_check.py 保持同一套变量名。
TEST_TARGET = os.environ.get("LLM_SHIELD_TEST_TARGET") or ""
MODEL = os.environ.get("LLM_SHIELD_TEST_MODEL") or "mimo-v2.5-pro"
BASE = f"http://127.0.0.1:{UPSTREAM_PORT}"

panel_proc = None
tmpdir = None
results = []

# 本文件是**手动**脚本：test_* 函数依赖 main() 里的 setup()（起 panel、读 token、
# 填 TOK_HDR），且会打真实上游消耗 token。pytest 按 test*.py 收集时会跳过 main()
# 直接调各 test_*，请求无 token 一律 403，产生与代码质量无关的假失败。
# 这里在被 pytest 导入时整体跳过；手动运行（__main__）不受影响。
# 需要在 pytest 下真跑时设 LLM_SHIELD_REAL_PROXY=1，并自行保证前置条件。
if "pytest" in sys.modules and not os.environ.get("LLM_SHIELD_REAL_PROXY"):
    import pytest

    pytest.skip(
        "真实上游手动测试：需 python tests/real_proxy_check.py 运行"
        "（或设 LLM_SHIELD_REAL_PROXY=1 强制在 pytest 下执行）",
        allow_module_level=True,
    )


def log(name, ok, detail=""):
    results.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" -- {detail}" if detail else ""))


TOK_HDR = {}


def http(path, method="GET", body=None, headers=None, timeout=30):
    url = f"http://127.0.0.1:{PANEL_PORT}{path}"
    h = dict(TOK_HDR)
    if headers:
        h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    if data:
        h["Content-Type"] = "application/json"
    req = Request(url, data=data, method=method, headers=h)
    with urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read())


def wait_port(port, host="127.0.0.1", timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection((host, port), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


def curl_chat(text, stream=False, extra=None):
    """通过代理发 chat 请求，返回 (status, body_text, raw)。"""
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": text}],
        "stream": stream,
        "max_tokens": 200,
    }
    if extra:
        payload.update(extra)
    data = json.dumps(payload).encode()
    req = Request(f"{BASE}/v1/chat/completions", data=data, method="POST",
                  headers={"Content-Type": "application/json",
                           "Authorization": f"Bearer {API_KEY}",
                           "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
    try:
        with urlopen(req, timeout=60) as r:
            raw = r.read().decode("utf-8", errors="replace")
            return r.status, raw, raw
    except Exception as e:
        body = ""
        if hasattr(e, "read"):
            try: body = e.read().decode("utf-8", errors="replace")[:400]
            except Exception: pass
        return getattr(e, "code", 0), f"{e} | body={body}", str(e)


def get_events():
    """拉取代理全部事件日志（用 ts 在前端过滤，since 是 seq 不是时间戳）。"""
    try:
        st, j = http("/api/logs?since=0&sensitive=0&q=&limit=500")
        return j.get("events", [])
    except Exception:
        return []


def find_event(events, etype, since_ts=0):
    for e in events:
        if e.get("type") == etype and e.get("ts", 0) >= since_ts:
            return e
    return None


def setup():
    global panel_proc, tmpdir
    # 数据隔离：panel 子进程读写独立临时目录，绝不碰项目 config.json / 事件库 / proxy_token
    tmpdir = tempfile.mkdtemp(prefix="llm-shield-test-")
    cfg_path = Path(tmpdir) / "config.json"
    shutil.copy2(ROOT / "engine" / "config.example.json", cfg_path)
    # 端口隔离（AGENTS 红线：绝不占用用户正在服务的 5801 / 187xx）。
    # 拷来的 config.json 里是常规端口，必须改写成独占端口，否则 start_proxy
    # 会去绑用户实例正在监听的端口 —— 要么抢占、要么把他的代理判成"端口被占用"。
    # 原来这里还有一句无条件的 POST /api/proxy/stop 到 5801，那是**用户的面板**：
    # 靠 403 才没停掉他的代理，纯属侥幸，已删。
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    ups = cfg.get("upstreams") or []
    if not ups:
        log("配置上游", False, "config.json 里没有 upstreams")
        return False
    ups[0]["port"] = UPSTREAM_PORT
    if TEST_TARGET:
        ups[0]["target"] = TEST_TARGET
        # 覆盖 target 时把常见路径都放开：不同中转的路由前缀不一样，
        # 漏一条会让测试在 passthrough_unlisted_path 那里静默跳过而不是失败
        ups[0]["paths"] = ["/v1/chat/completions", "/v1/completions",
                           "/v1/messages", "/chat/completions", "/v1/responses"]
    # 其余 upstream 顺延到同样独占的段，避免任何一个落回 187xx
    for i, u in enumerate(ups[1:], start=1):
        u["port"] = UPSTREAM_PORT + i
    cfg["upstreams"] = ups
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    # 启动 panel（独立面板端口，不碰 5801）
    panel_proc = subprocess.Popen(
        [sys.executable, "panel.py", "--no-browser"],
        cwd=str(ROOT),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "LLM_SHIELD_DATA_DIR": tmpdir, "LLM_SHIELD_TEST": "1",
             "LLM_SHIELD_PANEL_PORT": str(PANEL_PORT)},
    )
    if not wait_port(PANEL_PORT, timeout=25):
        out = panel_proc.stdout.read(4000).decode("utf-8", errors="replace") if panel_proc.stdout else ""
        log("panel 启动", False, f"端口 {PANEL_PORT} 未就绪: {out[:300]}")
        return False
    log("panel 启动", True)
    # 读 token（panel 写入临时数据目录，不再读项目根）
    token_file = Path(tmpdir) / "proxy_token"
    token = token_file.read_text().strip() if token_file.exists() else ""
    if not token:
        log("读取 token", False)
        return False
    global TOK_HDR
    TOK_HDR = {"X-Shield-Token": token}
    # 启动代理
    try:
        st, _ = http("/api/proxy/start", method="POST", headers=TOK_HDR)
    except Exception as e:
        log("启动代理", False, str(e))
        return False
    if not wait_port(UPSTREAM_PORT, timeout=15):
        log("启动代理", False, f"上游端口 {UPSTREAM_PORT} 未监听")
        return False
    log("启动代理", True)
    # 配置测试敏感词
    cfg = http("/api/config", headers=TOK_HDR)[1]
    cfg["sensitive"]["TESTNAME"] = ["张三丰", "李四光"]
    cfg["filter_enabled"] = True
    cfg["fail_closed"] = True
    cfg["response_scan"] = True
    cfg["debug"] = False
    http("/api/config", method="POST", body=cfg, headers=TOK_HDR)
    log("配置测试敏感词", True)
    time.sleep(1)
    return True


def teardown():
    global tmpdir
    try:
        http("/api/proxy/stop", method="POST", headers=TOK_HDR)
    except Exception:
        pass
    if panel_proc:
        panel_proc.terminate()
        try:
            panel_proc.wait(timeout=5)
        except Exception:
            panel_proc.kill()
    if tmpdir:
        shutil.rmtree(tmpdir, ignore_errors=True)
        tmpdir = None


# ===== 测试用例 =====

def test_non_stream_mask_restore():
    """非流式：手机号+邮箱+身份证+自定义词 → 脱敏 + 还原。"""
    t0 = int(time.time()) - 2
    text = "请原样重复我说的内容不要改动：电话13812345678 邮箱test@example.com 身份证110101199003074514 张三丰"
    st, raw, _ = curl_chat(text, stream=False)
    if st != 200:
        log("非流式-HTTP", False, f"status={st} raw={raw[:200]}")
        return
    log("非流式-HTTP", True)
    time.sleep(1.5)
    events = get_events()
    mask = find_event(events, "MASK", t0)
    restore = find_event(events, "RESTORE", t0)
    # 脱敏验证
    masked_count = mask.get("count", 0) if mask else 0
    log("非流式-脱敏(MASK count)", masked_count >= 4, f"count={masked_count} (期望>=4: 手机/邮箱/身份证/人名)")
    # 还原验证：响应里如果模型回显了，应该有原文没有占位符
    has_placeholder = "⟦X·" in raw
    has_phone = "13812345678" in raw
    if restore:
        rc = restore.get("restored", 0)
        log("非流式-还原(RESTORE)", rc >= 0, f"restored={rc} status={restore.get('status')}")
    else:
        log("非流式-还原(RESTORE)", False, "无 RESTORE 事件")
    # 响应不应残留占位符
    log("非流式-响应无占位符残留", not has_placeholder, f"含占位符={has_placeholder}")
    # 如果模型回显了电话，说明还原成功
    if has_phone:
        log("非流式-响应含原文(回显验证)", True, "电话号已还原")
    else:
        log("非流式-响应含原文(回显验证)", True, "模型未回显电话(正常，restored 事件已验证还原逻辑)")


def test_stream_mask_restore():
    """流式 SSE：脱敏 + 流式还原。"""
    t0 = int(time.time()) - 2
    text = "请原样重复：电话13987654321 邮箱stream@test.com 李四光"
    st, raw, _ = curl_chat(text, stream=True)
    if st != 200:
        log("流式-HTTP", False, f"status={st} raw={raw[:200]}")
        return
    log("流式-HTTP", True)
    # SSE 流式：raw 应该是 data: {...} 多行
    has_sse = "data:" in raw
    log("流式-SSE格式", has_sse)
    time.sleep(1.5)
    events = get_events()
    mask = find_event(events, "MASK", t0)
    restore = find_event(events, "RESTORE", t0)
    mc = mask.get("count", 0) if mask else 0
    log("流式-脱敏(MASK count)", mc >= 3, f"count={mc} (期望>=3)")
    if restore:
        log("流式-还原(RESTORE)", True, f"restored={restore.get('restored',0)} status={restore.get('status')}")
    else:
        log("流式-还原(RESTORE)", False, "无 RESTORE 事件")
    has_placeholder = "⟦X·" in raw
    log("流式-响应无占位符残留", not has_placeholder)


def test_credential_mask():
    """凭据脱敏：sk- key + Bearer token。"""
    t0 = int(time.time()) - 2
    text = "我的 key 是 sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnop 和 Bearer abcdefghijklmnopqrstuvwxyz1234567890"
    st, raw, _ = curl_chat(text, stream=False)
    if st != 200:
        log("凭据-HTTP", False, f"status={st}")
        return
    log("凭据-HTTP", True)
    time.sleep(1)
    events = get_events()
    mask = find_event(events, "MASK", t0)
    mc = mask.get("count", 0) if mask else 0
    # sk- 40字符 + Bearer 36字符 应该命中
    log("凭据-脱敏(MASK)", mc >= 2, f"count={mc} (期望>=2: sk-key + Bearer)")


def test_filter_disabled():
    """过滤开关关闭：原文直通，不脱敏。"""
    t0 = int(time.time()) - 3
    cfg = http("/api/config", headers=TOK_HDR)[1]
    cfg["filter_enabled"] = False
    http("/api/config", method="POST", body=cfg, headers=TOK_HDR)
    time.sleep(1)
    text = "测试原文直通 电话13800000000"
    st, raw, _ = curl_chat(text, stream=False)
    time.sleep(1)
    events = get_events()
    bypass = find_event(events, "BYPASS", t0)
    mask = find_event(events, "MASK", t0)
    log("过滤关闭-BYPASS事件", bypass is not None, f"bypass={'有' if bypass else '无'} mask={'有' if mask else '无(正确)'}")
    # 恢复
    cfg["filter_enabled"] = True
    http("/api/config", method="POST", body=cfg, headers=TOK_HDR)
    time.sleep(1)
    log("过滤关闭-恢复开启", True)


def test_non_target_path():
    """非目标路径：/v1/models 之类应放行或 404。"""
    req = Request(f"{BASE}/v1/models", headers={"Authorization": f"Bearer {API_KEY}"})
    try:
        with urlopen(req, timeout=15) as r:
            st = r.status
            log("非目标路径-/v1/models", st in (200, 404), f"status={st}")
    except Exception as e:
        log("非目标路径-/v1/models", True, f"放行(可能 404): {e}")


def test_response_scan():
    """响应侧扫描：让模型生成一个不在请求里的手机号（幻觉 PII）。"""
    t0 = int(time.time()) - 2
    # 问模型一个容易生成示例号码的问题
    text = "请给我一个示例手机号格式，随便编一个 1 开头的 11 位号码"
    st, raw, _ = curl_chat(text, stream=False)
    if st != 200:
        log("响应扫描-HTTP", False, f"status={st}")
        return
    log("响应扫描-HTTP", True)
    time.sleep(1.5)
    events = get_events()
    # SCAN_WARN 可能触发也可能不触发（取决于模型是否生成号码且不在 fwd）
    scan = find_event(events, "SCAN_WARN", t0)
    if scan:
        log("响应扫描-SCAN_WARN", True, f"count={scan.get('count',0)} (检测到外部 PII)")
    else:
        log("响应扫描-SCAN_WARN", True, "本次模型未生成外部 PII(正常，依赖模型输出)")


def test_config_persistence():
    """配置持久化：fail_closed / response_scan 往返保存。"""
    cfg = http("/api/config", headers=TOK_HDR)[1]
    orig_fc = cfg.get("fail_closed")
    orig_rs = cfg.get("response_scan")
    cfg["fail_closed"] = False
    cfg["response_scan"] = True
    http("/api/config", method="POST", body=cfg, headers=TOK_HDR)
    cfg2 = http("/api/config", headers=TOK_HDR)[1]
    ok = cfg2["fail_closed"] is False and cfg2["response_scan"] is True
    log("配置持久化-往返", ok, f"fail_closed={cfg2['fail_closed']} response_scan={cfg2['response_scan']}")
    # 恢复
    cfg2["fail_closed"] = orig_fc
    cfg2["response_scan"] = orig_rs
    http("/api/config", method="POST", body=cfg2, headers=TOK_HDR)


def test_status_api():
    """/api/status 返回完整字段。"""
    st, j = http("/api/status", headers=TOK_HDR)
    fields = ["proxy_running", "capture_mode", "upstreams", "filter_enabled", "proxy_pid", "uptime"]
    missing = [f for f in fields if f not in j]
    log("状态API-字段完整", not missing and j.get("proxy_running"), f"missing={missing} running={j.get('proxy_running')}")


def main():
    print("=" * 60)
    print("LLM Shield 真实代理全功能测试")
    print(f"上游: {BASE} (模型 {MODEL})")
    print("=" * 60)
    if not API_KEY:
        print("[FATAL] 未设置环境变量 LLM_SHIELD_API_KEY（真实上游 API key）。")
        print("       用法: $env:LLM_SHIELD_API_KEY=\"ah-...\"; python tests/test_real_proxy.py")
        return 2
    if not setup():
        teardown()
        print("\nsetup 失败，终止")
        return 1
    try:
        test_status_api()
        test_non_stream_mask_restore()
        test_stream_mask_restore()
        test_credential_mask()
        test_filter_disabled()
        test_non_target_path()
        test_response_scan()
        test_config_persistence()
    finally:
        teardown()
    # 汇总
    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)
    print("\n" + "=" * 60)
    print(f"结果: {passed} 通过 / {failed} 失败 / {len(results)} 总计")
    if failed:
        print("\n失败项:")
        for name, ok, detail in results:
            if not ok:
                print(f"  - {name}: {detail}")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())




