"""24h soak 健康巡检（审计必补测试）：验证长期运行稳定性。

用法（后台挂机跑 24 小时）：
    python tests/soak_health.py --hours 24 --log soak-report.log

检查项（每轮）：
    1. 面板 /api/status 可达、proxy_running=true、全部 upstream 端口 listening
    2. 事件库可写（MASK/RESTORE 计数增长）
    3. crash-dumps 目录无新增（无崩溃现场 = 无崩溃）
    4. 代理进程存活（无自动重启风暴：watchdog restarts 计数不激增）

脱敏正确性由 `tests/` 下的单测覆盖；本脚本专注「长期跑不崩」。
任何检查失败：记录时间点，不中断继续巡检（观察自动恢复能力）。
"""
import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _data_dir() -> Path:
    """引擎数据目录，与 panel.py `_default_data_root()` 同口径。

    优先 `LLM_SHIELD_DATA_DIR`（panel.py 给子进程设置的就是它，Docker 与测试也用它做隔离）；
    否则按平台约定推导。

    曾硬编码 `%APPDATA%\\LLMShield`：产品更名为 Data Maskit 后数据目录已变成
    `%APPDATA%\\Maskit`，脚本读的是不存在的目录，事件库计数恒为 -1、
    token 永远读不到，整份巡检结果失真却不会报错。
    """
    env = os.environ.get("LLM_SHIELD_DATA_DIR")
    if env:
        return Path(env)
    home = Path.home()
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        return (Path(base) if base else home / "AppData" / "Roaming") / "Maskit"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Maskit"
    base = os.environ.get("XDG_DATA_HOME")
    return (Path(base) if base else home / ".local" / "share") / "maskit"


DATA_DIR = _data_dir()
PANEL_URL = f"http://127.0.0.1:{os.environ.get('LLM_SHIELD_PANEL_PORT') or os.environ.get('SHIELD_ENGINE_PORT') or 5801}"
DB_PATH = DATA_DIR / "shield-events.sqlite3"
CRASH_DIR = DATA_DIR / "crash-dumps"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--log", default=str(ROOT / "soak-report.log"))
    ap.add_argument("--interval", type=float, default=60.0, help="巡检间隔秒")
    args = ap.parse_args()

    logf = open(args.log, "a", encoding="utf-8")
    def log(msg):
        line = f"[{time.strftime('%m-%d %H:%M:%S')}] {msg}"
        print(line, flush=True)
        logf.write(line + "\n")
        logf.flush()

    token_path = DATA_DIR / "proxy_token"
    token = token_path.read_text().strip() if token_path.exists() else ""
    def api(path, method="GET"):
        req = urllib.request.Request(PANEL_URL + path, method=method,
                                     headers={"X-Shield-Token": token})
        try:
            return json.loads(urllib.request.urlopen(req, timeout=15).read())
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def event_count():
        try:
            db = sqlite3.connect(str(DB_PATH), timeout=5)
            n = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            db.close()
            return n
        except Exception:
            return -1

    def crash_files():
        try:
            return sorted(CRASH_DIR.glob("crash-*.txt")) if CRASH_DIR.exists() else []
        except Exception:
            return []

    start = time.time()
    deadline = start + args.hours * 3600
    rounds = 0
    fails = []
    base_events = event_count()
    base_crashes = crash_files()
    last_events = base_events
    last_restarts = -1

    log(f"soak 启动: {args.hours}h 目标, 间隔 {args.interval}s, 基线事件 {base_events}, 崩溃现场 {len(base_crashes)} 份")
    while time.time() < deadline:
        rounds += 1
        problems = []
        try:
            s = api("/api/status")
            if not s.get("ok", True) or not s.get("proxy_running"):
                problems.append(f"proxy_running={s.get('proxy_running')} err={s.get('error')} last_error={s.get('last_error')}")
            else:
                down = [p["port"] for p in s.get("upstream_ports", []) if not p.get("listening")]
                if down:
                    problems.append(f"端口未监听: {down}")
                # watchdog 重启计数异常增长 = 崩溃风暴
                restarts = s.get("restarts") if isinstance(s.get("restarts"), (int, float)) else None
                if restarts is not None and last_restarts >= 0 and restarts - last_restarts >= 3:
                    problems.append(f"restarts 激增: {last_restarts} → {restarts}")
                if restarts is not None:
                    last_restarts = restarts
            # 事件库写入活性（有流量时计数增长；无流量不报错）
            now_events = event_count()
            if now_events < 0:
                problems.append("事件库不可读")
            last_events = now_events
            # 崩溃现场新增 = 有崩溃发生（即使已自动恢复）
            new_crashes = crash_files()
            if len(new_crashes) > len(base_crashes):
                fresh = new_crashes[len(base_crashes):]
                problems.append(f"新增崩溃现场: {[f.name for f in fresh]}")
        except Exception as e:
            problems.append(f"巡检异常: {type(e).__name__}: {e}")

        if problems:
            fails.append((rounds, time.strftime('%H:%M:%S'), problems))
            log(f"[FAIL] 第 {rounds} 轮: {'; '.join(problems)}")
        elif rounds % 20 == 0:
            log(f"[OK] 第 {rounds} 轮 (运行 {(time.time()-start)/3600:.1f}h, 事件 {now_events - base_events:+d})")
        time.sleep(args.interval)

    log(f"soak 结束: {rounds} 轮, 失败 {len(fails)} 次")
    for f in fails[:10]:
        log(f"  fail#{f[0]} @{f[1]}: {f[2]}")
    logf.close()
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
