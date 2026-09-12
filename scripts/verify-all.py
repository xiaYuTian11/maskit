"""全量本地门禁的唯一清单与执行入口。

**为什么要有这个文件**：门禁原先散在两处 —— `build.ps1` 只跑
「py_compile + 单测 + 前端构建」三样，`ci.yml` 跑全量。于是本地发版完全可能
「过了 build.ps1 却被 CI 拦下」，而那时 tag 已经推到远端、Release 已经在建了。
这里把清单收敛成唯一真相：

* `build.ps1`（本地发版）直接调本脚本；
* `ci.yml` 按 group 拆成四个 job 并行跑（保留逐步日志粒度）；
* `scripts/check-workflows.py` 会比对两边，任何一侧漏加/多加都会在 PR 阶段报错。

用法：
    python scripts/verify-all.py                    # 全跑
    python scripts/verify-all.py --only python,repo # 只跑某几组
    python scripts/verify-all.py --list             # 打印门禁清单（JSON，供漂移比对）
    python scripts/verify-all.py --python <解释器>   # 指定解释器（默认 MASKIT_PYTHON / 当前解释器）

零第三方依赖（stdlib only），这样在装依赖之前就能跑。
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# group 名与 ci.yml 的 job 名一一对应（python / frontend / rust / version）。
# 用 dict 列表而不是自由函数，是为了让 --list 能把它交给漂移比对。
GATES = [
    # ---- python（ci.yml: python job）----
    {"group": "python", "name": "Compile check", "cwd": ".", "argv": ["{python}", "-m", "py_compile", "@engine/*.py"]},
    {"group": "python", "name": "Unit tests", "cwd": ".", "argv": ["{python}", "-m", "unittest", "discover", "-s", "tests"]},
    {"group": "python", "name": "Smoke tests (stream)", "cwd": ".", "argv": ["{python}", "tests/smoke_stream.py"]},
    {"group": "python", "name": "Smoke tests (egress)", "cwd": ".", "argv": ["{python}", "tests/smoke_egress.py"]},
    # ---- frontend（ci.yml: frontend job，工作目录 frontend/）----
    {"group": "frontend", "name": "Typecheck & build", "cwd": "frontend", "argv": ["{npm}", "run", "build"]},
    {"group": "frontend", "name": "Lint", "cwd": "frontend", "argv": ["{npm}", "run", "lint"]},
    {"group": "frontend", "name": "i18n dictionary parity", "cwd": "frontend", "argv": ["{node}", "../scripts/check-i18n.mjs"]},
    {"group": "frontend", "name": ".env import parser cases", "cwd": "frontend",
     "argv": ["{node}", "--experimental-strip-types", "../scripts/check-env-import.mjs"]},
    # ---- rust（ci.yml: rust job，工作目录 src-tauri/）----
    {"group": "rust", "name": "Cargo check", "cwd": "src-tauri", "argv": ["{cargo}", "check"]},
    {"group": "rust", "name": "Cargo test", "cwd": "src-tauri", "argv": ["{cargo}", "test", "--lib"]},
    # ---- version（ci.yml: version job）----
    {"group": "version", "name": "Version numbers agree", "cwd": ".", "argv": ["{python}", "scripts/check-version.py"]},
    {"group": "version", "name": "Public release audit", "cwd": ".", "argv": ["{python}", "scripts/audit-public-release.py"]},
    {"group": "version", "name": "Workflow YAML and shell syntax", "cwd": ".", "argv": ["{python}", "scripts/check-workflows.py"]},
]

GROUPS = ["python", "frontend", "rust", "version"]


def _expand(spec: str, python: str, node: str, npm: str, cargo: str) -> list[str]:
    """把 argv 模板里的占位符与 @glob 展开成真正的命令行。"""
    out = []
    for token in spec:
        token = (token.replace("{python}", python).replace("{node}", node)
                 .replace("{npm}", npm).replace("{cargo}", cargo))
        if token.startswith("@"):
            # py_compile 的 engine/*.py 在 POSIX shell 里由 shell 展开，在 Windows 上
            # 由 PowerShell 展开；这里由 Python 展开，跨平台一致。
            hits = sorted(glob.glob(str(ROOT / token[1:])))
            if not hits:
                raise SystemExit(f"verify-all: 通配符没有匹配到文件：{token[1:]}")
            out.extend(hits)
        else:
            out.append(token)
    return out


def _resolve_python(explicit: str | None) -> str:
    return explicit or os.environ.get("MASKIT_PYTHON") or sys.executable


def _resolve_node() -> str | None:
    return shutil.which("node")


def _resolve_npm() -> str | None:
    # Windows 上 npm 是 npm.CMD：CreateProcess **不套用 PATHEXT**，裸名 "npm" 会直接
    # FileNotFoundError [WinError 2]，必须用 which 解析出的完整路径。
    return shutil.which("npm") or shutil.which("npm.cmd")


def _resolve_cargo() -> str:
    # cargo 是 cargo.exe，裸名本来就能跑；仍解析一次，只为在缺失时给出清晰报错。
    return shutil.which("cargo") or "cargo"


def _child_env(python: str) -> dict:
    env = dict(os.environ)
    # smoke_*.py 直接调 `mitmdump`；把解释器所在目录前置到 PATH，否则 Windows 上会
    # 命中 AppData\Roaming\Python\...\mitmdump.exe（没装 mitmproxy）而失败。
    bindir = str(pathlib.Path(python).resolve().parent)
    env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
    # WorkBuddy/CI 注入的 PYTHONPATH 会把 vendor shim 的 sitecustomize 拉进来，
    # 其 safe-delete 守卫会让部分用例在 finally 里 SystemExit。门禁必须干净。
    env.pop("PYTHONPATH", None)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return env


def main() -> int:
    ap = argparse.ArgumentParser(description="全量本地门禁（与 ci.yml 一一对应）")
    ap.add_argument("--only", default="", help="逗号分隔的组名，默认全部")
    ap.add_argument("--list", action="store_true", help="打印门禁清单 JSON 后退出")
    ap.add_argument("--python", default=None, help="Python 解释器路径")
    ap.add_argument("--dry-run", action="store_true", help="只打印将执行的命令")
    args = ap.parse_args()

    if args.list:
        print(json.dumps([{**g, "argv": list(g["argv"])} for g in GATES], ensure_ascii=False, indent=2))
        return 0

    only = {g.strip() for g in args.only.split(",") if g.strip()}
    unknown = only - set(GROUPS)
    if unknown:
        print(f"verify-all: FAIL 未知的组：{sorted(unknown)}（可选：{GROUPS}）")
        return 1

    python = _resolve_python(args.python)
    node = _resolve_node()
    npm = _resolve_npm()
    cargo = _resolve_cargo()
    if not pathlib.Path(python).exists() and not shutil.which(python):
        print(f"verify-all: FAIL 找不到 Python 解释器：{python}")
        return 1
    if node is None:
        print("verify-all: FAIL 找不到 node（前端与脚本校验需要）")
        return 1
    if npm is None and (not only or "frontend" in only):
        print("verify-all: FAIL 找不到 npm（前端门禁需要）")
        return 1

    selected = [g for g in GATES if not only or g["group"] in only]
    env = _child_env(python)
    failed: list[str] = []

    print(f"verify-all: 共 {len(selected)} 项门禁，解释器 {python}")
    for i, gate in enumerate(selected, 1):
        argv = _expand(gate["argv"], python, node or "node", npm or "npm", cargo)
        cwd = ROOT / gate["cwd"]
        label = f"[{i}/{len(selected)}] {gate['group']} · {gate['name']}"
        print(f"\n=== {label} ===", flush=True)
        print(f"    $ {' '.join(argv)}", flush=True)
        if args.dry_run:
            continue
        proc = subprocess.run(argv, cwd=str(cwd), env=env)
        if proc.returncode != 0:
            failed.append(f"{gate['group']} · {gate['name']} (exit {proc.returncode})")
            print(f"!!! 失败：{label}", flush=True)
            # 门禁是串行的且后一项依赖前一项的产物（构建产物、解释器状态），
            # 失败即停，避免后面刷屏掩盖真正的第一现场。
            break

    if args.dry_run:
        print("\nverify-all: DRY RUN，未执行任何命令。")
        return 0
    if failed:
        print("\nverify-all: FAIL")
        for f in failed:
            print(f"  - {f}")
        return 1
    print(f"\nverify-all: OK（{len(selected)} 项门禁全部通过）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
