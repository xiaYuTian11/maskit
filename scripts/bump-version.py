#!/usr/bin/env python3
"""全自动版本号自增与同步脚本（跨平台）。

自动同步 Maskit 六处版本号唯一真相：
1. engine/panel.py (__version__)
2. src-tauri/tauri.conf.json (version)
3. src-tauri/Cargo.toml ([package].version)
4. src-tauri/Cargo.lock (name = "maskit" package version)
5. frontend/package.json (version)
6. frontend/package-lock.json (version & packages[""].version)

用法：
  python scripts/bump-version.py          # 自动 patch+1 (如 0.2.3 -> 0.2.4)
  python scripts/bump-version.py 0.2.4    # 指定版本号
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PANEL_PY = ROOT / "engine" / "panel.py"
TAURI_CONF = ROOT / "src-tauri" / "tauri.conf.json"
CARGO_TOML = ROOT / "src-tauri" / "Cargo.toml"
CARGO_LOCK = ROOT / "src-tauri" / "Cargo.lock"
PKG_JSON = ROOT / "frontend" / "package.json"
PKG_LOCK = ROOT / "frontend" / "package-lock.json"


def get_current_version() -> str:
    content = PANEL_PY.read_text(encoding="utf-8")
    m = re.search(r"__version__\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", content)
    if not m:
        raise ValueError(f"Cannot find __version__ in {PANEL_PY}")
    return m.group(1)


def bump_patch(ver: str) -> str:
    parts = [int(p) for p in ver.split(".")]
    parts[2] += 1
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


def main():
    cur = get_current_version()
    if len(sys.argv) > 1:
        target = sys.argv[1].lstrip("v").strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+", target):
            print(f"Error: Invalid version format: {target}", file=sys.stderr)
            return 1
    else:
        target = bump_patch(cur)

    print(f"Bumping version: {cur} -> {target}")

    # 1. engine/panel.py
    panel_src = PANEL_PY.read_text(encoding="utf-8")
    panel_src = re.sub(r"__version__\s*=\s*['\"]\d+\.\d+\.\d+['\"]", f"__version__ = '{target}'", panel_src, count=1)
    PANEL_PY.write_text(panel_src, encoding="utf-8")

    # 2. src-tauri/tauri.conf.json
    conf_src = TAURI_CONF.read_text(encoding="utf-8")
    conf_src = re.sub(r'"version":\s*"\d+\.\d+\.\d+"', f'"version": "{target}"', conf_src, count=1)
    TAURI_CONF.write_text(conf_src, encoding="utf-8")

    # 3. src-tauri/Cargo.toml (仅替换 package 段首个 version)
    cargo_src = CARGO_TOML.read_text(encoding="utf-8")
    cargo_src = re.sub(r'(?m)^version\s*=\s*"\d+\.\d+\.\d+"', f'version = "{target}"', cargo_src, count=1)
    CARGO_TOML.write_text(cargo_src, encoding="utf-8")

    # 4. src-tauri/Cargo.lock
    cargo_lock_src = CARGO_LOCK.read_text(encoding="utf-8")
    cargo_lock_src = re.sub(
        r'(\[\[package\]\]\s*\r?\nname\s*=\s*"maskit"\s*\r?\nversion\s*=\s*)"\d+\.\d+\.\d+"',
        rf'\g<1>"{target}"',
        cargo_lock_src,
        count=1,
    )
    CARGO_LOCK.write_text(cargo_lock_src, encoding="utf-8")

    # 5. frontend/package.json
    pkg_data = json.loads(PKG_JSON.read_text(encoding="utf-8"))
    pkg_data["version"] = target
    PKG_JSON.write_text(json.dumps(pkg_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # 6. frontend/package-lock.json
    lock_data = json.loads(PKG_LOCK.read_text(encoding="utf-8"))
    lock_data["version"] = target
    if "packages" in lock_data and "" in lock_data["packages"]:
        lock_data["packages"][""]["version"] = target
    PKG_LOCK.write_text(json.dumps(lock_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # 验证
    check = subprocess.run([sys.executable, str(ROOT / "scripts" / "check-version.py")], capture_output=True, text=True)
    if check.returncode != 0:
        print("Version check failed after bump:\n" + check.stdout + check.stderr, file=sys.stderr)
        return 1

    print("Success: All 6 locations updated and verified!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
