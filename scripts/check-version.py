#!/usr/bin/env python3
"""版本号一致性检查（CI `version` job 与 build.ps1 共用）。

四处版本必须完全一致，否则安装包文件名、关于页、Docker 标签会各说各话：
  engine/panel.py          __version__（唯一真相来源）
  src-tauri/tauri.conf.json version
  src-tauri/Cargo.toml      [package].version
  frontend/package.json     version

用法：python scripts/check-version.py   （退出码 0 一致 / 1 不一致）
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_versions() -> dict[str, str]:
    panel = (ROOT / "engine" / "panel.py").read_text(encoding="utf-8")
    m = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", panel, re.M)
    tauri = json.loads((ROOT / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
    cargo = (ROOT / "src-tauri" / "Cargo.toml").read_text(encoding="utf-8")
    cm = re.search(r"^\[package\][^\[]*?^version\s*=\s*\"([^\"]+)\"", cargo, re.M | re.S)
    pkg = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    return {
        "engine/panel.py": m.group(1) if m else "<missing>",
        "src-tauri/tauri.conf.json": str(tauri.get("version", "<missing>")),
        "src-tauri/Cargo.toml": cm.group(1) if cm else "<missing>",
        "frontend/package.json": str(pkg.get("version", "<missing>")),
    }


def main() -> int:
    versions = read_versions()
    width = max(len(k) for k in versions)
    for k, v in versions.items():
        print(f"{k:<{width}}  {v}")
    if len(set(versions.values())) != 1:
        print("\nERROR: version mismatch; edit all four to the same value (panel.py is the source of truth)")
        return 1
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
