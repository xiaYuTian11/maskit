#!/usr/bin/env python3
"""版本号一致性检查（CI `version` job 与 build.ps1 共用）。

四处版本必须完全一致，否则安装包文件名、关于页、Docker 标签会各说各话：
  engine/panel.py          __version__（唯一真相来源）
  src-tauri/tauri.conf.json version
  src-tauri/Cargo.toml      [package].version
  frontend/package.json     version

用法：python scripts/check-version.py   （退出码 0 一致 / 1 不一致）
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def read_versions() -> dict[str, str]:
    panel = (ROOT / "engine" / "panel.py").read_text(encoding="utf-8")
    m = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", panel, re.M)
    tauri = json.loads((ROOT / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
    cargo = (ROOT / "src-tauri" / "Cargo.toml").read_text(encoding="utf-8")
    cm = re.search(r"^\[package\][^\[]*?^version\s*=\s*\"([^\"]+)\"", cargo, re.M | re.S)
    pkg = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    versions = {
        "engine/panel.py": m.group(1) if m else "<missing>",
        "src-tauri/tauri.conf.json": str(tauri.get("version", "<missing>")),
        "src-tauri/Cargo.toml": cm.group(1) if cm else "<missing>",
        "frontend/package.json": str(pkg.get("version", "<missing>")),
    }

    # Cargo.lock is part of the published source and can retain an old root package
    # version even when Cargo.toml was updated. Validate the exact maskit package entry.
    lock_path = ROOT / "src-tauri" / "Cargo.lock"
    if lock_path.exists():
        lock = lock_path.read_text(encoding="utf-8")
        lm = re.search(
            r"(?ms)^\[\[package\]\]\s*\nname\s*=\s*\"maskit\"\s*\nversion\s*=\s*\"([^\"]+)\"",
            lock,
        )
        versions["src-tauri/Cargo.lock"] = lm.group(1) if lm else "<missing>"

    # npm lockfile has two independent root version fields. Both must agree with the
    # package manifest; replacing only the first one makes npm ci reject the tree.
    lock_path = ROOT / "frontend" / "package-lock.json"
    if lock_path.exists():
        lock_obj = json.loads(lock_path.read_text(encoding="utf-8"))
        root_pkg = (lock_obj.get("packages") or {}).get("") or {}
        versions["frontend/package-lock.json"] = str(lock_obj.get("version", "<missing>"))
        versions["frontend/package-lock#root"] = str(root_pkg.get("version", "<missing>"))
        versions["frontend/package-lock#name"] = str(root_pkg.get("name", "<missing>"))
        versions["frontend/package.json#name"] = str(pkg.get("name", "<missing>"))
    return versions


def check_tag(tag: str, version: str) -> list[str]:
    errors: list[str] = []
    normalized = tag[1:] if tag.startswith("v") else tag
    if not tag.startswith("v") or not SEMVER_RE.fullmatch(normalized):
        errors.append(f"tag must match vX.Y.Z (got {tag!r})")
    elif normalized != version:
        errors.append(f"tag {tag} does not match source version {version}")

    # A release job checks out the complete tag history. Comparing the resolved tag
    # commit prevents accidentally publishing a package built from another ref.
    try:
        tag_commit = subprocess.check_output(
            ["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
        head_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
        if tag_commit != head_commit:
            errors.append(f"tag {tag} resolves to {tag_commit[:12]}, but HEAD is {head_commit[:12]}")
    except (OSError, subprocess.CalledProcessError) as exc:
        errors.append(f"cannot resolve release tag {tag}: {exc}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Check release version consistency")
    parser.add_argument(
        "--tag",
        default="",
        help="optional release tag (must be vX.Y.Z and point at HEAD)",
    )
    args = parser.parse_args()

    try:
        versions = read_versions()
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        print(f"ERROR: cannot read version metadata: {exc}")
        return 1
    width = max(len(k) for k in versions)
    for k, v in versions.items():
        print(f"{k:<{width}}  {v}")

    errors: list[str] = []
    primary_keys = (
        "engine/panel.py",
        "src-tauri/tauri.conf.json",
        "src-tauri/Cargo.toml",
        "frontend/package.json",
    )
    primary = [versions[key] for key in primary_keys]
    if any(not SEMVER_RE.fullmatch(v) for v in primary):
        errors.append("one or more primary version fields are missing or not strict X.Y.Z")
    if len(set(primary)) != 1:
        errors.append("panel.py / tauri.conf.json / Cargo.toml / package.json versions differ")

    expected = primary[0] if primary else ""
    for key in ("src-tauri/Cargo.lock", "frontend/package-lock.json", "frontend/package-lock#root"):
        value = versions.get(key)
        if value is not None and value != expected:
            errors.append(f"{key} version {value} does not match {expected}")
    if versions.get("frontend/package-lock#name") != versions.get("frontend/package.json#name"):
        errors.append("package.json and package-lock.json root names differ")

    if args.tag and expected:
        errors.extend(check_tag(args.tag, expected))

    if errors:
        print("\nERROR: version consistency check failed")
        for error in errors:
            print(f"- {error}")
        return 1
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
