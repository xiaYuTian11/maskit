#!/usr/bin/env python3
"""自动组装 Tauri 更新元数据 latest.json。

在指定目录下查找已签名的安装包（*.exe.sig），解析签名与版本信息，
生成符合 tauri-plugin-updater 规范的 latest.json。

用法：
  python scripts/generate-latest-json.py <目录路径> [--tag <tag>] [--repo <owner/repo>]
"""
import argparse
import datetime
import glob
import json
import os
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="生成 latest.json 更新元数据")
    parser.add_argument("dir", help="包含安装包及 .sig 文件的目录")
    parser.add_argument("--tag", default="", help="版本标签（如 v0.2.2，默认从环境变量或文件名解析）")
    parser.add_argument("--repo", default="xiaYuTian11/maskit", help="GitHub 仓库名（owner/repo）")
    args = parser.parse_args()

    root = Path(args.dir).resolve()
    if not root.exists():
        print(f"Directory not found: {root}", file=sys.stderr)
        return 1

    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "xiaYuTian11/maskit")

    # 1. 查找签名文件
    win_sigs = list(root.glob("**/*.exe.sig"))
    mac_sigs = (
        list(root.glob("**/*.app.tar.gz.sig"))
        or list(root.glob("**/*aarch64*.sig"))
        or list(root.glob("**/*darwin*.sig"))
        or list(root.glob("**/*.dmg.sig"))
        or [s for s in root.glob("**/*.sig") if not s.name.endswith(".exe.sig")]
    )

    if not win_sigs and not mac_sigs:
        print(f"No *.sig signature files found in {root}; skipping latest.json", file=sys.stderr)
        return 0

    # 2. 确定 tag 版本
    tag = args.tag or os.environ.get("GITHUB_REF_NAME", "")
    if not tag:
        sample = (win_sigs or mac_sigs)[0].name
        import re
        m = re.search(r"(\d+\.\d+\.\d+)", sample)
        if m:
            tag = f"v{m.group(1)}"
        else:
            tag = "latest"

    # 3. 组装平台数据
    platforms = {}

    # 1) Windows x86_64
    if win_sigs:
        sig_path = win_sigs[0]
        sig_content = sig_path.read_text(encoding="utf-8").strip()
        exe_name = sig_path.with_suffix("").name
        platforms["windows-x86_64"] = {
            "signature": sig_content,
            "url": f"https://github.com/{repo}/releases/download/{tag}/{exe_name}",
        }

    # 2) macOS aarch64 (Apple Silicon)
    if mac_sigs:
        sig_path = mac_sigs[0]
        sig_content = sig_path.read_text(encoding="utf-8").strip()
        bundle_name = sig_path.with_suffix("").name
        platforms["darwin-aarch64"] = {
            "signature": sig_content,
            "url": f"https://github.com/{repo}/releases/download/{tag}/{bundle_name}",
        }

    pub_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    data = {
        "version": tag,
        "notes": f"Data Maskit {tag} 发布更新。",
        "pub_date": pub_date,
        "platforms": platforms,
    }

    out_path = root / "latest.json"
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Successfully generated {out_path} for {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
