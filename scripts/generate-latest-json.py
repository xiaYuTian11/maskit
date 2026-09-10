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

    sigs = list(root.glob("**/*.exe.sig"))
    if not sigs:
        print(f"No *.exe.sig files found in {root}; skipping latest.json", file=sys.stderr)
        return 0

    sig_path = sigs[0]
    sig_content = sig_path.read_text(encoding="utf-8").strip()
    exe_path = sig_path.with_suffix("")
    exe_name = exe_path.name

    tag = args.tag or os.environ.get("GITHUB_REF_NAME", "")
    if not tag:
        # 从文件名尝试提取：Maskit_0.2.2_x64-setup.exe -> v0.2.2
        import re
        m = re.search(r"(\d+\.\d+\.\d+)", exe_name)
        if m:
            tag = f"v{m.group(1)}"
        else:
            tag = "latest"

    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "xiaYuTian11/maskit")
    pub_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    data = {
        "version": tag,
        "notes": f"Data Maskit {tag} 发布更新。",
        "pub_date": pub_date,
        "platforms": {
            "windows-x86_64": {
                "signature": sig_content,
                "url": f"https://github.com/{repo}/releases/download/{tag}/{exe_name}",
            }
        },
    }

    out_path = root / "latest.json"
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Successfully generated {out_path} for {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
