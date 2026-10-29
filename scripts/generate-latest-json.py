#!/usr/bin/env python3
"""自动组装 Tauri 更新元数据 latest.json。

在指定目录下查找已签名的安装包（*.exe.sig / *.app.tar.gz.sig / *.AppImage.sig /
*.deb.sig），解析签名与版本信息，生成符合 tauri-plugin-updater 规范的 latest.json。

Linux 的 deb 与 AppImage 各占一条独立条目（`linux-<arch>-deb` / `linux-<arch>`）：
updater 以 `{os}-{arch}-{bundle_type}` 查找，取错载体时 install_deb 会直接报
`invalid updater binary format`。

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

# 与 check-changelog.py 共用同一套「更新摘要」解析（scripts/release_notes.py）。
# 脚本按路径运行时 sys.path[0] 就是 scripts/，但单测用 importlib 按路径加载本文件时
# 不会 —— 显式插入，两种执行方式都成立。
sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_notes as rn  # noqa: E402


def _release_notes(tag: str, changelog_path: Path | None = None) -> str:
    """从 CHANGELOG 的对应版本章节生成**简短**中英双语更新说明。

    优先取 `### 更新摘要 / Summary`：那是写给用户的一两句话，直接放进更新弹窗。
    此前这里只数条数（「修复 2 项」），用户点更新等于什么都没看到 —— issue #40
    的原话是「版本介绍写的是人类能读的东西吗」。

    老版本（没写摘要）或章节缺失时回退到条数统计，最差回退到通用文案 ——
    文案不完整可以接受，但绝不能因此让发版流程失败。

    为什么不用整章：更新器弹窗只有几行高度，0.4.0 的章节有 2509 字节双语条目，
    全部塞进去用户得滚半天才看完，反而没人读。细节留给 Release 页（那里的 body
    由 render-release-notes.py 切出全文）。
    """
    fallback = f"Data Maskit {tag} 发布更新。"
    try:
        # 默认从仓库根的 CHANGELOG 读；参数用于单测注入临时文件。
        changelog = changelog_path or (Path(__file__).resolve().parent.parent / "CHANGELOG.md")
        text = changelog.read_text(encoding="utf-8")
    except OSError:
        return fallback

    ver = tag.lstrip("v")
    sec = dict(rn.split_versions(text)).get(ver)
    if sec is None:
        return fallback

    # ① 人话摘要：最多 3 条、总长 600 字符（弹窗高度有限，见 user_notes 的 docstring）
    human = rn.user_notes(sec, max_items=3, max_chars=600)
    if human:
        return f"Data Maskit {tag}\n{human}"

    # ② 回退：老版本没有摘要时，保留原来的条数统计
    body = sec

    import re as _re

    # 分节标题要**中英都能认**：CHANGELOG 用的是「### 新增 / Added」这种双语标题，
    # 但只带英文（### Added）或只带中文的写法也可能出现，因此两者任意命中即可。
    # 英文侧用词干（add / fix / chang）而不是全词：标题里可能是 Fixed 也可能是
    # Fixes、Changed 或 Changes，写死全词会整节漏算（漏一节只是摘要少一项，
    # 但那是静默的错数字，比报错更难发现）。
    labels = (("新增", "add", "Added"), ("修复", "fix", "Fixed"), ("优化", "chang", "Changed"))
    parts_cn: list[str] = []
    parts_en: list[str] = []
    for cn, en_kw, en_out in labels:
        m = _re.search(
            rf"^###[^\n]*(?:{cn}|{en_kw})[^\n]*\n(.*?)(?=^###|\Z)",
            body, _re.S | _re.M | _re.I,
        )
        if not m:
            continue
        n = len(_re.findall(r"^- ", m.group(1), _re.M))
        if n:
            parts_cn.append(f"{cn} {n} 项")
            parts_en.append(f"{n} {en_out.lower()}")
    if not parts_cn:
        return fallback

    return (f"Data Maskit {tag}：{'、'.join(parts_cn)}。详见 Release 页。\n"
            f"Data Maskit {tag}: {', '.join(parts_en)}. See the release page for details.")


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
    all_sigs = list(root.glob("**/*.sig"))
    win_sigs = [s for s in all_sigs if s.name.endswith(".exe.sig") or "windows" in s.as_posix().lower()]
    mac_sigs = [
        s for s in all_sigs
        if s not in win_sigs and (
            s.name.endswith(".app.tar.gz.sig")
            or "darwin" in s.as_posix().lower()
            or "macos" in s.as_posix().lower()
            or s.name.endswith(".dmg.sig")
        )
    ]
    linux_sigs = [
        s for s in all_sigs
        if s not in win_sigs and s not in mac_sigs and (
            ".appimage" in s.name.lower()
            or "linux" in s.as_posix().lower()
            or any(k in s.name.lower() for k in ("amd64", "x86_64", "aarch64", "arm64"))
        )
    ]
    # updater 只认 `.app.tar.gz`，`.dmg` 是首次安装用的；取错会让自动更新 404。
    # 必须**显式排序**：`root.glob()` 的枚举顺序由文件系统决定（2026-10-29 实测
    # 同一份代码本地绿、CI 红，根因就是 dmg 恰好在前面），直接取 `[0]` 会让同一份
    # release 在不同机器上产出不同的 latest.json。排序键让 `.app.tar.gz` 恒优先，
    # `.dmg` 只在没有 updater 载体时兜底。
    mac_sigs.sort(key=lambda s: (0 if s.name.endswith(".app.tar.gz.sig") else 1, s.name))

    # deb 是「系统包管理器安装」形态，与 AppImage 不是同一个更新载体，必须拆开。
    # 为什么不能共用 `linux-x86_64`：那条给 AppImage 用，deb 安装的客户端会先按
    # `linux-x86_64-deb` 找、找不到才回退到 `linux-x86_64`，于是拿到 AppImage；
    # 而 updater 的 install_deb 会先做 `is_deb()` 校验，失败即抛
    # `invalid updater binary format`（v0.7.0 实测事故：deb 用户点更新直接报格式错）。
    deb_sigs = [s for s in linux_sigs if s.name.lower().endswith(".deb.sig")]
    linux_sigs = [s for s in linux_sigs if s not in deb_sigs]

    linux_x64_sigs = [
        s for s in linux_sigs
        if any(k in s.as_posix().lower() for k in ("amd64", "x86_64", "x64", "linux-x64"))
        or not any(k in s.as_posix().lower() for k in ("arm64", "aarch64", "linux-arm64"))
    ]
    linux_arm64_sigs = [
        s for s in linux_sigs
        if any(k in s.as_posix().lower() for k in ("arm64", "aarch64", "linux-arm64"))
    ]
    # deb 侧同口径按架构拆（包名里带 amd64 / arm64）。
    deb_x64_sigs = [
        s for s in deb_sigs
        if any(k in s.as_posix().lower() for k in ("amd64", "x86_64", "x64", "linux-x64"))
    ]
    deb_arm64_sigs = [
        s for s in deb_sigs
        if any(k in s.as_posix().lower() for k in ("arm64", "aarch64", "linux-arm64"))
    ]

    if not win_sigs and not mac_sigs and not linux_sigs and not deb_sigs:
        print(f"No *.sig signature files found in {root}; skipping latest.json", file=sys.stderr)
        return 0

    # 2. 确定 tag 版本
    tag = args.tag or os.environ.get("GITHUB_REF_NAME", "")
    if not tag:
        sample = (win_sigs or mac_sigs or linux_sigs or deb_sigs)[0].name
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

    # 3) Linux x86_64
    if linux_x64_sigs:
        sig_path = linux_x64_sigs[0]
        sig_content = sig_path.read_text(encoding="utf-8").strip()
        bundle_name = sig_path.with_suffix("").name
        platforms["linux-x86_64"] = {
            "signature": sig_content,
            "url": f"https://github.com/{repo}/releases/download/{tag}/{bundle_name}",
        }

    # 4) Linux aarch64 (ARM64)
    if linux_arm64_sigs:
        sig_path = linux_arm64_sigs[0]
        sig_content = sig_path.read_text(encoding="utf-8").strip()
        bundle_name = sig_path.with_suffix("").name
        platforms["linux-aarch64"] = {
            "signature": sig_content,
            "url": f"https://github.com/{repo}/releases/download/{tag}/{bundle_name}",
        }

    # 5) Linux x86_64 (deb)：updater 运行时按 `{os}-{arch}-{bundle_type}` 查找，deb 安装的
    #    客户端会命中这里。url 必须指向 .deb 本体（install_deb 的 is_deb 校验要求真 deb 字节）。
    if deb_x64_sigs:
        sig_path = deb_x64_sigs[0]
        pkg_name = sig_path.with_suffix("").name  # 去掉 .sig → xxx.deb
        platforms["linux-x86_64-deb"] = {
            "signature": sig_path.read_text(encoding="utf-8").strip(),
            "url": f"https://github.com/{repo}/releases/download/{tag}/{pkg_name}",
        }

    # 6) Linux aarch64 (deb)
    if deb_arm64_sigs:
        sig_path = deb_arm64_sigs[0]
        pkg_name = sig_path.with_suffix("").name
        platforms["linux-aarch64-deb"] = {
            "signature": sig_path.read_text(encoding="utf-8").strip(),
            "url": f"https://github.com/{repo}/releases/download/{tag}/{pkg_name}",
        }

    pub_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    data = {
        "version": tag,
        "notes": _release_notes(tag),
        "pub_date": pub_date,
        "platforms": platforms,
    }

    out_path = root / "latest.json"
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Successfully generated {out_path} for {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
