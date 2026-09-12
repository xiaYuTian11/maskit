"""从 CHANGELOG.md 提取指定版本的完整章节，作为 GitHub Release body。

CHANGELOG.md 本身就是双语（中上英下），写一次就够；发版时按版本号截取对应章节作为
Release 的 markdown body，避免每个 tag 都人工维护两套文案。

用法：
    python3 scripts/render-release-notes.py <version-without-v>

示例：
    python3 scripts/render-release-notes.py 0.2.7
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# CHANGELOG.md 的二级章节标题严格是 `## [<version>]`（带方括号，便于 git diff 不混淆）。
# `## [Unreleased]` 不参与渲染——它面向下次发版，不该出现在线上 Release 页。
_HEADING_PREFIX = "## ["


def render(version: str, changelog: Path = Path("CHANGELOG.md")) -> str:
    """返回 `## [<version>]` 标题之下、下一节标题之上的全部文本（不含标题行）。"""
    # 显式拒绝 Unreleased：它面向下次发版，不该出现在线上 Release 页。
    # 不能只靠「章节为空」兜底 —— Unreleased 一旦写进条目（发版前的正常状态），
    # 那条兜底就不再成立，误传 'Unreleased' 会把未发布内容渲染成 Release body。
    if str(version).strip().lower() == "unreleased":
        raise SystemExit(
            "render-release-notes: 'Unreleased' 不是版本号（该章节面向下次发版，"
            "不该出现在线上 Release 页）——发版前请先把条目移到正式版本章节"
        )
    text = changelog.read_text(encoding="utf-8")
    needle = f"## [{version}]"

    lines = text.splitlines()
    start = next(
        (i + 1 for i, line in enumerate(lines) if line.startswith(needle)),
        None,
    )
    if start is None:
        raise SystemExit(f"render-release-notes: version {version!r} not found in {changelog}")

    end = len(lines)
    for j in range(start, len(lines)):
        if lines[j].startswith(_HEADING_PREFIX):
            end = j
            break

    body = "\n".join(lines[start:end]).rstrip()
    if not body.strip():
        raise SystemExit(
            f"render-release-notes: version {version!r} section is empty in {changelog}"
        )
    return body


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "version",
        help="版本号，例如 0.2.7（不要带 v 前缀，CI 会从 GITHUB_REF_NAME 自己剥）",
    )
    parser.add_argument(
        "--changelog",
        default="CHANGELOG.md",
        type=Path,
        help="CHANGELOG 文件路径（默认 ./CHANGELOG.md）",
    )
    args = parser.parse_args(argv)

    sys.stdout.write(render(args.version, args.changelog))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv[1:])