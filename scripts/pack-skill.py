#!/usr/bin/env python3
"""把 `agent-bundle/maskit-placeholders/` 打成可直接分发的 zip（Release 资产 + 门禁）。

**为什么需要这个脚本**：Skill 是宿主侧资产，网关代装不了（方案 §F1），只能靠
「能下载到的文件 + 用户/工具自行安装」。没有这个 zip，用户从 Release 下到手里的
只有安装包，拿不到行为契约；而契约缺失时模型会自己发明规则（把占位符换成
`sk-test-*`、对 token 做哈希、声称被阻断的任务已完成）。

**边界**：包内容的结构、渲染一致性与 token 安全由 `engine/skill_bundle.py` 负责
（`check_bundle`），本脚本只管「能不能打成包、打出来的包内容对不对、示例会不会
命中发布审计」。渲染源是 `contract.md`，`SKILL.md` 与 `templates/AGENTS.snippet.md`
都是它的渲染目标——**不要手改生成物**，改源文件后跑 `--render`。

用法：
    python scripts/pack-skill.py                 # 产出 dist_skill/Maskit_<版本>_skill.zip
    python scripts/pack-skill.py --render        # 从 contract.md 重新渲染两个目标
    python scripts/pack-skill.py --check         # 只渲染/打包并校验，不留产物（门禁用）
    python scripts/pack-skill.py --out <目录>     # 指定产物目录

版本号取自 `engine/panel.py` 的 `__version__`（仓库唯一真相来源），产物命名与安装包
（`Maskit_<版本>_x64-setup.exe`）和扩展包（`Maskit_<版本>_extension.zip`）对齐。
"""
from __future__ import annotations

import argparse
import importlib.util
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENGINE_DIR = ROOT / "engine"
BUNDLE_DIR = ROOT / "agent-bundle" / "maskit-placeholders"
PANEL_PY = ENGINE_DIR / "panel.py"
AUDIT_SCRIPT = ROOT / "scripts" / "audit-public-release.py"

sys.path.insert(0, str(ENGINE_DIR))
import skill_bundle  # noqa: E402  （engine/ 必须先进 sys.path）


def _load_module(path: pathlib.Path, name: str):
    """按路径加载脚本模块（`audit-public-release.py` 带连字符，不能直接 import）。

    直接 import 那几条正则而不是复制一份：复制的那份一旦与审计脚本漂移，
    自检就从"拦住事故"变成"给我们一个虚假的安心"。
    """
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _product_version() -> str:
    match = re.search(
        r"^__version__\s*=\s*['\"]([^'\"]+)['\"]",
        PANEL_PY.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not match:
        raise SystemExit("pack-skill: 无法从 engine/panel.py 读到 __version__")
    return match.group(1)


def _audit_hits(root: pathlib.Path) -> list[str]:
    """包内文本是否命中发布审计的凭据正则（§F5：命中即 CI 红，必须在这里先炸）。"""
    audit = _load_module(AUDIT_SCRIPT, "_audit_public_release")
    patterns = [("GOOGLE_KEY_RE", audit.GOOGLE_KEY_RE),
                ("AWS_KEY_RE", audit.AWS_KEY_RE),
                ("GITHUB_PAT_RE", audit.GITHUB_PAT_RE),
                ("PRIVATE_KEY_RE", audit.PRIVATE_KEY_RE),
                ("CONTROL_RE", audit.CONTROL_RE)]
    hits = []
    for path in skill_bundle.zipped_files(root):
        if path.suffix.lower() not in (".md", ".txt", ".json", ".yaml", ".yml"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, rx in patterns:
            if rx.search(text):
                hits.append("%s 命中 %s" % (path.relative_to(root).as_posix(), name))
    return hits


def _render(root: pathlib.Path) -> None:
    for rel, content in skill_bundle.render(root).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print("pack-skill: rendered %s" % rel)


def main() -> int:
    parser = argparse.ArgumentParser(description="把 Skill 包打成可分发 zip")
    parser.add_argument("--out", default="dist_skill", help="产物目录（默认 dist_skill）")
    parser.add_argument("--check", action="store_true", help="只渲染/打包并校验，不保留产物（门禁用）")
    parser.add_argument("--render", action="store_true", help="从 contract.md 重新渲染两个目标后退出")
    args = parser.parse_args()

    root = skill_bundle.find_bundle(BUNDLE_DIR)
    if args.render:
        _render(root)
        return 0

    # 顺序刻意如此：先渲染一致性，再看审计。渲染漂移说明包内文本不是源文件的产物，
    # 此时审计和打包都没有意义（审的是旧文本、打的是旧包）。
    issues = skill_bundle.generated_drift(root) + skill_bundle.check_bundle(root)
    issues += _audit_hits(root)
    if issues:
        for issue in issues:
            print("pack-skill: FAIL %s" % issue, file=sys.stderr)
        return 1

    version = _product_version()
    name = "Maskit_%s_skill.zip" % version
    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / name
            stats = skill_bundle.build_zip(root, dest)
            skill_bundle.verify_zip(dest, root)
        print("pack-skill: OK   %s  %d 文件 / %d 字节（--check，未留产物）"
              % (name, stats["count"], stats["bytes"]))
        return 0

    out_dir = pathlib.Path(args.out)
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    dest = out_dir / name
    stats = skill_bundle.build_zip(root, dest)
    skill_bundle.verify_zip(dest, root)
    print("pack-skill: OK   %s  %d 文件 / %d 字节  -> %s"
          % (name, stats["count"], stats["bytes"], dest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
