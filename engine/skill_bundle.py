"""占位符 Skill 包（`agent-bundle/maskit-placeholders`）的定位、渲染与打包。

**单一实现，两处消费**：

- `scripts/pack-skill.py`：门禁 `--check`、生成 `--render`、Release 资产打包；
- `panel.py` 的 `GET /api/skill/bundle`：桌面端 / 容器部署自助下载。

为什么不各写一份：打包逻辑写两份，用户从面板下载到的包与 Release 上的包就会漂移，
而门禁只覆盖其中一条路径——另一条要等用户打开才发现对不上。

**依赖边界**：纯 stdlib。渲染只做「唯一真相源 `contract.md` → 两个渲染目标」的
拼接，不引入模板引擎：规则文本要求两个目标逐字一致，任何"智能"渲染都是在给漂移
留门（比对与渲染用同一份代码，才不会出现"渲出来一样、比出来不一样"）。

**为什么不写真实形态的占位符字面量**：本仓库的开发机在 Maskit 网关之后，写进文件
的 `{{标签_六位后缀}}` 会在落盘时被还原成真实值（`AGENTS.md` §3.9 实测）。因此文档
示例一律用 `{{标签_后缀}}` 这类**引擎不认为是 token** 的形态，`check_bundle` 也会
拒绝包内出现任何严格形态的 token。
"""
from __future__ import annotations

import io
import pathlib
import re
import zipfile

BUNDLE_DIRNAME = "maskit-placeholders"
CONTRACT_FILE = "contract.md"
SKILL_FILE = "SKILL.md"
SNIPPET_FILE = "templates/AGENTS.snippet.md"
README_FILES = ("README.md", "README_EN.md")
GENERATED_FILES = (SKILL_FILE, SNIPPET_FILE)
REQUIRED_FILES = (CONTRACT_FILE, SKILL_FILE, SNIPPET_FILE) + README_FILES

# zip 内统一收在这个顶层目录下：解压后落地的是一个干净目录，不会把几个 md 散进
# 用户的下载目录（与 pack-extension 的 ARCHIVE_ROOT 同一约定）。
ARCHIVE_ROOT = BUNDLE_DIRNAME

# `contract.md` 是渲染源，不随包分发：用户拿到的是渲染后的 SKILL.md，多一个几乎
# 同文的源文件只会让读者分不清该改哪份。
EXCLUDE_FROM_ZIP = frozenset({CONTRACT_FILE})

# 渲染标记：两个目标的规则正文夹在同一个标记对之间，测试与门禁按标记抽取后逐字比对。
CONTRACT_BEGIN = "<!-- BEGIN CONTRACT (generated from contract.md; do not edit) -->"
CONTRACT_END = "<!-- END CONTRACT -->"

SKILL_NAME = "maskit-placeholders"
# description 是宿主**唯一预加载**的内容（渐进式披露），触发条件必须写实：
# 写不好 = 技能永远不被触发（方案 §F3）。
SKILL_DESCRIPTION = (
    "Maskit 本地网关会把敏感原文替换成 {{标签_后缀}} 形态的占位符再发给模型。"
    "当你收到这类占位符，或准备写工具参数、命令、文件与回复时读取本契约——"
    "按它原样使用 token：不编造、不拆分、不替换为示例数据、不无谓拒绝、"
    "不把未完成的任务说成完成。"
)

SKILL_HEADER = """# Maskit 占位符使用契约（Skill）

本文件是本契约的**渲染目标**：正文由 `contract.md` 生成，规则文本与
`templates/AGENTS.snippet.md` 逐字一致（门禁 `scripts/pack-skill.py --check` 会拦下漂移）。
宿主自动加载的是上面 frontmatter 里的 `name` 与 `description`；正文在触发时读取。
"""

SNIPPET_HEADER = """# Maskit 占位符使用契约（AGENTS.md / rules 片段）

适用于不读取 `SKILL.md` 的宿主（Codex CLI、Cursor rules、Gemini CLI 等）：
把下面标记对之间的内容**原样追加**到项目根或用户级的 `AGENTS.md` / rules 文件里。
不要改写成"你自己的版本"——规则文本与 `SKILL.md` 是同一份源渲染出来的。
"""

# 与引擎 `transparent._PLACEHOLDER_RX` / `_LOOSE_PLACEHOLDER_RX` 同构的**严格**形态，
# 只用于"包内不得出现真实 token"这条自检（见模块 docstring）。不 import 引擎：
# 打包脚本要能在没有 mitmproxy/flask 的干净环境里离线跑（门禁 CI 的 version job）。
_STRICT_TOKEN_RX = re.compile(
    r"\{\{[A-Z0-9]{1,12}_(?:[0-9a-f]{6}|[bcdfghjkmnpqrstvwxz]{6})\}\}"
)
_FRONTMATTER_RX = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.DOTALL)


def find_bundle(*candidates: pathlib.Path) -> pathlib.Path:
    """在候选目录里找到第一个「看起来是 Skill 包」的目录。

    候选由调用方给出（打包脚本给仓库路径，面板给打包态路径），本函数不猜环境。
    判据只看 `contract.md`：首次生成时 `SKILL.md` 还不存在，若把生成物也算进判据，
    `--render` 会先因为"找不到包"而拒绝运行（先有鸡还是先有蛋）。
    找不到就抛 `FileNotFoundError`：包是随发布分发的资产，缺失必须显式暴露，
    不能静默返回 None 让调用方各自决定（两处各决定一次 = 两种失败表现）。
    """
    for candidate in candidates:
        if candidate is None:
            continue
        root = pathlib.Path(candidate)
        if root.is_dir() and (root / CONTRACT_FILE).is_file():
            return root
    raise FileNotFoundError(
        "找不到 Skill 包（应包含 %s），候选：%s"
        % (CONTRACT_FILE, ", ".join(str(c) for c in candidates))
    )


def contract_block(root: pathlib.Path) -> str:
    """`contract.md` 的正文块（统一末尾换行，保证两个目标的比对是逐字节的）。"""
    return pathlib.Path(root, CONTRACT_FILE).read_text(encoding="utf-8").rstrip("\n") + "\n"


def _wrap(header: str, block: str) -> str:
    return "%s\n%s\n%s\n%s\n" % (header.rstrip("\n"), CONTRACT_BEGIN, block.rstrip("\n"), CONTRACT_END)


def render(root: pathlib.Path) -> dict[str, str]:
    """渲染两个目标：{相对路径: 内容}。内容即为期望落盘形态。"""
    root = pathlib.Path(root)
    block = contract_block(root)
    skill = "---\nname: %s\ndescription: %s\n---\n\n%s" % (
        SKILL_NAME, SKILL_DESCRIPTION, _wrap(SKILL_HEADER, block))
    snippet = _wrap(SNIPPET_HEADER, block)
    return {SKILL_FILE: skill, SNIPPET_FILE: snippet}


def generated_drift(root: pathlib.Path) -> list[str]:
    """生成物与渲染结果的差异列表（空 = 一致）。"""
    root = pathlib.Path(root)
    issues = []
    for rel, expected in render(root).items():
        path = root / rel
        if not path.is_file():
            issues.append("%s：缺失（跑 scripts/pack-skill.py --render 生成）" % rel)
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected:
            issues.append("%s：与 contract.md 渲染结果不一致（勿手改生成物）" % rel)
    return issues


def frontmatter(text: str) -> dict[str, str]:
    """解析 SKILL.md 的 YAML frontmatter（只认 `key: value` 单行，够用且零依赖）。"""
    match = _FRONTMATTER_RX.match(text)
    if not match:
        return {}
    fields: dict[str, str] = {}
    for line in match.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            return {}
        fields[key.strip()] = value.strip()
    return fields


def check_bundle(root: pathlib.Path) -> list[str]:
    """包级自检（结构 + frontmatter + 渲染一致 + token 安全），返回问题列表。"""
    root = pathlib.Path(root)
    issues: list[str] = []
    for rel in REQUIRED_FILES:
        path = root / rel
        if not path.is_file() or path.stat().st_size == 0:
            issues.append("%s：缺失或为空" % rel)
    if issues:
        return issues

    fields = frontmatter((root / SKILL_FILE).read_text(encoding="utf-8"))
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", fields.get("name", "")):
        issues.append("SKILL.md：frontmatter 的 name 必须是 ≤64 位小写字母/数字/连字符")
    if fields.get("name") != SKILL_NAME:
        issues.append("SKILL.md：name 必须与包目录名一致（%s）" % SKILL_NAME)
    description = fields.get("description", "")
    if len(description) < 20:
        issues.append("SKILL.md：description 过短，宿主不会按预期触发（需写清触发条件）")
    if len(description) > 1024:
        issues.append("SKILL.md：description 超过 1024 字符，部分宿主会截断")

    for rel in GENERATED_FILES:
        text = (root / rel).read_text(encoding="utf-8")
        if text.count(CONTRACT_BEGIN) != 1 or text.count(CONTRACT_END) != 1:
            issues.append("%s：缺少或不唯一的契约标记对" % rel)
        elif _extract_block(text) != contract_block(root).rstrip("\n"):
            issues.append("%s：契约正文字节与 contract.md 不一致" % rel)

    skill_block = _extract_block((root / SKILL_FILE).read_text(encoding="utf-8"))
    snippet_block = _extract_block((root / SNIPPET_FILE).read_text(encoding="utf-8"))
    if skill_block is not None and skill_block != snippet_block:
        issues.append("两个渲染目标的规则文本不一致（规则文本必须逐字一致）")

    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() not in (".md", ".txt", ".json", ".yaml", ".yml"):
            continue
        hit = _STRICT_TOKEN_RX.search(path.read_text(encoding="utf-8", errors="replace"))
        if hit:
            issues.append(
                "%s：含真实形态的占位符字面量 %s（本机网关会把字面量还原后落盘，"
                "示例请用 {{标签_后缀}} 这类非 token 形态）" % (rel, hit.group())
            )
    return issues


def _extract_block(text: str) -> str | None:
    start = text.find(CONTRACT_BEGIN)
    end = text.find(CONTRACT_END)
    if start < 0 or end < 0 or end < start:
        return None
    return text[start + len(CONTRACT_BEGIN):end].strip("\n")


def zipped_files(root: pathlib.Path) -> list[pathlib.Path]:
    """进入 zip 的文件（排除渲染源与缓存目录）。"""
    root = pathlib.Path(root)
    return sorted(
        path for path in root.rglob("*")
        if path.is_file()
        and path.relative_to(root).as_posix() not in EXCLUDE_FROM_ZIP
        and "__pycache__" not in path.parts
        and not path.name.startswith(".")
    )


def build_zip(root: pathlib.Path, dest) -> dict:
    """把包打成 zip。`dest` 可以是路径，也可以是字节流（面板端点用）。

    返回 `{"count", "bytes", "arcnames"}`，供调用方打印/断言。
    """
    root = pathlib.Path(root)
    files = zipped_files(root)
    if not files:
        raise ValueError("Skill 包为空：%s" % root)
    target = pathlib.Path(dest) if isinstance(dest, (str, pathlib.Path)) else dest
    if isinstance(target, pathlib.Path):
        target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, "%s/%s" % (ARCHIVE_ROOT, path.relative_to(root).as_posix()))
    if isinstance(target, pathlib.Path):
        size = target.stat().st_size
    else:
        size = int(getattr(target, "tell", lambda: 0)())
    return {"count": len(files), "bytes": size,
            "arcnames": ["%s/%s" % (ARCHIVE_ROOT, p.relative_to(root).as_posix()) for p in files]}


def build_zip_bytes(root: pathlib.Path) -> bytes:
    """内存打包（面板端点：不落盘，避免安装目录只读 / 并发写同一临时文件）。"""
    buffer = io.BytesIO()
    build_zip(root, buffer)
    return buffer.getvalue()


def verify_zip(dest, root: pathlib.Path) -> None:
    """校验产物本身：能完整读回、清单与源目录一致、SKILL.md 非空。"""
    path = pathlib.Path(dest)
    with zipfile.ZipFile(path) as archive:
        broken = archive.testzip()
        if broken:
            raise ValueError("Skill 包内文件损坏：%s" % broken)
        names = set(archive.namelist())
        expected = {"%s/%s" % (ARCHIVE_ROOT, p.relative_to(root).as_posix())
                    for p in zipped_files(root)}
        if names != expected:
            raise ValueError("Skill 包内清单与源目录不一致：%s" % sorted(names ^ expected))
        if not archive.read("%s/%s" % (ARCHIVE_ROOT, SKILL_FILE)).strip():
            raise ValueError("Skill 包内 %s 为空" % SKILL_FILE)
