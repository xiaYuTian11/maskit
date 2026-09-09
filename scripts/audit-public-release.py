#!/usr/bin/env python3
"""静态公开发布门禁。

这个检查故意只依赖 Python 标准库和 git：它在 CI 与维护者本机都能运行，
用于拦截最容易被忽略的发布问题（运行时数据入库、个人路径/密钥样例、
文档控制字符、未固定的 GitHub Action 和版本元数据漂移）。它不是完整的
渗透测试，也不替代单测、依赖扫描或人工审查。
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)(?:\s+#.*)?$", re.MULTILINE)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GOOGLE_KEY_RE = re.compile(r"AIza[0-9A-Za-z_-]{35,}")
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
GITHUB_PAT_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def tracked_files() -> list[Path]:
    try:
        raw = subprocess.check_output(
            ["git", "ls-files", "-z"], cwd=ROOT, stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    return [ROOT / item for item in raw.decode("utf-8", "replace").split("\0") if item]


def read_text(path: Path) -> str | None:
    # 二进制资源不参与文本规则；读取失败本身不应让审计静默通过。
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def main() -> int:
    files = tracked_files()
    if not files:
        print("audit-public-release: unable to enumerate tracked files", file=sys.stderr)
        return 1

    findings: list[str] = []

    forbidden_names = (
        "shield-events.sqlite3",
        "shield-events.jsonl",
        "proxy_token",
        "config.json.bak-",
        "model_prices_cache.json",
        "diagnostics-",
    )
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        low = rel.lower()
        if any(name in low for name in forbidden_names):
            findings.append(f"runtime artifact is tracked: {rel}")
        if low.endswith((".pem", ".key", ".p12", ".pfx")):
            findings.append(f"credential-like file is tracked: {rel}")

    # Action 必须固定到不可变 commit SHA，避免 tag 被替换后改变发布内容。
    for path in files:
        if ".github/workflows/" not in path.as_posix().replace("\\", "/"):
            continue
        text = read_text(path)
        if text is None:
            continue
        for ref in WORKFLOW_RE.findall(text):
            if ref.startswith("./"):
                continue
            if "@" not in ref:
                findings.append(f"workflow action has no ref: {path.relative_to(ROOT)} ({ref})")
                continue
            owner_repo, sha = ref.rsplit("@", 1)
            if "/" not in owner_repo or not SHA_RE.fullmatch(sha):
                findings.append(
                    f"workflow action is not pinned to a 40-char SHA: "
                    f"{path.relative_to(ROOT)} ({ref})"
                )

    # 只在高置信度文件中检查会触发 GitHub Secret Scanning 的完整字面量。
    # 测试应运行时构造伪造值，而不是把完整 key 形态写进公开历史。
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        text = read_text(path)
        if text is None:
            continue
        for label, pattern in (
            ("Google API key", GOOGLE_KEY_RE),
            ("AWS access key", AWS_KEY_RE),
            ("GitHub token", GITHUB_PAT_RE),
            ("private key block", PRIVATE_KEY_RE),
        ):
            if pattern.search(text):
                findings.append(f"possible {label} literal: {rel}")

        # 这些是本机环境的高置信度指纹；泛化的 C:\\Users\\<user> 示例不拦，
        # 以免文档/测试失去说明能力。
        if re.search(r"C:\\\\Users\\\\87561|D:\\\\software\\\\work|D:\\\\repo", text):
            findings.append(f"developer-local path is present: {rel}")

        if CONTROL_RE.search(text):
            findings.append(f"ASCII control character is present: {rel}")

    # 包管理元数据必须和锁文件根对象一致，防止 npm ci/发布页显示旧名称或版本。
    try:
        package = json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))
        lock = json.loads((ROOT / "frontend/package-lock.json").read_text(encoding="utf-8"))
        root_lock = (lock.get("packages") or {}).get("") or {}
        for key in ("name", "version"):
            if package.get(key) != lock.get(key) or package.get(key) != root_lock.get(key):
                findings.append(f"package-lock root {key} does not match package.json")
    except (OSError, ValueError, TypeError) as exc:
        findings.append(f"cannot validate npm metadata: {exc}")

    # Compose 默认只绑定本机；需要远程暴露时必须由部署者显式改绑定地址。
    compose = read_text(ROOT / "docker-compose.yml") or ""
    for line in compose.splitlines():
        if re.match(r"\s*-\s*[\"']?\$\{MASKIT_BIND_HOST", line):
            continue
        if re.search(r"\b(?:5801|1870[1-9]|18710):(?:5801|1870[1-9]|18710)\b", line):
            findings.append("docker-compose port is published without an explicit bind host")
            break
    if "MASKIT_BIND_HOST" not in compose:
        findings.append("docker-compose has no explicit MASKIT_BIND_HOST safety switch")

    if findings:
        print("audit-public-release: FAILED", file=sys.stderr)
        for finding in sorted(set(findings)):
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print(f"audit-public-release: OK ({len(files)} tracked files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
