"""GitHub Actions workflow 校验：YAML 可解析 + 结构完整 + bash 步骤语法正确。

为什么需要这条校验：CI 本身不 lint workflow（没有 actionlint / yamllint），
workflow 写坏只会在「推送后 Actions 页报错」才被发现，最坏情况是拖到打 tag 发版的
那一刻才炸——而那时安装包早就构建完了。所以把「能不能跑」提前到 PR 阶段。

检查项：
1. `.github/workflows/*.yml` 全部能被 YAML 解析，且是含 `jobs` 的映射；
2. 每个 job 必须有 `runs-on`；每个 step 必须**恰好**有 `uses` 或 `run` 之一；
3. 显式 `shell: bash` / `sh` 的步骤，把 `run` 抽出来跑 `bash -n`。
   只查显式 bash：`shell: pwsh` 的步骤拿 bash 语法去验必然误报（已实测）。

bash 的定位：Windows 上 PATH 里的 `bash` 常常是 WSL 垫片（`C:\\Windows\\System32\\bash.exe`），
根本跑不起来，所以用 `MASKIT_BASH` 指定；找不到可用 bash 就跳过第 3 项并打印警告——
CI 的 ubuntu runner 一定有真 bash，真正的 shell 校验在那里发生。

用法：`python scripts/check-workflows.py`（失败退出码 1）
依赖：`pyyaml`（见 requirements-dev.txt）
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
BASH_SHELLS = {"bash", "sh"}


def _find_bash():
    """返回一个真能用的 bash；Windows 上要绕开 WSL 垫片。"""
    override = os.environ.get("MASKIT_BASH")
    if override:
        return override
    found = shutil.which("bash")
    if found and os.name == "nt" and "system32" in found.lower():
        return None
    return found


def main():
    errors = []
    files = sorted(WORKFLOWS.glob("*.yml"))
    if not files:
        print(f"check-workflows: FAIL 没有找到 workflow 文件：{WORKFLOWS}")
        return 1

    bash = _find_bash()
    if bash is None:
        print("check-workflows: 警告 本机没有可用的 bash，跳过 shell 语法校验（CI 的 ubuntu runner 会做）。")
    shell_checked = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        script = pathlib.Path(tmpdir) / "step.sh"
        for path in files:
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                errors.append(f"{path.name}: YAML 解析失败: {exc}")
                continue
            if not isinstance(doc, dict) or "jobs" not in doc:
                errors.append(f"{path.name}: 顶层必须是含 jobs 的映射")
                continue

            for job_name, job in doc["jobs"].items():
                label = f"{path.name}: job {job_name}"
                if not isinstance(job, dict) or "runs-on" not in job:
                    errors.append(f"{label} 缺少 runs-on")
                    continue
                for step in job.get("steps") or []:
                    if not isinstance(step, dict):
                        errors.append(f"{label} 的 step 不是映射")
                        continue
                    name = step.get("name", "(未命名)")
                    has_uses, has_run = "uses" in step, "run" in step
                    if has_uses == has_run:
                        errors.append(f"{label} / {name}: step 必须恰好有 uses 或 run 之一")
                    if has_run and bash and str(step.get("shell", "")).lower() in BASH_SHELLS:
                        shell_checked += 1
                        script.write_text(step["run"], encoding="utf-8", newline="\n")
                        proc = subprocess.run([bash, "-n", str(script)], capture_output=True)
                        if proc.returncode != 0:
                            errors.append(
                                f"{label} / {name}: bash -n 失败\n"
                                + proc.stderr.decode("utf-8", "replace")
                            )
            print(f"check-workflows: OK   {path.name} ({len(doc['jobs'])} jobs)")

    print(f"check-workflows: 共 {len(files)} 个 workflow，bash 步骤校验 {shell_checked} 个")
    if errors:
        print("\n".join(f"check-workflows: FAIL {e}" for e in errors))
        return 1
    print("check-workflows: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
