"""运行期环境变量的文档一致性：`MASKIT_*` 必须登记在 `SECURITY.md`。

为什么要有这条：`MASKIT_*` 是**运维面**的开关（关缓存、调并发、换渲染目录、限预算……），
用户能不能发现某个能力，只取决于 `SECURITY.md` 那张表。2026-10-04 实测：批次 8 新增的
`MASKIT_LEAF_CACHE_*` / `MASKIT_NER_PREFETCH_LEAVES`、以及更早的 `MASKIT_SKILL_BUNDLE`
/ `MASKIT_WEB_DIST` 全都没登记 —— 代码能用，但没人知道它存在（等于没这个能力）。
这类漂移靠人记不住：新增变量的人在看代码，查变量的人在看文档。

判据只用**字面量读取**（`os.environ.get("MASKIT_X")` / `_env_int("MASKIT_X", ...)`），
不扫常量名 —— `MASKIT_MASK_WORKERS_ENV = _env_int("MASKIT_MASK_WORKERS", 0)` 这种取值常量
不是变量名本身，扫进来会误报。
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "SECURITY.md"

#: 读取环境变量的几种写法（引擎侧统一走 _env_* 助手，其余直接读 environ）
_READERS = r"(?:os\.environ\.get|os\.environ\[|_env_int|_env_float|_env_str|_env_bool)"
_PATTERN = re.compile(_READERS + r'\(\s*"(MASKIT_[A-Z0-9_]+)"')
#: SECURITY.md 里的登记形式：表格首列的 `MASKIT_X`（可能一行登记多个，用 `/` 分隔）
_DOC_ROW = re.compile(r"^\|\s*(`MASKIT_[A-Z0-9_]+`(?:\s*/\s*`MASKIT_[A-Z0-9_]+`)*)", re.M)

#: 不进 SECURITY.md 表的变量：只服务本机开发/门禁脚本，不影响运行中的引擎行为
_DEV_ONLY = {
    "MASKIT_BASH",      # scripts/verify-all.py：指定 bash（Windows 本地 WSL 垫片绕行）
    "MASKIT_PYTHON",    # scripts/verify-all.py / build.sh：指定解释器
    "MASKIT_NO_GATES",  # build.sh --no-gates 的等价环境变量
}


def _documented():
    text = SECURITY.read_text(encoding="utf-8")
    documented = set()
    for row in _DOC_ROW.findall(text):
        documented |= set(re.findall(r"MASKIT_[A-Z0-9_]+", row))
    return documented, text


class EnvVarDocsTests(unittest.TestCase):
    def test_every_runtime_env_var_is_documented(self):
        used = set()
        for path in sorted((ROOT / "engine").glob("*.py")):
            used |= set(_PATTERN.findall(path.read_text(encoding="utf-8")))
        self.assertGreater(len(used), 20, "没扫到环境变量读取（写法变了？请同步本测试）")
        documented, _ = _documented()
        missing = sorted(used - documented - _DEV_ONLY)
        self.assertEqual(missing, [],
                         "这些环境变量引擎真的在读，但 SECURITY.md 没登记（用户无从知道它存在）：%s"
                         % missing)

    def test_documented_env_vars_still_exist(self):
        """反向：文档里登记的变量必须真的有人读（否则读者照着设了也没用）。"""
        documented, _ = _documented()
        self.assertGreater(len(documented), 20, "没解析到 SECURITY.md 的环境变量表（格式变了？）")
        haystack = []
        for pattern in ("engine/*.py", "scripts/*", "Dockerfile",
                        "docker-compose.yml", "src-tauri/*", "build.sh", "build.ps1"):
            for path in ROOT.glob(pattern):
                if path.is_file():
                    haystack.append(path.read_text(encoding="utf-8", errors="ignore"))
        blob = "\n".join(haystack)
        stale = sorted(v for v in documented if v not in blob)
        self.assertEqual(stale, [],
                         "SECURITY.md 登记了这些变量，但仓库里没人读（改名或删掉了？）：%s" % stale)


if __name__ == "__main__":
    unittest.main()
