"""打包产物完整性：`engine/maskit-engine.spec` 必须覆盖全部引擎模块。

为什么单独一个文件：这类缺陷**只在打包态出现**，本地门禁与源码态永远绿。
`hiddenimports` 是逐个枚举引擎模块的（见 spec 里的既有条目与注释），而
`engine/selfcheck.py` 是 0.6.0 新增的 —— 加它的人（我）忘了同步 spec，
**源码态一切正常、打包态才会 ImportError**。

具体后果别夸大也别缩小：`panel.py` 里 `import selfcheck` 写在函数内（懒加载），
PyInstaller 的静态分析通常能捞到函数级 import，所以大概率仍会被打进包里；
但它**依赖分析器的运气**，而本项目其他 8 个引擎模块都显式枚举了 —— 漏一个就是
"打包机正常、用户机少功能"这一类最难排查的漂移（自检点了没反应，日志里只有
被 except 吞掉的导入错误）。所以：显式补上，并加这条守卫防止下一个新模块再漏。
"""
import ast
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "engine" / "maskit-engine.spec"


class EngineSpecCoverageTests(unittest.TestCase):
    def _engine_modules(self):
        """engine/ 下的一级模块名（排除 spec 自身与包）。"""
        return {p.stem for p in (ROOT / "engine").glob("*.py")}

    def _spec_source(self):
        return SPEC.read_text(encoding="utf-8")

    def test_spec_exists_and_lists_hiddenimports(self):
        self.assertTrue(SPEC.is_file(), "找不到 %s" % SPEC)
        src = self._spec_source()
        self.assertIn("hiddenimports", src, "spec 里没有 hiddenimports？")
        self.assertIn("pathex=[str(ENGINE_DIR)", src.replace(" ", ""),
                      "pathex 必须含 ENGINE_DIR，否则引擎模块解析不到")

    def test_every_engine_module_is_reachable_from_the_spec(self):
        """每个引擎模块都要能被 spec 找到（在 hiddenimports 里，或被 import 链带到）。

        判据不是"字面出现在 hiddenimports 里"这么窄：被 spec 里已列出的模块
        **导入**到的模块本来就会被 PyInstaller 带上。所以这里两路合并：
          ① hiddenimports 字面列出的；
          ② 从那些模块出发做一次导入闭包（含 `from x import y` 与 `import x`）。
        两条都不覆盖的引擎模块 = 打包态可能缺失，必须报出来。
        """
        modules = self._engine_modules()
        src = self._spec_source()
        listed = set(re.findall(r"'([a-z_]+)'", src)) & modules
        self.assertIn("panel", listed, "解析不到 hiddenimports 列表（spec 格式变了？）")

        # 导入闭包：把 engine/ 下的模块 import 关系走一遍
        declared = set(listed) | {"engine_entry"}
        seen = set()
        frontier = list(declared)
        while frontier:
            name = frontier.pop()
            if name in seen:
                continue
            seen.add(name)
            path = ROOT / "engine" / (name + ".py")
            if not path.is_file():
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        frontier.append(a.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom) and node.module:
                    frontier.append(node.module.split(".")[0])

        missing = sorted(m for m in modules if m not in seen and m not in listed)
        self.assertEqual(missing, [],
                         "这些引擎模块既没在 hiddenimports 里、也不在任何已列模块的导入链上："
                         "%s（打包态可能缺模块，源码态完全看不出来）" % missing)

    def test_transport_modules_are_shipped_as_source(self):
        src = self._spec_source()
        for name in ("connection_policy", "mitm_transport_adapter"):
            self.assertIn("'" + name + "'", src)
            self.assertIn("ENGINE_DIR / '" + name + ".py'", src)

    def _shipped_under_internal(self):
        """由 spec 推导出产物 `_internal/` 下会出现的相对路径（三种形状）。

        spec 里 datas 的源目录 → 产物里的 `_internal/<源相对路径>`（PyInstaller 的
        onefile/onedir 都是这个布局）。目录型的用前缀记（带尾部斜杠）。
        形状若变了这条会不匹配，正是想要的效果：让人回来同步断言。
        """
        src = self._spec_source()
        shipped = {"_internal/" + name for name in re.findall(r"ENGINE_DIR / '([^']+)'", src)}
        if "_skill_bundle(ROOT_DIR)" in src:
            shipped.add("_internal/skill_bundle/")
        if "_model_resources(ENGINE_DIR)" in src:
            shipped.add("_internal/models/ner_mini_zh/")
        return shipped

    def test_every_release_asserted_file_is_produced_by_the_spec(self):
        """`release.yml` 断言“包里必须有”的文件，spec 必须真的产出它。

        为什么单钉一条：两处清单是**手写**的，分属两个文件、不同时间由不同人维护。
        2026-10-04 实测：`inspection.py` / `protocol_contracts.py` 已加进 release.yml 的
        断言与 `test_release_build.PACKAGE_ENTRIES`，**唯独 spec 的 datas 没加** ——
        本地门禁全绿，产物里却没有这两个文件，发版时那一步断言会把整条流水线拦下
        （拦下已是最好的结果；若哪天断言被弱化，就是打包实例 ImportError）。
        这条把「断言」与「构建输入」钉在一起：只改一边必红。
        """
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        required = set(re.findall(r"resources/engine/(\S+)", workflow))
        self.assertIn("_internal/transparent.py", required,
                      "解析不到 release.yml 的包内容断言（workflow 格式变了？请同步这条）")
        shipped = self._shipped_under_internal()

        def produced(path):
            return path in shipped or any(
                path.startswith(d) for d in shipped if d.endswith("/"))

        missing = sorted(
            "_internal/" + p[len("_internal/"):] for p in required
            if p.startswith("_internal/") and not produced(p))
        self.assertEqual(missing, [],
                         "release.yml 断言这些文件必须在包里，但 spec 的 datas 产不出它们："
                         "%s（本地门禁看不出来，发版那步会直接红）" % missing)

    def test_selfcheck_is_explicitly_listed(self):
        """`selfcheck` 必须**显式**在 hiddenimports 里（0.6.0 漏过一次）。

        它由 panel 在函数内懒加载，且被三处调用点包在 try 里 —— 万一打包态缺它，
        表现是"自检点了没反应"而不是报错。所以即使导入闭包能覆盖它，也要求显式列出。
        """
        src = self._spec_source()
        self.assertRegex(src, r"hiddenimports[\s\S]{0,800}?'selfcheck'",
                         "hiddenimports 里没有 'selfcheck'（0.6.0 新增模块漏登记过）")


if __name__ == "__main__":
    unittest.main()
