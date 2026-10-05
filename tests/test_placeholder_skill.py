"""占位符 Skill 包的分发契约（方案 §F7）。

Skill 是**宿主侧资产**：网关代装不了，只能把文件递到用户手里，再由宿主自己的机制
（Agent Skills / AGENTS.md / rules）加载。所以「包能不能被下载到、内容是不是同一份、
示例会不会带上真实凭据」全部是产品行为，而不只是文档问题。本文件锁四件事：

1. **结构**：`contract.md` 是唯一真相源，`SKILL.md` 与 `templates/AGENTS.snippet.md`
   是它的渲染目标，规则正文**逐字节一致**（手改生成物必须被拦下）；
2. **可分发**：`pack-skill.py --check` 离线可跑，`/api/skill/bundle` 在 `/api/` 前缀下
   （否则绕过 `api_guard`，见 `AGENTS.md` §3.7）且返回的 zip 内容与源目录一致；
3. **发布审计**：包内文本不得命中 `scripts/audit-public-release.py` 的凭据正则
   （直接 import 那几条正则，不复制一份——复制的那份漂移后就只剩虚假安心）；
4. **安全性**：包内不得出现引擎认得的真实形态占位符字面量（本机网关会把字面量还原
   后落盘，见 `AGENTS.md` §3.9），且契约必须写明「不索要原文、不关闭保护」。

样例与断言里不写任何真实凭据或占位符字面量。
"""
import importlib.util
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import skill_bundle as sb  # noqa: E402

BUNDLE = ROOT / "agent-bundle" / "maskit-placeholders"
AUDIT = ROOT / "scripts" / "audit-public-release.py"


def _load_audit():
    """按路径加载审计脚本（文件名带连字符不能直接 import）。"""
    spec = importlib.util.spec_from_file_location("_audit_public_release", AUDIT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BundleStructureTests(unittest.TestCase):
    def test_required_files_exist(self):
        for rel in sb.REQUIRED_FILES:
            path = BUNDLE / rel
            self.assertTrue(path.is_file(), "缺少 %s" % rel)
            self.assertGreater(path.stat().st_size, 0, "%s 是空文件" % rel)

    def test_check_bundle_is_clean(self):
        self.assertEqual(sb.check_bundle(BUNDLE), [])

    def test_render_targets_share_byte_identical_rules(self):
        """两个渲染目标的规则正文必须逐字一致（渲染差异只允许 frontmatter 与切分）。"""
        skill = (BUNDLE / sb.SKILL_FILE).read_text(encoding="utf-8")
        snippet = (BUNDLE / sb.SNIPPET_FILE).read_text(encoding="utf-8")
        self.assertEqual(sb._extract_block(skill), sb._extract_block(snippet))
        self.assertEqual(sb._extract_block(skill), sb.contract_block(BUNDLE).rstrip("\n"))

    def test_generated_files_match_contract(self):
        """生成物与 contract.md 同源：手改生成物必须被 `--check` 拦下。"""
        self.assertEqual(sb.generated_drift(BUNDLE), [])

    def test_frontmatter_is_host_loadable(self):
        fields = sb.frontmatter((BUNDLE / sb.SKILL_FILE).read_text(encoding="utf-8"))
        self.assertEqual(fields.get("name"), sb.SKILL_NAME)
        self.assertTrue(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", fields.get("name", "")))
        # description 是宿主**唯一预加载**的内容，必须写实触发条件，否则技能永不被触发。
        desc = fields.get("description", "")
        self.assertGreater(len(desc), 40)
        self.assertIn("占位符", desc)

    def test_relative_links_resolve(self):
        """包内相对链接必须真的存在（README 指向不存在的文件＝安装指引断掉）。"""
        link_rx = re.compile(r"\]\((?!https?://|#)([^)]+)\)")
        for path in sorted(BUNDLE.rglob("*.md")):
            text = path.read_text(encoding="utf-8")
            for target in link_rx.findall(text):
                target = target.split("#", 1)[0].strip()
                if not target:
                    continue
                # 链接可能在包外（如仓库根的 scripts/），只校验包内相对链接
                resolved = (path.parent / target).resolve()
                in_bundle = BUNDLE.resolve() in resolved.parents or resolved == BUNDLE.resolve()
                if not in_bundle:
                    continue
                self.assertTrue(resolved.exists(), "%s 指向不存在的 %s" % (path.name, target))

    def test_contract_covers_mandatory_rules(self):
        """12 条规则的关键约束不能丢（丢了就是模型自己发明规则的入口）。

        断言用的是**契约里真实存在的表述**（如“不要编造新占位符”），不是另写一遍同义句：
        测试要锁的是契约现在的说法，而不是"换个词也对"。
        """
        block = sb.contract_block(BUNDLE)
        for needle in ("不要编造新占位符", "不拆分", "不把隐藏主机换成", "不声称成功",
                       "关闭脱敏", "不提供任何读取原文", "{{标签_后缀}}",
                       "不要对 token 计算"):
            self.assertIn(needle, block, "契约缺关键约束：%s" % needle)
        self.assertEqual(len(re.findall(r"^## \d+\.", block, re.M)), 12,
                         "规则条数变了就要同步 §F3 与测试")


class BundleSafetyTests(unittest.TestCase):
    def test_no_engine_recognisable_token_literals(self):
        """包内不得出现真实形态 token 字面量（本机网关会把它还原成真实值后落盘）。"""
        strict = re.compile(r"\{\{[A-Z0-9]{1,12}_(?:[0-9a-f]{6}|[bcdfghjkmnpqrstvwxz]{6})\}\}")
        for path in sb.zipped_files(BUNDLE):
            text = path.read_text(encoding="utf-8", errors="replace")
            self.assertEqual(strict.findall(text), [],
                             "%s 含真实形态占位符字面量" % path.relative_to(BUNDLE))

    def test_examples_do_not_trip_the_public_release_audit(self):
        audit = _load_audit()
        patterns = {"GOOGLE_KEY_RE": audit.GOOGLE_KEY_RE, "AWS_KEY_RE": audit.AWS_KEY_RE,
                    "GITHUB_PAT_RE": audit.GITHUB_PAT_RE, "PRIVATE_KEY_RE": audit.PRIVATE_KEY_RE,
                    "CONTROL_RE": audit.CONTROL_RE}
        for path in sb.zipped_files(BUNDLE):
            text = path.read_text(encoding="utf-8", errors="replace")
            for name, rx in patterns.items():
                self.assertIsNone(rx.search(text),
                                  "%s 命中 %s，会让 CI 的发布审计变红" % (path.name, name))


class PackageCliTests(unittest.TestCase):
    """`pack-skill.py --check` 必须能离线跑通（门禁用的就是这条命令）。"""

    def test_check_mode_passes_offline(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "pack-skill.py"), "--check"],
                                cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("pack-skill: OK", result.stdout)

    def test_check_mode_leaves_no_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "pack-skill.py"), "--check", "--out", tmp],
                cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list(Path(tmp).iterdir()), [], "--check 不应留产物")


class ZipContractTests(unittest.TestCase):
    def test_zip_layout_and_exclusions(self):
        data = sb.build_zip_bytes(BUNDLE)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
            self.assertTrue(archive.testzip() is None)
            self.assertIn("%s/%s" % (sb.ARCHIVE_ROOT, sb.SKILL_FILE), names)
            self.assertIn("%s/%s" % (sb.ARCHIVE_ROOT, sb.SNIPPET_FILE), names)
            # 渲染源不随包分发：多一个几乎同文的源文件只会让读者分不清该改哪份。
            self.assertNotIn("%s/%s" % (sb.ARCHIVE_ROOT, sb.CONTRACT_FILE), names)
            self.assertTrue(archive.read("%s/%s" % (sb.ARCHIVE_ROOT, sb.SKILL_FILE)).strip())


class SkillEndpointTests(unittest.TestCase):
    """/api/skill/bundle：桌面端与容器部署的唯一自助下载入口。"""

    def setUp(self):
        import panel  # 延迟导入：panel 依赖 flask，测试环境缺失时应报在用例里
        self.panel = panel
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = {"config": panel.CONFIG_PATH,
                      "origin": panel._origin_check_enabled, "remote": panel.REMOTE_MODE}
        panel.CONFIG_PATH = self.tmp / "config.json"
        panel._origin_check_enabled = False
        panel.REMOTE_MODE = False
        panel.save_config(panel.default_config())
        self.client = panel.app.test_client()
        self.addCleanup(self._restore)

    def _restore(self):
        self.panel.CONFIG_PATH = self._orig["config"]
        self.panel._origin_check_enabled = self._orig["origin"]
        self.panel.REMOTE_MODE = self._orig["remote"]

    def test_endpoint_is_registered_under_api_prefix(self):
        """必须挂在 /api/ 下：api_guard 只守这个前缀，挂到根空间等于人人可下载。"""
        rules = {str(rule) for rule in self.panel.app.url_map.iter_rules()}
        self.assertIn("/api/skill/bundle", rules)
        for rule in rules:
            if "skill" in rule:
                self.assertTrue(rule.startswith("/api/"), "Skill 端点必须带 /api/ 前缀：%s" % rule)

    def _get(self, path):
        """带面板令牌请求：`/api/*` 一律过 `api_guard`（Host/Origin/令牌三重校验）。"""
        return self.client.get(path, headers={"X-Shield-Token": self.panel.API_TOKEN})

    def test_bundle_download(self):
        resp = self._get("/api/skill/bundle")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/zip", resp.headers.get("Content-Type", ""))
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        with zipfile.ZipFile(io.BytesIO(resp.data)) as archive:
            self.assertIn("%s/%s" % (sb.ARCHIVE_ROOT, sb.SKILL_FILE), set(archive.namelist()))

    def test_missing_bundle_fails_loudly(self):
        """包缺失必须显式 500（而不是返回空 zip，让用户下到一个坏包）。"""
        original = self.panel.skill_bundle.find_bundle
        self.panel.skill_bundle.find_bundle = lambda *a, **k: (_ for _ in ()).throw(
            FileNotFoundError("skill bundle missing (test)"))
        try:
            resp = self._get("/api/skill/bundle")
        finally:
            self.panel.skill_bundle.find_bundle = original
        self.assertEqual(resp.status_code, 500)
        self.assertFalse(resp.get_json().get("ok"))
        self.assertIn("missing", json.dumps(resp.get_json()))

    def test_candidates_cover_the_container_layout(self):
        """候选目录必须覆盖**容器布局**：`/app/agent-bundle/maskit-placeholders`。

        容器里 `engine/` 被拷成 `/app/*`，所以 `_BUNDLE_ROOT` 是 `/app`、`它的上一级是 `/`。
        只写 `_BUNDLE_ROOT.parent / "agent-bundle"` 会解析到 `/agent-bundle`，在 Docker 里
        恒不存在 —— 表现为“本地与安装包都正常、容器部署点下载就 500”，2026-10-04 实测命中。
        """
        candidates = [str(p) for p in self.panel._skill_bundle_candidates()]
        expected = str(self.panel._BUNDLE_ROOT / "agent-bundle" / sb.BUNDLE_DIRNAME)
        self.assertIn(expected, candidates,
                      "候选目录没覆盖容器布局（Docker 部署下 /api/skill/bundle 会 500）：%s" % candidates)

    def test_finder_resolves_a_container_like_tree(self):
        """在不真的跑容器的前提下，把容器目录树复现一遍并验证能被找到。"""
        fake_root = self.tmp / "app"
        bundle = fake_root / "agent-bundle" / sb.BUNDLE_DIRNAME
        bundle.mkdir(parents=True)
        for name in (sb.CONTRACT_FILE, sb.SKILL_FILE, sb.SNIPPET_FILE):
            path = bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# test\n", encoding="utf-8")
        original = self.panel._BUNDLE_ROOT
        self.panel._BUNDLE_ROOT = fake_root
        try:
            root = sb.find_bundle(*self.panel._skill_bundle_candidates())
        finally:
            self.panel._BUNDLE_ROOT = original
        self.assertEqual(root, bundle)

    def test_dockerfile_ships_the_bundle(self):
        """Dockerfile 必须把 agent-bundle 拷进镜像（静态判据，不依赖本机有 docker）。

        判据取“COPY 源目录”而不是整文件关键字：改成 `COPY . .` 也算合格，
        而删掉这行则一定是回归。
        """
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        copies_bundle = any(
            line.strip().upper().startswith("COPY") and "agent-bundle" in line
            for line in dockerfile.splitlines()
        )
        self.assertTrue(copies_bundle,
                        "Dockerfile 没有把 agent-bundle/ 拷进镜像：容器部署的 Skill 下载会 500")


if __name__ == "__main__":
    unittest.main()