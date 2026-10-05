"""生产源码里不得出现「值形态」的号码 / 邮箱 / 凭据字面量。

这条守卫来自一次真实事故，不是洁癖：本机网关会把工具调用里写的占位符字面量
（`{{PHONE_xxxxxx}}` 形态）在**落盘时还原成它代表的真实值**（AGENTS.md §3.9）。
于是「照着格式写一个示例号码」这个动作，实际写进源码的是一串真实号码——
2026-10-02 在 `engine/panel.py` 的演示默认样例与 `frontend/src/lib/i18n.tsx`
的「填样例」文本里各查出一处：源码字符串里躺着真实号码与邮箱，而现有门禁
（py_compile / 单测 / 前端构建 / 发布审计）全都不会红——发布审计只扫密钥类正则。

因此规则是：**生产源码里的示例值一律片段拼接**（`'1' + '3' + '0' + '0'.repeat(8)`），
源码文本里不出现完整的号码/邮箱，运行时拼出来的串照样命中规则（否则样例演示不出
东西）。保留域（example.com / *.invalid / *.internal / *.test / *.local）不算，
它们是给人看的假域名，不含任何真实归属。

**扫描范围有意只到生产源码**（`engine/*.py` + `frontend/src`）：测试夹具里成规模地
使用「一眼可见是伪造」的号码（如尾段全 0），把它们纳入扫描需要一份脆弱的白名单，
而白名单一旦过期就会把守卫变成虚假的绿。夹具的严格性靠代码评审，生产源码靠本文件。
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 中国大陆手机号形态（11 位、1[3-9] 开头）。用它而不是「任意 11 位数字」：
# 后者会把时间戳、端口、调试常量一起卷进来，守卫立刻变成噪声源。
MOBILE_RX = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
MAIL_RX = re.compile(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}")
# 保留域（RFC2606 / RFC6761）：example.com/org/net、.invalid、.test、.local、.internal
RESERVED_MAIL_RX = re.compile(
    r"@(example\.(com|org|net)|[\w.-]*\.(invalid|test|local|internal|example))\b")
# 凭据形态：只认「前缀 + 长随机尾」，避免把 `sk-test`（短、明显假）也拦下来
SECRET_RX = re.compile(
    r"(?<![A-Za-z0-9_-])(?:sk|ah|ghp|gho|xox[baprs]|AKIA)[-_][A-Za-z0-9]{24,}(?![A-Za-z0-9_-])")


def _production_sources():
    files = sorted(ROOT.glob("engine/*.py"))
    files += sorted((ROOT / "frontend" / "src").rglob("*.ts"))
    files += sorted((ROOT / "frontend" / "src").rglob("*.tsx"))
    return [f for f in files if f.is_file()]


class SourcePiiLiteralTests(unittest.TestCase):
    def test_no_mobile_like_literal(self):
        offenders = []
        for f in _production_sources():
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if MOBILE_RX.search(line):
                    offenders.append("%s:%d" % (f.relative_to(ROOT), i))
        self.assertEqual(offenders, [],
                         "生产源码里出现手机号形态字面量：示例值必须片段拼接（本文件 docstring 有原因）")

    def test_no_non_reserved_email_literal(self):
        offenders = []
        for f in _production_sources():
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                for m in MAIL_RX.finditer(line):
                    if not RESERVED_MAIL_RX.search(m.group()):
                        offenders.append("%s:%d" % (f.relative_to(ROOT), i))
        self.assertEqual(offenders, [],
                         "生产源码里出现非保留域邮箱字面量：改用 example.*/.invalid 或片段拼接")

    def test_no_long_secret_like_literal(self):
        offenders = []
        for f in _production_sources():
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if SECRET_RX.search(line):
                    offenders.append("%s:%d" % (f.relative_to(ROOT), i))
        self.assertEqual(offenders, [], "生产源码里出现凭据形态字面量（前缀 + 长随机尾）")

    def test_demo_samples_are_fragment_built_not_literals(self):
        """两个「会被用户看到」的样例必须是运行时拼出来的，且真的命中规则。"""
        import sys
        sys.path.insert(0, str(ROOT / "engine"))
        import panel
        for name in ("_DEMO_SAMPLE_TEXT", "_DEMO_PROBE_TEXT"):
            text = getattr(panel, name)
            self.assertTrue(MOBILE_RX.search(text), "%s 应含手机号形态（否则演示无效）" % name)
            self.assertTrue(MAIL_RX.search(text), "%s 应含邮箱形态" % name)
        # 源码里不出现完整形态（正是上面两条测试守的），而运行时必须有
        source = (ROOT / "engine" / "panel.py").read_text(encoding="utf-8")
        self.assertIsNone(MOBILE_RX.search(source))

    def test_scan_actually_covers_files(self):
        """防止扫描目录写错导致“零命中”的假绿。"""
        files = _production_sources()
        self.assertGreater(len(files), 20, "生产源码文件数异常，扫描范围可能写错了")
        names = {f.name for f in files}
        self.assertIn("transparent.py", names)
        self.assertIn("panel.py", names)
        self.assertIn("i18n.tsx", names)


if __name__ == "__main__":
    unittest.main()