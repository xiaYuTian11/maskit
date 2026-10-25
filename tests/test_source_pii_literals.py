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

# 中文姓名形态（2026-10-25 新增，来自同一条事故链的第二次踩中）。
#
# 为什么必须加：`engine/zh_names.py` 的注释里写着「`客户陈建国` / `联系人：XXX`」
# 这类**示例串**，本机网关在落盘时把占位符还原成了真实自然人姓名 —— 与号码/邮箱
# 完全同一机制（本文件 docstring 记录的那次事故）。而当时的守卫只扫号码/邮箱/凭据，
# 姓名一路绿灯进了仓库。
#
# 判据：常见姓氏 + 1~2 汉字，且**紧邻**角色词/称谓/标点（即 docstring 里的示例位置）。
# 不扫裸的两三个汉字：那是正常中文文本，会把守卫变成噪声源。
NAME_ROLE_BEFORE = ("客户", "联系人：", "我叫", "作者：", "作者: ", "姓名：", "名字：",
                    "署名：", "收件人：", "发件人：", "负责人：", "提交者：")
NAME_TITLE_AFTER = ("先生", "女士", "小姐", "反馈", "说")
SURNAMES = "王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于蒋"
# 边界必须**窄**：只认反引号收尾（代码注释里的示例惯用写法）或紧跟称谓。
# 用句号/右括号当边界会把「客户端指定」这类普通词组卷进来（实测误报）。
NAME_RX = re.compile(
    "(?:" + "|".join(re.escape(w) for w in NAME_ROLE_BEFORE) + ")"
    r"[\u4e00-\u9fff]{2,3}(?=`|" + "|".join(NAME_TITLE_AFTER) + ")")


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

    def test_no_real_name_sample_literal(self):
        """生产源码里不得出现「角色词 + 真实姓名」形态的示例串。

        起因：`engine/zh_names.py` 的注释示例被网关在落盘时还原成真实姓名并入库
        （与号码/邮箱同一机制）。示例一律改用「某甲/某乙」这类显式假名。
        """
        offenders = []
        for f in _production_sources():
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                for m in NAME_RX.finditer(line):
                    # 「某X」是我们约定的假名，放行
                    if "某" in m.group(0):
                        continue
                    offenders.append("%s:%d: %s" % (f.relative_to(ROOT), i, m.group(0)))
        self.assertEqual(offenders, [],
                         "生产源码里出现真实姓名形态示例：改用「某甲/某乙」或片段拼接")

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