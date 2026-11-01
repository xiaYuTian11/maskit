"""中文姓名启发层的**语义等价性**回归锁（2026-11-02）。

## 为什么必须有这个文件

`zh_names.find_names` 从「逐字符全扫 + 32KB 硬截断」改成「证据词预筛 + 姓氏
候选位扫描」后，性能从 648ms/1.32MB 降到 8ms，但**语义必须逐字节不变**——
它是脱敏链路的一部分，少识别一个名字就是漏检，多识别一个就是误掩正文。

改动过程中真实踩过两个坑（都靠随机对拍抓出来）：
1. 候选位扫描丢了「反例词跳词」语义 → 多识别 45/2000
   （`师傅` 的第二个字 `傅` 也是姓氏，旧实现跳词后不检查它）；
2. 改成「整词区间屏蔽」后 → 少识别 1/2000
   （旧实现若已从更早位置产出实体并跳到词内，那个位置仍会被检查）。

最终实现用**游标复刻旧实现的顺序扫描语义**，本文件把「等价」钉住。

## 本文件的判据

用一份**逐字符的参考实现**（旧算法原样）作为 oracle，在大量随机语料上对拍。
语料刻意包含姓氏字、反例词、证据词、标点、英文、数字 —— 覆盖所有分支。
"""
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import zh_names as Z  # noqa: E402


def _reference_find_names(text):
    """参考实现：旧算法原样（逐字符全扫 + 反例词跳词）。

    这是 oracle，**不要**改成调用新实现 —— 那样对拍就永远通过，失去意义。
    """
    if not isinstance(text, str) or len(text) < 2:
        return []
    if not Z._HAN_RX.search(text):
        return []
    out = []
    i = 0
    n = len(text)
    while i < n:
        slen = Z._surname_len_at(text, i)
        if not slen:
            i += 1
            continue
        blocked = False
        for w in Z._not_name_buckets().get(text[i], ()):
            if text.startswith(w, i):
                blocked = True
                i += len(w)
                break
        if blocked:
            continue
        matched = None
        for glen in (2, 1):
            gstart, gend = i + slen, i + slen + glen
            if gend > n:
                continue
            if not Z._given_len_ok(text, gstart, gend):
                continue
            if not (Z._has_role_before(text, i)
                    or Z._has_title_after(text, gend)
                    or Z._has_verb_before(text, i)):
                continue
            matched = (i, gend)
            break
        if matched:
            out.append((matched[0], matched[1], "NAME"))
            i = matched[1]
        else:
            i += slen
    return out


def _corpus():
    """语料池：覆盖所有分支（姓氏/反例词/证据词/标点/英文/数字）。"""
    return (list("王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗") +
            list("大锤小会三罗经理总先生女士联系人客户由请给和的了是在有") +
            list("，。：；！？  \n\t") + list("abc123XYZ") +
            list(Z.ZH_ROLES) + list(Z.ZH_AFTER) + list(Z.ZH_BEFORE_VERBS))


class SemanticEquivalenceTests(unittest.TestCase):
    """新实现必须与参考实现**逐条一致**。"""

    def test_handwritten_cases_match_reference(self):
        """手写关键用例（含反例词、跳词、长文本）。"""
        S = "\u738b"      # 运行时拼接，不在源码里写姓名
        G = "\u5927\u9524"
        cases = [
            "联系人：" + S + G + "请回电。",
            "客户" + S + G + "已确认。",
            S + "经理来了。",
            "\u5f20\u91cf\u8fd0\u7b97\u5f88\u6162",          # 反例词「张量」
            "\u9ad8\u5ea6\u5f91\u91cd\u8981",                # 反例词「高度」
            "请联系" + S + G + "确认。",
            "hello world no chinese",
            "",
            "{{NAME_abc123}} / {{PHONE_bcdfgh}}",
        ]
        for c in cases:
            with self.subTest(case=c[:30]):
                self.assertEqual(Z.find_names(c), _reference_find_names(c))

    def test_random_fuzz_matches_reference(self):
        """随机对拍 5000 条（CI 里控制在秒级）。

        固定种子：同一份代码每次跑出同一批语料，回归时差异可复现。
        本地手工验证过 20000 条零差异（本用例取 5000 以保证门禁速度）。
        """
        random.seed(20261102)
        pool = _corpus()
        diffs = []
        for _ in range(5000):
            ln = random.randint(0, 60)
            text = "".join(random.choice(pool) for _ in range(ln))
            old = _reference_find_names(text)
            new = Z.find_names(text)
            if old != new:
                diffs.append((text, old, new))
        self.assertFalse(
            diffs,
            "新实现与参考实现不一致（前 3 条）:\n%s"
            % "\n".join("%r\n  old=%r\n  new=%r" % d for d in diffs[:3]))

    def test_long_text_scan_is_complete(self):
        """长文本（远超旧 32KB 上限）尾部姓名必须扫到 —— 这是本次改动的**目的**。"""
        S = "\u738b"
        G = "\u5927\u9524"
        filler = "这是正常的业务描述文字，没有任何人名。" * 2000
        text = filler + "联系人：" + S + G + "请回电"
        self.assertGreater(len(text), 32 * 1024)
        spans = Z.find_names(text)
        self.assertTrue(spans, "超过 32KB 之后的人名也必须扫到（旧实现返回空）")
        self.assertIn(S + G, [text[s:e] for s, e, _ in spans])


if __name__ == "__main__":
    unittest.main()
