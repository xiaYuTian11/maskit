"""批次 8（P1-6）：叶子结果缓存 —— 正确性、隐私与失效。

长会话的形态是「客户端每轮重发整段历史」，只有最后一条变了。缓存整段叶子的
脱敏结果能把这一轮的成本从 O(历史) 降到 O(新增)，但它是**脱敏主链路上的一层
缓存**，所以四件事必须同时钉住，缺任何一条都不该上线：

  1. 命中结果与冷跑**逐字节一致**（含占位符、含 last_hits 统计口径）；
  2. 缓存里**不留原文**（§G1 与 ner_engine 的结果缓存同口径：键是进程密钥摘要）；
  3. 会话映射一漂（淘汰 / 清空 / 跨会话）就必须当未命中重跑，
     否则会把 A 会话的占位符发给 B 会话；
  4. 抽样自检一旦发现不一致，**整体关闭**缓存（命中路径上的错误是静默的，
     宁可丢掉这个优化，也不能让用户拿到错的脱敏结果）。

这些用例全部不依赖 NER 模型：`NER_ENABLED` 一律关掉，测的是规则路径。
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import transparent as tr


def _phone(i=0):
    """显然伪造的样例号码（尾段按序号变化，不做真实号段）。"""
    return "138" + "%08d" % i


def _fake_email():
    """保留域邮箱（RFC 2606），片段拼接避免源码里出现完整形态。"""
    return "user" + "@" + "example" + ".invalid"


def _placeholder(label, suffix):
    """占位符字面量一律片段拼接（AGENTS.md §3.9：整串写进文件可能被网关还原）。"""
    return "{" * 2 + label + "_" + suffix + "}" * 2


class _LeafCacheIsolation(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self._data_root = tr._DATA_ROOT
        tr._DATA_ROOT = Path(tmp.name)
        self.addCleanup(self._restore_data_root)

        self._saved_globals = (tr.NER_ENABLED, tr.BUILTIN_RULES)
        tr.NER_ENABLED = False
        self.addCleanup(self._restore_globals)

        self._saved_tables = (dict(tr.sessions), dict(tr._RECENT_FWD),
                              dict(tr._RECENT_REV), dict(tr._RECENT_SUFFIX))
        self.addCleanup(self._restore_tables)
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()

        self._saved_cache_ok = tr._LEAF_CACHE_OK[0]
        tr._LEAF_CACHE_OK[0] = True
        tr._leaf_cache_clear()
        tr._LEAF_CACHE_STATS.update(hit=0, miss=0, verify=0, poison=0)
        self.addCleanup(self._restore_cache_ok)

    def _restore_data_root(self):
        tr._DATA_ROOT = self._data_root

    def _restore_globals(self):
        tr.NER_ENABLED, tr.BUILTIN_RULES = self._saved_globals

    def _restore_tables(self):
        sessions, fwd, rev, suffix = self._saved_tables
        tr.sessions.clear()
        tr.sessions.update(sessions)
        tr._RECENT_FWD.clear()
        tr._RECENT_FWD.update(fwd)
        tr._RECENT_REV.clear()
        tr._RECENT_REV.update(rev)
        tr._RECENT_SUFFIX.clear()
        tr._RECENT_SUFFIX.update(suffix)

    def _restore_cache_ok(self):
        tr._LEAF_CACHE_OK[0] = self._saved_cache_ok
        tr._leaf_cache_clear()


class CacheCorrectnessTests(_LeafCacheIsolation):
    def test_second_turn_is_byte_identical_and_hits(self):
        sid = "lc-turn"
        body = {"messages": [
            {"role": "user", "content": "手机 %s 的机主叫张三" % _phone(1)},
            {"role": "assistant", "content": "已记录"},
        ]}
        first = tr._mask_tree(json.loads(json.dumps(body)), sid)
        misses = tr._LEAF_CACHE_STATS["miss"]
        second = tr._mask_tree(json.loads(json.dumps(body)), sid)
        self.assertEqual(json.dumps(second, ensure_ascii=False),
                         json.dumps(first, ensure_ascii=False),
                         "命中路径必须与冷跑逐字节一致")
        self.assertGreater(tr._LEAF_CACHE_STATS["hit"], 0, "第二次没有命中缓存")
        self.assertEqual(misses, tr._LEAF_CACHE_STATS["miss"], "第二次不该有新未命中")

    def test_hit_replays_last_hits_so_counts_match(self):
        """命中必须重放 `_hit()`：否则 MASK 事件的「本次命中」恒为 0。"""
        sid = "lc-stats"
        text = "联系人手机 %s" % _phone(2)
        tr.mask(text, sid)
        s = tr.sessions[sid]
        cold = set(s["last_hits"])
        self.assertTrue(cold, "冷跑就没记到命中，用例前提不成立")
        s["last_hits"].clear()
        tr.mask(text, sid)
        self.assertEqual(set(s["last_hits"]), cold,
                         "命中路径的 last_hits 与冷跑不一致")

    def test_mapping_reset_forces_recompute_with_new_placeholder(self):
        sid = "lc-reset"
        text = "手机 %s" % _phone(3)
        tr.mask(text, sid)
        self.assertGreater(len(tr._LEAF_CACHE), 0, "用例前提：第一次应当入库")
        tr.reset_mappings(reason="test")
        self.assertEqual(len(tr._LEAF_CACHE), 0, "清空映射后叶子缓存必须一起清掉")
        second = tr.mask(text, sid)
        # 重新签发：占位符可以是新的，但绝不能沿用已失效的映射
        s = tr.sessions[sid]
        for m in tr._PLACEHOLDER_RX.finditer(second):
            self.assertIn(m.group(), s["rev"], "输出了本会话映射里不存在的占位符")

    def test_cross_session_output_is_restorable_in_its_own_session(self):
        text = "手机 %s 邮箱 %s" % (_phone(4), _fake_email())
        a = tr.mask(text, "lc-a")
        b = tr.mask(text, "lc-b")
        self.assertEqual(tr.restore(b, "lc-b"), text,
                         "第二个会话拿到的占位符在它自己的会话里还原不了")
        self.assertEqual(tr.restore(a, "lc-a"), text)

    def test_rule_toggle_invalidates_cached_result(self):
        sid = "lc-rule"
        text = "手机 %s" % _phone(5)
        masked = tr.mask(text, sid)
        self.assertNotIn(_phone(5), masked, "用例前提：PHONE 规则应当命中")
        # 关掉 PHONE 规则（整体换对象，与 `_maybe_reload` 同形）
        tr.BUILTIN_RULES = dict(tr.BUILTIN_RULES, PHONE=False)
        again = tr.mask(text, sid)
        self.assertIn(_phone(5), again,
                      "规则开关变了仍命中旧缓存：缓存代号漏了规则表")

    def test_explicit_bump_invalidates(self):
        sid = "lc-bump"
        text = "手机 %s" % _phone(6)
        tr.mask(text, sid)
        self.assertGreater(len(tr._LEAF_CACHE), 0)
        tr._leaf_cache_bump()
        tr.mask(text, sid)
        for ent in tr._LEAF_CACHE.values():
            self.assertEqual(ent[0], tr._leaf_cache_gen(),
                             "换代后仍留下了旧代号的条目")

    def test_oversized_leaf_is_not_stored(self):
        sid = "lc-big"
        with mock.patch.object(tr, "_LEAF_CACHE_MAX_LEAF", 4):
            tr.mask("手机 %s" % _phone(7), sid)
        self.assertEqual(len(tr._LEAF_CACHE), 0, "超过单条上限的叶子不该入库")

    def test_cache_size_is_bounded(self):
        with mock.patch.object(tr, "_LEAF_CACHE_MAX", 4):
            for i in range(12):
                tr.mask("手机 %s 编号 %d" % (_phone(i), i), "lc-bound-%d" % i)
        self.assertLessEqual(len(tr._LEAF_CACHE), 4)

    def test_disabled_switch_short_circuits_everything(self):
        tr._LEAF_CACHE_OK[0] = False
        tr.mask("手机 %s" % _phone(8), "lc-off")
        self.assertEqual(len(tr._LEAF_CACHE), 0)
        self.assertEqual(tr._LEAF_CACHE_STATS["hit"], 0)

    def test_total_off_switch_reads_the_env(self):
        """`MASKIT_LEAF_CACHE=0` 必须在**启动时**就把缓存整体关掉。

        为什么要有总开关：缓存只是加速手段，怀疑它算错时要能当场停。
        自检不一致也会关，但那条路要等抽中（默认 256 次里的 1 次）才触发，
        运维上没法"现在就停" —— 没有总开关就只能回滚版本。
        """
        with mock.patch.dict(os.environ, {"MASKIT_LEAF_CACHE": "0"}):
            self.assertFalse(tr._leaf_cache_env_enabled())
        with mock.patch.dict(os.environ, {"MASKIT_LEAF_CACHE": "1"}):
            self.assertTrue(tr._leaf_cache_env_enabled())
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(tr._leaf_cache_env_enabled(), "未设置时必须默认开启")


class CachePrivacyTests(_LeafCacheIsolation):
    def test_cache_holds_no_plaintext(self):
        """§G1：键是摘要、值是脱敏文本 + 占位符清单，**不得**出现原文。"""
        sid = "lc-priv"
        secret = _phone(9)
        email = _fake_email()
        tr.mask("手机 %s 邮箱 %s" % (secret, email), sid)
        dumped = repr(tr._LEAF_CACHE)
        self.assertNotIn(secret, dumped, "缓存里出现了原文手机号")
        self.assertNotIn(email, dumped, "缓存里出现了原文邮箱")
        self.assertEqual(len(tr._LEAF_CACHE), 1)
        key = next(iter(tr._LEAF_CACHE))
        self.assertRegex(key, r"^[0-9a-f]{32}$", "键不是进程密钥摘要")
        self.assertNotIn(secret, key)

    def test_cache_key_is_stable_and_separates_texts(self):
        a = tr._leaf_cache_key("文本一")
        self.assertEqual(a, tr._leaf_cache_key("文本一"))
        self.assertNotEqual(a, tr._leaf_cache_key("文本二"))

    def test_stored_tokens_are_placeholders_only(self):
        sid = "lc-tok"
        secret = _phone(11)
        tr.mask("手机 %s" % secret, sid)
        ent = next(iter(tr._LEAF_CACHE.values()))
        tokens = ent[3]
        self.assertTrue(tokens, "有命中的叶子必须登记占位符")
        for tok, label, dig in tokens:
            self.assertIsNotNone(tr._PLACEHOLDER_RX.fullmatch(tok),
                                 "登记的不是占位符：%r" % (tok,))
            self.assertNotIn(secret, tok)
            self.assertIsInstance(label, str)
            self.assertRegex(dig, r"^[0-9a-f]{16}$", "原文摘要形态不对")

    def test_token_alone_is_not_identity(self):
        """代号被重新签发给**另一个原文**后，旧条目必须失效，否则会把值还原错。

        场景（真实路径可达，见 `_orig_digest` 的注释）：全局复用窗口（上限 2000）
        淘汰后，同一个后缀会被 `_new_token` 重新签发给别的原文。此时「代号在本会话
        里对得上」不再说明它指向当初那个原文，只有原文摘要能分辨。

        判据取**可观察后果**而不是内部计数：同一条带占位符的文本，还原后必须
        等于自己的原文。漏了摘要校验时 `restore` 会给出**另一个号码**（跨会话串扰）。
        """
        sid = "lc-reissue"
        original = _phone(21)
        text = "手机 %s" % original
        tr.mask(text, sid)
        ent = next(iter(tr._LEAF_CACHE.values()))
        tok = ent[3][0][0]
        # 模拟「同一个后缀被重新签发给另一个原文」：本会话里该代号改指向别的原值
        other = _phone(22)
        tr.sessions[sid]["rev"][tok] = other
        tr.sessions[sid]["fwd"][other] = tok
        tr.sessions[sid]["fwd"].pop(original, None)
        masked = tr.mask(text, sid)
        self.assertEqual(tr.restore(masked, sid), text,
                         "命中了一条指向别的原文的旧结果：客户端会把 %s 还原成 %s"
                         % (original, other))

    def test_uncorrupted_entry_still_hits(self):
        """上一条的对照组：映射没被改指时必须照旧命中（避免把优化误伤成失效）。"""
        sid = "lc-reissue-ok"
        text = "手机 %s" % _phone(23)
        tr.mask(text, sid)
        miss_before = tr._LEAF_CACHE_STATS["miss"]
        tr.mask(text, sid)
        self.assertEqual(tr._LEAF_CACHE_STATS["miss"], miss_before,
                         "映射未变却未命中，等于缓存失效")


class CacheSelfCheckTests(_LeafCacheIsolation):
    def _poison(self, text, wrong_text):
        """塞一条**通过校验但内容错误**的条目，模拟「代号漏了一项」的失效逻辑缺陷。"""
        key = tr._leaf_cache_key(text)
        with tr._LEAF_CACHE_LOCK:
            tr._LEAF_CACHE[key] = (tr._leaf_cache_gen(), len(text), wrong_text, [])
        # 让下一次调用正好落在抽样点上
        tr._LEAF_CACHE_TICK[0] = tr._LEAF_CACHE_VERIFY_EVERY - 1

    def test_sampling_detects_mismatch_and_disables_cache(self):
        sid = "lc-poison"
        text = "手机 %s" % _phone(12)
        self._poison(text, "被污染的文本")
        got = tr.mask(text, sid)
        self.assertNotEqual(got, "被污染的文本", "自检没有拦住错误的缓存内容")
        self.assertNotIn(_phone(12), got, "重算结果应当已把号码换成占位符")
        self.assertIsNotNone(tr._PLACEHOLDER_RX.search(got), "重算结果里没有占位符")
        self.assertFalse(tr._LEAF_CACHE_OK[0], "发现不一致后没有整体关闭缓存")
        self.assertEqual(tr._LEAF_CACHE_STATS["poison"], 1)
        self.assertEqual(len(tr._LEAF_CACHE), 0, "关闭时必须清空")

    def test_verification_runs_even_when_ner_degraded(self):
        """NER 降级时这一轮不写缓存，但**抽样比对仍必须跑**。

        否则缓存里的错误内容要等到下一次「完整跑完」才被发现 —— 而 NER 开启时
        “降级”恰恰是常态，等于自检在最需要它的时候闭眼。
        """
        sid = "lc-poison-ner"
        text = "手机 %s" % _phone(14)
        # 代号含 `NER_ENABLED`：必须先把它打开再投毒，否则投进去的条目代号不符、
        # 直接当未命中重跑（自检根本不会触发，用例就测了个寂寞）。
        with mock.patch.object(tr, "NER_ENABLED", True):
            self._poison(text, "被污染的文本")
            # 让 `_ner_skip_epoch` 前后不一致 → `_ner_clean` 为假（模拟降级）
            epochs = iter([1, 2, 2, 2])
            with mock.patch.object(tr, "_ner_skip_epoch",
                                   side_effect=lambda: next(epochs)), \
                 mock.patch.object(tr, "_ner_warn_once", lambda *a, **k: None), \
                 mock.patch.dict(sys.modules, {"ner_engine": mock.Mock(
                     is_ner_available=lambda: True, extract_entities=lambda t: [])}):
                got = tr.mask(text, sid)
        self.assertNotEqual(got, "被污染的文本", "降级时自检被跳过了")
        self.assertFalse(tr._LEAF_CACHE_OK[0])
        self.assertEqual(tr._LEAF_CACHE_STATS["poison"], 1)

    def test_non_sampled_call_serves_the_cache(self):
        """抽样之外仍然走命中路径（否则这个优化等于没做）。"""
        sid = "lc-nosample"
        text = "手机 %s" % _phone(13)
        tr._LEAF_CACHE_TICK[0] = 1        # 远离抽样点
        tr.mask(text, sid)
        hits = tr._LEAF_CACHE_STATS["hit"]
        tr._LEAF_CACHE_TICK[0] = 2
        tr.mask(text, sid)
        self.assertEqual(tr._LEAF_CACHE_STATS["hit"], hits + 1)


if __name__ == "__main__":
    unittest.main()
