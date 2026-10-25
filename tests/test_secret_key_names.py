"""SECRET 规则的**键名形态**覆盖（.env / docker-compose / k8s 的真实写法）。

## 为什么有这组用例

2026-10-25 真机事件库只读复盘（43763 条事件）发现：用户开启的 7 条内置规则里
`SECRET` 是唯一一条「看起来开了、实际上大半不工作」的规则——实测下面这些真实
写法**全部原文上行**：

```
DB_PASSWORD=hunter2abc        MYSQL_ROOT_PASSWORD=abc12345
REDIS_PASSWORD=abc12345       JWT_SECRET=abc12345
SECRET_KEY=abc12345           GITHUB_TOKEN=abc12345
OPENAI_API_KEY=abcdef1234567890   db.password=abc12345
```

根因是 `transparent.py` 里 SECRET 规则关键词两侧的边界：

    (?<![A-Za-z0-9_.])(?:password|passwd|...)(?![A-Za-z0-9_.])

`DB_PASSWORD` 里 `PASSWORD` 左边是 `_`、再左边是 `B`，**左边界直接失败**，整条
规则连正则都跑不到。也就是说这条规则只认得「裸关键词」写法（`password=`），
而真实泄漏面几乎全是带前缀的（`DB_` / `MYSQL_` / `OPENAI_` / `db.`）。

修法（对齐 magpie `internal/redact/redact.go:147` 的思路）：键名允许前缀/后缀，
再用**值语义**收窄误报（`_secret_value_ok`）——计数词（`max_tokens`）、代码标识符
（`secretName: Uint8Array`）必须继续放行。

## 两侧都要锁

命中侧防止「改了正则忘了 marker」；**误报侧**防止把 `max_tokens=4096`、
`token_count=12` 这类协议/计数字段当凭据脱敏（那会让上游直接收到被打码的参数）。
两侧缺一条，这个文件就失去意义。
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))


def _fresh_engine():
    """隔离实例：**不在 import 时改环境变量**。

    为什么：本模块与旧测试跑在同一进程（`unittest discover`）。如果在 import 时设
    `LLM_SHIELD_DATA_DIR`，它会覆盖其他模块的隔离目录，而 `panel.DB_PATH` /
    `tr._DATA_ROOT` 在 import 时就固化了 —— 实测：后 import 的模块“偷”走前者
    的目录，`test_panel_event_store_uses_panel_data_root` 当场失败。

    正确口径与旧测试一致（见 `tests/test_regressions.py:2076`）：per-test 临时
    替换 `tr._DATA_ROOT`，用完恢复。
    """
    import transparent as tr
    return tr


def _write_json(path, obj):
    """写 JSON 并**关闭句柄**（`json.dump(f, open(...))` 不关句柄，会报 ResourceWarning）。"""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False)


tr = _fresh_engine()


class _IsolatedCase(unittest.TestCase):
    """每条用例都从一份干净的全局态开始，并在结束后恢复。

    `_maybe_reload(force=True)` 会**整体换对象**发布 `BUILTIN_RULES` / `CUSTOM_WORDS`，
    所以必须重新取引用，存旧引用当快照不够。
    """

    CONFIG = {}

    def setUp(self):
        self._saved = {
            "CUSTOM_WORDS": tr.CUSTOM_WORDS,
            "BUILTIN_RULES": tr.BUILTIN_RULES,
            "SENSITIVE_DISABLED": tr.SENSITIVE_DISABLED,
            "SENSITIVE_WORD_DISABLED": tr.SENSITIVE_WORD_DISABLED,
            "SENSITIVE_WORD_WHOLE": tr.SENSITIVE_WORD_WHOLE,
            "UPSTREAMS": tr.UPSTREAMS,
            "TARGET_DOMAINS": tr.TARGET_DOMAINS,
            "API_PATHS": tr.API_PATHS,
            "CAPTURE_MODE": tr.CAPTURE_MODE,
            "FAIL_CLOSED": tr.FAIL_CLOSED,
            "_DATA_ROOT": tr._DATA_ROOT,
        }
        self._dir = tempfile.mkdtemp(prefix="maskit-secret-")
        _write_json(
            os.path.join(self._dir, "config.json"),
            dict(
                self.CONFIG,
                target_domains=["api.example.com"],
                api_paths=["/v1/messages"],
            ),
        )
        tr._DATA_ROOT = Path(self._dir)
        self._cfg_mtime = tr._cfg_mtime[0]
        tr._cfg_mtime[0] = None
        tr._maybe_reload(force=True)
        tr.BUILTIN_RULES = {k: True for k in tr.DEFAULT_BUILTIN_RULES}
        tr._CUSTOM_WORD_RX_CACHE.clear()

    def tearDown(self):
        # 必须把 `_maybe_reload` 能改的**全部**全局都恢复：漏一个就是跨模块污染。
        # 实测：漏了 `SENSITIVE_WORD_WHOLE` / `UPSTREAMS` 时，后续模块的
        # `FailClosedCaptureModeTests` 拿到的全局态与它 setUp 时假设的不一致，
        # 未知形态请求被原样放行（看着像回归，实际是本类隔离缺陷）。
        for key in (
            "CUSTOM_WORDS", "BUILTIN_RULES", "SENSITIVE_DISABLED",
            "SENSITIVE_WORD_DISABLED", "SENSITIVE_WORD_WHOLE", "UPSTREAMS",
            "TARGET_DOMAINS", "API_PATHS", "CAPTURE_MODE", "FAIL_CLOSED",
        ):
            setattr(tr, key, self._saved[key])
        tr._DATA_ROOT = self._saved["_DATA_ROOT"]
        tr._cfg_mtime[0] = self._cfg_mtime
        shutil.rmtree(self._dir, ignore_errors=True)


class SecretKeyNameCoverageTests(_IsolatedCase):
    """带前缀/带点号的键名必须命中（真实 .env / compose / k8s 写法）。"""

    CONFIG = {"sensitive": {}, "builtin_rules": {"SECRET": True}}

    # 值一律用**片段拼接**构造，避免本文件自己成为「源码里的明文凭据样本」
    # （AGENTS.md §3 第 9 条：占位符/凭据样例不得以字面量出现在源码里）。
    CASES = {
        "DB_PASSWORD": "Db" + "Pass" + "9x7q",
        "MYSQL_ROOT_PASSWORD": "My" + "Root" + "8w3e",
        "POSTGRES_PASSWORD": "Pg" + "Pass" + "7r2t",
        "REDIS_PASSWORD": "Rd" + "Pass" + "6y1u",
        "MONGO_INITDB_ROOT_PASSWORD": "Mg" + "Root" + "5i9o",
        "JWT_SECRET": "Jw" + "Sec" + "4p8a",
        "SECRET_KEY": "Sk" + "Key" + "3o7s",
        "GITHUB_TOKEN": "Gh" + "Tok" + "2d6f",
        "OPENAI_API_KEY": "Oa" + "Key" + "1g5h",
        "ANTHROPIC_API_KEY": "An" + "Key" + "9j4k",
        "AWS_SECRET_ACCESS_KEY": "Aw" + "Sk" + "8l3z",
        "db.password": "Dp" + "Pass" + "7x2c",
        "app.auth.token": "At" + "Tok" + "6v1b",
        "X_API_KEY": "Xa" + "Key" + "5n0m",
        "client_secret": "Cs" + "Sec" + "4b9v",
    }

    def test_prefixed_key_names_are_masked(self):
        for key, value in self.CASES.items():
            for sep in ("=", ": ", "："):
                with self.subTest(key=key, sep=sep):
                    text = f"{key}{sep}{value}"
                    sid = f"sk-{key}-{abs(hash(sep)) % 9973}"
                    tr._new_session(sid)
                    out = tr.mask(text, sid)
                    self.assertIn(
                        "{{SECRET_",
                        out,
                        f"{key}{sep}<value> 未脱敏：{out!r}",
                    )
                    self.assertNotIn(value, out, f"{key} 的值仍在明文里：{out!r}")

    def test_quoted_values_are_masked(self):
        """JSON / YAML / .env 三种引号形态（真实粘贴场景）。"""
        value = "Qq" + "Val" + "3z8y"
        cases = [
            f'{{"DB_PASSWORD": "{value}"}}',
            f"DB_PASSWORD='{value}'",
            f"DB_PASSWORD = \"{value}\"",
        ]
        for i, text in enumerate(cases):
            with self.subTest(case=i):
                sid = f"sk-q{i}"
                tr._new_session(sid)
                out = tr.mask(text, sid)
                self.assertNotIn(value, out, f"引号形态漏检：{out!r}")

    def test_restore_round_trip_is_exact(self):
        """命中后必须逐字还原（含引号、分隔符、全角冒号）。"""
        value = "Rt" + "Val" + "9w4e"
        cases = [
            f"DB_PASSWORD={value}",
            f'{{"OPENAI_API_KEY": "{value}"}}',
            f"密码：{value}",
            f"数据库密码：{value}，请妥善保管",
        ]
        for i, text in enumerate(cases):
            sid = f"sk-rt{i}"
            tr._new_session(sid)
            masked = tr.mask(text, sid)
            self.assertNotEqual(masked, text, f"未命中：{text!r}")
            self.assertEqual(tr.restore_final(masked, sid), text, f"还原不逐字：{text!r}")


class SecretFalsePositiveTests(_IsolatedCase):
    """误报侧：协议计数、代码标识符、说明文案一律不许被打码。

    这一组比命中侧更重要：把 `max_tokens=4096` 打成占位符，上游收到的就是非法
    参数（400），而用户完全不知道是自己开的规则干的。
    """

    CONFIG = {"sensitive": {}, "builtin_rules": {"SECRET": True}}

    MUST_NOT_MASK = {
        # OpenAI / Anthropic 协议参数
        "max_tokens=4096",
        "max_completion_tokens=8192",
        "prompt_tokens=1234",
        "completion_tokens=5678",
        "total_tokens=6912",
        "cache_read_input_tokens=900",
        "cache_creation_input_tokens=120",
        "reasoning_tokens=300",
        # 计数 / 速率类指标
        "token_count=12",
        "tokens_per_second=55",
        "token_budget=2048",
        "maxTokens=4096",
        # 代码标识符 / 成员访问
        "toBase64Url(secret)",
        "getSecret()",
        "ModelUtils.toStringSafe(x)",
        "secret: CamelCaseName",
        # 中文说明句（值里没有数字/符号，不该被当凭据）
        "密码：请联系管理员重置",
        "令牌：稍后由运维发放",
        # URL 路径
        "token: /api/v1/refresh",
        # 时间
        "会议时间：14:30 开始",
    }

    # 已知误报（**不当断言**）：键名通配 + 值含数字时，形如类型注解的文本
    # （`secretName: Uint8Array`）会被误遮。
    #
    # 为什么不在规则层硬猜：唯一可靠的判据是「值是不是类型名/方法名」，而这需要
    # 语言级解析；magpie 用 `notCode` 做上下文启发，实测同样会漏。这类误报的
    # 正确出口是 B-4 的值级白名单（`allow_values`），由用户一次性钉住
    # （"Uint8Array"），而不是在热路径上堆无法验证的启发式。
    #
    # 放在这里是为了让后来者知道「这是已知的，不是回归」——加新用例时不要
    # 把它当成必须绿的项。
    KNOWN_FALSE_POSITIVES = {
        "secretName: Uint8Array",
    }

    def test_known_false_positives_are_documented(self):
        """已知误报必须**真的**误报（变了就说明判据变了，要重写这条文档）。

        这不是「允许误报」：它锁的是「我们知道自己误报在哪、范围有多大」。
        哪天它不再误报了，这条会红，提醒把那行从 KNOWN_FALSE_POSITIVES 删掉。
        """
        for text in self.KNOWN_FALSE_POSITIVES:
            sid = "sk-known-fp"
            tr._new_session(sid)
            out = tr.mask(text, sid)
            self.assertNotEqual(
                out, text,
                f"{text!r} 已不再误报——请从 KNOWN_FALSE_POSITIVES 移除并加进"
                f"MUST_NOT_MASK",
            )

    def test_protocol_and_code_shapes_are_not_masked(self):
        for i, text in enumerate(self.MUST_NOT_MASK):
            with self.subTest(text=text):
                sid = f"sk-fp{i}"
                tr._new_session(sid)
                out = tr.mask(text, sid)
                self.assertEqual(out, text, f"误报：{text!r} -> {out!r}")

    def test_counter_words_are_not_secret_names(self):
        """`_secret_value_ok` 的计数词判定必须存在且可单独测试。"""
        self.assertTrue(hasattr(tr, "_secret_value_ok"), "缺少 _secret_value_ok 收窄函数")
        for name in ("max_tokens", "total_tokens", "token_count", "cache_read_input_tokens"):
            self.assertFalse(
                tr._secret_value_ok("4096", name), f"{name} 被当成凭据名"
            )


class SecretMarkerParityTests(_IsolatedCase):
    """预检 marker 与正则必须同源。

    `_rule_may_hit` 用 `_RULE_MARKERS` 做快速预检：marker 命不中就直接跳过整条
    规则。**正则改对了但忘了 marker，等于没改**（CGNAT 规则踩过同一个坑）。
    """

    CONFIG = {"sensitive": {}, "builtin_rules": {"SECRET": True}}

    def test_secret_markers_cover_all_separators(self):
        markers = tr._RULE_MARKERS["SECRET"]
        for sep in ("=", ":", "：", "＝"):
            self.assertIn(sep, markers, f"SECRET marker 缺少分隔符 {sep!r}")

    def test_prefixed_key_passes_marker_precheck(self):
        """带前缀的键名必须能通过预检（否则正则再对也跑不到）。"""
        for text in ("DB_PASSWORD=x", "OPENAI_API_KEY=x", "db.password=x"):
            self.assertTrue(
                tr._rule_may_hit(text, "SECRET"),
                f"预检把 {text!r} 整条跳过了",
            )


if __name__ == "__main__":
    unittest.main()
