"""凭据类标签的**唯一定义源**（引擎侧）。

为什么单独一个模块：这份集合原先在 4 个地方各写一遍（transparent / panel /
event_store / 前端两份 TS），口径分成 5 个与 7 个两派。少两个标签的那几处会让
「凭据原文永不落库」这条红线在**读路径**上漏掉 CONNSTR 与 PRIVATE_KEY——
CONNSTR 的捕获组就是连接串里的密码本身，PRIVATE_KEY 更是整块 PEM 私钥。

模块刻意只依赖 stdlib：`event_store` 不能 import `transparent`（那会把 mitmproxy
拖进面板 Flask 进程），所以共享常量必须放在两边都能安全 import 的独立模块里。
前端有一份等价的 TS 定义（`frontend/src/lib/credential-labels.ts`），由
`tests/test_regressions.py::test_credential_label_sets_stay_in_sync` 守死不漂移。
"""

# 判定语义：label 在此集合内 → 原文**永不落库**，只记打码 preview + 长度 + sha256 摘要。
CREDENTIAL_LABELS = frozenset({
    "API_KEY",
    "TOKEN",
    "SECRET",
    "ACCESS_KEY",
    "JWT",
    # 下面两个曾长期漏在集合外，明文原样写进 events.items[].original：
    # 生产库实测曾有 CONNSTR 5091 条 / PRIVATE_KEY 468 条明文。
    "CONNSTR",
    "PRIVATE_KEY",
})

# ========== 用户显式标记为凭据的自定义分类（2026-11-04）==========
#
# 为什么需要它（**这是现存的一个真安全洞**，不是新功能）：
# 凭据判定一直只看 `label in CREDENTIAL_LABELS`，而自定义分类名由用户自由填写。
# 用户建一个叫「密钥」/「密码表」的中文分类放 API key 时，`label` 不在上面那个
# 集合里 → `items[].original` **明文写进本地 SQLite**，直接违反「凭据原文永不落库」。
# 中文标签推广后这个面会扩大（让用户更习惯用中文分类名），所以必须同时堵。
#
# 为什么用「分类级标记」而不是「认中文同义词」：`密钥` / `密码` / `凭据` / `证件`
# 的枚举永远漏一个，而漏一个就是一条明文。标记由用户显式给出，引擎只做忠实执行。
#
# 跨进程约定：这是**可变模块级状态**，engine 与 panel 各自在配置加载时写入
# （面板 run 在 Flask 进程、引擎 run 在 sidecar 进程，两边都读同一份 config.json）。
CREDENTIAL_CATEGORIES = set()


def set_credential_categories(labels) -> None:
    """整体替换「被标记为凭据的自定义分类」集合（配置热重载时调）。

    就地 clear+update 而不是重新绑定：调用方可能已持有旧引用，换对象会让那些
    读者永远看不到新配置（与 `transparent.CUSTOM_WORDS` 用整表换对象是**相反**
    的取舍，因为那里的读者是并发线程、这里是单次配置加载后的纯读）。
    """
    try:
        CREDENTIAL_CATEGORIES.clear()
        CREDENTIAL_CATEGORIES.update(
            str(x).strip() for x in (labels or []) if str(x or "").strip()
        )
    except Exception:
        pass


def is_credential(label) -> bool:
    """该标签是否按**凭据**处理（原文永不落库）。

    唯一的判定入口。新增调用点必须用它，不要直接写 `label in CREDENTIAL_LABELS`——
    那份内置集合只是一半条件，漏掉用户标记的那一半就是一次明文落盘。
    """
    return label in CREDENTIAL_LABELS or label in CREDENTIAL_CATEGORIES

# ========== 凭据**回流**检测的种类（audit_signals 的 `_CREDENTIAL_PATTERNS`） ==========
# 与上面的 CREDENTIAL_LABELS 不是一回事：那份是**脱敏侧**的标签（打码时用的业务标签），
# 这份是**审计侧**凭据回流规则匹配到的 kind 名，两者口径不同、不可合并。
# 放这里的理由与 CREDENTIAL_LABELS 相同：`audit_signals` 按这份名单产出
# `kind = "credential_echo:<kind>"`、证据 = `<kind> len=… sha256=…`；
# `event_store` 读侧要对**证据前缀**做降噪谓词
# （见 `_DEPRECATED_AUDIT_EVIDENCE_PREFIXES`），各写一遍必然漂移
# （历史事故正是这样发生）。由
# `tests/test_audit.py::test_credential_echo_kinds_stay_in_sync` 守死与规则表一致。
CREDENTIAL_ECHO_KINDS = (
    "github_token",
    "google_api_key",
    "aliyun_ak",
    "tencent_ak",
    "slack_token",
    "stripe_key",
    "aws_ak",
    "jwt",
)

# ========== W1-1 凭据回流的分档标记 ==========
# 规则无法区分「真实凭据」与「教学示例」（编程助手在代码块里写 .env 模板/CI 密钥
# 是家常便饭），故按**客观结构**（是否代码块内 + 值的熵）分档，并在证据尾部打标记：
#   · 代码块内 或 低熵 → LOW  + CREDENTIAL_ECHO_SAMPLE_MARKER（默认门槛下不入库）
#   · 其余（非代码块 + 高熵） → MEDIUM + CREDENTIAL_ECHO_REAL_MARKER
# CREDENTIAL_ECHO_REAL_MARKER 同时是读侧降噪的**保护标记**：带它的事件绝不允许被历史噪音谓词隐藏。
CREDENTIAL_ECHO_SAMPLE_MARKER = "[示例形态]"
CREDENTIAL_ECHO_REAL_MARKER = "[疑似真实凭据]"
