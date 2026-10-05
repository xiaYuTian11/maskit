"""协议不可改写状态契约表（§A2，批次 3）。

**只做结构分类**：不跑正则、不做 NER、不碰网络、不读配置。判据来源是各协议的官方文档
（每条载体都带 `source`，见 §8 R12 的"含来源引用"要求）。

## 为什么需要这张表

上游为了让"多轮/多步"对话能复用模型内部推理，会下发**不可改写状态**：签名（覆盖某段正文）
或密文（自包含句柄）。客户端只要原样回放它，上游就认；**改写正文、改写签名、或只改其中
一侧，都会让状态失效**——轻则降级，重则整轮 400 且用户无法自救（Anthropic 的思考块正文不
可编辑；Anthropic 检索结果的密文被改写会直接返回
`Invalid encrypted_content in search_result block`）。

2026-10-02 实测（§A1 E2c）：默认规则下这些 base64 载体侥幸不被改写（靠相邻字符边界校验），
但**用户只要在 UI 加一个 2 字符自定义词**（如 `Ab`），`AbCdEf…` 就会被切成
`{{CUSTOMER_…}}CdEf…`。所以这是"普通操作即可触发"的破坏路径，必须由判据表覆盖。

## 判据口径（不得放松）

1. **结构 + 角色，禁止字段名集合**：判据 = 载体所在容器的键名 + 父键 + 协议角色 +
   块类型/不可改写字段非空。字段名豁免会连工具参数里的同名键一起放过（AstrLink
   `continuation_test.go:134` 锁定的反例：`tool_use.input` 里的 `{"type":"thinking",
   "signature":…}` 必须照常扫描）。本模块**不提供**任何"全局字段名跳过"入口。
2. **真实数组**：`array_path` 非空的载体必须是"真实数组的元素"（`path` 以数组下标结尾），
   不是同名的对象字段。两条入口的 path 起点不同（整包入口顶层键进 `path`；生产代理链路
   按顶层键逐个调用、顶层键留在 `key` 里而 `path` 从下标开始），判据同时接受两种形态——
   否则"同一条请求走两条链路结果不同"的老问题会再来一次。
3. **未知协议继续保守扫描**：本表只做"豁免"，不命中就照原样扫，不因结构不认识而放宽。
4. **两种作用域**：
   - `block`：签名**覆盖兄弟明文**（Anthropic/LiteLLM 的 `thinking`、OpenRouter 的
     `reasoning.text`）——只锁签名等于保证 400，所以整块只读（§A1 D6-B 定案）。
   - `slot`：载体是**自包含密文句柄**（Responses `encrypted_content`、Gemini
     `thoughtSignature`、Anthropic 检索结果密文）——只有该字段本身不可改写，
     兄弟字段照常扫描（少锁一点就少一条漏检面）。
5. **请求与响应共用这张表**：响应侧"不还原"的块类型由 `restore_skip_types()` 导出，
   不在别处再写一份硬编码。

## 已知未覆盖 / 刻意不做的部分

- 协议识别是**结构性**的，没有叠加 HTTP 路径与配置协议（§A2 设想的联合识别）。
  五个载体的结构判据当前唯一，多一层判据只会引入未验证的分支；需要时再扩展，
  且扩展点就是本模块。
- 响应侧的 base64 载体不额外加"跳过还原"逻辑：占位符要求字面 `{{`，base64 字母表里
  没有 `{`，还原天然碰不到它们（§A1 E3）。响应侧真正的风险面是"思考正文"。
"""
from typing import NamedTuple


class Carrier(NamedTuple):
    """一条"协议不可改写状态"判据（新增载体 = 加一行，不改逻辑）。"""

    name: str                 # 载体标识（测试与排障用）
    protocol: str             # 所属协议（人读，不参与判据）
    key: str                  # 载体所在容器的键名（真实数组 / typed record 的键）
    parents: tuple            # `key` 的父键白名单；() = 不限
    roles: tuple              # 允许的 message 角色；含 None = 要求"不在任何 message 内"
    types: tuple              # ((块类型, 不可改写字段), ...)；() = 无块类型判据
    slots: tuple              # 无块类型判据时的不可改写字段（字段名 + 非空值才算命中）
    scope: str                # "block" = 整块只读；"slot" = 只锁不可改写字段
    source: str               # 官方来源（§8 R12 要求可回溯）
    restore_skip: tuple       # 响应侧不还原的块类型（含流式增量形态另加）
    allow_business: bool = False   # 是否在"业务区"内也生效（当前仅 Responses 顶层 input）
    array_path: str = ""      # 非空时要求是 `array_path` 这个真实数组的元素


CARRIERS: tuple = (
    # Anthropic Messages：带 signature 的 thinking 块（批次 1 的窄热修，这里改为表驱动）。
    Carrier(
        name="anthropic_thinking",
        protocol="anthropic_messages",
        key="content",
        parents=("messages", "message"),
        roles=("assistant",),
        types=(("thinking", "signature"), ("redacted_thinking", "data")),
        slots=(),
        scope="block",
        source="https://platform.claude.com/docs/en/build-with-claude/thinking",
        restore_skip=("thinking", "redacted_thinking"),
    ),
    # OpenAI Responses：reasoning 项的加密推理（无状态用法靠它复用推理）。
    # `input` 在 `_MASK_BUSINESS_KEYS` 里 → 该子树在整包入口下是业务区，必须显式放行。
    Carrier(
        name="responses_reasoning",
        protocol="openai_responses",
        key="input",
        parents=(),
        roles=(None,),
        types=(("reasoning", "encrypted_content"),),
        slots=(),
        scope="slot",
        source="https://developers.openai.com/api/docs/guides/reasoning",
        restore_skip=(),
        allow_business=True,
        array_path="input",
    ),
    # Gemini generateContent：Part 上的思考签名。**刻意只锁签名本身**——它是自包含的
    # 加密推理表示，`functionCall.args` 里的业务参数与同名的 `thoughtSignature` 键
    # 都还要照常扫描（后者是 AstrLink 夹具点名的反例）。
    Carrier(
        name="gemini_thought_signature",
        protocol="gemini_generate_content",
        key="parts",
        parents=("contents", "content"),
        roles=("model",),
        types=(),
        slots=("thoughtSignature", "thought_signature"),
        scope="slot",
        source="https://ai.google.dev/gemini-api/docs/generate-content/thought-signatures",
        restore_skip=(),
    ),
    # LiteLLM 的 OpenAI 兼容层把 Anthropic 思考块摊到消息的 `thinking_blocks` 上。
    Carrier(
        name="litellm_thinking_blocks",
        protocol="litellm_openai_compat",
        key="thinking_blocks",
        parents=("message", "messages"),
        roles=("assistant",),
        types=(("thinking", "signature"), ("redacted_thinking", "data")),
        slots=(),
        scope="block",
        source="https://docs.litellm.ai/docs/reasoning_content",
        restore_skip=("thinking", "redacted_thinking"),
    ),
    # OpenRouter 的 `reasoning_details`：签名型（reasoning.text）与密文型（reasoning.encrypted）。
    Carrier(
        name="openrouter_reasoning_details",
        protocol="openrouter_chat_completions",
        key="reasoning_details",
        parents=("message", "messages"),
        roles=("assistant",),
        types=(("reasoning.text", "signature"), ("reasoning.encrypted", "data")),
        slots=(),
        scope="block",
        source="https://openrouter.ai/docs/guides/best-practices/reasoning-tokens",
        restore_skip=("reasoning.text", "reasoning.encrypted"),
    ),
    # Anthropic 服务端检索结果：密文被改写时上游直接 400（Invalid encrypted_content）。
    # 角色收 assistant 与 user 两种：文档示例是 assistant 轮，而有些客户端把服务端工具
    # 结果回放在 user 轮；判据主体是嵌套 typed record，角色只是必要条件。
    Carrier(
        name="anthropic_web_search_result",
        protocol="anthropic_messages",
        key="content",
        parents=("content",),
        roles=("assistant", "user"),
        types=(("web_search_result", "encrypted_content"),),
        slots=(),
        scope="slot",
        source="https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool",
        restore_skip=(),
    ),
)

# 响应侧不还原的块类型：契约表里"签名覆盖明文"的块 + 流式增量形态。
# `thinking_delta` 只以 SSE 增量事件出现（不在整包里作为块），故只归响应侧。
_RESTORE_ONLY_TYPES = ("thinking_delta",)


def restore_skip_types() -> frozenset:
    """响应侧不还原的块类型集合（请求/响应共用同一份判据）。"""
    out = set(_RESTORE_ONLY_TYPES)
    for c in CARRIERS:
        out.update(c.restore_skip)
    return frozenset(out)


def _in_real_array(carrier, path) -> bool:
    """当前节点是否落在 `carrier.array_path` 这个**真实数组**里。

    两条入口路径形态不同（见模块 docstring 第 2 条）：整包入口的顶层键会进 `path`
    （`("input", 0)`），生产代理链路按顶层键逐个调用、顶层键留在 `key` 里
    （`(0,)`）。两种都必须认，否则同一请求走两条链路结果不同。
    """
    if not carrier.array_path:
        return True
    if not (path and isinstance(path[-1], int)):
        return False
    head = path[:-1]
    return head == () or head == (carrier.array_path,)


def match(obj, key, parent, path, role, in_business):
    """命中的载体（或 None）。`obj` 是当前 dict 节点。"""
    if not isinstance(obj, dict):
        return None
    for c in CARRIERS:
        if key != c.key:
            continue
        if c.parents and parent not in c.parents:
            continue
        if c.roles and role not in c.roles:
            continue
        if in_business and not c.allow_business:
            continue
        if not _in_real_array(c, path):
            continue
        if c.types:
            # 块类型 → 不可改写字段：字段缺失或为空都不算命中（无签名的块上游无从校验，
            # 照常脱敏才不白丢一个漏检面）。
            field = dict(c.types).get(obj.get("type"))
            if not field:
                continue
            value = obj.get(field)
            if not (isinstance(value, str) and value):
                continue
            return c
        # 无块类型判据的载体（Gemini Part）：至少一个不可改写字段非空才算命中。
        if any(isinstance(obj.get(s), str) and obj.get(s) for s in c.slots):
            return c
    return None


def protected_fields(carrier, obj) -> frozenset:
    """`slot` 作用域下这条载体锁住的字段（`block` 作用域不使用）。"""
    if carrier.types:
        field = dict(carrier.types).get(obj.get("type"))
        return frozenset({field} if field else ())
    return frozenset(s for s in carrier.slots
                     if isinstance(obj.get(s), str) and obj.get(s))
