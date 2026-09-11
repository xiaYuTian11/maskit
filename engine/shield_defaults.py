"""LLM Shield 默认配置。"""
# 数据面具 Maskit — 本地 LLM 敏感信息脱敏代理
# Copyright (C) 2026 TMW
#
# 本程序是自由软件：你可以依据自由软件基金会发布的 GNU Affero 通用公共许可证
# （版本 3）条款重新分发和/或修改它。
# 本程序基于「希望有用」的目的分发，但不附带任何担保；亦无对适销性或特定用途
# 适用性的默示担保。详见 GNU Affero 通用公共许可证。
# 你应已随本程序收到一份 GNU AGPL 副本；若无，见 <https://www.gnu.org/licenses/>。

import re

# 出口代理默认值：关闭 + 空地址（用户在高级设置里填）
DEFAULT_EGRESS_PROXY = {"enabled": False, "url": ""}

_EGRESS_RE = re.compile(
    r"^(?:(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://)?"
    r"(?P<host>\[[0-9A-Fa-f:]+\]|[^:/\s]+)"
    r"(?::(?P<port>\d{1,5}))?/?$"
)


def parse_egress_proxy(url):
    """解析出口代理地址 → mitmproxy 的 ServerSpec `(scheme, (host, port))`；非法返回 None。

    接受 `http://127.0.0.1:7890`、`https://proxy.corp:8443`、`127.0.0.1:7890`（省略
    scheme 时按 http）。**只支持 http/https**：mitmproxy 的 `via` 最终走
    `_upstream_proxy.py`，那里硬断言 `scheme in ("http", "https")`，socks5 根本不走
    这条路径——用户填了 socks5 必须明确拒绝，静默忽略会变成「配了代理却仍直连」，
    比报错难查得多（Clash/v2ray 都同时提供 http 代理端口，让用户改填即可）。

    返回值直接赋给 `flow.server_conn.via`。注意实际连接走 CONNECT 隧道（实测：
    即便目标是明文 http，mitmproxy 也发 CONNECT），故上游代理必须支持 CONNECT。
    """
    text = str(url or "").strip()
    if not text:
        return None
    m = _EGRESS_RE.match(text)
    if not m:
        return None
    scheme = (m.group("scheme") or "http").lower()
    if scheme not in ("http", "https"):
        return None
    host = (m.group("host") or "").strip().strip("[]")
    if not host:
        return None
    raw_port = m.group("port")
    port = int(raw_port) if raw_port else (443 if scheme == "https" else 80)
    if not (0 < port <= 65535):
        return None
    return (scheme, (host, port))


# 反向代理模式：每个 upstream = 一个本地端口入口。
# 多端口模式（默认）：客户端 base_url 指向 http://127.0.0.1:<port>，Shield 按入站端口路由到 target，无需剥前缀。
# 本地到 Shield 是明文 HTTP（无需 CA），Shield 到上游才 HTTPS。
# 端口用 18700-18799 冷门段，避免与常见服务冲突。
DEFAULT_UPSTREAMS = [
    # 开源默认值：仅官方公开渠道示例。自用中转渠道请通过面板「客户端管理」或
    # config.json 的 upstreams 自行添加（不会进入仓库）。
    {
        "name": "openai",
        "port": 18701,
        "base_path": "/openai",
        "target": "https://api.openai.com",
        "paths": ["/v1/chat/completions", "/v1/completions", "/v1/responses"],
    },
    {
        "name": "deepseek",
        "port": 18702,
        "base_path": "/deepseek",
        "target": "https://api.deepseek.com",
        "paths": ["/v1/chat/completions", "/v1/completions"],
    },
    {
        "name": "anthropic",
        "port": 18703,
        "base_path": "/anthropic",
        "target": "https://api.anthropic.com",
        "paths": ["/v1/messages"],
    },
]

# 兼容旧 capture_mode=explicit/local 的域名白名单（从 DEFAULT_UPSTREAMS 派生）
DEFAULT_DOMAINS = [u["target"].replace("https://", "").replace("http://", "").split("/")[0].split(":")[0] for u in DEFAULT_UPSTREAMS]

DEFAULT_PATHS = [
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/messages",
    "/chat/completions",
    "/v1/responses",
    "/v1/rerank",
    "/rerank",
]

DEFAULT_TTL = 600
DEFAULT_SECRET_PREFIXES = ["sk-", "ah-"]
DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 5802

# 内置正则规则默认状态：推荐 7 项核心隐私/凭据默认开启，其余 12 项默认关闭
# 避免过多的冷门/高误报规则（如内网IP、MAC、车牌等）干扰模型正常代码/配置推理。
DEFAULT_BUILTIN_RULES = {
    "API_KEY": True,
    "CARD": True,
    "CONNSTR": True,
    "EMAIL": True,
    "IDCARD": True,
    "LANDLINE": True,
    "PHONE": True,
    "ACCESS_KEY": False,
    "HKID": False,
    "IBAN": False,
    "IP_INTERNAL": False,
    "IP_PRIVATE": False,
    "JWT": False,
    "MAC": False,
    "PLATE": False,
    "PRIVATE_KEY": False,
    "SECRET": False,
    "TOKEN": False,
    "USCC": False,
}

# UI 展示用：标签 → 说明
BUILTIN_RULE_META = {
    "PRIVATE_KEY": "PEM 私钥（整块替换，-----BEGIN...PRIVATE KEY-----）",
    "CONNSTR": "连接串密码（scheme://user:pass@host，只脱密码）",
    "PHONE": "手机号（含 138-1234-5678 / 空格分隔 / +86 前缀）",
    "EMAIL": "邮箱（含中文用户名）",
    "LANDLINE": "座机（区号 + 分隔 + 7-8 位号码）",
    "PLATE": "车牌（普通 5 位 / 新能源 6 位）",
    "HKID": "港澳通行证（H 开头 8 位，默认关防误伤）",
    "IDCARD": "身份证（15 位旧证 + 18 位二代证，省份+日期+校验位多重校验）",
    "IP_PRIVATE": "内网 IP：192.168.x / 链路本地",
    "IP_INTERNAL": "内网 IP：10.x / 172.16-31.x（默认关——易误伤版本号）",
    "CARD": "银行卡（Luhn）",
    "IBAN": "IBAN（mod-97）",
    "USCC": "统一社会信用代码（18 位，默认关防误伤）",
    "MAC": "MAC 地址（xx:xx:xx:xx:xx:xx，默认关防误伤）",
    "API_KEY": "GitHub 等 API Key 形态",
    "ACCESS_KEY": "AWS Access Key",
    "JWT": "JWT",
    "TOKEN": "Bearer Token",
    "SECRET": "password=/token=/api_key= 等赋值凭据",
}


# ========== 模型价格表（费用估算用） ==========
# 内置常见模型官方价（美元 / 每百万 token）。按「最长前缀匹配」命中：
# claude-sonnet-4-5 会命中 claude-sonnet-4-5 条目而不是 claude-sonnet 前缀。
# 未收录的模型（含中转渠道私有模型）返回 None，前端显示「未定价」不计金额。
# 价格随官方调整会过时——仅作估算，精确价格以渠道账单为准；
# 用户可在高级设置里自配价格覆盖（config.model_prices）。
# 参考价（2026-06 官方发布价，$/1M tokens）：
MODEL_PRICES = {
    # Anthropic Claude
    "claude-opus-4": {"input": 5.0, "output": 25.0},
    "claude-sonnet-4-5": {"input": 3.0, "output": 15.0},
    "claude-sonnet-4": {"input": 3.0, "output": 15.0},
    "claude-3-5-sonnet": {"input": 3.0, "output": 15.0},
    "claude-3-7-sonnet": {"input": 3.0, "output": 15.0},
    "claude-3-haiku": {"input": 0.25, "output": 1.25},
    "claude-3-opus": {"input": 15.0, "output": 75.0},
    # OpenAI
    "gpt-5-mini": {"input": 0.25, "output": 2.0},
    "gpt-5-nano": {"input": 0.05, "output": 0.4},
    "gpt-5": {"input": 1.25, "output": 10.0},
    "gpt-4.1-nano": {"input": 0.1, "output": 0.4},
    "gpt-4.1-mini": {"input": 0.4, "output": 1.6},
    "gpt-4.1": {"input": 2.0, "output": 8.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.6},
    "gpt-4o": {"input": 2.5, "output": 10.0},
    "o3-mini": {"input": 1.1, "output": 4.4},
    # Google Gemini
    "gemini-2.5-pro": {"input": 1.25, "output": 10.0},
    "gemini-2.5-flash": {"input": 0.3, "output": 2.5},
    "gemini-2.0-flash": {"input": 0.1, "output": 0.4},
    "gemini-1.5-pro": {"input": 1.25, "output": 5.0},
    "gemini-1.5-flash": {"input": 0.075, "output": 0.3},
    # DeepSeek（官方价）
    "deepseek-reasoner": {"input": 0.55, "output": 2.19},
    "deepseek-chat": {"input": 0.27, "output": 1.1},
    "deepseek-v3": {"input": 0.27, "output": 1.1},
    "deepseek": {"input": 0.27, "output": 1.1},
    # 国内主流（参考官方目录价，估算）
    "qwen-max": {"input": 1.6, "output": 6.4},
    "qwen-plus": {"input": 0.4, "output": 1.2},
    "qwen-turbo": {"input": 0.1, "output": 0.3},
    "glm-4": {"input": 0.5, "output": 2.0},
    "glm-4.5": {"input": 0.6, "output": 2.6},
    "moonshot": {"input": 0.6, "output": 2.5},
    "kimi-k2": {"input": 0.6, "output": 2.5},
    "doubao": {"input": 0.3, "output": 0.8},
    "ernie": {"input": 0.4, "output": 1.2},
    # 其他常见
    "llama-3.3": {"input": 0.2, "output": 0.2},
    "grok-4": {"input": 3.0, "output": 15.0},
    "grok-3": {"input": 3.0, "output": 15.0},
}


"""在线目录的「去厂商前缀」索引缓存。

同步下来的目录是 OpenRouter 形态的 key（`deepseek/deepseek-chat`），
而真实流量里 model 字段是裸名（`deepseek-chat`）——两边对不上，
原来只做精确匹配，结果 389 条目录几乎一条都命中不了，全部退回 36 条内置表，
表现就是「同步了个寂寞，新模型还得等我发版」。

索引按需构建一次，用对象身份比对复用（目录几百条，每次请求重建太浪费）。
"""
_BARE_INDEX_SRC = None
_BARE_INDEX = {}


def _norm_model(name):
    """模型名归一：小写 + 点号当横杠。

    各家对同一个模型的写法不统一——Anthropic 官方 API 叫 `claude-3-5-haiku-20241022`，
    OpenRouter 目录里叫 `anthropic/claude-3.5-haiku`。不归一就永远对不上，
    实测这条会让整个 claude-3.5 系列显示「未定价」。
    """
    return str(name or "").split("/")[-1].lower().replace(".", "-")


def _bare_price_index(cache):
    """{归一化模型名: price}。同名不同厂商时按 key 排序取第一个，保证结果可复现。"""
    global _BARE_INDEX_SRC, _BARE_INDEX
    if cache is _BARE_INDEX_SRC:
        return _BARE_INDEX
    index = {}
    for full in sorted(cache):
        bare = _norm_model(full)
        if bare and bare not in index:
            index[bare] = cache[full]
    _BARE_INDEX_SRC = cache
    _BARE_INDEX = index
    return index


def estimate_cost(model, prompt_tokens, completion_tokens, overrides=None, cache=None):
    """按模型估算费用（美元）。

    Args:
        model: 模型名（如 "claude-sonnet-4-5" / "anthropic/claude-sonnet-4-5"）。
        prompt_tokens / completion_tokens: token 数（整数）。
        overrides: 用户自配价格 {model: {input, output}}（config.model_prices），
            精确匹配优先于一切。
        cache: 在线同步价格目录 {model: {input, output}}（load_price_cache 产物）。

    匹配顺序（先在线目录后内置表——内置表只是断网/首装的兜底，不该抢主路径）：
        1. overrides 精确        —— 用户自己配的，最高优先
        2. cache   精确          —— 流量里带厂商前缀时
        3. cache   去前缀精确    —— 真实流量的常态（gpt-4o / deepseek-chat）
        4. cache   去前缀最长前缀 —— 带日期/变体后缀（claude-3-5-haiku-20241022）
        5. 内置表  最长前缀      —— 断网或目录里没有时的最后兜底

    返回 (cost_usd, price)：
        cost_usd: float 估算金额；price: 命中的价格条目 {input, output} 或 None（未定价）。
    """
    price = None
    m = str(model or "").strip()
    if m:
        bare = _norm_model(m)
        if overrides and m in overrides:
            price = overrides[m]
        elif cache and m in cache:
            price = cache[m]
        elif cache:
            index = _bare_price_index(cache)
            price = index.get(bare)
            if price is None:
                # 最长前缀：claude-3-5-haiku-20241022 命中 claude-3-5-haiku
                cand = None
                for prefix in index:
                    if bare.startswith(prefix) and (cand is None or len(prefix) > len(cand)):
                        cand = prefix
                if cand is not None:
                    price = index[cand]
        if price is None:
            # 兜底：内置表按最长前缀匹配。内置表里有 10 个 key 带点号
            # （gpt-4.1 / gemini-2.5-pro / glm-4.5 …），bare 已经把点归一成横杠，
            # 这里必须对 key 做同样归一，否则这批条目会集体匹配不上。
            cand = None
            for prefix, entry in MODEL_PRICES.items():
                np = prefix.replace(".", "-")
                if bare.startswith(np) and (cand is None or len(np) > len(cand)):
                    cand, price = np, entry
    if price is None:
        return 0.0, None
    p = max(0, int(prompt_tokens or 0))
    c = max(0, int(completion_tokens or 0))
    cost = p / 1e6 * float(price.get("input") or 0) + c / 1e6 * float(price.get("output") or 0)
    return round(cost, 6), price


# ========== 在线价格同步（OpenRouter / 自定义源） ==========
# 价格不写死：默认从 OpenRouter 免费 API 同步全量模型定价（无 key、无需登录），
# 本地缓存到 data 目录，启动时自动同步 + 定期刷新。新模型同步后自动收录，
# 用户零操作。源 URL 可在配置里改成自托管（格式同 OpenRouter：{data: [{id, pricing}]}）。
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
PRICE_SYNC_INTERVAL_DAYS = 7  # 缓存超过 7 天视为过期，触发后台刷新


def fetch_openrouter_prices(url=OPENROUTER_MODELS_URL, timeout=20):
    """拉取在线模型价格目录。

    兼容 OpenRouter /api/v1/models 格式：
        {"data": [{"id": "anthropic/claude-sonnet-4-5",
                   "pricing": {"prompt": "3", "completion": "15", ...}}, ...]}

    Args:
        url: 价格源 URL（默认 OpenRouter；可换成自托管同格式 JSON）。
        timeout: 秒。

    返回 {model: {"input": $/1M, "output": $/1M}}——仅收录 prompt/completion
    都是正有限数的条目（OpenRouter 返回字符串美元价，含 "0"、"NaN" 噪音）。

    抛出：urllib.error.URLError / socket.timeout / json.JSONDecodeError / ValueError。
    """
    import json
    import urllib.request

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Maskit-PriceSync/1.0",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    data = json.loads(raw)
    # 兼容自托管源直接返回 {"prices": {model: {"input": ..., "output": ...}}}
    if isinstance(data, dict) and isinstance(data.get("prices"), dict):
        direct_prices = {}
        for m_name, p_info in data["prices"].items():
            if isinstance(p_info, dict) and ("input" in p_info or "output" in p_info):
                try:
                    pin = float(p_info.get("input") or 0)
                    pout = float(p_info.get("output") or 0)
                    if pin > 0 or pout > 0:
                        direct_prices[str(m_name).strip()] = {"input": round(pin, 6), "output": round(pout, 6)}
                except (TypeError, ValueError):
                    continue
        if direct_prices:
            return direct_prices

    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ValueError(f"价格源响应缺少 data 列表: {str(data)[:120]}")
    prices = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        model = str(it.get("id") or "").strip()
        if not model:
            continue
        pricing = it.get("pricing") or {}
        try:
            # OpenRouter pricing 单位是「每 token 美元」字符串（如 "0.000003"），
            # ×1e6 统一成 $/1M token 口径（与内置表/estimate_cost 一致）。
            pin = float(pricing.get("prompt") or 0) * 1e6
            pout = float(pricing.get("completion") or 0) * 1e6
            # 缓存命中价（input_cache_read，可选）：仅作展示，费用估算用标准输入价
            pcache = None
            try:
                cr = pricing.get("input_cache_read")
                if cr is not None and str(cr).strip():
                    cv = float(cr) * 1e6
                    if cv > 0 and _finite(cv):
                        pcache = round(cv, 6)
            except (TypeError, ValueError):
                pcache = None
            # 缓存写入价（input_cache_write，可选）：仅作展示。OpenRouter 对部分模型提供。
            pcw = None
            try:
                cw = pricing.get("input_cache_write")
                if cw is not None and str(cw).strip():
                    cwv = float(cw) * 1e6
                    if cwv > 0 and _finite(cwv):
                        pcw = round(cwv, 6)
            except (TypeError, ValueError):
                pcw = None
        except (TypeError, ValueError):
            continue
        # OpenRouter 对部分模型返回 0 价/NaN（如自定义路由），剔除噪音
        if not (pin > 0 and pout > 0 and _finite(pin) and _finite(pout)):
            continue
        entry = {"input": round(pin, 6), "output": round(pout, 6)}
        if pcache is not None:
            entry["cache_read"] = pcache
        if pcw is not None:
            entry["cache_write"] = pcw
        prices[model] = entry
    return prices


def _finite(v):
    import math
    return math.isfinite(v)


def load_price_cache(path):
    """读价格缓存文件；缺失/损坏返回 None（回退内置表）。"""
    try:
        import json
        if not path or not getattr(path, "exists", lambda: False)():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        prices = raw.get("prices")
        if not isinstance(prices, dict) or not prices:
            return None
        out = {}
        for model, p in prices.items():
            if isinstance(p, dict):
                try:
                    e = {"input": float(p.get("input") or 0), "output": float(p.get("output") or 0)}
                    # 保留缓存价格（可选，仅展示用）：旧缓存可能没有这两个字段
                    for ck in ("cache_read", "cache_write"):
                        cv = p.get(ck)
                        if cv is not None:
                            try:
                                cvn = round(float(cv), 6)
                                if cvn > 0 and _finite(cvn):
                                    e[ck] = cvn
                            except (TypeError, ValueError):
                                pass
                    out[str(model)] = e
                except (TypeError, ValueError):
                    continue
        if not out:
            return None
        return {
            "synced_at": raw.get("synced_at") or 0,
            "source": raw.get("source") or "",
            "prices": out,
        }
    except Exception:
        return None


def save_price_cache(path, prices, source):
    """写价格缓存文件（含同步时间）。失败静默——缓存不是关键路径。"""
    try:
        import json
        import time
        payload = {
            "synced_at": time.time(),
            "source": source,
            "prices": prices,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def extract_usage(body_text, previous=None):
    """从响应 body 提取 token 用量（尽力而为，供统计与费用估算）。

    支持三种形态：
    - OpenAI chat/completions 非流式：顶层 usage.{prompt_tokens,completion_tokens}
    - Anthropic messages：usage.{input_tokens,output_tokens}
    - SSE：包括 message_start.message.usage 和 response.* 的 response.usage。
      用量是累计计数：只更新本次出现的字段，不相加，也不把缺失字段清零。
    previous 可传入此前流片段的结果；文本截断不影响跨片段累计。
    返回 {"prompt_tokens": int, "completion_tokens": int} 或 {}（没采到）。
    """
    import json
    usage = dict(previous or {})

    def merge(data):
        if not isinstance(data, dict):
            return
        u = data.get("usage")
        if not isinstance(u, dict) or not u:
            if data.get("type") == "message_start":
                envelope = data.get("message")
            elif str(data.get("type", "")).startswith("response."):
                envelope = data.get("response")
            else:
                envelope = data.get("meta")
            if isinstance(envelope, dict):
                u = envelope.get("usage") or envelope.get("tokens")
        if not isinstance(u, dict):
            return
        updates = {}
        for field, aliases in (("prompt_tokens", ("prompt_tokens", "input_tokens")),
                               ("completion_tokens", ("completion_tokens", "output_tokens"))):
            for alias in aliases:
                if alias not in u:
                    continue
                try:
                    value = int(u[alias])
                except (TypeError, ValueError, OverflowError):
                    continue
                if value >= 0:
                    updates[field] = value
                    break
        # Preserve the existing total-only compatibility path.
        if not updates and u.get("total_tokens") is not None:
            try:
                total = int(u["total_tokens"])
                if total >= 0:
                    updates["prompt_tokens"] = total
            except (TypeError, ValueError, OverflowError):
                pass
        if updates:
            usage.update(updates)
            usage.setdefault("prompt_tokens", 0)
            usage.setdefault("completion_tokens", 0)

    if not body_text:
        return usage
    try:
        data = json.loads(body_text)
    except (TypeError, ValueError):
        pass
    else:
        merge(data)
        return usage
    # SSE data lines may contain partial usage snapshots from different events.
    for line in body_text.splitlines():
        if not line.startswith("data:"):
            continue
        line_data = line[5:].lstrip(" ")
        if not line_data or line_data == "[DONE]":
            continue
        try:
            d = json.loads(line_data)
        except Exception:
            continue
        merge(d)
    return usage
