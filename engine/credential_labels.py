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
