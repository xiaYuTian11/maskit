"""中文姓名启发层：补 NER 的漏检、剔 NER 的过检。

## 为什么需要这一层

`ner_engine` 是概率模型，两类错都真实存在（2026-10-25 隔离实例实测）：

- **漏检**：`客户某甲` / `联系人：某乙` / `我叫某丙` 这类「角色词 + 姓名」
  的固定句式，模型经常只标出一部分或干脆漏掉；
- **过检**：`张开的括号` / `王国的军队` —— 姓氏字开头的普通词被当成姓名。

参照 magpie `internal/redact/zhname.go`：用**纯 stdlib 的规则层**双向修正。
它是 NER 的**后处理**，不是独立检测器——关掉 NER 时不跑（否则等于给用户一个
他没开的检测面）。

## 判据（三条同时成立才算姓名）

1. **形态**：常见姓氏（单字或复姓） + 1~2 个字的名；
2. **上下文证据**（至少一条）：
   - 前面是角色词（`客户` / `联系人` / `作者` / `我叫` …）；
   - 后面是称谓或动词（`先生` / `女士` / `说` / `反馈` …）；
   - 前面是「给 / 找 / 问 / 让」这类**双字动词**（单字太弱，会把 `给力` 也算上）；
3. **不在反例词表里**（`张量` / `高度` / `程序` / `方法` … 这些以姓氏字开头的普通词）。

第 3 条优先于第 1、2 条：反例词即使被角色词包着也不算（`客户高度认可` 里的
`高度` 不是人名）。

## 为什么不用「前后是汉字」这种弱判据

那会把任意两字词都标成人名。宁可少补几个，也不能把普通文本大面积打码——
用户看到满屏占位符会直接关掉整个功能。
"""
from __future__ import annotations

import re
import unicodedata

# 常见单字姓（按使用频率粗排，不追求全量——漏掉的姓由 NER 自己兜）。
ZH_SURNAMES = (
    "王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于蒋"
    "蔡余杜叶程苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付傅方白邹孟熊秦邱江尹薛"
    "闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴莫孔向汤常温康施文牛樊葛邢安齐易乔伍"
    "庞颜倪庄聂章鲁岳翟殷詹申欧耿关兰焦俞左柳甘祝包宁尚符舒阮柯纪梅童凌毕单季裴霍"
    "涂成苗谷盛曲翁冉骆蓝路游辛靳管柴蒙鲍华喻祁蒲房滕屈饶解牟艾尤阳时穆农司卓古吉"
    "缪简车项连芦麦褚娄窦戚岑景党宫费卜冷晏席卫米柏宗瞿桂全佟应臧闵苟邬边卞姬师仇"
    "栾隋商刁沙荣巫寇桑郎甄丛仲虞敖巩佘池查麻苑迟邝"
)

# 复姓
ZH_COMPOUND_SURNAMES = (
    "欧阳", "司马", "上官", "诸葛", "东方", "皇甫", "尉迟", "公孙", "慕容", "令狐",
    "司徒", "夏侯", "长孙", "宇文", "轩辕", "端木", "独孤", "南宫", "西门", "钟离",
    "呼延", "申屠", "闻人", "澹台", "拓跋", "万俟", "夹谷", "谷梁", "左丘", "东郭",
)

# 反例词表：以姓氏字开头但是普通词。**优先于**姓氏规则。
ZH_NOT_NAMES = frozenset({
    # 高频技术/日常词
    "张量", "张开", "张贴", "张力", "高度", "高效", "高级", "高速", "高亮", "高手",
    "高兴", "高压", "高温", "王国", "王者", "王牌", "黄河", "黄色", "黄金", "方法",
    "方向", "方式", "方案", "方便", "方面", "方程", "程序", "程度", "温度", "白色",
    "金额", "金融", "金牌", "江湖", "石头", "马上", "周期", "周末", "周围", "周边",
    "周报", "文件", "文本", "文档", "文字", "文章", "文化", "余额", "安全", "安装",
    "安排", "安心", "钱包", "叶子", "毛病", "万一", "雷达", "宋体", "常量", "常用",
    "常见", "向量", "向上", "全部", "全局", "全面", "史上", "易用", "时间", "时候",
    "明天", "明确", "明白", "任何", "任务", "任意", "华为", "管理", "简单", "简介",
    "范围", "许多", "许可", "包括", "包含", "关于", "关系", "关闭", "连接", "成功",
    "成为", "应用", "应该", "单位", "单元", "单独", "司机", "车辆", "车子", "路径",
    "路由", "林业", "龙头", "柏林", "米饭", "宁可", "师傅", "老师", "老板", "老婆",
    "老公", "老家", "小时", "小心", "小说", "小姐", "小孩", "小组", "周一", "周二",
    "周三", "周四", "周五", "周六", "周日", "周天", "句号", "史前", "温暖", "康复",
    # 行政/地名（会被 GPE 类规则处理，不该进 NAME）
    "中国", "北京", "上海", "广东", "深圳", "杭州", "江苏", "浙江",
})

# 反例词按**首字**分桶（性能关键，2026-10-25 实测）：
# 原实现每个候选位置都 `text.startswith(w)` 遍历全部 138 个反例词，姓氏字密集的
# 文本实测 **10.6 µs/字符**（1MB ≈ 8.6 秒）——那是热路径上的 DoS 面。
# 按首字分桶后，每个位置只检查同首字的几个词（平均 2~3 个）。
# 桶内按**长度降序**：长词优先匹配（`王国的军队` 要先于 `王国`）。
_ZH_NOT_NAMES_BY_HEAD = {}


def _not_name_buckets():
    """反例词分桶（惰性构建一次；词表是模块级常量，不会变）。"""
    buckets = _ZH_NOT_NAMES_BY_HEAD
    if buckets:
        return buckets
    for w in ZH_NOT_NAMES:
        if not w:
            continue
        buckets.setdefault(w[0], []).append(w)
    for v in buckets.values():
        v.sort(key=len, reverse=True)
    return buckets


# 角色词：出现在姓名**之前**，说明后面是人。
#
# 必须同时收录「角色 + 是」（`提交者是欧阳娜娜`）：这是中文里最常见的句式，
# 只收 `提交者` 而句式写的是 `提交者是` 时，`endswith` 会失配（实测漏检）。
# 加 `是` 不会引入误报：`提交者是` 后面跟的必是受事（人或物），而姓氏规则与
# 名用字判据会把「物」挡掉。
ZH_ROLES = (
    "客户", "联系人", "作者", "提交者", "审核人", "审批人", "负责人", "经办人",
    "收件人", "发件人", "收货人", "申请人", "报告人", "同事", "姓名", "名字",
    "署名", "签名", "我叫", "他叫", "她叫", "名叫", "叫做", "尊敬的", "亲爱的",
    "致", "转告", "通知", "抄送", "推荐", "介绍",
    # 「角色 + 是」形态
    "提交者是", "审核人是", "负责人是", "作者是", "客户是", "联系人是",
    "申请人 是", "经办人是", "收件人是", "发件人是", "报告人是",
)

# 称谓/动词：出现在姓名**之后**，说明前面是人。
ZH_AFTER = (
    "先生", "女士", "小姐", "老师", "同学", "同志", "经理", "总监", "主任",
    "师傅", "医生", "律师", "教授", "博士", "工程师", "会计",
    "说", "讲", "表示", "认为", "反馈", "提到", "提交", "负责", "告诉",
    "回复", "反馈说", "已读", "收到",
)

# 前置双字动词：这些词后面跟的通常是**受事**（人）。
ZH_BEFORE_VERBS = (
    "给", "找", "问", "让", "和", "与", "跟", "叫", "请", "通知", "联系",
    "转给", "交给", "告诉", "麻烦", "谢谢",
)

# 名用字不能是这些（它们是句子继续下去用的虚词/高频字）
ZH_NOT_GIVEN = frozenset(
    "的了在是和与跟同说他她它我你您们这那个不也都就还把被给到对从向为以等及或并而"
    "吗呢吧啊去来有没要会能让请已将再又很更最先后上下里外时年日号发打回写问讲叫找"
    "用做看想知道得地着过之其此每各某该所反表认提负"
)


# 汉字判定缓存（性能关键）：`unicodedata.name()` 每次都要查表并构造字符串，
# 在逐字符循环里是主要开销。CJK 统一表意文字都在 U+3400-9FFF / U+F900-FAFF，
# 直接比码位比查表快一个数量级（实测 10.6 → 1.2 µs/字符）。
def _is_han(ch: str) -> bool:
    if not ch:
        return False
    cp = ord(ch)
    # CJK 统一表意文字（含扩展 A）+ 兼容表意文字 + 扩展 B 起的高位面
    return (0x3400 <= cp <= 0x4DBF or 0x4E00 <= cp <= 0x9FFF
            or 0xF900 <= cp <= 0xFAFF or 0x20000 <= cp <= 0x3FFFF)


# 汉字/姓氏的**快筛正则**（性能关键，2026-10-25）。
#
# 原实现是 `any(_is_han(c) for c in text)`：纯 Python 逐字符迭代，1MB 英文文本
# 实测 106ms —— 而这段跑在**截断之前**，于是「截断上限 32KB」根本挡不住它。
# 真机长会话请求体 1.9MB，每次脱敏都白付这笔钱。
#
# 换成正则后由 C 引擎扫描，同样的 1MB 只要 ~2ms（50 倍）。判据完全等价：
# 字符类就是 `_is_han` 的码位区间的并集。
_HAN_RX = re.compile("[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff"
                     "\U00020000-\U0003ffff]")


def _surname_len_at(text: str, i: int) -> int:
    """从 `i` 开始能匹配多长的姓氏（2=复姓，1=单姓，0=不是姓）。"""
    two = text[i:i + 2]
    if len(two) == 2 and two in ZH_COMPOUND_SURNAMES:
        return 2
    if text[i:i + 1] and text[i] in ZH_SURNAMES:
        return 1
    return 0


# 角色词与姓名之间可能隔着分隔符（`联系人：某乙` / `客户-陈建国` /
# `作者: 某甲`）。判据必须**跳过紧邻的标点**，否则「联系人：」永远匹配不上
# —— 而带冒号恰恰是最常见的写法（实测漏检）。
_SEPARATORS = frozenset("：:，,。.、；;！!？? \t\u3000-—_|/()（）[]【】<>《》\"'“”‘’")
# `str.lstrip` 要字符串而不是集合：预先拼好，避免每次调用都 join
_SEPARATORS_STR = "".join(sorted(_SEPARATORS))


def _trim_separators(text: str, end: int, *, limit: int = 4) -> int:
    """从 `end` 往前跳过连续的标点/空白，返回新的结束位置（最多跳 limit 个）。"""
    j = end
    skipped = 0
    while j > 0 and skipped < limit and text[j - 1] in _SEPARATORS:
        j -= 1
        skipped += 1
    return j


# 角色词/称谓/动词按**长度**分组（性能关键）：`endswith` 每次都要构造切片并
# 逐个比较，而按长度分组后可以直接取对应长度的尾部切片做集合查找（O(1)）。
# 实测这一项把 `_has_role_before` 从 13ms/2万次降到 2ms/2万次。
def _by_len(words):
    groups = {}
    for w in words:
        groups.setdefault(len(w), set()).add(w)
    return groups


_ZH_ROLES_BY_LEN = _by_len(ZH_ROLES)
_ZH_AFTER_BY_LEN = _by_len(ZH_AFTER)
_ZH_VERBS_BY_LEN = _by_len(ZH_BEFORE_VERBS)


def _tail_hits(head: str, groups) -> bool:
    """`head` 的尾部是否命中任一分组里的词（按长度取切片 + 集合查找）。"""
    n = len(head)
    for ln, words in groups.items():
        if ln <= n and head[n - ln:] in words:
            return True
    return False


def _head_hits(tail: str, groups) -> bool:
    """`tail` 的头部是否命中任一分组里的词。"""
    for ln, words in groups.items():
        if tail[:ln] in words:
            return True
    return False


def _has_role_before(text: str, start: int) -> bool:
    """姓名前是否有角色词（窗口 8 字，且允许中间隔着标点）。

    为什么窗口 8 而不是 6：`提交者是` / `尊敬的` 这类 3~4 字角色词 + 1~2 个标点
    就要 6~7 个字符位，6 会临界漏检。
    """
    head = text[max(0, start - 8):_trim_separators(text, start)]
    return _tail_hits(head, _ZH_ROLES_BY_LEN)


def _has_title_after(text: str, end: int) -> bool:
    """姓名后是否有称谓/动词（同样允许中间隔标点：`某甲，先生`）。"""
    tail = text[end:end + 5]
    stripped = tail.lstrip(_SEPARATORS_STR)
    return _head_hits(stripped, _ZH_AFTER_BY_LEN)


def _has_verb_before(text: str, start: int) -> bool:
    head = text[max(0, start - 5):_trim_separators(text, start, limit=2)]
    return _tail_hits(head, _ZH_VERBS_BY_LEN)


# 强证据用的前置动词：**只收双字及以上**（如双字的「联系」「转给」「告诉」「麻烦」）。
#
# 为什么排除单字（2026-10-28 真机）：单字动词（「请」「给」「和」）的上下文太泛，
# 普通技术句子的「请……」「给……」就能满足。`has_strong_context` 用它决定要不要
# 掩 2~3 字候选，而误掩会把正文换成占位符（模型据此分析代码必然出错）。
# 双字动词仍覆盖「动词短语 + 受事（人）」这类真实句式。
_ZH_STRONG_VERBS_BY_LEN = {ln: ws for ln, ws in _ZH_VERBS_BY_LEN.items() if ln >= 2}


def _has_strong_verb_before(text: str, start: int) -> bool:
    """实体前 8 字内是否出现**双字**前置动词（不要求紧贴尾部）。

    「请联系甲方某甲」里实体前是「甲方」，只查尾部会漏掉「联系」；而头部子串查找
    不会引入单字动词那类噪声（表里只剩双字词）。
    """
    head = text[max(0, start - 8):_trim_separators(text, start, limit=2)]
    for words in _ZH_STRONG_VERBS_BY_LEN.values():
        for w in words:
            if w in head:
                return True
    return False


def _given_len_ok(text: str, gstart: int, gend: int) -> bool:
    """名的部分是否合法：1~2 字，且不含虚词/句读。"""
    given = text[gstart:gend]
    if not given or len(given) > 2:
        return False
    for ch in given:
        if not _is_han(ch) or ch in ZH_NOT_GIVEN:
            return False
    return True


# 单次扫描的字符上限（性能闸，2026-10-25）。
#
# 为什么必须有：这是**逐字符**循环，最坏形态（姓氏字密集）实测 3.6 µs/字符
# —— 1MB 要 3.6 秒，跑在脱敏热路径上就是一次请求把整个 worker 占死。
# 而中文姓名是**短文本**现象：一封邮件、一段对话、一条工单，都在几十 KB 以内。
# 超限时只扫前 N 字符并**计数上报**（不静默），与 NER 的 `_SCAN_BODY_MAX`
# 同一口径（那边也是「人写的正文不会藏在 512KB 之后」）。
MAX_SCAN_CHARS = 32 * 1024

# 截断**不在这里记账**（2026-10-25 复核）：本模块跑在 `_MASK_POOL` 的多 worker
# 线程里，进程级计数会跨请求串号（会话 A 的截断挂到会话 B 的事件上）。
# 正确做法与 `_note_definition_skip` 同形态：由**调用方**写进 sid 级会话字典、
# 随 MASK 事件取走清零。`find_names(..., return_truncated=True)` 返回该标志。


def find_names(text, return_truncated=False):
    """找出**上下文可证实**的中文姓名，返回 [(start, end, "NAME")]。

    三条判据同时成立（见模块 docstring）。返回区间两两不重叠，按起点升序。

    `return_truncated=True` 时返回 `(spans, truncated)`：`truncated` 表示文本
    超过 `MAX_SCAN_CHARS` 被截断（调用方据此写进 sid 级会话字典并上报，
    **不要**用模块级计数——那会在多 worker 线程间串号）。

    永不抛异常：热路径上跑，出错返回空（等价于「这轮没找到」），
    与 `audit_signals` 同一纪律。
    """
    def _ret(spans, truncated=False):
        return (spans, truncated) if return_truncated else spans

    try:
        if not isinstance(text, str) or len(text) < 2:
            return _ret([])
        # 截断必须**在预检之前**（2026-10-25）：原实现的汉字预检扫的是**全文**，
        # 于是「上限 32KB」完全挡不住超长文本——纯英文 1MB 实测 106ms 全花在
        # 那次逐字符预检上（真机长会话请求体 1.9MB，每轮白付）。
        #
        # ⚠️ 截断标志的**判定位置**不能随便挪（2026-10-25 复核 P2-1）：
        # 必须在「无汉字早退」**之后**才能置位。否则一段 >32KB 的纯英文/纯代码
        # system prompt 也会报 `zh_names_truncated` —— 而它里面根本没有姓名候选，
        # 截断没损失任何东西。那是纯粹的新噪声源（本模块的全部意义就是去噪）。
        _over = len(text) > MAX_SCAN_CHARS
        if _over:
            text = text[:MAX_SCAN_CHARS]
        # 快路径：没有汉字就没有中文姓名。用 C 引擎的正则扫（比逐字符快 ~50 倍），
        # 判据与 `_is_han` 的码位区间完全等价。
        if not _HAN_RX.search(text):
            # 无汉字 → 截断不损失任何候选，**不报截断**
            return _ret([])
        _truncated = _over
        out = []
        i = 0
        n = len(text)
        while i < n:
            slen = _surname_len_at(text, i)
            if not slen:
                i += 1
                continue
            # 反例词优先：`张量` / `高度` 这类直接跳过整个词。
            # 只查**同首字**的桶（见 `_not_name_buckets` 的性能说明）。
            blocked = False
            for w in _not_name_buckets().get(text[i], ()):
                if text.startswith(w, i):
                    blocked = True
                    i += len(w)
                    break
            if blocked:
                continue
            matched = None
            # 名 1~2 字：优先试 2 字（`某乙`），再试 1 字（`某丁`）
            for glen in (2, 1):
                gstart, gend = i + slen, i + slen + glen
                if gend > n:
                    continue
                if not _given_len_ok(text, gstart, gend):
                    continue
                # 上下文证据：角色词 / 称谓 / 前置动词，至少一条
                if not (_has_role_before(text, i)
                        or _has_title_after(text, gend)
                        or _has_verb_before(text, i)):
                    continue
                matched = (i, gend)
                break
            if matched:
                out.append((matched[0], matched[1], "NAME"))
                i = matched[1]
            else:
                i += slen
        return _ret(out, _truncated)
    except Exception:
        return _ret([])


def is_han(ch: str) -> bool:
    """公共别名：外部（如 `transparent._short_name_without_context`）需要与姓氏判定
    同一套汉字口径，不要另写一份码位区间。"""
    return _is_han(ch)


def has_strong_context(text, start, end):
    """实体区间是否有**强**上下文证据：角色词 / 后置称谓 / 自身以称谓结尾。

    为什么只收强证据（2026-10-28 真机事件库）：`_has_verb_before` 的窗口只有 5 字
    且收单字动词（`给`/`请`/`和`），`请保持简洁` 这类普通句子就能满足 —— 据此
    保留 2~3 字候选，等于把高频词全打成占位符。当日 NAME 命中 65103 次，其中
    62141 次是 ≤3 字中文普通词（`简洁` 4990 / `时直` 4987 / `边界` 4800 / `项目规` 4564），
    模型看到的正文被替换成占位符。强证据判据不用于提高召回，只用于回答「这个短候选
    值不值得冒误掩码的风险」。
    """
    try:
        if not isinstance(text, str) or start < 0 or end > len(text) or end <= start:
            return False
        if _has_role_before(text, start) or _has_title_after(text, end):
            return True
        # 双字前置动词（如「联系」「转给」）：单字动词不算强证据。
        if _has_strong_verb_before(text, start):
            return True
        # `张经理` / `王主任`：称谓包在实体自身尾部（NER 常把称谓一起标进实体）
        return _tail_hits(text[start:end], _ZH_AFTER_BY_LEN)
    except Exception:
        return False


def rejected_spans(text, ner_spans):
    """从 NER 的实体区间里剔掉「反例词表里的伪姓名」。

    `ner_spans` 是 [(start, end, label)]；返回**应当删除**的那些区间。

    判据：标签是 NAME 且区间文本在反例词表里（或区间文本是反例词的前缀）。
    为什么是「前缀」也算：模型常把 `张开的括号` 标成 `张开`，那正是反例词本身。
    """
    try:
        bad = []
        if not isinstance(text, str) or not ner_spans:
            return bad
        for sp in ner_spans:
            try:
                s, e = int(sp[0]), int(sp[1])
                label = sp[2] if len(sp) > 2 else ""
            except (TypeError, ValueError, IndexError):
                continue
            if label not in ("NAME", "PERSON"):
                continue
            if s < 0 or e > len(text) or e <= s:
                continue
            frag = text[s:e]
            if frag in ZH_NOT_NAMES:
                bad.append(sp)
                continue
            # 片段是某个反例词的前缀（`张开` ⊂ `张开的括号` 的模型标注）
            if any(w.startswith(frag) for w in ZH_NOT_NAMES):
                bad.append(sp)
        return bad
    except Exception:
        return []
