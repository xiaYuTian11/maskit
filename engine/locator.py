"""实体定位：把"文本里的敏感字符区间"映射成"图像里的矩形"，并自校验。

## 为什么要做到"字符级"

整行打码会把"手机："这类标签一起盖掉（实测：一行 `手机：<号码> 姓名：<姓名>`，
整行遮会把标签也糊了）。用户明确要求"不要误伤"，而误伤的另一面是**漏字**
（框太窄，号码露出半截）。所以这里做两件事：

1. **只框住敏感子串本身**：按东亚宽度加权把行框切开（CJK/全角=2，其余=1）；
2. **裁图复认自校验**：把算出的框裁出来再识别一遍，实体串必须完整落在框里；
   不满足就退到整行框（`verified=False`），再不行就报失败，由上层按 fail-closed 处理。

## 为什么用 difflib 拿区间，而不是改核心脱敏器

`transparent._mask_text()` 一次跑几十条规则 + 自定义词 + 归一化补扫，热路径上再插
"记录每个命中偏移"的出参，等于给最敏感的代码加一条容易漂的分支。而我们要的只是
**原文 ↔ 脱敏文本的差异区间**——`SequenceMatcher` 的 `replace/delete` opcode 就是它，
开销是微秒级（一行百来字）。实测这比改核心代码更可控。

> 若哪天实测精度不够（比如同一行里出现两个相同值导致对齐错位），再把出参方案做成
> 备选；设计文档 §5.2 已记录两条路线。
"""

import difflib
import io
import math
import re
import unicodedata
from dataclasses import dataclass

from PIL import Image

# 从 `{{PHONE_abcxyz}}` 里取标签。标签字符类含 CJK：自定义词库的中文分类名
# 会原样进 token（`{{人名_bcdfgh}}`），不认就会让视觉脱敏的标签展示空掉。
_PLACEHOLDER_LABEL_RX = re.compile(r"\{\{\s*([A-Z0-9_\u4e00-\u9fff]{1,24})_")

# pad：左右各 0.5em（em=行高）+ 块宽的 4%（见 char_x 注释：加权模型的字体误差
# 与块宽成正比，固定 em 留白护不住宽行）。实测宽度加权会**偏窄**，评测里出现过
# "左边界差 6px、恰好切掉身份证第一位"的用例（30px 字号 ≈ 0.2em）——0.35em 不够，
# 0.5em 才有余量。让多了只是多遮半个字符（可接受），让少了就是漏字（不可接受）。
DEFAULT_PAD_EM = 0.5
# 按块宽缩放的留白分量：|模型比例 2.0 - 最坏字体 1.33| 加权后 ≈ 4% 块宽
PAD_FRAC_OF_WIDTH = 0.04
# 自校验失败后扩到整行框时的额外外扩（同上理由）
LINE_PAD_EM = 0.10
# 垂直留白：实体框曾直接沿用 det 行框的 y1/y2，零留白 —— 英文降部（g/p/y 的下半
# 截）和高位数字的上弧会露出笔画残边（2026-10-30 实测，复认 OCR 读不出但肉眼可见）。
# 每侧 0.15em（em=行高）：足以盖住降部，又不会叠到上下相邻行（行间距通常 ≥0.3em）。
VERT_PAD_EM = 0.15


@dataclass(frozen=True)
class EntityRect:
    """一个待打码的矩形（**像素**坐标）与其来源。"""

    quad: tuple            # x1, y1, x2, y2
    charspan: tuple        # 原始文本里的 [start, end)
    label: str
    verified: bool         # 是否通过"裁图复认"
    fallback: str          # "" | "line"（退到整行框）


def _eaw(ch):
    """东亚宽度权重：全角/宽字符算 2，其余算 1。"""
    return 2.0 if unicodedata.east_asian_width(ch) in ("W", "F") else 1.0


class MaskFailed(Exception):
    """脱敏判定本身失败（规则引擎抛异常）。

    **不能当成"没命中"**：那等于"判定失败 → 原图放行"，是 fail-open。
    调用方必须按失败处理（阻断或遮盖）。
    """


def spans_from_mask(text, mask_fn):
    """`mask_fn(text) -> masked_text` → `[(start, end, label)]`（**原文**坐标）。

    判定失败抛 `MaskFailed`（见类注释），不静默返回空。
    """
    if not text:
        return []
    try:
        masked = mask_fn(text)
    except Exception as e:
        raise MaskFailed(type(e).__name__)
    if not isinstance(masked, str):
        raise MaskFailed("non_str_result")
    if masked == text:
        return []
    spans = []
    sm = difflib.SequenceMatcher(a=text, b=masked, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag not in ("replace", "delete") or i2 <= i1:
            continue
        m = _PLACEHOLDER_LABEL_RX.search(masked[j1:j2] if tag == "replace" else "")
        spans.append((i1, i2, (m.group(1) if m else "")))
    # 相邻/重叠区间合并（同一实体的多段替换）
    merged = []
    for s, e, label in sorted(spans):
        if merged and s <= merged[-1][1]:
            ps, pe, pl = merged[-1]
            merged[-1] = (ps, max(pe, e), pl or label)
        else:
            merged.append((s, e, label))
    return merged


def char_x(quad, text, start, end, pad_em=DEFAULT_PAD_EM):
    """按宽度加权把字符区间 [start, end) 映射成 x 区间（未裁剪）。

    加权模型的误差与**块宽成正比**：它假设 CJK:数字 = 2:1，但实测微软雅黑是
    24:18 = 1.33（Noto Sans CJK ≈ 1.8，宋体 ≈ 2.0）——前缀合成的偏差率约
    |2.0-1.33|/1.33 × 前缀占比 ≈ 3~4%。固定 0.5em 留白只护得住 ~400px 宽的块
    （443px 实测超出 3.3px → 首位数字露边）；1000px 宽的聊天截图行误差会到
    ~38px，必漏。所以留白必须带一个**随块宽缩放的分量**，按最坏字体（比例
    差最大）定 4%。宁可多遮 4% 也不要漏——漏是泄露，多遮只是误伤。
    """
    x1, y1, x2, y2 = quad
    total = sum(_eaw(c) for c in text)
    if total <= 0 or x2 <= x1:
        return x1, x2
    pre = sum(_eaw(c) for c in text[:start])
    mid = sum(_eaw(c) for c in text[start:end])
    width = (x2 - x1)
    pad = pad_em * max(1.0, y2 - y1) + PAD_FRAC_OF_WIDTH * width
    bx1 = x1 + width * (pre / total) - pad
    bx2 = x1 + width * ((pre + mid) / total) + pad
    return max(x1, bx1), min(x2, bx2)


# 裁图复认的最小画布高。实测（30px 字号的实体裁图）：不加白边时识别成 `38030038(`、
# 号码被切成半截（实测边缘字符丢失）；把裁图贴到 ≥64px 高的白底画布上就完整了。
# 原因是识别模型的输入会被缩放/归一化，贴边内容会丢——所以给白边不是可选项。
VERIFY_MIN_HEIGHT = 64
VERIFY_MARGIN = 0   # 复认只测"要涂的那块"，不外扩


def _crop_png(img, rect, margin=VERIFY_MARGIN):
    """裁出矩形并贴到白底画布上（供复认）。

    ⚠️ 默认 margin=0：**复认必须只测"真正要涂的那块"**。曾经的 8px 外扩让
    "框偏窄 6px" 的实体也通过复认（裁剪多带了那 6px，号码自然读得全），
    结果画出来的框是窄的、露字——这是评测抓出来的真实缺陷，别再把 margin 加回来。
    贴白边（≥64px 高）只为识别模型稳定，不改变内容区域。
    """
    x1, y1, x2, y2 = rect
    w, h = img.size
    # 向外取整：保证涂色区域完整落在裁剪里（向内取整会把边缘半像素切掉）
    box = (max(0, math.floor(x1) - margin), max(0, math.floor(y1) - margin),
           min(w, math.ceil(x2) + margin), min(h, math.ceil(y2) + margin))
    if box[2] <= box[0] or box[3] <= box[1]:
        return None
    crop = img.crop(box).convert("RGB")
    if crop.size[1] < VERIFY_MIN_HEIGHT:
        canvas = Image.new("RGB", (crop.size[0] + 24, VERIFY_MIN_HEIGHT + 24), (255, 255, 255))
        canvas.paste(crop, (12, 12))
        crop = canvas
    buf = io.BytesIO()
    crop.save(buf, "PNG")
    return buf.getvalue()


def verify_rect(img, rect, needle, recognize, *, deadline=None, crop_cache=None):
    """裁图复认：`needle`（实体原文）是否完整落在这个框里。

    收紧成"去空白后包含"：OCR 复认常丢空格（实测 `Tax ID` → `TaxID`），
    空格不算漏字，数字/字母/汉字才算。
    """
    def _norm(s):
        return "".join(ch for ch in str(s or "") if not ch.isspace())

    payload = _crop_png(img, rect)
    if not payload:
        return False
    if crop_cache is not None and payload in crop_cache:
        got = crop_cache[payload]
    else:
        try:
            got = _norm(recognize(payload, deadline=deadline))
        except Exception:
            return False
        if crop_cache is not None:
            crop_cache[payload] = got
    want = _norm(needle)
    if not want:
        return False
    return want in got


def locate(blocks, mask_fn, *, img, recognize, min_score=0.5,
           pad_em=DEFAULT_PAD_EM, deadline=None):
    """`blocks` + 脱敏器 → `(rects, stats)`。

    - `rects`: 去重/合并后的 `EntityRect` 列表（可直接拿去涂色）；
    - `stats`: `{"entities", "verified", "line_fallback", "failed", "low_conf"}`
      供事件上报（`vision_masked` / `vision_verified` / `vision_lines_masked`）。

    自校验失败时的退路：**实体框 → 整行框 → 记 failed**。退到整行框仍然要复认一次，
    因为"整行框都框不住"说明块本身有问题（例如 det 框只盖住了半个词），此时上层必须阻断。
    """
    rects = []
    stats = {"entities": 0, "verified": 0, "line_fallback": 0, "failed": 0, "low_conf": 0}
    crop_cache = {}
    for block in blocks:
        text = (block.text or "").strip()
        if not text:
            continue
        if block.score < min_score:
            stats["low_conf"] += 1
            continue
        try:
            spans = spans_from_mask(text, mask_fn)
        except MaskFailed:
            # 判定失败：整块记失败，由上层阻断（绝不"当没命中"放行）
            stats["failed"] += 1
            continue
        if not spans:
            continue
        x1, y1, x2, y2 = block.quad
        line_rect = (x1, y1, x2, y2)
        line_pad = LINE_PAD_EM * max(1.0, y2 - y1)
        v_pad = VERT_PAD_EM * max(1.0, y2 - y1)
        vy1 = max(0, y1 - v_pad)
        vy2 = min(img.size[1], y2 + v_pad)
        padded_line = (max(0, x1 - line_pad), vy1,
                       min(img.size[0], x2 + line_pad), vy2)
        for start, end, label in spans:
            needle = text[start:end]
            stats["entities"] += 1
            bx1, bx2 = char_x(block.quad, text, start, end, pad_em=pad_em)
            rect = (bx1, vy1, bx2, vy2)
            # 整块快路径：整块即实体且分数高（>=0.85），无需字符切分，det 原生真框已足额覆盖
            if start == 0 and end == len(text) and block.score >= 0.85:
                stats["verified"] += 1
                rects.append(EntityRect(padded_line, (start, end), label, True, ""))
                continue
            if verify_rect(img, rect, needle, recognize, deadline=deadline, crop_cache=crop_cache):
                stats["verified"] += 1
                rects.append(EntityRect(rect, (start, end), label, True, ""))
                continue
            # 退一：整行框
            if verify_rect(img, padded_line, needle, recognize, deadline=deadline, crop_cache=crop_cache):
                stats["line_fallback"] += 1
                rects.append(EntityRect(padded_line, (start, end), label, False, "line"))
                continue
            stats["failed"] += 1
            rects.append(EntityRect(tuple(line_rect), (start, end), label, False, "failed"))

    return _merge(rects), stats


def _merge(rects):
    """合并同一行内重叠/相邻的框：减少色块碎片，也让"多个实体在同一行"看起来正常。"""
    if not rects:
        return []
    out = []
    for r in rects:
        if out:
            last = out[-1]
            lx1, ly1, lx2, ly2 = last.quad
            x1, y1, x2, y2 = r.quad
            same_row = abs(y1 - ly1) <= 2 and abs(y2 - ly2) <= 2
            if same_row and x1 <= lx2 + 2:
                out[-1] = EntityRect((min(lx1, x1), min(ly1, y1), max(lx2, x2), max(ly2, y2)),
                                     (last.charspan[0], r.charspan[1]),
                                     last.label or r.label,
                                     last.verified and r.verified,
                                     last.fallback or r.fallback)
                continue
        out.append(r)
    return out
