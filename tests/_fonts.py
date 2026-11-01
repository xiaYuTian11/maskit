"""OCR 测试与评测共用的跨平台字体查找。

为什么单独一个模块：OCR 用例要画中文，PIL 的 `load_default()` 是位图字体、画不出 CJK。
原来各文件硬编码 `C:/Windows/Fonts/msyh.ttc`，在 CI（ubuntu）上会静默退回默认字体，
中文用例要么全红、要么画出一张没有字的图却"通过"。统一在这里找，找不到就明确报告。

CI 上由 `apt-get install fonts-noto-cjk` 提供（见 .github/workflows/ci.yml）。
"""
import os
from pathlib import Path

_CJK = (
    "C:/Windows/Fonts/msyh.ttc",
    "C:/Windows/Fonts/simhei.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
    "/System/Library/Fonts/PingFang.ttc",
    "/System/Library/Fonts/STHeiti Medium.ttc",
)
_LATIN = (
    "C:/Windows/Fonts/arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/Library/Fonts/Arial.ttf",
)


def _first(paths):
    override = os.environ.get("MASKIT_TEST_CJK_FONT")
    if override and Path(override).is_file():
        return override
    for p in paths:
        if Path(p).is_file():
            return p
    return None


CJK_FONT_PATH = _first(_CJK)
LATIN_FONT_PATH = _first(_LATIN) or CJK_FONT_PATH
HAS_CJK_FONT = CJK_FONT_PATH is not None
SKIP_REASON = ("没有可用的 CJK 字体（装 fonts-noto-cjk，或设 MASKIT_TEST_CJK_FONT）；"
               "默认位图字体画不出中文，跑了也没有意义")


def font(size, cjk=True):
    from PIL import ImageFont
    path = CJK_FONT_PATH if cjk else LATIN_FONT_PATH
    if path:
        return ImageFont.truetype(path, size)
    return ImageFont.load_default()
