"""图片 / Office 内嵌图 / PDF / 代理链路的脱敏契约锁（本地 det+rec 架构）。

## 这个文件为什么存在

`visual_redactor` 是唯一一条"把像素当正文"的通道，漏了**什么都看不出来**。所以断言分三层：

1. **逻辑层**（注入假 `Block`，不跑模型）：只遮实体、格式保持、干净零触碰、
   定位失败必须阻断、`allow_cover` 只给 PDF 用；
2. **集成层**（真模型 + 合成图）：中文号码能被打码，且只打那一块；
3. **载体层**：OOXML 内嵌图 / PDF 页 / 代理 data URL / HTTP 后端兼容路径 / 端点语义。

> 占位符样例纪律（AGENTS §3.9）：本文件不写占位符字面量，断言只查标签子串
> （如 `PHONE_`）；号码一律用尾段全 0 的显式假串。
"""
import base64
import io
import json
import re
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _fonts  # noqa: E402

import event_store  # noqa: E402
import ocr_engine as E  # noqa: E402
import panel  # noqa: E402
import pdf_redactor  # noqa: E402
import transparent as tr  # noqa: E402
import visual_redactor as vr  # noqa: E402

try:
    from PIL import Image, ImageDraw, ImageFont
except Exception:  # pragma: no cover
    Image = None

FAKE_PHONE = "13800138000"
FAKE_ID = "110101199003074514"
SID = "ext:visual-test"


def _png(size=(400, 100), color=(255, 255, 255)):
    img = Image.new("RGB", size, color)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _jpeg(size=(400, 100), color=(255, 255, 255)):
    img = Image.new("RGB", size, color)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=90)
    return buf.getvalue()


def _pixel(raw, xy):
    return Image.open(io.BytesIO(raw)).convert("RGB").getpixel(xy)


def _patch_blocks(test, blocks):
    """注入假 Block（跳过真模型），返回调用记录。"""
    calls = []

    def fake(image_bytes, *, deadline=None, max_tokens=None):
        calls.append(len(image_bytes))
        return tuple(blocks), {"backend": "fake", "orientation": 0, "ms": 0.0,
                               "downscaled": False, "low_conf": 0}

    test.addCleanup(setattr, vr, "detect_blocks", vr.detect_blocks)
    vr.detect_blocks = fake
    return calls


def _patch_recognize(test, fn=None):
    fn = fn or (lambda payload, deadline=None: "")
    test.addCleanup(setattr, vr, "_recognize", vr._recognize)
    vr._recognize = fn


def _ok_recognize(payload, deadline=None):
    """默认复认：永不失败（逻辑层测试只要验证"涂哪里"）。"""
    return FAKE_PHONE


def _patch_env(test, name, value):
    import os
    original = os.environ.get(name)
    os.environ[name] = value

    def restore():
        if original is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = original

    test.addCleanup(restore)


class LogicTests(unittest.TestCase):
    """注入假 Block：不依赖模型，锁"涂哪块、涂不涂、失败怎么办"。"""

    def setUp(self):
        tr._known_reset_for_tests()
        self.addCleanup(vr.configure, "", False, "auto")

    def test_only_the_entity_is_painted(self):
        """实体级：号码块涂灰，块外像素不动（不误伤同行其它内容）。"""
        _patch_blocks(self, [E.Block(quad=(120.0, 30.0, 260.0, 60.0),
                                     text=FAKE_PHONE, score=0.9)])
        _patch_recognize(self, _ok_recognize)
        res = vr.process_image_multimodal(_png((400, 100)), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_REDACTED)
        self.assertEqual(res["hit_count"], 1)
        self.assertEqual(_pixel(res["bytes"], (190, 45)), vr._FILL, "号码没被涂")
        self.assertEqual(_pixel(res["bytes"], (20, 45)), (255, 255, 255), "块外被误涂")
        self.assertEqual(_pixel(res["bytes"], (340, 45)), (255, 255, 255), "块外被误涂")

    def test_clean_image_is_byte_identical(self):
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 100.0, 40.0),
                                     text="welcome to the dashboard", score=0.9)])
        raw = _png()
        res = vr.process_image_multimodal(raw, SID, tr)
        self.assertEqual(res["mode"], vr.MODE_CLEAN)
        self.assertEqual(res["bytes"], raw, "干净图必须零触碰")
        self.assertEqual(res["hit_count"], 0)

    def test_jpeg_input_stays_jpeg(self):
        _patch_blocks(self, [E.Block(quad=(50.0, 20.0, 300.0, 60.0),
                                     text="note " + FAKE_PHONE, score=0.9)])
        _patch_recognize(self, _ok_recognize)
        res = vr.process_image_multimodal(_jpeg((400, 100)), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_REDACTED)
        self.assertEqual(res["format"], "JPEG")
        self.assertTrue(res["bytes"].startswith(b"\xff\xd8"), "JPEG 被写成了别的格式")

    def test_geometry_failure_covers_instead_of_faking(self):
        """定位失败 → **整图遮盖**（默认），绝不假称已打码。

        2026-11-03 改：旧契约是「图片一律 503 阻断」，实测代价太大——深色背景截图
        （终端/IDE 深色主题）的 OCR 复认不稳定，6 分钟内 14 次阻断，用户客户端
        只报「请求失败」，不知道是本地网关拦的。

        遮盖并不降低安全：整图涂灰 = 像素零保留，比“精确遮几个框”更彻底。
        本测试守住的是**不能假称成功**（`mode` 必须是 REDACTED，不是 CLEAN）。
        """
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 300.0, 60.0),
                                     text="手机：" + FAKE_PHONE, score=0.9)])
        _patch_recognize(self, lambda payload, deadline=None: "")   # 复认永远失败
        res = vr.process_image_multimodal(_png(), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_REDACTED, "定位失败不能假称干净")
        self.assertTrue(res["stats"].get("covered"), "必须标为整图遮盖")
        self.assertEqual(_pixel(res["bytes"], (200, 50)), vr._FILL, "整图必须是遮盖色")

    def test_geometry_failure_can_still_block_when_cover_disabled(self):
        """`allow_cover=False` 仍保留旧行为（阻断）——给需要严格语义的调用方。"""
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 300.0, 60.0),
                                     text="手机：" + FAKE_PHONE, score=0.9)])
        _patch_recognize(self, lambda payload, deadline=None: "")
        res = vr.process_image_multimodal(_png(), SID, tr, allow_cover=False)
        self.assertEqual((res["mode"], res["reason"]), (vr.MODE_BLOCKED, vr.BLOCK_GEOMETRY))
        self.assertEqual(res["bytes"], b"")

    def test_allow_cover_is_default_for_images(self):
        """默认值就是允许遮盖（与 PDF 页同口径）。"""
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 300.0, 60.0),
                                     text="手机：" + FAKE_PHONE, score=0.9)])
        _patch_recognize(self, lambda payload, deadline=None: "")
        res = vr.process_image_multimodal(_png(), SID, tr, allow_cover=True)
        self.assertEqual(res["mode"], vr.MODE_REDACTED)
        self.assertTrue(res["stats"].get("covered"))
        self.assertEqual(_pixel(res["bytes"], (200, 50)), vr._FILL)

    # ── 扫描本身失败：默认阻断，可开关降级为整图遮盖 ───────────────────

    def test_scan_failure_blocks_by_default(self):
        """OCR 未就绪/超时/解码失败 → 默认仍阻断。

        为什么不默认遮盖：这类失败意味着**不知道图里有什么**，遮成灰块等于图片
        功能整体不可用，而且日志里只有 reason 码，用户无法排查。
        """
        def boom(image_bytes, *, deadline=None, max_tokens=None):
            raise vr._Blocked(vr.BLOCK_UNAVAILABLE)
        real = vr.detect_blocks
        vr.detect_blocks = boom
        self.addCleanup(setattr, vr, "detect_blocks", real)
        res = vr.process_image_multimodal(_png(), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_BLOCKED)
        self.assertEqual(res["reason"], vr.BLOCK_UNAVAILABLE)

    def test_scan_failure_can_be_covered_when_enabled(self):
        """显式开 cover_on_scan_fail 后，扫不了也整图遮盖（请求不失败）。"""
        def boom(image_bytes, *, deadline=None, max_tokens=None):
            raise vr._Blocked(vr.BLOCK_UNAVAILABLE)
        real = vr.detect_blocks
        vr.detect_blocks = boom
        self.addCleanup(setattr, vr, "detect_blocks", real)
        res = vr.process_image_multimodal(_png(), SID, tr, cover_on_scan_fail=True)
        self.assertEqual(res["mode"], vr.MODE_REDACTED, "开启后必须降级为遮盖")
        self.assertTrue(res["stats"].get("covered"))
        self.assertEqual(res["stats"].get("cover_reason"), vr.BLOCK_UNAVAILABLE,
                         "降级原因必须如实带出，否则无从归因")
        self.assertEqual(_pixel(res["bytes"], (200, 50)), vr._FILL)

    def test_cover_on_scan_fail_is_configurable_via_configure(self):
        """面板下发的配置能影响行为（否则开关等于摆设）。"""
        vr.configure(cover_on_scan_fail=True)
        self.addCleanup(vr.configure, cover_on_scan_fail=False)
        self.assertTrue(vr.cover_on_scan_fail())
        vr.configure(cover_on_scan_fail=False)
        self.assertFalse(vr.cover_on_scan_fail())

    def test_low_confidence_blocks_are_not_painted(self):
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 300.0, 60.0),
                                     text=FAKE_PHONE, score=0.2)])
        _patch_recognize(self, _ok_recognize)
        res = vr.process_image_multimodal(_png(), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_CLEAN, "低分块不该被拿来打码")
        self.assertEqual(res["stats"]["low_conf"], 1, "但必须计数上报")

    def test_mask_engine_failure_blocks_instead_of_passing(self):
        """规则引擎抛异常 → 必须阻断。当成"没命中"就是 fail-open（原图放行）。"""
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 300.0, 60.0),
                                     text="手机：" + FAKE_PHONE, score=0.9)])

        class Boom(object):
            @staticmethod
            def mask(_t, _sid):
                raise RuntimeError("nlp_broken")

            @staticmethod
            def mask_body(_t, _sid):
                raise RuntimeError("nlp_broken")

        res = vr.redact_image_bytes(_png(), SID, Boom(), allow_cover=False)
        self.assertEqual(res["mode"], vr.MODE_BLOCKED)
        self.assertGreaterEqual(res["stats"].get("failed", 0), 1)

    def test_line_fallback_is_counted(self):
        """实体框复认失败、整行框成功 → 仍然打码，但记 `line_fallback`。"""
        _patch_blocks(self, [E.Block(quad=(50.0, 20.0, 500.0, 60.0),
                                     text="手机：" + FAKE_PHONE + " 姓名：张测试", score=0.9)])

        def picky(payload, deadline=None):
            img = Image.open(io.BytesIO(payload))
            return "手机：" + FAKE_PHONE if img.size[0] >= 350 else ""

        _patch_recognize(self, picky)
        res = vr.process_image_multimodal(_png((600, 100)), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_REDACTED)
        self.assertEqual(res["stats"]["line_fallback"], 1)
        self.assertEqual(res["stats"]["verified"], 0)


class HiddenCarrierTests(unittest.TestCase):
    """像素之外的文字载体（2026-11-01 实测泄漏）：元数据、动图后续帧、EXIF 方向。

判据是「输出字节里没有明文」且「其余元数据原样保留」：打码只替换敏感值，
不删用户的作者/描述/色彩配置（2026-11-01 用户定案）。
    """

    def setUp(self):
        tr._known_reset_for_tests()
        self.addCleanup(vr.configure, "", False, "auto")

    def _clean_blocks(self):
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 100.0, 40.0),
                                     text="welcome to the dashboard", score=0.9)])

    def test_png_text_chunk_value_is_replaced_rest_kept(self):
        from PIL import PngImagePlugin
        self._clean_blocks()
        info = PngImagePlugin.PngInfo()
        info.add_text("Comment", "owner " + FAKE_PHONE)
        info.add_text("Software", "some editor 1.0")
        buf = io.BytesIO()
        Image.new("RGB", (400, 100), (255, 255, 255)).save(buf, "PNG", pnginfo=info,
                                                          dpi=(144, 144))
        res = vr.process_image_multimodal(buf.getvalue(), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_REDACTED)
        self.assertNotIn(FAKE_PHONE.encode(), res["bytes"], "PNG 文本块里的号码原样出网")
        self.assertEqual(res["stats"].get("metadata_masked"), 1)
        out = Image.open(io.BytesIO(res["bytes"]))
        self.assertTrue(out.info["Comment"].startswith("owner {{"), out.info.get("Comment"))
        self.assertEqual(out.info.get("Software"), "some editor 1.0", "无害元数据被删")
        self.assertEqual(tuple(round(v) for v in out.info.get("dpi", (0, 0))), (144, 144))
        self.assertEqual(_pixel(res["bytes"], (200, 50)), (255, 255, 255), "像素不该被动")

    def test_jpeg_exif_value_is_replaced_rest_kept(self):
        self._clean_blocks()
        exif = Image.Exif()
        exif[0x010E] = "tel " + FAKE_PHONE
        exif[0x0110] = "CameraX"
        buf = io.BytesIO()
        Image.new("RGB", (400, 100), (255, 255, 255)).save(buf, "JPEG", exif=exif.tobytes())
        res = vr.process_image_multimodal(buf.getvalue(), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_REDACTED)
        self.assertNotIn(FAKE_PHONE.encode(), res["bytes"])
        self.assertEqual(res["format"], "JPEG")
        out = Image.open(io.BytesIO(res["bytes"])).getexif()
        self.assertTrue(str(out.get(0x010E)).startswith("tel {{"), out.get(0x010E))
        self.assertEqual(out.get(0x0110), "CameraX", "相机型号被删")

    def test_harmless_metadata_keeps_zero_touch(self):
        """元数据没命中规则：仍是原字节（不为剥离而剥离）。"""
        from PIL import PngImagePlugin
        self._clean_blocks()
        info = PngImagePlugin.PngInfo()
        info.add_text("Software", "some editor 1.0")
        buf = io.BytesIO()
        Image.new("RGB", (400, 100), (255, 255, 255)).save(buf, "PNG", pnginfo=info)
        res = vr.process_image_multimodal(buf.getvalue(), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_CLEAN)
        self.assertEqual(res["bytes"], buf.getvalue())

    def test_animated_image_is_blocked(self):
        """OCR 只看第一帧：敏感值在第 2 帧时曾被判干净原样上行。"""
        calls = _patch_blocks(self, [])
        # 两帧像素必须不同：PIL 保存 GIF 时会把相同的帧合并成一帧。
        f1 = Image.new("RGB", (200, 60), (255, 255, 255))
        f2 = Image.new("RGB", (200, 60), (0, 0, 0))
        buf = io.BytesIO()
        f1.save(buf, "GIF", save_all=True, append_images=[f2], duration=200)
        self.assertEqual(Image.open(io.BytesIO(buf.getvalue())).n_frames, 2, "构造失败")
        res = vr.process_image_multimodal(buf.getvalue(), SID, tr)
        self.assertEqual((res["mode"], res["reason"]), (vr.MODE_BLOCKED, vr.BLOCK_ANIMATED))
        self.assertEqual(calls, [], "动图不该白跑 OCR")
        self.assertIn(vr.BLOCK_ANIMATED, panel._VISUAL_BLOCK_HINTS, "缺用户提示")

    def test_exif_rotated_photo_boxes_land_on_upright_pixels(self):
        """Orientation=6 的手机照片：OCR 框是摆正后的坐标，涂色也必须画在摆正后的图上。"""
        _patch_blocks(self, [E.Block(quad=(120.0, 30.0, 260.0, 60.0),
                                     text=FAKE_PHONE, score=0.9)])
        _patch_recognize(self, _ok_recognize)
        upright = Image.new("RGB", (400, 100), (255, 255, 255))
        stored = upright.rotate(90, expand=True)          # 存成「躺着」的像素（100x400）
        exif = Image.Exif()
        exif[0x0112] = 6
        buf = io.BytesIO()
        stored.save(buf, "JPEG", exif=exif.tobytes())
        res = vr.process_image_multimodal(buf.getvalue(), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_REDACTED)
        out = Image.open(io.BytesIO(res["bytes"]))
        self.assertEqual(out.size, (400, 100), "输出应是摆正后的方向")
        self.assertIn(out.getexif().get(0x0112), (None, 1), "像素已摆正，方向标签必须是 1 或不带")
        self.assertLess(sum(out.convert("RGB").getpixel((190, 45))), 3 * 160, "号码位置没被涂")


class EngineIntegrationTests(unittest.TestCase):
    """真模型 + 合成图：证明"整条链路能真的把中文号码涂掉"。"""

    def setUp(self):
        tr._known_reset_for_tests()

    def test_cjk_screenshot_is_masked(self):
        img = Image.new("RGB", (1000, 300), (255, 255, 255))
        d = ImageDraw.Draw(img)
        f = _fonts.font(30)
        d.text((40, 80), "手机：" + FAKE_PHONE + " 姓名：张测试", fill=(0, 0, 0), font=f)
        buf = io.BytesIO()
        img.save(buf, "PNG")
        res = vr.process_image_multimodal(buf.getvalue(), "ext:int1", tr)
        self.assertEqual(res["mode"], vr.MODE_REDACTED, res)
        self.assertGreaterEqual(res["hit_count"], 1)
        self.assertGreaterEqual(res["stats"]["verified"], 1, "自校验应当通过")
        # 号码区域（实测真值 x≈130..330, y≈87..117）必须灰；标签区不得被涂。
        # 标签区不能用硬编码白像素断言：(60,100) 在雅黑下是「手」的笔画间隙、
        # 在 CI 的 Noto CJK 下落在笔画上（2026-11-01 CI 实测翻红，本地却绿）。
        # 改为「手机：」条带与原图逐像素一致：实体级打码不碰标签，字体无关。
        self.assertEqual(_pixel(res["bytes"], (200, 100)), vr._FILL)
        orig = Image.open(io.BytesIO(buf.getvalue())).convert("RGB")
        out = Image.open(io.BytesIO(res["bytes"])).convert("RGB")
        self.assertEqual(out.size, orig.size, "输出尺寸不该变")
        label_band = (36, 76, 80, 128)    # 「手」所在左半标签；右缘离号码框留白（最坏 ~85px）有余量
        self.assertEqual(out.crop(label_band).tobytes(), orig.crop(label_band).tobytes(),
                         "标签区被误涂")

    def test_corrupt_image_blocks(self):
        res = vr.process_image_multimodal(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "ext:bad", tr)
        self.assertEqual(res["mode"], vr.MODE_BLOCKED)
        self.assertIn(res["reason"], (vr.BLOCK_DECODE, vr.BLOCK_UNAVAILABLE))


class DataUrlTests(unittest.TestCase):
    def setUp(self):
        tr._known_reset_for_tests()
        self.addCleanup(vr.configure, "", False, "auto")

    def _url(self, raw, mime="image/png"):
        return "data:%s;base64,%s" % (mime, base64.b64encode(raw).decode("ascii"))

    def test_masked(self):
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 200.0, 50.0),
                                     text=FAKE_PHONE, score=0.9)])
        _patch_recognize(self, _ok_recognize)
        out, hits, status = vr.mask_data_url(self._url(_png()), SID, tr)
        self.assertEqual(status, vr.ST_MASKED)
        self.assertGreaterEqual(hits, 1)
        self.assertTrue(out.startswith("data:image/png;base64,"), "MIME 必须保持")
        raw = base64.b64decode(out.split(",", 1)[1])
        self.assertEqual(_pixel(raw, (100, 30)), vr._FILL)

    def test_clean_returns_original_value(self):
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 200.0, 50.0),
                                     text="nothing sensitive", score=0.9)])
        url = self._url(_png())
        out, hits, status = vr.mask_data_url(url, SID, tr)
        self.assertEqual((out, hits, status), (url, 0, vr.ST_CLEAN))

    def test_non_image_is_not_applicable(self):
        out, hits, status = vr.mask_data_url("data:audio/mpeg;base64,AAAA", SID, tr)
        self.assertEqual(status, vr.ST_NOT_APPLICABLE)

    def test_gif_is_blocked_not_passed(self):
        buf = io.BytesIO()
        Image.new("RGB", (40, 40), (255, 255, 255)).save(buf, "GIF")
        out, hits, status = vr.mask_data_url(self._url(buf.getvalue(), "image/gif"), SID, tr)
        self.assertEqual(status, vr.BLOCK_UNSUPPORTED, "动图打不了码就必须阻断")

    def test_too_large_is_blocked(self):
        big = "A" * (vr.MAX_DATA_URL_IMAGE_BYTES * 2)
        out, hits, status = vr.mask_data_url("data:image/png;base64," + big, SID, tr)
        self.assertEqual(status, vr.BLOCK_TOO_LARGE)

    def test_ocr_failure_propagates_as_status(self):
        _patch_blocks(self, [])

        def boom(image_bytes, *, deadline=None, max_tokens=None):
            raise vr._Blocked(vr.BLOCK_TIMEOUT)

        real = vr.detect_blocks
        vr.detect_blocks = boom
        self.addCleanup(setattr, vr, "detect_blocks", real)
        out, hits, status = vr.mask_data_url(self._url(_png()), SID, tr)
        self.assertEqual(status, vr.BLOCK_TIMEOUT)


class HttpBackendTests(unittest.TestCase):
    """HTTP 后端（兼容路径）：坐标来自 `<loc_*>` 标记，必须过覆盖率闸门。"""

    def setUp(self):
        tr._known_reset_for_tests()
        vr.configure(engine="http")
        self.addCleanup(vr.configure, "", False, "auto")
        _patch_env(self, vr.OCR_ENDPOINT_ENV, "http://127.0.0.1:8082/v1/chat/completions")
        self.addCleanup(vr.configure, "", False, "auto")

    def _patch_ocr(self, text=None, reason="", truncated=False):
        original = vr.query_local_ocr

        def fake(image_bytes, timeout=None, max_tokens=None):
            if reason:
                return None, {"reason": reason, "truncated": truncated}
            return text, {"reason": "", "truncated": truncated}

        self.addCleanup(setattr, vr, "query_local_ocr", original)
        vr.query_local_ocr = fake

    def test_loc_tokens_are_masked(self):
        self._patch_ocr("<loc_0><loc_0><loc_500><loc_1000>" + FAKE_PHONE)
        _patch_recognize(self, lambda payload, deadline=None: FAKE_PHONE)
        res = vr.process_image_multimodal(_png((400, 100)), SID, tr)
        self.assertEqual(res["mode"], vr.MODE_REDACTED)
        self.assertEqual(res["stats"]["backend"], "http")

    def test_missing_tags_block(self):
        """只给纯文本、不给标记 → 定位不到 → 阻断（覆盖率闸门）。"""
        self._patch_ocr("手机：" + FAKE_PHONE + "\n姓名：张测试")
        res = vr.process_image_multimodal(_png((400, 100)), SID, tr)
        self.assertEqual((res["mode"], res["reason"]), (vr.MODE_BLOCKED, vr.BLOCK_GEOMETRY))

    def test_truncated_output_blocks(self):
        self._patch_ocr("<loc_0><loc_0><loc_500><loc_1000>" + FAKE_PHONE, truncated=True)
        res = vr.process_image_multimodal(_png((400, 100)), SID, tr)
        self.assertEqual((res["mode"], res["reason"]), (vr.MODE_BLOCKED, vr.BLOCK_TRUNCATED))

    def test_partial_tags_block(self):
        """14 行只标 3 行（实测 gemini 会这样）→ 必须阻断，不能只遮那 3 行。"""
        lines = "<loc_0><loc_0><loc_100><loc_1000>" + FAKE_PHONE + "\n" + "\n".join(
            "row %d 1380013800%d" % (i, i) for i in range(5))
        self._patch_ocr(lines)
        res = vr.process_image_multimodal(_png((400, 200)), SID, tr)
        self.assertEqual((res["mode"], res["reason"]), (vr.MODE_BLOCKED, vr.BLOCK_GEOMETRY))


# ---------------------------------------------------------------------------
# 文档载体
# ---------------------------------------------------------------------------

def _docx(texts=(), images=()):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        body = "".join("<w:p><w:r><w:t>%s</w:t></w:r></w:p>" % t for t in texts)
        z.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body>%s</w:body></w:document>" % body)
        for name, blob in images:
            z.writestr(name, blob)
    return buf.getvalue()


def _assemble_pdf(objs):
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(("%d 0 obj\n" % i).encode() + body + b"\nendobj\n")
    xref = out.tell()
    out.write(("xref\n0 %d\n" % (len(objs) + 1)).encode())
    out.write(b"0000000000 65535 f \n")
    for off in offsets:
        out.write(("%010d 00000 n \n" % off).encode())
    out.write(("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
               % (len(objs) + 1, xref)).encode())
    return out.getvalue()


def _pdf_bytes(pages, size=(595, 842), render_mode=0):
    """手写最小 PDF（文本页），供 PDF 载体测试用。

    `render_mode`：0=填充 1=描边 2=填充+描边 3=不可见 4=裁剪 7=用于路径。
    3 用来测“文本层有字、渲染时看不见”（扫描件 OCR 层、白字等）。
    """
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>"]
    plan, num = [], 3
    for item in pages:
        op = "BT /F1 20 Tf %d Tr 60 %d Td (%s) Tj ET" % (render_mode, size[1] - 120, item)
        content = op.encode("latin-1")
        plan.append((num, content))
        num += 3
    kids = " ".join("%d 0 R" % p[0] for p in plan)
    objs.append(("<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, len(plan))).encode())
    for page_num, content in plan:
        objs.append(("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources "
                     "<< /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>"
                     % (size[0], size[1], page_num + 1, page_num + 2)).encode())
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        objs.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
    return _assemble_pdf(objs)


def _page_text(pdf_bytes, index):
    import pypdfium2 as pdfium
    doc = pdfium.PdfDocument(pdf_bytes)
    try:
        return doc[index].get_textpage().get_text_range(0, 400)
    finally:
        doc.close()


class _ExtClientBase(unittest.TestCase):
    """与 tests/test_ext_bridge.py 同一套隔离手法：临时配置目录 + 独立事件库。"""

    EXT_TOKEN = "visual-test-token"

    def setUp(self):
        tr._known_reset_for_tests()
        self.addCleanup(vr.configure, "", False, "auto")
        self.tmp = Path(tempfile.mkdtemp(prefix="maskit-visual-"))
        self.addCleanup(self._cleanup_tmp)
        self._saved = {
            "config_path": panel.CONFIG_PATH,
            "data_root": tr._DATA_ROOT,
            "db_path": event_store.DB_PATH,
            "origin_check": panel._origin_check_enabled,
            "remote": panel.REMOTE_MODE,
        }
        panel.CONFIG_PATH = self.tmp / "config.json"
        tr._DATA_ROOT = self.tmp
        event_store.DB_PATH = self.tmp / "shield-events.sqlite3"
        event_store._reset_writer()
        panel._origin_check_enabled = True
        panel.REMOTE_MODE = False
        self.client = panel.app.test_client()
        tr.sessions.clear()
        panel._EXT_STATS.update({"mask": 0, "restore": 0})
        panel._EXT_LAST_SWEEP = 0.0
        self.addCleanup(self._teardown_state)
        self._save_cfg({"ext_bridge_enabled": True, "ext_token": self.EXT_TOKEN})

    def _teardown_state(self):
        try:
            event_store.flush_event_queue()
        except Exception:
            pass
        panel.CONFIG_PATH = self._saved["config_path"]
        tr._DATA_ROOT = self._saved["data_root"]
        event_store.DB_PATH = self._saved["db_path"]
        event_store._reset_writer()
        panel._origin_check_enabled = self._saved["origin_check"]
        panel.REMOTE_MODE = self._saved["remote"]
        tr.sessions.clear()

    def _cleanup_tmp(self):
        for p in sorted(self.tmp.glob("**/*"), reverse=True):
            try:
                p.unlink()
            except Exception:
                pass
        try:
            self.tmp.rmdir()
        except Exception:
            pass

    def _save_cfg(self, patch):
        cfg = panel.default_config()
        if panel.CONFIG_PATH.exists():
            try:
                cfg.update(json.loads(panel.CONFIG_PATH.read_text(encoding="utf-8")))
            except Exception:
                pass
        cfg.update(patch)
        panel.save_config(cfg)
        return cfg

    def _post(self, path, payload, token=None):
        headers = {"X-Shield-Token": self.EXT_TOKEN if token is None else token}
        return self.client.post(path, json=payload, headers=headers)


class EndpointTests(_ExtClientBase):
    def test_switch_off_returns_passthrough_without_blocking(self):
        calls = _patch_blocks(self, [])
        res = self._post("/api/ext/mask-image",
                         {"base64": base64.b64encode(_png()).decode("ascii"), "sid": SID})
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertEqual(body["mode"], "passthrough")
        self.assertEqual(body["hit_count"], 0)
        self.assertEqual(body["base64"], "", "passthrough 不该把原图回传一份")
        self.assertEqual(calls, [], "开关关着时连 OCR 都不该调")

    def test_requires_token(self):
        res = self._post("/api/ext/mask-image", {"base64": "AAAA"}, token="wrong")
        self.assertEqual(res.status_code, 403)

    def test_blocked_returns_503_with_reason_and_hint(self):
        self._save_cfg({"multimodal_vision": True})

        def boom(image_bytes, *, deadline=None, max_tokens=None):
            raise vr._Blocked(vr.BLOCK_TIMEOUT)

        real = vr.detect_blocks
        vr.detect_blocks = boom
        self.addCleanup(setattr, vr, "detect_blocks", real)
        res = self._post("/api/ext/mask-image",
                         {"base64": base64.b64encode(_png()).decode("ascii"), "sid": SID})
        self.assertEqual(res.status_code, 503)
        body = res.get_json()
        self.assertTrue(body["blocking"])
        self.assertEqual(body["error"], vr.BLOCK_TIMEOUT)
        self.assertTrue(body.get("hint"))

    def test_masked_image_endpoint(self):
        self._save_cfg({"multimodal_vision": True})
        _patch_blocks(self, [E.Block(quad=(50.0, 20.0, 250.0, 70.0),
                                     text=FAKE_PHONE, score=0.9)])
        _patch_recognize(self, _ok_recognize)
        res = self._post("/api/ext/mask-image",
                         {"base64": base64.b64encode(_png((400, 100))).decode("ascii"),
                          "sid": SID})
        body = res.get_json()
        self.assertEqual(res.status_code, 200, body)
        self.assertEqual(body["mode"], vr.MODE_REDACTED)
        self.assertEqual(body["vision"]["verified"], 1)
        self.assertEqual(_pixel(base64.b64decode(body["base64"]), (150, 45)), vr._FILL)

    def test_oversized_payload_is_attributed(self):
        self._save_cfg({"multimodal_vision": True})
        big = "A" * (panel._EXT_MAX_BODY + 1024)
        res = self._post("/api/ext/mask-image", {"base64": big, "sid": SID})
        self.assertEqual(res.status_code, 413)
        body = res.get_json()
        self.assertTrue(body["blocking"])
        self.assertTrue(body.get("reason_codes"))

    def test_ping_reports_capability(self):
        """`multimodal` = 开关；`vision_ready` = 真的能脱敏（扩展只认后者）。"""
        headers = {"X-Shield-Token": self.EXT_TOKEN}
        body = self.client.get("/api/ext/ping", headers=headers).get_json()
        self.assertFalse(body["multimodal"])
        self.assertFalse(body["vision_ready"])
        self._save_cfg({"multimodal_vision": True})
        body2 = self.client.get("/api/ext/ping", headers=headers).get_json()
        self.assertTrue(body2["multimodal"])
        # 本机装了 OCR 运行时 → 就绪；没装则 False（两种情况都不允许"开关开着就发图"）
        self.assertEqual(body2["vision_ready"], bool(vr.available()[0]))


class DocxEmbeddedTests(_ExtClientBase):
    def test_embedded_image_masked_and_counted(self):
        self._save_cfg({"multimodal_vision": True})
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 90.0, 60.0),
                                     text=FAKE_PHONE, score=0.9)])
        _patch_recognize(self, _ok_recognize)
        docx = _docx(texts=["hello"], images=[("word/media/image1.png", _png((100, 100)))])
        res = self._post("/api/ext/mask-file", {
            "filename": "report.docx",
            "base64": base64.b64encode(docx).decode("ascii"), "sid": SID})
        body = res.get_json()
        self.assertEqual(res.status_code, 200, body)
        self.assertGreaterEqual(body["hit_count"], 1)
        self.assertEqual(body["visual"]["scanned"], 1)
        out = base64.b64decode(body["base64"])
        with zipfile.ZipFile(io.BytesIO(out)) as z:
            media = z.read("word/media/image1.png")
        self.assertEqual(_pixel(media, (50, 35)), vr._FILL)

    def test_embedded_blocked_when_scan_fails(self):
        self._save_cfg({"multimodal_vision": True})

        def boom(image_bytes, *, deadline=None, max_tokens=None):
            raise vr._Blocked(vr.BLOCK_UNAVAILABLE)

        real = vr.detect_blocks
        vr.detect_blocks = boom
        self.addCleanup(setattr, vr, "detect_blocks", real)
        docx = _docx(texts=["x"], images=[("word/media/image1.png", _png((100, 100)))])
        res = self._post("/api/ext/mask-file", {
            "filename": "report.docx",
            "base64": base64.b64encode(docx).decode("ascii"), "sid": SID})
        self.assertEqual(res.status_code, 503)
        self.assertTrue(res.get_json()["blocking"])

    def test_switch_off_does_not_call_ocr(self):
        calls = _patch_blocks(self, [])
        docx = _docx(texts=["x"], images=[("word/media/image1.png", _png((100, 100)))])
        res = self._post("/api/ext/mask-file", {
            "filename": "report.docx",
            "base64": base64.b64encode(docx).decode("ascii"), "sid": SID})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(calls, [], "开关关着时不该调 OCR")


class PdfTests(_ExtClientBase):
    def _patch_pages(self, blocks_per_page):
        """PDF 逐页扫：每页给一组假 Block（按调用顺序取）。"""
        queue = list(blocks_per_page)
        calls = []

        def fake(image_bytes, *, deadline=None, max_tokens=None):
            calls.append(max_tokens)
            blocks = queue.pop(0) if queue else ()
            return tuple(blocks), {"backend": "fake", "orientation": 0, "ms": 0.0,
                                   "downscaled": False, "low_conf": 0}

        self.addCleanup(setattr, vr, "detect_blocks", vr.detect_blocks)
        vr.detect_blocks = fake
        return calls

    def test_clean_pdf_is_returned_byte_identical(self):
        self._save_cfg({"multimodal_vision": True})
        self._patch_pages([(), ()])
        raw = _pdf_bytes(["page one", "page two"])
        out, hits, status = pdf_redactor.mask_pdf_bytes(raw, SID, tr)
        self.assertEqual((status, hits), (pdf_redactor.ST_CLEAN, 0))
        self.assertEqual(out, raw)

    def _with_hidden(self, kind):
        """在干净 PDF 上加一个「页面之外」的载体，里面放号码。"""
        import pypdf
        import pypdf.annotations
        from pypdf.generic import (ArrayObject, DictionaryObject, FloatObject, NameObject,
                                   TextStringObject)
        w = pypdf.PdfWriter(clone_from=pypdf.PdfReader(io.BytesIO(_pdf_bytes(["clean page"]))))
        if kind == "info":
            w.add_metadata({"/Author": "tel " + FAKE_PHONE})
        elif kind == "annot":
            w.add_annotation(0, pypdf.annotations.Text(rect=(50, 50, 80, 80),
                                                       text="call " + FAKE_PHONE))
        elif kind == "attach":
            w.add_attachment("contacts.txt", ("tel " + FAKE_PHONE).encode())
        elif kind == "outline":
            w.add_outline_item("tel " + FAKE_PHONE, 0)
        elif kind == "form":
            field = DictionaryObject({
                NameObject("/FT"): NameObject("/Tx"), NameObject("/T"): TextStringObject("p"),
                NameObject("/V"): TextStringObject(FAKE_PHONE),
                NameObject("/Type"): NameObject("/Annot"),
                NameObject("/Subtype"): NameObject("/Widget"),
                NameObject("/Rect"): ArrayObject([FloatObject(10), FloatObject(10),
                                                  FloatObject(200), FloatObject(30)])})
            ref = w._add_object(field)
            w.pages[0][NameObject("/Annots")] = ArrayObject([ref])
            w._root_object[NameObject("/AcroForm")] = DictionaryObject(
                {NameObject("/Fields"): ArrayObject([ref])})
        buf = io.BytesIO()
        w.write(buf)
        raw = buf.getvalue()
        self.assertIn(FAKE_PHONE.encode(), raw, "构造失败：号码不在输入里")
        return raw

    @staticmethod
    def _hidden_value(out, kind):
        """从输出里取回该载体的文字：用来证明「载体还在、只是值被换了」。"""
        import pypdf
        rd = pypdf.PdfReader(io.BytesIO(out))
        if kind == "info":
            return str(rd.metadata.get("/Author"))
        if kind == "annot":
            return " ".join(str(a.get_object().get("/Contents"))
                            for a in rd.pages[0].get("/Annots") or [])
        if kind == "attach":
            return rd.attachments["contacts.txt"][0].decode("utf-8")
        if kind == "outline":
            return rd.outline[0].title
        if kind == "form":
            return str(rd.get_fields()["p"].get("/V"))
        raise AssertionError(kind)

    def test_hidden_carriers_keep_structure_and_replace_value(self):
        """注释/表单值/附件/书签/文档信息：曾在「干净」判定下原字节上行。

        修法是只替换命中值（可还原的占位符），载体本身与其余内容保留——用户之后还要读
        作者、注释、附件（2026-11-01 定案）。
        """
        self._save_cfg({"multimodal_vision": True})
        for kind in ("info", "annot", "attach", "outline", "form"):
            with self.subTest(kind=kind):
                self._patch_pages([()])
                out, hits, status = pdf_redactor.mask_pdf_bytes(self._with_hidden(kind), SID, tr)
                self.assertEqual(status, pdf_redactor.ST_MASKED)
                self.assertGreaterEqual(hits, 1)
                self.assertNotIn(FAKE_PHONE.encode(), out)
                self.assertIn("clean page", _page_text(out, 0), "干净页仍应保留矢量文本")
                value = self._hidden_value(out, kind)
                self.assertIn("{{", value, "%s 载体被删或没替换：%r" % (kind, value))

    def test_binary_attachment_is_passed_through_and_counted(self):
        """扫不了的二进制附件：按定案放行（原样保留），但必须计数，不静默。"""
        import pypdf
        self._save_cfg({"multimodal_vision": True})
        self._patch_pages([()])
        w = pypdf.PdfWriter(clone_from=pypdf.PdfReader(io.BytesIO(_pdf_bytes(["clean page"]))))
        blob = b"PK\x03\x04" + bytes(range(256)) * 4
        w.add_attachment("data.zip", blob)
        buf = io.BytesIO()
        w.write(buf)
        out, hits, status = pdf_redactor.mask_pdf_bytes(buf.getvalue(), SID, tr)
        self.assertEqual((status, hits), (pdf_redactor.ST_CLEAN, 0))
        self.assertEqual(out, buf.getvalue(), "没命中就应零触碰")
        self.assertEqual(pdf_redactor.last_stats().get("attachments_unscanned"), 1)

    def test_masked_page_keeps_links_and_metadata(self):
        """命中页栅格化时保留页对象：超链接还在；文档信息只替换命中值。"""
        self._save_cfg({"multimodal_vision": True})
        _patch_recognize(self, _ok_recognize)
        import pypdf
        import pypdf.annotations
        w = pypdf.PdfWriter(clone_from=pypdf.PdfReader(io.BytesIO(
            _pdf_bytes(["phone " + FAKE_PHONE]))))
        w.add_metadata({"/Subject": "tel " + FAKE_PHONE, "/Title": "report"})
        w.add_annotation(0, pypdf.annotations.Link(rect=(10, 10, 60, 30),
                                                   url="https://example.invalid/doc"))
        buf = io.BytesIO()
        w.write(buf)
        self._patch_pages([[E.Block(quad=(60.0, 700.0, 400.0, 730.0), text=FAKE_PHONE, score=0.9)]])
        out, _hits, status = pdf_redactor.mask_pdf_bytes(buf.getvalue(), SID, tr)
        self.assertEqual(status, pdf_redactor.ST_MASKED)
        self.assertNotIn(FAKE_PHONE.encode(), out)
        self.assertEqual(_page_text(out, 0), "", "命中页文本层必须清掉")
        rd = pypdf.PdfReader(io.BytesIO(out))
        self.assertEqual(str(rd.metadata.get("/Title")), "report")
        self.assertTrue(str(rd.metadata.get("/Subject")).startswith("tel {{"))
        uris = [str(a.get_object()["/A"]["/URI"]) for a in rd.pages[0].get("/Annots") or []]
        self.assertEqual(uris, ["https://example.invalid/doc"], "命中页上的超链接被删")

    def test_only_pii_page_is_rasterised(self):
        self._save_cfg({"multimodal_vision": True})
        _patch_recognize(self, _ok_recognize)
        self._patch_pages([(), [E.Block(quad=(60.0, 700.0, 400.0, 730.0),
                                        text=FAKE_PHONE, score=0.9)]])
        raw = _pdf_bytes(["clean page", "phone " + FAKE_PHONE])
        out, hits, status = pdf_redactor.mask_pdf_bytes(raw, SID, tr)
        self.assertEqual(status, pdf_redactor.ST_MASKED)
        self.assertGreaterEqual(hits, 1)
        self.assertIn("clean page", _page_text(out, 0), "干净页丢了矢量文本")
        self.assertEqual(_page_text(out, 1), "", "含 PII 的页必须已栅格化")

    def test_pdf_page_ocr_budget_is_larger(self):
        self._save_cfg({"multimodal_vision": True})
        calls = self._patch_pages([(), ()])
        raw = _pdf_bytes(["a", "b"])
        pdf_redactor.mask_pdf_bytes(raw, SID, tr)
        self.assertTrue(calls)
        self.assertEqual(calls[0], pdf_redactor.PAGE_OCR_MAX_TOKENS)

    def test_pdf_blocked_when_scan_fails(self):
        self._save_cfg({"multimodal_vision": True})

        def boom(image_bytes, *, deadline=None, max_tokens=None):
            raise vr._Blocked(vr.BLOCK_UNAVAILABLE)

        real = vr.detect_blocks
        vr.detect_blocks = boom
        self.addCleanup(setattr, vr, "detect_blocks", real)
        out, hits, status = pdf_redactor.mask_pdf_bytes(_pdf_bytes(["a"]), SID, tr)
        self.assertEqual(status, vr.BLOCK_UNAVAILABLE)

    def test_text_layer_invisible_pii_is_masked(self):
        """渲染模式 3（不可见）的文本层：OCR 读不到，上游能抽取。必须扫文本层。"""
        self._save_cfg({"multimodal_vision": True})
        _patch_recognize(self, _ok_recognize)
        self._patch_pages([()])
        raw = _pdf_bytes(["phone " + FAKE_PHONE + " hidden"], render_mode=3)
        out, hits, status = pdf_redactor.mask_pdf_bytes(raw, SID, tr)
        self.assertEqual(status, pdf_redactor.ST_MASKED)
        self.assertGreaterEqual(hits, 1)
        text = _page_text(out, 0)
        self.assertNotIn(FAKE_PHONE, text, "文本层不能有明文号码")

    def test_pdf_by_magic_without_extension(self):
        self._save_cfg({"multimodal_vision": True})
        _patch_recognize(self, _ok_recognize)
        self._patch_pages([[E.Block(quad=(60.0, 700.0, 400.0, 730.0),
                                    text=FAKE_PHONE, score=0.9)]])
        raw = _pdf_bytes(["phone " + FAKE_PHONE])
        res = self._post("/api/ext/mask-file", {
            "filename": "attachment.bin",
            "base64": base64.b64encode(raw).decode("ascii"), "sid": SID})
        body = res.get_json()
        self.assertEqual(res.status_code, 200, body)
        self.assertGreaterEqual(body["hit_count"], 1)


class ProxyPathTests(unittest.TestCase):
    """代理链路（`transparent._mask_tree`）：截图 data URL 的主要入口。"""

    def setUp(self):
        tr._known_reset_for_tests()
        self._saved = tr.VISION_OCR_ENABLED
        tr.VISION_OCR_ENABLED = True
        self.addCleanup(setattr, tr, "VISION_OCR_ENABLED", self._saved)
        self.addCleanup(vr.configure, "", False, "auto")
        self.url = "data:image/png;base64," + base64.b64encode(_png((200, 60))).decode("ascii")
        self.body = {"messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": self.url}}]}]}

    def _leaf(self, body):
        return body["messages"][0]["content"][0]["image_url"]["url"]

    def test_nested_image_url_is_masked(self):
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 120.0, 50.0),
                                     text=FAKE_PHONE, score=0.9)])
        _patch_recognize(self, _ok_recognize)
        flag = [False]
        out = tr._mask_tree(self.body, "ext:p1", flag=flag)
        self.assertNotEqual(self._leaf(out), self.url)
        self.assertTrue(self._leaf(out).startswith("data:image/png;base64,"))
        self.assertTrue(flag[0], "树变了却没置脏标记 → 请求体不会回写")
        self.assertEqual(tr._take_vision_masks("ext:p1"), (1, 1, 0))

    def test_clean_image_untouched(self):
        _patch_blocks(self, [E.Block(quad=(10.0, 10.0, 120.0, 50.0),
                                     text="dashboard", score=0.9)])
        out = tr._mask_tree(self.body, "ext:p2")
        self.assertEqual(self._leaf(out), self.url)

    def test_scan_failure_raises_for_fail_closed(self):
        def boom(image_bytes, *, deadline=None, max_tokens=None):
            raise vr._Blocked(vr.BLOCK_TIMEOUT)

        real = vr.detect_blocks
        vr.detect_blocks = boom
        self.addCleanup(setattr, vr, "detect_blocks", real)
        with self.assertRaises(tr._VisionBlocked) as ctx:
            tr._mask_tree(self.body, "ext:p3")
        self.assertEqual(ctx.exception.reason, vr.BLOCK_TIMEOUT)

    def test_switch_off_keeps_legacy_exemption(self):
        tr.VISION_OCR_ENABLED = False
        calls = _patch_blocks(self, [])
        out = tr._mask_tree(self.body, "ext:p4")
        self.assertEqual(self._leaf(out), self.url)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
