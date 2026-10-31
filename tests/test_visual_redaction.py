"""视觉多模态脱敏与嵌入图片穿透专项单元测试套件"""

import io
import json
import base64
import zipfile
import pytest
from PIL import Image

import panel
import transparent as tr
import visual_redactor
from panel import mask_ooxml_bytes, app

@pytest.fixture(autouse=True)
def setup_teardown():
    tr._known_reset_for_tests()
    yield

def test_analyze_image_intent():
    # 1. 审美改样式意图
    assert visual_redactor.analyze_image_intent("帮我看看这个界面的布局样式好看吗？") == "UI_VISUAL_REDACT"
    assert visual_redactor.analyze_image_intent("这个按钮的 margin 和 padding 怎么调") == "UI_VISUAL_REDACT"

    # 2. 数据提取意图
    assert visual_redactor.analyze_image_intent("把图里的表格和数据提取出来") == "DOC_EXTRACT"
    assert visual_redactor.analyze_image_intent("OCR 识别这段代码") == "DOC_EXTRACT"

    # 3. 视觉直方图快筛 (纯白底色 -> DOC_EXTRACT)
    img = Image.new('RGB', (400, 200), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    assert visual_redactor.analyze_image_intent("", buf.getvalue()) == "DOC_EXTRACT"

def test_visual_mask_generation():
    img = Image.new('RGB', (200, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    raw_bytes = buf.getvalue()

    masked_bytes = visual_redactor.apply_visual_mask(raw_bytes, "<loc_100><loc_100><loc_200><loc_200>")
    assert len(masked_bytes) > 0
    assert masked_bytes != raw_bytes

def test_ooxml_embedded_image_penetration(monkeypatch):
    """测试带有 media/image1.png 敏感图片的 Word 文档是否能被深度穿透脱敏"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        # 正文包含敏感手机号
        z.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Contact: 13800138000</w:t></w:r></w:p></w:body></w:document>')
        # 嵌图媒体
        img = Image.new('RGB', (100, 100), color=(255, 255, 255))
        img_buf = io.BytesIO()
        img.save(img_buf, format='PNG')
        z.writestr("word/media/image1.png", img_buf.getvalue())
    raw_docx = buf.getvalue()

    sid = "ext:test_visual_docx"
    tr._new_session(sid)

    def mock_query_local_ocr(b):
        return "Employee Phone: 13812345678"
    monkeypatch.setattr(visual_redactor, "query_local_ocr", mock_query_local_ocr)

    masked_docx, hits = mask_ooxml_bytes(raw_docx, "test.docx", sid, tr)
    print(f"DEBUG: mask_ooxml_bytes returned hits={hits}")
    assert hits >= 2
    assert len(masked_docx) > 0


def test_api_ext_mask_image(monkeypatch):
    """测试 /api/ext/mask-image 接口"""
    client = app.test_client()

    img = Image.new('RGB', (100, 100), color=(255, 255, 255))
    img_buf = io.BytesIO()
    img.save(img_buf, format='PNG')
    b64_img = base64.b64encode(img_buf.getvalue()).decode('ascii')

    def mock_query_local_ocr(b):
        return "Important ID: 110101199003074514"
    monkeypatch.setattr(visual_redactor, "query_local_ocr", mock_query_local_ocr)

    # 启用扩展桥接开关
    panel._ext_cfg_state["ext_bridge_enabled"] = True
    token = panel._ext_cfg_state.get("ext_token") or "test_token"
    panel._ext_cfg_state["ext_token"] = token

    resp = client.post("/api/ext/mask-image",
                       headers={"X-Shield-Token": token},
                       json={
                           "base64": b64_img,
                           "prompt": "提取表格里的身份证",
                           "sid": "ext:test_api_img"
                       })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["mode"] == "TEXT_ONLY"
    assert "110101199003074514" not in data["content"]
    assert "IDCARD_" in data["content"]

