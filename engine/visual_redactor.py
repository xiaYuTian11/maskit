"""多模态视觉脱敏与内嵌图片深度清洗引擎 (Visual Redactor)

功能特性:
1. 前置轻量意图与视觉快筛 (0-3ms，无需模型):
   - DOC_EXTRACT: 数据/代码提取类，OCR 结构化后原图销毁，转为 Markdown 安全文本。
   - UI_VISUAL_REDACT: 界面/排版审美类，保留布局，局部对敏感文字物理遮罩打码。
2. 桥接本地独显加速的 OCR 服务 (127.0.0.1:8082 Xiaomi-OCR-0)。
3. Office 复合文档 (Word / PPT / Excel / PDF) 深度穿透:
   - 提取嵌入媒体 (media/image.png) 并安全遮蔽，重新封包回写，彻底消灭文档内嵌图泄密死角。
4. 工业级高可用容灾 (Fail-Open / Graceful Fallback):
   - 若 OCR 服务未启动或超时，平滑降级，绝不卡死主网关流程。
"""

import os
import io
import re
import json
import time
import base64
import urllib.request
from typing import Tuple, Dict, Any, Optional
from PIL import Image, ImageDraw

# OCR 服务默认端口与配置
_OCR_ENDPOINT = os.environ.get("MASKIT_OCR_ENDPOINT", "http://127.0.0.1:8082/v1/chat/completions")
_OCR_TIMEOUT_S = 10.0

# 界面与排版审美类意图词
_UI_STYLE_KEYWORDS = {
    '样式', '布局', 'css', 'ui', 'ux', '好看', '审美', '设计', '美化', '排版',
    '颜色', '对齐', '边距', 'padding', 'margin', '按钮', '前端'
}

# 数据提取类意图词
_DATA_EXTRACT_KEYWORDS = {
    '提取', '识别', 'ocr', '表格', '数据', '文本', '发票', '代码', '复制',
    '转文字', 'sql', '字段', '整理'
}


def analyze_image_intent(prompt: str, image_bytes: Optional[bytes] = None) -> str:
    """分析用户是想要审美改样式 (UI_VISUAL_REDACT)，还是数据/代码提取 (DOC_EXTRACT)。耗时 < 3ms"""
    p_lower = (prompt or "").lower()
    has_ui = any(k in p_lower for k in _UI_STYLE_KEYWORDS)
    has_data = any(k in p_lower for k in _DATA_EXTRACT_KEYWORDS)

    if has_ui and not has_data:
        return 'UI_VISUAL_REDACT'
    if has_data and not has_ui:
        return 'DOC_EXTRACT'

    # 无 Prompt 或意图模糊时，通过轻量视觉直方图判断
    if image_bytes:
        try:
            img = Image.open(io.BytesIO(image_bytes))
            gray = img.convert('L')
            hist = gray.histogram()
            # 纯白背景占比高一般是文档/表格/代码
            white_ratio = sum(hist[240:]) / max(1, sum(hist))
            w, h = img.size
            aspect_ratio = h / max(1, w)
            if white_ratio > 0.70:
                return 'DOC_EXTRACT'
            if aspect_ratio > 1.8 or white_ratio < 0.40:
                return 'UI_VISUAL_REDACT'
        except Exception:
            pass

    return 'DOC_EXTRACT'


def query_local_ocr(image_bytes: bytes) -> Optional[str]:
    """调用本地独显加速的 Xiaomi-OCR-0 服务，带超时与容灾"""
    try:
        b64 = base64.b64encode(image_bytes).decode('ascii')
        payload = {
            'model': 'xiaomi-ocr-0',
            'messages': [{
                'role': 'user',
                'content': [
                    {'type': 'text', 'text': 'Parse this image accurately and output text and layout.'},
                    {'type': 'image_url', 'image_url': {'url': f'data:image/png;base64,{b64}'}}
                ]
            }],
            'temperature': 0.1,
            'max_tokens': 1024
        }
        req = urllib.request.Request(
            _OCR_ENDPOINT,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=_OCR_TIMEOUT_S) as r:
            res = json.loads(r.read().decode('utf-8'))
            return res['choices'][0]['message']['content']
    except Exception:
        # Fail-Open 降级
        return None


def apply_visual_mask(image_bytes: bytes, ocr_text: str) -> bytes:
    """在图片上将敏感文字区域进行物理局部遮蔽 (打码)，保留其余界面的排版与样式"""
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        draw = ImageDraw.Draw(img)
        w, h = img.size

        # 匹配 <loc_y1><loc_x1><loc_y2><loc_x2>
        loc_pattern = r'<loc_(\d+)><loc_(\d+)><loc_(\d+)><loc_(\d+)>'
        matches = list(re.finditer(loc_pattern, ocr_text or ""))
        if matches:
            for m in matches:
                y1, x1, y2, x2 = [int(v) for v in m.groups()]
                px1, py1 = int(x1 * w / 1000), int(y1 * h / 1000)
                px2, py2 = int(x2 * w / 1000), int(y2 * h / 1000)
                draw.rectangle([px1, py1, px2, py2], fill=(220, 220, 220), outline=(180, 180, 180))
        else:
            # 文本区局部遮盖保底
            draw.rectangle([int(w * 0.1), int(h * 0.35), int(w * 0.85), int(h * 0.85)],
                           fill=(235, 235, 235), outline=(200, 200, 200))
            draw.text((int(w * 0.15), int(h * 0.5)), '[MASKIT PROTECTED]', fill=(120, 120, 120))

        out_buf = io.BytesIO()
        img.save(out_buf, format='PNG')
        return out_buf.getvalue()
    except Exception:
        return image_bytes


def process_image_multimodal(image_bytes: bytes, prompt: str, sid: str, tr) -> Dict[str, Any]:
    """主分流入口: 处理独立上传/发送的图片"""
    intent = analyze_image_intent(prompt, image_bytes)
    ocr_res = query_local_ocr(image_bytes)

    if not ocr_res:
        # OCR 挂了或未开启：优雅降级，直接返回原始图片，不卡死主链路
        return {"mode": "PASSTHROUGH", "bytes": image_bytes, "hit_count": 0}

    # 检查 OCR 提取的文本是否含有敏感词
    masked_text = tr.mask_body(ocr_res, sid)
    has_sensitive = (masked_text != ocr_res)

    if intent == 'DOC_EXTRACT':
        # 只要提取数据：彻底销毁原图，返回脱敏后的 Markdown 文本
        return {
            "mode": "TEXT_ONLY",
            "content": f"\n\n[Maskit: 已将图片解析为安全脱敏文档]\n{masked_text}",
            "hit_count": 1 if has_sensitive else 0
        }
    else:
        # UI 审美：如果含敏感信息则打码，否则直接原图
        if has_sensitive:
            redacted_bytes = apply_visual_mask(image_bytes, ocr_res)
            return {"mode": "REDACTED_IMAGE", "bytes": redacted_bytes, "hit_count": 1}
        return {"mode": "CLEAN_IMAGE", "bytes": image_bytes, "hit_count": 0}


def mask_embedded_image_bytes(image_bytes: bytes, sid: str, tr) -> Tuple[bytes, int]:
    """专门用于 Word / PPT / Excel 内部嵌入图片 (media/) 的穿透脱敏"""
    ocr_res = query_local_ocr(image_bytes)
    if not ocr_res:
        return image_bytes, 0

    masked_text = tr.mask_body(ocr_res, sid)
    if masked_text != ocr_res:
        # 内部图片包含敏感信息，打码后写回文档
        masked_img = apply_visual_mask(image_bytes, ocr_res)
        return masked_img, 1
    return image_bytes, 0
