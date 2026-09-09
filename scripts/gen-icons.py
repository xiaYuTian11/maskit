# -*- coding: utf-8 -*-
"""生成 Data Maskit 品牌图标——复刻官网 Logo（渐变盾牌 + 脱敏遮挡条）。

用户明确要求：软件图标用官网上那个（靛蓝紫青渐变 #818cf8→#a78bfa→#22d3ee
盾牌 + 两条深色遮挡横条，语义=脱敏）。透明背景，Windows 各尺寸通用。

输出（覆盖式，可反复重跑）：
  src-tauri/icons/*.png（icon 512 / 128 / 32 / Square 系列 / StoreLogo）
  src-tauri/icons/icon.ico（16-256 多尺寸，Tauri 壳 + 安装器 + 快捷方式）
  shield.ico（PyInstaller 引擎 exe）
"""
import os
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICONS_DIR = os.path.join(ROOT, "src-tauri", "icons")

# ---- 官网 Logo 同款配色 ----
G1 = (129, 140, 248)    # #818cf8 顶部
G2 = (167, 139, 250)    # #a78bfa 中部
G3 = (34, 211, 238)     # #22d3ee 底部
BAR_COLOR = (10, 15, 30)  # #0a0f1e 遮挡条


def _bezier(p0, p1, p2, n=24):
    """二次贝塞尔采样。"""
    pts = []
    for i in range(n + 1):
        t = i / n
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]
        pts.append((x, y))
    return pts


def shield_path(scale, cx=24.0, cy=24.0):
    """官网 Logo 外盾路径（48 视口）采样为多边形，scale 缩放到目标尺寸。

    d="M24 3.5 41 9.5v12.2c0 10.6-6.9 19.4-17 23.8-10.1-4.4-17-13.2-17-23.8V9.5L24 3.5Z"
    """
    def P(x, y):
        return ((x - cx) * scale + cx * scale, (y - cy) * scale + cy * scale)

    pts = [P(24, 3.5), P(41, 9.5), P(41, 21.7)]
    # 右弧：c0 10.6-6.9 19.4-17 23.8（近似两段二阶）
    pts += _bezier(P(41, 21.7), P(37.5, 33.0), P(24, 45.5), 22)[1:]
    # 左弧：-10.1-4.4-17-13.2-17-23.8
    pts += _bezier(P(24, 45.5), P(10.5, 33.0), P(7, 21.7), 22)[1:]
    pts.append(P(7, 9.5))
    return pts


def draw_bars(img, scale):
    """两条深色遮挡横条（48 视口：rect x13 y18.5 w22 h4 rx2 / x13 y26 w14 h4 rx2）。"""
    d = ImageDraw.Draw(img)
    r = max(1, int(2 * scale))
    # 上横条
    x0, y0, w, h = 13 * scale, 18.5 * scale, 22 * scale, 4 * scale
    d.rounded_rectangle([x0, y0, x0 + w, y0 + h], radius=r, fill=BAR_COLOR + (224,))
    # 下横条
    x0, y0, w, h = 13 * scale, 26 * scale, 14 * scale, 4 * scale
    d.rounded_rectangle([x0, y0, x0 + w, y0 + h], radius=r, fill=BAR_COLOR + (224,))


def draw_icon(S):
    """S×S 画布：透明背景 + 渐变盾牌 + 两条深色遮挡条（官网 Logo 同款）。"""
    scale = S / 48.0
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # 1) 盾牌 mask + 垂直渐变（#818cf8 → #a78bfa → #22d3ee）
    outer = shield_path(scale)
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).polygon(outer, fill=255)
    grad = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grad)
    for y in range(S):
        t = y / S
        if t < 0.5:
            k = t / 0.5
            c = tuple(int(G1[i] + (G2[i] - G1[i]) * k) for i in range(3))
        else:
            k = (t - 0.5) / 0.5
            c = tuple(int(G2[i] + (G3[i] - G2[i]) * k) for i in range(3))
        gd.line([(0, y), (S, y)], fill=c + (255,))
    img.paste(grad, (0, 0), mask)

    # 2) 两条遮挡横条
    draw_bars(img, scale)
    return img


def main():
    master = draw_icon(1024)
    os.makedirs(ICONS_DIR, exist_ok=True)

    def save_png(img, path, size=None):
        im = img.resize((size, size), Image.LANCZOS) if size else img
        im.save(path, "PNG")
        print(f"  {os.path.relpath(path, ROOT)} ({im.size[0]}x{im.size[1]})")

    save_png(master, os.path.join(ICONS_DIR, "icon.png"), 512)
    save_png(master, os.path.join(ICONS_DIR, "128x128.png"), 128)
    save_png(master, os.path.join(ICONS_DIR, "32x32.png"), 32)
    for size in [30, 44, 50, 71, 89, 107, 142, 150, 284, 310]:
        name = "StoreLogo.png" if size == 50 else f"Square{size}x{size}Logo.png"
        save_png(master, os.path.join(ICONS_DIR, name), size)

    def save_ico(path):
        frames = [master.resize((s, s), Image.LANCZOS) for s in [16, 24, 32, 48, 64, 128, 256]]
        frames[0].save(path, "ICO", sizes=[(f.width, f.height) for f in frames], append_images=frames[1:])
        print(f"  {os.path.relpath(path, ROOT)} (ico 多尺寸)")

    save_ico(os.path.join(ICONS_DIR, "icon.ico"))
    save_ico(os.path.join(ROOT, "shield.ico"))
    print("完成 ✅")


if __name__ == "__main__":
    main()
