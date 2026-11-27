# -*- coding: utf-8 -*-
"""生成应用图标 assets/app.ico（纯标准库：手绘像素 + PNG/ICO 编码）

图案：靛蓝→青色的圆角方块 + 白色雷达同心圆 + 扫描扇形 + 目标光点
"""
from __future__ import annotations

import math
import os
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "assets")

SS = 4  # 超采样倍数


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return lo if v < lo else hi if v > hi else v


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _sd_round_rect(px: float, py: float, x: float, y: float,
                   w: float, h: float, r: float) -> float:
    """圆角矩形有符号距离（内部为负）"""
    cx, cy = x + w / 2, y + h / 2
    qx, qy = abs(px - cx) - (w / 2 - r), abs(py - cy) - (h / 2 - r)
    ax, ay = max(qx, 0.0), max(qy, 0.0)
    return math.hypot(ax, ay) + min(max(qx, qy), 0.0) - r


def _render(size: int, full_bleed: bool = False) -> bytes:
    """返回 size×size 的 RGBA 原始字节（full_bleed=True 用于 iOS 主屏幕图标，铺满不透明）"""
    S = size * (2 if size >= 384 else SS)
    buf = bytearray(S * S * 4)

    margin = 0 if full_bleed else 0.015 * S
    corner = 0 if full_bleed else 0.225 * S
    scale = 1.0 if not full_bleed else 1.12
    cx, cy = 0.5 * S, 0.53 * S
    maxr = 0.385 * S * scale
    rings = [0.145 * S * scale, 0.255 * S * scale, 0.365 * S * scale]
    stroke = max(1.6, 0.018 * S)
    blips = [(0.625, 0.355), (0.335, 0.285), (0.665, 0.675), (0.435, 0.745)]
    blip_r = 0.030 * S

    for y in range(S):
        py = y + 0.5
        row = y * S * 4
        for x in range(S):
            px = x + 0.5
            i = row + x * 4

            # ---- 背景圆角方块：靛蓝 -> 青色 对角渐变 ----
            sd = _sd_round_rect(px, py, margin, margin,
                                S - 2 * margin, S - 2 * margin, corner)
            a_bg = _clamp(0.5 - sd)
            if a_bg <= 0:
                continue
            t = _clamp((px + py) / (2.0 * S))
            R = _lerp(99, 6, t)
            G = _lerp(102, 182, t)
            B = _lerp(241, 212, t)
            # 左上柔光
            hl = _clamp(1.0 - math.hypot(px - 0.28 * S, py - 0.24 * S) / (0.85 * S))
            R += 34 * hl * hl
            G += 34 * hl * hl
            B += 34 * hl * hl

            # ---- 雷达 ----
            d = math.hypot(px - cx, py - cy)
            if d < maxr * 1.08:
                ang = math.degrees(math.atan2(py - cy, px - cx))
                # 扫描扇形（-32° ~ 0°），按半径衰减
                if -32.0 <= ang <= 0.0 and d < maxr:
                    k = 1.0 - d / maxr
                    # 边缘角度渐隐
                    edge = _clamp((-32.0 - ang) / 6.0) * _clamp((ang + 32.0) / 6.0)
                    sweep = 0.42 * k * (0.45 + 0.55 * edge)
                    R = _lerp(R, 255, sweep)
                    G = _lerp(G, 255, sweep)
                    B = _lerp(B, 255, sweep)
                # 扫描前沿亮线
                if -3.2 <= ang <= 0.0 and d < maxr:
                    R, G, B = 255, 255, 255
                # 同心圆环
                for rr in rings:
                    cov = _clamp(1.0 - abs(d - rr) / stroke)
                    if cov > 0:
                        a = 0.62 * cov
                        R = _lerp(R, 255, a)
                        G = _lerp(G, 255, a)
                        B = _lerp(B, 255, a)
                # 目标光点
                for bx, by in blips:
                    dd = math.hypot(px - bx * S, py - by * S)
                    cov = _clamp(1.0 - dd / blip_r)
                    if cov > 0:
                        a = 0.95 * cov
                        R = _lerp(R, 255, a)
                        G = _lerp(G, 255, a)
                        B = _lerp(B, 255, a)

            buf[i] = int(_clamp(R, 0, 255))
            buf[i + 1] = int(_clamp(G, 0, 255))
            buf[i + 2] = int(_clamp(B, 0, 255))
            buf[i + 3] = int(255 * a_bg)

    # ---- 降采样 ----
    ss = 2 if size >= 384 else SS
    out = bytearray(size * size * 4)
    for y in range(size):
        for x in range(size):
            r = g = b = a = 0
            for dy in range(ss):
                base = ((y * ss + dy) * S + x * ss) * 4
                for dx in range(ss):
                    j = base + dx * 4
                    r += buf[j]
                    g += buf[j + 1]
                    b += buf[j + 2]
                    a += buf[j + 3]
            n = ss * ss
            k = (y * size + x) * 4
            out[k] = r // n
            out[k + 1] = g // n
            out[k + 2] = b // n
            out[k + 3] = a // n
    return bytes(out)


def _png(w: int, h: int, rgba: bytes) -> bytes:
    raw = b"".join(b"\x00" + rgba[y * w * 4:(y + 1) * w * 4] for y in range(h))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def main():
    os.makedirs(ASSETS, exist_ok=True)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    pngs = []
    for s in sizes:
        data = _png(s, s, _render(s))
        pngs.append((s, data))
        if s == 256:
            with open(os.path.join(ASSETS, "preview.png"), "wb") as f:
                f.write(data)

    header = struct.pack("<HHH", 0, 1, len(pngs))
    offset = 6 + 16 * len(pngs)
    entries, body = b"", b""
    for s, data in pngs:
        w = 0 if s >= 256 else s
        entries += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32,
                               len(data), offset)
        offset += len(data)
        body += data
    ico_path = os.path.join(ASSETS, "app.ico")
    with open(ico_path, "wb") as f:
        f.write(header + entries + body)
    print("icon:", ico_path, os.path.getsize(ico_path), "bytes")
    print("preview:", os.path.join(ASSETS, "preview.png"))

    # PWA / iOS 主屏幕图标
    static_dir = os.path.join(ROOT, "static")
    os.makedirs(static_dir, exist_ok=True)
    for size, name in ((192, "icon-192.png"), (512, "icon-512.png")):
        with open(os.path.join(static_dir, name), "wb") as f:
            f.write(_png(size, size, _render(size)))
    with open(os.path.join(static_dir, "apple-touch-icon.png"), "wb") as f:
        f.write(_png(180, 180, _render(180, full_bleed=True)))
    with open(os.path.join(static_dir, "icon-maskable-512.png"), "wb") as f:
        f.write(_png(512, 512, _render(512, full_bleed=True)))

    # Android APK 启动图标（mipmap 各密度，铺满式）
    android_res = os.path.join(ROOT, "android", "res")
    os.makedirs(android_res, exist_ok=True)
    for dpi, size in (("mdpi", 48), ("hdpi", 72), ("xhdpi", 96),
                      ("xxhdpi", 144), ("xxxhdpi", 192)):
        d = os.path.join(android_res, f"mipmap-{dpi}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "ic_launcher.png"), "wb") as f:
            f.write(_png(size, size, _render(size, full_bleed=True)))
    print("pwa icons:", static_dir, "(192 / 512 / maskable 512 / apple-touch 180)")
    print("android icons:", android_res, "(mdpi~xxxhdpi)")


if __name__ == "__main__":
    main()
