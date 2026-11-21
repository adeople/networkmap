# -*- coding: utf-8 -*-
"""统一的资源 / 数据路径解析（源码运行与 PyInstaller 打包后行为一致）

- 源码运行：资源与数据都在脚本所在目录（与之前行为一致）
- 打包运行（onefile）：
    RES_DIR  = sys._MEIPASS（临时解包目录，只读资源：static）
    DATA_DIR = exe 所在目录（可写：notes.json / history.json / nmap_results.json …）
  exe 所在目录不可写时（如放在 Program Files），自动回退到
  %LOCALAPPDATA%\\LanProbe
"""
from __future__ import annotations

import os
import sys

FROZEN = bool(getattr(sys, "frozen", False))


def _writable(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".lanprobe_probe")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        return True
    except OSError:
        return False


if FROZEN:
    RES_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
    _exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    _fallback = os.path.join(
        os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
        "LanProbe")
    DATA_DIR = _exe_dir if _writable(_exe_dir) else _fallback
else:
    RES_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = RES_DIR

STATIC_DIR = os.path.join(RES_DIR, "static")


def data_file(name: str) -> str:
    """数据文件名 -> 可写绝对路径（位于 DATA_DIR）"""
    return os.path.join(DATA_DIR, name)
