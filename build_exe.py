# -*- coding: utf-8 -*-
"""一键打包为单文件 exe（PyInstaller）

用法：
    python build_exe.py            # 构建
    python build_exe.py --dir      # 额外构建一个目录版（启动更快，便于排错）

产物：
    dist/LanProbe.exe      英文名（稳定，适合脚本调用）
    dist/LAN探针.exe        中文名副本（双击使用）
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(ROOT, "assets")
ICON = os.path.join(ASSETS, "app.ico")


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(">", " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, text=True, errors="ignore", **kw)


def main():
    if not os.path.isfile(os.path.join(ROOT, "static", "index.html")):
        sys.exit("找不到 static/index.html，请在项目根目录运行本脚本")

    # 1) 确保图标存在
    if not os.path.isfile(ICON):
        print("生成图标…")
        _run([sys.executable, os.path.join("tools", "make_icon.py")], check=True)

    # 2) 检查 PyInstaller
    try:
        ver = subprocess.run([sys.executable, "-m", "PyInstaller", "--version"],
                             capture_output=True, text=True).stdout.strip()
        print("PyInstaller:", ver)
    except Exception:
        sys.exit("未安装 PyInstaller，请先执行：python -m pip install pyinstaller")

    # 3) 构建参数
    common = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile",
        "--name", "LanProbe",
        "--icon", ICON,
        "--add-data", os.path.join("static") + os.pathsep + "static",
        "--exclude-module", "tkinter",
        "--exclude-module", "unittest",
        "--exclude-module", "doctest",
        "--exclude-module", "pydoc",
        "--console",
        "server.py",
    ]

    print("\n=== 构建单文件 exe ===")
    r = _run(common)
    if r.returncode != 0:
        sys.exit("构建失败，请查看上面的输出")

    exe = os.path.join(ROOT, "dist", "LanProbe.exe")
    if not os.path.isfile(exe):
        sys.exit("未找到 dist/LanProbe.exe")

    cn = os.path.join(ROOT, "dist", "LAN探针.exe")
    shutil.copy2(exe, cn)
    print(f"\n✅ 单文件版: {exe}  ({os.path.getsize(exe) / 1024 / 1024:.1f} MB)")
    print(f"✅ 中文名副本: {cn}")

    if "--dir" in sys.argv:
        print("\n=== 构建目录版 ===")
        dir_args = [
            sys.executable, "-m", "PyInstaller",
            "--noconfirm", "--clean",
            "--name", "LanProbeDir",
            "--icon", ICON,
            "--add-data", os.path.join("static") + os.pathsep + "static",
            "--exclude-module", "tkinter",
            "--exclude-module", "unittest",
            "--exclude-module", "doctest",
            "--exclude-module", "pydoc",
            "--console", "--onedir",
            "server.py",
        ]
        _run(dir_args)
        print("✅ 目录版: dist/LanProbeDir/LanProbeDir.exe")

    print("\n提示：exe 首次运行会在其所在目录生成 notes.json / history.json / "
          "nmap_results.json；目录不可写时自动改用 %LOCALAPPDATA%\\LanProbe")


if __name__ == "__main__":
    main()
