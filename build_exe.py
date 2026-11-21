# -*- coding: utf-8 -*-
"""一键打包为单文件 exe（PyInstaller）

用法：
    python build_exe.py            # 构建
    python build_exe.py --dir      # 额外构建一个目录版（启动更快，便于排错）

产物：
    dist/networkmap.exe           单文件版（双击使用）
"""
from __future__ import annotations

import os
import subprocess
import sys

# CI（如 GitHub Actions 的 Windows 运行器）stdout 可能是 cp1252，
# 直接打印中文/emoji 会抛 UnicodeEncodeError，这里做兜底
for _stream in (sys.stdout, sys.stderr):
    try:
        if "utf" not in (_stream.encoding or "").lower():
            _stream.reconfigure(errors="replace")
    except Exception:
        pass

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
        "--name", "networkmap",
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

    exe = os.path.join(ROOT, "dist", "networkmap.exe")
    if not os.path.isfile(exe):
        sys.exit("未找到 dist/networkmap.exe")
    print(f"\n✅ 单文件版: {exe}  ({os.path.getsize(exe) / 1024 / 1024:.1f} MB)")

    if "--dir" in sys.argv:
        print("\n=== 构建目录版 ===")
        dir_args = [
            sys.executable, "-m", "PyInstaller",
            "--noconfirm", "--clean",
            "--name", "networkmap-dir",
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
        print("✅ 目录版: dist/networkmap-dir/networkmap-dir.exe")

    print("\n提示：exe 首次运行会在其所在目录生成 notes.json / history.json / "
          "nmap_results.json；目录不可写时自动改用 %LOCALAPPDATA%\\networkmap")


if __name__ == "__main__":
    main()
