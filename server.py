# -*- coding: utf-8 -*-
"""
LAN 探针 · 本地 Web 服务（纯 Python 标准库，无第三方依赖）

- GET  /            前端页面（static/）
- GET  /api/state   网络信息 + 设备列表 + 扫描状态（备注已合并）
- POST /api/scan    触发一次扫描
- POST /api/notes   保存 / 删除设备备注 {key, alias, note}

默认监听 127.0.0.1:8791（不暴露到局域网），--host 0.0.0.0 可改。
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import scanner
import nmapscan
import paths

ROOT = paths.DATA_DIR
STATIC = paths.STATIC_DIR
NOTES_FILE = paths.data_file("notes.json")
DEFAULT_PORT = 8791

_notes_lock = threading.Lock()

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


# ---------------------------------------------------------------- 备注

def _load_notes() -> dict:
    try:
        with open(NOTES_FILE, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_notes(notes: dict) -> None:
    tmp = NOTES_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(notes, f, ensure_ascii=False, indent=2)
    os.replace(tmp, NOTES_FILE)


def _save_note(key: str, alias: str, note: str) -> bool:
    key = (key or "").strip()
    if not key or len(key) > 40:
        return False
    alias = (alias or "").strip()[:60]
    note = (note or "").strip()[:500]
    with _notes_lock:
        notes = _load_notes()
        if not alias and not note:
            notes.pop(key, None)  # 两项都清空即删除备注
        else:
            notes[key] = {"alias": alias, "note": note}
        _save_notes(notes)
    return True


# ---------------------------------------------------------------- 请求处理

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LanExplorer/1.0"

    def log_message(self, fmt, *args):  # 静默访问日志
        pass

    # -- 基础响应 --
    def _send(self, code: int, body, ctype: str = "application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (ConnectionResetError, BrokenPipeError):
            pass

    def _send_json_error(self, code: int, msg: str):
        self._send(code, {"ok": False, "error": msg})

    # -- 路由 --
    def do_GET(self):
        try:
            path = self.path.split("?", 1)[0]
            if path == "/api/state":
                self._api_state()
            elif path == "/api/history":
                qs = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
                self._api_history(qs)
            elif path in ("/", "/index.html"):
                self._serve_static("index.html")
            elif path == "/favicon.ico":
                self._send(204, b"")
            else:
                name = path.lstrip("/")
                if "/" not in name and name:
                    self._serve_static(name)
                else:
                    self._send_json_error(404, "not found")
        except Exception as e:  # 防止单请求异常拖垮服务线程
            try:
                self._send_json_error(500, f"{type(e).__name__}: {e}")
            except Exception:
                pass

    def do_POST(self):
        try:
            path = self.path.split("?", 1)[0]
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "ignore") if length else ""
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                return self._send_json_error(400, "JSON 解析失败")
            if not isinstance(data, dict):
                return self._send_json_error(400, "请求体应为 JSON 对象")

            if path == "/api/scan":
                started = scanner.start_scan()
                self._send(200, {"ok": True, "started": started})
            elif path == "/api/nmap":
                self._api_nmap(data)
            elif path == "/api/notes":
                if _save_note(data.get("key", ""), data.get("alias", ""), data.get("note", "")):
                    self._send(200, {"ok": True})
                else:
                    self._send_json_error(400, "无效的备注数据")
            else:
                self._send_json_error(404, "not found")
        except Exception as e:
            try:
                self._send_json_error(500, f"{type(e).__name__}: {e}")
            except Exception:
                pass

    # -- 业务 --
    def _api_nmap(self, data: dict):
        """启动 nmap 深度扫描。目标可为 IP/CIDR/范围；缺省取最近常规扫描的在线设备"""
        if not nmapscan.nmap_exe():
            return self._send(200, {"ok": False, "started": False,
                                    "error": "未检测到 nmap，请先安装（winget install Insecure.Nmap）"})
        opts = {"profile": data.get("profile"),
                "scripts": data.get("scripts") if isinstance(data.get("scripts"), list) else [],
                "timing": data.get("timing")}

        targets_raw = (data.get("targets") or "").strip()
        if targets_raw:
            tokens = [t for t in re.split(r"[\s,;，；]+", targets_raw) if t]
            bad = [t for t in tokens if not nmapscan.valid_target(t)]
            if bad:
                return self._send(200, {"ok": False, "started": False,
                                        "error": "无效目标: " + "、".join(bad[:5])})
            targets = list(dict.fromkeys(tokens))
        else:
            snap = scanner.state_snapshot()
            devices = snap.get("result") or []
            targets = [d["ip"] for d in devices
                       if d.get("alive") or d.get("is_gateway")]
        targets = list(dict.fromkeys(targets))[:nmapscan.MAX_TARGETS]
        if not targets:
            return self._send(200, {"ok": False, "started": False,
                                    "error": "没有可扫描的目标，请先执行一次常规扫描或填写目标"})
        started = nmapscan.start(targets, opts)
        self._send(200, {"ok": True, "started": started,
                         "targets": targets if started else [],
                         "error": None if started else "已有深度扫描在进行中"})

    def _read_history(self) -> list:
        try:
            with open(paths.data_file("history.json"), encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def _api_history(self, qs: dict):
        """GET /api/history           -> 快照列表（摘要）
           GET /api/history?id=<ts>   -> 某次快照完整内容"""
        items = self._read_history()
        ident = (qs.get("id") or [None])[0]
        if ident:
            try:
                target = float(ident)
            except ValueError:
                return self._send_json_error(400, "无效 id")
            for it in items:
                if abs(float(it.get("ts", 0)) - target) < 0.001:
                    return self._send(200, {"ok": True, "item": it})
            return self._send_json_error(404, "未找到该快照")
        self._send(200, {"ok": True, "items": [
            {"ts": it.get("ts"), "subnet": it.get("subnet"),
             "total": it.get("total"), "alive": it.get("alive")}
            for it in reversed(items)]})

    def _api_state(self):
        snap = scanner.state_snapshot()
        notes = _load_notes()
        devices = snap.get("result") or []
        for d in devices:
            memo = notes.get(d.get("key", "")) or {}
            d["alias"] = memo.get("alias", "")
            d["note"] = memo.get("note", "")
            d["has_note"] = bool(d["alias"] or d["note"])
        info = scanner.get_info()
        # 系统代理指向的设备打标（127.0.0.1 视为本机）
        sp = info.get("system_proxy") or {}
        sp_host = sp.get("host", "")
        for d in devices:
            d["sys_proxy_target"] = (d["ip"] == sp_host) or (
                sp_host in ("127.0.0.1", "localhost") and d["is_self"])
        # 合并 nmap 深度扫描结果
        nmap_store = nmapscan.store_snapshot()
        nmap_snap = nmapscan.snapshot()
        for d in devices:
            nm = nmap_store["results"].get(d["ip"])
            d["nmap"] = nm
            d["nmap_ports"] = len(nm["ports"]) if nm else 0
        self._send(200, {
            "ok": True,
            "scanning": snap["scanning"],
            "phase": snap["phase"],
            "progress": snap["progress"],
            "detail": snap["detail"],
            "error": snap.get("error"),
            "last_ts": snap["last_ts"],
            "duration": snap["duration"],
            "devices": devices,
            "info": info,
            "nmap": {
                "available": nmapscan.nmap_exe() is not None,
                "running": nmap_snap["running"],
                "phase": nmap_snap["phase"],
                "progress": nmap_snap["progress"],
                "detail": nmap_snap["detail"],
                "error": nmap_snap.get("error"),
                "last_ts": max(nmap_snap["last_ts"], nmap_store["last_ts"]),
                "count": len(nmap_store["results"]),
            },
        })

    def _serve_static(self, name: str):
        full = os.path.normpath(os.path.join(STATIC, os.path.basename(name)))
        if not full.startswith(STATIC) or not os.path.isfile(full):
            return self._send_json_error(404, "not found")
        ext = os.path.splitext(full)[1].lower()
        with open(full, "rb") as f:
            body = f.read()
        self._send(200, body, CONTENT_TYPES.get(ext, "application/octet-stream"))


# ---------------------------------------------------------------- 启动

class Server(ThreadingHTTPServer):
    # Windows 上 SO_REUSEADDR 会静默允许多个进程绑定同一端口，必须关闭
    allow_reuse_address = False


def main():
    args = sys.argv[1:]
    port = DEFAULT_PORT
    if "--port" in args:
        try:
            port = int(args[args.index("--port") + 1])
        except (ValueError, IndexError):
            pass
    host = "127.0.0.1"
    if "--host" in args:
        i = args.index("--host")
        if i + 1 < len(args):
            host = args[i + 1]

    srv = None
    for candidate in range(port, port + 11):  # 端口被占用时自动顺延，最多试 10 个
        try:
            srv = Server((host, candidate), Handler)
            port = candidate
            break
        except OSError:
            continue
    if srv is None:
        print(f"[!] 端口 {port}~{port + 10} 均被占用，无法启动。")
        print(f"    可能已有实例在运行，可尝试手动打开 http://127.0.0.1:{port}")
        try:
            input("按回车键退出…")
        except EOFError:
            pass
        return

    url = f"http://{'127.0.0.1' if host=='127.0.0.1' else host}:{port}"
    print("=" * 52)
    print("  LAN 探针 已启动:", url)
    print("  数据目录:", paths.DATA_DIR)
    print("  备注数据:", NOTES_FILE)
    if paths.FROZEN:
        print("  提示：关闭本窗口即退出工具")
    print("=" * 52)
    if "--no-open" not in args:
        threading.Timer(0.8, webbrowser.open, [url]).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出")


if __name__ == "__main__":
    main()
