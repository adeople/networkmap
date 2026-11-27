# -*- coding: utf-8 -*-
"""
networkmap · 本地 Web 服务（纯 Python 标准库，无第三方依赖）

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
import socket
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
SETTINGS_FILE = paths.data_file("settings.json")
DEFAULT_PORT = 8791

# 局域网访问状态（--lan 时启用，手机扫码直接打开，无需登录）
LAN = {"enabled": False, "ip": "", "port": DEFAULT_PORT, "url": ""}

DEFAULT_SETTINGS = {"auto_scan": {"enabled": False, "interval_min": 5}}

_notes_lock = threading.Lock()
_settings_lock = threading.Lock()
_autoscan = {"thread": None, "stop": None}

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".webmanifest": "application/manifest+json; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}


def _lan_ip() -> str:
    """本机在局域网中的 IPv4（UDP connect 探测，不实际发包）"""
    try:
        return scanner._self_ip_via_socket() or ""
    except Exception:
        return ""


_discovery_stop = threading.Event()


def _pick_lan_ip(peer_ip: str) -> str:
    """从本机所有 IPv4 里选与询问方同网段的地址（避开 TUN/VPN 网段）"""
    try:
        candidates = socket.gethostbyname_ex(socket.gethostname())[2]
    except Exception:
        return ""
    prefix = peer_ip.rsplit(".", 1)[0]
    for c in candidates:
        if c != peer_ip and c.rsplit(".", 1)[0] == prefix:
            return c
    return ""


def _start_discovery_responder():
    """手机 APK 的自动发现应答：UDP 8790 广播询问 -> 回 JSON 地址"""
    def run():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", 8790))
            s.settimeout(1.0)
            while not _discovery_stop.is_set():
                try:
                    data, addr = s.recvfrom(1024)
                    if b"networkmap-discover" not in data:
                        continue
                    if not LAN["enabled"] or not LAN["url"]:
                        continue
                    # 手机从 192.168.1.x 询问时，优先应答同网段的地址
                    url = LAN["url"]
                    same = _pick_lan_ip(addr[0])
                    if same:
                        port_s = url.rsplit(":", 1)[-1].rstrip("/")
                        url = f"http://{same}:{port_s}/"
                    reply = json.dumps({"v": 1, "url": url, "name": "networkmap"}).encode()
                    s.sendto(reply, addr)
                except socket.timeout:
                    continue
                except OSError:
                    break
            s.close()
        except OSError:
            pass

    threading.Thread(target=run, name="nm-discovery", daemon=True).start()


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


def _save_note(key: str, alias: str, note: str, dtype: str = "") -> bool:
    key = (key or "").strip()
    if not key or len(key) > 40:
        return False
    alias = (alias or "").strip()[:60]
    note = (note or "").strip()[:500]
    dtype = (dtype or "").strip()[:20]
    with _notes_lock:
        notes = _load_notes()
        if not alias and not note and not dtype:
            notes.pop(key, None)  # 三项都清空即删除备注
        else:
            notes[key] = {"alias": alias, "note": note, "type": dtype}
        _save_notes(notes)
    return True


# ---------------------------------------------------------------- 设置 / 自动巡检

def _load_settings() -> dict:
    merged = json.loads(json.dumps(DEFAULT_SETTINGS))  # 深拷贝默认值
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            merged.update(data)
    except Exception:
        pass
    return merged


def _save_settings(s: dict) -> None:
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SETTINGS_FILE)


def _apply_autoscan():
    """按当前设置启动/停止后台巡检线程"""
    if _autoscan["stop"]:
        _autoscan["stop"].set()
    _autoscan.update(thread=None, stop=None)
    s = _load_settings()
    as_ = s.get("auto_scan") or {}
    if not as_.get("enabled"):
        return
    interval_min = as_.get("interval_min") if isinstance(as_.get("interval_min"), int) else 5
    interval_min = max(1, min(60, interval_min))
    stop = threading.Event()

    def run():
        while not stop.wait(interval_min * 60):
            try:
                if not scanner.state_snapshot()["scanning"]:
                    scanner.start_scan()
            except Exception:
                pass

    t = threading.Thread(target=run, name="autoscan", daemon=True)
    _autoscan.update(thread=t, stop=stop)
    t.start()


# ---------------------------------------------------------------- 请求处理

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "networkmap/1.0"

    def log_message(self, fmt, *args):  # 静默访问日志
        pass

    # -- 基础响应 --
    def _send(self, code: int, body, ctype: str = "application/json; charset=utf-8",
              cache: bool = False):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache" if cache else "no-store")
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
                if name:
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
                if _save_note(data.get("key", ""), data.get("alias", ""),
                              data.get("note", ""), data.get("type", "")):
                    self._send(200, {"ok": True})
                else:
                    self._send_json_error(400, "无效的备注数据")
            elif path == "/api/settings":
                self._api_settings(data)
            elif path == "/api/wol":
                self._api_wol(data)
            else:
                self._send_json_error(404, "not found")
        except Exception as e:
            try:
                self._send_json_error(500, f"{type(e).__name__}: {e}")
            except Exception:
                pass

    # -- 业务 --
    def _api_settings(self, data: dict):
        """读取/更新设置：{auto_scan:{enabled,interval_min}}"""
        with _settings_lock:
            s = _load_settings()
            if isinstance(data.get("auto_scan"), dict):
                cur = s.setdefault("auto_scan", {})
                cur["enabled"] = bool(data["auto_scan"].get("enabled"))
                try:
                    iv = int(data["auto_scan"].get("interval_min") or 5)
                    cur["interval_min"] = max(1, min(60, iv))
                except (TypeError, ValueError):
                    cur["interval_min"] = 5
                _save_settings(s)
            _apply_autoscan()
            self._send(200, {"ok": True, "settings": s})

    def _api_wol(self, data: dict):
        """发送 Wake-on-LAN 魔术包"""
        mac = (data.get("mac") or "").strip()
        ok = scanner.wake_on_lan(mac)
        if ok:
            self._send(200, {"ok": True, "mac": mac.upper().replace("-", ":")})
        else:
            self._send(200, {"ok": False, "error": "MAC 地址无效或发送失败"})

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
            d["type"] = memo.get("type", "")
            d["has_note"] = bool(d["alias"] or d["note"] or d["type"])
        info = scanner.get_info()
        info["lan"] = {
            "enabled": LAN["enabled"],
            "url": LAN["url"],
            "ip": LAN["ip"],
            "port": LAN["port"],
        }
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
            "settings": _load_settings(),
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
        """静态资源（支持 static/ 下的子目录，如 vendor/qrcode.js）"""
        rel = name.replace("/", os.sep).replace("\\", os.sep)
        full = os.path.normpath(os.path.join(STATIC, rel))
        base = os.path.normpath(STATIC) + os.sep
        if not full.startswith(base) or not os.path.isfile(full):
            return self._send_json_error(404, "not found")
        ext = os.path.splitext(full)[1].lower()
        with open(full, "rb") as f:
            body = f.read()
        self._send(200, body, CONTENT_TYPES.get(ext, "application/octet-stream"),
                   cache=True)


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
    lan_mode = "--lan" in args
    host = "0.0.0.0" if lan_mode else "127.0.0.1"
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

    # 局域网（手机访问）模式
    if lan_mode:
        ip = (scanner.get_info().get("ip") or "") or _lan_ip()  # 物理网卡优先，避开 TUN
        LAN.update(enabled=True, ip=ip, port=port,
                   url=f"http://{ip}:{port}/" if ip else "")
        if LAN["url"]:
            _start_discovery_responder()  # 手机 APK UDP 自动发现

    print("=" * 52)
    print("  networkmap 已启动:", url)
    if LAN["enabled"] and LAN["url"]:
        print("  📱 手机访问:", LAN["url"])
        print("     手机与电脑连同一 Wi-Fi，扫码或输入上面地址即可")
    elif lan_mode:
        print("  📱 已启用局域网模式，但未取到本机 IP")
    else:
        print("  提示：加 --lan 启动可让手机访问（同一 Wi-Fi）")
    print("  数据目录:", paths.DATA_DIR)
    print("  备注数据:", NOTES_FILE)
    if paths.FROZEN:
        print("  关闭本窗口即退出工具")
    print("=" * 52)

    # 按设置启动后台自动巡检
    s = _load_settings()
    if (s.get("auto_scan") or {}).get("enabled"):
        _apply_autoscan()
        print(f"  🔁 自动巡检已开启（每 {max(1, min(60, (s['auto_scan'].get('interval_min') or 5)))} 分钟）")

    if "--no-open" not in args:
        threading.Timer(0.8, webbrowser.open, [url]).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出")


if __name__ == "__main__":
    main()
