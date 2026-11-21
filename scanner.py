# -*- coding: utf-8 -*-
"""
networkmap · 局域网扫描引擎（纯 Python 标准库，面向 Windows）

能力：
- 识别本机网卡（IP / MAC / 网关 / DNS / 子网）
- Ping 扫描 + ARP 表 + TCP 探测，发现同网段设备
- 反向 DNS 与 NetBIOS 解析主机名，OUI 识别网卡厂商
- 探测常见代理端口（Clash / v2rayN / SOCKS5 / Squid 等）并做协议握手确认
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import paths

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# 常见代理 / 隧道端口 -> 用途说明
PROXY_PORTS = [
    (7890, "Clash"), (7891, "Clash"), (7897, "Clash Verge"), (7899, "Clash"),
    (1080, "SOCKS5"), (1086, "SOCKS5"), (1087, "HTTP"),
    (10808, "v2rayN SOCKS"), (10809, "v2rayN HTTP"),
    (3128, "Squid"), (8118, "Privoxy"), (9050, "Tor"),
    (8080, "HTTP"), (8888, "Charles/Fiddler"),
    (6152, "Surge HTTP"), (6153, "Surge"), (9090, "Clash 面板"),
    (8001, "HTTP"), (8008, "HTTP"),
]

# 对"不响应 ping"设备的 TCP 存活探测端口
PRESENCE_PORTS = [80, 443, 445, 22, 3389, 53, 8080, 5000, 8443]

# 常见 OUI 厂商（精选高置信条目，离线识别）
OUI_VENDORS = {
    "AC:DE:48": "Apple", "00:1B:63": "Apple", "F0:18:98": "Apple",
    "A4:5E:60": "Apple", "D0:03:4B": "Apple", "8C:85:90": "Apple",
    "A0:A8:CD": "Intel", "9C:B6:D0": "Intel", "D4:3A:E9": "Intel",
    "00:E0:4C": "Realtek",
    "AC:36:13": "Samsung", "00:16:32": "Samsung",
    "64:09:80": "Xiaomi", "28:6C:07": "Xiaomi", "AC:C1:EE": "Xiaomi", "F0:B4:29": "Xiaomi",
    "78:1D:BA": "Huawei", "00:46:4B": "Huawei",
    "F4:F2:6D": "TP-Link", "14:CC:20": "TP-Link", "C0:25:E9": "TP-Link", "1C:FA:68": "TP-Link",
    "AC:9E:17": "ASUS", "40:B0:76": "ASUS",
    "F8:BC:12": "Dell", "D4:BE:D9": "Dell",
    "3C:D9:2B": "HP", "F4:39:27": "HP",
    "54:E1:AD": "Lenovo", "8C:16:45": "Lenovo",
    "00:15:5D": "Microsoft (Hyper-V)", "08:00:27": "VirtualBox",
    "00:0C:29": "VMware", "00:50:56": "VMware",
    "5C:CF:7F": "Espressif", "30:AE:A4": "Espressif", "24:6F:28": "Espressif",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "00:1A:A1": "Cisco", "A0:40:A0": "NETGEAR", "B0:39:56": "NETGEAR",
    "78:8A:20": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
    "48:8F:5A": "MikroTik", "D4:CA:6D": "MikroTik",
    "C8:3A:35": "Tenda", "50:2B:73": "Tenda",
    "34:4B:50": "ZTE", "F4:F5:D8": "Google", "40:8D:5C": "Gigabyte",
    "00:11:32": "Synology",
}

# ---------------------------------------------------------------- 状态管理

_lock = threading.Lock()
_state = {
    "scanning": False, "phase": "", "progress": 0, "detail": "",
    "result": None, "last_ts": 0, "duration": 0.0, "error": None,
}
_thread: threading.Thread | None = None
_nbt_budget = {"n": 0}
_nbt_lock = threading.Lock()

_info_lock = threading.Lock()
_info_cache = {"ts": 0.0, "data": None}


def state_snapshot() -> dict:
    with _lock:
        return dict(_state)


def _set(**kw):
    with _lock:
        _state.update(kw)


def start_scan() -> bool:
    """启动一次后台扫描；若已有扫描进行中则返回 False"""
    global _thread
    with _lock:
        if _state["scanning"]:
            return False
        _state.update(scanning=True, phase="准备中", progress=1, detail="",
                      error=None, result=None if _state["last_ts"] == 0 else _state["result"])
        _thread = threading.Thread(target=_run, name="lan-scan", daemon=True)
        _thread.start()
        return True


def _run():
    _nbt_budget["n"] = 60
    t0 = time.time()
    try:
        devices, subnet = _scan_all()
        _save_history(devices, subnet)  # 失败不影响扫描结果
        with _lock:
            _state.update(result=devices, last_ts=time.time(),
                          duration=round(time.time() - t0, 1),
                          error=None, phase="完成", progress=100, detail="")
    except Exception as e:  # 扫描失败也要把状态交还出去
        with _lock:
            _state.update(error=f"{type(e).__name__}: {e}", phase="出错", detail="")
    finally:
        with _lock:
            _state.update(scanning=False)


# ---------------------------------------------------------------- 网卡信息

_PS_INFO = r"""
$ErrorActionPreference='SilentlyContinue';
$cfg = Get-NetIPConfiguration -Detailed | Where-Object {$_.IPv4Address -and $_.IPv4DefaultGateway} | Select-Object -First 1;
if (-not $cfg) { $cfg = Get-NetIPConfiguration -Detailed | Where-Object {$_.IPv4Address} | Select-Object -First 1 }
if ($cfg) {
  $ad = Get-NetAdapter -InterfaceIndex $cfg.InterfaceIndex -ErrorAction SilentlyContinue;
  [pscustomobject]@{
    iface  = $cfg.InterfaceAlias;
    ip     = $cfg.IPv4Address.IPAddress;
    prefix = $cfg.IPv4Address.PrefixLength;
    gw     = (@($cfg.IPv4DefaultGateway | ForEach-Object {$_.NextHop}) -join ',');
    dns    = (@($cfg.DNSServer | ForEach-Object {$_.ServerAddresses}) -join ',');
    mac    = $ad.MacAddress;
  } | ConvertTo-Json -Compress
} else { Write-Output '{"error":"no-adapter"}' }
"""


def _first_str(v) -> str:
    if isinstance(v, list):
        v = v[0] if v else ""
    return str(v or "").strip()


def _self_ip_via_socket() -> str:
    """借助 UDP connect 探知默认路由出口 IP（不实际发包）"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("223.5.5.5", 53))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return ""


def _gw_from_route_print() -> str:
    try:
        out = subprocess.run(["route", "print", "-4"], capture_output=True, text=True,
                             errors="ignore", timeout=10,
                             creationflags=CREATE_NO_WINDOW).stdout or ""
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    except Exception:
        pass
    return ""


def _collect_info() -> dict:
    info: dict = {}
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", _PS_INFO],
            capture_output=True, text=True, errors="ignore", timeout=25,
            creationflags=CREATE_NO_WINDOW,
        ).stdout or ""
        data = json_loads_safe(out)
        if isinstance(data, dict):
            data = [data]
        if isinstance(data, list) and data and "error" not in data[0]:
            d = data[0]
            mac = _first_str(d.get("mac")).replace("-", ":").upper()
            info = {
                "iface": _first_str(d.get("iface")),
                "ip": _first_str(d.get("ip")),
                "prefix": _to_int(d.get("prefix"), 24),
                "gateway": _first_str(d.get("gw")),
                "dns": _first_str(d.get("dns")),
                "mac": mac,
            }
    except Exception:
        info = {}
    if not info.get("ip"):
        # 兜底：route print + UDP socket
        info.setdefault("iface", "")
        info["ip"] = _self_ip_via_socket()
        info.setdefault("gateway", "")
        if not info.get("gateway"):
            info["gateway"] = _gw_from_route_print()
        info.setdefault("dns", "")
        info.setdefault("mac", "")
        info.setdefault("prefix", 24)
    return info


def json_loads_safe(text: str):
    text = (text or "").strip()
    if not text:
        return None
    # PS 有时会输出多余行，取第一行能解析的 JSON
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{") or line.startswith("["):
            try:
                import json
                return json.loads(line)
            except Exception:
                continue
    return None


def _to_int(v, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def get_info(force: bool = False) -> dict:
    """网卡 + 系统代理信息（60 秒缓存；扫描开始时强制刷新）"""
    now = time.time()
    with _info_lock:
        if not force and _info_cache["data"] and now - _info_cache["ts"] < 60:
            return dict(_info_cache["data"])
    data = _collect_info()
    data["system_proxy"] = _system_proxy()
    data["clamped"] = False
    data["scanned_subnet"] = ""
    with _info_lock:
        _info_cache.update(ts=time.time(), data=data)
    return dict(data)


def _system_proxy() -> dict:
    """读取 Windows 系统代理（WinINET 设置，含 PAC）"""
    base = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def _q(name: str) -> str:
        try:
            out = subprocess.run(["reg", "query", base, "/v", name],
                                 capture_output=True, text=True, errors="ignore",
                                 timeout=8, creationflags=CREATE_NO_WINDOW).stdout or ""
            m = re.search(re.escape(name) + r"\s+REG_\w+\s+(\S+)", out)
            return m.group(1) if m else ""
        except Exception:
            return ""

    enabled = _q("ProxyEnable").lower() == "0x1"
    server = _q("ProxyServer")
    pac = _q("AutoConfigURL")
    host, port = "", ""
    if server:
        s = server
        if ";" in s or "=" in s:  # 形如 http=127.0.0.1:10809;https=...
            m = re.search(r"(?:https?|socks?)=([^;]+)", s)
            s = m.group(1) if m else s.split(";")[0].split("=")[-1]
        m = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)", s)
        if m:
            host, port = m.group(1), m.group(2)
    return {"enabled": enabled, "server": server,
            "host": host, "port": port, "autoconfig": pac}


# ---------------------------------------------------------------- 基础探测

def _ping(ip: str):
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", "800", ip],
                           capture_output=True, text=True, errors="ignore",
                           timeout=5, creationflags=CREATE_NO_WINDOW)
        if r.returncode == 0:
            ttl = None
            m = re.search(r"TTL[=:]\s*(\d+)", r.stdout or "", re.IGNORECASE)
            if m:
                ttl = int(m.group(1))
            return True, ttl
    except Exception:
        pass
    return False, None


def _tcp_open(ip: str, port: int, timeout: float = 0.45) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _read_arp() -> dict:
    """解析 arp -a，返回 {ip: mac}（MAC 统一为大写冒号格式）"""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             errors="ignore", timeout=12,
                             creationflags=CREATE_NO_WINDOW).stdout or ""
    except Exception:
        return {}
    entries = {}
    for m in re.finditer(
            r"(\d+\.\d+\.\d+\.\d+)\s+(([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})", out):
        ip = m.group(1)
        mac = m.group(2).replace("-", ":").upper()
        if mac != "00:00:00:00:00:00" and not mac.startswith("01:00:5E") and mac != "FF:FF:FF:FF:FF:FF":
            entries[ip] = mac
    return entries


def _rev_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(2.0)
        name = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except Exception:
        return ""
    # 无 PTR 记录时 Windows 常把 IP 原样返回，视为失败
    if not name or name == ip.lower() or name.endswith(".in-addr.arpa"):
        return ""
    return name


def _netbios(ip: str) -> str:
    """NetBIOS 查询（Windows 主机大多能取到机器名），受预算限制避免拖慢扫描"""
    with _nbt_lock:
        if _nbt_budget["n"] <= 0:
            return ""
        _nbt_budget["n"] -= 1
    try:
        out = subprocess.run(["nbtstat", "-A", ip], capture_output=True,
                             text=True, errors="ignore", timeout=9,
                             creationflags=CREATE_NO_WINDOW).stdout or ""
        for line in out.splitlines():
            if "UNIQUE" not in line.upper() and "唯一" not in line:
                continue
            m = re.match(r"\s*([A-Za-z0-9][\w\-.]{0,30})\s*<00>", line)
            if m and not m.group(1).upper().startswith("__"):
                return m.group(1)
    except Exception:
        pass
    return ""


def _verify_proxy(ip: str, port: int) -> str:
    """对已开放端口做轻量协议握手，返回 '' | 'HTTP' | 'HTTP?' | 'SOCKS5' | '面板'"""
    if port == 9090:  # Clash 外部控制面板
        try:
            s = socket.create_connection((ip, port), timeout=1.2)
            s.settimeout(2.0)
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            d = s.recv(256)
            s.close()
            if d.startswith(b"HTTP"):
                return "面板"
        except OSError:
            pass
        return ""
    # HTTP 代理：绝对 URI GET。真代理会转发并返回连接测试文件内容，
    # 普通网页服务（如路由器管理页）虽响应 HTTP 但内容不符
    try:
        s = socket.create_connection((ip, port), timeout=1.2)
        s.settimeout(2.5)
        s.sendall(b"GET http://www.msftconnecttest.com/connecttest.txt HTTP/1.1\r\n"
                  b"Host: www.msftconnecttest.com\r\n"
                  b"User-Agent: networkmap\r\nConnection: close\r\n\r\n")
        d = b""
        while len(d) < 4096:
            try:
                chunk = s.recv(1024)
            except OSError:
                break
            if not chunk:
                break
            d += chunk
        s.close()
        if d.startswith(b"HTTP"):
            first = d.split(b"\r\n", 1)[0]
            if b"200" in first and b"icrosoft Connect Test" in d:
                return "HTTP"   # 已验证：能通过它访问到测试文件
            return "HTTP?"      # 疑似：响应了 HTTP 但内容不符
    except OSError:
        pass
    # SOCKS5 握手
    try:
        s = socket.create_connection((ip, port), timeout=1.2)
        s.settimeout(2.0)
        s.sendall(b"\x05\x01\x00")
        d = s.recv(4)
        s.close()
        if len(d) >= 2 and d[0] == 5:
            return "SOCKS5"
    except OSError:
        pass
    return ""


# ---------------------------------------------------------------- 小工具

def _vendor(mac: str) -> str:
    return OUI_VENDORS.get(mac[:8], "") if mac else ""


def _os_guess(ttl) -> str:
    if ttl is None:
        return ""
    if ttl <= 64:
        return "Linux/Unix 类"
    if ttl <= 128:
        return "Windows"
    return "网络设备"


def _ip_key(ip: str):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999,)


def _in_net(ip: str, net: ipaddress._BaseNetwork) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


# ---------------------------------------------------------------- 主流程

def _scan_all() -> list:
    _set(phase="获取网络配置", progress=2, detail="")
    info = get_info(force=True)
    self_ip = info.get("ip") or ""
    if not self_ip:
        raise RuntimeError("未能获取本机 IPv4 地址，请检查网络连接")
    gw = info.get("gateway") or ""
    prefix = info.get("prefix") or 24
    try:
        net = ipaddress.ip_network(f"{self_ip}/{int(prefix)}", strict=False)
    except ValueError:
        net = ipaddress.ip_network(f"{self_ip}/24", strict=False)
    clamped = False
    if net.prefixlen != 24:  # 过大网段按 /24 截断，避免扫描数万地址
        net = ipaddress.ip_network(f"{self_ip}/24", strict=False)
        clamped = True
    hosts = [str(h) for h in net.hosts()]
    hosts_set = set(hosts)
    info["clamped"] = clamped
    info["scanned_subnet"] = str(net)
    total = len(hosts)

    # 1) Ping 扫描
    _set(phase="Ping 扫描", progress=6, detail="0/{}".format(total))
    alive: dict = {}
    ping_done = [0]

    def _ping_task(ip):
        ok, ttl = _ping(ip)
        if ok:
            alive[ip] = {"ttl": ttl, "via": ["ping"]}
        ping_done[0] += 1
        if ping_done[0] % 10 == 0 or ping_done[0] == total:
            _set(progress=min(46, 6 + int(40 * ping_done[0] / total)),
                 detail="{}/{}".format(ping_done[0], total))

    with ThreadPoolExecutor(max_workers=48) as ex:
        list(ex.map(_ping_task, hosts))

    # 2) ARP 表补充（能抓到不回 ping 但最近有流量的设备）
    _set(phase="读取 ARP 表", progress=48, detail="")
    arp = _read_arp()
    candidates = set(alive) | {ip for ip in arp if ip in hosts_set} | {self_ip}
    if gw:
        candidates.add(gw)

    # 3) TCP 存活探测（针对未响应 ping 的候选）
    need_probe = sorted(candidates - set(alive))
    if need_probe:
        _set(phase="TCP 探测", progress=52, detail="0/{}".format(len(need_probe)))
        pdone = [0]

        def _probe(ip):
            hit = None
            for port in PRESENCE_PORTS:
                if _tcp_open(ip, port, 0.3):
                    hit = port
                    break
            pdone[0] += 1
            if pdone[0] % 8 == 0 or pdone[0] == len(need_probe):
                _set(progress=min(64, 52 + int(12 * pdone[0] / len(need_probe))),
                     detail="{}/{}".format(pdone[0], len(need_probe)))
            return ip, hit

        with ThreadPoolExecutor(max_workers=48) as ex:
            for ip, port in ex.map(_probe, need_probe):
                if port:
                    alive[ip] = {"ttl": None, "via": ["tcp"]}

    # 4) 主机名解析（反向 DNS + NetBIOS）
    name_targets = sorted(candidates & set(alive))
    names: dict = {}
    if name_targets:
        _set(phase="解析主机名", progress=66, detail="0/{}".format(len(name_targets)))
        ndone = [0]

        def _name(ip):
            n = _rev_dns(ip)
            if not n:
                n = _netbios(ip)
            ndone[0] += 1
            _set(progress=min(78, 66 + int(12 * ndone[0] / len(name_targets))),
                 detail="{}/{}".format(ndone[0], len(name_targets)))
            return ip, n

        with ThreadPoolExecutor(max_workers=16) as ex:
            for ip, n in ex.map(_name, name_targets):
                if n:
                    names[ip] = n

    # 5) 代理端口探测（在线设备 + 网关）
    probe_list = sorted(candidates & set(alive))
    if gw and gw not in probe_list:
        probe_list.append(gw)
    open_ports: dict = {}
    if probe_list:
        _set(phase="代理端口探测", progress=80, detail="")
        ppairs = [(ip, p, label) for ip in probe_list for p, label in PROXY_PORTS]
        cdone = [0]

        def _pp(task):
            ip, p, label = task
            ok = _tcp_open(ip, p, 0.45)
            cdone[0] += 1
            if cdone[0] % 20 == 0 or cdone[0] == len(ppairs):
                _set(progress=min(92, 80 + int(12 * cdone[0] / len(ppairs))),
                     detail="{}/{}".format(cdone[0], len(ppairs)))
            return task, ok

        with ThreadPoolExecutor(max_workers=48) as ex:
            for task, ok in ex.map(_pp, ppairs):
                if ok:
                    ip, p, label = task
                    open_ports.setdefault(ip, {})[p] = label

    # 6) 代理协议握手确认
    _set(phase="识别代理协议", progress=93, detail="")
    port_kind: dict = {}
    for ip, ports in open_ports.items():
        kinds = {}
        for p in sorted(ports):
            kinds[p] = _verify_proxy(ip, p)
        port_kind[ip] = kinds

    # 7) 汇总设备记录
    devices = []
    for ip in sorted(candidates, key=_ip_key):
        a = alive.get(ip)
        via = sorted(set((a or {}).get("via", []) + (["arp"] if ip in arp else [])))
        ports_out = [
            {"port": p, "name": label, "kind": port_kind.get(ip, {}).get(p, "")}
            for p, label in sorted(open_ports.get(ip, {}).items())
        ]
        kinds = sorted({k for k in port_kind.get(ip, {}).values()
                        if k in ("HTTP", "SOCKS5")})
        mac = arp.get(ip, "") or (info.get("mac", "") if ip == self_ip else "")
        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": _vendor(mac),
            "hostname": names.get(ip, ""),
            "alive": a is not None,
            "via": via,
            "ttl": (a or {}).get("ttl"),
            "os_guess": _os_guess((a or {}).get("ttl")) if a else "",
            "is_self": ip == self_ip,
            "is_gateway": bool(gw) and ip == gw,
            "ports": ports_out,
            "proxy_kinds": kinds,
            "proxy_confirmed": bool(kinds),
            "key": mac or f"ip:{ip}",
        })
    _set(phase="完成", progress=100, detail="共 {} 台设备".format(len(devices)))
    return devices, str(net)


# ---------------------------------------------------------------- 扫描历史

HISTORY_FILE = paths.data_file("history.json")
HISTORY_MAX = 30


def _save_history(devices: list, subnet: str):
    """每次常规扫描结束后保存一份快照，用于"历史 vs 当前"变化对比（对标 Ndiff）"""
    try:
        items = []
        try:
            with open(HISTORY_FILE, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    items = data
        except Exception:
            items = []
        try:  # 合并当时已有的 nmap 端口号，让端口变化对比更完整
            import nmapscan
            nmap_ports = {ip: [p["port"] for p in (r.get("ports") or [])]
                          for ip, r in (nmapscan.store_snapshot()["results"]).items()}
        except Exception:
            nmap_ports = {}
        items.append({
            "ts": time.time(),
            "subnet": subnet or "",
            "total": len(devices),
            "alive": sum(1 for d in devices if d["alive"]),
            "devices": [{
                "ip": d["ip"], "mac": d["mac"], "hostname": d["hostname"],
                "vendor": d["vendor"], "alive": d["alive"],
                "ports": sorted(set([p["port"] for p in d["ports"]]
                                    + nmap_ports.get(d["ip"], [])))[:60],
                "proxy_confirmed": d["proxy_confirmed"],
            } for d in devices],
        })
        items = items[-HISTORY_MAX:]
        tmp = HISTORY_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=1)
        os.replace(tmp, HISTORY_FILE)
    except Exception:
        pass
