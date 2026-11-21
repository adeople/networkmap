# -*- coding: utf-8 -*-
"""
networkmap · nmap 深度扫描模块（可选功能，需本机安装 nmap）

- 调用本机 nmap 对指定目标做端口 + 服务指纹 + NSE 脚本扫描
- 命令基底：nmap -sT -sV --version-light -Pn -oX <xml> [档位] [脚本] [时序] <targets...>
  （TCP connect 扫描，无需管理员权限/Npcap）
- 支持目标语法：单 IP、CIDR（如 192.168.1.0/24）、范围（192.168.1.1-254）
- 边跑边解析 XML 统计已完成主机数作为进度；结束后解析并持久化到 nmap_results.json
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

import paths

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

DATA_FILE = paths.data_file("nmap_results.json")
XML_FILE = paths.data_file("nmap-last.xml")

MAX_TARGETS = 64        # 单次扫描目标条目上限（CIDR/范围算一条）
MAX_RUNTIME = 1500      # 最长运行 25 分钟（全端口/漏洞脚本会更久）

# 端口档位 -> nmap 参数
PROFILES = {
    "fast": ["--top-ports", "200"],
    "standard": [],
    "full": ["-p-"],
}

# 信息类 NSE 脚本（均为纯网络探测，无需 Npcap/管理员）
INFO_SCRIPTS = "http-title,http-server-header,smb-os-discovery,ssl-cert,ftp-anon"

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

_lock = threading.Lock()
_state = {"running": False, "phase": "", "progress": 0, "detail": "",
          "last_ts": 0, "error": None}
_thread: threading.Thread | None = None

_store = None


def _load_store():
    try:
        with open(DATA_FILE, encoding="utf-8") as f:
            data = json_load(f.read())
            if isinstance(data, dict) and isinstance(data.get("results"), dict):
                return data
    except Exception:
        pass
    return {"last_ts": 0, "results": {}}


def json_load(text):
    import json
    return json.loads(text)


def json_dump(obj, path):
    import json
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


_store = _load_store()


def _set(**kw):
    with _lock:
        _state.update(kw)


def snapshot() -> dict:
    with _lock:
        return dict(_state)


def store_snapshot() -> dict:
    with _lock:
        return {"last_ts": _store["last_ts"],
                "results": dict(_store["results"])}


def nmap_exe() -> str | None:
    """定位 nmap：优先 PATH，其次常见安装位置（便于 exe 分发后直接可用）"""
    found = shutil.which("nmap")
    if found:
        return found
    candidates = []
    scoop = os.environ.get("SCOOP")
    for base in (scoop, r"D:\scoop",
                 os.path.join(os.path.expanduser("~"), "scoop"),
                 r"C:\ProgramData\scoop"):
        if base:
            candidates.append(os.path.join(base, "shims", "nmap.exe"))
    candidates += [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def valid_target(t: str) -> bool:
    """单 IP / CIDR（>=/20，避免误扫超大网段）/ IP 范围"""
    t = (t or "").strip()
    if not t:
        return False
    if _IP_RE.match(t):
        return True
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$", t)
    if m:
        return (20 <= int(m.group(2)) <= 32
                and all(0 <= int(x) <= 255 for x in m.group(1).split(".")))
    # 192.168.1.1-254 形式
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){2})\.(\d{1,3})-(\d{1,3})$", t)
    if m and all(0 <= int(x) <= 255 for x in m.groups()):
        return int(m.group(2)) <= int(m.group(3))
    # 192.168.1.1-192.168.1.254 形式
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}(?:\.\d{1,3}){3}$", t):
        return True
    return False


def valid_ip(ip: str) -> bool:
    return bool(_IP_RE.match(ip or ""))


def _find_scoop_ps() -> str | None:
    for base in (os.environ.get("SCOOP", ""), r"D:\scoop",
                 os.path.join(os.path.expanduser("~"), "scoop")):
        if base:
            p = os.path.join(base, "apps", "scoop", "current", "bin", "scoop.ps1")
            if os.path.isfile(p):
                return p
    return None


def _nmap_healthy(exe: str) -> bool:
    """nmap --version 能否正常返回（本机某安全/网络组件曾两次篡改其加密库导致崩溃）"""
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True,
                           errors="ignore", timeout=20,
                           creationflags=CREATE_NO_WINDOW)
        return r.returncode == 0
    except Exception:
        return False


def _repair_nmap() -> tuple[bool, str]:
    """自愈：用 scoop 重装（本地缓存，无需联网，约 15 秒）"""
    ps = _find_scoop_ps()
    if not ps:
        return False, "未找到 scoop，无法自动修复，请手动重装 nmap"
    common = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
              "-File", ps]
    try:
        subprocess.run(common + ["uninstall", "nmap"], capture_output=True,
                       text=True, errors="ignore", timeout=120,
                       creationflags=CREATE_NO_WINDOW)
        subprocess.run(common + ["install", "nmap"], capture_output=True,
                       text=True, errors="ignore", timeout=240,
                       creationflags=CREATE_NO_WINDOW)
    except Exception as e:
        return False, f"修复过程异常: {e}"
    exe = nmap_exe()
    if exe and _nmap_healthy(exe):
        return True, ""
    return False, "重装后仍无法运行"


def start(targets: list[str], opts: dict | None = None) -> bool:
    """启动一次 nmap 深度扫描（后台线程），进行中则返回 False"""
    global _thread
    opts = opts or {}
    profile = opts.get("profile") if opts.get("profile") in PROFILES else "standard"
    timing = opts.get("timing") if opts.get("timing") in (3, 4) else 4
    scripts = [s for s in (opts.get("scripts") or []) if s in ("info", "vuln")]

    exe = nmap_exe()
    if not exe:
        _set(error="未检测到 nmap，请先安装（winget install Insecure.Nmap）")
        return False
    targets = [t.strip() for t in targets if valid_target(t)][:MAX_TARGETS]
    if not targets:
        _set(error="没有有效的扫描目标")
        return False
    known_total = len(targets) if all(_IP_RE.match(t) for t in targets) else 0

    # 健康检查：nmap 被篡改时自动修复
    with _lock:
        if _state["running"]:
            return False
        _state.update(running=True, phase="检查 nmap 可用性", progress=1,
                      detail="", error=None)
    if not _nmap_healthy(exe):
        _set(phase="nmap 已损坏，正在自动修复（scoop 重装）", detail="")
        ok, msg = _repair_nmap()
        exe = nmap_exe() or ""
        if not ok or not exe:
            _set(running=False,
                 error="自动修复失败：" + msg +
                       "。可手动执行：scoop uninstall nmap 后再 scoop install nmap")
            return False
        _set(detail="修复成功")

    cmd = [exe, "-sT", "-sV", "--version-light", f"-T{timing}", "-Pn"]
    cmd += PROFILES[profile]
    script_spec = ",".join((["vuln"] if "vuln" in scripts else [])
                           + ([INFO_SCRIPTS] if "info" in scripts else []))
    if script_spec:
        cmd += ["--script", script_spec]
    cmd += ["-oX", XML_FILE] + targets

    with _lock:
        _state.update(phase="准备中", detail=" ".join(targets))
        _thread = threading.Thread(target=_run, args=(cmd, targets, known_total),
                                   name="nmap-scan", daemon=True)
        _thread.start()
        return True


def _run(cmd: list[str], targets: list[str], known_total: int):
    t0 = time.time()
    try:
        _set(phase="启动 nmap", progress=2, detail=" ".join(targets))
        try:  # 删除上一轮的 XML，避免 nmap 失败时误用旧结果
            os.remove(XML_FILE)
        except OSError:
            pass
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE,
                                creationflags=CREATE_NO_WINDOW)
        while proc.poll() is None:
            time.sleep(2)
            if time.time() - t0 > MAX_RUNTIME:
                proc.kill()
                _set(error="扫描超时已终止（>25 分钟）", phase="超时", detail="")
                break
            done = _count_hosts_done(XML_FILE)
            elapsed = int(time.time() - t0)
            if known_total:
                _set(phase="nmap 深度扫描",
                     progress=min(95, max(3, int(100 * done / known_total))),
                     detail="{}/{} 台 · 已进行 {}s".format(
                         min(done, known_total), known_total, elapsed))
            else:  # 含 CIDR/范围时总数未知，显示已扫描主机数
                _set(phase="nmap 深度扫描", progress=50,
                     detail="已扫描 {} 台主机 · 已进行 {}s".format(done, elapsed))

        code = proc.poll()
        try:
            err_tail = (proc.stderr.read() or "").strip()[-400:]
        except Exception:
            err_tail = ""
        results = _parse_xml(XML_FILE) if os.path.isfile(XML_FILE) else {}
        if results and code in (0, 1):
            _merge_results(results)
            _set(phase="完成", progress=100,
                 detail="{} 台主机有结果".format(len(results)),
                 last_ts=time.time())
        elif results:
            _merge_results(results)  # 保留已得到的部分结果
            _set(error=_crash_hint(code, err_tail), phase="出错",
                 detail="已解析 {} 台主机的部分结果".format(len(results)))
        else:
            _set(error=_crash_hint(code, err_tail), phase="出错", detail="")
    except Exception as e:
        _set(error=f"{type(e).__name__}: {e}", phase="出错", detail="")
    finally:
        _set(running=False)


def _crash_hint(code: int, err_tail: str = "") -> str:
    """把 nmap 的退出码翻译成可操作的提示"""
    base = f"nmap 异常退出（退出码 {code}）"
    if code in (3221225477, 3221225725):  # 0xC0000005 / 0xC00000FD 原生崩溃
        return base + "：nmap 进程崩溃。可能是系统内存不足；若此前扫描一直正常，" \
                      "更可能是其加密库（libcrypto/libssh2）被系统内某些安全或网络组件篡改" \
                      "——再次发起深度扫描会自动检测并修复"
    return base + (f"：{err_tail[:200]}" if err_tail else "，未产生扫描结果")


def _count_hosts_done(path: str) -> int:
    """nmap 会把完成的 <host> 元素逐步写入 XML，用它估算进度"""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read().count("</host>")
    except OSError:
        return 0


def _merge_results(results: dict):
    with _lock:
        _store["results"].update(results)
        _store["last_ts"] = time.time()
        try:
            json_dump(_store, DATA_FILE)
        except Exception:
            pass


def _parse_xml(path: str) -> dict:
    """解析 nmap XML 输出 -> {ip: {status, hostname, mac, vendor, ports[], scripts[], os_match}}"""
    try:
        tree = ET.parse(path)
    except (OSError, ET.ParseError):
        return {}
    root = tree.getroot()
    results: dict = {}
    for host in root.findall("host"):
        addrs: dict = {}
        for a in host.findall("address"):
            addrs[a.get("addrtype") or ""] = (
                a.get("addr") or "", a.get("vendor") or "")
        ip = addrs.get("ipv4", ("", ""))[0]
        if not ip:
            continue
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name") or ""
        ports: list = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc = p.find("service")
                name = svc.get("name") if svc is not None else ""
                tunnel = svc.get("tunnel") if svc is not None else ""
                label = name or ""
                if tunnel == "ssl" and name == "https":
                    label = "https(ssl)"
                pscripts = [{"id": s.get("id") or "",
                             "output": (s.get("output") or "")[:600]}
                            for s in p.findall("script")]
                ports.append({
                    "port": int(p.get("portid") or 0),
                    "proto": p.get("protocol") or "tcp",
                    "service": label,
                    "product": (svc.get("product") if svc is not None else "") or "",
                    "version": (svc.get("version") if svc is not None else "") or "",
                    "scripts": pscripts,
                })
        # 主机级 NSE 脚本输出（如 smb-os-discovery）
        host_scripts = []
        hs = host.find("hostscript")
        if hs is not None:
            host_scripts = [{"id": s.get("id") or "",
                             "output": (s.get("output") or "")[:600]}
                            for s in hs.findall("script")]
        # OS 识别（仅当启用 -O 且有权限时 nmap 才输出）
        os_match = None
        osm = host.find("os/osmatch")
        if osm is not None:
            os_match = {"name": osm.get("name") or "",
                        "accuracy": osm.get("accuracy") or ""}
        st_el = host.find("status")
        status = st_el.get("state") if st_el is not None else ""
        mac, vendor = addrs.get("mac", ("", ""))
        results[ip] = {
            "ip": ip,
            "status": status,
            "hostname": hostname,
            "mac": (mac or "").upper().replace("-", ":"),
            "vendor": vendor or "",
            "ports": ports,
            "scripts": host_scripts,
            "os_match": os_match,
            "ts": int(time.time()),
        }
    return results
