/* ============ networkmap · 前端逻辑 ============ */
"use strict";

const $ = s => document.querySelector(s);
const els = {
  netinfo: $("#netinfo"), progWrap: $("#progWrap"), progBar: $("#progBar"),
  phaseText: $("#phaseText"), detailText: $("#detailText"),
  nmapBtn: $("#nmapBtn"),
  nmapProgWrap: $("#nmapProgWrap"), nmapProgBar: $("#nmapProgBar"),
  nmapPhaseText: $("#nmapPhaseText"), nmapDetailText: $("#nmapDetailText"),
  nmapHelp: $("#nmapHelp"), nmapHelpClose: $("#nmapHelpClose"),
  nmapHelpRetry: $("#nmapHelpRetry"), nmapHelpOk: $("#nmapHelpOk"),
  nmapOpts: $("#nmapOpts"), nmapOptsClose: $("#nmapOptsClose"),
  nmapOptsCancel: $("#nmapOptsCancel"), nmapOptsGo: $("#nmapOptsGo"),
  nmapTargets: $("#nmapTargets"), nmapProfile: $("#nmapProfile"),
  nmapTiming: $("#nmapTiming"), nmapScriptInfo: $("#nmapScriptInfo"),
  nmapScriptVuln: $("#nmapScriptVuln"),
  histBtn: $("#histBtn"), histOv: $("#histOv"), histClose: $("#histClose"),
  histList: $("#histList"), histDiff: $("#histDiff"),
  reportBtn: $("#reportBtn"),
  mapBtn: $("#mapBtn"), mapPanel: $("#mapPanel"),
  mapGrid: $("#mapGrid"), mapSubnet: $("#mapSubnet"),
  grid: $("#grid"), empty: $("#empty"), lastScan: $("#lastScan"),
  q: $("#q"), chips: $("#chips"),
  scanBtn: $("#scanBtn"), emptyScan: $("#emptyScan"),
  themeBtn: $("#themeBtn"), csvBtn: $("#csvBtn"),
  overlay: $("#overlay"), mIco: $("#mIco"), mIp: $("#mIp"), mHost: $("#mHost"),
  mInfo: $("#mInfo"), mNmap: $("#mNmap"), mAlias: $("#mAlias"), mNote: $("#mNote"),
  mSave: $("#mSave"), mCancel: $("#mCancel"), mDel: $("#mDel"), mClose: $("#mClose"),
  toast: $("#toast"),
};

const S = {
  info: null, devices: [], scanning: false, phase: "", progress: 0, detail: "",
  last_ts: 0, duration: 0, error: null, nmap: null,
  filter: "all", q: "", editingKey: null, firstLoadDone: false,
};

/* ---------------- 工具 ---------------- */
const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const ipNum = ip => ip.split(".").map(Number);

function toast(msg) {
  els.toast.textContent = msg;
  els.toast.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { els.toast.hidden = true; }, 1800);
}

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const p = n => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function relTime(ts) {
  if (!ts) return "未扫描";
  const diff = Math.max(0, Date.now() / 1000 - ts);
  if (diff < 60) return "刚刚";
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`;
  return `${Math.floor(diff / 86400)} 天前`;
}

function deviceIcon(d) {
  if (d.is_gateway) return "🌐";
  if (d.proxy_confirmed) return "🛡️";
  if (d.is_self) return "💻";
  if (!d.alive) return "💤";
  const v = ((d.vendor || "") + " " + (d.hostname || "")).toLowerCase();
  if (/xiaomi|mi |redmi|huawei|iphone|android|honor|oppo|vivo|oneplus|samsung|phone/.test(v)) return "📱";
  if (/synology|nas|raspberry/.test(v)) return "🗄️";
  if (/esp|espressif|tuya/.test(v)) return "🔌";
  return "🖥️";
}

/* ---------------- 数据 ---------------- */
async function getState() {
  const r = await fetch("/api/state");
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

async function post(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return r.json();
}

async function refresh() {
  try {
    const st = await getState();
    Object.assign(S, {
      info: st.info, devices: st.devices, scanning: st.scanning,
      phase: st.phase, progress: st.progress, detail: st.detail,
      last_ts: st.last_ts, duration: st.duration, error: st.error,
      nmap: st.nmap || null,
    });
    render();
    S.firstLoadDone = true;
    // 首次打开且从未扫描过 → 自动开始一次扫描
    if (S.firstLoadDone && !S.scanning && !S.last_ts && !autoScanTried) {
      autoScanTried = true;
      startScan();
    }
  } catch (e) {
    els.netinfo.innerHTML = `<span class="ni-item">⚠️ 无法连接后端服务，请确认 server.py 正在运行</span>`;
  }
}

let autoScanTried = false;

async function startScan() {
  try {
    await post("/api/scan");
    toast("开始扫描当前网段…");
    setTimeout(refresh, 400);
  } catch (e) { toast("触发扫描失败"); }
}

/* ---------------- 渲染 ---------------- */
function render() {
  renderNetInfo();
  renderProgress();
  renderNmapProgress();
  renderChips();
  renderMap();
  renderGrid();
  renderFooter();
  document.title = S.scanning
    ? `扫描中 ${S.progress}% · networkmap`
    : (S.nmap && S.nmap.running ? `nmap 深度扫描中 · networkmap` : "networkmap · 局域网设备与代理网关发现");
}

/* ---------------- 子网地图 ---------------- */
let showMap = false;

function renderMap() {
  els.mapPanel.hidden = !showMap;
  if (!showMap) return;
  const myIp = (S.info && S.info.ip) || "";
  const parts = myIp.split(".");
  const prefix = parts.length === 4 ? parts.slice(0, 3).join(".") : "";
  els.mapSubnet.textContent = (S.info && S.info.scanned_subnet) || "";
  const cells = [];
  for (let i = 1; i <= 254; i++) {
    const ip = prefix + "." + i;
    const d = S.devices.find(x => x.ip === ip);
    let cls = "map-cell";
    let title = ip;
    if (d) {
      title = `${ip} · ${d.alias || d.hostname || d.vendor || (d.alive ? "在线" : "离线/ARP")}`;
      if (d.alive) cls += " alive";
      if (d.is_gateway) cls += " gw";
      if (d.proxy_confirmed || d.ports.length) cls += " px";
      if (d.has_note) cls += " noted";
    }
    cells.push(`<div class="${cls}" data-ip="${esc(ip)}" title="${esc(title)}"></div>`);
  }
  els.mapGrid.innerHTML = cells.join("");
}

function renderNmapProgress() {
  const n = S.nmap;
  if (!n) return;
  els.nmapProgWrap.hidden = !n.running;
  els.nmapBtn.disabled = n.running;
  els.nmapBtn.textContent = n.running ? `⏳ 深度扫描 ${n.progress}%` : "🎯 深度扫描";
  if (!n.running) return;
  els.nmapProgBar.style.width = Math.max(4, n.progress) + "%";
  els.nmapPhaseText.textContent = `${n.phase}…`;
  els.nmapDetailText.textContent = n.detail || "";
}

/* 深度扫描：打开选项弹窗（目标 / 端口档位 / NSE 脚本 / 速度） */
async function startNmapScan() {
  const n = S.nmap;
  if (!n) return;
  if (n.running) { toast("深度扫描正在进行中"); return; }
  if (!n.available) { els.nmapHelp.hidden = false; return; }
  if (!els.nmapTargets.value.trim()) {
    const ips = S.devices.filter(d => d.alive || d.is_gateway).map(d => d.ip);
    els.nmapTargets.value = ips.join(" ");
  }
  els.nmapOpts.hidden = false;
}

async function confirmNmapScan() {
  const targets = els.nmapTargets.value.trim();
  if (!targets) { toast("请填写扫描目标"); return; }
  const scripts = [];
  if (els.nmapScriptInfo.checked) scripts.push("info");
  if (els.nmapScriptVuln.checked) scripts.push("vuln");
  const body = {
    targets,
    profile: els.nmapProfile.value,
    timing: +els.nmapTiming.value,
    scripts,
  };
  try {
    const r = await post("/api/nmap", body);
    if (r.ok && r.started) {
      els.nmapOpts.hidden = true;
      toast(`深度扫描 ${r.targets.length} 个目标…`);
    } else {
      toast(r.error || "启动失败");
    }
  } catch (e) { toast("请求失败，请检查后端服务"); }
  setTimeout(refresh, 400);
}

function renderNetInfo() {
  const i = S.info || {};
  const sp = i.system_proxy || {};
  const ni = [];
  if (i.iface) ni.push(item("📶", "网卡", esc(i.iface)));
  if (i.ip) ni.push(item("🖥️", "本机", esc(i.ip)));
  if (i.mac) ni.push(item("🏷️", "MAC", esc(i.mac)));
  if (i.gateway) ni.push(item("🌐", "网关", esc(i.gateway)));
  if (i.scanned_subnet) ni.push(item("🔎", "扫描范围", esc(i.scanned_subnet) + (i.clamped ? "（已截断）" : "")));
  if (sp.enabled && sp.host) {
    ni.push(`<span class="ni-item"><span class="ni-ico">🛡️</span>系统代理 <b>${esc(sp.host)}:${esc(sp.port)}</b></span><span class="ni-pill">已开启</span>`);
  } else if (sp.autoconfig) {
    ni.push(`<span class="ni-item"><span class="ni-ico">🛡️</span>PAC 脚本</span><span class="ni-pill">已配置</span>`);
  } else {
    ni.push(`<span class="ni-item"><span class="ni-ico">🛡️</span>系统代理</span><span class="ni-pill off">未开启</span>`);
  }
  els.netinfo.innerHTML = ni.join("");
  function item(ico, label, val) {
    return `<span class="ni-item"><span class="ni-ico">${ico}</span>${label} <b>${val}</b></span>`;
  }
}

function renderProgress() {
  els.progWrap.hidden = !S.scanning;
  els.progBar.style.width = (S.scanning ? Math.max(4, S.progress) : 0) + "%";
  els.phaseText.textContent = S.scanning ? `${S.phase}…` : "";
  els.detailText.textContent = S.scanning ? (S.detail || "") : "";
  els.scanBtn.disabled = S.scanning;
  els.scanBtn.textContent = S.scanning ? `⏳ 扫描中 ${S.progress}%` : "开始扫描";
}

function deviceCounts() {
  const c = { all: S.devices.length, alive: 0, gateway: 0, proxy: 0, noted: 0 };
  for (const d of S.devices) {
    if (d.alive) c.alive++;
    if (d.is_gateway) c.gateway++;
    if (d.proxy_confirmed || d.ports.length) c.proxy++;
    if (d.has_note) c.noted++;
  }
  return c;
}

function renderChips() {
  const c = deviceCounts();
  const labels = { all: "全部", alive: "在线", gateway: "网关", proxy: "代理", noted: "有备注" };
  for (const chip of els.chips.querySelectorAll(".chip[data-f]")) {
    const f = chip.dataset.f;
    chip.textContent = `${labels[f]} ${c[f]}`;
    chip.classList.toggle("on", S.filter === f);
  }
}

function matchFilter(d) {
  if (S.filter === "alive" && !d.alive) return false;
  if (S.filter === "gateway" && !d.is_gateway) return false;
  if (S.filter === "proxy" && !(d.proxy_confirmed || d.ports.length)) return false;
  if (S.filter === "noted" && !d.has_note) return false;
  if (S.q) {
    const hay = [d.ip, d.mac, d.vendor, d.hostname, d.alias, d.note, d.os_guess,
      ...d.ports.map(p => `${p.port} ${p.name} ${p.kind}`)].join(" ").toLowerCase();
    if (!hay.includes(S.q)) return false;
  }
  return true;
}

function sortOrder(d) {
  // 网关 > 代理 > 本机 > 其它；组内按 IP 数值
  if (d.is_gateway) return 0;
  if (d.proxy_confirmed || d.ports.length) return 1;
  if (d.is_self) return 2;
  return 3;
}

function renderGrid() {
  const list = S.devices.filter(matchFilter)
    .sort((a, b) => sortOrder(a) - sortOrder(b)
      || ipNum(a.ip).reduce((s, n) => s * 1000 + n, 0) - ipNum(b.ip).reduce((s, n) => s * 1000 + n, 0));
  els.empty.hidden = !(S.last_ts && !list.length) && !(S.last_ts === 0 && !S.scanning && S.firstLoadDone);
  if (!S.last_ts && !S.scanning) { els.grid.innerHTML = ""; return; }
  els.grid.innerHTML = list.map(card).join("");
  for (const el of els.grid.querySelectorAll(".card")) {
    el.addEventListener("click", () => openModal(el.dataset.key));
  }
}

function card(d) {
  const badges = [];
  if (d.is_gateway) badges.push(`<span class="badge gw">网关</span>`);
  if (d.is_self) badges.push(`<span class="badge self">本机</span>`);
  if (d.sys_proxy_target) badges.push(`<span class="badge sys">系统代理指向</span>`);
  if (d.proxy_confirmed) badges.push(`<span class="badge px">代理 · ${esc(d.proxy_kinds.join(" / "))}</span>`);
  else if (d.ports.length) badges.push(`<span class="badge px2">开放代理端口</span>`);
  if (d.nmap_ports) badges.push(`<span class="badge nmap">深度扫描 · ${d.nmap_ports} 端口</span>`);
  if (d.has_note) badges.push(`<span class="badge nt">备注</span>`);

  const ports = d.ports.map(p => {
    const hot = p.kind === "HTTP" || p.kind === "SOCKS5";
    const kind = p.kind ? ` · ${esc(p.kind)}` : "";
    return `<span class="port${hot ? " hot" : ""}">${p.port} ${esc(p.name)}${kind}</span>`;
  }).join("");
  const nmapPorts = d.nmap && d.nmap.ports && d.nmap.ports.length ? d.nmap.ports : [];
  const nmapChips = nmapPorts.slice(0, 4).map(p => {
    const label = [p.service, p.product].filter(Boolean).join(" ") || p.proto;
    return `<span class="port nmap">${p.port} ${esc(label)}</span>`;
  }).join("") + (nmapPorts.length > 4
    ? `<span class="port nmap">+${nmapPorts.length - 4} 更多</span>` : "");

  const alias = d.alias || "";
  const note = d.note || "";
  const noteHtml = d.has_note
    ? `<em>${alias ? `<span class="n-alias">📝 ${esc(alias)}</span>` : `<span>📝</span>`}${note ? `<span class="n-text">${esc(note)}</span>` : ""}</em>`
    : `<span class="n-hint">点击添加备注…</span>`;

  const cls = ["card", d.is_gateway ? "gw" : "", (d.proxy_confirmed || d.ports.length) ? "px" : "",
    d.is_self ? "self" : "", d.alive ? "" : "off"].filter(Boolean).join(" ");

  const host = esc(d.alias || d.hostname || d.vendor || (d.alive ? "在线" : "离线 / ARP 记录"));
  const meta = [
    d.mac ? "MAC " + d.mac : "MAC —",
    d.vendor || "",
    d.os_guess || "",
  ].filter(Boolean).join(" · ");

  return `<div class="${cls}" data-key="${esc(d.key)}">
    <div class="c-top">
      <span class="c-ico">${deviceIcon(d)}</span>
      <div class="c-t"><span class="c-ip">${esc(d.ip)}</span><span class="c-host">${host}</span></div>
      <span class="c-edit">✎ 备注</span>
    </div>
    <div class="c-badges">${badges.join("")}</div>
    ${ports ? `<div class="c-ports">${ports}</div>` : ""}
    ${nmapChips ? `<div class="c-ports">${nmapChips}</div>` : ""}
    <div class="c-meta">${esc(meta)}</div>
    <div class="c-note">${noteHtml}</div>
  </div>`;
}

function renderFooter() {
  const parts = [];
  parts.push(S.last_ts
    ? `上次扫描 ${fmtTime(S.last_ts)}（${relTime(S.last_ts)}${S.duration ? ` · 耗时 ${S.duration}s` : ""}）`
    : "未扫描");
  if (S.nmap && S.nmap.last_ts) {
    parts.push(`深度扫描 ${fmtTime(S.nmap.last_ts)}（${S.nmap.count} 台有结果）`);
  }
  if (S.nmap && S.nmap.error) parts.push(`⚠️ 深度扫描：${S.nmap.error}`);
  els.lastScan.textContent = parts.join("　·　");
}

/* ---------------- 备注弹窗 ---------------- */
function openModal(key) {
  const d = S.devices.find(x => x.key === key);
  if (!d) return;
  S.editingKey = key;
  els.mIco.textContent = deviceIcon(d);
  els.mIp.textContent = d.ip;
  els.mHost.textContent = [d.hostname, d.vendor, d.mac].filter(Boolean).join(" · ") || "—";
  const ports = d.ports.length
    ? d.ports.map(p => `${p.port}(${p.name}${p.kind ? "/" + p.kind : ""})`).join("、")
    : "无";
  const via = { ping: "Ping", tcp: "TCP", arp: "ARP" };
  els.mInfo.innerHTML =
    `状态：<b>${d.alive ? "在线" : "离线"}</b>　发现方式：<b>${d.via.map(v => via[v] || v).join("+") || "—"}</b><br>` +
    `MAC：<b>${esc(d.mac || "—")}</b>　厂商：<b>${esc(d.vendor || "未知")}</b><br>` +
    `主机名：<b>${esc(d.hostname || "—")}</b>　系统猜测：<b>${esc(d.os_guess || "—")}</b><br>` +
    `开放端口：<b>${esc(ports)}</b>` +
    (d.proxy_kinds.length ? `　代理类型：<b>${esc(d.proxy_kinds.join("、"))}</b>` : "");
  els.mAlias.value = d.alias || "";
  els.mNote.value = d.note || "";
  // nmap 深度扫描结果区块（端口 / 服务指纹 / NSE 脚本 / OS 猜测）
  const nm = d.nmap;
  const nmPorts = (nm && nm.ports) || [];
  const nmScripts = (nm && nm.scripts) || [];
  if (nmPorts.length || nmScripts.length) {
    const fmtOut = s => esc(String(s.output || "").replace(/\s+/g, " ").trim().slice(0, 200) || "（无输出）");
    const rows = nmPorts.map(p => {
      const prod = [p.product, p.version].filter(Boolean).join(" ");
      const sc = (p.scripts || []).map(s =>
        `<div class="nm-script">└ <b>${esc(s.id)}</b>：${fmtOut(s)}</div>`).join("");
      return `<div class="nm-row">
        <span class="nm-port">${p.port}/${esc(p.proto)}</span>
        <span class="nm-svc">${esc(p.service || "未知服务")}</span>
        <span class="nm-prod">${esc(prod || "—")}</span>${sc}
      </div>`;
    }).join("");
    const hs = nmScripts.map(s =>
      `<div class="nm-row"><span class="nm-svc">${esc(s.id)}</span><span class="nm-prod">${fmtOut(s)}</span></div>`).join("");
    const os = nm.os_match
      ? `<div class="nm-row"><span class="nm-svc">OS 猜测</span><span class="nm-prod">${esc(nm.os_match.name)}（准确率 ${esc(nm.os_match.accuracy)}%）</span></div>`
      : "";
    const host = nm.hostname ? `　nmap 主机名：<b>${esc(nm.hostname)}</b>` : "";
    els.mNmap.innerHTML =
      `<h3>🎯 nmap 深度扫描 · ${nmPorts.length} 个开放端口${host}</h3>${os}${rows}${hs}`;
    els.mNmap.hidden = false;
  } else {
    els.mNmap.hidden = true;
    els.mNmap.innerHTML = "";
  }
  els.overlay.hidden = false;
  els.mAlias.focus();
}

function closeModal() { els.overlay.hidden = true; S.editingKey = null; }

async function saveNote(del) {
  const key = S.editingKey;
  if (!key) return;
  const body = {
    key,
    alias: del ? "" : els.mAlias.value,
    note: del ? "" : els.mNote.value,
  };
  const r = await post("/api/notes", body);
  if (r.ok) {
    const d = S.devices.find(x => x.key === key);
    if (d) {
      d.alias = body.alias; d.note = body.note;
      d.has_note = !!(body.alias || body.note);
    }
    closeModal(); render();
    toast(del ? "备注已删除" : "备注已保存");
  } else {
    toast("保存失败：" + (r.error || "未知错误"));
  }
}

/* ---------------- 导出 CSV ---------------- */
function exportCSV() {
  if (!S.devices.length) { toast("还没有可导出的数据"); return; }
  const rows = [["IP", "MAC", "厂商", "主机名", "备注名称", "备注", "状态", "系统猜测", "发现方式", "代理端口", "nmap端口", "标签"]];
  for (const d of S.devices.slice().sort((a, b) =>
    ipNum(a.ip).reduce((s, n) => s * 1000 + n, 0) - ipNum(b.ip).reduce((s, n) => s * 1000 + n, 0))) {
    const tags = [];
    if (d.is_gateway) tags.push("网关");
    if (d.proxy_confirmed) tags.push("代理:" + d.proxy_kinds.join("/"));
    if (d.is_self) tags.push("本机");
    if (d.sys_proxy_target) tags.push("系统代理指向");
    const nmapSummary = d.nmap && d.nmap.ports ? d.nmap.ports
      .map(p => `${p.port}/${p.proto} ${[p.service, p.product].filter(Boolean).join(" ")}`.trim())
      .join("、") : "";
    rows.push([
      d.ip, d.mac, d.vendor, d.hostname, d.alias, d.note,
      d.alive ? "在线" : "离线", d.os_guess,
      d.via.map(v => ({ ping: "Ping", tcp: "TCP", arp: "ARP" }[v] || v)).join("+"),
      d.ports.map(p => `${p.port} ${p.name}${p.kind ? "(" + p.kind + ")" : ""}`).join(" "),
      nmapSummary,
      tags.join(" "),
    ]);
  }
  const csv = "\ufeff" + rows.map(r =>
    r.map(v => `"${String(v ?? "").replace(/"/g, '""')}"`).join(",")).join("\r\n");
  const a = document.createElement("a");
  const dt = new Date();
  const p = n => String(n).padStart(2, "0");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  a.download = `lan-devices-${dt.getFullYear()}${p(dt.getMonth() + 1)}${p(dt.getDate())}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast("已导出 CSV");
}

/* ---------------- 扫描历史与变化对比（对标 Ndiff） ---------------- */
async function openHistory() {
  els.histOv.hidden = false;
  els.histDiff.hidden = true;
  try {
    const r = await fetch("/api/history").then(x => x.json());
    renderHistList(r.items || []);
  } catch (e) {
    els.histList.innerHTML = `<div class="hd-none">无法读取历史</div>`;
  }
}

function renderHistList(items) {
  if (!items.length) {
    els.histList.innerHTML = `<div class="hd-none">暂无历史快照，执行一次常规扫描后自动记录（最多保留 30 份）。</div>`;
    return;
  }
  els.histList.innerHTML = items.map((it, idx) => `
    <div class="hist-row">
      <b>#${items.length - idx}</b>
      <span>${fmtTime(it.ts)}</span>
      <span class="h-meta">${relTime(it.ts)} · 设备 ${it.total} 台 / 在线 ${it.alive} · ${esc(it.subnet || "")}</span>
      <button class="btn" data-ts="${it.ts}">🔍 对比当前</button>
    </div>`).join("");
  for (const btn of els.histList.querySelectorAll("button[data-ts]")) {
    btn.addEventListener("click", () => showHistDiff(parseFloat(btn.dataset.ts)));
  }
}

async function showHistDiff(ts) {
  let item;
  try {
    const r = await fetch("/api/history?id=" + ts).then(x => x.json());
    item = r.item;
  } catch (e) { toast("读取快照失败"); return; }
  const base = {};
  for (const d of item.devices || []) base[d.ip] = d;
  const cur = {};
  for (const d of S.devices) cur[d.ip] = d;

  const added = [], gone = [], changed = [];
  for (const ip in cur) {
    const c = cur[ip], b = base[ip];
    if (!b) { if (c.alive) added.push(c); continue; }
    if (!b.alive && c.alive) added.push(c);
    if (b.alive && !c.alive) { gone.push({ ip, note: "离线" }); continue; }
    if (b.alive && c.alive) {
      const bs = new Set(b.ports || []);
      const cs = new Set([...(c.ports || []).map(p => p.port),
        ...((c.nmap && c.nmap.ports) || []).map(p => p.port)]);
      const addP = [...cs].filter(p => !bs.has(p));
      const rmP = [...bs].filter(p => !cs.has(p));
      const proxyChg = b.proxy_confirmed !== c.proxy_confirmed
        ? (c.proxy_confirmed ? "新确认为代理" : "代理已消失") : "";
      if (addP.length || rmP.length || proxyChg) {
        changed.push({ ip, add: addP.join(", "), rm: rmP.join(", "), proxy: proxyChg });
      }
    }
  }
  for (const ip in base) {
    if (base[ip].alive && !cur[ip]) gone.push({ ip, note: "已从设备列表消失" });
  }

  const row = c => esc(c.alias ? `${c.ip}（${c.alias}）` : c.ip);
  const sec = (title, n, cls, rows) =>
    `<h4>${title} ${n}</h4>` + (n ? rows : `<div class="hd-none">无</div>`);
  els.histDiff.innerHTML =
    `<div class="h-meta">对比基准：${fmtTime(item.ts)} 的快照 → 当前状态</div>` +
    sec("🟢 新上线", added.length, "hd-add",
      added.map(c => `<div class="hd-add">${row(c)}${c.hostname ? " · " + esc(c.hostname) : ""}</div>`).join("")) +
    sec("🔴 已离线 / 消失", gone.length, "hd-gone",
      gone.map(g => `<div class="hd-gone">${esc(g.ip)}${g.note ? " · " + esc(g.note) : ""}</div>`).join("")) +
    sec("🟡 端口 / 代理变化", changed.length, "hd-chg",
      changed.map(g => `<div class="hd-chg">${esc(g.ip)}${g.add ? ` · 新增端口: ${esc(g.add)}` : ""}${g.rm ? ` · 关闭端口: ${esc(g.rm)}` : ""}${g.proxy ? ` · ${esc(g.proxy)}` : ""}</div>`).join(""));
  els.histDiff.hidden = false;
}

/* ---------------- HTML 报告导出 ---------------- */
function exportReport() {
  if (!S.devices.length) { toast("还没有可导出的数据"); return; }
  const c = deviceCounts();
  const i = S.info || {};
  const sp = i.system_proxy || {};
  const sorted = S.devices.slice().sort((a, b) => sortOrder(a) - sortOrder(b)
    || ipNum(a.ip).reduce((s, n) => s * 1000 + n, 0) - ipNum(b.ip).reduce((s, n) => s * 1000 + n, 0));
  const rows = sorted.map(d => {
    const nmapPorts = ((d.nmap && d.nmap.ports) || [])
      .map(p => `${p.port} ${[p.service, p.product].filter(Boolean).join(" ")}`.trim()).join("、");
    const tags = [d.is_gateway ? "网关" : "", d.proxy_confirmed ? "代理:" + d.proxy_kinds.join("/") : "",
      d.is_self ? "本机" : "", d.sys_proxy_target ? "系统代理指向" : ""].filter(Boolean).join(" ");
    return `<tr class="${d.alive ? "" : "off"}">
      <td>${esc(d.ip)}</td><td>${esc(d.alias || d.hostname || "—")}</td>
      <td>${esc(d.mac || "—")}</td><td>${esc(d.vendor || "—")}</td>
      <td>${d.alive ? "在线" : "离线"}</td><td>${tags || "—"}</td>
      <td>${d.ports.map(p => `${p.port} ${esc(p.name)}${p.kind ? "(" + esc(p.kind) + ")" : ""}`).join("、") || "—"}</td>
      <td>${esc(nmapPorts || "—")}</td>
      <td>${esc(d.note || "")}</td></tr>`;
  }).join("");
  const dt = new Date();
  const p2 = n => String(n).padStart(2, "0");
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>networkmap · 扫描报告 ${dt.getFullYear()}-${p2(dt.getMonth() + 1)}-${p2(dt.getDate())}</title>
<style>
body{font-family:"Segoe UI","Microsoft YaHei",sans-serif;max-width:1080px;margin:30px auto;padding:0 24px;color:#1b2437;background:#fff}
h1{font-size:22px}.meta{color:#6b7690;font-size:13px;margin-bottom:18px;line-height:1.9}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{border:1px solid #e4e9f3;padding:7px 9px;text-align:left;vertical-align:top}
th{background:#f3f5fa}tr.off td{color:#9aa3b5;background:#fafbfe}
td{word-break:break-all}
</style></head><body>
<h1>🛰️ networkmap · 局域网扫描报告</h1>
<div class="meta">生成时间：${dt.toLocaleString("zh-CN")}<br>
网卡：${esc(i.iface || "—")} · 本机：${esc(i.ip || "—")} · 网关：${esc(i.gateway || "—")} · 扫描范围：${esc(i.scanned_subnet || "—")}<br>
系统代理：${sp.enabled ? esc(sp.server) + "（已开启）" : "未开启"} · 设备总数：${c.all} · 在线：${c.alive} · 代理节点：${c.proxy} · 有备注：${c.noted}</div>
<table><thead><tr><th>IP</th><th>名称</th><th>MAC</th><th>厂商</th><th>状态</th><th>标签</th><th>代理端口</th><th>nmap 端口/服务</th><th>备注</th></tr></thead>
<tbody>${rows}</tbody></table>
<p style="color:#9aa3b5;font-size:11px;margin-top:16px">由 networkmap生成${S.nmap && S.nmap.last_ts ? " · nmap 深度扫描时间 " + fmtTime(S.nmap.last_ts) : " · nmap 深度扫描未执行"}</p>
</body></html>`;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([html], { type: "text/html;charset=utf-8" }));
  a.download = `lan-report-${dt.getFullYear()}${p2(dt.getMonth() + 1)}${p2(dt.getDate())}.html`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast("HTML 报告已导出");
}

/* ---------------- 主题 ---------------- */
function applyTheme() {
  const saved = localStorage.getItem("lan.dark");
  const dark = saved === null
    ? window.matchMedia("(prefers-color-scheme: dark)").matches
    : saved === "1";
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  els.themeBtn.textContent = dark ? "☀️" : "🌙";
}
els.themeBtn.addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme !== "dark";
  localStorage.setItem("lan.dark", dark ? "1" : "0");
  applyTheme();
});

/* ---------------- 事件 ---------------- */
els.scanBtn.addEventListener("click", () => { if (!S.scanning) startScan(); });
els.emptyScan.addEventListener("click", startScan);
els.nmapBtn.addEventListener("click", startNmapScan);
els.nmapHelpClose.addEventListener("click", () => { els.nmapHelp.hidden = true; });
els.nmapHelpOk.addEventListener("click", () => { els.nmapHelp.hidden = true; });
els.nmapHelpRetry.addEventListener("click", async () => {
  await refresh();
  if (S.nmap && S.nmap.available) { els.nmapHelp.hidden = true; toast("已检测到 nmap，可以使用深度扫描了"); }
  else toast("仍未检测到 nmap，请安装后重试");
});
els.nmapHelp.addEventListener("click", e => { if (e.target === els.nmapHelp) els.nmapHelp.hidden = true; });
els.nmapOptsClose.addEventListener("click", () => { els.nmapOpts.hidden = true; });
els.nmapOptsCancel.addEventListener("click", () => { els.nmapOpts.hidden = true; });
els.nmapOptsGo.addEventListener("click", confirmNmapScan);
els.nmapOpts.addEventListener("click", e => { if (e.target === els.nmapOpts) els.nmapOpts.hidden = true; });
els.histBtn.addEventListener("click", openHistory);
els.histClose.addEventListener("click", () => { els.histOv.hidden = true; });
els.histOv.addEventListener("click", e => { if (e.target === els.histOv) els.histOv.hidden = true; });
els.reportBtn.addEventListener("click", exportReport);
els.mapBtn.addEventListener("click", () => {
  showMap = !showMap;
  els.mapBtn.classList.toggle("on", showMap);
  renderMap();
});
els.mapGrid.addEventListener("click", e => {
  const cell = e.target.closest(".map-cell");
  if (!cell) return;
  const d = S.devices.find(x => x.ip === cell.dataset.ip);
  if (d) openModal(d.key);
  else toast(cell.dataset.ip + " · 未知设备");
});
els.csvBtn.addEventListener("click", exportCSV);
els.chips.addEventListener("click", e => {
  const chip = e.target.closest(".chip");
  if (!chip || !chip.dataset.f) return;
  S.filter = chip.dataset.f;
  render();
});
els.q.addEventListener("input", () => { S.q = els.q.value.trim().toLowerCase(); render(); });
els.q.addEventListener("keydown", e => {
  if (e.key === "Enter" && S.q.match(/^\d{1,3}(\.\d{1,3}){3}$/)) {
    // 搜索的恰是一个 IP → 直接打开该设备备注
    const d = S.devices.find(x => x.ip === S.q);
    if (d) openModal(d.key);
  }
});
els.mSave.addEventListener("click", () => saveNote(false));
els.mDel.addEventListener("click", () => saveNote(true));
els.mCancel.addEventListener("click", closeModal);
els.mClose.addEventListener("click", closeModal);
els.overlay.addEventListener("click", e => { if (e.target === els.overlay) closeModal(); });
document.addEventListener("keydown", e => {
  if (e.key === "Escape") {
    closeModal();
    els.nmapHelp.hidden = true;
    els.nmapOpts.hidden = true;
    els.histOv.hidden = true;
  }
});

/* ---------------- 启动 ---------------- */
applyTheme();
refresh();
setInterval(refresh, 2200);
