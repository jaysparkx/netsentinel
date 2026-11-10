// NetSentinel front end — no framework, no CDN: it must work offline in the exam hall.

const $ = (sel) => document.querySelector(sel);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const pct = (x, d = 1) => (x == null ? "—" : `${(x * 100).toFixed(d)}%`);
const num = (x) => Number(x).toLocaleString("en-US");
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

// Every verdict maps to one of four colours.
function kindOf(label) {
  if (label === "normal") return "normal";
  if (label === "Unknown-Anomaly") return "unknown";
  if (label === "Probe" || label === "PortScan") return "probe";
  return "attack";
}
const COLOR = () => ({ normal: css("--calm"), probe: css("--scan"), attack: css("--breach"), unknown: css("--ghost") });

async function getJSON(url, options) {
  const res = await fetch(url, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || `${res.status} ${res.statusText}`);
  return body;
}

let STATUS = null;

// =================================================================== incidents (shared)
function incidentHTML(inc) {
  const s = inc.sample || inc;
  const route = s.src_ip ? `${s.src_ip} → ${s.dst_ip}${s.dst_port != null ? ":" + s.dst_port : ""}` : "";
  const meta = [
    inc.connections != null ? `${num(inc.connections)} connections` : null,
    inc.dst_ports != null && inc.dst_ports > 1 ? `${num(inc.dst_ports)} ports` : null,
    s.service ? `${s.protocol_type}/${s.service} ${s.flag}` : null,
  ].filter(Boolean).join(", ");
  const reasons = (inc.reasons || []).map((r) => {
    const z = r.z_score == null ? "" : ` <code>z=${r.z_score > 0 ? "+" : ""}${r.z_score.toFixed(1)}</code>`;
    return `<li><code>${esc(r.feature)}=${esc(r.value)}</code>${z} — ${esc(r.description)}</li>`;
  }).join("");
  return `<li class="incident" data-kind="${kindOf(inc.final_label || inc.label)}">
    <span class="bar"></span>
    <div class="who"><b>${esc(inc.final_label || inc.label)}</b>${esc(route)}<small>${esc(meta)}</small></div>
    <div class="why"><p>${esc(inc.description)}</p>${reasons ? `<ul>${reasons}</ul>` : ""}</div>
  </li>`;
}

// =================================================================== the tape
// A seismograph of connections: x = capture time, height = anomaly score (log scale),
// colour = final verdict, dashed line = the anomaly threshold.
class Tape {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.points = [];
    this.threshold = null;
    this.windowSec = 40;
    this.now = 0;
    this.targetNow = 0;
    this.staticDuration = null;
    this.markers = [];
    this.clock = null;          // live mode: a function returning "seconds since start"
    new ResizeObserver(() => this.resize()).observe(canvas);
    this.resize();
    if (!reducedMotion) requestAnimationFrame(() => this.loop());
  }
  resize() {
    const r = this.canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = Math.max(1, r.width * dpr);
    this.canvas.height = Math.max(1, r.height * dpr);
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.w = r.width; this.h = r.height;
    this.draw();
  }
  reset(threshold) { this.points = []; this.markers = []; this.threshold = threshold; this.now = this.targetNow = 0; this.staticDuration = null; }
  mark(t, text) { this.markers.push({ t, text }); }
  push(t, score, label) { this.points.push({ t, score, kind: kindOf(label) }); this.targetNow = t; if (reducedMotion) this.draw(); }
  showAll(points, threshold, duration) {
    this.points = points.map(([t, label, score]) => ({ t, score, kind: kindOf(label) }));
    this.threshold = threshold; this.staticDuration = Math.max(duration, 1); this.draw();
  }
  y(score) {
    const lo = -4, hi = 1, top = 18, bottom = this.h - 22;
    const v = Math.min(Math.max(Math.log10(Math.max(score, 1e-6)), lo), hi);
    return bottom - ((v - lo) / (hi - lo)) * (bottom - top);
  }
  loop() {
    if (this.clock) this.targetNow = this.clock();
    this.now += (this.targetNow - this.now) * 0.18;
    this.draw();
    requestAnimationFrame(() => this.loop());
  }
  draw() {
    const { ctx, w, h } = this;
    if (!w) return;
    ctx.clearRect(0, 0, w, h);
    const rule = css("--rule"), ash = css("--ash"), bone = css("--bone"), colors = COLOR();
    ctx.font = `11px ${css("--display")}`;
    // score gridlines (decades)
    for (let p = -4; p <= 1; p++) {
      const yy = this.y(10 ** p);
      ctx.strokeStyle = rule; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(0, yy + 0.5); ctx.lineTo(w, yy + 0.5); ctx.stroke();
      ctx.fillStyle = ash; ctx.fillText(`1e${p}`, 6, yy - 4);
    }
    const isStatic = this.staticDuration != null;
    const span = isStatic ? this.staticDuration : this.windowSec;
    const right = isStatic ? this.staticDuration : this.now;
    const x = (t) => w - 8 - ((right - t) / span) * (w - 60);
    const base = h - 22;
    for (const p of this.points) {
      const xx = x(p.t);
      if (xx < 50 || xx > w) continue;
      ctx.strokeStyle = colors[p.kind];
      ctx.globalAlpha = p.kind === "normal" ? 0.55 : 0.9;
      ctx.beginPath(); ctx.moveTo(xx + 0.5, base); ctx.lineTo(xx + 0.5, this.y(p.score)); ctx.stroke();
    }
    ctx.globalAlpha = 1;
    for (const m of this.markers) {          // attack launches from the attack range
      const xx = x(m.t);
      if (xx < 50 || xx > w) continue;
      ctx.strokeStyle = bone; ctx.setLineDash([2, 3]);
      ctx.beginPath(); ctx.moveTo(xx + 0.5, 4); ctx.lineTo(xx + 0.5, base); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = bone; ctx.fillText(m.text, xx + 5, 12);
    }
    if (this.threshold) {
      const ty = this.y(this.threshold);
      ctx.strokeStyle = bone; ctx.setLineDash([4, 4]);
      ctx.beginPath(); ctx.moveTo(50, ty + 0.5); ctx.lineTo(w, ty + 0.5); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = bone; ctx.fillText("anomaly threshold", w - 130, ty - 6);
    }
    ctx.fillStyle = ash;
    ctx.fillText(isStatic ? `0s — ${this.staticDuration.toFixed(0)}s` : `last ${this.windowSec}s${this.clock ? "" : " of capture time"}`, 56, h - 6);
  }
}

const tape = new Tape($("#tape-canvas"));
let replaySource = null, replayPaused = false;
const counts = { conn: 0, alert: 0, probe: 0, unknown: 0 };

function setStats(t) {
  $("#s-conn").textContent = num(counts.conn);
  $("#s-alert").textContent = num(counts.alert);
  $("#s-probe").textContent = num(counts.probe);
  $("#s-unknown").textContent = num(counts.unknown);
  if (t != null) $("#s-time").textContent = `${t.toFixed(1)}s`;
}

function pushFeed(listEl, inc, max = 8) {
  listEl.insertAdjacentHTML("afterbegin", incidentHTML(inc));
  while (listEl.children.length > max) listEl.lastElementChild.remove();
}

async function startReplay() {
  replaySource?.close();
  Object.keys(counts).forEach((k) => (counts[k] = 0));
  setStats(0);
  $("#tape-feed").innerHTML = "";
  const sample = $("#tape-sample").value;
  if (!sample) return;

  if (reducedMotion) {   // no animation: show the whole capture at once
    const data = await getJSON("/api/analyze", { method: "POST", body: form({ sample, custom: true }) });
    tape.showAll(data.tape, data.threshold, data.duration_s);
    data.incidents.slice(0, 8).forEach((inc) => pushFeed($("#tape-feed"), inc));
    return;
  }
  const speed = $("#tape-speed").value;
  replaySource = new EventSource(`/api/replay?sample=${encodeURIComponent(sample)}&speed=${speed}&custom=true`);
  replaySource.addEventListener("meta", (e) => tape.reset(JSON.parse(e.data).threshold));
  replaySource.addEventListener("conn", (e) => {
    const ev = JSON.parse(e.data);
    tape.push(ev.t, ev.score, ev.label);
    counts.conn++;
    if (ev.label !== "normal") counts.alert++;
    if (kindOf(ev.label) === "probe") counts.probe++;
    if (ev.label === "Unknown-Anomaly") counts.unknown++;
    setStats(ev.t);
    if (ev.incident) pushFeed($("#tape-feed"), { ...ev, ...ev.incident, sample: ev });
  });
  replaySource.addEventListener("end", () => {
    replaySource.close();
    setTimeout(() => { if (!replayPaused) startReplay(); }, 4000);   // loop for the demo
  });
  replaySource.onerror = () => replaySource.close();
}

$("#tape-play").addEventListener("click", (e) => {
  replayPaused = !replayPaused;
  e.currentTarget.textContent = replayPaused ? "Play" : "Pause";
  if (replayPaused) replaySource?.close(); else startReplay();
});
$("#tape-speed").addEventListener("change", () => !replayPaused && startReplay());
$("#tape-sample").addEventListener("change", () => !replayPaused && startReplay());

function form(obj) {
  const fd = new FormData();
  Object.entries(obj).forEach(([k, v]) => fd.append(k, v));
  return fd;
}

// =================================================================== charts (plain SVG)
function hbars(rows, { max = 1, width = 560, label = 150, row = 30, fmt = pct } = {}) {
  const colors = COLOR();
  const h = rows.length * row + 6;
  const inner = width - label - 70;
  const body = rows.map((r, i) => {
    const y = i * row + 4;
    const bw = Math.max(1, (r.value / max) * inner);
    return `<text x="0" y="${y + 15}">${esc(r.label)}</text>
      <rect x="${label}" y="${y + 3}" width="${inner}" height="16" fill="none" stroke="${css("--rule")}"/>
      <rect x="${label}" y="${y + 3}" width="${bw}" height="16" fill="${colors[r.kind] || r.color}"/>
      <text class="val" x="${label + inner + 10}" y="${y + 15}">${fmt(r.value)}</text>`;
  }).join("");
  return `<svg viewBox="0 0 ${width} ${h}" role="img">${body}</svg>`;
}

function pairedBars(cats, { width = 560, label = 120 } = {}) {
  const ash = css("--ash"), ghost = css("--ghost");
  const rowH = 44, inner = width - label - 70;
  const body = cats.map((c, i) => {
    const y = i * rowH + 4;
    return `<text x="0" y="${y + 20}">${esc(c.name)}</text>
      <rect x="${label}" y="${y + 4}" width="${Math.max(1, c.clf * inner)}" height="12" fill="${ash}"/>
      <text class="val" x="${label + inner + 10}" y="${y + 14}">${pct(c.clf, 0)}</text>
      <rect x="${label}" y="${y + 20}" width="${Math.max(1, c.hyb * inner)}" height="12" fill="${ghost}"/>
      <text class="val" x="${label + inner + 10}" y="${y + 30}">${pct(c.hyb, 0)}</text>`;
  }).join("");
  const legend = `<text x="${label}" y="${cats.length * rowH + 20}"><tspan fill="${ash}">■ classifier only</tspan>   <tspan fill="${ghost}">■ hybrid</tspan></text>`;
  return `<svg viewBox="0 0 ${width} ${cats.length * rowH + 28}" role="img">${body}${legend}</svg>`;
}

function curve(points, { width = 560, height = 300 } = {}) {
  if (!points.length) return `<p class="empty-note">No threshold analysis for this run.</p>`;
  const pad = { l: 52, r: 24, t: 16, b: 40 };
  const maxX = Math.max(...points.map((p) => p.false_alarm_rate)) * 1.15 || 0.01;
  const minY = Math.max(0, Math.min(...points.map((p) => p.detection_rate)) - 0.05);
  const maxY = Math.min(1, Math.max(...points.map((p) => p.detection_rate)) + 0.03);
  const sx = (v) => pad.l + (v / maxX) * (width - pad.l - pad.r);
  const sy = (v) => height - pad.b - ((v - minY) / (maxY - minY || 1)) * (height - pad.t - pad.b);
  const sorted = [...points].sort((a, b) => a.false_alarm_rate - b.false_alarm_rate);
  const path = sorted.map((p, i) => `${i ? "L" : "M"}${sx(p.false_alarm_rate)},${sy(p.detection_rate)}`).join(" ");
  const ghost = css("--ghost"), bone = css("--bone"), rule = css("--rule");
  const dots = sorted.map((p) => {
    const def = Math.abs(p.percentile - 99) < 1e-9;
    return `<circle cx="${sx(p.false_alarm_rate)}" cy="${sy(p.detection_rate)}" r="${def ? 6 : 4}" fill="${def ? bone : ghost}"/>
      <text x="${sx(p.false_alarm_rate) + 9}" y="${sy(p.detection_rate) + 14}">p${p.percentile}${def ? " (used)" : ""}</text>`;
  }).join("");
  const ticksX = [0, maxX / 2, maxX].map((v) => `<text x="${sx(v) - 12}" y="${height - pad.b + 20}">${pct(v)}</text>`).join("");
  const ticksY = [minY, (minY + maxY) / 2, maxY].map((v) => `<text x="0" y="${sy(v) + 4}">${pct(v, 0)}</text>`).join("");
  return `<svg viewBox="0 0 ${width} ${height}" role="img">
    <line x1="${pad.l}" y1="${height - pad.b}" x2="${width - pad.r}" y2="${height - pad.b}" stroke="${rule}"/>
    <line x1="${pad.l}" y1="${pad.t}" x2="${pad.l}" y2="${height - pad.b}" stroke="${rule}"/>
    <path d="${path}" fill="none" stroke="${ghost}" stroke-width="1.5"/>${dots}${ticksX}${ticksY}
    <text x="${width / 2 - 40}" y="${height - 6}">false alarm rate</text>
    <text x="${pad.l + 6}" y="${pad.t + 4}">detection rate</text></svg>`;
}

// =================================================================== results
const RUN_NOTES = {
  full: "NSL-KDD — الاختبار الرسمي KDDTest+ فيه 17 نوع هجوم غير موجود في التدريب.",
  live: "نفس NSL-KDD لكن بـ 28 ميزة فقط يمكن حسابها من ترويسات الحزم — هذا النموذج الذي يحلّل ملفات pcap.",
  cicids2017_temporal: "حركة حقيقية من 2017: تدريب على الاثنين–الأربعاء، اختبار على الخميس–الجمعة. كل هجمات الاختبار لم يرها النظام قط.",
  cicids2017_random: "نفس البيانات بتقسيم عشوائي (الطريقة الشائعة في الأبحاث): كل أنواع الهجمات رآها النظام — لذلك الأرقام شبه مثالية ومضلِّلة.",
};

async function showRun(runId, testSet) {
  document.querySelectorAll("#run-tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.run === runId));
  $("#run-note").textContent = RUN_NOTES[runId] || "";
  let res;
  try { res = await getJSON(`/api/results/${runId}`); }
  catch (err) { $("#kpis").innerHTML = `<p class="error">${esc(err.message)}</p>`; return; }

  const splits = Object.keys(res.test);
  const split = testSet && res.test[testSet] ? testSet : splits[0];
  const m = res.test[split];
  const c = m.classifier_only, a = m.anomaly_only, h = m.hybrid, nv = m.novel_attacks;

  $("#kpis").innerHTML = `
    <div class="kpi up"><div class="v">${pct(h.detection_rate)}</div><div class="from">from ${pct(c.detection_rate)} with the classifier alone</div><div class="l">attacks detected (hybrid)</div></div>
    <div class="kpi"><div class="v">${pct(h.false_alarm_rate, 2)}</div><div class="from">from ${pct(c.false_alarm_rate, 2)}</div><div class="l">false alarms on normal traffic</div></div>
    <div class="kpi ${nv ? "up" : ""}"><div class="v">${nv ? pct(nv.hybrid_dr) : "—"}</div><div class="from">${nv ? `from ${pct(nv.classifier_only_dr)} — ${num(nv.n_samples)} unseen attacks` : "every attack type was seen in training"}</div><div class="l">never-seen attacks caught</div></div>
    <div class="kpi"><div class="v">${num(m.n_samples)}</div><div class="from">${esc(split)}${splits.length > 1 ? ` <select id="split-pick">${splits.map((s) => `<option ${s === split ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>` : ""}</div><div class="l">test connections, unseen during training</div></div>`;
  $("#split-pick")?.addEventListener("change", (e) => showRun(runId, e.target.value));

  $("#chart-modes").innerHTML = hbars([
    { label: "classifier only", value: c.detection_rate, color: css("--ash") },
    { label: "anomaly only", value: a.detection_rate, color: css("--rule-strong") },
    { label: "hybrid", value: h.detection_rate, kind: "unknown" },
  ]);
  $("#chart-novel").innerHTML = nv
    ? hbars([
        { label: "classifier only", value: nv.classifier_only_dr, color: css("--ash") },
        { label: "anomaly only", value: nv.anomaly_only_dr, color: css("--rule-strong") },
        { label: "hybrid", value: nv.hybrid_dr, kind: "unknown" },
      ]) + `<p class="empty-note" style="margin-top:12px">${nv.attack_types.map(esc).join(", ")}</p>`
    : `<p class="empty-note">In a random split every attack family also appears in training, so there is nothing "new" to catch. That is why papers using this split report ~99%.</p>`;

  const byCat = m.detection_rate_by_category;
  const cats = Object.keys(byCat.hybrid).filter((k) => k !== "normal")
    .map((k) => ({ name: k, clf: byCat.classifier_only[k], hyb: byCat.hybrid[k] }))
    .sort((x, y) => (y.hyb - y.clf) - (x.hyb - x.clf));
  $("#chart-cats").innerHTML = pairedBars(cats);
  $("#chart-threshold").innerHTML = curve(m.threshold_sensitivity || []);

  const table = res.validation.classifier_comparison;
  const winner = res.metadata.classifier;
  $("#table-models").innerHTML = `<table><thead><tr><th>model</th><th class="num">macro-F1</th><th class="num">accuracy</th><th class="num">detection</th><th class="num">false alarms</th><th class="num">train time</th></tr></thead><tbody>${
    Object.entries(table).sort((x, y) => y[1].f1_macro - x[1].f1_macro).map(([name, r]) =>
      `<tr class="${name === winner ? "winner" : ""}"><td>${esc(name)}${name === winner ? " — selected" : ""}</td><td class="num">${r.f1_macro.toFixed(4)}</td><td class="num">${pct(r.accuracy, 2)}</td><td class="num">${pct(r.detection_rate, 2)}</td><td class="num">${pct(r.false_alarm_rate, 2)}</td><td class="num">${r.train_seconds}s</td></tr>`).join("")
  }</tbody></table><p class="empty-note" style="margin-top:12px">Anomaly detector: ${esc(res.metadata.detector)}, threshold at the ${res.metadata.threshold_percentile}th percentile of normal validation traffic.</p>`;
}

// =================================================================== analyze
let analyzeTape = null;
async function analyze(body, sourceLabel) {
  const out = $("#analyze-out");
  out.innerHTML = `<p class="loading">Reading packets and scoring every connection in ${esc(sourceLabel)}</p>`;
  try {
    const d = await getJSON("/api/analyze", { method: "POST", body });
    const colors = COLOR();
    const total = d.n_connections;
    const order = Object.entries(d.label_counts).sort((a, b) => b[1] - a[1]);
    out.innerHTML = `
      <div class="tape-stats" style="border-top:1px solid var(--rule)">
        <div class="stat"><span class="stat-n">${num(total)}</span><span class="stat-l">connections</span></div>
        <div class="stat"><span class="stat-n">${num(d.n_alerts)}</span><span class="stat-l">alerts</span></div>
        <div class="stat"><span class="stat-n">${num(d.incidents.length)}</span><span class="stat-l">incidents (grouped)</span></div>
        <div class="stat"><span class="stat-n">${d.duration_s}s</span><span class="stat-l">capture length</span></div>
        <div class="stat"><span class="stat-n" style="font-size:20px">${esc(d.model === "custom" ? "local baseline" : "NSL-KDD")}</span><span class="stat-l">normal learned from</span></div>
      </div>
      <div class="mix">${order.map(([k, v]) => `<span title="${esc(k)}: ${v}" style="width:${(v / total) * 100}%;background:${colors[kindOf(k)]}"></span>`).join("")}</div>
      <div class="mix-legend">${order.map(([k, v]) => `<span><i class="sw ${kindOf(k) === "attack" ? "attack" : kindOf(k)}"></i>${esc(k)} ${num(v)}</span>`).join("")}</div>
      <div class="tape-wrap"><canvas id="analyze-canvas" style="display:block;width:100%;height:220px"></canvas></div>
      <h3 class="cell-title" style="margin-top:32px">Incidents, most severe first</h3>
      <ol class="feed">${d.incidents.map(incidentHTML).join("")}</ol>`;
    analyzeTape = new Tape($("#analyze-canvas"));
    analyzeTape.showAll(d.tape, d.threshold, d.duration_s);
  } catch (err) {
    out.innerHTML = `<p class="error">${esc(err.message)}</p>`;
  }
}

function renderSamples() {
  const box = $("#samples");
  box.innerHTML = STATUS.samples.filter((s) => s.available).map((s) => `
    <button class="sample" type="button" data-sample="${esc(s.id)}" aria-pressed="false">
      <span class="tag ${s.real ? "" : "synthetic"}">${s.real ? "real capture" : "synthetic"}</span>
      <span class="name">${esc(s.label)}</span>
      <span class="note" lang="ar">${esc(s.note)}</span>
    </button>`).join("") || `<p class="empty-note" style="padding:18px">No sample captures found. Record one with tools/capture_real_traffic.sh.</p>`;
  box.querySelectorAll(".sample").forEach((btn) => btn.addEventListener("click", () => {
    box.querySelectorAll(".sample").forEach((b) => b.setAttribute("aria-pressed", b === btn));
    analyze(form({ sample: btn.dataset.sample, custom: $("#use-baseline").checked }), btn.querySelector(".name").textContent);
  }));
}

function uploadFile(file) {
  if (!file) return;
  document.querySelectorAll(".sample").forEach((b) => b.setAttribute("aria-pressed", "false"));
  analyze(form({ file, custom: $("#use-baseline").checked }), file.name);
}
$("#upload").addEventListener("change", (e) => uploadFile(e.target.files[0]));
const drop = $("#drop");
["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => uploadFile(e.dataTransfer.files[0]));

// =================================================================== live: defender (IDS) + attacker (terminal)
let liveSource = null, liveTape = null, liveTimer = null;
const liveCounts = { conn: 0, alert: 0, probe: 0, unknown: 0 };
const ATTACK_NAMES = { port_scan: "Port scan", service_scan: "Service scan", http_flood: "HTTP flood" };

function renderLive() {
  $("#live-body").innerHTML = `
    <div class="switches">
      <button class="switch" role="switch" aria-checked="false" id="sw-monitor" type="button" ${STATUS.is_root ? "" : "disabled"}>
        <i></i><span><b>Monitoring</b><small>NetSentinel reads every packet on <select id="live-iface" aria-label="Interface">
          <option value="lo0">lo0</option><option value="en0">en0</option></select></small></span></button>
      <button class="switch danger" role="switch" aria-checked="false" id="sw-auto" type="button">
        <i></i><span><b>Attack mode</b><small>scan → flood → service scan, on repeat</small></span></button>
      <button class="switch" role="switch" aria-checked="false" id="sw-browse" type="button">
        <i></i><span><b>Normal browsing</b><small>a user visiting the site in the background</small></span></button>
    </div>
    ${STATUS.is_root ? "" : `<p class="root-note">Monitoring is off because the server has no root access to the network card.
      Restart it with <code>sudo .venv/bin/netsentinel web</code>. The attack terminal works either way.</p>`}
    <div class="duel">
      <div class="duel-ids">
        <div class="duel-head"><b>Defender</b><span id="live-state">NetSentinel is not monitoring.</span></div>
        <canvas id="live-canvas" role="img" aria-label="Live connections: height is anomaly score, colour is the verdict"></canvas>
        <div class="tape-stats">
          <div class="stat"><span class="stat-n" id="l-conn">0</span><span class="stat-l">connections</span></div>
          <div class="stat"><span class="stat-n" id="l-alert">0</span><span class="stat-l">alerts</span></div>
          <div class="stat probe"><span class="stat-n" id="l-probe">0</span><span class="stat-l">scan / probe</span></div>
          <div class="stat unknown"><span class="stat-n" id="l-unknown">0</span><span class="stat-l">unknown</span></div>
          <div class="stat"><span class="stat-n" id="l-time">0s</span><span class="stat-l">watching</span></div>
        </div>
      </div>
      <div class="duel-term">
        <div class="duel-head"><b>Attacker</b><span>target fixed to 127.0.0.1 — this laptop only</span></div>
        <div class="term" id="term" aria-live="polite"></div>
        <form class="term-input" id="term-form" autocomplete="off">
          <label for="term-cmd">attacker@range:~$</label>
          <input id="term-cmd" spellcheck="false" placeholder="type help">
        </form>
        <div class="quick">
          <button type="button" class="btn ghost" data-cmd="scan">scan</button>
          <button type="button" class="btn ghost" data-cmd="service-scan">service-scan</button>
          <button type="button" class="btn ghost" data-cmd="flood">flood</button>
          <button type="button" class="btn ghost" data-cmd="help">help</button>
        </div>
      </div>
    </div>`;
  liveTape = new Tape($("#live-canvas"));
  $("#sw-monitor").addEventListener("click", toggleMonitor);
  $("#live-iface").addEventListener("click", (e) => e.stopPropagation());
  $("#sw-auto").addEventListener("click", (e) => post("/api/range/auto", { on: e.currentTarget.getAttribute("aria-checked") !== "true" }).then(syncSwitches));
  $("#sw-browse").addEventListener("click", (e) => post("/api/range/background", { on: e.currentTarget.getAttribute("aria-checked") !== "true" }).then(syncSwitches));
  $("#term-form").addEventListener("submit", (e) => { e.preventDefault(); runCmd($("#term-cmd").value); $("#term-cmd").value = ""; });
  document.querySelectorAll("[data-cmd]").forEach((b) => b.addEventListener("click", () => runCmd(b.dataset.cmd)));
  openConsole();
  getJSON("/api/range").then(syncSwitches);
  setInterval(() => getJSON("/api/range").then(syncSwitches).catch(() => {}), 3000);
}

async function post(url, payload) {
  return getJSON(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload || {}) });
}
function syncSwitches(state) {
  $("#sw-auto").setAttribute("aria-checked", state.auto);
  $("#sw-browse").setAttribute("aria-checked", state.background);
}
function runCmd(cmd) {
  if (!cmd.trim()) return;
  post("/api/range/command", { cmd }).then(syncSwitches).catch((err) => termLine({ stream: "err", text: err.message }));
}

// --- the attacker terminal: a stream of real tool output from the server
function termLine({ stream, text }) {
  const term = $("#term");
  if (stream === "clear") { term.innerHTML = ""; return; }
  const div = document.createElement("div");
  div.className = `tl ${stream}`;
  div.textContent = stream === "cmd" ? `$ ${text}` : stream === "prompt" ? `attacker@range:~$ ${text}` : text;
  const atBottom = term.scrollHeight - term.scrollTop - term.clientHeight < 40;
  term.appendChild(div);
  while (term.children.length > 600) term.firstElementChild.remove();
  if (atBottom) term.scrollTop = term.scrollHeight;
}
function openConsole() {
  const src = new EventSource("/api/range/console");
  src.addEventListener("line", (e) => termLine(JSON.parse(e.data)));
}

// --- the defender: live capture stream
function setLiveStats(elapsed) {
  $("#l-conn").textContent = num(liveCounts.conn);
  $("#l-alert").textContent = num(liveCounts.alert);
  $("#l-probe").textContent = num(liveCounts.probe);
  $("#l-unknown").textContent = num(liveCounts.unknown);
  if (elapsed != null) $("#l-time").textContent = `${Math.floor(elapsed)}s`;
}

function toggleMonitor() {
  const sw = $("#sw-monitor");
  if (liveSource) {
    liveSource.close(); liveSource = null; liveTape.clock = null; clearInterval(liveTimer);
    sw.setAttribute("aria-checked", "false");
    $("#live-state").textContent = "Stopped.";
    return;
  }
  Object.keys(liveCounts).forEach((k) => (liveCounts[k] = 0));
  setLiveStats(0);
  $("#live-feed").innerHTML = "";
  const iface = $("#live-iface").value;
  liveSource = new EventSource(`/api/live?iface=${encodeURIComponent(iface)}&custom=true`);
  sw.setAttribute("aria-checked", "true");
  $("#live-state").textContent = `Watching ${iface}. Verdicts every 3 seconds.`;
  const started = performance.now();
  liveTimer = setInterval(() => setLiveStats((performance.now() - started) / 1000), 500);

  liveSource.addEventListener("meta", (ev) => {
    liveTape.reset(JSON.parse(ev.data).threshold);
    liveTape.clock = () => (performance.now() - started) / 1000;
  });
  liveSource.addEventListener("conn", (ev) => {
    const c = JSON.parse(ev.data);
    liveTape.push(c.t, c.score, c.label);
    liveCounts.conn++;
    if (c.label !== "normal") liveCounts.alert++;
    if (kindOf(c.label) === "probe") liveCounts.probe++;
    if (c.label === "Unknown-Anomaly") liveCounts.unknown++;
    if (c.incident) {
      pushFeed($("#live-feed"), { ...c, ...c.incident, sample: c }, 12);
      termLine({ stream: `ids ${kindOf(c.label)}`, text: `[NetSentinel] ALERT ${c.label} ${c.src_ip} → ${c.dst_ip}:${c.dst_port} — ${c.incident.description}` });
    }
  });
  liveSource.addEventListener("range", (ev) => {
    const r = JSON.parse(ev.data);
    if (r.kind === "attack_started") liveTape.mark(r.t, `▶ ${ATTACK_NAMES[r.attack] || r.attack}`);
  });
  liveSource.onerror = () => { $("#live-state").textContent = "Lost the connection to the detector. Is the server still running?"; };
}

// =================================================================== lab
let LAB = null;
const labValues = {};
function renderLab() {
  $("#lab-presets").innerHTML = Object.entries(LAB.presets).map(([id, p]) =>
    `<button class="btn ghost" type="button" data-preset="${id}" lang="ar">${esc(p.label)}</button>`).join("");
  document.querySelectorAll("[data-preset]").forEach((b) => b.addEventListener("click", () => loadPreset(b.dataset.preset)));
  $("#lab-controls").innerHTML = LAB.controls.map((c) => c.type === "choice"
    ? `<div class="control"><label for="ctl-${c.feature}">${c.feature}</label>
        <select id="ctl-${c.feature}" data-f="${c.feature}">${c.options.map((o) => `<option>${o}</option>`).join("")}</select><output></output>
        <small lang="ar">${esc(c.description)}</small></div>`
    : `<div class="control"><label for="ctl-${c.feature}">${c.feature}</label>
        <input type="range" id="ctl-${c.feature}" data-f="${c.feature}" min="${c.min}" max="${c.max}" step="${c.step}">
        <output id="out-${c.feature}"></output><small lang="ar">${esc(c.description)}</small></div>`).join("");
  document.querySelectorAll("#lab-controls [data-f]").forEach((el) => el.addEventListener("input", () => {
    labValues[el.dataset.f] = el.type === "range" ? Number(el.value) : el.value;
    syncOutputs(); scheduleLab();
  }));
  loadPreset("normal");
}
function loadPreset(id) {
  Object.keys(labValues).forEach((k) => delete labValues[k]);
  Object.assign(labValues, LAB.presets[id].values);
  document.querySelectorAll("[data-preset]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.preset === id));
  document.querySelectorAll("#lab-controls [data-f]").forEach((el) => { el.value = labValues[el.dataset.f] ?? 0; });
  syncOutputs(); runLab();
}
function syncOutputs() {
  document.querySelectorAll("#lab-controls input[type=range]").forEach((el) => { $(`#out-${el.dataset.f}`).textContent = el.value; });
}
let labTimer = null;
function scheduleLab() { clearTimeout(labTimer); labTimer = setTimeout(runLab, 120); }
async function runLab() {
  try {
    const r = await getJSON("/api/lab", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ run: "full", values: labValues }) });
    const pos = (v) => Math.min(100, Math.max(0, ((Math.log10(Math.max(v, 1e-6)) + 4) / 5) * 100));
    $("#lab-verdict").innerHTML = `
      <div class="verdict-label" data-kind="${kindOf(r.label)}">${esc(r.label)}</div>
      <p class="ar" lang="ar" dir="rtl" style="margin:0;color:var(--bone)">${esc(r.description)}</p>
      <div class="verdict-meta">classifier says ${esc(r.classifier_label)} with ${pct(r.confidence, 0)} confidence</div>
      <div class="meter" title="anomaly score vs threshold"><i style="width:${pos(r.score)}%;background:${r.score > r.threshold ? css("--ghost") : css("--ash")}"></i><b style="left:${pos(r.threshold)}%"></b></div>
      <div class="verdict-meta">anomaly score ${r.score.toFixed(4)} — threshold ${r.threshold.toFixed(4)}</div>
      ${r.reasons.length ? `<ul>${r.reasons.map((x) => `<li><code>${esc(x.feature)}=${esc(x.value)}</code> — ${esc(x.description)}</li>`).join("")}</ul>` : ""}`;
  } catch (err) { $("#lab-verdict").innerHTML = `<p class="error">${esc(err.message)}</p>`; }
}

// =================================================================== boot
async function boot() {
  try {
    STATUS = await getJSON("/api/status");
  } catch {
    $("#status").textContent = "Detector offline. Start it with: netsentinel web";
    $("#status").className = "status err";
    return;
  }
  const runs = STATUS.runs.filter((r) => r.available);
  const samples = STATUS.samples.filter((s) => s.available);
  $("#status").textContent = `${runs.length} trained models, ${samples.length} captures${STATUS.is_root ? ", live capture enabled" : ""}`;
  $("#status").className = "status ok";

  $("#tape-sample").innerHTML = samples.map((s) => `<option value="${esc(s.id)}">${esc(s.label)}${s.real ? "" : " (synthetic)"}</option>`).join("");
  $("#run-tabs").innerHTML = runs.map((r) => `<button role="tab" type="button" data-run="${esc(r.id)}" aria-selected="false">${esc(r.label)}</button>`).join("");
  document.querySelectorAll("#run-tabs button").forEach((b) => b.addEventListener("click", () => showRun(b.dataset.run)));

  renderSamples();
  renderLive();
  startReplay();
  if (runs.length) showRun(runs.find((r) => r.id === "cicids2017_temporal")?.id || runs[0].id);
  try { LAB = await getJSON("/api/lab/presets"); renderLab(); }
  catch (err) { $("#lab-verdict").innerHTML = `<p class="error">${esc(err.message)}</p>`; }
}
boot();
