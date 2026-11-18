// NetSentinel website

const $ = id => document.getElementById(id);

function esc(text) {
  return String(text == null ? "" : text)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function pct(x, digits = 1) {
  if (x == null) return "-";
  return (x * 100).toFixed(digits) + "%";
}

function n(x) {
  return Number(x).toLocaleString();
}

// colour group for a label
function kind(label) {
  if (label === "normal" || label === "BENIGN") return "normal";
  if (label === "Unknown-Anomaly") return "unknown";
  if (label === "Probe" || label === "PortScan") return "probe";
  return "attack";
}

const KINDS = ["normal", "probe", "attack", "unknown"];
const KIND_NAME = {normal: "normal", probe: "scan / probe", attack: "known attack", unknown: "unknown anomaly"};
const RANK = {normal: 0, probe: 1, unknown: 2, attack: 3};
const color = name => getComputedStyle(document.documentElement).getPropertyValue("--" + name).trim();

async function getJSON(url, options) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

function postJSON(url, body) {
  return getJSON(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
}


// ------------------------------------------------------------------ tooltips
// any svg/html element with a data-tip attribute shows it on hover

const tip = $("tip");
document.addEventListener("mousemove", function (e) {
  const el = e.target.closest && e.target.closest("[data-tip]");
  if (!el) { tip.hidden = true; return; }
  tip.innerHTML = el.getAttribute("data-tip");
  tip.hidden = false;
  const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
  tip.style.left = x + "px";
  tip.style.top = (e.clientY + 14) + "px";
});


// ------------------------------------------------------------------ charts (plain SVG)

function svgOpen(w, h) {
  return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}">`;
}

function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

// stacked columns; bins = [{normal, probe, attack, unknown, label}], slots = fixed column count
function stackedBars(el, bins, slots, height = 180) {
  const w = el.clientWidth || 600, h = height, left = 42, bottom = 18;
  const count = slots || bins.length || 1;
  const totals = bins.map(b => KINDS.reduce((s, k) => s + (b[k] || 0), 0));
  const max = niceMax(Math.max(1, ...totals));
  const plotW = w - left, plotH = h - bottom - 6;
  const bw = plotW / count;
  let out = svgOpen(w, h);
  for (let i = 0; i <= 4; i++) {
    const y = 6 + plotH * (1 - i / 4);
    out += `<line class="grid-line" x1="${left}" x2="${w}" y1="${y}" y2="${y}"/><text x="${left - 6}" y="${y + 4}" text-anchor="end">${n(max * i / 4)}</text>`;
  }
  bins.forEach((b, i) => {
    const x = left + (count - bins.length + i) * bw;
    let y = 6 + plotH;
    let tipText = `<b>${esc(b.label || "")}</b><br>${n(totals[i])} connections`;
    for (const k of KINDS) {
      const v = b[k] || 0;
      if (!v) continue;
      const bh = v / max * plotH;
      y -= bh;
      out += `<rect x="${x + 1}" y="${y}" width="${Math.max(bw - 2, 1)}" height="${bh}" fill="${color(k)}"/>`;
      tipText += `<br>${KIND_NAME[k]}: ${n(v)}`;
    }
    out += `<rect class="hit" x="${x}" y="6" width="${bw}" height="${plotH}" data-tip="${esc(tipText)}"/>`;
  });
  out += `<line class="axis" x1="${left}" x2="${w}" y1="${6 + plotH}" y2="${6 + plotH}"/>`;
  if (bins.length) {
    out += `<text x="${left + (count - bins.length) * bw}" y="${h - 3}">${esc(bins[0].label || "")}</text>`;
    out += `<text x="${w}" y="${h - 3}" text-anchor="end">${esc(bins[bins.length - 1].label || "")}</text>`;
  }
  el.innerHTML = out + "</svg>";
}

// small line of values between 0 and 1
function sparkline(el, values) {
  const w = el.clientWidth || 240, h = 46;
  let out = svgOpen(w, h) + `<line class="grid-line" x1="0" x2="${w}" y1="${h - 1}" y2="${h - 1}"/>`;
  if (values.length > 1) {
    const pts = values.map((v, i) => `${(i / (values.length - 1)) * w},${h - 2 - v * (h - 6)}`).join(" ");
    out += `<polyline points="${pts}" fill="none" stroke="${color("attack")}" stroke-width="1.5"/>`;
  }
  el.innerHTML = out + `<text x="0" y="10">100%</text></svg>`;
}

// histogram of autoencoder scores on a log axis, centred on the threshold
function scoreHistogram(el, scores, threshold) {
  const w = el.clientWidth || 500, h = 170, left = 42, bottom = 18, nb = 48;
  if (!threshold) { el.innerHTML = `<p class="empty" style="padding:0">No data yet.</p>`; return; }
  const lo = Math.log10(threshold) - 3, hi = Math.log10(threshold) + 2;
  const bins = Array.from({length: nb}, () => ({normal: 0, probe: 0, attack: 0, unknown: 0}));
  for (const [s, k] of scores) {
    const t = (Math.log10(Math.max(s, 1e-12)) - lo) / (hi - lo);
    bins[Math.min(nb - 1, Math.max(0, Math.floor(t * nb)))][k] += 1;
  }
  const totals = bins.map(b => KINDS.reduce((a, k) => a + b[k], 0));
  const max = niceMax(Math.max(1, ...totals));
  const plotW = w - left, plotH = h - bottom - 6, bw = plotW / nb;
  const xOf = logv => left + (logv - lo) / (hi - lo) * plotW;
  let out = svgOpen(w, h);
  for (let i = 0; i <= 2; i++) {
    const y = 6 + plotH * (1 - i / 2);
    out += `<line class="grid-line" x1="${left}" x2="${w}" y1="${y}" y2="${y}"/><text x="${left - 6}" y="${y + 4}" text-anchor="end">${n(max * i / 2)}</text>`;
  }
  bins.forEach((b, i) => {
    let y = 6 + plotH;
    const x = left + i * bw;
    const from = Math.pow(10, lo + (hi - lo) * i / nb), to = Math.pow(10, lo + (hi - lo) * (i + 1) / nb);
    let t = `score ${from.toPrecision(2)} to ${to.toPrecision(2)}<br>${n(totals[i])} connections`;
    for (const k of KINDS) {
      if (!b[k]) continue;
      const bh = b[k] / max * plotH;
      y -= bh;
      out += `<rect x="${x + 0.5}" y="${y}" width="${bw - 1}" height="${bh}" fill="${color(k)}"/>`;
      t += `<br>${KIND_NAME[k]}: ${n(b[k])}`;
    }
    out += `<rect class="hit" x="${x}" y="6" width="${bw}" height="${plotH}" data-tip="${esc(t)}"/>`;
  });
  for (let d = Math.ceil(lo); d <= Math.floor(hi); d++) {
    out += `<text x="${xOf(d)}" y="${h - 3}" text-anchor="middle">1e${d}</text>`;
  }
  const tx = xOf(Math.log10(threshold));
  out += `<line x1="${tx}" x2="${tx}" y1="2" y2="${6 + plotH}" stroke="${color("text")}" stroke-dasharray="3 3"/>`;
  out += `<text class="val" x="${tx + 5}" y="14">threshold ${threshold.toPrecision(3)}</text>`;
  out += `<line class="axis" x1="${left}" x2="${w}" y1="${6 + plotH}" y2="${6 + plotH}"/>`;
  el.innerHTML = out + "</svg>";
}

// 0..65535 split into 256 buckets; height = how many ports in the bucket were touched
function portStrip(el, ports) {
  const w = el.clientWidth || 500, h = 130, bottom = 18, nb = 256, plotH = h - bottom - 4;
  const buckets = Array.from({length: nb}, () => ({count: 0, worst: "normal"}));
  for (const [port, k] of ports) {
    const b = buckets[Math.floor(port / 256)];
    b.count += 1;
    if (RANK[k] > RANK[b.worst]) b.worst = k;
  }
  const bw = w / nb;
  let out = svgOpen(w, h) + `<rect x="0" y="4" width="${w}" height="${plotH}" fill="#0c0f11"/>`;
  buckets.forEach((b, i) => {
    if (!b.count) return;
    const bh = Math.max(3, Math.log2(b.count + 1) / 8 * plotH);
    out += `<rect x="${i * bw}" y="${4 + plotH - bh}" width="${Math.max(bw, 1.5)}" height="${bh}" fill="${color(b.worst)}"
      data-tip="ports ${i * 256} to ${i * 256 + 255}<br>${b.count} touched, worst: ${KIND_NAME[b.worst]}"/>`;
  });
  for (const p of [0, 16384, 32768, 49152, 65535]) {
    const x = p / 65536 * w;
    out += `<text x="${x}" y="${h - 3}" text-anchor="${p === 0 ? "start" : p === 65535 ? "end" : "middle"}">${p}</text>`;
  }
  el.innerHTML = out + "</svg>";
}

// horizontal bars; rows = [{label, values: [{v, color, name}]}], one or two bars per row
function hbars(el, rows, opts = {}) {
  const w = el.clientWidth || 500, labelW = opts.labelW || 120, valueW = 54;
  const per = rows[0] ? rows[0].values.length : 1;
  const barH = per > 1 ? 9 : 14, gap = 3, rowH = per * (barH + gap) + 10;
  const h = rows.length * rowH + 4;
  const max = opts.max || Math.max(...rows.flatMap(r => r.values.map(v => v.v)), 1e-9);
  const fmt = opts.fmt || pct;
  const plotW = Math.max(40, w - labelW - valueW);
  let out = svgOpen(labelW + plotW + valueW, h);
  rows.forEach((r, i) => {
    const y0 = i * rowH + 4;
    out += `<text class="lbl" x="0" y="${y0 + (per * (barH + gap)) / 2 + 4}">${esc(r.label)}</text>`;
    r.values.forEach((v, j) => {
      const y = y0 + j * (barH + gap);
      const bw = Math.max(1, (v.v || 0) / max * plotW);
      out += `<rect x="${labelW}" y="${y}" width="${plotW}" height="${barH}" fill="#0c0f11"/>`;
      out += `<rect x="${labelW}" y="${y}" width="${bw}" height="${barH}" fill="${v.color}" rx="1"
        data-tip="<b>${esc(r.label)}</b><br>${esc(v.name || "")} ${fmt(v.v)}"/>`;
      out += `<text class="val" x="${labelW + plotW + 6}" y="${y + barH - 1}">${fmt(v.v)}</text>`;
    });
  });
  el.innerHTML = out + "</svg>";
}

// lines over a few labelled x points, values 0..1; marks one x as "used"
function lineChart(el, xs, series, marked) {
  const w = el.clientWidth || 500, h = 190, left = 40, right = 16, bottom = 22, top = 10;
  const plotW = w - left - right, plotH = h - top - bottom;
  const max = niceMax(Math.max(...series.flatMap(s => s.values)));
  const xOf = i => left + (xs.length === 1 ? plotW / 2 : i / (xs.length - 1) * plotW);
  const yOf = v => top + plotH * (1 - v / max);
  let out = svgOpen(w, h);
  for (let i = 0; i <= 4; i++) {
    const y = yOf(max * i / 4);
    out += `<line class="grid-line" x1="${left}" x2="${w - right}" y1="${y}" y2="${y}"/><text x="${left - 6}" y="${y + 4}" text-anchor="end">${pct(max * i / 4, 0)}</text>`;
  }
  xs.forEach((x, i) => {
    out += `<text x="${xOf(i)}" y="${h - 5}" text-anchor="middle">${esc(x)}</text>`;
    if (i === marked) {
      out += `<line x1="${xOf(i)}" x2="${xOf(i)}" y1="${top}" y2="${top + plotH}" stroke="${color("muted")}" stroke-dasharray="3 3"/>`;
      out += `<text class="val" x="${xOf(i) + 5}" y="${top + 10}">used</text>`;
    }
  });
  for (const s of series) {
    const pts = s.values.map((v, i) => `${xOf(i)},${yOf(v)}`).join(" ");
    out += `<polyline points="${pts}" fill="none" stroke="${s.color}" stroke-width="2"/>`;
    s.values.forEach((v, i) => { out += `<circle cx="${xOf(i)}" cy="${yOf(v)}" r="3" fill="${s.color}"/>`; });
  }
  xs.forEach((x, i) => {
    const t = `<b>${esc(x)}</b>` + series.map(s => `<br>${s.name}: ${pct(s.values[i])}`).join("");
    const half = plotW / Math.max(xs.length - 1, 1) / 2;
    out += `<rect class="hit" x="${xOf(i) - half}" y="${top}" width="${half * 2}" height="${plotH}" data-tip="${esc(t)}"/>`;
  });
  el.innerHTML = out + "</svg>";
}


// ------------------------------------------------------------------ results

const RUN_NAMES = {
  full: "NSL-KDD, all 40 features",
  live: "NSL-KDD, 28 packet features",
  cicids2017_temporal: "CIC-IDS2017, split by day",
  cicids2017_random: "CIC-IDS2017, random split"
};
let currentResults = null;
let cmMode = "hybrid";

async function loadRun(run) {
  for (const b of document.querySelectorAll("#run-tabs button")) b.setAttribute("aria-selected", b.dataset.run === run);
  currentResults = await getJSON("/api/results/" + run);
  $("split").innerHTML = Object.keys(currentResults.test).map(s => `<option>${esc(s)}</option>`).join("");
  showResults();
}

function delta(a, b, lowerIsBetter) {
  const d = (a - b) * 100;
  const sign = d >= 0 ? "+" : "";
  const good = lowerIsBetter ? d <= 0 : d >= 0;
  return `${good ? "<b>" : ""}${sign}${d.toFixed(1)} pts${good ? "</b>" : ""} vs classifier alone`;
}

function showResults() {
  const res = currentResults;
  const m = res.test[$("split").value];
  const c = m.classifier_only, h = m.hybrid;
  $("run-meta").textContent = `Classifier: ${res.metadata.classifier.replace(/_/g, " ")}. Anomaly detector: ${res.metadata.detector}. `
    + `${n(m.n_samples)} test connections.`;

  let kpis = `
    <div class="kpi"><div class="v">${pct(h.detection_rate)}</div><div class="l">attacks detected</div><div class="d">${delta(h.detection_rate, c.detection_rate)}</div></div>
    <div class="kpi"><div class="v">${pct(h.false_alarm_rate, 2)}</div><div class="l">false alarms</div><div class="d">${delta(h.false_alarm_rate, c.false_alarm_rate, true)}</div></div>`;
  if (m.novel_attacks) {
    const nv = m.novel_attacks;
    kpis += `<div class="kpi"><div class="v">${pct(nv.hybrid_dr)}</div><div class="l">new attacks detected</div><div class="d">${delta(nv.hybrid_dr, nv.classifier_only_dr)}</div></div>`;
  } else {
    kpis += `<div class="kpi"><div class="v">${pct(h.precision)}</div><div class="l">precision</div><div class="d">${delta(h.precision, c.precision)}</div></div>`;
  }
  kpis += `<div class="kpi"><div class="v">${pct(h.accuracy)}</div><div class="l">accuracy</div><div class="d">${delta(h.accuracy, c.accuracy)}</div></div>`;
  $("kpis").innerHTML = kpis;

  const cats = m.detection_rate_by_category;
  hbars($("r-cats"), Object.keys(cats.hybrid).filter(k => k !== "normal").map(k => ({
    label: k,
    values: [{v: cats.classifier_only[k], color: color("normal"), name: "classifier alone"},
             {v: cats.hybrid[k], color: color("unknown"), name: "hybrid"}]
  })), {max: 1});

  showConfusion();

  const ts = m.threshold_sensitivity || [];
  const used = ts.findIndex(t => t.percentile === res.metadata.threshold_percentile);
  const series = [
    {name: "detection rate", color: color("unknown"), values: ts.map(t => t.detection_rate)},
    {name: "false alarm rate", color: color("attack"), values: ts.map(t => t.false_alarm_rate)}
  ];
  if (m.novel_attacks) series.push({name: "new attacks caught", color: color("probe"), values: ts.map(t => t.novel_dr)});
  lineChart($("r-threshold"), ts.map(t => "p" + t.percentile), series, used);

  if (m.novel_attacks) {
    const nv = m.novel_attacks;
    $("r-novel-n").textContent = n(nv.n_samples) + " connections";
    hbars($("r-novel"), [
      {label: "classifier alone", values: [{v: nv.classifier_only_dr, color: color("normal")}]},
      {label: "autoencoder alone", values: [{v: nv.anomaly_only_dr, color: color("muted")}]},
      {label: "hybrid", values: [{v: nv.hybrid_dr, color: color("unknown")}]}
    ], {max: 1, labelW: 130});
    $("r-novel-types").textContent = "Types: " + nv.attack_types.join(", ");
  } else {
    $("r-novel-n").textContent = "";
    $("r-novel").innerHTML = `<p class="empty" style="padding:0">With a random split every attack type is in the training data, so nothing here is new. That is why this split scores so high.</p>`;
    $("r-novel-types").textContent = "";
  }

  const val = res.validation;
  let tbl = `<table><tr><th>classifier</th><th class="num">macro F1</th><th class="num">detection</th><th class="num">false alarms</th><th class="num">train s</th></tr>`;
  for (const [name, r] of Object.entries(val.classifier_comparison)) {
    tbl += `<tr class="${name === res.metadata.classifier ? "chosen" : ""}"><td>${name.replace(/_/g, " ")}</td><td class="num">${r.f1_macro.toFixed(3)}</td>
      <td class="num">${pct(r.detection_rate)}</td><td class="num">${pct(r.false_alarm_rate, 2)}</td><td class="num">${r.train_seconds}</td></tr>`;
  }
  tbl += `<tr><th>anomaly detector</th><th class="num">ROC AUC</th><th class="num">detection</th><th class="num">false alarms</th><th class="num">train s</th></tr>`;
  for (const [name, r] of Object.entries(val.detector_comparison)) {
    tbl += `<tr class="${name === res.metadata.detector ? "chosen" : ""}"><td>${name.replace(/_/g, " ")}</td><td class="num">${r.roc_auc.toFixed(3)}</td>
      <td class="num">${pct(r.detection_rate)}</td><td class="num">${pct(r.false_alarm_rate, 2)}</td><td class="num">${r.train_seconds}</td></tr>`;
  }
  $("r-models").innerHTML = tbl + `</table><p class="caption" style="padding:0 14px 12px">Highlighted rows were picked automatically: best macro F1 and best ROC AUC.</p>`;

  const fi = Object.entries(res.feature_importance || {}).slice(0, 10);
  hbars($("r-features"), fi.map(([k, v]) => ({label: k, values: [{v, color: color("muted")}]})),
    {labelW: 190, fmt: v => v.toFixed(4)});
}

function showConfusion() {
  const m = currentResults.test[$("split").value][cmMode];
  const pos = m.tp + m.fn, neg = m.fp + m.tn;
  const cell = (v, total, good) => {
    const share = total ? v / total : 0;
    const bg = good ? `rgba(79,179,232,${0.08 + share * 0.5})` : `rgba(229,83,75,${0.06 + share * 0.6})`;
    return `<div class="cell" style="background:${bg}">${n(v)}<small>${pct(share)} of row</small></div>`;
  };
  $("r-cm").innerHTML = `<div class="cm">
      <div class="h"></div><div class="h">predicted attack</div><div class="h">predicted normal</div>
      <div class="h">real attack</div>${cell(m.tp, pos, true)}${cell(m.fn, pos, false)}
      <div class="h">real normal</div>${cell(m.fp, neg, false)}${cell(m.tn, neg, true)}
    </div><p class="caption">Missed attacks: ${n(m.fn)}. False alarms: ${n(m.fp)}.</p>`;
  for (const b of document.querySelectorAll("#cm-mode button")) b.setAttribute("aria-pressed", b.dataset.mode === cmMode);
}

$("split").onchange = showResults;
for (const b of document.querySelectorAll("#cm-mode button")) {
  b.onclick = function () { cmMode = b.dataset.mode; showConfusion(); };
}


// ------------------------------------------------------------------ analysis

function pairRows(pairs, withTime) {
  if (!pairs.length) return `<tr><td class="empty">Nothing yet.</td></tr>`;
  let html = `<tr><th>source</th><th>target</th><th class="num">connections</th><th class="num">ports</th>
    <th class="num">flagged</th><th>mostly</th>${withTime ? "<th>last seen</th>" : ""}</tr>`;
  for (const p of pairs) {
    const ports = p.portCount != null ? p.portCount : p.ports.length;
    html += `<tr><td class="mono">${esc(p.src)}</td><td class="mono">${esc(p.dst)}</td><td class="num">${n(p.connections)}</td>
      <td class="num">${n(ports)}</td><td class="num">${n(p.alerts)}</td>
      <td><span class="tag ${p.main}">${KIND_NAME[p.main]}</span></td>${withTime ? `<td class="mono">${esc(p.last)}</td>` : ""}</tr>`;
  }
  return html;
}

function incidentHTML(inc) {
  const reasons = inc.reasons.map(r => {
    const z = r.z_score == null ? "" : ` (z=${r.z_score.toFixed(1)})`;
    return `<li><code>${esc(r.feature)} = ${esc(r.value)}</code>${z}: ${esc(r.description)}</li>`;
  }).join("");
  const ports = inc.ports ? `, ${n(inc.ports)} ports` : "";
  return `<div class="incident" data-kind="${kind(inc.label)}"><span class="bar"></span>
    <div class="who"><b>${esc(inc.label)}</b><small class="mono">${esc(inc.src)} &rarr; ${esc(inc.dst)}</small><br>
      <small>${n(inc.connections)} connections${ports}, ${esc(inc.severity)} severity</small></div>
    <ul>${reasons}</ul></div>`;
}

async function analyze(formData) {
  const out = $("analysis-out");
  out.innerHTML = `<p class="loading">Reading packets...</p>`;
  try {
    const d = await getJSON("/api/analyze", {method: "POST", body: formData});
    const total = Object.values(d.counts).reduce((a, b) => a + b, 0) || 1;
    const mix = Object.entries(d.counts).map(([l, c]) =>
      `<span style="width:${c / total * 100}%;background:${color(kind(l))}" data-tip="${esc(l)}: ${n(c)}"></span>`).join("");
    const legend = Object.entries(d.counts).map(([l, c]) => `<li><i class="sw ${kind(l)}"></i>${esc(l)} ${n(c)}</li>`).join("");
    out.innerHTML = `
      <div class="grid">
        <div class="panel c12"><div class="counters">
          <div class="counter"><div class="v">${n(d.connections)}</div><div class="l">connections</div></div>
          <div class="counter attack"><div class="v">${n(d.alerts)}</div><div class="l">flagged</div></div>
          <div class="counter"><div class="v">${d.seconds}s</div><div class="l">of traffic</div></div>
          <div class="counter"><div class="v">${n(d.incidents.length)}</div><div class="l">incidents</div></div>
          <div class="counter"><div class="v">${n(d.pairs.length)}</div><div class="l">conversations</div></div>
        </div><div class="panel-b"><div class="mix">${mix}</div><ul class="legend">${legend}</ul></div></div>
        <div class="panel c7"><div class="panel-h"><b>Timeline</b><span>${d.timeline.seconds}s in 60 slices</span></div>
          <div class="panel-b"><div class="chart" id="an-timeline"></div></div></div>
        <div class="panel c5"><div class="panel-h"><b>Conversations</b><span>source to target</span></div>
          <div class="panel-b flush scroll"><table>${pairRows(d.pairs)}</table></div></div>
        <div class="panel c12"><div class="panel-h"><b>Incidents</b><span>alerts grouped by source, target and type</span></div>
          <div class="panel-b flush">${d.incidents.map(incidentHTML).join("") || `<p class="empty">No alerts.</p>`}</div></div>
      </div>`;
    const step = d.timeline.seconds / 60;
    const bins = d.timeline.bins.normal.map((_, i) => {
      const b = {label: `${(i * step).toFixed(1)}s`};
      for (const k of KINDS) b[k] = d.timeline.bins[k][i];
      return b;
    });
    stackedBars($("an-timeline"), bins, 60, 200);
  } catch (e) {
    out.innerHTML = `<p class="error">${esc(e.message)}</p>`;
  }
}

function analyzeSample(name) {
  for (const b of document.querySelectorAll(".sample")) b.setAttribute("aria-pressed", b.dataset.sample === name);
  const fd = new FormData();
  fd.append("sample", name);
  fd.append("custom", $("custom").checked);
  analyze(fd);
}

$("upload").onchange = function (e) {
  for (const b of document.querySelectorAll(".sample")) b.setAttribute("aria-pressed", "false");
  const fd = new FormData();
  fd.append("file", e.target.files[0]);
  fd.append("custom", $("custom").checked);
  analyze(fd);
};


// ------------------------------------------------------------------ monitor

const terminal = $("terminal");
let totals, history, scores, ports, pairs, threshold = null, source = null, mode = "replay";

function resetMonitor() {
  totals = {total: 0, alerts: 0, probe: 0, unknown: 0, attack: 0};
  history = [];          // last 60 batches
  scores = [];           // last 3000 [score, kind]
  ports = new Map();     // port -> worst kind
  pairs = new Map();     // "src>dst" -> row
  $("log").innerHTML = `<li class="empty" style="display:block">No incidents.</li>`;
  drawMonitor();
}

function print(text, cls) {
  if (cls === "clear") { terminal.innerHTML = ""; return; }
  const line = document.createElement("div");
  line.className = "tl " + (cls || "");
  line.textContent = text;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

// what the last 20 batches look like, in plain words
function status() {
  if (!source && !history.length) return ["idle", "Idle", "Start a replay or a live capture."];
  const recent = history.slice(-20);
  const sum = k => recent.reduce((s, b) => s + b[k], 0);
  const conns = sum("conns"), flagged = sum("alerts");
  if (!flagged) return ["quiet", "Quiet", `${n(conns)} connections, none flagged.`];
  if (sum("attack") > 0 || sum("unknown") > Math.max(20, conns * 0.1)) {
    return ["attack", "Under attack", `${n(sum("attack"))} known-attack and ${n(sum("unknown"))} unknown connections. ${pct(flagged / conns, 0)} of traffic flagged.`];
  }
  if (sum("probe") > 0) return ["scanning", "Being scanned", `${n(sum("probe"))} scan / probe connections against ${n(ports.size)} ports so far.`];
  return ["watch", "Watch", `${n(flagged)} of ${n(conns)} connections flagged.`];
}

function drawMonitor() {
  $("c-total").textContent = n(totals.total);
  $("c-alerts").textContent = n(totals.alerts);
  $("c-probe").textContent = n(totals.probe);
  $("c-unknown").textContent = n(totals.unknown);
  const last = history.slice(-3);
  $("c-rate").textContent = n(Math.round(last.length ? last.reduce((s, b) => s + b.conns, 0) / last.length : 0));

  const [level, word, why] = status();
  document.body.dataset.level = level;
  $("level").textContent = word.toLowerCase();
  $("state").textContent = word;
  $("state-why").textContent = why;
  sparkline($("spark"), history.map(b => b.conns ? b.alerts / b.conns : 0));

  stackedBars($("traffic"), history, 60, 190);
  scoreHistogram($("scores"), scores, threshold);
  portStrip($("ports"), [...ports.entries()]);
  const scanned = [...ports.values()].filter(k => k !== "normal").length;
  $("ports-note").textContent = ports.size
    ? `${n(ports.size)} distinct ports, ${n(scanned)} of them in flagged connections. A scan shows up as a wide band.`
    : "A port scan shows up as a wide band; normal traffic as a few thin lines.";

  // which model caught it: the classifier names it, or only the autoencoder flags it
  const named = totals.alerts - totals.unknown;
  const flagged = totals.alerts || 1;
  $("layers").innerHTML = totals.alerts ? `
    <div class="split"><i style="width:${named / flagged * 100}%;background:${color("attack")}"></i><i style="width:${totals.unknown / flagged * 100}%;background:${color("unknown")}"></i></div>
    <div class="layer-row"><span><i class="sw attack"></i>Named by the classifier</span><span class="num">${n(named)}</span></div>
    <div class="layer-row"><span><i class="sw unknown"></i>Only the autoencoder</span><span class="num">${n(totals.unknown)}</span></div>
    <p class="caption">${pct(totals.unknown / flagged, 0)} of flagged connections would have passed as normal with the classifier alone.</p>`
    : `<p class="empty" style="padding:0">No flagged connections yet.</p>`;

  const rows = [...pairs.values()].sort((a, b) => b.alerts - a.alerts || b.connections - a.connections);
  $("pairs").innerHTML = pairRows(rows, true);
}

function onBatch(b) {
  const time = new Date().toTimeString().slice(0, 8);
  const bin = {normal: 0, probe: 0, attack: 0, unknown: 0, conns: b.connections, alerts: 0, label: time};
  for (const [label, count] of Object.entries(b.counts)) {
    const k = kind(label);
    bin[k] += count;
    if (k !== "normal") bin.alerts += count;
  }
  totals.total += b.connections;
  totals.alerts += bin.alerts;
  totals.probe += bin.probe;
  totals.unknown += bin.unknown;
  totals.attack += bin.attack;
  history.push(bin);
  if (history.length > 60) history.shift();
  scores.push(...b.scores);
  if (scores.length > 3000) scores.splice(0, scores.length - 3000);

  for (const [port, k] of b.ports) {
    const old = ports.get(port);
    if (!old || RANK[k] > RANK[old]) ports.set(port, k);
  }
  for (const p of b.pairs) {
    const key = p.src + ">" + p.dst;
    const row = pairs.get(key) || {src: p.src, dst: p.dst, connections: 0, alerts: 0, portSet: new Set()};
    row.connections += p.connections;
    row.alerts += p.alerts;
    for (const port of p.ports) row.portSet.add(port);
    row.portCount = row.portSet.size;
    row.kindCounts = row.kindCounts || {};
    row.kindCounts[p.main] = (row.kindCounts[p.main] || 0) + p.alerts;
    row.main = Object.entries(row.kindCounts).filter(([k]) => k !== "normal").sort((a, b) => b[1] - a[1])[0]?.[0] || "normal";
    row.last = time;
    pairs.set(key, row);
  }

  const log = $("log");
  if (b.alerts.length && log.querySelector(".empty")) log.innerHTML = "";
  for (const a of b.alerts) {
    if (mode === "live") print(`[ALERT] ${a.label} ${a.src} -> ${a.dst} (${a.connections} conn)`, "ids " + kind(a.label));
    log.insertAdjacentHTML("afterbegin", `<li data-kind="${kind(a.label)}"><time>${time}</time><span class="bar"></span>
      <div><div class="t"><b>${esc(a.label)}</b><span>${n(a.connections)} conn</span></div>
      <div class="why" data-tip="${esc(a.why)}">${esc(a.src)} &rarr; ${esc(a.dst)} &middot; ${esc(a.why)}</div></div></li>`);
  }
  while (log.children.length > 60) log.lastChild.remove();
  drawMonitor();
}

function startMonitor() {
  resetMonitor();
  const url = mode === "live"
    ? "/api/live?iface=" + $("iface").value
    : `/api/replay?sample=${$("replay-sample").value}&speed=${$("replay-speed").value}`;
  source = new EventSource(url);
  $("monitor-btn").textContent = "Stop";
  $("monitor-btn").className = "btn stop";
  $("sensor").textContent = "starting...";
  source.addEventListener("start", function (e) {
    const s = JSON.parse(e.data);
    threshold = s.threshold;
    $("sensor").textContent = (mode === "live" ? "live on " : "replaying ") + s.source;
    if (mode === "live") print("[monitor] watching " + s.source, "info");
  });
  source.addEventListener("batch", e => onBatch(JSON.parse(e.data)));
  source.addEventListener("end", function () {
    stopMonitor();
    $("sensor").textContent = "replay finished";
  });
  source.onerror = function () {
    if (source && source.readyState === EventSource.CLOSED) stopMonitor();
  };
}

function stopMonitor() {
  if (source) source.close();
  source = null;
  $("monitor-btn").textContent = "Start";
  $("monitor-btn").className = "btn";
  $("sensor").textContent = "sensor idle";
  drawMonitor();
}

$("monitor-btn").onclick = () => (source ? stopMonitor() : startMonitor());

for (const b of document.querySelectorAll("#mode button")) {
  b.onclick = function () {
    if (source) stopMonitor();
    mode = b.dataset.mode;
    for (const x of document.querySelectorAll("#mode button")) x.setAttribute("aria-pressed", x === b);
    $("replay-opts").hidden = mode !== "replay";
    $("live-opts").hidden = mode !== "live";
  };
}

// attack range

function setSwitch(id, on) {
  $(id).setAttribute("aria-checked", on ? "true" : "false");
}

function sendCommand(cmd) {
  postJSON("/api/range/command", {cmd: cmd}).then(syncRange).catch(e => print(e.message, "err"));
}

function syncRange(state) {
  setSwitch("browse", state.browsing);
  setSwitch("auto", state.auto);
}

for (const btn of document.querySelectorAll(".cmd")) btn.onclick = () => sendCommand(btn.dataset.cmd);

$("cmd-form").onsubmit = function (e) {
  e.preventDefault();
  const input = $("cmd");
  if (input.value.trim()) sendCommand(input.value);
  input.value = "";
};

$("browse").onclick = function () { sendCommand("browse " + (this.getAttribute("aria-checked") !== "true" ? "on" : "off")); };
$("auto").onclick = function () { sendCommand("auto " + (this.getAttribute("aria-checked") !== "true" ? "on" : "off")); };

// output from nmap / flood comes from the server as a stream of lines
const rangeConsole = new EventSource("/api/range/console");
rangeConsole.addEventListener("line", function (e) {
  const line = JSON.parse(e.data);
  if (line.kind === "prompt") print("attacker$ " + line.text, "prompt");
  else if (line.kind === "cmd") print("$ " + line.text, "cmd");
  else print(line.text, line.kind === "out" ? "" : line.kind);
});


// ------------------------------------------------------------------ lab

const presets = {
  normal: {flag: "SF", service: "http", src_bytes: 250, count: 5, serror_rate: 0, rerror_rate: 0,
           dst_host_count: 50, dst_host_serror_rate: 0},
  synflood: {flag: "S0", service: "private", src_bytes: 0, count: 250, serror_rate: 1, rerror_rate: 0,
             dst_host_count: 255, dst_host_serror_rate: 1},
  scan: {flag: "REJ", service: "other", src_bytes: 0, count: 1, serror_rate: 0, rerror_rate: 1,
         dst_host_count: 255, dst_host_serror_rate: 0}
};

const labForm = $("lab-form");

for (const btn of document.querySelectorAll(".preset")) {
  btn.onclick = function () {
    const p = presets[btn.dataset.preset];
    for (const key of Object.keys(p)) labForm.elements[key].value = p[key];
    labForm.requestSubmit();
  };
}

labForm.onsubmit = async function (e) {
  e.preventDefault();
  const values = {};
  for (const el of labForm.elements) {
    if (!el.name) continue;
    values[el.name] = el.type === "number" ? Number(el.value) : el.value;
  }
  // a scan or flood also means the stats over the last connections change
  if (values.flag === "S0") values.srv_serror_rate = values.serror_rate;
  if (values.flag === "REJ") values.srv_rerror_rate = values.rerror_rate;
  values.srv_count = values.count;

  const out = $("lab-body");
  try {
    const r = await postJSON("/api/lab", values);
    const reasons = r.reasons.map(x => `<li><code>${esc(x.feature)} = ${esc(x.value)}</code>: ${esc(x.description)}</li>`).join("");
    // log scale, threshold in the middle
    const pos = Math.min(Math.max((Math.log10(r.score) - Math.log10(r.threshold) + 2) / 4, 0), 1) * 100;
    out.innerHTML = `<label>decision</label><div class="verdict" data-kind="${kind(r.label)}">${esc(r.label)}</div>
      <p class="state-why">${esc(r.description)}</p>
      <label>autoencoder score vs threshold (log scale)</label>
      <div class="meter"><i style="width:${pos}%"></i><b style="left:50%"></b></div>
      <p class="caption mono">score ${r.score.toPrecision(3)}, threshold ${r.threshold.toPrecision(3)}<br>
        classifier said ${esc(r.classifier_label)} (${pct(r.confidence)} sure)</p>
      <label style="display:block;margin-top:12px">most unusual values</label><ul class="reasons">${reasons}</ul>`;
  } catch (err) {
    out.innerHTML = `<p class="error">${esc(err.message)}</p>`;
  }
};


// ------------------------------------------------------------------ start

async function start() {
  let st;
  try {
    st = await getJSON("/api/status");
  } catch (e) {
    $("sensor").textContent = "server not reachable";
    return;
  }

  for (const run of st.runs) {
    const b = document.createElement("button");
    b.type = "button";
    b.dataset.run = run;
    b.textContent = RUN_NAMES[run] || run;
    b.onclick = () => loadRun(run);
    $("run-tabs").appendChild(b);
  }

  for (const s of st.samples) {
    $("replay-sample").innerHTML += `<option value="${esc(s)}">${esc(s)}.pcap</option>`;
    const b = document.createElement("button");
    b.type = "button";
    b.className = "sample";
    b.dataset.sample = s;
    b.textContent = s + ".pcap";
    b.onclick = () => analyzeSample(s);
    $("samples").appendChild(b);
  }

  if (!st.root) {
    $("root-note").hidden = false;
    $("root-note").innerHTML = "Live capture needs root. Restart with <code>sudo .venv/bin/netsentinel web</code>. Replay works without it.";
    document.querySelector('#mode button[data-mode="live"]').disabled = true;
  }

  getJSON("/api/range").then(syncRange);
  if (st.runs.length) loadRun(st.runs[0]);
}

let resizeTimer;
window.addEventListener("resize", function () {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(function () {
    drawMonitor();
    if (currentResults) showResults();
  }, 150);
});

resetMonitor();
start();
