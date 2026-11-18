// NetSentinel website

function esc(text) {
  return String(text == null ? "" : text)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function pct(x) {
  if (x == null) return "-";
  return (x * 100).toFixed(1) + "%";
}

// colour group for a label
function kind(label) {
  if (label === "normal" || label === "BENIGN") return "normal";
  if (label === "Unknown-Anomaly") return "unknown";
  if (label === "Probe" || label === "PortScan") return "probe";
  return "attack";
}

const COLORS = {normal: "var(--calm)", probe: "var(--scan)", attack: "var(--breach)", unknown: "var(--ghost)"};

async function getJSON(url, options) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

function postJSON(url, body) {
  return getJSON(url, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  });
}

let status = null;


// results

let currentResults = null;

async function loadRun(run) {
  for (const b of document.querySelectorAll("#run-tabs button")) {
    b.setAttribute("aria-selected", b.dataset.run === run);
  }
  currentResults = await getJSON("/api/results/" + run);
  const splitSelect = document.getElementById("split");
  splitSelect.innerHTML = "";
  for (const split of Object.keys(currentResults.test)) {
    splitSelect.innerHTML += `<option>${esc(split)}</option>`;
  }
  showResults();
}

function showResults() {
  const res = currentResults;
  const split = document.getElementById("split").value;
  const m = res.test[split];
  const tag = split.replace("+", "plus");

  document.getElementById("run-meta").textContent =
    `${res.metadata.classifier} + ${res.metadata.detector}, ${m.n_samples.toLocaleString()} test rows`;

  const c = m.classifier_only, h = m.hybrid;
  let kpis = `
    <div class="kpi up"><div class="v">${pct(h.detection_rate)}</div>
      <div class="from">classifier alone ${pct(c.detection_rate)}</div><div class="l">detection rate</div></div>
    <div class="kpi"><div class="v">${pct(h.false_alarm_rate)}</div>
      <div class="from">classifier alone ${pct(c.false_alarm_rate)}</div><div class="l">false alarms</div></div>`;
  if (m.novel_attacks) {
    const n = m.novel_attacks;
    kpis += `<div class="kpi up"><div class="v">${pct(n.hybrid_dr)}</div>
      <div class="from">classifier alone ${pct(n.classifier_only_dr)}</div><div class="l">new attacks caught</div></div>`;
  } else {
    kpis += `<div class="kpi"><div class="v">${pct(h.precision)}</div>
      <div class="from">classifier alone ${pct(c.precision)}</div><div class="l">precision</div></div>`;
  }
  kpis += `<div class="kpi"><div class="v">${h.f1.toFixed(3)}</div>
    <div class="from">classifier alone ${c.f1.toFixed(3)}</div><div class="l">F1</div></div>`;
  document.getElementById("kpis").innerHTML = kpis;

  let modes = `<table><tr><th></th><th class="num">detection</th><th class="num">false alarms</th><th class="num">F1</th></tr>`;
  for (const mode of ["classifier_only", "anomaly_only", "hybrid"]) {
    const r = m[mode];
    modes += `<tr class="${mode === "hybrid" ? "winner" : ""}"><td>${mode.replace("_", " ")}</td>
      <td class="num">${pct(r.detection_rate)}</td><td class="num">${pct(r.false_alarm_rate)}</td>
      <td class="num">${r.f1.toFixed(3)}</td></tr>`;
  }
  document.getElementById("table-modes").innerHTML = modes + "</table>";

  const cats = m.detection_rate_by_category;
  let catTable = `<table><tr><th>family</th><th class="num">classifier</th><th class="num">hybrid</th></tr>`;
  for (const cat of Object.keys(cats.hybrid)) {
    if (cat === "normal") continue;
    catTable += `<tr><td>${esc(cat)}</td><td class="num">${pct(cats.classifier_only[cat])}</td>
      <td class="num">${pct(cats.hybrid[cat])}</td></tr>`;
  }
  document.getElementById("table-cats").innerHTML = catTable + "</table>";

  const fig = `/reports/${res.run}/figures/`;
  const figs = [["confusion", "Confusion matrix"], ["roc", "ROC curve"],
                ["threshold_sensitivity", "Threshold trade-off"]];
  if (m.novel_attacks) figs.push(["novel_detection", "Attacks never seen in training"]);
  document.getElementById("figs").innerHTML = figs.map(([f, title]) =>
    `<figure class="panel"><div class="panel-h"><span>FIG</span>${title}</div>
     <img src="${fig}${f}_${tag}.png" alt="${title}" onerror="this.parentNode.remove()"></figure>`).join("");
}

document.getElementById("split").onchange = showResults;


// charts

function setupCanvas(canvas) {
  const ratio = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (canvas.width !== w * ratio) { canvas.width = w * ratio; canvas.height = h * ratio; }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, w, h);
  return {ctx, w, h};
}

const CSSVAR = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const KINDS = ["normal", "probe", "attack", "unknown"];
const kindColor = k => ({normal: CSSVAR("--calm"), probe: CSSVAR("--scan"), attack: CSSVAR("--breach"), unknown: CSSVAR("--ghost")})[k];

// stacked bars, one per bin: bins = [{normal, probe, attack, unknown}, ...]
function drawStacked(canvas, bins, slots) {
  const {ctx, w, h} = setupCanvas(canvas);
  const n = slots || bins.length || 1;
  // square-root scale so one burst does not flatten every other bar
  const max = Math.sqrt(Math.max(1, ...bins.map(b => KINDS.reduce((s, k) => s + (b[k] || 0), 0))));
  const bw = w / n;
  ctx.strokeStyle = CSSVAR("--rule");
  for (let i = 1; i < 4; i++) { ctx.beginPath(); ctx.moveTo(0, h * i / 4); ctx.lineTo(w, h * i / 4); ctx.stroke(); }
  bins.forEach((b, i) => {
    let y = h;
    const x = (n - bins.length + i) * bw;
    const total = KINDS.reduce((s, k) => s + (b[k] || 0), 0);
    const height = Math.sqrt(total) / max * (h - 16);
    for (const k of KINDS) {
      const bh = total ? (b[k] || 0) / total * height : 0;
      ctx.fillStyle = kindColor(k);
      ctx.fillRect(x + 1, y - bh, Math.max(bw - 2, 1), bh);
      y -= bh;
    }
  });
  ctx.fillStyle = CSSVAR("--ash");
  ctx.font = "11px Departure, monospace";
  ctx.fillText("max " + Math.round(max * max) + " conn (sqrt scale)", 6, 12);
}

// scatter of anomaly scores with the threshold line
function drawScores(canvas, points, threshold) {
  const {ctx, w, h} = setupCanvas(canvas);
  if (!threshold) return;
  const lo = Math.log10(threshold) - 3, hi = Math.log10(threshold) + 3;
  const y = s => h - (Math.min(Math.max(Math.log10(Math.max(s, 1e-9)), lo), hi) - lo) / (hi - lo) * (h - 10) - 5;
  points.forEach((p, i) => {
    ctx.fillStyle = kindColor(p[1]);
    ctx.fillRect(i / Math.max(points.length, 1) * w, y(p[0]) - 1.5, 3, 3);
  });
  ctx.strokeStyle = CSSVAR("--bone");
  ctx.setLineDash([4, 4]);
  ctx.beginPath(); ctx.moveTo(0, y(threshold)); ctx.lineTo(w, y(threshold)); ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillStyle = CSSVAR("--bone");
  ctx.font = "11px Departure, monospace";
  ctx.fillText("threshold " + threshold.toFixed(4), 6, y(threshold) - 6);
}

function hostRows(hosts) {
  let html = `<tr><th>host</th><th class="num">connections</th><th class="num">alerts</th><th>status</th></tr>`;
  for (const h of hosts) {
    const word = {normal: "clear", probe: "scanned", attack: "attacked", unknown: "anomalous"}[h.worst];
    html += `<tr><td class="mono">${esc(h.ip)}</td><td class="num">${h.connections.toLocaleString()}</td>
      <td class="num">${h.alerts.toLocaleString()}</td><td><span class="chip ${h.worst}">${word}</span></td></tr>`;
  }
  return html;
}


// analysis

function incidentHTML(inc) {
  let reasons = "";
  for (const r of inc.reasons) {
    const z = r.z_score == null ? "" : ` (z=${r.z_score.toFixed(1)})`;
    reasons += `<li><code>${esc(r.feature)} = ${esc(r.value)}</code>${z}: ${esc(r.description)}</li>`;
  }
  const ports = inc.ports ? `, ${inc.ports} ports` : "";
  return `<li class="incident" data-kind="${kind(inc.label)}"><span class="bar"></span>
    <div class="who"><b>${esc(inc.label)}</b>${esc(inc.src)} &rarr; ${esc(inc.dst)}
      <small>${inc.connections} connections${ports}, ${esc(inc.severity)}</small></div>
    <div class="why" style="direction:ltr;text-align:left"><ul style="padding:0 0 0 18px">${reasons}</ul></div></li>`;
}

async function analyze(formData) {
  const out = document.getElementById("analyze-out");
  out.innerHTML = `<p class="loading">Reading packets</p>`;
  try {
    const d = await getJSON("/api/analyze", {method: "POST", body: formData});
    const total = Object.values(d.counts).reduce((a, b) => a + b, 0) || 1;
    let mix = "", legend = "";
    for (const [label, count] of Object.entries(d.counts)) {
      mix += `<span style="width:${count / total * 100}%;background:${COLORS[kind(label)]}"></span>`;
      legend += `<span><i class="sw ${kind(label)}"></i>${esc(label)} ${count.toLocaleString()}</span>`;
    }
    let html = `<div class="tape-stats" style="grid-template-columns:repeat(3,minmax(0,1fr));border-top:1px solid var(--rule)">
      <div class="stat"><span class="stat-n">${d.connections.toLocaleString()}</span><span class="stat-l">connections</span></div>
      <div class="stat"><span class="stat-n alert-n">${d.alerts.toLocaleString()}</span><span class="stat-l">alerts</span></div>
      <div class="stat"><span class="stat-n">${d.seconds}s</span><span class="stat-l">of traffic</span></div></div>
      <div class="mix">${mix}</div><div class="mix-legend">${legend}</div>
      <div class="grid-2">
        <div class="panel"><div class="panel-h"><span>AN-01</span>Timeline (${d.timeline.seconds}s, 60 slices)</div>
          <canvas id="an-timeline" height="190"></canvas></div>
        <div class="panel"><div class="panel-h"><span>AN-02</span>Hosts</div>
          <div class="scroll"><table>${hostRows(d.hosts)}</table></div></div>
      </div>
      <div class="panel"><div class="panel-h"><span>AN-03</span>Incidents</div><ol class="feed" style="padding:0 14px">`;
    for (const inc of d.incidents) html += incidentHTML(inc);
    out.innerHTML = html + "</ol></div>";
    const bins = d.timeline.bins.normal.map((_, i) => Object.fromEntries(KINDS.map(k => [k, d.timeline.bins[k][i]])));
    drawStacked(document.getElementById("an-timeline"), bins);
  } catch (e) {
    out.innerHTML = `<p class="error">${esc(e.message)}</p>`;
  }
}

function analyzeSample(name) {
  for (const b of document.querySelectorAll(".sample")) b.setAttribute("aria-pressed", b.dataset.sample === name);
  const fd = new FormData();
  fd.append("sample", name);
  fd.append("custom", document.getElementById("custom").checked);
  analyze(fd);
}

document.getElementById("upload").onchange = function (e) {
  for (const b of document.querySelectorAll(".sample")) b.setAttribute("aria-pressed", "false");
  const fd = new FormData();
  fd.append("file", e.target.files[0]);
  fd.append("custom", document.getElementById("custom").checked);
  analyze(fd);
};


// operations

const terminal = document.getElementById("terminal");
let totals, history, scores, hosts, threshold = null, source = null, mode = "replay";

function resetOps() {
  totals = {total: 0, alerts: 0, probe: 0, unknown: 0};
  history = [];      // last 60 batches: {normal, probe, attack, unknown, conns, alerts}
  scores = [];       // last 1500 [score, kind]
  hosts = {};
  document.getElementById("live-feed").innerHTML = "";
  updateOps();
}

function print(text, cls) {
  if (cls === "clear") {
    terminal.innerHTML = "";
    return;
  }
  const line = document.createElement("div");
  line.className = "tl " + (cls || "");
  line.textContent = text;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

// threat level from the last 20 batches
function threatLevel() {
  const recent = history.slice(-20);
  const conns = recent.reduce((s, b) => s + b.conns, 0);
  const alerts = recent.reduce((s, b) => s + b.alerts, 0);
  const attack = recent.reduce((s, b) => s + b.attack, 0);
  const unknown = recent.reduce((s, b) => s + b.unknown, 0);
  const probe = recent.reduce((s, b) => s + b.probe, 0);
  const share = conns ? alerts / conns : 0;
  if (!source && !conns) return ["low", "No scan running."];
  if (alerts === 0) return ["low", "No alerts in the last 20 batches."];
  if (share > 0.6 && alerts > 100) return ["severe", `${pct(share)} of recent traffic is hostile.`];
  if (attack > 0 || unknown > 20 || share > 0.25) return ["high", `${attack} known attack and ${unknown} unknown connections recently.`];
  if (probe > 0 || share > 0.05) return ["elevated", `${probe} scan / probe connections recently.`];
  return ["guarded", `${alerts} alerts out of ${conns} recent connections.`];
}

function updateOps() {
  for (const key of Object.keys(totals)) {
    document.getElementById("c-" + key).textContent = totals[key].toLocaleString();
  }
  const last = history.slice(-3);
  const rate = last.length ? last.reduce((s, b) => s + b.conns, 0) / last.length : 0;
  document.getElementById("c-rate").textContent = Math.round(rate).toLocaleString();

  const [level, why] = threatLevel();
  document.body.dataset.level = level;
  document.getElementById("threat-big").textContent = level.toUpperCase();
  document.getElementById("threat-word").textContent = level.toUpperCase();
  document.getElementById("threat-why").textContent = why;

  drawStacked(document.getElementById("traffic-canvas"), history, 60);
  drawScores(document.getElementById("score-canvas"), scores, threshold);
  const list = Object.values(hosts).sort((a, b) => b.alerts - a.alerts || b.connections - a.connections);
  document.getElementById("hosts").innerHTML = hostRows(list);
}

function onBatch(b) {
  const bin = {normal: 0, probe: 0, attack: 0, unknown: 0, conns: b.connections, alerts: 0};
  for (const [label, count] of Object.entries(b.counts)) {
    bin[kind(label)] += count;
    if (label !== "normal" && label !== "BENIGN") bin.alerts += count;
  }
  totals.total += b.connections;
  totals.alerts += bin.alerts;
  totals.probe += bin.probe;
  totals.unknown += bin.unknown;
  history.push(bin);
  if (history.length > 60) history.shift();
  scores.push(...b.points);
  if (scores.length > 1500) scores.splice(0, scores.length - 1500);

  const rank = {normal: 0, probe: 1, unknown: 2, attack: 3};
  for (const h of b.hosts) {
    const old = hosts[h.ip] || {ip: h.ip, connections: 0, alerts: 0, worst: "normal"};
    old.connections += h.connections;
    old.alerts += h.alerts;
    if (rank[h.worst] > rank[old.worst]) old.worst = h.worst;
    hosts[h.ip] = old;
  }

  const feed = document.getElementById("live-feed");
  const time = new Date().toISOString().slice(11, 19);
  for (const a of b.alerts) {
    if (mode === "live") print(`[ALERT] ${a.label} ${a.src} -> ${a.dst} (${a.connections} conn)`, "ids " + kind(a.label));
    feed.insertAdjacentHTML("afterbegin", `<li class="incident" data-kind="${kind(a.label)}"><span class="bar"></span>
      <div class="who"><time>${time}</time><b>${esc(a.label)}</b>${esc(a.src)} &rarr; ${esc(a.dst)}
      <small>${a.connections} connections</small></div>
      <div class="why" style="direction:ltr;text-align:left"><code>${esc(a.why)}</code></div></li>`);
  }
  while (feed.children.length > 40) feed.lastChild.remove();
  updateOps();
}

function startScan() {
  resetOps();
  let url;
  if (mode === "live") {
    url = "/api/live?iface=" + document.getElementById("iface").value;
  } else {
    url = `/api/replay?sample=${document.getElementById("replay-sample").value}&speed=${document.getElementById("replay-speed").value}`;
  }
  source = new EventSource(url);
  const btn = document.getElementById("monitor-btn");
  btn.textContent = "Stop scan";
  btn.classList.add("running");
  source.addEventListener("start", function (e) {
    const s = JSON.parse(e.data);
    threshold = s.threshold;
    document.getElementById("source-name").textContent = (mode === "live" ? "live: " : "replay: ") + s.source;
    if (mode === "live") print("[monitor] watching " + s.source, "info");
  });
  source.addEventListener("batch", e => onBatch(JSON.parse(e.data)));
  source.addEventListener("end", function () {
    stopScan();
    document.getElementById("source-name").textContent += " (finished)";
  });
  source.onerror = function () {
    if (source && source.readyState === EventSource.CLOSED) stopScan();
  };
}

function stopScan() {
  if (source) source.close();
  source = null;
  const btn = document.getElementById("monitor-btn");
  btn.textContent = "Start scan";
  btn.classList.remove("running");
  updateOps();
}

document.getElementById("monitor-btn").onclick = function () {
  if (source) stopScan();
  else startScan();
};

for (const b of document.querySelectorAll("#mode button")) {
  b.onclick = function () {
    if (source) stopScan();
    mode = b.dataset.mode;
    for (const x of document.querySelectorAll("#mode button")) x.setAttribute("aria-pressed", x === b);
    document.getElementById("replay-opts").hidden = mode !== "replay";
    document.getElementById("live-opts").hidden = mode !== "live";
  };
}

function setSwitch(id, on) {
  document.getElementById(id).setAttribute("aria-checked", on ? "true" : "false");
}

function sendCommand(cmd) {
  postJSON("/api/range/command", {cmd: cmd}).then(syncRange).catch(function (e) {
    print(e.message, "err");
  });
}

function syncRange(state) {
  setSwitch("browse", state.browsing);
  setSwitch("auto", state.auto);
}

for (const btn of document.querySelectorAll(".cmd")) {
  btn.onclick = function () { sendCommand(btn.dataset.cmd); };
}

document.getElementById("cmd-form").onsubmit = function (e) {
  e.preventDefault();
  const input = document.getElementById("cmd");
  if (input.value.trim()) sendCommand(input.value);
  input.value = "";
};

document.getElementById("browse").onclick = function () {
  sendCommand("browse " + (this.getAttribute("aria-checked") !== "true" ? "on" : "off"));
};
document.getElementById("auto").onclick = function () {
  sendCommand("auto " + (this.getAttribute("aria-checked") !== "true" ? "on" : "off"));
};

// output from nmap / flood comes from the server as a stream of lines
const console_ = new EventSource("/api/range/console");
console_.addEventListener("line", function (e) {
  const line = JSON.parse(e.data);
  if (line.kind === "prompt") print("attacker$ " + line.text, "prompt");
  else if (line.kind === "cmd") print("$ " + line.text, "cmd");
  else print(line.text, line.kind === "out" ? "" : line.kind);
});

setInterval(function () {
  document.getElementById("clock").textContent = new Date().toISOString().slice(11, 19) + " UTC";
}, 1000);
window.addEventListener("resize", () => updateOps());


// lab

const presets = {
  normal: {flag: "SF", service: "http", src_bytes: 250, count: 5, serror_rate: 0, rerror_rate: 0,
           dst_host_count: 50, dst_host_serror_rate: 0},
  synflood: {flag: "S0", service: "private", src_bytes: 0, count: 250, serror_rate: 1, rerror_rate: 0,
             dst_host_count: 255, dst_host_serror_rate: 1},
  scan: {flag: "REJ", service: "other", src_bytes: 0, count: 1, serror_rate: 0, rerror_rate: 1,
         dst_host_count: 255, dst_host_serror_rate: 0}
};

const labForm = document.getElementById("lab-form");

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

  const out = document.getElementById("lab-body");
  try {
    const r = await postJSON("/api/lab", values);
    let reasons = "";
    for (const x of r.reasons) reasons += `<li><code>${esc(x.feature)} = ${esc(x.value)}</code>: ${esc(x.description)}</li>`;
    // meter: anomaly score with the threshold mark in the middle
    const fill = Math.min(r.score / (2 * r.threshold), 1) * 100;
    out.innerHTML = `<div class="verdict-label" data-kind="${kind(r.label)}">${esc(r.label)}</div>
      <p class="verdict-meta">${esc(r.description)}</p>
      <div class="meter"><i style="width:${fill}%"></i><b style="left:50%"></b></div>
      <p class="verdict-meta">anomaly score ${r.score.toFixed(4)} / threshold ${r.threshold.toFixed(4)}<br>
        classifier: ${esc(r.classifier_label)} (${pct(r.confidence)})</p>
      <ul style="direction:ltr;text-align:left;padding:0 0 0 18px">${reasons}</ul>`;
  } catch (err) {
    out.innerHTML = `<p class="error">${esc(err.message)}</p>`;
  }
};


// start

async function start() {
  const statusEl = document.getElementById("status");
  try {
    status = await getJSON("/api/status");
  } catch (e) {
    statusEl.textContent = "Server not reachable";
    statusEl.className = "status err";
    return;
  }
  statusEl.textContent = status.runs.length + " models" + (status.root ? ", live capture on" : "");
  statusEl.className = "status ok";

  const tabs = document.getElementById("run-tabs");
  for (const run of status.runs) {
    const b = document.createElement("button");
    b.type = "button";
    b.dataset.run = run;
    b.textContent = run;
    b.onclick = function () { loadRun(run); };
    tabs.appendChild(b);
  }

  const samples = document.getElementById("samples");
  for (const s of status.samples) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "sample";
    b.dataset.sample = s;
    b.innerHTML = `<span class="name">${esc(s)}.pcap</span><span class="tag">recorded on this laptop</span>`;
    b.onclick = function () { analyzeSample(s); };
    samples.appendChild(b);
  }
  samples.style.gridTemplateColumns = `repeat(${Math.max(status.samples.length, 1)}, minmax(0, 1fr))`;

  if (!status.root) {
    const note = document.getElementById("root-note");
    note.hidden = false;
    note.innerHTML = "Live capture needs root: restart with <code>sudo .venv/bin/netsentinel web</code>. Replay works without it.";
    document.querySelector('#mode button[data-mode="live"]').disabled = true;
  }

  const replaySelect = document.getElementById("replay-sample");
  for (const s of status.samples) replaySelect.innerHTML += `<option value="${esc(s)}">${esc(s)}.pcap</option>`;
  getJSON("/api/range").then(syncRange);
  if (status.runs.length) loadRun(status.runs[0]);
}

resetOps();
start();
