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
    `<figure class="cell"><figcaption class="cell-title">${title}</figcaption>
     <img src="${fig}${f}_${tag}.png" alt="${title}" onerror="this.parentNode.remove()"></figure>`).join("");
}

document.getElementById("split").onchange = showResults;


// analyze

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
      const color = COLORS[kind(label)];
      mix += `<span style="width:${count / total * 100}%;background:${color}"></span>`;
      legend += `<span><i class="sw ${kind(label)}"></i>${esc(label)} ${count.toLocaleString()}</span>`;
    }
    let html = `<div class="tape-stats" style="grid-template-columns:repeat(3,minmax(0,1fr));border-top:1px solid var(--rule)">
      <div class="stat"><span class="stat-n">${d.connections.toLocaleString()}</span><span class="stat-l">connections</span></div>
      <div class="stat"><span class="stat-n">${d.alerts.toLocaleString()}</span><span class="stat-l">alerts</span></div>
      <div class="stat"><span class="stat-n">${d.seconds}s</span><span class="stat-l">of traffic</span></div></div>
      <div class="mix">${mix}</div><div class="mix-legend">${legend}</div>
      <h3 class="cell-title">Incidents</h3><ol class="feed">`;
    for (const inc of d.incidents) html += incidentHTML(inc);
    out.innerHTML = html + "</ol>";
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


// live

const terminal = document.getElementById("terminal");
const totals = {total: 0, normal: 0, alerts: 0, probe: 0, unknown: 0};
let liveSource = null;

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

function updateCounts() {
  for (const key of Object.keys(totals)) {
    document.getElementById("c-" + key).textContent = totals[key].toLocaleString();
  }
}

function setSwitch(id, on) {
  document.getElementById(id).setAttribute("aria-checked", on ? "true" : "false");
}

function startMonitoring() {
  for (const key of Object.keys(totals)) totals[key] = 0;
  updateCounts();
  document.getElementById("live-feed").innerHTML = "";
  const iface = document.getElementById("iface").value;
  liveSource = new EventSource("/api/live?iface=" + iface);
  setSwitch("monitor-btn", true);
  print("[monitor] watching " + iface, "info");

  liveSource.addEventListener("batch", function (e) {
    const b = JSON.parse(e.data);
    totals.total += b.connections;
    for (const [label, count] of Object.entries(b.counts)) {
      if (label === "normal") totals.normal += count;
      else totals.alerts += count;
      if (kind(label) === "probe") totals.probe += count;
      if (label === "Unknown-Anomaly") totals.unknown += count;
    }
    updateCounts();
    const feed = document.getElementById("live-feed");
    for (const a of b.alerts) {
      print(`[IDS] ${a.label} ${a.src} -> ${a.dst} (${a.connections} conn) ${a.why}`, "ids " + kind(a.label));
      feed.insertAdjacentHTML("afterbegin", `<li class="incident" data-kind="${kind(a.label)}"><span class="bar"></span>
        <div class="who"><b>${esc(a.label)}</b>${esc(a.src)} &rarr; ${esc(a.dst)}
        <small>${a.connections} connections</small></div>
        <div class="why" style="direction:ltr;text-align:left"><code>${esc(a.why)}</code></div></li>`);
    }
    while (feed.children.length > 8) feed.lastChild.remove();
  });
  liveSource.onerror = function () {
    print("[monitor] connection lost", "err");
  };
}

function stopMonitoring() {
  liveSource.close();
  liveSource = null;
  setSwitch("monitor-btn", false);
  print("[monitor] stopped", "info");
}

document.getElementById("monitor-btn").onclick = function (e) {
  if (e.target.tagName === "SELECT" || e.target.tagName === "OPTION") return;
  if (liveSource) stopMonitoring();
  else startMonitoring();
};

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
  const on = this.getAttribute("aria-checked") !== "true";
  sendCommand("browse " + (on ? "on" : "off"));
};
document.getElementById("auto").onclick = function () {
  const on = this.getAttribute("aria-checked") !== "true";
  sendCommand("auto " + (on ? "on" : "off"));
};

// output from nmap / flood comes from the server as a stream of lines
const console_ = new EventSource("/api/range/console");
console_.addEventListener("line", function (e) {
  const line = JSON.parse(e.data);
  if (line.kind === "prompt") print("attacker$ " + line.text, "prompt");
  else if (line.kind === "cmd") print("$ " + line.text, "cmd");
  else print(line.text, line.kind === "out" ? "" : line.kind);
});


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
    note.innerHTML = "Monitoring needs root. Restart with <code>sudo .venv/bin/netsentinel web</code> (attack buttons work anyway).";
    document.getElementById("monitor-btn").disabled = true;
  }

  getJSON("/api/range").then(syncRange);
  if (status.runs.length) loadRun(status.runs[0]);
}

start();
