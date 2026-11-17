// NetSentinel website

function esc(text) {
  return String(text == null ? "" : text)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function pct(x) {
  if (x == null) return "-";
  return (x * 100).toFixed(1) + "%";
}

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

async function loadRun() {
  const run = document.getElementById("run").value;
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

  let html = `<p>Classifier: <b>${esc(res.metadata.classifier)}</b>,
    anomaly detector: <b>${esc(res.metadata.detector)}</b>,
    test rows: ${m.n_samples.toLocaleString()}</p>`;

  html += "<table><tr><th></th><th>Detection rate</th><th>False alarms</th><th>Precision</th><th>F1</th></tr>";
  for (const mode of ["classifier_only", "anomaly_only", "hybrid"]) {
    const r = m[mode];
    html += `<tr><td>${mode.replace("_", " ")}</td><td>${pct(r.detection_rate)}</td>
      <td>${pct(r.false_alarm_rate)}</td><td>${pct(r.precision)}</td><td>${r.f1.toFixed(3)}</td></tr>`;
  }
  html += "</table>";

  if (m.novel_attacks) {
    const n = m.novel_attacks;
    html += `<p>Attacks not seen in training (${n.n_samples.toLocaleString()} rows):
      classifier ${pct(n.classifier_only_dr)}, anomaly ${pct(n.anomaly_only_dr)},
      <b>hybrid ${pct(n.hybrid_dr)}</b></p>`;
  }

  html += "<table><tr><th>Category</th><th>Classifier only</th><th>Hybrid</th></tr>";
  const cats = m.detection_rate_by_category;
  for (const cat of Object.keys(cats.hybrid)) {
    if (cat === "normal") continue;
    html += `<tr><td>${esc(cat)}</td><td>${pct(cats.classifier_only[cat])}</td><td>${pct(cats.hybrid[cat])}</td></tr>`;
  }
  html += "</table>";

  const fig = `/reports/${res.run}/figures/`;
  html += `<img src="${fig}confusion_${tag}.png" alt="confusion matrix">`;
  html += `<img src="${fig}roc_${tag}.png" alt="roc curve">`;
  if (m.novel_attacks) html += `<img src="${fig}novel_detection_${tag}.png" alt="novel attacks">`;
  html += `<img src="${fig}threshold_sensitivity_${tag}.png" alt="threshold">`;

  document.getElementById("results-body").innerHTML = html;
}

document.getElementById("run").onchange = loadRun;
document.getElementById("split").onchange = showResults;


// analyze

function incidentHTML(inc) {
  let reasons = "";
  for (const r of inc.reasons) {
    const z = r.z_score == null ? "" : ` (z=${r.z_score.toFixed(1)})`;
    reasons += `<li>${esc(r.feature)} = ${esc(r.value)}${z}: ${esc(r.description)}</li>`;
  }
  const ports = inc.ports ? `, ${inc.ports} ports` : "";
  return `<div class="incident">
    <b>${esc(inc.label)}</b> (${esc(inc.severity)}) ${esc(inc.src)} &rarr; ${esc(inc.dst)},
    ${inc.connections} connections${ports}
    <ul>${reasons}</ul></div>`;
}

async function analyze(formData) {
  const out = document.getElementById("analyze-body");
  out.innerHTML = "<p>Working...</p>";
  try {
    const d = await getJSON("/api/analyze", {method: "POST", body: formData});
    let html = `<p>${d.connections.toLocaleString()} connections, ${d.alerts.toLocaleString()} alerts,
      ${d.seconds}s of traffic</p><table><tr><th>Label</th><th>Count</th></tr>`;
    for (const [label, count] of Object.entries(d.counts)) {
      html += `<tr><td>${esc(label)}</td><td>${count}</td></tr>`;
    }
    html += "</table><h3>Incidents</h3>";
    if (d.incidents.length === 0) html += "<p>No alerts.</p>";
    for (const inc of d.incidents) html += incidentHTML(inc);
    out.innerHTML = html;
  } catch (e) {
    out.innerHTML = `<p class="err">${esc(e.message)}</p>`;
  }
}

document.getElementById("analyze-btn").onclick = function () {
  const fd = new FormData();
  fd.append("sample", document.getElementById("sample").value);
  fd.append("custom", document.getElementById("custom").checked);
  analyze(fd);
};

document.getElementById("upload").onchange = function (e) {
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
  if (cls) line.className = cls;
  line.textContent = text;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

function updateCounts() {
  for (const key of Object.keys(totals)) {
    document.getElementById("c-" + key).textContent = totals[key].toLocaleString();
  }
}

function startMonitoring() {
  for (const key of Object.keys(totals)) totals[key] = 0;
  updateCounts();
  const iface = document.getElementById("iface").value;
  liveSource = new EventSource("/api/live?iface=" + iface);
  document.getElementById("monitor-btn").textContent = "Stop monitoring";
  print("[monitor] watching " + iface, "info");

  liveSource.addEventListener("batch", function (e) {
    const b = JSON.parse(e.data);
    totals.total += b.connections;
    for (const [label, count] of Object.entries(b.counts)) {
      if (label === "normal") totals.normal += count;
      else totals.alerts += count;
      if (label === "Probe" || label === "PortScan") totals.probe += count;
      if (label === "Unknown-Anomaly") totals.unknown += count;
    }
    updateCounts();
    for (const a of b.alerts) {
      print(`[ALERT] ${a.label} ${a.src} -> ${a.dst} (${a.connections} conn) ${a.why}`, "alert");
    }
  });
  liveSource.onerror = function () {
    print("[monitor] connection lost", "err");
  };
}

function stopMonitoring() {
  liveSource.close();
  liveSource = null;
  document.getElementById("monitor-btn").textContent = "Start monitoring";
  print("[monitor] stopped", "info");
}

document.getElementById("monitor-btn").onclick = function () {
  if (liveSource) stopMonitoring();
  else startMonitoring();
};

function sendCommand(cmd) {
  postJSON("/api/range/command", {cmd: cmd}).then(syncRange).catch(function (e) {
    print(e.message, "err");
  });
}

function syncRange(state) {
  document.getElementById("browse").checked = state.browsing;
  document.getElementById("auto").checked = state.auto;
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

document.getElementById("browse").onchange = function (e) {
  sendCommand("browse " + (e.target.checked ? "on" : "off"));
};
document.getElementById("auto").onchange = function (e) {
  sendCommand("auto " + (e.target.checked ? "on" : "off"));
};

// output from nmap / flood comes from the server as a stream of lines
const console_ = new EventSource("/api/range/console");
console_.addEventListener("line", function (e) {
  const line = JSON.parse(e.data);
  if (line.kind === "prompt") print("attacker$ " + line.text);
  else if (line.kind === "cmd") print("$ " + line.text, "info");
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
    for (const x of r.reasons) reasons += `<li>${esc(x.feature)} = ${esc(x.value)}: ${esc(x.description)}</li>`;
    out.innerHTML = `<p>Result: <b>${esc(r.label)}</b> (${esc(r.description)})<br>
      classifier: ${esc(r.classifier_label)} (${pct(r.confidence)}),
      anomaly score ${r.score.toFixed(4)} / threshold ${r.threshold.toFixed(4)}</p><ul>${reasons}</ul>`;
  } catch (err) {
    out.innerHTML = `<p class="err">${esc(err.message)}</p>`;
  }
};


// start

async function start() {
  try {
    status = await getJSON("/api/status");
  } catch (e) {
    document.getElementById("status").textContent = "Server not reachable.";
    return;
  }
  document.getElementById("status").textContent =
    status.runs.length + " models loaded" + (status.root ? ", live capture available" : "");

  const runSelect = document.getElementById("run");
  for (const run of status.runs) runSelect.innerHTML += `<option>${esc(run)}</option>`;
  const sampleSelect = document.getElementById("sample");
  for (const s of status.samples) sampleSelect.innerHTML += `<option>${esc(s)}</option>`;

  if (!status.root) {
    document.getElementById("root-note").textContent =
      "Monitoring needs root. Restart the server with: sudo .venv/bin/netsentinel web (the attack buttons work anyway).";
    document.getElementById("monitor-btn").disabled = true;
  }

  getJSON("/api/range").then(syncRange);
  if (status.runs.length) loadRun();
}

start();
