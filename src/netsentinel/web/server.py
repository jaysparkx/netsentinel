# FastAPI backend for the website. Start it with: netsentinel web
# (use sudo if you want live capture)

import asyncio
import json
import os
import queue
import tempfile
import threading
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from netsentinel.alerts import group_incidents
from netsentinel.config import PROJECT_ROOT, load_config
from netsentinel.data.schema import CATEGORY_DESCRIPTIONS
from netsentinel.live.capture import live_capture, read_pcap_features
from netsentinel.models.hybrid import HybridIDS
from netsentinel.pipeline.train import model_path
from netsentinel.web.attack_range import AttackRange

STATIC_DIR = Path(__file__).parent / "static"
CFG = load_config()
CACHE_DIR = PROJECT_ROOT / "data" / "cache"
CUSTOM_MODEL = model_path(CFG, "live").with_name("hybrid_ids_custom.joblib")

RUNS = ["full", "live", "cicids2017_temporal", "cicids2017_random"]
SAMPLES = {
    "real_attack": PROJECT_ROOT / "data/real/real_attack.pcap",
    "real_normal": PROJECT_ROOT / "data/real/real_normal.pcap",
}

app = FastAPI(title="NetSentinel")


@app.middleware("http")
async def no_cache(request, call_next):
    # the page and its files change between versions, so the browser must not keep old copies
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    return response

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
CFG.paths.reports_dir.mkdir(parents=True, exist_ok=True)
app.mount("/reports", StaticFiles(directory=CFG.paths.reports_dir), name="reports")

RANGE = AttackRange(docroot=PROJECT_ROOT / "docs")
models = {}
features_cache = {}
cache_lock = threading.Lock()


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def get_model(path):
    path = str(path)
    if path not in models:
        models[path] = HybridIDS.load(Path(path))
    return models[path]


def pcap_model(custom):
    # pcaps use the live model, or the one retrained on this machine (netsentinel baseline)
    path = CUSTOM_MODEL if custom and CUSTOM_MODEL.exists() else model_path(CFG, "live")
    if not path.exists():
        raise HTTPException(409, "no live model, run: netsentinel train")
    return get_model(path)


def sample_features(path):
    # reading a pcap takes a few seconds, so keep the result in memory and on disk
    key = f"{path.stem}-{int(path.stat().st_mtime)}"
    with cache_lock:
        if key not in features_cache:
            disk = CACHE_DIR / f"{key}.pkl"
            if disk.exists():
                features_cache[key] = pd.read_pickle(disk)
            else:
                df = read_pcap_features(str(path))
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                df.to_pickle(disk)
                features_cache[key] = df
        return features_cache[key]


def to_python(v):
    if hasattr(v, "item"):
        v = v.item()
    if isinstance(v, float) and v != v:  # NaN
        return None
    return v


def explain(model, row, top_k=4):
    return [{k: to_python(v) for k, v in r.items()} for r in model.explain(row, top_k=top_k)]


def incident_list(model, features, pred, limit=10):
    out = []
    for _, inc in group_incidents(features, pred).head(limit).iterrows():
        row = features.loc[inc["representative"]]
        out.append({
            "label": inc["final_label"],
            "severity": inc["severity"],
            "connections": int(inc["connections"]),
            "ports": int(inc["dst_ports"]) if "dst_ports" in inc.index else None,
            "src": row.get("src_ip"),
            "dst": row.get("dst_ip"),
            "reasons": explain(model, row),
        })
    return out


def kind(label):
    if label in ("normal", "BENIGN"):
        return "normal"
    if label == "Unknown-Anomaly":
        return "unknown"
    if label in ("Probe", "PortScan"):
        return "probe"
    return "attack"


def timeline(features, pred, bins=60):
    # connections per time bin, split by verdict colour
    t = features["timestamp"].to_numpy()
    edges = np.linspace(t.min(), t.max() + 1e-6, bins + 1)
    idx = np.clip(np.searchsorted(edges, t, side="right") - 1, 0, bins - 1)
    kinds = pred["final_label"].map(kind).to_numpy()
    out = {k: [0] * bins for k in ("normal", "probe", "attack", "unknown")}
    for i, k in zip(idx, kinds):
        out[k][i] += 1
    return {"seconds": round(float(edges[-1] - edges[0]), 1), "bins": out}


def conversations(features, pred, limit=50):
    # one row per source -> target pair, so a scanner shows up as one line with many ports
    df = pd.DataFrame({"src": features["src_ip"], "dst": features["dst_ip"], "port": features["dst_port"],
                       "kind": pred["final_label"].map(kind), "alert": pred["is_alert"]})
    rank = {"normal": 0, "probe": 1, "unknown": 2, "attack": 3}
    rows = []
    for (src, dst), g in df.groupby(["src", "dst"]):
        flagged = g.loc[g["kind"] != "normal", "kind"]
        rows.append({"src": src, "dst": dst, "connections": len(g), "alerts": int(g["alert"].sum()),
                     "ports": sorted(int(p) for p in g["port"].unique())[:3000],
                     # the most common verdict among flagged connections, so a scan with a few
                     # DoS hits still reads as a scan
                     "main": flagged.mode().iloc[0] if len(flagged) else "normal",
                     "worst": max(g["kind"], key=rank.get)})
    rows.sort(key=lambda r: (-r["alerts"], -r["connections"]))
    return rows[:limit]


def port_kinds(features, pred):
    # worst verdict seen on each destination port
    rank = {"normal": 0, "probe": 1, "unknown": 2, "attack": 3}
    df = pd.DataFrame({"port": features["dst_port"], "rank": pred["final_label"].map(kind).map(rank)})
    names = {v: k for k, v in rank.items()}
    worst = df.groupby("port")["rank"].max()
    return [[int(p), names[int(r)]] for p, r in worst.items()][:5000]


def batch_payload(model, features, pred):
    # same message for live capture and replay
    alerts = []
    for _, inc in group_incidents(features, pred).head(5).iterrows():
        row = features.loc[inc["representative"]]
        reasons = explain(model, row, top_k=2)
        alerts.append({
            "label": inc["final_label"],
            "connections": int(inc["connections"]),
            "src": row.get("src_ip"),
            "dst": f"{row.get('dst_ip')}:{row.get('dst_port')}",
            "why": ", ".join(f"{r['feature']}={r['value']}" for r in reasons),
        })
    return {
        "connections": len(features),
        "counts": {k: int(v) for k, v in pred["final_label"].value_counts().items()},
        "alerts": alerts,
        "scores": [[round(float(s), 5), kind(l)] for s, l in zip(pred["anomaly_score"], pred["final_label"])][:2000],
        "pairs": conversations(features, pred),
        "ports": port_kinds(features, pred),
    }


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
def status():
    return {
        "root": is_root(),
        "runs": [r for r in RUNS if (CFG.paths.reports_dir / r / "metrics.json").exists()],
        "samples": [k for k, p in SAMPLES.items() if p.exists()],
        "custom_baseline": CUSTOM_MODEL.exists(),
    }


@app.get("/api/results/{run}")
def results(run):
    path = CFG.paths.reports_dir / run / "metrics.json"
    if run not in RUNS or not path.exists():
        raise HTTPException(404, f"no results for {run}")
    return json.loads(path.read_text())


@app.post("/api/analyze")
async def analyze(sample: str = Form(None), custom: bool = Form(True), file: UploadFile = File(None)):
    model = pcap_model(custom)
    if file is not None:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(await file.read())
        try:
            features = await asyncio.to_thread(read_pcap_features, tmp.name)
        except Exception as e:
            raise HTTPException(400, f"could not read the file as pcap: {e}")
        finally:
            os.unlink(tmp.name)
    elif sample in SAMPLES:
        features = await asyncio.to_thread(sample_features, SAMPLES[sample])
    else:
        raise HTTPException(400, "send a sample name or a file")
    if features.empty:
        raise HTTPException(400, "no IPv4 connections in the file")

    pred = await asyncio.to_thread(model.predict, features)
    return {
        "connections": len(features),
        "alerts": int(pred["is_alert"].sum()),
        "seconds": round(float(features["timestamp"].max() - features["timestamp"].min()), 1),
        "counts": {k: int(v) for k, v in pred["final_label"].value_counts().items()},
        "incidents": incident_list(model, features, pred),
        "pairs": conversations(features, pred, limit=20),
        "timeline": timeline(features, pred),
        "threshold": model.detector.threshold_,
    }


def sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@app.get("/api/live")
async def live(request: Request, iface: str = "lo0"):
    if not is_root():
        raise HTTPException(403, "live capture needs root: sudo .venv/bin/netsentinel web")
    model = pcap_model(True)
    batches = queue.Queue()
    stop = threading.Event()

    def on_batch(features):
        batches.put((features, model.predict(features)))

    threading.Thread(target=live_capture, daemon=True,
                     kwargs={"on_batch": on_batch, "interface": iface, "batch_seconds": 3.0,
                             "should_stop": stop.is_set}).start()

    async def stream():
        yield sse("start", {"source": iface, "threshold": model.detector.threshold_})
        try:
            while not await request.is_disconnected():
                try:
                    features, pred = await asyncio.to_thread(batches.get, True, 1.0)
                except queue.Empty:
                    yield ": ping\n\n"
                    continue
                yield sse("batch", batch_payload(model, features, pred))
        finally:
            stop.set()

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/replay")
async def replay(request: Request, sample: str = "real_attack", speed: float = 4.0):
    # play a recorded capture back in its own timing, in 1 second windows,
    # so the monitors can run without root
    if sample not in SAMPLES or not SAMPLES[sample].exists():
        raise HTTPException(404, f"no sample {sample}")
    model = pcap_model(True)
    features = await asyncio.to_thread(sample_features, SAMPLES[sample])
    pred = await asyncio.to_thread(model.predict, features)
    speed = min(max(speed, 0.5), 20.0)
    window = (features["timestamp"] - features["timestamp"].min()).astype(int)

    async def stream():
        yield sse("start", {"source": sample + ".pcap", "threshold": model.detector.threshold_})
        last = None
        for second, idx in features.groupby(window).groups.items():
            if await request.is_disconnected():
                return
            # skip long quiet gaps
            await asyncio.sleep(min(second - last, 2) / speed if last is not None else 0)
            last = second
            yield sse("batch", batch_payload(model, features.loc[idx], pred.loc[idx]))
        yield sse("end", {})

    return StreamingResponse(stream(), media_type="text/event-stream")


def local_only(request):
    # attack commands are only accepted from this machine
    if request.client is None or request.client.host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(403, "only allowed from this machine")


@app.get("/api/range")
def range_state():
    return RANGE.state()


@app.post("/api/range/command")
def range_command(request: Request, payload: dict):
    local_only(request)
    RANGE.run_command(str(payload.get("cmd", "")), is_root())
    return RANGE.state()


@app.get("/api/range/console")
async def range_console(request: Request):
    async def stream():
        _, total = RANGE.lines_since(0)
        index = max(0, total - 200)
        while not await request.is_disconnected():
            lines, index = RANGE.lines_since(index)
            for line in lines:
                yield sse("line", line)
            if not lines:
                yield ": ping\n\n"
            await asyncio.sleep(0.25)

    return StreamingResponse(stream(), media_type="text/event-stream")


# a normal web connection, used as the starting point in the lab form
NORMAL_CONNECTION = dict(protocol_type="tcp", service="http", flag="SF", src_bytes=250, dst_bytes=2000,
                         count=5, srv_count=5, same_srv_rate=1.0, dst_host_count=50, dst_host_srv_count=50,
                         dst_host_same_srv_rate=1.0, logged_in=1)


@app.post("/api/lab")
def lab(payload: dict):
    model = get_model(model_path(CFG, "full"))
    row = {f: 0 for f in model.features}
    row.update(NORMAL_CONNECTION)
    for k, v in payload.items():
        if k in row:
            row[k] = v
    frame = pd.DataFrame([row])
    p = model.predict(frame).iloc[0]
    return {
        "label": p["final_label"],
        "classifier_label": p["classifier_label"],
        "confidence": to_python(p["confidence"]),
        "score": to_python(p["anomaly_score"]),
        "threshold": model.detector.threshold_,
        "description": CATEGORY_DESCRIPTIONS.get(p["final_label"], ""),
        "reasons": explain(model, frame.iloc[0], top_k=5),
    }
