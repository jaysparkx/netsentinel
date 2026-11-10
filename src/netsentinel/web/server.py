"""
خادم الواجهة الويب (FastAPI).

لماذا خادم + صفحة بدل Streamlit؟ تحكّم كامل في الشكل، بثّ حيّ للأحداث (SSE)،
ويعمل بالكامل دون إنترنت (الخطوط والمكتبات محلية) — مهم في قاعة العرض.

    GET  /                      الصفحة
    GET  /api/status            النماذج والملفات المتاحة، وهل الخادم يعمل بصلاحيات root
    GET  /api/results/{run}     نتائج تجربة (metrics.json)
    POST /api/analyze           تحليل ملف pcap (جاهز أو مرفوع) ← ملخّص + حوادث + خط زمني
    GET  /api/replay            بثّ ملف pcap حقيقي اتصالاً اتصالاً بتوقيته الأصلي (SSE)
    GET  /api/live              التقاط حيّ من كرت الشبكة (SSE) — يحتاج تشغيل الخادم بـ sudo
    GET  /api/lab/presets       نقاط بداية للمختبر اليدوي
    POST /api/lab               قرار النظام على اتصال واحد

التشغيل:  netsentinel web     ثم افتح  http://127.0.0.1:8000
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
import os
import queue
import tempfile
import threading
import time
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from netsentinel.alerts import group_incidents
from netsentinel.web.attack_range import AttackRange
from netsentinel.config import PROJECT_ROOT, load_config
from netsentinel.data.schema import CATEGORY_DESCRIPTIONS_AR
from netsentinel.models.hybrid import HybridIDS
from netsentinel.pipeline.train import model_path

STATIC_DIR = Path(__file__).parent / "static"
CFG = load_config()

RUNS = {
    "full": {"label": "NSL-KDD · full", "note": "معيار أكاديمي — 40 ميزة"},
    "live": {"label": "NSL-KDD · live", "note": "28 ميزة من ترويسات الحزم فقط"},
    "cicids2017_temporal": {"label": "CIC-IDS2017 · temporal", "note": "حركة حقيقية 2017 — كل هجمات الاختبار جديدة"},
    "cicids2017_random": {"label": "CIC-IDS2017 · random", "note": "التقسيم العشوائي الشائع في الأبحاث"},
}
SAMPLES = {
    "real_attack": {"path": PROJECT_ROOT / "data/real/real_attack.pcap", "real": True,
                    "label": "real_attack.pcap", "note": "التقطناه من جهازنا: تصفّح + nmap + HTTP flood"},
    "real_normal": {"path": PROJECT_ROOT / "data/real/real_normal.pcap", "real": True,
                    "label": "real_normal.pcap", "note": "التقطناه من جهازنا: تصفّح طبيعي فقط"},
    "demo_attack": {"path": PROJECT_ROOT / "data/demo/demo_attack.pcap", "real": False,
                    "label": "demo_attack.pcap", "note": "صناعي: SYN flood + port scan + ping sweep"},
}
CUSTOM_MODEL = model_path(CFG, "live").with_name("hybrid_ids_custom.joblib")
ID_COLUMNS = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol_type", "service", "flag"]

@asynccontextmanager
async def lifespan(_app: FastAPI):
    warm_cache()
    yield


app = FastAPI(title="NetSentinel", docs_url="/api/docs", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ----------------------------------------------------------------------------- تحميل وتخزين مؤقت
@lru_cache(maxsize=8)
def _load(path: str) -> HybridIDS:
    return HybridIDS.load(Path(path))


def _pcap_model(custom: bool) -> HybridIDS:
    """ملفات pcap تُحلَّل بنموذج live، أو بنسخته المضبوطة على طبيعي الجهاز (netsentinel baseline)."""
    path = CUSTOM_MODEL if custom and CUSTOM_MODEL.exists() else model_path(CFG, "live")
    if not path.exists():
        raise HTTPException(409, "لا يوجد نموذج live مدرَّب — شغّل: netsentinel train")
    return _load(str(path))


_FEATURE_LOCK = threading.Lock()
_FEATURE_MEMO: dict[tuple[str, float], pd.DataFrame] = {}
CACHE_DIR = PROJECT_ROOT / "data" / "cache"


def _features_for(path: Path) -> pd.DataFrame:
    """
    تحويل pcap إلى ميزات مكلف (~10 ث للملف الحقيقي)، لذلك نخزّن النتيجة:
        1. في الذاكرة — للطلبات التالية أثناء التشغيل.
        2. على القرص (data/cache) — فيصبح إعادة تشغيل الخادم فورياً.
    القفل يضمن أن طلبين متزامنين لا يقرآن نفس الملف مرتين. mtime يُبطل التخزين إذا تغيّر الملف.
    """
    key = (str(path), path.stat().st_mtime)
    with _FEATURE_LOCK:
        if key in _FEATURE_MEMO:
            return _FEATURE_MEMO[key]
        disk = CACHE_DIR / f"{path.stem}-{int(key[1])}.pkl"
        if disk.exists():
            features = pd.read_pickle(disk)
        else:
            from netsentinel.live.capture import read_pcap_features
            features = read_pcap_features(str(path))
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            features.to_pickle(disk)
        _FEATURE_MEMO[key] = features
        return features


def _sample_path(sample: str) -> Path:
    if sample not in SAMPLES or not SAMPLES[sample]["path"].exists():
        raise HTTPException(404, f"الملف '{sample}' غير موجود")
    return SAMPLES[sample]["path"]


# ----------------------------------------------------------------------------- تحويل النتائج لـ JSON
def _clean(value):
    """قيم numpy ← أنواع Python حتى يقبلها JSON."""
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return None if np.isnan(value) else float(value)
    return value


def _reasons(model: HybridIDS, row: pd.Series, top_k: int = 4) -> list[dict]:
    return [{k: _clean(v) for k, v in r.items()} for r in model.explain(row, top_k=top_k)]


def _incidents(model: HybridIDS, features: pd.DataFrame, pred: pd.DataFrame, limit: int = 12) -> list[dict]:
    incidents = group_incidents(features, pred)
    out = []
    for _, inc in incidents.head(limit).iterrows():
        row = features.loc[inc["representative"]]
        out.append({
            **{k: _clean(v) for k, v in inc.items() if k != "representative"},
            "description": CATEGORY_DESCRIPTIONS_AR.get(inc["final_label"], ""),
            "sample": {c: _clean(row[c]) for c in ID_COLUMNS if c in row.index},
            "reasons": _reasons(model, row),
        })
    return out


def _tape(features: pd.DataFrame, pred: pd.DataFrame, max_points: int = 6000) -> list[list]:
    """نقاط "شريط الحزم": [ثانية منذ البداية، القرار، درجة الشذوذ] — مع تقليص إن كثرت."""
    t = features["timestamp"] - features["timestamp"].min()
    frame = pd.DataFrame({"t": t.round(3), "label": pred["final_label"], "score": pred["anomaly_score"]})
    if len(frame) > max_points:
        frame = frame.iloc[np.linspace(0, len(frame) - 1, max_points).astype(int)]
    return frame.to_numpy().tolist()


def _summarize(model: HybridIDS, features: pd.DataFrame, pred: pd.DataFrame) -> dict:
    return {
        "n_connections": len(features),
        "n_alerts": int(pred["is_alert"].sum()),
        "duration_s": round(float(features["timestamp"].max() - features["timestamp"].min()), 1),
        "label_counts": {k: int(v) for k, v in pred["final_label"].value_counts().items()},
        "threshold": model.detector.threshold_,
        "model": model.metadata.get("baseline_source", "NSL-KDD"),
        "incidents": _incidents(model, features, pred),
        "tape": _tape(features, pred),
    }


# ----------------------------------------------------------------------------- المسارات
@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
def status() -> dict:
    return {
        "is_root": hasattr(os, "geteuid") and os.geteuid() == 0,
        "custom_baseline": CUSTOM_MODEL.exists(),
        "runs": [{"id": k, **v, "available": (CFG.paths.reports_dir / k / "metrics.json").exists()}
                 for k, v in RUNS.items()],
        "samples": [{"id": k, "label": v["label"], "note": v["note"], "real": v["real"],
                     "available": v["path"].exists()} for k, v in SAMPLES.items()],
    }


@app.get("/api/results/{run}")
def results(run: str) -> dict:
    path = CFG.paths.reports_dir / run / "metrics.json"
    if run not in RUNS or not path.exists():
        raise HTTPException(404, f"لا توجد نتائج للتجربة '{run}' — شغّل netsentinel train")
    return json.loads(path.read_text(encoding="utf-8"))


@app.post("/api/analyze")
async def analyze(
    sample: str | None = Form(None),
    custom: bool = Form(True),
    file: UploadFile | None = File(None),
) -> dict:
    model = _pcap_model(custom)
    if file is not None:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(await file.read())
        try:
            from netsentinel.live.capture import read_pcap_features
            features = await asyncio.to_thread(read_pcap_features, tmp.name)
        except Exception as exc:   # ملف تالف أو ليس pcap
            raise HTTPException(400, f"تعذّرت قراءة الملف كـ pcap: {exc}") from exc
        finally:
            os.unlink(tmp.name)
        name = file.filename
    elif sample:
        features = await asyncio.to_thread(_features_for, _sample_path(sample))
        name = SAMPLES[sample]["label"]
    else:
        raise HTTPException(400, "أرسل sample أو file")
    if features.empty:
        raise HTTPException(400, "لم نجد أي اتصال IPv4 في الملف")
    pred = await asyncio.to_thread(model.predict, features)
    return {"source": name, **_summarize(model, features, pred)}


def _event(model: HybridIDS, row: pd.Series, p: pd.Series, t0: float, seen: set) -> dict:
    """حدث واحد في البثّ. الشرح يُحسب فقط لأول اتصال من كل حادثة جديدة (توفيراً للوقت)."""
    event = {
        "t": round(float(row["timestamp"] - t0), 3),
        **{c: _clean(row[c]) for c in ID_COLUMNS if c in row.index},
        "label": p["final_label"], "severity": p["severity"],
        "score": _clean(p["anomaly_score"]), "confidence": _clean(p["confidence"]),
    }
    key = (row.get("src_ip"), row.get("dst_ip"), p["final_label"])
    if p["is_alert"] and key not in seen:
        seen.add(key)
        event["incident"] = {"description": CATEGORY_DESCRIPTIONS_AR.get(p["final_label"], ""),
                             "reasons": _reasons(model, row, top_k=3)}
    return event


@app.get("/api/replay")
async def replay(request: Request, sample: str = "real_attack", speed: float = 4.0, custom: bool = True):
    """
    يعيد بثّ ملف pcap حقيقي اتصالاً اتصالاً بتوقيته الأصلي (مسرَّعاً بـ speed).
    الميزات "سببية": كل اتصال يُحسب من ماضيه فقط، لذا الإعادة مطابقة لما كان سيحدث حيّاً.
    الفجوات الطويلة (> 1.5 ث) تُختصر حتى لا ينتظر الجمهور.
    """
    model = _pcap_model(custom)
    features = await asyncio.to_thread(_features_for, _sample_path(sample))
    pred = await asyncio.to_thread(model.predict, features)
    order = features["timestamp"].sort_values().index
    t0 = float(features["timestamp"].min())
    speed = min(max(speed, 0.25), 50.0)

    async def stream():
        seen: set = set()
        yield _sse("meta", {"sample": sample, "n": len(features), "threshold": model.detector.threshold_,
                            "duration_s": round(float(features["timestamp"].max() - t0), 1)})
        last_t = t0
        for idx in order:
            if await request.is_disconnected():
                return
            row, p = features.loc[idx], pred.loc[idx]
            gap = min(float(row["timestamp"]) - last_t, 1.5) / speed
            last_t = float(row["timestamp"])
            if gap > 0.002:
                await asyncio.sleep(gap)
            yield _sse("conn", _event(model, row, p, t0, seen))
        yield _sse("end", {})

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@app.get("/api/live")
async def live(request: Request, iface: str = "lo0", custom: bool = True):
    """التقاط حيّ: Scapy في خيط منفصل يدفع الدفعات إلى طابور، والبثّ يقرأ منه."""
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        raise HTTPException(403, "الالتقاط الحي يحتاج صلاحيات root: شغّل الخادم بـ  sudo .venv/bin/netsentinel web")
    from netsentinel.live.capture import live_capture

    model = _pcap_model(custom)
    batches: queue.Queue = queue.Queue()
    stop = threading.Event()

    def on_batch(features: pd.DataFrame) -> None:
        batches.put((features, model.predict(features)))

    worker = threading.Thread(
        target=live_capture, daemon=True,
        kwargs={"on_batch": on_batch, "interface": iface, "batch_seconds": 3.0, "should_stop": stop.is_set})
    worker.start()

    async def stream():
        seen: set = set()
        t0 = time.time()
        _, range_index = RANGE.events_since(0)       # نبثّ فقط أحداث الهجوم التي تقع بعد البدء
        yield _sse("meta", {"iface": iface, "live": True, "threshold": model.detector.threshold_, "t0": t0})
        try:
            while not await request.is_disconnected():
                new_events, range_index = RANGE.events_since(range_index)
                for ev in new_events:
                    if ev["kind"] == "attack_started":
                        seen.clear()   # كل هجوم جديد يستحق بطاقة حادثة جديدة حتى لو تطابق المصدر/الهدف
                    yield _sse("range", {**ev, "t": round(ev["time"] - t0, 2)})
                try:
                    features, pred = await asyncio.to_thread(batches.get, True, 1.0)
                except queue.Empty:
                    yield ": keep-alive\n\n"
                    continue
                for idx in features.sort_values("timestamp").index:
                    yield _sse("conn", _event(model, features.loc[idx], pred.loc[idx], t0, seen))
        finally:
            stop.set()

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


# ----------------------------------------------------------------------------- ميدان الهجوم
RANGE = AttackRange(docroot=PROJECT_ROOT / "docs")


def _local_only(request: Request) -> None:
    """أوامر الهجوم تُقبل فقط من نفس الجهاز — حتى لو شُغّل الخادم على عنوان شبكة."""
    if request.client is None or request.client.host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(403, "ميدان الهجوم متاح فقط من نفس الجهاز")


@app.get("/api/range")
def range_state() -> dict:
    return RANGE.state()


@app.post("/api/range/background")
def range_background(request: Request, payload: dict) -> dict:
    _local_only(request)
    RANGE.set_background(bool(payload.get("on")))
    return RANGE.state()


@app.post("/api/range/attack/{attack_id}")
def range_attack(request: Request, attack_id: str) -> dict:
    _local_only(request)
    try:
        return RANGE.launch(attack_id, is_root=_is_root())
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


@app.post("/api/range/auto")
def range_auto(request: Request, payload: dict) -> dict:
    _local_only(request)
    RANGE.set_auto(bool(payload.get("on")), is_root=_is_root())
    return RANGE.state()


@app.post("/api/range/command")
def range_command(request: Request, payload: dict) -> dict:
    _local_only(request)
    RANGE.run_command(str(payload.get("cmd", "")), is_root=_is_root())
    return RANGE.state()


@app.get("/api/range/console")
async def range_console(request: Request):
    """بثّ طرفية الموقع: آخر 200 سطر ثم كل سطر جديد فور ظهوره."""
    async def stream():
        _, total = RANGE.console_since(0)
        index = max(0, total - 200)
        while not await request.is_disconnected():
            lines, index = RANGE.console_since(index)
            for line in lines:
                yield _sse("line", line)
            if not lines:
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.25)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


# ----------------------------------------------------------------------------- المختبر
LAB_PRESETS = {
    "normal": {"label": "اتصال ويب طبيعي", "values": dict(
        protocol_type="tcp", service="http", flag="SF", src_bytes=250, dst_bytes=2000, count=5, srv_count=5,
        same_srv_rate=1.0, dst_host_count=50, dst_host_srv_count=50, dst_host_same_srv_rate=1.0, logged_in=1)},
    "syn_flood": {"label": "SYN flood", "values": dict(
        protocol_type="tcp", service="private", flag="S0", src_bytes=0, dst_bytes=0, count=250, srv_count=20,
        serror_rate=1.0, srv_serror_rate=1.0, same_srv_rate=0.08, diff_srv_rate=0.06, dst_host_count=255,
        dst_host_srv_count=20, dst_host_same_srv_rate=0.08, dst_host_serror_rate=1.0, dst_host_srv_serror_rate=1.0)},
    "port_scan": {"label": "مسح منافذ", "values": dict(
        protocol_type="tcp", service="other", flag="REJ", src_bytes=0, dst_bytes=0, count=1, srv_count=1,
        rerror_rate=1.0, srv_rerror_rate=1.0, dst_host_count=255, dst_host_srv_count=1, dst_host_diff_srv_rate=0.9,
        dst_host_rerror_rate=0.9, dst_host_srv_rerror_rate=1.0, dst_host_same_src_port_rate=1.0)},
}
LAB_CONTROLS = [
    {"feature": "flag", "type": "choice", "options": ["SF", "S0", "REJ", "RSTO", "RSTR", "SH", "S1", "OTH"]},
    {"feature": "src_bytes", "type": "range", "min": 0, "max": 100000, "step": 50},
    {"feature": "count", "type": "range", "min": 0, "max": 511, "step": 1},
    {"feature": "serror_rate", "type": "range", "min": 0, "max": 1, "step": 0.01},
    {"feature": "rerror_rate", "type": "range", "min": 0, "max": 1, "step": 0.01},
    {"feature": "dst_host_count", "type": "range", "min": 0, "max": 255, "step": 1},
]


@app.get("/api/lab/presets")
def lab_presets() -> dict:
    model = _load(str(model_path(CFG, "full")))
    return {"presets": LAB_PRESETS, "controls": [
        {**c, "description": model.spec.describe(c["feature"])} for c in LAB_CONTROLS]}


@app.post("/api/lab")
def lab(payload: dict) -> dict:
    run = payload.get("run", "full")
    if run not in ("full", "live"):
        raise HTTPException(400, "المختبر يدعم نماذج NSL-KDD فقط (full / live)")
    model = _load(str(model_path(CFG, run)))
    # نبدأ من اتصال طبيعي كامل حتى لا تبقى ميزة نصية (protocol_type...) بقيمة رقمية 0
    row = {f: 0 for f in model.features}
    row.update({k: v for k, v in LAB_PRESETS["normal"]["values"].items() if k in row})
    row.update({k: v for k, v in payload.get("values", {}).items() if k in row})
    frame = pd.DataFrame([row])
    p = model.predict(frame).iloc[0]
    return {
        "label": p["final_label"], "classifier_label": p["classifier_label"], "severity": p["severity"],
        "confidence": _clean(p["confidence"]), "score": _clean(p["anomaly_score"]),
        "threshold": model.detector.threshold_,
        "description": CATEGORY_DESCRIPTIONS_AR.get(p["final_label"], ""),
        "reasons": _reasons(model, frame.iloc[0], top_k=5),
    }


def warm_cache() -> None:
    """يحضّر ميزات الملفات الجاهزة في الخلفية عند بدء الخادم، فيكون العرض فورياً."""
    def work():
        for meta in SAMPLES.values():
            if meta["path"].exists():
                _features_for(meta["path"])
    threading.Thread(target=work, daemon=True).start()

