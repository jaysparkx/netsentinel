"""
لوحة تحكّم NetSentinel (Streamlit) — واجهة عربية لمركز العمليات الأمنية (SOC).

التشغيل:
    streamlit run app/dashboard.py

الصفحات:
    1. 📊 أداء النظام      : نتائج التقييم والرسوم من آخر تدريب.
    2. 🔍 تحليل حركة       : رفع ملف pcap أو CSV ← تنبيهات مشروحة.
    3. 🧪 تجربة يدوية      : عدّل ميزات اتصال واحد وشاهد كيف يتغيّر القرار.
"""

from __future__ import annotations

import json
import tempfile

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from netsentinel.alerts import group_incidents
from netsentinel.config import PROJECT_ROOT, load_config
from netsentinel.data.schema import CATEGORY_DESCRIPTIONS_AR, FEATURE_DESCRIPTIONS_AR
from netsentinel.models.hybrid import HybridIDS
from netsentinel.pipeline.train import model_path

st.set_page_config(page_title="NetSentinel IDS", page_icon="🛡️", layout="wide")

# اتجاه من اليمين لليسار للنصوص العربية، مع إبقاء الجداول والأكواد باتجاه LTR
st.markdown("""
<style>
  .stApp, .stMarkdown, .stTabs, section[data-testid="stSidebar"] { direction: rtl; text-align: right; }
  [data-testid="stDataFrame"], code, pre, .js-plotly-plot { direction: ltr; text-align: left; }
  .alert-card { border-right: 6px solid; padding: .6rem 1rem; margin: .4rem 0; border-radius: 6px;
                background: rgba(127,127,127,.08); }
</style>
""", unsafe_allow_html=True)

CFG = load_config()
SEVERITY_COLOR = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "none": "#16a34a"}
RUN_LABELS = {
    "full": "NSL-KDD — الكامل (40 ميزة)",
    "live": "NSL-KDD — الحي (28 ميزة)",
    "cicids2017_temporal": "CIC-IDS2017 — زمني (Zero-day حقيقي)",
    "cicids2017_random": "CIC-IDS2017 — عشوائي",
}
LABEL_COLORS = {"normal": "#16a34a", "DoS": "#dc2626", "Probe": "#f59e0b", "R2L": "#7c3aed",
                "U2R": "#111827", "Unknown-Anomaly": "#0ea5e9", "DDoS": "#991b1b", "PortScan": "#f59e0b",
                "BruteForce": "#7c3aed", "WebAttack": "#db2777", "Bot": "#111827", "Infiltration": "#4b5563",
                "Heartbleed": "#be123c"}


SAMPLE_PCAPS = {
    "🟢 حقيقي: real_attack.pcap (nmap + HTTP flood على جهازك)": PROJECT_ROOT / "data" / "real" / "real_attack.pcap",
    "🟢 حقيقي: real_normal.pcap (تصفّح طبيعي)": PROJECT_ROOT / "data" / "real" / "real_normal.pcap",
    "⚪ صناعي: demo_attack.pcap": PROJECT_ROOT / "data" / "demo" / "demo_attack.pcap",
}


@st.cache_resource
def load_model_file(path: str) -> HybridIDS:
    return HybridIDS.load(Path(path))


@st.cache_resource
def get_model(profile: str) -> HybridIDS | None:
    path = model_path(CFG, profile)
    return HybridIDS.load(path) if path.exists() else None


@st.cache_data
def get_metrics(profile: str) -> dict | None:
    path = CFG.paths.reports_dir / profile / "metrics.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _ltr(text: str) -> str:
    """نص لاتيني (IP، أسماء ميزات) معزول باتجاه LTR حتى لا ينقلب داخل الصفحة العربية."""
    return f"<code dir='ltr' style='unicode-bidi:isolate'>{text}</code>"


def _reason_html(reason: dict) -> str:
    """سطر شرح واحد: الميزة=القيمة (z) — الوصف العربي."""
    feature_value = _ltr(f"{reason['feature']}={reason['value']}")
    z = reason["z_score"]
    z_part = f" {_ltr(f'z={z:+.1f}')}" if z is not None else ""
    return f"<li>{feature_value}{z_part} — {reason['description']}</li>"


def render_alerts(model: HybridIDS, features: pd.DataFrame, pred: pd.DataFrame, limit: int = 15) -> None:
    """يعرض الحوادث (تنبيهات مجمّعة حسب المصدر/الهدف/النوع) مع شرح كل منها."""
    incidents = group_incidents(features, pred)
    if incidents.empty:
        st.success("✓ لا توجد تنبيهات — كل الاتصالات تبدو طبيعية.")
        return
    st.subheader(f"🚨 أخطر الحوادث ({min(limit, len(incidents))} من {len(incidents):,}) — "
                 f"{int(pred['is_alert'].sum()):,} اتصالاً مشبوهاً")
    for _, inc in incidents.head(limit).iterrows():
        row = features.loc[inc["representative"]]
        who = (f"{row['src_ip']} → {row['dst_ip']}" if "src_ip" in row.index else f"record #{inc['representative']}")
        ports = f" | منافذ مختلفة: {inc['dst_ports']}" if "dst_ports" in inc.index else ""
        reasons_html = "".join(_reason_html(r) for r in model.explain(row, top_k=4)) \
            or "<li>لا توجد ميزة واحدة بارزة — القرار من نمط مركّب.</li>"
        st.markdown(
            f"<div class='alert-card' style='border-color:{SEVERITY_COLOR[inc['severity']]}'>"
            f"<b>{inc['final_label']}</b> — {CATEGORY_DESCRIPTIONS_AR.get(inc['final_label'], '')}<br>"
            f"{_ltr(who)} | اتصالات: {inc['connections']:,}{ports} | ثقة المصنِّف: {inc['mean_confidence']:.2f}"
            f" | أعلى شذوذ: {inc['max_anomaly']:.4f}<ul>{reasons_html}</ul></div>",
            unsafe_allow_html=True,
        )


# ============================================================================ الشريط الجانبي
with st.sidebar:
    st.title("🛡️ NetSentinel")
    st.caption("نظام هجين لكشف التسلّل في الشبكات باستخدام تعلّم الآلة")
    available = [run for run in RUN_LABELS if model_path(CFG, run).exists()]
    if not available:
        st.error("لا يوجد نموذج مدرَّب. شغّل:\n\n`netsentinel train`")
        st.stop()
    profile = st.radio("النموذج / التجربة", available, format_func=RUN_LABELS.get)
    model = get_model(profile)
    if model is None:
        st.error("لا يوجد نموذج مدرَّب. شغّل:\n\n`netsentinel train`")
        st.stop()
    st.markdown(f"**المصنِّف:** `{model.metadata.get('classifier')}`  \n"
                f"**كاشف الشذوذ:** `{model.metadata.get('detector')}`  \n"
                f"**تاريخ التدريب:** {model.metadata.get('trained_at')}")

tab_perf, tab_analyze, tab_lab = st.tabs(["📊 أداء النظام", "🔍 تحليل حركة", "🧪 تجربة يدوية"])

# ============================================================================ 1) الأداء
with tab_perf:
    metrics = get_metrics(profile)
    if not metrics:
        st.info("لا توجد نتائج تقييم بعد.")
    else:
        split = st.selectbox("مجموعة الاختبار", list(metrics["test"]))
        m = metrics["test"][split]
        h, c = m["hybrid"], m["classifier_only"]
        cols = st.columns(4)
        cols[0].metric("نسبة الكشف (الهجين)", f"{h['detection_rate']:.1%}",
                       f"{(h['detection_rate'] - c['detection_rate']) * 100:+.1f} نقطة عن المصنِّف وحده")
        cols[1].metric("الإنذارات الكاذبة", f"{h['false_alarm_rate']:.2%}",
                       f"{(h['false_alarm_rate'] - c['false_alarm_rate']) * 100:+.2f} نقطة", delta_color="inverse")
        cols[2].metric("F1", f"{h['f1']:.4f}")
        cols[3].metric("Macro-F1 (تصنيف متعدّد)", f"{m['multiclass']['f1_macro']:.4f}")

        if "novel_attacks" in m:
            n = m["novel_attacks"]
            st.subheader(f"🧬 الهجمات الجديدة (لم تظهر في التدريب) — {n['n_samples']:,} سجل")
            novel_df = pd.DataFrame({
                "الوضع": ["المصنِّف وحده", "كاشف الشذوذ وحده", "الهجين"],
                "نسبة الكشف": [n["classifier_only_dr"], n["anomaly_only_dr"], n["hybrid_dr"]],
            })
            st.plotly_chart(px.bar(novel_df, x="الوضع", y="نسبة الكشف", text_auto=".1%", range_y=[0, 1],
                                   color="الوضع"), width="stretch")

        st.subheader("نسبة الكشف لكل فئة")
        by_cat = pd.DataFrame(m["detection_rate_by_category"]).drop(index="normal", errors="ignore")
        st.plotly_chart(px.bar(by_cat.reset_index(names="category").melt(id_vars="category"),
                               x="category", y="value", color="variable", barmode="group",
                               text_auto=".1%", range_y=[0, 1.05]), width="stretch")

        fig_dir = CFG.paths.reports_dir / profile / "figures"
        tag = split.replace("+", "plus")
        c1, c2 = st.columns(2)
        for col, name in [(c1, f"confusion_{tag}.png"), (c2, f"roc_{tag}.png"),
                          (c1, f"anomaly_scores_{tag}.png"), (c2, "feature_importance.png")]:
            if (fig_dir / name).exists():
                col.image(str(fig_dir / name))

        st.subheader("مقارنة المصنِّفات (التحقق)")
        st.dataframe(pd.DataFrame(metrics["validation"]["classifier_comparison"]).T)

# ============================================================================ 2) التحليل
with tab_analyze:
    st.markdown("ارفع **ملف pcap** (من Wireshark/tcpdump) أو **CSV** بأعمدة NSL-KDD.")
    upload = st.file_uploader("الملف", type=["pcap", "pcapng", "csv", "txt"])

    samples = {label: path for label, path in SAMPLE_PCAPS.items() if path.exists()}
    c1, c2 = st.columns([3, 1])
    sample = c1.selectbox("أو اختر ملفاً جاهزاً", list(samples)) if samples else None
    use_sample = sample is not None and c2.button("تحليل", width="stretch")
    custom_path = model_path(CFG, "live").with_name("hybrid_ids_custom.joblib")
    use_custom = custom_path.exists() and st.checkbox(
        "استخدم خط الأساس المضبوط على حركة جهازك (netsentinel baseline)", value=True)

    def pcap_model() -> HybridIDS:
        """ملفات pcap تُحلَّل بنموذج 'live' (28 ميزة من الترويسات)، أو نسخته المضبوطة محلياً."""
        return load_model_file(str(custom_path)) if use_custom else get_model("live")

    features, analysis_model = None, model
    if upload is not None and upload.name.endswith((".pcap", ".pcapng")):
        from netsentinel.live.capture import read_pcap_features
        with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
            tmp.write(upload.getbuffer())
            tmp.flush()
            features = read_pcap_features(tmp.name)
        analysis_model = pcap_model()
    elif upload is not None:
        from netsentinel.data.schema import RAW_COLUMNS
        features = pd.read_csv(upload, header=None if upload.name.endswith(".txt") else "infer",
                               names=RAW_COLUMNS if upload.name.endswith(".txt") else None)
        features.columns = features.columns.str.strip()   # ملفات CIC-IDS2017 فيها مسافات في أسماء الأعمدة
    elif use_sample:
        from netsentinel.live.capture import read_pcap_features
        features = read_pcap_features(str(samples[sample]))
        analysis_model = pcap_model()
    if features is not None and analysis_model.spec.profile == "live":
        st.info(f"التحليل بنموذج: {'live + خط أساس محلي' if use_custom else 'live (NSL-KDD)'}")

    if features is not None:
        with st.spinner("جارٍ التحليل..."):
            pred = analysis_model.predict(features)
        st.caption(f"عدد الاتصالات المحلَّلة: {len(features):,}")
        counts = pred["final_label"].value_counts().reset_index()
        counts.columns = ["label", "count"]
        c1, c2 = st.columns([1, 2])
        c1.plotly_chart(px.pie(counts, names="label", values="count", color="label",
                               color_discrete_map=LABEL_COLORS, hole=.45), width="stretch")
        if "timestamp" in features.columns:
            timeline = features[["timestamp"]].assign(label=pred["final_label"].to_numpy())
            timeline["second"] = pd.to_datetime(timeline["timestamp"], unit="s").dt.floor("5s")
            series = timeline.groupby(["second", "label"]).size().reset_index(name="n")
            c2.plotly_chart(px.area(series, x="second", y="n", color="label",
                                    color_discrete_map=LABEL_COLORS, title="الاتصالات عبر الزمن"),
                            width="stretch")
        render_alerts(analysis_model, features, pred)
        with st.expander("الجدول الكامل"):
            st.dataframe(pd.concat([features, pred], axis=1))
        st.download_button("⬇️ تنزيل النتائج CSV", pd.concat([features, pred], axis=1).to_csv(index=False),
                           "netsentinel_results.csv", "text/csv")

# ============================================================================ 3) المختبر
with tab_lab:
    if model.spec.name != "NSL-KDD":
        st.info("المختبر اليدوي مبني على ميزات NSL-KDD — اختر نموذج NSL-KDD من الشريط الجانبي.")
        st.stop()
    st.markdown("عدّل خصائص **اتصال واحد** وشاهد قرار النظام فوراً — مفيد لفهم ما تعلّمه النموذج.")
    base = {f: 0 for f in model.features}
    base.update(protocol_type="tcp", service="http", flag="SF", src_bytes=250, dst_bytes=2000,
                count=5, srv_count=5, same_srv_rate=1.0, dst_host_count=50, dst_host_srv_count=50,
                dst_host_same_srv_rate=1.0)
    if "logged_in" in base:
        base["logged_in"] = 1

    preset = st.selectbox("نقطة بداية", ["اتصال طبيعي", "SYN Flood", "مسح منافذ"])
    if preset == "SYN Flood":
        base.update(service="private", flag="S0", src_bytes=0, dst_bytes=0, count=250, srv_count=20,
                    serror_rate=1.0, srv_serror_rate=1.0, same_srv_rate=0.08, diff_srv_rate=0.06,
                    dst_host_count=255, dst_host_srv_count=20, dst_host_same_srv_rate=0.08,
                    dst_host_serror_rate=1.0, dst_host_srv_serror_rate=1.0, logged_in=0)
    elif preset == "مسح منافذ":
        base.update(service="other", flag="REJ", src_bytes=0, dst_bytes=0, count=1, srv_count=1,
                    rerror_rate=1.0, srv_rerror_rate=1.0, dst_host_count=255, dst_host_srv_count=1,
                    dst_host_diff_srv_rate=0.9, dst_host_rerror_rate=0.9, dst_host_srv_rerror_rate=1.0,
                    dst_host_same_src_port_rate=1.0, logged_in=0)

    c1, c2, c3 = st.columns(3)
    row = dict(base)
    row["flag"] = c1.selectbox("flag", ["SF", "S0", "REJ", "RSTO", "RSTR", "SH", "S1", "OTH"],
                               index=["SF", "S0", "REJ", "RSTO", "RSTR", "SH", "S1", "OTH"].index(base["flag"]),
                               help=FEATURE_DESCRIPTIONS_AR["flag"], key=f"lab_{preset}_flag")
    row["src_bytes"] = c1.number_input("src_bytes", 0, 10**9, int(base["src_bytes"]),
                                       help=FEATURE_DESCRIPTIONS_AR["src_bytes"], key=f"lab_{preset}_src_bytes")
    row["count"] = c2.slider("count", 0, 511, int(base["count"]), help=FEATURE_DESCRIPTIONS_AR["count"], key=f"lab_{preset}_count")
    row["serror_rate"] = c2.slider("serror_rate", 0.0, 1.0, float(base["serror_rate"]),
                                   help=FEATURE_DESCRIPTIONS_AR["serror_rate"], key=f"lab_{preset}_serror_rate")
    row["dst_host_count"] = c3.slider("dst_host_count", 0, 255, int(base["dst_host_count"]),
                                      help=FEATURE_DESCRIPTIONS_AR["dst_host_count"], key=f"lab_{preset}_dst_host_count")
    row["rerror_rate"] = c3.slider("rerror_rate", 0.0, 1.0, float(base["rerror_rate"]),
                                   help=FEATURE_DESCRIPTIONS_AR["rerror_rate"], key=f"lab_{preset}_rerror_rate")

    one = pd.DataFrame([row])
    res = model.predict(one).iloc[0]
    color = SEVERITY_COLOR[res["severity"]]
    st.markdown(f"<div class='alert-card' style='border-color:{color}'><h3>{res['final_label']}</h3>"
                f"{CATEGORY_DESCRIPTIONS_AR.get(res['final_label'], '')}<br>"
                f"رأي المصنِّف: <b>{res['classifier_label']}</b> (ثقة {res['confidence']:.2f}) — "
                f"درجة الشذوذ {res['anomaly_score']:.4f} "
                f"(العتبة {model.detector.threshold_:.4f})</div>", unsafe_allow_html=True)
    for r in model.explain(one.iloc[0]):
        st.markdown(f"- `{r['feature']}={r['value']}` — {r['description']}")
