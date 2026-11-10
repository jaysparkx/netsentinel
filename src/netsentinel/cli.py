"""
واجهة سطر الأوامر (CLI).

    netsentinel download [--dataset all]        تنزيل NSL-KDD و/أو CIC-IDS2017
    netsentinel train [--profile full]          تدريب + تقييم + تقرير (NSL-KDD)
    netsentinel train --dataset cicids2017      تجارب الحركة الحقيقية الحديثة
    netsentinel predict data.csv                تحليل ملف CSV بصيغة NSL-KDD
    netsentinel pcap capture.pcap               تحليل ملف pcap
    netsentinel live [--iface en0]              مراقبة حيّة (تحتاج sudo)
    netsentinel baseline normal.pcap            ضبط "الطبيعي" على شبكتك
    netsentinel web                             الواجهة الويب  ← http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
from pathlib import Path

import pandas as pd

from netsentinel.alerts import group_incidents
from netsentinel.config import load_config
from netsentinel.data.schema import CATEGORY_DESCRIPTIONS_AR

logger = logging.getLogger("netsentinel")

SEVERITY_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "none": "🟩"}
ID_COLUMNS = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol_type", "service", "flag"]


def _load_model(cfg, profile: str, custom_path: str | None = None):
    """يحمّل النموذج الافتراضي للملف، أو نموذجاً محدّداً (مثل ناتج أمر baseline)."""
    from netsentinel.models.hybrid import HybridIDS
    from netsentinel.pipeline.train import model_path

    # ⚠️ ملفات joblib تُحمَّل بـ pickle، أي أنها قد تنفّذ كوداً — لا تحمّل نموذجاً من مصدر غير موثوق.
    path = Path(custom_path) if custom_path else model_path(cfg, profile)
    if not path.exists():
        sys.exit(f"لا يوجد نموذج مدرَّب في {path} — شغّل أولاً: netsentinel train")
    return HybridIDS.load(path), path


def _print_alerts(model, features: pd.DataFrame, predictions: pd.DataFrame, max_alerts: int = 20) -> None:
    """يطبع ملخّصاً ثم أخطر الحوادث (تنبيهات مجمّعة) مع شرح سبب كل منها."""
    counts = predictions["final_label"].value_counts()
    print("\n── الملخّص ──")
    for label, n in counts.items():
        print(f"  {label:<16} {n:>7,}   {CATEGORY_DESCRIPTIONS_AR.get(label, '')}")

    incidents = group_incidents(features, predictions)
    if incidents.empty:
        print("\n✓ لا توجد تنبيهات.")
        return

    print(f"\n── أخطر {min(max_alerts, len(incidents))} حوادث من {len(incidents):,} "
          f"({int(predictions['is_alert'].sum()):,} اتصالاً مشبوهاً) ──")
    for _, inc in incidents.head(max_alerts).iterrows():
        row = features.loc[inc["representative"]]
        ident = " ".join(f"{c}={row[c]}" for c in ID_COLUMNS if c in row.index)
        ports = f" منافذ_مختلفة={inc['dst_ports']}" if "dst_ports" in inc.index else ""
        print(f"\n{SEVERITY_ICON[inc['severity']]} [{inc['final_label']}] اتصالات={inc['connections']:,}{ports}"
              f" ثقة={inc['mean_confidence']:.2f} أعلى_شذوذ={inc['max_anomaly']:.4f}\n   {ident}")
        for reason in model.explain(row, top_k=3):
            z = f"z={reason['z_score']:+.1f}" if reason["z_score"] is not None else ""
            print(f"     • {reason['feature']}={reason['value']} {z} — {reason['description']}")


# ---------------------------------------------------------------------------- الأوامر
def cmd_download(args, cfg) -> None:
    if args.dataset in ("nsl-kdd", "all"):
        from netsentinel.data.loader import download_nsl_kdd
        download_nsl_kdd(cfg.paths.raw_dir, force=args.force)
    if args.dataset in ("cicids2017", "all"):
        from netsentinel.data.cicids import download_cicids
        download_cicids(cfg.paths.raw_dir, force=args.force)


def cmd_train(args, cfg) -> None:
    if args.dataset == "nsl-kdd":
        from netsentinel.pipeline.train import run_training
        run_training(cfg, [args.profile] if args.profile else None)
    else:
        from netsentinel.pipeline.cicids_experiments import run_cicids
        run_cicids(cfg, [args.experiment] if args.experiment else None)


def cmd_predict(args, cfg) -> None:
    model, _ = _load_model(cfg, args.profile, args.model)
    df = pd.read_csv(args.csv)
    predictions = model.predict(df)
    _print_alerts(model, df, predictions, args.max_alerts)
    if args.output:
        pd.concat([df, predictions], axis=1).to_csv(args.output, index=False)
        print(f"\n✓ حُفظت النتائج في {args.output}")


def cmd_pcap(args, cfg) -> None:
    from netsentinel.live.capture import read_pcap_features
    model, _ = _load_model(cfg, "live", args.model)
    features = read_pcap_features(args.pcap)
    print(f"استُخرج {len(features):,} اتصال من الملف.")
    predictions = model.predict(features)
    _print_alerts(model, features, predictions, args.max_alerts)
    if args.output:
        pd.concat([features, predictions], axis=1).to_csv(args.output, index=False)
        print(f"\n✓ حُفظت النتائج في {args.output}")


def cmd_live(args, cfg) -> None:
    from netsentinel.live.capture import live_capture
    model, _ = _load_model(cfg, "live", args.model)

    def on_batch(features: pd.DataFrame) -> None:
        _print_alerts(model, features, model.predict(features), args.max_alerts)

    try:
        live_capture(on_batch, interface=args.iface, batch_seconds=args.interval)
    except PermissionError:
        sys.exit("الالتقاط الحي يحتاج صلاحيات: sudo .venv/bin/netsentinel live")
    except KeyboardInterrupt:
        print("\nتم الإيقاف.")


def cmd_baseline(args, cfg) -> None:
    from netsentinel.live.capture import read_pcap_features
    model, path = _load_model(cfg, "live")
    features = read_pcap_features(args.pcap)
    if len(features) < 200:
        sys.exit(f"عدد الاتصالات ({len(features)}) قليل جداً — سجّل حركة طبيعية أطول (≥200 اتصال).")
    model.refit_baseline(features, cfg.anomaly.threshold_percentile)
    out = Path(args.output) if args.output else path.with_name("hybrid_ids_custom.joblib")
    model.save(out)
    print(f"✓ ضُبط خط الأساس على {len(features):,} اتصال طبيعي. النموذج: {out}")


def cmd_web(args, cfg) -> None:
    import webbrowser

    import uvicorn

    url = f"http://{args.host}:{args.port}"
    print(f"NetSentinel يعمل على  {url}   (Ctrl+C للإيقاف)")
    if not args.no_browser:
        threading.Timer(1.5, webbrowser.open, args=(url,)).start()
    # timeout_graceful_shutdown: البثّ الحي (SSE) يبقى مفتوحاً ما دامت الصفحة مفتوحة، فبدون مهلة
    # ينتظر الخادم إغلاقها إلى الأبد عند الإيقاف أو إعادة التحميل.
    uvicorn.run("netsentinel.web.server:app", host=args.host, port=args.port, log_level="warning",
                reload=args.reload, reload_dirs=[str(Path(__file__).parent)] if args.reload else None,
                timeout_graceful_shutdown=2)


# ---------------------------------------------------------------------------- المُحلِّل
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netsentinel", description="Hybrid ML Network Intrusion Detection")
    parser.add_argument("--config", help="مسار ملف الإعدادات YAML")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("download", help="تنزيل مجموعات البيانات")
    p.add_argument("--dataset", default="nsl-kdd", choices=["nsl-kdd", "cicids2017", "all"])
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_download)

    p = sub.add_parser("train", help="تدريب وتقييم وتوليد التقرير")
    p.add_argument("--dataset", default="nsl-kdd", choices=["nsl-kdd", "cicids2017"])
    p.add_argument("--profile", choices=["full", "live"], help="NSL-KDD فقط")
    p.add_argument("--experiment", choices=["random", "temporal"], help="CIC-IDS2017 فقط")
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("predict", help="تحليل CSV بصيغة NSL-KDD")
    p.add_argument("--model", help="مسار نموذج مخصّص (مثل hybrid_ids_custom.joblib)")
    p.add_argument("csv")
    p.add_argument("--profile", default="full", choices=["full", "live"])
    p.add_argument("--output", "-o")
    p.add_argument("--max-alerts", type=int, default=20)
    p.set_defaults(func=cmd_predict)

    p = sub.add_parser("pcap", help="تحليل ملف pcap")
    p.add_argument("--model", help="مسار نموذج مخصّص (مثل hybrid_ids_custom.joblib)")
    p.add_argument("pcap")
    p.add_argument("--output", "-o")
    p.add_argument("--max-alerts", type=int, default=20)
    p.set_defaults(func=cmd_pcap)

    p = sub.add_parser("live", help="مراقبة حيّة لكرت الشبكة")
    p.add_argument("--model", help="مسار نموذج مخصّص (مثل hybrid_ids_custom.joblib)")
    p.add_argument("--iface")
    p.add_argument("--interval", type=float, default=10.0)
    p.add_argument("--max-alerts", type=int, default=10)
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("web", help="تشغيل الواجهة الويب")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-browser", action="store_true", help="لا تفتح المتصفّح تلقائياً")
    p.add_argument("--reload", action="store_true", help="أعد التشغيل تلقائياً عند تعديل الكود (للتطوير)")
    p.set_defaults(func=cmd_web)

    p = sub.add_parser("baseline", help="ضبط كاشف الشذوذ على حركة شبكتك الطبيعية")
    p.add_argument("pcap")
    p.add_argument("--output", "-o")
    p.set_defaults(func=cmd_baseline)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    args.func(args, load_config(args.config))


if __name__ == "__main__":
    main()
