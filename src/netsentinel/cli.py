"""Command line tool.

netsentinel download [--dataset all]
netsentinel train [--dataset cicids2017]
netsentinel predict data.csv
netsentinel pcap capture.pcap
netsentinel live --iface en0      (needs sudo)
netsentinel baseline normal.pcap
netsentinel web
"""

import argparse
import logging
import sys
import threading
from pathlib import Path

import pandas as pd

from netsentinel.alerts import group_incidents
from netsentinel.config import load_config
from netsentinel.data.schema import CATEGORY_DESCRIPTIONS

ID_COLUMNS = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol_type", "service", "flag"]


def load_model(cfg, profile, custom_path=None):
    from netsentinel.models.hybrid import HybridIDS
    from netsentinel.pipeline.train import model_path

    path = Path(custom_path) if custom_path else model_path(cfg, profile)
    if not path.exists():
        sys.exit(f"no trained model at {path}, run: netsentinel train")
    return HybridIDS.load(path), path


def print_alerts(model, features, predictions, max_alerts=20):
    print("\nSummary")
    for label, n in predictions["final_label"].value_counts().items():
        print(f"  {label:<16} {n:>7,}   {CATEGORY_DESCRIPTIONS.get(label, '')}")

    incidents = group_incidents(features, predictions)
    if incidents.empty:
        print("\nno alerts")
        return

    print(f"\nTop {min(max_alerts, len(incidents))} of {len(incidents)} incidents "
          f"({int(predictions['is_alert'].sum()):,} suspicious connections)")
    for _, inc in incidents.head(max_alerts).iterrows():
        row = features.loc[inc["representative"]]
        ident = " ".join(f"{c}={row[c]}" for c in ID_COLUMNS if c in row.index)
        ports = f" ports={inc['dst_ports']}" if "dst_ports" in inc.index else ""
        print(f"\n[{inc['severity'].upper()}] {inc['final_label']} connections={inc['connections']}{ports}"
              f" confidence={inc['mean_confidence']:.2f} max_score={inc['max_anomaly']:.4f}")
        print("   " + ident)
        for r in model.explain(row, top_k=3):
            z = f"z={r['z_score']:+.1f}" if r["z_score"] is not None else ""
            print(f"     - {r['feature']}={r['value']} {z} ({r['description']})")


def cmd_download(args, cfg):
    if args.dataset in ("nsl-kdd", "all"):
        from netsentinel.data.loader import download_nsl_kdd
        download_nsl_kdd(cfg.paths.raw_dir, force=args.force)
    if args.dataset in ("cicids2017", "all"):
        from netsentinel.data.cicids import download_cicids
        download_cicids(cfg.paths.raw_dir, force=args.force)


def cmd_train(args, cfg):
    if args.dataset == "nsl-kdd":
        from netsentinel.pipeline.train import run_training
        run_training(cfg, [args.profile] if args.profile else None)
    else:
        from netsentinel.pipeline.cicids_experiments import run_cicids
        run_cicids(cfg, [args.experiment] if args.experiment else None)


def cmd_predict(args, cfg):
    model, _ = load_model(cfg, args.profile, args.model)
    df = pd.read_csv(args.csv)
    predictions = model.predict(df)
    print_alerts(model, df, predictions, args.max_alerts)
    if args.output:
        pd.concat([df, predictions], axis=1).to_csv(args.output, index=False)
        print(f"\nsaved to {args.output}")


def cmd_pcap(args, cfg):
    from netsentinel.live.capture import read_pcap_features

    model, _ = load_model(cfg, "live", args.model)
    features = read_pcap_features(args.pcap)
    print(f"{len(features):,} connections in the file")
    predictions = model.predict(features)
    print_alerts(model, features, predictions, args.max_alerts)
    if args.output:
        pd.concat([features, predictions], axis=1).to_csv(args.output, index=False)
        print(f"\nsaved to {args.output}")


def cmd_live(args, cfg):
    from netsentinel.live.capture import live_capture

    model, _ = load_model(cfg, "live", args.model)

    def on_batch(features):
        print_alerts(model, features, model.predict(features), args.max_alerts)

    try:
        live_capture(on_batch, interface=args.iface, batch_seconds=args.interval)
    except PermissionError:
        sys.exit("live capture needs root: sudo .venv/bin/netsentinel live")
    except KeyboardInterrupt:
        print("\nstopped")


def cmd_baseline(args, cfg):
    from netsentinel.live.capture import read_pcap_features

    model, path = load_model(cfg, "live")
    features = read_pcap_features(args.pcap)
    if len(features) < 200:
        sys.exit(f"only {len(features)} connections, record more normal traffic (200+)")
    model.refit_baseline(features, cfg.anomaly.threshold_percentile)
    out = Path(args.output) if args.output else path.with_name("hybrid_ids_custom.joblib")
    model.save(out)
    print(f"baseline trained on {len(features):,} connections, saved to {out}")


def cmd_web(args, cfg):
    import webbrowser

    import uvicorn

    url = f"http://{args.host}:{args.port}"
    print(f"NetSentinel running at {url} (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(1.5, webbrowser.open, args=(url,)).start()
    # short shutdown timeout, otherwise open live streams keep the server waiting
    uvicorn.run("netsentinel.web.server:app", host=args.host, port=args.port, log_level="warning",
                reload=args.reload, timeout_graceful_shutdown=2)


def build_parser():
    parser = argparse.ArgumentParser(prog="netsentinel", description="Hybrid ML intrusion detection")
    parser.add_argument("--config", help="path to a yaml config")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("download", help="download datasets")
    p.add_argument("--dataset", default="nsl-kdd", choices=["nsl-kdd", "cicids2017", "all"])
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_download)

    p = sub.add_parser("train", help="train, evaluate and write the report")
    p.add_argument("--dataset", default="nsl-kdd", choices=["nsl-kdd", "cicids2017"])
    p.add_argument("--profile", choices=["full", "live"])
    p.add_argument("--experiment", choices=["random", "temporal"])
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("predict", help="analyse a csv in NSL-KDD format")
    p.add_argument("csv")
    p.add_argument("--model")
    p.add_argument("--profile", default="full", choices=["full", "live"])
    p.add_argument("--output", "-o")
    p.add_argument("--max-alerts", type=int, default=20)
    p.set_defaults(func=cmd_predict)

    p = sub.add_parser("pcap", help="analyse a pcap file")
    p.add_argument("pcap")
    p.add_argument("--model")
    p.add_argument("--output", "-o")
    p.add_argument("--max-alerts", type=int, default=20)
    p.set_defaults(func=cmd_pcap)

    p = sub.add_parser("live", help="live capture in the terminal")
    p.add_argument("--model")
    p.add_argument("--iface")
    p.add_argument("--interval", type=float, default=10.0)
    p.add_argument("--max-alerts", type=int, default=10)
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("web", help="start the website")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--reload", action="store_true")
    p.set_defaults(func=cmd_web)

    p = sub.add_parser("baseline", help="retrain the anomaly detector on your own normal traffic")
    p.add_argument("pcap")
    p.add_argument("--output", "-o")
    p.set_defaults(func=cmd_baseline)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    args.func(args, load_config(args.config))


if __name__ == "__main__":
    main()
