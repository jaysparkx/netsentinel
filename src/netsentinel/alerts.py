import pandas as pd

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "none": 3}


def group_incidents(features, predictions):
    """Group alerts with the same source, target and label into one incident.
    A port scan is hundreds of alerts but only one incident."""
    alerts = predictions[predictions["is_alert"] == 1]
    if alerts.empty:
        return pd.DataFrame()

    frame = alerts.join(features.drop(columns=alerts.columns, errors="ignore"))
    keys = ["src_ip", "dst_ip", "final_label"]
    if "src_ip" not in frame.columns:
        # no IPs (e.g. NSL-KDD rows): every alert is its own incident
        frame = frame.assign(src_ip="-", dst_ip="-", _row=range(len(frame)))
        keys.append("_row")

    agg = {
        "severity": ("severity", "first"),
        "connections": ("final_label", "size"),
        "max_anomaly": ("anomaly_score", "max"),
        "mean_confidence": ("confidence", "mean"),
    }
    if "dst_port" in frame.columns:
        agg["dst_ports"] = ("dst_port", "nunique")

    grouped = frame.groupby(keys, sort=False)
    incidents = grouped.agg(**agg).reset_index()
    incidents["representative"] = grouped["anomaly_score"].idxmax().to_numpy()  # row used for the explanation

    incidents["_order"] = incidents["severity"].map(SEVERITY_ORDER)
    incidents = incidents.sort_values(["_order", "connections"], ascending=[True, False])
    return incidents.drop(columns=["_order", "_row"], errors="ignore").reset_index(drop=True)
