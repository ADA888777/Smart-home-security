"""Learns the *normal profile* of every known device from normal traffic.

For each device we keep percentiles of every feature plus the exact set of
destinations and ports it used. Rules compare new traffic to this profile.
"""
import json

import pandas as pd

from backend import config
from backend.monitoring.traffic_features import FEATURE_COLUMNS


def build_baselines(features: pd.DataFrame, flows: pd.DataFrame, registry=config.DEVICES) -> dict:
    baselines = {}
    for ip, g in features.groupby("source_ip"):
        if ip not in registry:
            continue
        stats = {
            col: {
                "mean": round(float(g[col].mean()), 2),
                "std": round(float(g[col].std()), 2),
                "p50": round(float(g[col].median()), 2),
                "p99": round(float(g[col].quantile(0.99)), 2),
                "p999": round(float(g[col].quantile(0.999)), 2),
                "max": round(float(g[col].max()), 2),
            }
            for col in FEATURE_COLUMNS
        }
        own = flows[flows["source_ip"] == ip]
        baselines[ip] = {
            "name": registry[ip]["name"],
            "windows_observed": int(len(g)),
            "stats": stats,
            "known_destinations": sorted(own["destination_ip"].unique().tolist()),
            "known_ports": sorted(int(p) for p in own["destination_port"].unique()),
        }
    return baselines


def save_baselines(baselines, path=config.BASELINES_JSON):
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(baselines, indent=2))


def load_baselines(path=config.BASELINES_JSON) -> dict:
    return json.loads(path.read_text())
