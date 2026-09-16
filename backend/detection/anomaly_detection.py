"""Isolation Forest anomaly detection — one model per known device.

Models are trained on NORMAL traffic only (unsupervised). The decision
threshold is a low quantile of the training scores (see config).
anomaly_score (0..1) is a severity heuristic, not a probability.
"""
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from backend import config
from backend.monitoring.traffic_features import FEATURE_COLUMNS

SCORE_SCALE = 0.2  # raw-score distance below threshold that maps to severity 1.0


def to_matrix(features: pd.DataFrame) -> np.ndarray:
    values = np.log1p(features[FEATURE_COLUMNS].to_numpy(dtype=float))
    hour = features["window"].dt.hour + features["window"].dt.minute / 60
    angle = 2 * np.pi * hour.to_numpy() / 24
    return np.column_stack([values, np.sin(angle), np.cos(angle)])


def train_models(features: pd.DataFrame, registry=config.DEVICES) -> dict:
    models = {}
    for ip, g in features.groupby("source_ip"):
        if ip not in registry:
            continue
        X = to_matrix(g)
        model = IsolationForest(n_estimators=config.IF_N_ESTIMATORS,
                                random_state=config.RANDOM_SEED).fit(X)
        scores = model.score_samples(X)
        models[ip] = {"model": model,
                      "threshold": float(np.quantile(scores, config.ML_THRESHOLD_QUANTILE))}
    return models


def _explain(row, stats):
    ratios = []
    for col in FEATURE_COLUMNS:
        typical = stats[col]["p50"]
        ratio = (row[col] + 1) / (typical + 1)
        ratios.append((abs(np.log(ratio)), col, row[col], typical, ratio))
    top = sorted(ratios, reverse=True)[:2]
    return "; ".join(f"{c}={v:,.0f} vs typical {t:,.0f} ({r:.1f}x)" for _, c, v, t, r in top)


def score_features(features: pd.DataFrame, models: dict, baselines: dict) -> pd.DataFrame:
    out = features[["source_ip", "window"]].copy()
    out["ml_score"] = np.nan
    out["ml_anomaly"] = False
    out["anomaly_score"] = 0.0
    out["ml_reason"] = ""

    for ip, idx in features.groupby("source_ip").groups.items():
        if ip not in models:
            continue  # unknown devices have no learned behaviour
        g = features.loc[idx]
        m = models[ip]
        scores = m["model"].score_samples(to_matrix(g))
        anomalous = scores < m["threshold"]
        out.loc[idx, "ml_score"] = scores
        out.loc[idx, "ml_anomaly"] = anomalous
        out.loc[idx, "anomaly_score"] = np.clip((m["threshold"] - scores) / SCORE_SCALE, 0, 1)
        for i in np.asarray(idx)[anomalous]:
            out.loc[i, "ml_reason"] = ("Isolation Forest: behaviour differs from learned profile — "
                                       + _explain(features.loc[i], baselines[ip]["stats"]))
    return out


def save_models(models, path=config.ANOMALY_MODEL_PKL):
    path.parent.mkdir(exist_ok=True)
    joblib.dump(models, path)


def load_models(path=config.ANOMALY_MODEL_PKL) -> dict:
    return joblib.load(path)
