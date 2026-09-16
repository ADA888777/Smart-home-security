"""Evaluate rules, Isolation Forest and the hybrid system on the labelled test set.

The test set (attack_traffic.csv) is generated with a different seed and
different days than the training data. Results are written to docs/.

Run:  python -m backend.ml.evaluate
"""
import json

import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from backend import config
from backend.detection.anomaly_detection import load_models
from backend.detection.baseline import load_baselines
from backend.detection.pipeline import analyze
from backend.monitoring.collector import load_csv


def metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
            "false_positive_rate": round(fp / (fp + tn), 4),
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}


def main():
    flows = load_csv(config.ATTACK_TRAFFIC_CSV)
    features, risk = analyze(flows, load_baselines(), load_models())
    df = features[["source_ip", "window", "label", "scenario"]].merge(risk, on=["source_ip", "window"])

    detectors = {
        "Rules only": (df["rule_points"] > 0).astype(int),
        "Isolation Forest only": df["ml_anomaly"].astype(int),
        "Hybrid (alert = MEDIUM or above)": df["risk_level"].isin(config.ALERT_LEVELS).astype(int),
    }
    overall = {name: metrics(df["label"], pred) for name, pred in detectors.items()}

    per_scenario = {}
    for scenario, g in df.groupby("scenario"):
        per_scenario[scenario] = {name: round(float(pred[g.index].mean()), 4)
                                  for name, pred in detectors.items()}
        per_scenario[scenario]["windows"] = int(len(g))
    levels = pd.crosstab(df["scenario"], df["risk_level"])

    config.DOCS_DIR.mkdir(exist_ok=True)
    (config.DOCS_DIR / "evaluation_results.json").write_text(json.dumps(
        {"overall": overall, "per_scenario_detection_rate": per_scenario,
         "risk_levels": levels.to_dict()}, indent=2))

    lines = ["# Evaluation results", "",
             f"Test set: {len(df):,} device-minutes, {int(df['label'].sum())} attack windows. "
             "Synthetic data generated from the Packet Tracer topology, different seed and days "
             "from training.", "", "## Overall", "",
             "| Detector | Precision | Recall | F1 | FPR | TP | FP | TN | FN |",
             "|---|---|---|---|---|---|---|---|---|"]
    for name, m in overall.items():
        lines.append(f"| {name} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | "
                     f"{m['false_positive_rate']:.4f} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} |")
    lines += ["", "## Detection rate per scenario", "",
              "| Scenario | Windows | Rules | Isolation Forest | Hybrid |", "|---|---|---|---|---|"]
    for s, v in per_scenario.items():
        vals = list(detectors)
        lines.append(f"| {s} | {v['windows']} | {v[vals[0]]:.1%} | {v[vals[1]]:.1%} | {v[vals[2]]:.1%} |")
    lines += ["", "(For `normal` this is the false-alarm rate.)", "",
              "## Risk level by scenario", "", levels.to_markdown()]
    (config.DOCS_DIR / "evaluation_results.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
