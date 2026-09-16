"""Combines rule findings and ML results into one risk verdict per device/window."""
import pandas as pd

from backend import config


def level_for(points: float, n_indicators: int) -> str:
    if points <= 0:
        return "NORMAL"
    for minimum, level in config.RISK_LEVELS:
        if points >= minimum:
            if level == "CRITICAL" and n_indicators < config.CRITICAL_MIN_INDICATORS:
                return "HIGH"
            return level
    return "LOW"


def assess(features: pd.DataFrame, findings: pd.DataFrame, ml: pd.DataFrame) -> pd.DataFrame:
    keys = ["source_ip", "window"]
    risk = features[keys].merge(ml, on=keys, how="left")

    if len(findings):
        grouped = findings.groupby(keys).agg(
            rule_points=("points", "sum"), rules=("rule", list), rule_reasons=("reason", list)
        ).reset_index()
        risk = risk.merge(grouped, on=keys, how="left")
    else:
        risk["rule_points"], risk["rules"], risk["rule_reasons"] = 0, None, None

    risk["rule_points"] = risk["rule_points"].fillna(0)
    risk["ml_anomaly"] = risk["ml_anomaly"].fillna(False).astype(bool)
    risk["ml_points"] = risk["ml_anomaly"] * (
        config.ML_BASE_POINTS + config.ML_SEVERITY_POINTS * risk["anomaly_score"].fillna(0))
    risk["risk_points"] = (risk["rule_points"] + risk["ml_points"]).round(1)

    def indicators(r):
        found = list(dict.fromkeys(r["rules"])) if isinstance(r["rules"], list) else []
        return found + (["ml_anomaly"] if r["ml_anomaly"] else [])

    def reasons(r):
        found = list(r["rule_reasons"]) if isinstance(r["rule_reasons"], list) else []
        return found + ([r["ml_reason"]] if r["ml_anomaly"] else [])

    risk["indicators"] = risk.apply(indicators, axis=1)
    risk["reasons"] = risk.apply(reasons, axis=1)
    risk["risk_level"] = [level_for(p, len(i)) for p, i in zip(risk["risk_points"], risk["indicators"])]
    return risk[keys + ["risk_level", "risk_points", "indicators", "reasons",
                        "rule_points", "ml_anomaly", "anomaly_score", "ml_score"]]
