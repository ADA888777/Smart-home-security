"""End-to-end detection: flows -> features -> rules + ML -> risk."""
from backend import config
from backend.detection.anomaly_detection import score_features
from backend.detection.risk_engine import assess
from backend.detection.rules import evaluate_rules
from backend.monitoring.traffic_features import build_features


def analyze(flows, baselines, models, registry=config.DEVICES):
    features = build_features(flows)
    findings = evaluate_rules(features, flows, baselines, registry)
    ml = score_features(features, models, baselines)
    return features, assess(features, findings, ml)
