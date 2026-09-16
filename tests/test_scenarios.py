"""Controlled simulation tests — the six scenarios from the project spec.

Each test builds one minute of traffic, runs the full detection pipeline
(features -> rules -> Isolation Forest -> risk engine) and checks the verdict.
No real network is attacked; all traffic is simulated.
"""
import numpy as np
import pandas as pd
import pytest

from backend import config
from backend.detection.anomaly_detection import train_models
from backend.detection.baseline import build_baselines
from backend.detection.pipeline import analyze
from backend.monitoring.traffic_features import build_features
from backend.simulator import attack_scenarios as attacks
from backend.simulator.traffic_generator import device_minute_flows, generate_normal

CAMERA = "192.168.10.10"
SMART_LIGHT = "192.168.10.12"
MINUTE = pd.Timestamp("2026-09-20 14:30:00")


@pytest.fixture(scope="module")
def trained():
    flows = generate_normal(pd.Timestamp("2026-09-01"), minutes=2 * 24 * 60, seed=101)
    features = build_features(flows)
    return build_baselines(features, flows), train_models(features)


def run(trained, flow_rows):
    baselines, models = trained
    _, risk = analyze(pd.DataFrame(flow_rows), baselines, models)
    return risk


def verdict_for(risk, ip):
    rows = risk[risk["source_ip"] == ip]
    assert len(rows) == 1, f"expected one window for {ip}"
    return rows.iloc[0]


def test_1_normal_camera_traffic_is_normal(trained):
    rng = np.random.default_rng(1)
    flows = device_minute_flows(rng, CAMERA, MINUTE)

    v = verdict_for(run(trained, flows), CAMERA)

    assert v["risk_level"] == "NORMAL"
    assert v["indicators"] == []


def test_2_unknown_device_is_medium_with_alert(trained):
    rng = np.random.default_rng(2)
    flows = attacks.unknown_device(rng, MINUTE, ip="192.168.10.150")

    v = verdict_for(run(trained, flows), "192.168.10.150")

    assert "unknown_device" in v["indicators"]
    assert v["risk_level"] == "MEDIUM"
    assert v["risk_level"] in config.ALERT_LEVELS


def test_3_traffic_spike_is_high(trained):
    rng = np.random.default_rng(3)
    flows = device_minute_flows(rng, CAMERA, MINUTE)
    flows += attacks.traffic_spike(rng, CAMERA, MINUTE, intensity=12)

    v = verdict_for(run(trained, flows), CAMERA)

    # Isolation Forest saturates on values outside the training range, so the
    # spike rule (not the model) is what guarantees this detection.
    assert "traffic_spike" in v["indicators"]
    assert v["risk_level"] == "HIGH"


def test_4_unusual_port_is_flagged(trained):
    rng = np.random.default_rng(4)
    flows = device_minute_flows(rng, SMART_LIGHT, MINUTE)
    flows += attacks.unusual_port(rng, SMART_LIGHT, MINUTE, port=23)

    v = verdict_for(run(trained, flows), SMART_LIGHT)

    assert "unexpected_port" in v["indicators"]
    assert "23" in " ".join(v["reasons"])
    assert v["risk_level"] in config.ALERT_LEVELS


def test_5_unusual_destination_is_flagged(trained):
    rng = np.random.default_rng(5)
    flows = device_minute_flows(rng, CAMERA, MINUTE)
    flows += attacks.unusual_destination(rng, CAMERA, MINUTE, destination="185.220.101.34")

    v = verdict_for(run(trained, flows), CAMERA)

    assert "unknown_destination" in v["indicators"]
    assert "185.220.101.34" in " ".join(v["reasons"])
    assert v["risk_level"] in config.ALERT_LEVELS


def test_6_multiple_indicators_are_critical(trained):
    rng = np.random.default_rng(6)
    flows = device_minute_flows(rng, CAMERA, MINUTE)
    flows += attacks.data_exfiltration(rng, CAMERA, MINUTE)

    v = verdict_for(run(trained, flows), CAMERA)

    assert len(v["indicators"]) >= config.CRITICAL_MIN_INDICATORS
    assert v["risk_level"] == "CRITICAL"


def test_critical_is_capped_to_high_without_enough_indicators():
    from backend.detection.risk_engine import level_for

    assert level_for(points=120, n_indicators=2) == "HIGH"
    assert level_for(points=120, n_indicators=3) == "CRITICAL"
    assert level_for(points=0, n_indicators=0) == "NORMAL"
