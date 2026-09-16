"""Central configuration for the Smart Home Network Security system.

Everything that the detection logic depends on (addresses, thresholds, points)
lives here so it can be tuned in one place and cited in the report.
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
DOCS_DIR = BASE_DIR / "docs"

NORMAL_TRAFFIC_CSV = DATA_DIR / "normal_traffic.csv"   # training data (normal only)
ATTACK_TRAFFIC_CSV = DATA_DIR / "attack_traffic.csv"   # labelled test set (normal + attacks)
BASELINES_JSON = MODELS_DIR / "baselines.json"
ANOMALY_MODEL_PKL = MODELS_DIR / "anomaly_model.pkl"

RANDOM_SEED = 42

# ---------------------------------------------------------------------------
# Network (must match the Packet Tracer topology)
# In Packet Tracer: Home Gateway > Config > LAN > set IP to 192.168.10.1
# then reserve/assign the device addresses below.
# ---------------------------------------------------------------------------
NETWORK_CIDR = "192.168.10.0/24"
GATEWAY_IP = "192.168.10.1"

DEVICES = {
    "192.168.10.10": {"name": "Camera", "type": "camera", "mac": "00:1A:2B:3C:00:10"},
    "192.168.10.11": {"name": "Smart TV", "type": "smart_tv", "mac": "00:1A:2B:3C:00:11"},
    "192.168.10.12": {"name": "Smart Light", "type": "smart_light", "mac": "00:1A:2B:3C:00:12"},
    "192.168.10.13": {"name": "Speaker", "type": "speaker", "mac": "00:1A:2B:3C:00:13"},
    "192.168.10.20": {"name": "Laptop", "type": "laptop", "mac": "00:1A:2B:3C:00:20"},
    "192.168.10.21": {"name": "Smartphone", "type": "smartphone", "mac": "00:1A:2B:3C:00:21"},
}

# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------
WINDOW = "1min"  # features are computed per device per window

# ---------------------------------------------------------------------------
# Security rules
# A value is a "spike" when it exceeds RULE_MULTIPLIER x the device's
# 99.9th percentile seen during normal operation.
# ---------------------------------------------------------------------------
RULE_MULTIPLIER = 2.0

RULE_POINTS = {
    "unknown_device": 40,
    "traffic_spike": 60,       # > 2x the highest normal volume is HIGH on its own
    "unexpected_port": 30,
    "unknown_destination": 30,
    "abnormal_connection_pattern": 35,
}

# ---------------------------------------------------------------------------
# Isolation Forest
# The threshold is the ML_THRESHOLD_QUANTILE of the scores on normal training
# data, i.e. we accept ~0.5% false positives on data that looks like training.
# ---------------------------------------------------------------------------
IF_N_ESTIMATORS = 200
ML_THRESHOLD_QUANTILE = 0.005
ML_BASE_POINTS = 20       # points for any ML anomaly
ML_SEVERITY_POINTS = 15   # extra points scaled by anomaly_score (0..1)

# ---------------------------------------------------------------------------
# Risk engine: (minimum points, level), checked top-down.
# CRITICAL additionally requires at least CRITICAL_MIN_INDICATORS
# independent indicators, otherwise it is capped at HIGH.
# ---------------------------------------------------------------------------
RISK_LEVELS = [(90, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (1, "LOW")]
CRITICAL_MIN_INDICATORS = 3
ALERT_LEVELS = {"MEDIUM", "HIGH", "CRITICAL"}  # levels that create an alert
