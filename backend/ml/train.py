"""Build device baselines and train Isolation Forest models on NORMAL traffic only.

Run:  python -m backend.ml.train
"""
from backend import config
from backend.detection.anomaly_detection import save_models, train_models
from backend.detection.baseline import build_baselines, save_baselines
from backend.monitoring.collector import load_csv
from backend.monitoring.traffic_features import build_features


def main():
    flows = load_csv(config.NORMAL_TRAFFIC_CSV)
    if (flows["scenario"] != "normal").any():
        raise ValueError("Training data must contain normal traffic only")
    features = build_features(flows)

    baselines = build_baselines(features, flows)
    save_baselines(baselines)
    save_models(train_models(features))

    print(f"Trained on {len(features):,} device-minutes from {len(baselines)} devices")
    for ip, b in baselines.items():
        s = b["stats"]
        print(f"  {b['name']:<12} {ip:<15} packets/min p50={s['packets_per_minute']['p50']:>6,.0f} "
              f"p99.9={s['packets_per_minute']['p999']:>6,.0f}  ports={b['known_ports']}")


if __name__ == "__main__":
    main()
