# Smart Home Network Security and Anomaly Detection System

Hybrid detection (explainable rules + Isolation Forest) for a smart-home network
designed in Cisco Packet Tracer (LAN 192.168.10.0/24, gateway 192.168.10.1).

## Run

```bash
pip install -r requirements.txt
python -m backend.simulator.traffic_generator   # data/normal_traffic.csv (7 days, normal only)
python -m backend.simulator.attack_scenarios    # data/attack_traffic.csv (3 other days + labelled attacks)
python -m backend.ml.train                      # models/baselines.json + models/anomaly_model.pkl
python -m backend.ml.evaluate                   # docs/evaluation_results.md
python -m pytest -q                             # the 6 controlled-simulation scenarios
```

## Pipeline

flows -> per-device/minute features -> security rules + Isolation Forest -> risk engine
(NORMAL / LOW / MEDIUM / HIGH / CRITICAL, each with written reasons).

## Limitations (state these in the report)

- Data is synthetic, generated from the topology's device profiles. Rules score very
  well partly because normal devices use a fixed set of destinations; real devices
  contact changing CDN IPs, so `unknown_destination` would need domain-based allowlists.
- Isolation Forest saturates outside the training range: a 12x spike scores like a 2x
  spike. Extreme univariate spikes are therefore handled by rules.
- Subtle spikes (below 2x the normal 99.9th percentile) are missed by both detectors.
