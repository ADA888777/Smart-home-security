# Evaluation results

Test set: 25,970 device-minutes, 300 attack windows. Synthetic data generated from the Packet Tracer topology, different seed and days from training.

## Overall

| Detector | Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| Rules only | 1.000 | 0.947 | 0.973 | 0.0000 | 284 | 0 | 25670 | 16 |
| Isolation Forest only | 0.321 | 0.203 | 0.249 | 0.0050 | 61 | 129 | 25541 | 239 |
| Hybrid (alert = MEDIUM or above) | 1.000 | 0.947 | 0.973 | 0.0000 | 284 | 0 | 25670 | 16 |

## Detection rate per scenario

| Scenario | Windows | Rules | Isolation Forest | Hybrid |
|---|---|---|---|---|
| data_exfiltration | 50 | 100.0% | 36.0% | 100.0% |
| normal | 25670 | 0.0% | 0.5% | 0.0% |
| port_scan | 50 | 100.0% | 72.0% | 100.0% |
| traffic_spike | 50 | 68.0% | 0.0% | 68.0% |
| unknown_device | 50 | 100.0% | 0.0% | 100.0% |
| unusual_destination | 50 | 100.0% | 6.0% | 100.0% |
| unusual_port | 50 | 100.0% | 8.0% | 100.0% |

(For `normal` this is the false-alarm rate.)

## Risk level by scenario

| scenario            |   CRITICAL |   HIGH |   LOW |   MEDIUM |   NORMAL |
|:--------------------|-----------:|-------:|------:|---------:|---------:|
| data_exfiltration   |         50 |      0 |     0 |        0 |        0 |
| normal              |          0 |      0 |   129 |        0 |    25541 |
| port_scan           |         20 |     30 |     0 |        0 |        0 |
| traffic_spike       |          0 |     34 |     0 |        0 |       16 |
| unknown_device      |          0 |      0 |     0 |       50 |        0 |
| unusual_destination |          0 |      6 |     0 |       44 |        0 |
| unusual_port        |          1 |      2 |     0 |       47 |        0 |
