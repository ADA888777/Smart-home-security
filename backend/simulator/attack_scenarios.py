"""Controlled attack scenarios injected into simulated traffic.

Nothing here touches a real network: each function only returns flow records
in the same schema as the normal generator. Intensities are randomised so the
evaluation contains both obvious and subtle cases.

Run:  python -m backend.simulator.attack_scenarios
"""
import numpy as np
import pandas as pd

from backend import config
from backend.simulator.traffic_generator import (
    PROFILES, ephemeral_port, generate_normal, make_flow, random_ts,
)

SUSPICIOUS_IPS = ["185.220.101.34", "45.155.205.99", "91.219.236.18", "103.75.190.12"]
UNUSUAL_PORTS = [22, 23, 2323, 445, 3389, 5555, 6667]


def _primary_service(ip):
    return max(PROFILES[ip]["services"], key=lambda s: s[3])


def traffic_spike(rng, ip, minute, intensity=None):
    """Device sends k times its usual volume to its normal service."""
    p = PROFILES[ip]
    k = intensity if intensity is not None else rng.uniform(1.5, 15)
    dst, port, proto, _ = _primary_service(ip)
    extra = max(1, int(p["ppm"] * p["activity"](minute.hour) * (k - 1)))
    n = int(rng.integers(1, 4))
    return [make_flow(random_ts(rng, minute), ip, dst, proto, ephemeral_port(rng), port,
                      extra // n + 1, (extra // n + 1) * p["pkt_size"], "traffic_spike")
            for _ in range(n)]


def unusual_port(rng, ip, minute, port=None):
    """Device talks to a port it never uses (e.g. Telnet from a smart light)."""
    port = port if port is not None else int(rng.choice(UNUSUAL_PORTS))
    dst = _primary_service(ip)[0]
    rows = []
    for _ in range(int(rng.integers(1, 3))):
        pk = int(rng.integers(3, 30))
        rows.append(make_flow(random_ts(rng, minute), ip, dst, "TCP", ephemeral_port(rng),
                              port, pk, pk * 80, "unusual_port"))
    return rows


def unusual_destination(rng, ip, minute, destination=None):
    """Device contacts an external IP outside its normal profile."""
    p = PROFILES[ip]
    dst = destination or str(rng.choice(SUSPICIOUS_IPS))
    pk = max(3, int(p["ppm"] * rng.uniform(0.1, 1.0)))
    return [make_flow(random_ts(rng, minute), ip, dst, "TCP", ephemeral_port(rng), 443,
                      pk, pk * p["pkt_size"], "unusual_destination")]


def port_scan(rng, ip, minute):
    """Compromised device scans the gateway (abnormal connection pattern)."""
    n_ports = int(rng.integers(15, 300))
    ports = rng.choice(np.arange(1, 1025), size=n_ports, replace=False)
    return [make_flow(random_ts(rng, minute), ip, config.GATEWAY_IP, "TCP",
                      ephemeral_port(rng), int(port), 1, 60, "port_scan")
            for port in ports]


def unknown_device(rng, minute, ip=None):
    """A device that is not in the registry joins and starts talking."""
    ip = ip or f"192.168.10.{int(rng.integers(100, 200))}"
    rows = [make_flow(random_ts(rng, minute), ip, config.GATEWAY_IP, "UDP",
                      ephemeral_port(rng), 53, 2, 180, "unknown_device")]
    for _ in range(int(rng.integers(1, 4))):
        pk = int(rng.integers(5, 100))
        rows.append(make_flow(random_ts(rng, minute), ip, str(rng.choice(SUSPICIOUS_IPS)),
                              "TCP", ephemeral_port(rng), 443, pk, pk * 500, "unknown_device"))
    return rows


def data_exfiltration(rng, ip, minute):
    """Multiple indicators: large upload, unknown destination, unusual ports."""
    p = PROFILES[ip]
    dst = str(rng.choice(SUSPICIOUS_IPS))
    rows = []
    for port in (4444, 8443):
        pk = int(p["ppm"] * rng.uniform(5, 20))
        rows.append(make_flow(random_ts(rng, minute), ip, dst, "TCP", ephemeral_port(rng),
                              port, pk, pk * 1400, "data_exfiltration"))
    return rows


DEVICE_SCENARIOS = {
    "traffic_spike": traffic_spike,
    "unusual_port": unusual_port,
    "unusual_destination": unusual_destination,
    "port_scan": port_scan,
    "data_exfiltration": data_exfiltration,
}


def build_test_set(start, minutes, seed, attacks_per_scenario=50):
    """Normal traffic with labelled attack windows injected at random times."""
    rng = np.random.default_rng(seed)
    flows = generate_normal(start, minutes, seed=seed)
    start = pd.Timestamp(start).floor("min")
    used, extra = set(), []

    def free_slot(ip):
        while True:
            minute = start + pd.Timedelta(minutes=int(rng.integers(0, minutes)))
            if (ip, minute) not in used:
                used.add((ip, minute))
                return minute

    for name, fn in DEVICE_SCENARIOS.items():
        for _ in range(attacks_per_scenario):
            ip = str(rng.choice(list(PROFILES)))
            extra.extend(fn(rng, ip, free_slot(ip)))
    for i in range(attacks_per_scenario):
        ip = f"192.168.10.{100 + i}"
        extra.extend(unknown_device(rng, free_slot(ip), ip=ip))

    return pd.concat([flows, pd.DataFrame(extra)], ignore_index=True).sort_values(
        "timestamp", ignore_index=True)


def main():
    config.DATA_DIR.mkdir(exist_ok=True)
    flows = build_test_set("2026-09-10", minutes=3 * 24 * 60, seed=2026)
    flows.to_csv(config.ATTACK_TRAFFIC_CSV, index=False)
    n_attack = (flows["scenario"] != "normal").sum()
    print(f"Wrote {len(flows):,} flows ({n_attack:,} attack flows) -> {config.ATTACK_TRAFFIC_CSV}")


if __name__ == "__main__":
    main()
