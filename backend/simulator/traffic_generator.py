"""Generates realistic *normal* flow records for the smart-home topology.

Packet Tracer cannot export traffic, so this module reproduces the same
devices, addresses and services as the .pkt topology. Each device has a
behaviour profile (packets/min, packet size, connections, services it talks to,
and how active it is at each hour of the day).

Run:  python -m backend.simulator.traffic_generator
"""
import numpy as np
import pandas as pd

from backend import config

GW = config.GATEWAY_IP
DNS = (GW, 53, "UDP")
NTP = ("162.159.200.1", 123, "UDP")


def _always(_hour):
    return 1.0


def _evening(hour):
    return 1.5 if 18 <= hour <= 23 else (0.2 if hour < 7 else 0.6)


def _daytime(hour):
    return 1.0 if 8 <= hour <= 23 else 0.1


def _awake(hour):
    return 1.0 if hour >= 7 else 0.3


# services: (destination_ip, destination_port, protocol, weight)
PROFILES = {
    "192.168.10.10": {  # Camera — steady upload to its cloud service
        "ppm": 80, "pkt_size": 520, "flows": 5, "activity": _always,
        "services": [("52.95.110.20", 443, "TCP", 0.7), (*NTP, 0.1), (*DNS, 0.2)],
    },
    "192.168.10.11": {  # Smart TV — streaming, busiest in the evening
        "ppm": 120, "pkt_size": 900, "flows": 8, "activity": _evening,
        "services": [("45.57.40.1", 443, "TCP", 0.5), ("142.250.185.46", 443, "TCP", 0.3),
                     (*DNS, 0.15), ("23.62.99.10", 80, "TCP", 0.05)],
    },
    "192.168.10.12": {  # Smart Light — tiny MQTT heartbeats
        "ppm": 6, "pkt_size": 150, "flows": 2, "activity": _always,
        "services": [("34.231.20.5", 8883, "TCP", 0.8), (*DNS, 0.2)],
    },
    "192.168.10.13": {  # Speaker
        "ppm": 30, "pkt_size": 300, "flows": 3, "activity": _awake,
        "services": [("54.239.28.85", 443, "TCP", 0.7), (*DNS, 0.2), (*NTP, 0.1)],
    },
    "192.168.10.20": {  # Laptop — browsing, work hours
        "ppm": 200, "pkt_size": 700, "flows": 12, "activity": _daytime,
        "services": [("142.250.185.46", 443, "TCP", 0.3), ("140.82.112.3", 443, "TCP", 0.2),
                     ("13.107.42.14", 443, "TCP", 0.2), ("151.101.1.69", 443, "TCP", 0.1),
                     (*DNS, 0.2)],
    },
    "192.168.10.21": {  # Smartphone
        "ppm": 90, "pkt_size": 600, "flows": 7, "activity": _awake,
        "services": [("17.253.144.10", 443, "TCP", 0.35), ("157.240.1.35", 443, "TCP", 0.3),
                     ("142.250.185.46", 443, "TCP", 0.15), (*DNS, 0.2)],
    },
}


def make_flow(ts, src, dst, proto, sport, dport, packets, nbytes, scenario="normal"):
    return {
        "timestamp": ts, "source_ip": src, "destination_ip": dst, "protocol": proto,
        "source_port": int(sport), "destination_port": int(dport),
        "packets": int(packets), "bytes": int(nbytes), "scenario": scenario,
    }


def random_ts(rng, minute):
    return minute + pd.Timedelta(seconds=float(rng.uniform(0, 59.9)))


def ephemeral_port(rng):
    return int(rng.integers(49152, 65536))


def device_minute_flows(rng, ip, minute):
    """Normal flows of one device during one minute."""
    p = PROFILES[ip]
    factor = p["activity"](minute.hour)
    n_flows = max(1, int(rng.poisson(p["flows"] * factor)))
    mean_packets = p["ppm"] * factor
    total_packets = max(n_flows, int(rng.normal(mean_packets, mean_packets * 0.25)))

    shares = rng.dirichlet(np.ones(n_flows))
    packets = np.maximum(1, np.round(shares * total_packets)).astype(int)
    weights = np.array([s[3] for s in p["services"]], dtype=float)
    chosen = rng.choice(len(p["services"]), size=n_flows, p=weights / weights.sum())

    rows = []
    for pk, idx in zip(packets, chosen):
        dst, port, proto, _ = p["services"][idx]
        size = p["pkt_size"] * rng.lognormal(0, 0.15)
        rows.append(make_flow(random_ts(rng, minute), ip, dst, proto,
                              ephemeral_port(rng), port, pk, pk * size))
    return rows


def generate_normal(start, minutes, seed=config.RANDOM_SEED):
    rng = np.random.default_rng(seed)
    start = pd.Timestamp(start).floor("min")
    rows = []
    for m in range(minutes):
        minute = start + pd.Timedelta(minutes=m)
        for ip in PROFILES:
            rows.extend(device_minute_flows(rng, ip, minute))
    return pd.DataFrame(rows).sort_values("timestamp", ignore_index=True)


def main(days=7):
    config.DATA_DIR.mkdir(exist_ok=True)
    flows = generate_normal("2026-09-01", minutes=days * 24 * 60, seed=config.RANDOM_SEED)
    flows.to_csv(config.NORMAL_TRAFFIC_CSV, index=False)
    print(f"Wrote {len(flows):,} normal flows ({days} days) -> {config.NORMAL_TRAFFIC_CSV}")


if __name__ == "__main__":
    main()
