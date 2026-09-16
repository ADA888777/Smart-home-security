"""Turns raw flow records into per-device, per-minute behaviour features."""
import pandas as pd

from backend import config

FEATURE_COLUMNS = [
    "packets_per_minute",
    "bytes_per_minute",
    "connection_count",
    "unique_destinations",
    "unique_dst_ports",
    "average_packet_size",
    "tcp_count",
    "udp_count",
]


def prepare_flows(flows: pd.DataFrame) -> pd.DataFrame:
    df = flows.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["window"] = df["timestamp"].dt.floor(config.WINDOW)
    if "scenario" not in df:
        df["scenario"] = "normal"
    return df


def build_features(flows: pd.DataFrame) -> pd.DataFrame:
    df = prepare_flows(flows)
    df["is_tcp"] = (df["protocol"] == "TCP").astype(int)
    df["is_udp"] = (df["protocol"] == "UDP").astype(int)

    feats = (
        df.groupby(["source_ip", "window"])
        .agg(
            packets_per_minute=("packets", "sum"),
            bytes_per_minute=("bytes", "sum"),
            connection_count=("packets", "size"),
            unique_destinations=("destination_ip", "nunique"),
            unique_dst_ports=("destination_port", "nunique"),
            tcp_count=("is_tcp", "sum"),
            udp_count=("is_udp", "sum"),
        )
        .reset_index()
    )
    feats["average_packet_size"] = feats["bytes_per_minute"] / feats["packets_per_minute"]

    # Ground-truth label (only meaningful for simulated data)
    attack = df[df["scenario"] != "normal"].groupby(["source_ip", "window"])["scenario"].first()
    feats = feats.merge(attack.rename("scenario").reset_index(), on=["source_ip", "window"], how="left")
    feats["scenario"] = feats["scenario"].fillna("normal")
    feats["label"] = (feats["scenario"] != "normal").astype(int)
    return feats
