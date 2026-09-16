"""Finds which devices are active on the LAN and whether they are known."""
import ipaddress

import pandas as pd

from backend import config

LAN = ipaddress.ip_network(config.NETWORK_CIDR)


def discover_devices(flows: pd.DataFrame, registry=config.DEVICES) -> pd.DataFrame:
    df = flows.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    lan = df[df["source_ip"].map(lambda ip: ipaddress.ip_address(ip) in LAN)]
    lan = lan[lan["source_ip"] != config.GATEWAY_IP]

    seen = lan.groupby("source_ip")["timestamp"].agg(["min", "max"]).reset_index()
    seen.columns = ["ip_address", "first_seen", "last_seen"]
    seen["known"] = seen["ip_address"].isin(registry)
    seen["name"] = seen["ip_address"].map(lambda ip: registry.get(ip, {}).get("name", "Unknown device"))
    seen["device_type"] = seen["ip_address"].map(lambda ip: registry.get(ip, {}).get("type", "unknown"))
    seen["mac_address"] = seen["ip_address"].map(lambda ip: registry.get(ip, {}).get("mac"))
    return seen.sort_values("ip_address", ignore_index=True)
