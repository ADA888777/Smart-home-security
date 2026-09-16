"""Traffic sources that all produce the same flow schema.

- load_csv():     simulated data derived from the Packet Tracer topology
- capture_live(): optional real capture with Scapy (needs root/admin rights and
                  permission to monitor the network — only use on your own network)
"""
import time
from collections import defaultdict

import pandas as pd

FLOW_COLUMNS = ["timestamp", "source_ip", "destination_ip", "protocol",
                "source_port", "destination_port", "packets", "bytes"]


def load_csv(path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def capture_live(interface=None, seconds=60) -> pd.DataFrame:
    """Sniff packets and aggregate them into flows (5-tuple) for `seconds`."""
    from scapy.all import IP, TCP, UDP, sniff  # optional dependency

    flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "first": None})

    def on_packet(pkt):
        if IP not in pkt:
            return
        if TCP in pkt:
            proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
        else:
            proto, sport, dport = "ICMP" if pkt[IP].proto == 1 else "OTHER", 0, 0
        key = (pkt[IP].src, pkt[IP].dst, proto, sport, dport)
        f = flows[key]
        f["packets"] += 1
        f["bytes"] += len(pkt)
        f["first"] = f["first"] or time.time()

    sniff(iface=interface, prn=on_packet, store=False, timeout=seconds)
    rows = [
        {"timestamp": pd.Timestamp.fromtimestamp(v["first"]), "source_ip": k[0],
         "destination_ip": k[1], "protocol": k[2], "source_port": k[3],
         "destination_port": k[4], "packets": v["packets"], "bytes": v["bytes"]}
        for k, v in flows.items()
    ]
    return pd.DataFrame(rows, columns=FLOW_COLUMNS)
