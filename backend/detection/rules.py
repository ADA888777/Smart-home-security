"""Explainable security rules. Each finding carries a human-readable reason."""
import pandas as pd

from backend import config
from backend.monitoring.traffic_features import prepare_flows

FINDING_COLUMNS = ["source_ip", "window", "rule", "points", "reason"]


def _name(ip, registry):
    return registry.get(ip, {}).get("name", ip)


def _fmt(values, limit=5):
    values = sorted(values, key=str)
    text = ", ".join(str(v) for v in values[:limit])
    return text + (f" (+{len(values) - limit} more)" if len(values) > limit else "")


def _finding(ip, window, rule, reason):
    return {"source_ip": ip, "window": window, "rule": rule,
            "points": config.RULE_POINTS[rule], "reason": reason}


def rule_unknown_device(features, registry):
    out = []
    for r in features[~features["source_ip"].isin(registry)].to_dict("records"):
        out.append(_finding(r["source_ip"], r["window"], "unknown_device",
                            f"Unknown device {r['source_ip']} is active on the network "
                            f"({r['packets_per_minute']} packets/min to {r['unique_destinations']} destinations)"))
    return out


def _over_limit(features, baselines, columns, rule, registry, label):
    known = features[features["source_ip"].isin(baselines)]
    out = []
    for r in known.to_dict("records"):
        stats = baselines[r["source_ip"]]["stats"]
        broken = []
        for col in columns:
            limit = stats[col]["p999"] * config.RULE_MULTIPLIER
            if r[col] > limit:
                broken.append(f"{col}={r[col]:,.0f} (normal ~{stats[col]['p50']:,.0f}, limit {limit:,.0f})")
        if broken:
            out.append(_finding(r["source_ip"], r["window"], rule,
                                f"{label} on {_name(r['source_ip'], registry)}: " + "; ".join(broken)))
    return out


def rule_traffic_spike(features, baselines, registry):
    return _over_limit(features, baselines, ["packets_per_minute", "bytes_per_minute"],
                       "traffic_spike", registry, "Traffic spike")


def rule_abnormal_connection_pattern(features, baselines, registry):
    return _over_limit(features, baselines, ["connection_count", "unique_dst_ports"],
                       "abnormal_connection_pattern", registry, "Abnormal connection pattern")


def _not_in_profile(flows, baselines, column, profile_key, rule, registry, label):
    known = flows[flows["source_ip"].isin(baselines)]
    allowed = pd.MultiIndex.from_tuples(
        [(ip, v) for ip, b in baselines.items() for v in b[profile_key]])
    values = known[column].astype(int) if column == "destination_port" else known[column]
    mask = ~pd.MultiIndex.from_arrays([known["source_ip"], values]).isin(allowed)
    out = []
    for (ip, window), g in known[mask].groupby(["source_ip", "window"]):
        new_values = g[column].unique().tolist()
        normal = baselines[ip][profile_key]
        out.append(_finding(ip, window, rule,
                            f"{_name(ip, registry)} used {label} {_fmt(new_values)} "
                            f"(normal: {_fmt(normal)})"))
    return out


def rule_unexpected_port(flows, baselines, registry):
    return _not_in_profile(flows, baselines, "destination_port", "known_ports",
                           "unexpected_port", registry, "unexpected port(s)")


def rule_unknown_destination(flows, baselines, registry):
    return _not_in_profile(flows, baselines, "destination_ip", "known_destinations",
                           "unknown_destination", registry, "unknown destination(s)")


def evaluate_rules(features, flows, baselines, registry=config.DEVICES) -> pd.DataFrame:
    flows = prepare_flows(flows)
    findings = (
        rule_unknown_device(features, registry)
        + rule_traffic_spike(features, baselines, registry)
        + rule_unexpected_port(flows, baselines, registry)
        + rule_unknown_destination(flows, baselines, registry)
        + rule_abnormal_connection_pattern(features, baselines, registry)
    )
    return pd.DataFrame(findings, columns=FINDING_COLUMNS)
