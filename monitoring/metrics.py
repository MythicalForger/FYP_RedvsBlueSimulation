import numpy as np
from collections import Counter, defaultdict

def normalize_blue_decision(event: dict) -> str:
    if event.get("role") == "blue_alert":
        return "Blocked"
    decision = event.get("decision") or event.get("verdict")
    if decision in ("blocked", "soft_block"):
        return "Blocked"
    return "Allowed"

def compute_decision_metrics(events):
    decisions = []
    latencies = []
    layer_hits = Counter()

    for e in events:
        if e.get("role") not in ("blue_decision", "blue_alert"):
            continue

        decision = normalize_blue_decision(e)
        decisions.append(decision)

        if "latency" in e:
            try:
                latencies.append(float(str(e["latency"]).replace("ms", "")))
            except:
                pass

        src = e.get("decision_source")
        if src:
            layer_hits[src] += 1

    counts = Counter(decisions)
    total = sum(counts.values()) or 1

    return {
        "counts": dict(counts),
        "block_rate": round(counts.get("Blocked", 0) / total, 3),
        "latency": {
            "median_ms": round(np.median(latencies), 1) if latencies else None,
            "p95_ms": round(np.percentile(latencies, 95), 1) if latencies else None,
        },
        "layer_hits": dict(layer_hits),
    }

def attack_type_outcomes(red_logs, alerts):
    alert_ids = {a["id"] for a in alerts if "id" in a}
    stats = defaultdict(lambda: Counter())

    for r in red_logs:
        aid = r.get("attack_id", "unknown")
        pid = r.get("id")
        if pid in alert_ids:
            stats[aid]["Blocked"] += 1
        else:
            stats[aid]["Allowed"] += 1

    return {k: dict(v) for k, v in stats.items()}
