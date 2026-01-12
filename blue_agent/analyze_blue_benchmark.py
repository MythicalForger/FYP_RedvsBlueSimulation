#analyze_blue_benchmark.py
import json
from collections import Counter
import os
import sys

import numpy as np

# default path can be overridden by env BENCHMARK_PATH or CLI arg
PATH = os.environ.get("BENCHMARK_PATH", "blue_benchmark_results.jsonl")
if len(sys.argv) > 1:
    PATH = sys.argv[1]


def load_results(path: str):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def compute_metrics(records):
    y_true = []
    y_pred = []
    latencies = []

    for row in records:
        if "error" in row:
            continue

        label = row.get("label")
        verdict = row.get("blue_verdict")
        latency = row.get("latency_s")

        # Ground truth: 1 = malicious, 0 = benign
        if label == "malicious":
            true = 1
        elif label == "benign":
            true = 0
        else:
            continue

        # Prediction: treat blocked / soft-blocked as 1, allowed as 0
        # Our Blue implementation uses:
        # - decision field: "blocked", "soft_block", or "allowed"
        # - response field: text like "Blocked by Blue" for blocked/soft_block
        is_block_like = False
        if verdict in ("blocked", "soft_block"):
            is_block_like = True
        elif isinstance(verdict, str) and "blocked" in verdict.lower():
            is_block_like = True

        pred = 1 if is_block_like else 0

        y_true.append(true)
        y_pred.append(pred)

        if isinstance(latency, (int, float)):
            latencies.append(latency)

    if not y_true:
        raise ValueError("No valid records found to compute metrics.")

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    detection_rate = tp / (tp + fn + 1e-9)  # TPR / recall on malicious
    false_positive_rate = fp / (fp + tn + 1e-9)
    precision = tp / (tp + fp + 1e-9) if (tp + fp) > 0 else 0.0
    recall = detection_rate
    f1 = 2 * precision * recall / (precision + recall + 1e-9) if (precision + recall) > 0 else 0.0

    print("Total samples:", len(y_true))
    print("TP, TN, FP, FN:", tp, tn, fp, fn)
    print("Detection rate (TPR) on malicious:", round(detection_rate, 3))
    print("False positive rate (FPR) on benign:", round(false_positive_rate, 3))
    print("Precision:", round(precision, 3))
    print("Recall:", round(recall, 3))
    print("F1 score:", round(f1, 3))

    if latencies:
        lat = np.array(latencies)
        print("Latency median (ms):", round(float(np.median(lat) * 1000), 1))
        print("Latency 95th percentile (ms):", round(float(np.percentile(lat, 95) * 1000), 1))
    else:
        print("No latency values recorded.")


def summarize_by_category(records):
    """
    Optional helper: show counts of decisions per label (malicious/benign).
    """
    counts = Counter()
    for row in records:
        label = row.get("label")
        verdict = row.get("blue_verdict")
        key = (label, verdict)
        counts[key] += 1

    print("\nCounts by (label, blue_verdict):")
    for (label, verdict), c in sorted(counts.items()):
        print(f"{label:9s} | {str(verdict):20s} : {c}")


if __name__ == "__main__":
    recs = load_results(PATH)
    summarize_by_category(recs)
    print()
    compute_metrics(recs)