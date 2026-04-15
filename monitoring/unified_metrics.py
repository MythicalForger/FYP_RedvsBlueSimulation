"""
Unified Benchmark Metrics Calculator
=====================================
Single source of truth for benchmark metric calculations.
Use this in BOTH analyze_blue_benchmark.py AND stats_api.py
to ensure consistency.

Usage:
    from unified_metrics import compute_benchmark_metrics
    
    metrics = compute_benchmark_metrics(records)
    print(metrics)
"""

import json
import numpy as np
from typing import List, Dict, Optional


def load_benchmark_results(path: str) -> List[Dict]:
    """Load benchmark results from JSONL file."""
    records = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return []
    return records


def compute_benchmark_metrics(records: List[Dict]) -> Optional[Dict]:
    """
    Compute standardized benchmark metrics from benchmark results.
    
    Args:
        records: List of benchmark result dictionaries containing:
            - label: "malicious" or "benign"
            - blue_verdict: verdict from Blue agent
            - latency_s: response time in seconds
    
    Returns:
        Dictionary with metrics or None if no valid data
    """
    if not records:
        return None
    
    y_true = []
    y_pred = []
    latencies = []
    
    for row in records:
        # Skip error records
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
        
        # Prediction: treat blocked/soft_block as 1 (detected), allowed as 0
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
        return None
    
    # Confusion matrix
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    
    total = tp + tn + fp + fn
    
    # Core metrics
    accuracy = (tp + tn) / total if total > 0 else 0.0
    detection_rate = tp / (tp + fn + 1e-9)  # TPR / Recall
    false_positive_rate = fp / (fp + tn + 1e-9)  # FPR
    precision = tp / (tp + fp + 1e-9) if (tp + fp) > 0 else 0.0
    recall = detection_rate
    f1_score = (2 * precision * recall / (precision + recall + 1e-9) 
                if (precision + recall) > 0 else 0.0)
    
    # Latency metrics
    latency_median_ms = None
    latency_p95_ms = None
    if latencies:
        latency_median_ms = float(np.median(latencies) * 1000)
        latency_p95_ms = float(np.percentile(latencies, 95) * 1000)
    
    return {
        "total_samples": len(y_true),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": round(accuracy, 3),
        "detection_rate": round(detection_rate, 3),
        "false_positive_rate": round(false_positive_rate, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1_score, 3),
        "latency_median_ms": round(latency_median_ms, 1) if latency_median_ms else None,
        "latency_p95_ms": round(latency_p95_ms, 1) if latency_p95_ms else None,
    }


def print_metrics(metrics: Dict) -> None:
    """Print metrics in a formatted way (for terminal use)."""
    if not metrics:
        print("No valid benchmark data found.")
        return
    
    print(f"Total samples: {metrics['total_samples']}")
    print(f"TP, TN, FP, FN: {metrics['tp']}, {metrics['tn']}, {metrics['fp']}, {metrics['fn']}")
    print(f"Accuracy: {metrics['accuracy']}")
    print(f"Detection rate (TPR/Recall): {metrics['detection_rate']}")
    print(f"False positive rate (FPR): {metrics['false_positive_rate']}")
    print(f"Precision: {metrics['precision']}")
    print(f"Recall: {metrics['recall']}")
    print(f"F1 score: {metrics['f1_score']}")
    
    if metrics['latency_median_ms']:
        print(f"Latency median (ms): {metrics['latency_median_ms']}")
        print(f"Latency 95th percentile (ms): {metrics['latency_p95_ms']}")
    else:
        print("No latency values recorded.")


if __name__ == "__main__":
    import sys
    
    # Allow path override via CLI or env
    import os
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
        "BENCHMARK_PATH", "blue_benchmark_results.jsonl"
    )
    
    print(f"Loading benchmark results from: {path}")
    records = load_benchmark_results(path)
    print(f"Loaded {len(records)} records")
    
    metrics = compute_benchmark_metrics(records)
    print("\n" + "="*60)
    print("BENCHMARK METRICS")
    print("="*60)
    print_metrics(metrics)
