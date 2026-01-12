from fastapi import FastAPI, Request, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio, json
from pathlib import Path
import uvicorn
import threading
import time
import numpy as np
from collections import Counter
from log_utils import read_jsonl, ACTIVE_LOGS

# Use Docker container paths when running inside container
if Path("/app").exists():
    # Running inside Docker container
    LOG_DIR = Path("/app/logs")
else:
    # Running locally
    ROOT = Path(__file__).resolve().parents[1]
    LOG_DIR = ROOT / "logs"

AI_EVENTS = LOG_DIR / "ai_events.jsonl"
ALERTS = LOG_DIR / "alerts.jsonl"
STATS = LOG_DIR / "stats.json"
RED_SENT = LOG_DIR / "red_sent.jsonl"

# Benchmark results path - handle both Docker and local
if Path("/app").exists():
    BENCHMARK_RESULTS = Path("/app/benchmarks/blue_benchmark_results.jsonl")
else:
    ROOT = Path(__file__).resolve().parents[1]
    BENCHMARK_RESULTS = ROOT / "benchmarks" / "blue_benchmark_results.jsonl"

app = FastAPI(title="Agentic Monitoring API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

subscribers = []  # for SSE streaming (if added later)

# Global stats state
stats_state = {"attacks": 0, "mitigations": 0, "false_positives": 0, "total_events": 0}


def compute_benchmark_metrics():
    """Compute metrics from benchmark results if available."""
    if not BENCHMARK_RESULTS.exists():
        return None
    
    records = read_jsonl(BENCHMARK_RESULTS)
    if not records:
        return None
    
    y_true = []
    y_pred = []
    latencies = []
    
    for row in records:
        if "error" in row:
            continue
        
        label = row.get("label")
        verdict = row.get("blue_verdict")
        latency = row.get("latency_s")
        
        if label == "malicious":
            true = 1
        elif label == "benign":
            true = 0
        else:
            continue
        
        is_block_like = False
        if verdict in ("blocked", "soft_block"):
            is_block_like = True
        elif isinstance(verdict, str) and "blocked" in str(verdict).lower():
            is_block_like = True
        
        pred = 1 if is_block_like else 0
        y_true.append(true)
        y_pred.append(pred)
        
        if isinstance(latency, (int, float)):
            latencies.append(latency)
    
    if not y_true:
        return None
    
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    
    detection_rate = tp / (tp + fn + 1e-9)
    false_positive_rate = fp / (fp + tn + 1e-9)
    precision = tp / (tp + fp + 1e-9) if (tp + fp) > 0 else 0.0
    recall = detection_rate
    f1 = 2 * precision * recall / (precision + recall + 1e-9) if (precision + recall) > 0 else 0.0
    
    latency_median = float(np.median(latencies) * 1000) if latencies else None
    latency_p95 = float(np.percentile(latencies, 95) * 1000) if latencies else None
    
    return {
        "total_samples": len(y_true),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "detection_rate": round(detection_rate, 3),
        "false_positive_rate": round(false_positive_rate, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "latency_median_ms": round(latency_median, 1) if latency_median else None,
        "latency_p95_ms": round(latency_p95, 1) if latency_p95 else None
    }


def update_stats_from_logs():
    """Update stats by reading all existing logs."""
    global stats_state
    
    events = read_jsonl(AI_EVENTS)
    alerts = read_jsonl(ALERTS)
    red_sent = read_jsonl(RED_SENT)  # Source of truth for all attacks sent
    
    # Reset stats
    stats_state = {"attacks": 0, "mitigations": 0, "false_positives": 0, "total_events": 0, 
                   "allowed": 0, "block_rate": 0.0, "success_rate": 0.0}
    
    # Count ALL attacks from red_sent.jsonl (source of truth - every attack sent by red agent)
    stats_state["attacks"] = len(red_sent)
    
    # Count mitigations from red_sent.jsonl where status_code == 403 (blocked)
    mitigations = sum(1 for r in red_sent if r.get("status_code") == 403)
    stats_state["mitigations"] = mitigations
    
    # Count allowed requests (status_code == 200)
    allowed = sum(1 for r in red_sent if r.get("status_code") == 200)
    stats_state["allowed"] = allowed
    
    # Calculate block rate
    if stats_state["attacks"] > 0:
        stats_state["block_rate"] = round(mitigations / stats_state["attacks"], 3)
        stats_state["success_rate"] = round(allowed / stats_state["attacks"], 3)
    
    # Count total events
    stats_state["total_events"] = len(events)
    
    # Calculate false positives from benchmark data if available
    benchmark_metrics = compute_benchmark_metrics()
    if benchmark_metrics:
        stats_state["false_positives"] = benchmark_metrics.get("fp", 0)
        stats_state["benchmark_metrics"] = benchmark_metrics
    else:
        # Fallback: count benign requests that were blocked (if we can identify them)
        # This is a simplified approach - ideally use benchmark data
        stats_state["false_positives"] = 0
    
    # Save stats
    try:
        with open(STATS, "w", encoding="utf-8") as f:
            json.dump(stats_state, f, indent=2)
    except PermissionError:
        pass




@app.get("/health")
def health_check():
    """Simple health check endpoint."""
    return {"status": "healthy", "service": "monitoring_api"}


@app.get("/stats")
def get_stats():
    """Return basic statistics."""
    # Update stats from logs
    update_stats_from_logs()
    return JSONResponse(stats_state)


@app.get("/events")
def get_events(limit: int = 100):
    """Fetch recent events."""
    data = read_jsonl(AI_EVENTS)
    return JSONResponse(data[-limit:])


@app.get("/alerts")
def get_alerts():
    """Fetch alerts for timeline view."""
    data = read_jsonl(ALERTS)
    return JSONResponse(data)


@app.get("/benchmark")
def get_benchmark():
    """Fetch benchmark metrics if available."""
    metrics = compute_benchmark_metrics()
    if metrics:
        return JSONResponse(metrics)
    return JSONResponse({"error": "No benchmark data available"})


@app.get("/metrics")
def get_detailed_metrics():
    """Get detailed metrics including decision breakdown."""
    events = read_jsonl(AI_EVENTS)
    alerts = read_jsonl(ALERTS)
    red_sent = read_jsonl(RED_SENT)
    
    # Decision breakdown
    decisions = Counter()
    for e in events:
        if e.get("role") == "blue_decision":
            decision = e.get("decision") or e.get("verdict", "unknown")
            decisions[decision] += 1
    
    # Attack type breakdown
    attack_types = Counter()
    for r in red_sent:
        status = r.get("status_code", 0)
        if status == 403:
            attack_types["blocked"] += 1
        elif status == 200:
            attack_types["allowed"] += 1
        else:
            attack_types["other"] += 1
    
    # Time-based metrics
    timestamps = []
    for r in red_sent:
        if "ts" in r:
            timestamps.append(r["ts"])
    
    return JSONResponse({
        "decisions": dict(decisions),
        "attack_outcomes": dict(attack_types),
        "total_attacks": len(red_sent),
        "total_alerts": len(alerts),
        "time_range": {
            "earliest": min(timestamps) if timestamps else None,
            "latest": max(timestamps) if timestamps else None
        }
    })


@app.post("/internal/publish")
async def internal_publish(payload: dict = Body(...)):
    """Internal endpoint used by log_watcher to push events."""
    for queue in subscribers:
        await queue.put(payload)
    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run("stats_api:app", host="0.0.0.0", port=9000)
