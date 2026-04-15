#!/usr/bin/env python3
"""
Monitoring API - Stats & Metrics Endpoint
==========================================
FastAPI service that provides real-time stats and benchmark metrics
for the Red vs Blue agent simulation.

Endpoints:
  GET /health         - Health check
  GET /stats          - Live simulation statistics
  GET /events         - Recent AI events log
  GET /alerts         - Security alerts log
  GET /benchmark      - Benchmark performance metrics
  GET /metrics        - Detailed metrics with decision breakdown
"""

import os
import json
import time
from pathlib import Path
from collections import Counter
from typing import List, Dict

import uvicorn
from fastapi import FastAPI, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio

# Import unified metrics module for consistent calculations
from unified_metrics import compute_benchmark_metrics, load_benchmark_results

# ──────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────

# Log directory paths
if Path("/app").exists():
    # Running inside Docker container
    LOG_DIR = Path("/app/logs")
    BENCHMARK_DIR = Path("/app/benchmarks")
else:
    # Running locally
    ROOT = Path(__file__).resolve().parents[1]
    LOG_DIR = ROOT / "logs"
    BENCHMARK_DIR = ROOT / "benchmarks"

# Log file paths
AI_EVENTS = LOG_DIR / "ai_events.jsonl"
ALERTS = LOG_DIR / "alerts.jsonl"
RED_SENT = LOG_DIR / "red_sent.jsonl"
STATS = LOG_DIR / "stats.json"

# Benchmark results path - configurable via environment variable
BENCHMARK_RESULTS = os.environ.get(
    "BENCHMARK_RESULTS",
    str(BENCHMARK_DIR / "blue_benchmark_results.jsonl")
)

# Create directories
LOG_DIR.mkdir(parents=True, exist_ok=True)
BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)

# Initialize log files
for log_file in [AI_EVENTS, ALERTS, RED_SENT]:
    log_file.touch(exist_ok=True)

# ──────────────────────────────────────────────────────────────
# FASTAPI APPLICATION
# ──────────────────────────────────────────────────────────────

app = FastAPI(title="AI Security Monitoring API", version="2.0")

# Enable CORS for dashboard access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SSE subscribers for real-time updates
subscribers = []

# Stats state cache
stats_state = {
    "attacks": 0,
    "mitigations": 0,
    "false_positives": 0,
    "total_events": 0,
    "allowed": 0,
    "block_rate": 0.0,
    "success_rate": 0.0,
}

# ──────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ──────────────────────────────────────────────────────────────

def read_jsonl(path: Path) -> List[Dict]:
    """Read JSONL file and return list of records."""
    if not path.exists():
        return []
    
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def update_stats_from_logs():
    """
    Update cached stats by reading all existing logs.
    Called periodically to keep stats fresh.
    """
    global stats_state

    events = read_jsonl(AI_EVENTS)
    alerts = read_jsonl(ALERTS)
    red_sent = read_jsonl(RED_SENT)

    stats_state = {
        "attacks": 0,
        "mitigations": 0,
        "false_positives": 0,
        "total_events": 0,
        "allowed": 0,
        "block_rate": 0.0,
        "success_rate": 0.0,
    }

    # Count attacks and outcomes
    stats_state["attacks"] = len(red_sent)
    mitigations = sum(1 for r in red_sent if r.get("status_code") == 403)
    stats_state["mitigations"] = mitigations
    allowed = sum(1 for r in red_sent if r.get("status_code") == 200)
    stats_state["allowed"] = allowed

    # Calculate rates
    if stats_state["attacks"] > 0:
        stats_state["block_rate"] = round(mitigations / stats_state["attacks"], 3)
        stats_state["success_rate"] = round(allowed / stats_state["attacks"], 3)

    stats_state["total_events"] = len(events)

    # Get false positives from benchmark metrics
    benchmark_metrics = compute_benchmark_metrics(load_benchmark_results(BENCHMARK_RESULTS))
    if benchmark_metrics:
        stats_state["false_positives"] = benchmark_metrics.get("fp", 0)
        stats_state["benchmark_metrics"] = benchmark_metrics
    else:
        stats_state["false_positives"] = 0

    # Save stats to file (for other tools to read)
    try:
        with open(STATS, "w", encoding="utf-8") as f:
            json.dump(stats_state, f, indent=2)
    except PermissionError:
        pass


# ──────────────────────────────────────────────────────────────
# API ENDPOINTS
# ──────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "monitoring_api",
        "version": "2.0",
        "log_dir": str(LOG_DIR),
        "benchmark_path": BENCHMARK_RESULTS,
    }


@app.get("/stats")
def get_stats():
    """
    Live simulation statistics from red_sent.jsonl.
    
    Returns:
        - attacks: Total attack requests sent
        - mitigations: Requests blocked by Blue (HTTP 403)
        - allowed: Requests that passed through (HTTP 200)
        - block_rate: Percentage of requests blocked
        - success_rate: Percentage of requests allowed
        - false_positives: FP count from benchmark
        - total_events: Total log events
    """
    red_sent = read_jsonl(RED_SENT)
    events = read_jsonl(AI_EVENTS)

    attacks = len(red_sent)
    mitigations = sum(1 for r in red_sent if r.get("status_code") == 403)
    allowed = sum(1 for r in red_sent if r.get("status_code") == 200)
    block_rate = round(mitigations / attacks, 3) if attacks > 0 else 0.0
    success_rate = round(allowed / attacks, 3) if attacks > 0 else 0.0

    # Get false positives from benchmark data using unified metrics
    benchmark_metrics = compute_benchmark_metrics(load_benchmark_results(BENCHMARK_RESULTS))
    false_positives = benchmark_metrics.get("fp", 0) if benchmark_metrics else 0

    return JSONResponse({
        "attacks": attacks,
        "mitigations": mitigations,
        "allowed": allowed,
        "block_rate": block_rate,
        "success_rate": success_rate,
        "false_positives": false_positives,
        "total_events": len(events),
    })


@app.get("/events")
def get_events(limit: int = 100):
    """
    Get recent AI events from log.
    
    Args:
        limit: Maximum number of events to return (default: 100)
    
    Returns:
        List of most recent events
    """
    data = read_jsonl(AI_EVENTS)
    return JSONResponse(data[-limit:])


@app.get("/alerts")
def get_alerts():
    """
    Get all security alerts.
    
    Returns:
        List of all alerts from alerts.jsonl
    """
    data = read_jsonl(ALERTS)
    return JSONResponse(data)


@app.get("/benchmark")
def get_benchmark():
    """
    Full benchmark metrics from blue_benchmark_results.jsonl.
    
    Uses unified_metrics module for consistent calculation with terminal analyzer.
    
    Returns:
        Dictionary with classification metrics:
        - total_samples, tp, tn, fp, fn
        - accuracy, detection_rate, false_positive_rate
        - precision, recall, f1_score
        - latency_median_ms, latency_p95_ms
    """
    print(f"[Benchmark] Reading from: {BENCHMARK_RESULTS}")
    
    records = load_benchmark_results(BENCHMARK_RESULTS)
    print(f"[Benchmark] Loaded {len(records)} records")
    
    metrics = compute_benchmark_metrics(records)
    
    if metrics:
        print(f"[Benchmark] Metrics computed: {metrics.get('total_samples')} valid samples")
        return JSONResponse(metrics)
    else:
        print("[Benchmark] No valid data found")
        return JSONResponse({
            "error": "No benchmark data available",
            "benchmark_path": BENCHMARK_RESULTS,
            "help": "Run: docker compose run --rm benchmark"
        })


@app.get("/metrics")
def get_detailed_metrics():
    """
    Detailed metrics including decision breakdown.
    
    Returns:
        - decisions: Counter of Blue agent decisions
        - attack_outcomes: Counter of attack results (blocked/allowed/other)
        - total_attacks: Total attacks from red agent
        - total_alerts: Total security alerts
        - time_range: Earliest and latest event timestamps
    """
    events = read_jsonl(AI_EVENTS)
    alerts = read_jsonl(ALERTS)
    red_sent = read_jsonl(RED_SENT)

    # Count Blue agent decisions
    decisions = Counter()
    for e in events:
        if e.get("role") == "blue_decision":
            decision = e.get("decision") or e.get("verdict", "unknown")
            decisions[decision] += 1

    # Count attack outcomes
    attack_types = Counter()
    for r in red_sent:
        status = r.get("status_code", 0)
        if status == 403:
            attack_types["blocked"] += 1
        elif status == 200:
            attack_types["allowed"] += 1
        else:
            attack_types["other"] += 1

    # Get time range
    timestamps = [r["ts"] for r in red_sent if "ts" in r]

    return JSONResponse({
        "decisions": dict(decisions),
        "attack_outcomes": dict(attack_types),
        "total_attacks": len(red_sent),
        "total_alerts": len(alerts),
        "time_range": {
            "earliest": min(timestamps) if timestamps else None,
            "latest": max(timestamps) if timestamps else None,
        },
    })


@app.post("/internal/publish")
async def internal_publish(payload: dict = Body(...)):
    """
    Internal endpoint for publishing real-time updates to SSE subscribers.
    """
    for queue in subscribers:
        await queue.put(payload)
    return {"ok": True}


# ──────────────────────────────────────────────────────────────
# STARTUP & BACKGROUND TASKS
# ──────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    """Initialize stats on startup."""
    print("="*70)
    print("🚀 Monitoring API Starting")
    print("="*70)
    print(f"Log directory:       {LOG_DIR}")
    print(f"Benchmark path:      {BENCHMARK_RESULTS}")
    print(f"AI events:           {AI_EVENTS}")
    print(f"Alerts:              {ALERTS}")
    print(f"Red sent:            {RED_SENT}")
    print("="*70)
    
    # Update stats from existing logs
    update_stats_from_logs()
    print("✅ Initial stats loaded")


# ──────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting Monitoring API on port 9000...")
    uvicorn.run("stats_api:app", host="0.0.0.0", port=9000, reload=False)
