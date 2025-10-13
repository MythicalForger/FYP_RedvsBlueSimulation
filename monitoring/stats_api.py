from fastapi import FastAPI, Request, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio, json
from pathlib import Path
import uvicorn
import threading
import time

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


def update_stats_from_logs():
    """Update stats by reading all existing logs."""
    global stats_state
    
    events = read_jsonl(AI_EVENTS)
    alerts = read_jsonl(ALERTS)
    
    # Reset stats
    stats_state = {"attacks": 0, "mitigations": 0, "false_positives": 0, "total_events": 0}
    
    # Count attacks from events
    for e in events:
        stats_state["total_events"] += 1
        if e.get("role") == "red_request":
            prompt = e.get("prompt", "").lower()
            suspicious = ["delete", "system32", "password", "config", "hack", "exploit"]
            if any(kw in prompt for kw in suspicious):
                stats_state["attacks"] += 1
    
    # Count attacks from alerts
    for a in alerts:
        if a.get("action") == "blocked_by_blue":
            prompt = a.get("prompt", "").lower()
            suspicious = ["delete", "system32", "password", "config", "hack", "exploit"]
            if any(kw in prompt for kw in suspicious):
                stats_state["attacks"] += 1
            stats_state["mitigations"] += 1
    
    # Save stats
    try:
        with open(STATS, "w", encoding="utf-8") as f:
            json.dump(stats_state, f, indent=2)
    except PermissionError:
        pass


def read_jsonl(path: Path):
    items = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        items.append(json.loads(line))
                    except:
                        continue
    except FileNotFoundError:
        pass
    return items


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


@app.post("/internal/publish")
async def internal_publish(payload: dict = Body(...)):
    """Internal endpoint used by log_watcher to push events."""
    for queue in subscribers:
        await queue.put(payload)
    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run("stats_api:app", host="0.0.0.0", port=9000)
