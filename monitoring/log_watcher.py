import json
import time
from pathlib import Path
import threading

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

state = {"attacks": 0, "mitigations": 0, "false_positives": 0, "total_events": 0}


def tail_file(path: Path, callback):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        print(f"[Watcher] Warning: Cannot create directory {path.parent}, using existing logs")
    
    try:
        path.touch(exist_ok=True)
    except PermissionError:
        print(f"[Watcher] Warning: Cannot create file {path}, skipping")
        return
        
    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                obj = json.loads(line.strip())
                callback(obj)
            except Exception:
                continue


def update_stats(event):
    state["total_events"] += 1

    role = event.get("role", "")
    action = event.get("action", {})

    # Attack detection - count malicious prompts from red agent
    if role == "red_request":
        prompt = event.get("prompt", "").lower()
        suspicious = ["delete", "system32", "password", "config", "hack", "exploit"]
        if any(kw in prompt for kw in suspicious):
            state["attacks"] += 1

    # Also count attacks from alerts (blocked malicious prompts)
    if event.get("action") == "blocked_by_blue":
        prompt = event.get("prompt", "").lower()
        suspicious = ["delete", "system32", "password", "config", "hack", "exploit"]
        if any(kw in prompt for kw in suspicious):
            state["attacks"] += 1

    # Mitigations - count when blue agent blocks malicious content
    if role == "blue_alert" and event.get("action") == "blocked_by_blue":
        state["mitigations"] += 1

    try:
        with open(STATS, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except PermissionError:
        print(f"[Watcher] Warning: Cannot write to {STATS}, stats not persisted")


def run_watchers():
    print("[Watcher] Watching logs...")
    threading.Thread(target=tail_file, args=(AI_EVENTS, update_stats), daemon=True).start()
    threading.Thread(target=tail_file, args=(ALERTS, update_stats), daemon=True).start()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    run_watchers()
