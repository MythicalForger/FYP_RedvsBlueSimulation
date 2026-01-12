from pathlib import Path
import json
from typing import List

# Use Docker container paths when running inside container
if Path("/app").exists():
    # Running inside Docker container
    LOG_DIR = Path("/app/logs")
else:
    # Running locally
    ROOT = Path(__file__).resolve().parents[1]
    LOG_DIR = ROOT / "logs"

ACTIVE_LOGS = {
    "events": LOG_DIR / "ai_events.jsonl",
    "alerts": LOG_DIR / "alerts.jsonl",
    "red": LOG_DIR / "red_sent.jsonl",
}

def read_jsonl(path: Path) -> List[dict]:
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
            except:
                continue
    return rows

def active_log_status():
    status = {}
    for name, path in ACTIVE_LOGS.items():
        if path.exists():
            status[name] = {
                "path": str(path),
                "updated": path.stat().st_mtime,
                "size_kb": round(path.stat().st_size / 1024, 2),
            }
        else:
            status[name] = None
    return status
