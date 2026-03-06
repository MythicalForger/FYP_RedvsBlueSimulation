# agent_ai/logger.py

import json
import time
import os

LOG_DIR = "/app/logs"
EVENT_LOG = os.path.join(LOG_DIR, "ai_events.jsonl")

os.makedirs(LOG_DIR, exist_ok=True)
open(EVENT_LOG, "a").close()


def log_event(event: dict):
    event["ts"] = event.get("ts", time.time())
    with open(EVENT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
