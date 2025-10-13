# agent_ai/app.py
from flask import Flask, request, jsonify
import os, json, uuid
from datetime import datetime

app = Flask(__name__)

LOG_JSONL = "/app/logs/ai_events.jsonl"
OUTPUT_FILE = "/app/outputs/note.txt"

os.makedirs("/app/logs", exist_ok=True)
os.makedirs("/app/outputs", exist_ok=True)

# ----------------------------
# Logging helper (ISO 8601 timestamp only)
# ----------------------------
def write_jsonl(path: str, obj: dict):
    obj["timestamp"] = datetime.utcnow().isoformat() + "Z"
    line = json.dumps(obj, separators=(",", ":"))
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line)  # also print to stdout

@app.route("/prompt", methods=["POST"])
def prompt():
    payload = request.json or {}
    text = payload.get("text", "")
    prompt_id = payload.get("id", str(uuid.uuid4()))

    # Log that we received a request
    event = {
        "id": prompt_id,
        "role": "red_request",
        "prompt": text,
        "via_blue": request.headers.get("X-Via-Blue", "true")
    }
    write_jsonl(LOG_JSONL, {**event, "stage": "received"})

    response = ""
    action = None

    try:
        if text.startswith("search:"):
            query = text.split("search:", 1)[1].strip()
            # dummy search result (safe for sandbox)
            response = f"Dummy search result for '{query}'"
            action = {"type": "search", "query": query}
        elif text.startswith("write:"):
            content = text.split("write:", 1)[1].strip()
            with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
                out.write(content + "\n")
            response = f"Written to note.txt: {content}"
            action = {"type": "write", "content": content}
        else:
            response = "Unrecognized command."
            action = {"type": "noop"}
    except Exception as e:
        response = f"Error: {repr(e)}"
        action = {"type": "error", "error": str(e)}

    # Log the response event
    write_jsonl(LOG_JSONL, {
        "id": prompt_id,
        "role": "agent_response",
        "prompt": text,
        "response": response,
        "action": action
    })

    return jsonify({"response": response})

if __name__ == "__main__":
    # debug=False is fine in container; expose default 8000
    print("[AGENT_AI] Running on :8000")
    app.run(host="0.0.0.0", port=8000, debug=False)

