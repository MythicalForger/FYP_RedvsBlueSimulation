# agent_ai/app.py
from flask import Flask, request, jsonify
import os, json, time, uuid

app = Flask(__name__)

LOG_JSONL = "/app/logs/ai_events.jsonl"
OUTPUT_FILE = "/app/outputs/note.txt"

os.makedirs("/app/logs", exist_ok=True)
os.makedirs("/app/outputs", exist_ok=True)

def write_event(event: dict):
    # Append a single JSON object as a line (JSONL). This is atomic enough for our use.
    with open(LOG_JSONL, "a") as f:
        f.write(json.dumps(event, separators=(",", ":")) + "\n")

@app.route("/prompt", methods=["POST"])
def prompt():
    payload = request.json or {}
    text = payload.get("text", "")
    prompt_id = payload.get("id", str(uuid.uuid4()))
    ts = time.time()

    # Log that we received a request (role kept as red_request for compatibility)
    event = {
        "ts": ts,
        "id": prompt_id,
        "role": "red_request",
        "prompt": text,
        # record whether it came via Blue (optional header)
        "via_blue": request.headers.get("X-Via-Blue", "true")
    }
    write_event({**event, "stage": "received"})

    response = ""
    action = None

    try:
        if text.startswith("search:"):
            query = text.split("search:", 1)[1].strip()
            # dummy search result (safe for sandbox). Replace with DuckDuckGo / Tavily later.
            response = f"Dummy search result for '{query}'"
            action = {"type": "search", "query": query}
        elif text.startswith("write:"):
            content = text.split("write:", 1)[1].strip()
            with open(OUTPUT_FILE, "a") as out:
                out.write(content + "\n")
            response = f"Written to note.txt: {content}"
            action = {"type": "write", "content": content}
        else:
            response = "Unrecognized command."
            action = {"type": "noop"}
    except Exception as e:
        response = f"Error: {repr(e)}"
        action = {"type": "error", "error": str(e)}

    # Log the response event (structured)
    write_event({
        "ts": time.time(),
        "id": prompt_id,
        "role": "agent_response",
        "prompt": text,
        "response": response,
        "action": action
    })

    return jsonify({"response": response})

if __name__ == "__main__":
    # debug=False is fine in container; expose default 8000
    app.run(host="0.0.0.0", port=8000, debug=False)
