# blue_agent/blue.py
# Blue now acts as a gatekeeper HTTP service:
# - receives prompts from Red
# - inspects them for suspicious keywords
# - if safe, forwards the same payload to Agent AI
# - if suspicious, blocks and writes an alert (does not forward)

from flask import Flask, request, jsonify
import time, json, os, requests

# Where to forward safe prompts
AGENT_AI_URL = os.environ.get("AGENT_AI_URL", "http://agent_ai:8000/prompt")

# Shared logs (Agent AI's log file is still used for final events; Blue writes intercept events too)
LOG_FILE = "/app/logs/ai_events.jsonl"    # shared structured log from agent_ai (and Blue will append intercept events)
ALERTS_FILE = "/app/logs/alerts.jsonl"    # blue writes alerts here
INTERCEPT_LOG = "/app/logs/blue_intercept.jsonl"  # Blue-specific structured log

SUSPICIOUS_KEYWORDS = ["delete", "system32", "password", "config", "hack", "exploit"]

os.makedirs("/app/logs", exist_ok=True)
open(ALERTS_FILE, "a").close()
open(LOG_FILE, "a").close()
open(INTERCEPT_LOG, "a").close()

app = Flask(__name__)

def write_jsonl(path: str, obj: dict):
    with open(path, "a") as f:
        f.write(json.dumps(obj, separators=(",", ":")) + "\n")

def analyze_prompt_text(text: str):
    """Return list of reasons (empty => safe)."""
    if not text:
        return ["empty_prompt"]
    txt = text.lower()
    reasons = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in txt:
            reasons.append(f"keyword_in_prompt:{kw}")
    return reasons

@app.route("/prompt", methods=["POST"])
def intercept_prompt():
    payload = request.json or {}
    text = payload.get("text", "")
    prompt_id = payload.get("id", str(int(time.time() * 1000)))
    ts = time.time()

    # Log that Blue received/intercepted the prompt
    intercept_event = {
        "ts": ts,
        "id": prompt_id,
        "role": "blue_intercept",
        "prompt": text,
        "meta": {"from": request.remote_addr}
    }
    write_jsonl(INTERCEPT_LOG, intercept_event)
    # Also write a shallow event into the shared ai_events log so the full pipeline has visibility
    write_jsonl(LOG_FILE, {**intercept_event, "stage": "intercepted"})

    # analyze
    reasons = analyze_prompt_text(text)
    if reasons:
        # suspicious -> block and alert
        alert = {
            "ts": time.time(),
            "id": prompt_id,
            "prompt": text,
            "reasons": reasons,
            "action": "blocked_by_blue"
        }
        write_jsonl(ALERTS_FILE, alert)
        # also log blocked in shared log
        write_jsonl(LOG_FILE, {**alert, "role": "blue_alert", "stage": "blocked"})
        # Return 403 with explanation
        return jsonify({"response": "Blocked by Blue Agent", "reasons": reasons}), 403

    # safe -> forward to Agent AI (preserve id and text)
    try:
        forward_payload = {"text": text, "id": prompt_id}
        r = requests.post(AGENT_AI_URL, json=forward_payload, timeout=10)
        # write forwarded event
        write_jsonl(LOG_FILE, {
            "ts": time.time(),
            "id": prompt_id,
            "role": "blue_forward",
            "prompt": text,
            "forward_to": AGENT_AI_URL,
            "status_code": r.status_code
        })
        # Propagate the Agent AI's response back to Red
        try:
            return jsonify(r.json()), r.status_code
        except ValueError:
            # non-json reply from agent ai
            return (r.text, r.status_code, {"Content-Type": "text/plain"})
    except requests.RequestException as e:
        # forwarding failed -> log and return error
        err = {"ts": time.time(), "id": prompt_id, "role": "blue_error",
               "prompt": text, "error": str(e)}
        write_jsonl(LOG_FILE, err)
        write_jsonl(ALERTS_FILE, {"ts": time.time(), "id": prompt_id, "prompt": text,
                                 "reasons": ["forward_error"], "error": str(e)})
        return jsonify({"response": "Blue failed to forward to Agent AI", "error": str(e)}), 502

if __name__ == "__main__":
    print("[BLUE] Starting Blue Gatekeeper on :8001, forwarding to", AGENT_AI_URL)
    app.run(host="0.0.0.0", port=8001, debug=False)


