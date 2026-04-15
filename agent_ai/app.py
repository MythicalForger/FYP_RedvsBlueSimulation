from flask import Flask, request, jsonify
import time

from core import AgentCore
from logger import log_event

app = Flask(__name__)
agent = AgentCore()


@app.route("/prompt", methods=["POST"])
def prompt():
    """
    Main entrypoint called by the Blue agent.

    Contract:
    - Expects JSON: {"text": "<prompt>", "id": "<optional id>"}
    - Returns JSON: {"response": "<text>", "action": {...}}
    - Logs:
        - role = "red_request" (incoming)
        - role = "agent_response" (inside AgentCore)
    """
    payload = request.json or {}
    text = payload.get("text", "") or ""
    pid = payload.get("id", str(int(time.time() * 1000)))

    # Log incoming request in a way that monitoring & controller understand:
    # - role: "red_request" (matches existing dashboards)
    # - prompt: original input text (used for display + basic heuristics)
    log_event(
        {
            "role": "red_request",
            "id": pid,
            "prompt": text,
            "via_blue": request.headers.get("X-Via-Blue", "true"),
        }
    )

    result = agent.process_prompt(pid, text)
    # result already has the `response` field expected by Blue/benchmark
    return jsonify(result), 200


if __name__ == "__main__":
    print("[AGENT_AI] Agentic AI running on :8000")
    app.run(host="0.0.0.0", port=8000)

