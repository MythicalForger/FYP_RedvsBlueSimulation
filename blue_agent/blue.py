# blue_agent/blue.py
# Blue Gatekeeper – Hybrid Rule + LLM Reasoning (Phase 3)
# Adds a modular Decision Engine combining static and semantic checks

from flask import Flask, request, jsonify
import time, json, os, requests, subprocess

# --- Configuration ---
AGENT_AI_URL = os.environ.get("AGENT_AI_URL", "http://agent_ai:8000/prompt")
USE_LLM_REASONING = os.environ.get("USE_LLM_REASONING", "false").lower() == "true"
LLM_MODEL = os.environ.get("LLM_MODEL", "gemma:2b")

# --- Log paths ---
LOG_FILE = "/app/logs/ai_events.jsonl"
ALERTS_FILE = "/app/logs/alerts.jsonl"
INTERCEPT_LOG = "/app/logs/blue_intercept.jsonl"

SUSPICIOUS_KEYWORDS = ["delete", "system32", "password", "config", "hack", "exploit"]

os.makedirs("/app/logs", exist_ok=True)
for f in [LOG_FILE, ALERTS_FILE, INTERCEPT_LOG]:
    open(f, "a").close()

app = Flask(__name__)

# ==============================================================
# -------------------- Helper Functions -------------------------
# ==============================================================

def write_jsonl(path: str, obj: dict):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, separators=(",", ":")) + "\n")


def analyze_prompt_text(text: str):
    """Rule-based keyword analysis. Returns list of reasons (empty ⇒ safe)."""
    if not text:
        return ["empty_prompt"]
    txt = text.lower()
    reasons = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in txt:
            reasons.append(f"keyword_in_prompt:{kw}")
    return reasons


def llm_reasoning_check(prompt: str) -> bool:
    """
    Uses local Gemma (via Ollama) to semantically judge the prompt.
    Returns True if safe, False if unsafe.
    """
    query = (
        "Analyze this text. If it shows intent to hack, damage systems, "
        "or steal data, respond only with 'unsafe'. Otherwise respond only with 'safe'.\n\n"
        f"Text: {prompt}"
    )
    try:
        result = subprocess.run(
            ["ollama", "run", LLM_MODEL],
            input=query.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=25,
        )
        output = result.stdout.decode("utf-8").strip().lower()
        print(f"[BLUE][LLM] Output → {output}")
        if "unsafe" in output:
            return False
        return True
    except Exception as e:
        print("[BLUE][LLM] Error:", e)
        return True  # fallback: assume safe if LLM fails


# ==============================================================
# -------------------- Decision Engine --------------------------
# ==============================================================

def decision_engine(prompt: str) -> dict:
    """
    Combines rule-based and LLM-based checks.
    Returns a decision dict: { 'safe': bool, 'reasons': [...], 'source': str }
    """
    reasons = analyze_prompt_text(prompt)

    # Static rules first
    if reasons:
        return {"safe": False, "reasons": reasons, "source": "rules"}

    # LLM-based reasoning next
    if USE_LLM_REASONING:
        safe = llm_reasoning_check(prompt)
        if not safe:
            return {"safe": False, "reasons": ["llm_flagged:unsafe_intent"], "source": "llm"}

    # Passed all checks
    return {"safe": True, "reasons": [], "source": "passed_all"}


# ==============================================================
# -------------------- Flask Route ------------------------------
# ==============================================================

@app.route("/prompt", methods=["POST"])
def intercept_prompt():
    payload = request.json or {}
    text = payload.get("text", "")
    prompt_id = payload.get("id", str(int(time.time() * 1000)))
    ts = time.time()

    # Log interception event
    intercept_event = {
        "ts": ts,
        "id": prompt_id,
        "role": "blue_intercept",
        "prompt": text,
        "meta": {"from": request.remote_addr, "llm_enabled": USE_LLM_REASONING},
    }
    write_jsonl(INTERCEPT_LOG, intercept_event)
    write_jsonl(LOG_FILE, {**intercept_event, "stage": "intercepted"})

    # --- Decision Engine Invocation ---
    decision = decision_engine(text)

    # --- Act on Decision ---
    if not decision["safe"]:
        alert = {
            "ts": time.time(),
            "id": prompt_id,
            "prompt": text,
            "reasons": decision["reasons"],
            "decision_source": decision["source"],
            "action": "blocked_by_blue",
        }
        write_jsonl(ALERTS_FILE, alert)
        write_jsonl(LOG_FILE, {**alert, "role": "blue_alert", "stage": "blocked"})
        return jsonify({"response": "Blocked by Blue Agent", **alert}), 403

    # --- Forward Safe Prompt to Agent AI ---
    try:
        forward_payload = {"text": text, "id": prompt_id}
        r = requests.post(AGENT_AI_URL, json=forward_payload, timeout=10)

        write_jsonl(LOG_FILE, {
            "ts": time.time(),
            "id": prompt_id,
            "role": "blue_forward",
            "prompt": text,
            "decision_source": decision["source"],
            "forward_to": AGENT_AI_URL,
            "status_code": r.status_code,
        })

        try:
            return jsonify(r.json()), r.status_code
        except ValueError:
            return (r.text, r.status_code, {"Content-Type": "text/plain"})

    except requests.RequestException as e:
        err = {
            "ts": time.time(),
            "id": prompt_id,
            "role": "blue_error",
            "prompt": text,
            "error": str(e),
        }
        write_jsonl(LOG_FILE, err)
        write_jsonl(ALERTS_FILE, {
            "ts": time.time(),
            "id": prompt_id,
            "prompt": text,
            "reasons": ["forward_error"],
            "error": str(e),
        })
        return jsonify({"response": "Blue failed to forward to Agent AI", "error": str(e)}), 502


# ==============================================================
# -------------------- Run Service ------------------------------
# ==============================================================

if __name__ == "__main__":
    print("[BLUE] Starting Blue Gatekeeper on :8001")
    print(f"[BLUE] LLM reasoning enabled: {USE_LLM_REASONING} (Model: {LLM_MODEL})")
    print("[BLUE] Forwarding safe prompts to:", AGENT_AI_URL)
    app.run(host="0.0.0.0", port=8001, debug=False)

