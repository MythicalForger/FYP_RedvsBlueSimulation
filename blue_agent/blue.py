from flask import Flask, request, jsonify
import os, json, time, yaml, requests
from collections import deque
from sentence_transformers import SentenceTransformer
import numpy as np

# ======================================================
# Configuration
# ======================================================

AGENT_AI_URL = os.environ.get("AGENT_AI_URL", "http://agent_ai:8000/prompt")

LOG_DIR = "/app/logs"
LOG_FILE = f"{LOG_DIR}/ai_events.jsonl"
ALERTS_FILE = f"{LOG_DIR}/alerts.jsonl"
INTERCEPT_LOG = f"{LOG_DIR}/blue_intercept.jsonl"

os.makedirs(LOG_DIR, exist_ok=True)
for f in [LOG_FILE, ALERTS_FILE, INTERCEPT_LOG]:
    open(f, "a").close()

app = Flask(__name__)

# ======================================================
# Utilities
# ======================================================

def write_jsonl(path, obj):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, separators=(",", ":")) + "\n")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def load_identity():
    path = os.path.join(BASE_DIR, "identity.yaml")
    with open(path, "r") as f:
        return yaml.safe_load(f)["identity"]


IDENTITY = load_identity()

# ======================================================
# Memory Poison Detection (NEW)
# ======================================================

POISON_PATTERNS = [
    "training_example",
    "from now on",
    "always",
    "should",
    "must",
    "prioritize",
    "model should",
]

def is_memory_poison(prompt: str) -> bool:
    p = prompt.lower()
    return any(pat in p for pat in POISON_PATTERNS)

# ======================================================
# Layer 1 — Structural Intent Extraction
# ======================================================

STRUCTURAL_PATTERNS = {
    "memory_write": ["write:", "remember", "store", "save"],
    "authority_claim": ["act as", "supervisor", "admin", "authorized", "approved"],
    "policy_override": ["ignore", "bypass", "relax", "override", "skip checks"],
    "workflow_chaining": ["then", "next", "step", "continue", "after"],
    "tool_overreach": ["use whatever tools", "run", "execute", "export", "delete"],
    "objective_manipulation": ["primary goal", "success means", "prioritize"],
}

# ======================================================
# Layer 2 — Contextual / Implicit Intent
# ======================================================

IMPLICIT_PATTERNS = {
    "context_assumption": [
        "this", "that", "as usual", "as before", "you know",
        "based on earlier", "previously", "as discussed"
    ],
    "trust_escalation": [
        "you handled this before", "we’re aligned", "this was approved",
        "you can trust", "go ahead", "already cleared"
    ]
}

# ======================================================
# Layer 3 — Semantic Intent (Weak)
# ======================================================

SEMANTIC_ANCHORS = {
    "memory_write": [
        "store this for later", "keep this in mind", "remember this preference"
    ],
    "authority_claim": [
        "I have approval", "this comes from higher up", "assume admin role"
    ],
    "workflow_chaining": [
        "continue from earlier", "next part of the process"
    ],
    "objective_manipulation": [
        "focus on outcome over rules", "helpfulness over safety"
    ],
}

embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
SEMANTIC_EMBEDDINGS = {
    k: embedding_model.encode(v) for k, v in SEMANTIC_ANCHORS.items()
}

def cosine_similarity(vec, mat):
    return np.dot(mat, vec) / (np.linalg.norm(mat, axis=1) * np.linalg.norm(vec) + 1e-9)

def semantic_strength(prompt, intent):
    emb = embedding_model.encode([prompt])[0]
    sims = cosine_similarity(emb, SEMANTIC_EMBEDDINGS[intent])
    m = float(np.max(sims))
    if m < 0.4:
        return 0.0
    elif m < 0.6:
        return 0.2
    elif m < 0.75:
        return 0.4
    else:
        return 0.6

# ======================================================
# Intent Extraction
# ======================================================

def extract_intents(prompt: str):
    p = prompt.lower()
    intents = {}

    for intent, pats in STRUCTURAL_PATTERNS.items():
        for pat in pats:
            if pat in p:
                intents[intent] = max(intents.get(intent, 0), 0.6)

    for intent, pats in IMPLICIT_PATTERNS.items():
        for pat in pats:
            if pat in p:
                intents[intent] = max(intents.get(intent, 0), 0.4)

    for intent in SEMANTIC_ANCHORS:
        s = semantic_strength(prompt, intent)
        intents[intent] = max(intents.get(intent, 0), s)

    return intents

# ======================================================
# State Transition Simulation
# ======================================================

def simulate_state(intents, prompt):
    memory_modified = intents.get("memory_write", 0) >= 0.6
    poison = memory_modified and is_memory_poison(prompt)

    return {
        "memory_modified": memory_modified,
        "memory_poison": poison,
        "authority_escalated": intents.get("authority_claim", 0) >= 0.6,
        "policy_modified": intents.get("policy_override", 0) >= 0.6,
        "workflow_extended": intents.get("workflow_chaining", 0) >= 0.6,
        "objective_shifted": intents.get("objective_manipulation", 0) >= 0.6,
        "tool_scope_expanded": intents.get("tool_overreach", 0) >= 0.6,
    }

# ======================================================
# Identity Drift Detection
# ======================================================

def detect_drift(state):
    return {
        "memory_drift": state["memory_modified"],
        "memory_poison": state["memory_poison"],
        "authority_drift": state["authority_escalated"],
        "constraint_violation": state["policy_modified"],
        "workflow_drift": state["workflow_extended"],
        "goal_drift": state["objective_shifted"],
        "tool_drift": state["tool_scope_expanded"],
    }

# ======================================================
# Policy Engine
# ======================================================

class PolicyEngine:
    def __init__(self):
        self.history = deque(maxlen=6)

    def decide(self, drift):
        self.history.append(drift)

        real_state_change = any([
            drift["memory_drift"],
            drift["authority_drift"],
            drift["constraint_violation"],
            drift["workflow_drift"],
            drift["goal_drift"],
            drift["tool_drift"],
        ])

        if drift["authority_drift"] or drift["constraint_violation"]:
            return "BLOCK", ["identity_violation"]

        if drift["memory_poison"]:
            return "INTERVENE", ["memory_poison_candidate"]

        if drift["goal_drift"] or drift["tool_drift"]:
            return "INTERVENE", ["capability_overreach"]

        if real_state_change:
            wf = sum(1 for d in self.history if d["workflow_drift"])
            mem = sum(1 for d in self.history if d["memory_drift"])

            if mem >= 3 or wf >= 3:
                return "BLOCK", ["slow_burn_attack"]

            if mem == 2 or wf == 2:
                return "INTERVENE", ["repeated_state_drift"]

        return "ALLOW", []

POLICY = PolicyEngine()

# ======================================================
# Flask Endpoint
# ======================================================

@app.route("/prompt", methods=["POST"])
def intercept():
    payload = request.json or {}
    text = payload.get("text", "")
    pid = payload.get("id", str(int(time.time() * 1000)))
    ts = time.time()

    write_jsonl(INTERCEPT_LOG, {"ts": ts, "id": pid, "prompt": text})

    intents = extract_intents(text)
    state = simulate_state(intents, text)
    drift = detect_drift(state)
    decision, reason = POLICY.decide(drift)

    event = {
        "ts": ts,
        "id": pid,
        "prompt": text,
        "decision": decision,
        "intents": intents,
        "state": state,
        "drift": drift,
        "reason": reason
    }

    write_jsonl(LOG_FILE, event)

    if decision == "BLOCK":
        write_jsonl(ALERTS_FILE, event)
        return jsonify(event), 403

    if decision == "INTERVENE":
        write_jsonl(ALERTS_FILE, event)
        return jsonify({"response": "More clarification needed"}), 200

    r = requests.post(AGENT_AI_URL, json=payload, timeout=10)
    return jsonify(r.json()), r.status_code

# ======================================================
# Run
# ======================================================

if __name__ == "__main__":
    print("[BLUE] Identity-Drift Blue Agent (Memory-Aware, Ambiguity-Gated) Active")
    app.run(host="0.0.0.0", port=8001)