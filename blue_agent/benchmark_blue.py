"""
benchmark_blue.py  —  v2.0
===========================
Sends every attack template from attacks.json to the Blue agent and
records its verdict.  Runs in a timed loop so the benchmark duration
can be controlled via env var or CLI arg.

Changes from v1:
  • Records semantic_score from Blue's response (useful for threshold tuning)
  • Handles "soft_block" as a third verdict (already blocked at the gate)
  • Adds per-category breakdown by attack type
  • Cleaner verdict normalisation
"""

import os
import sys
import time
import json
import requests

BLUE_URL             = os.environ.get("BLUE_URL",         "http://localhost:8001/prompt")
OUTPUT_PATH_DEFAULT  = os.environ.get("OUTPUT_PATH",      "blue_benchmark_results.jsonl")
BENCHMARK_SECONDS_DEFAULT = int(os.environ.get("BENCHMARK_SECONDS", "150"))
ATTACKS_PATH         = os.path.join(os.path.dirname(__file__), "red_agent", "attacks.json")


# ──────────────────────────────────────────────────────────────
def load_prompts_from_attacks():
    """
    Load prompts from attacks.json.
    Entries whose `type` starts with 'benign_' → benign label.
    Everything else                            → malicious label.
    """
    with open(ATTACKS_PATH, "r", encoding="utf-8") as f:
        attacks = json.load(f)

    malicious, benign = [], []
    for entry in attacks:
        template   = entry.get("template")
        entry_type = (entry.get("type") or "").lower()
        if not template:
            continue
        if entry_type.startswith("benign_"):
            benign.append((template, entry.get("id", ""), entry.get("type", "")))
        else:
            malicious.append((template, entry.get("id", ""), entry.get("type", "")))

    return malicious, benign


def normalise_verdict(data: dict, status_code: int) -> str:
    """
    Extract a canonical verdict string from a Blue response dict.
    Returns: "blocked" | "soft_block" | "allowed"
    """
    decision = data.get("decision", "")
    if isinstance(decision, str):
        dl = decision.lower()
        if dl in ("blocked", "block"):
            return "blocked"
        if dl in ("soft_block", "soft-block", "softblock"):
            return "soft_block"
        if dl in ("allowed", "allow"):
            return "allowed"
        if "block" in dl:
            return "blocked"

    # Fall back to HTTP status code
    if status_code == 403:
        return "blocked"
    return "allowed"


# ──────────────────────────────────────────────────────────────
def run_benchmark(output_path: str = None, duration_seconds: int = None) -> None:
    results = []
    output_path      = output_path or OUTPUT_PATH_DEFAULT
    duration_seconds = int(duration_seconds or BENCHMARK_SECONDS_DEFAULT)

    malicious_prompts, benign_prompts = load_prompts_from_attacks()

    # Flatten into (label, idx, text, attack_id, attack_type)
    all_prompts = []
    for text, aid, atype in malicious_prompts:
        all_prompts.append(("malicious", text, aid, atype))
    for text, aid, atype in benign_prompts:
        all_prompts.append(("benign",    text, aid, atype))

    if not all_prompts:
        print("No prompts found in attacks.json; exiting.")
        return

    print(
        f"Benchmark running for {duration_seconds}s → {BLUE_URL}\n"
        f"Templates: {len(all_prompts)}  "
        f"({len(malicious_prompts)} malicious, {len(benign_prompts)} benign)"
    )

    start_time    = time.time()
    round_counter = 0

    while time.time() - start_time < duration_seconds:
        round_counter += 1
        for label, text, attack_id, attack_type in all_prompts:
            if time.time() - start_time >= duration_seconds:
                break

            payload   = {"text": text, "id": f"{label}-{attack_id}-r{round_counter}"}
            req_start = time.time()
            try:
                r       = requests.post(BLUE_URL, json=payload, timeout=15)
                latency = time.time() - req_start

                try:
                    data = r.json()
                except Exception:
                    data = {"raw_text": r.text}

                verdict    = normalise_verdict(data, r.status_code)
                sem_score  = data.get("semantic_score")
                operation  = data.get("operation", "")

                results.append({
                    "id":             payload["id"],
                    "label":          label,
                    "attack_id":      attack_id,
                    "attack_type":    attack_type,
                    "status_code":    r.status_code,
                    "latency_s":      latency,
                    "blue_verdict":   verdict,
                    "semantic_score": sem_score,
                    "operation":      operation,
                    "prompt":         text,
                })
                print(
                    f"{label:9s} | r{round_counter} | {r.status_code} | "
                    f"{latency*1000:6.1f}ms | {verdict:10s} | sem={sem_score} | {text[:60]!r}"
                )
            except Exception as e:
                results.append({
                    "id":          payload["id"],
                    "label":       label,
                    "attack_id":   attack_id,
                    "attack_type": attack_type,
                    "error":       str(e),
                    "prompt":      text,
                })
                print(f"{label:9s} | r{round_counter} | ERROR | {e}")

    with open(output_path, "w", encoding="utf-8") as f:
        for row in results:
            f.write(json.dumps(row) + "\n")

    print(f"\nSaved {len(results)} results → {output_path}")


# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    arg_path = sys.argv[1] if len(sys.argv) > 1 else None
    run_benchmark(arg_path)