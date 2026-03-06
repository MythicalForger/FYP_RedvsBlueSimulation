#!/usr/bin/env python3
"""
Automated Ablation Study Benchmark
===================================
Runs Blue Agent under different ABLATION_MODE settings
and computes performance metrics automatically.

Configs:
A: structural only
B: semantic only
C: full system
"""

import json
import requests
import time
import os
import subprocess
from pathlib import Path
from typing import Dict, List


# ---------- Paths ----------
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
ATTACKS_FILE = PROJECT_ROOT / "red_agent" / "attacks.json"

BLUE_AGENT_URL = "http://localhost:8001"
OUTPUT_FILE = BASE_DIR / "ablation_results.jsonl"
SUMMARY_FILE = BASE_DIR / "ablation_summary.json"


# ---------- Benchmark ----------
class AblationBenchmark:
    def __init__(self):
        self.attacks = self.load_attacks()

    def load_attacks(self) -> List[Dict]:
        if not ATTACKS_FILE.exists():
            raise FileNotFoundError(f"attacks.json not found at {ATTACKS_FILE}")

        with open(ATTACKS_FILE, "r") as f:
            data = json.load(f)

        if isinstance(data, list):
            return data

        return data.get("attacks", [])

    # ---------- Docker Control ----------
    def restart_blue(self, mode: str):
        print(f"\n🔁 Restarting Blue Agent with ABLATION_MODE={mode}")

        env = os.environ.copy()
        env["ABLATION_MODE"] = mode

        subprocess.run(["docker", "compose", "down"], cwd=PROJECT_ROOT)
        subprocess.run(
            ["docker", "compose", "up", "-d", "--build", "blue_agent"],
            cwd=PROJECT_ROOT,
            env=env,
        )

        self.wait_for_blue()

    def wait_for_blue(self, timeout=30):
        print("⏳ Waiting for Blue Agent health check...")

        start = time.time()
        while time.time() - start < timeout:
            try:
                r = requests.get(f"{BLUE_AGENT_URL}/health", timeout=3)
                if r.status_code == 200:
                    print("✅ Blue Agent is healthy.")
                    return
            except:
                pass
            time.sleep(1)

        raise RuntimeError("Blue Agent failed to start.")

    # ---------- Benchmark Run ----------
    def run_config(self, config_name: str, mode: str) -> Dict:
        print(f"\n{'='*60}")
        print(f"Running Config {config_name}: {mode}")
        print(f"{'='*60}")

        self.restart_blue(mode)

        results = []

        for i, attack in enumerate(self.attacks):
            if i % 25 == 0:
                print(f"Progress: {i}/{len(self.attacks)}")

            try:
                start = time.time()

                response = requests.post(
                    f"{BLUE_AGENT_URL}/prompt",
                    json={"text": attack["template"], "id": f"{config_name}-{attack['id']}"},
                    timeout=15,
                )

                latency = time.time() - start
                verdict = "blocked" if response.status_code == 403 else "allowed"

                expected = attack.get("expected_outcome", "blocked")

                results.append({
                    "config": config_name,
                    "mode": mode,
                    "attack_id": attack["id"],
                    "attack_type": attack["type"],
                    "expected": expected,
                    "verdict": verdict,
                    "correct": verdict == expected,
                    "latency_s": latency
                })

            except Exception as e:
                print(f"Error on {attack['id']}: {e}")

        return results

    # ---------- Metrics ----------
    def compute_metrics(self, results: List[Dict]) -> Dict:
        tp = sum(1 for r in results if r["expected"] == "blocked" and r["verdict"] == "blocked")
        tn = sum(1 for r in results if r["expected"] == "allowed" and r["verdict"] == "allowed")
        fp = sum(1 for r in results if r["expected"] == "allowed" and r["verdict"] == "blocked")
        fn = sum(1 for r in results if r["expected"] == "blocked" and r["verdict"] == "allowed")

        total = tp + tn + fp + fn

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        latencies = [r["latency_s"] for r in results]
        latencies.sort()

        median_latency = latencies[len(latencies)//2] if latencies else 0
        p95_latency = latencies[int(len(latencies)*0.95)] if latencies else 0

        return {
            "total": total,
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall_tpr": round(recall, 4),
            "fpr": round(fpr, 4),
            "f1": round(f1, 4),
            "median_latency_ms": round(median_latency * 1000, 2),
            "p95_latency_ms": round(p95_latency * 1000, 2),
        }

    # ---------- Run All ----------
    def run(self):
        configs = [
            ("A", "structural"),
            ("B", "semantic"),
            ("C", "full"),
        ]

        summary = {}

        for name, mode in configs:
            results = self.run_config(name, mode)
            metrics = self.compute_metrics(results)
            summary[name] = {"mode": mode, "metrics": metrics}

            print("\nMetrics:")
            print(json.dumps(metrics, indent=2))

        with open(SUMMARY_FILE, "w") as f:
            json.dump(summary, f, indent=2)

        print("\n" + "="*70)
        print("ABLATION COMPLETE")
        print("="*70)

        print(f"\nSummary saved to {SUMMARY_FILE}")

        print("\nComparison Table:")
        print("-"*70)
        print(f"{'Config':<10}{'Mode':<15}{'TPR':<8}{'FPR':<8}{'F1':<8}{'Latency(ms)':<12}")
        print("-"*70)

        for name, data in summary.items():
            m = data["metrics"]
            print(f"{name:<10}{data['mode']:<15}"
                  f"{m['recall_tpr']:<8}"
                  f"{m['fpr']:<8}"
                  f"{m['f1']:<8}"
                  f"{m['median_latency_ms']:<12}")


if __name__ == "__main__":
    benchmark = AblationBenchmark()
    benchmark.run()