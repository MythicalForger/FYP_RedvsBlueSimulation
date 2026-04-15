#!/usr/bin/env python3
"""
Analyze Blue Benchmark Results
===============================
Reads blue_benchmark_results.jsonl and computes classification metrics.

Usage:
    python analyze_blue_benchmark.py [path_to_results.jsonl]
    
Environment variables:
    BENCHMARK_PATH: Path to benchmark results file (default: blue_benchmark_results.jsonl)
"""

import json
from collections import Counter
import os
import sys

# Import unified metrics module for consistent calculations
from unified_metrics import compute_benchmark_metrics, load_benchmark_results, print_metrics

# Default path can be overridden by env BENCHMARK_PATH or CLI arg
PATH = os.environ.get("BENCHMARK_PATH", "blue_benchmark_results.jsonl")
if len(sys.argv) > 1:
    PATH = sys.argv[1]


def summarize_by_category(records):
    """
    Show breakdown of decisions per label (malicious/benign).
    """
    counts = Counter()
    for row in records:
        label = row.get("label")
        verdict = row.get("blue_verdict")
        key = (label, verdict)
        counts[key] += 1

    print("\n" + "="*70)
    print("DECISION BREAKDOWN BY LABEL")
    print("="*70)
    print(f"{'Label':<12} | {'Verdict':<20} | {'Count':>6}")
    print("-"*70)
    for (label, verdict), c in sorted(counts.items()):
        label_str = str(label) if label else "unknown"
        verdict_str = str(verdict) if verdict else "N/A"
        print(f"{label_str:<12} | {verdict_str:<20} | {c:>6}")


def main():
    """Main execution flow."""
    print("="*70)
    print("BLUE AGENT BENCHMARK ANALYSIS")
    print("="*70)
    print(f"Reading from: {PATH}")
    print()
    
    # Load results
    try:
        records = load_benchmark_results(PATH)
    except FileNotFoundError:
        print(f"❌ ERROR: File not found: {PATH}")
        print("\nMake sure you've run the benchmark first:")
        print("  docker compose run --rm benchmark")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERROR: Failed to load results: {e}")
        sys.exit(1)
    
    if not records:
        print("❌ No records found in file")
        sys.exit(1)
    
    print(f"✅ Loaded {len(records)} total records")
    
    # Show decision breakdown
    summarize_by_category(records)
    
    # Compute and display metrics
    print("\n" + "="*70)
    print("CLASSIFICATION METRICS")
    print("="*70)
    
    metrics = compute_benchmark_metrics(records)
    
    if metrics:
        print_metrics(metrics)
        print("\n" + "="*70)
        print("✅ Analysis complete!")
        print("="*70)
    else:
        print("❌ Could not compute metrics - no valid data found")
        print("\nPossible reasons:")
        print("  - All records have errors")
        print("  - No records with 'malicious' or 'benign' labels")
        print("  - File is corrupted")
        sys.exit(1)


if __name__ == "__main__":
    main()
