#!/usr/bin/env python3
"""
Threshold Sensitivity Analysis
===============================
Analyzes Blue Agent performance across different semantic similarity thresholds
to identify optimal operating points.

Generates ROC-style curves and precision-recall tradeoff analysis.

Usage:
    python threshold_sensitivity.py --results blue_benchmark_results.jsonl
"""

import json
import argparse
from collections import defaultdict
import numpy as np

def load_results(filepath):
    """Load benchmark results"""
    results = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                results.append(json.loads(line))
    return results

def compute_metrics_at_threshold(results, soft_threshold, block_threshold):
    """
    Recompute verdicts at given thresholds and calculate metrics
    
    Logic:
    - If semantic_score >= block_threshold: BLOCK
    - Elif semantic_score >= soft_threshold: SOFT_BLOCK  
    - Elif structural violation: BLOCK
    - Else: ALLOW
    """
    tp = tn = fp = fn = 0
    
    for r in results:
        label = r.get('label', 'malicious')
        
        # Recompute verdict based on new thresholds
        sem_score = r.get('semantic_score')
        operation = r.get('operation', '')
        
        # Structural violations (these are always blocked regardless of semantic score)
        structural_block = any([
            'secret_read' in operation,
            'authority_escalation' in operation,
            'policy_modification' in operation,
            'persistent_memory_write' in operation,
            'tool_execution' in operation,
            'configuration_change' in operation,
            'privileged_access' in operation
        ])
        
        # Determine verdict at this threshold
        if structural_block:
            predicted_blocked = True
        elif sem_score is not None:
            if sem_score >= block_threshold:
                predicted_blocked = True
            elif sem_score >= soft_threshold:
                predicted_blocked = True  # Treat soft_block as blocked for metrics
            else:
                predicted_blocked = False
        else:
            # No semantic score means it was allowed structurally
            predicted_blocked = False
        
        # Update confusion matrix
        if label == 'malicious':
            if predicted_blocked:
                tp += 1
            else:
                fn += 1
        else:  # benign
            if predicted_blocked:
                fp += 1
            else:
                tn += 1
    
    # Calculate metrics
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) > 0 else 0
    
    return {
        'soft_threshold': soft_threshold,
        'block_threshold': block_threshold,
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'accuracy': round(accuracy, 4),
        'tpr': round(tpr, 4),
        'fpr': round(fpr, 4),
        'precision': round(precision, 4),
        'f1': round(f1, 4)
    }

def threshold_sweep(results):
    """Sweep through threshold values"""
    # Test thresholds
    thresholds = np.arange(0.25, 0.70, 0.05)
    
    sweep_results = []
    
    print(f"\n{'Soft':<8} {'Block':<8} {'TPR':<8} {'FPR':<8} {'Prec':<8} {'F1':<8} {'Acc':<8}")
    print("-" * 64)
    
    for soft_t in thresholds:
        for block_t in thresholds:
            if block_t <= soft_t:
                continue  # Block threshold must be higher than soft
            
            metrics = compute_metrics_at_threshold(results, soft_t, block_t)
            sweep_results.append(metrics)
            
            print(f"{soft_t:<8.2f} {block_t:<8.2f} "
                  f"{metrics['tpr']:<8.3f} {metrics['fpr']:<8.3f} "
                  f"{metrics['precision']:<8.3f} {metrics['f1']:<8.3f} "
                  f"{metrics['accuracy']:<8.3f}")
    
    return sweep_results

def find_optimal_threshold(sweep_results, criterion='f1'):
    """Find optimal threshold based on criterion"""
    best = max(sweep_results, key=lambda x: x[criterion])
    return best

def generate_roc_data(sweep_results):
    """Generate data for ROC curve plotting"""
    # Group by unique (soft, block) pairs and sort by FPR
    roc_points = sorted(sweep_results, key=lambda x: x['fpr'])
    
    print("\n\nROC Curve Data (FPR vs TPR):")
    print(f"{'FPR':<10} {'TPR':<10} {'Soft':<10} {'Block':<10}")
    print("-" * 40)
    
    for point in roc_points[::3]:  # Print every 3rd point to avoid clutter
        print(f"{point['fpr']:<10.3f} {point['tpr']:<10.3f} "
              f"{point['soft_threshold']:<10.2f} {point['block_threshold']:<10.2f}")
    
    return roc_points

def generate_pr_curve_data(sweep_results):
    """Generate precision-recall curve data"""
    pr_points = sorted(sweep_results, key=lambda x: x['tpr'])
    
    print("\n\nPrecision-Recall Curve Data:")
    print(f"{'Recall':<10} {'Precision':<10} {'Soft':<10} {'Block':<10}")
    print("-" * 40)
    
    for point in pr_points[::3]:
        print(f"{point['tpr']:<10.3f} {point['precision']:<10.3f} "
              f"{point['soft_threshold']:<10.2f} {point['block_threshold']:<10.2f}")
    
    return pr_points

def main():
    parser = argparse.ArgumentParser(description='Threshold sensitivity analysis')
    parser.add_argument('--results', required=True, help='Path to benchmark results JSONL')
    parser.add_argument('--output', default='threshold_analysis.json', help='Output file')
    
    args = parser.parse_args()
    
    print("Loading results...")
    results = load_results(args.results)
    print(f"Loaded {len(results)} samples")
    
    print("\n" + "="*60)
    print("THRESHOLD SENSITIVITY ANALYSIS")
    print("="*60)
    
    # Perform threshold sweep
    sweep_results = threshold_sweep(results)
    
    # Find optimal thresholds
    print("\n\nOPTIMAL THRESHOLDS:")
    print("-" * 60)
    
    for criterion in ['f1', 'accuracy', 'tpr']:
        optimal = find_optimal_threshold(sweep_results, criterion)
        print(f"\nBest {criterion.upper()}:")
        print(f"  Soft threshold:  {optimal['soft_threshold']:.2f}")
        print(f"  Block threshold: {optimal['block_threshold']:.2f}")
        print(f"  TPR: {optimal['tpr']:.3f}, FPR: {optimal['fpr']:.3f}")
        print(f"  Precision: {optimal['precision']:.3f}, F1: {optimal['f1']:.3f}")
    
    # Generate curve data for plotting
    roc_data = generate_roc_data(sweep_results)
    pr_data = generate_pr_curve_data(sweep_results)
    
    # Save results
    output = {
        'sweep_results': sweep_results,
        'roc_data': roc_data,
        'pr_data': pr_data,
        'optimal_f1': find_optimal_threshold(sweep_results, 'f1'),
        'optimal_accuracy': find_optimal_threshold(sweep_results, 'accuracy'),
        'optimal_tpr': find_optimal_threshold(sweep_results, 'tpr')
    }
    
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n\nResults saved to {args.output}")
    print("\nTo plot ROC curve:")
    print("  Use 'fpr' and 'tpr' columns from roc_data")
    print("\nTo plot PR curve:")
    print("  Use 'tpr' (recall) and 'precision' columns from pr_data")

if __name__ == "__main__":
    main()