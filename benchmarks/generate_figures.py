#!/usr/bin/env python3
"""
Generate Publication-Quality Figures for Journal Paper
=======================================================
Creates all figures needed for the Results section.

Figures generated:
1. ROC Curve (FPR vs TPR)
2. Precision-Recall Curve
3. Detection Rate by Attack Category (bar chart)
4. Detection Rate Over Co-Evolution Cycles (line plot)
5. Weight Entropy Over Cycles (line plot)
6. Latency Distribution (histogram)
7. Semantic Score Distribution (malicious vs benign)
8. Confusion Matrix Heatmap

Requirements:
    pip install matplotlib seaborn numpy pandas

Usage:
    python generate_figures.py --results blue_benchmark_results.jsonl
"""

import json
import argparse
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from collections import defaultdict
import os

# Set publication-quality style
plt.style.use('seaborn-v0_8-paper')
sns.set_palette("colorblind")

def load_jsonl(filepath):
    """Load JSONL file"""
    data = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    return data

def figure1_roc_curve(threshold_data, output_dir):
    """Generate ROC curve"""
    roc_data = threshold_data.get('roc_data', [])
    
    fprs = [p['fpr'] for p in roc_data]
    tprs = [p['tpr'] for p in roc_data]
    
    plt.figure(figsize=(8, 6))
    plt.plot(fprs, tprs, 'b-', linewidth=2.5, label='Blue Agent')
    plt.plot([0, 1], [0, 1], 'k--', linewidth=1, alpha=0.5, label='Random Classifier')
    
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate (Recall)', fontsize=12)
    plt.title('Blue Agent ROC Curve', fontsize=14, fontweight='bold')
    plt.grid(True, alpha=0.3)
    plt.legend(loc='lower right', fontsize=11)
    plt.xlim([-0.05, 1.05])
    plt.ylim([-0.05, 1.05])
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig1_roc_curve.png'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'fig1_roc_curve.pdf'), bbox_inches='tight')
    print("✓ Figure 1: ROC Curve saved")
    plt.close()

def figure2_pr_curve(threshold_data, output_dir):
    """Generate Precision-Recall curve"""
    pr_data = threshold_data.get('pr_data', [])
    
    recalls = [p['tpr'] for p in pr_data]  # TPR = Recall
    precisions = [p['precision'] for p in pr_data]
    
    plt.figure(figsize=(8, 6))
    plt.plot(recalls, precisions, 'g-', linewidth=2.5, label='Blue Agent')
    
    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title('Precision-Recall Curve', fontsize=14, fontweight='bold')
    plt.grid(True, alpha=0.3)
    plt.legend(loc='upper right', fontsize=11)
    plt.xlim([-0.05, 1.05])
    plt.ylim([-0.05, 1.05])
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig2_pr_curve.png'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'fig2_pr_curve.pdf'), bbox_inches='tight')
    print("✓ Figure 2: Precision-Recall Curve saved")
    plt.close()

def figure3_detection_by_category(category_data, output_dir):
    """Bar chart of detection rate by attack category"""
    
    # Sort by TPR
    sorted_data = sorted(category_data, key=lambda x: x['tpr'], reverse=True)[:15]
    
    categories = [d['attack_type'].replace('_', ' ').title()[:25] for d in sorted_data]
    tprs = [d['tpr'] * 100 for d in sorted_data]  # Convert to percentage
    
    # Color-code by performance level
    colors = ['darkgreen' if t >= 90 else 'orange' if t >= 75 else 'red' for t in tprs]
    
    plt.figure(figsize=(12, 6))
    bars = plt.barh(range(len(categories)), tprs, color=colors, alpha=0.7)
    
    plt.yticks(range(len(categories)), categories, fontsize=10)
    plt.xlabel('Detection Rate (%)', fontsize=12)
    plt.title('Detection Performance by Attack Category (Top 15)', fontsize=14, fontweight='bold')
    plt.xlim([0, 105])
    plt.grid(True, axis='x', alpha=0.3)
    
    # Add value labels
    for i, (bar, val) in enumerate(zip(bars, tprs)):
        plt.text(val + 1, i, f'{val:.1f}%', va='center', fontsize=9)
    
    # Add legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='darkgreen', alpha=0.7, label='High (≥90%)'),
        Patch(facecolor='orange', alpha=0.7, label='Medium (75-90%)'),
        Patch(facecolor='red', alpha=0.7, label='Low (<75%)')
    ]
    plt.legend(handles=legend_elements, loc='lower right', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig3_detection_by_category.png'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'fig3_detection_by_category.pdf'), bbox_inches='tight')
    print("✓ Figure 3: Detection by Category saved")
    plt.close()

def figure4_coevolution_detection(coevolution_summary, output_dir):
    """Line plot of detection rate over co-evolution cycles"""
    
    progression = coevolution_summary.get('detection_rate_progression', [])
    
    if not progression:
        print("⚠ Figure 4: No co-evolution data available (run coevolution_tracker.py first)")
        return
    
    cycles = [p['cycle'] for p in progression]
    tprs = [p['tpr'] * 100 for p in progression]  # Convert to percentage
    
    plt.figure(figsize=(10, 6))
    plt.plot(cycles, tprs, 'b-o', linewidth=2.5, markersize=8, label='Detection Rate')
    
    # Add horizontal line at initial TPR
    plt.axhline(y=tprs[0], color='gray', linestyle='--', alpha=0.5, label='Initial Performance')
    
    plt.xlabel('Training Cycle', fontsize=12)
    plt.ylabel('Detection Rate (%)', fontsize=12)
    plt.title('Blue Agent Detection Rate Over Red-Blue Co-Evolution', fontsize=14, fontweight='bold')
    plt.grid(True, alpha=0.3)
    plt.legend(loc='best', fontsize=11)
    plt.ylim([min(tprs) - 5, max(tprs) + 5])
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig4_coevolution_detection.png'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'fig4_coevolution_detection.pdf'), bbox_inches='tight')
    print("✓ Figure 4: Co-Evolution Detection Rate saved")
    plt.close()

def figure5_weight_entropy(coevolution_summary, output_dir):
    """Line plot of weight entropy over cycles"""
    
    progression = coevolution_summary.get('weight_entropy_progression', [])
    
    if not progression:
        print("⚠ Figure 5: No weight entropy data available")
        return
    
    cycles = [p['cycle'] for p in progression]
    entropies = [p['entropy'] for p in progression]
    
    plt.figure(figsize=(10, 6))
    plt.plot(cycles, entropies, 'g-s', linewidth=2.5, markersize=8, label='Weight Entropy')
    
    plt.xlabel('Training Cycle', fontsize=12)
    plt.ylabel('Weight Entropy (bits)', fontsize=12)
    plt.title('Attack Weight Distribution Entropy Over Co-Evolution', fontsize=14, fontweight='bold')
    plt.grid(True, alpha=0.3)
    plt.legend(loc='best', fontsize=11)
    
    # Add annotation
    plt.text(0.5, 0.95, 'Higher entropy = More diverse attack sampling',
             transform=plt.gca().transAxes, fontsize=10, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig5_weight_entropy.png'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'fig5_weight_entropy.pdf'), bbox_inches='tight')
    print("✓ Figure 5: Weight Entropy saved")
    plt.close()

def figure6_latency_distribution(results, output_dir):
    """Histogram of latency distribution"""
    
    latencies = [r['latency_s'] * 1000 for r in results if 'latency_s' in r]  # Convert to ms
    
    plt.figure(figsize=(10, 6))
    plt.hist(latencies, bins=50, color='steelblue', alpha=0.7, edgecolor='black')
    
    # Add vertical lines for median and p95
    median = np.median(latencies)
    p95 = np.percentile(latencies, 95)
    
    plt.axvline(median, color='red', linestyle='--', linewidth=2, label=f'Median: {median:.1f} ms')
    plt.axvline(p95, color='orange', linestyle='--', linewidth=2, label=f'P95: {p95:.1f} ms')
    
    plt.xlabel('Latency (ms)', fontsize=12)
    plt.ylabel('Frequency', fontsize=12)
    plt.title('Blue Agent Response Latency Distribution', fontsize=14, fontweight='bold')
    plt.legend(loc='upper right', fontsize=11)
    plt.grid(True, axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig6_latency_distribution.png'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'fig6_latency_distribution.pdf'), bbox_inches='tight')
    print("✓ Figure 6: Latency Distribution saved")
    plt.close()

def figure7_semantic_scores(results, output_dir):
    """Distribution of semantic scores for malicious vs benign"""
    
    malicious_scores = [r['semantic_score'] for r in results 
                       if r.get('label') == 'malicious' and r.get('semantic_score') is not None]
    benign_scores = [r['semantic_score'] for r in results 
                    if r.get('label') == 'benign' and r.get('semantic_score') is not None]
    
    plt.figure(figsize=(10, 6))
    
    plt.hist(malicious_scores, bins=30, color='red', alpha=0.5, label='Malicious', edgecolor='black')
    plt.hist(benign_scores, bins=15, color='green', alpha=0.5, label='Benign', edgecolor='black')
    
    # Add threshold lines
    plt.axvline(0.55, color='darkred', linestyle='--', linewidth=2, label='Block Threshold (0.55)')
    plt.axvline(0.38, color='orange', linestyle='--', linewidth=2, label='Soft Block Threshold (0.38)')
    
    plt.xlabel('Semantic Similarity Score', fontsize=12)
    plt.ylabel('Frequency', fontsize=12)
    plt.title('Semantic Score Distribution: Malicious vs Benign', fontsize=14, fontweight='bold')
    plt.legend(loc='upper right', fontsize=11)
    plt.grid(True, axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig7_semantic_scores.png'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'fig7_semantic_scores.pdf'), bbox_inches='tight')
    print("✓ Figure 7: Semantic Score Distribution saved")
    plt.close()

def figure8_confusion_matrix(results, output_dir):
    """Confusion matrix heatmap"""
    
    # Compute confusion matrix
    tp = sum(1 for r in results if r.get('label') == 'malicious' and r.get('blue_verdict') in ['blocked', 'soft_block'])
    fn = sum(1 for r in results if r.get('label') == 'malicious' and r.get('blue_verdict') == 'allowed')
    fp = sum(1 for r in results if r.get('label') == 'benign' and r.get('blue_verdict') in ['blocked', 'soft_block'])
    tn = sum(1 for r in results if r.get('label') == 'benign' and r.get('blue_verdict') == 'allowed')
    
    cm = np.array([[tp, fn], [fp, tn]])
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=True,
                xticklabels=['Predicted: Malicious', 'Predicted: Benign'],
                yticklabels=['Actual: Malicious', 'Actual: Benign'],
                annot_kws={'fontsize': 16, 'fontweight': 'bold'})
    
    plt.title('Confusion Matrix', fontsize=14, fontweight='bold')
    plt.ylabel('True Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig8_confusion_matrix.png'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'fig8_confusion_matrix.pdf'), bbox_inches='tight')
    print("✓ Figure 8: Confusion Matrix saved")
    plt.close()

def main():
    parser = argparse.ArgumentParser(description='Generate publication figures')
    parser.add_argument('--results', required=True, help='Path to blue_benchmark_results.jsonl')
    parser.add_argument('--threshold-data', default='threshold_analysis.json', help='Threshold analysis JSON')
    parser.add_argument('--category-data', default='category_analysis.json', help='Category analysis JSON')
    parser.add_argument('--coevolution-data', default='coevolution_data/evolution_summary.json', help='Co-evolution summary JSON')
    parser.add_argument('--output-dir', default='figures', help='Output directory for figures')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    print("\n" + "="*60)
    print("GENERATING PUBLICATION-QUALITY FIGURES")
    print("="*60 + "\n")
    
    # Load data
    print("Loading data...")
    results = load_jsonl(args.results)
    print(f"  Loaded {len(results)} benchmark results")
    
    # Load threshold data if available
    threshold_data = {}
    if os.path.exists(args.threshold_data):
        with open(args.threshold_data, 'r') as f:
            threshold_data = json.load(f)
        print(f"  Loaded threshold analysis data")
    
    # Load category data if available
    category_data = []
    if os.path.exists(args.category_data):
        with open(args.category_data, 'r') as f:
            data = json.load(f)
            category_data = data.get('category_stats', [])
        print(f"  Loaded category analysis data")
    
    # Load co-evolution data if available
    coevolution_summary = {}
    if os.path.exists(args.coevolution_data):
        with open(args.coevolution_data, 'r') as f:
            coevolution_summary = json.load(f)
        print(f"  Loaded co-evolution data")
    
    print("\nGenerating figures...\n")
    
    # Generate all figures
    if threshold_data:
        figure1_roc_curve(threshold_data, args.output_dir)
        figure2_pr_curve(threshold_data, args.output_dir)
    else:
        print("⚠ Skipping Figures 1-2: Run threshold_sensitivity.py first")
    
    if category_data:
        figure3_detection_by_category(category_data, args.output_dir)
    else:
        print("⚠ Skipping Figure 3: Run attack_category_analysis.py first")
    
    if coevolution_summary:
        figure4_coevolution_detection(coevolution_summary, args.output_dir)
        figure5_weight_entropy(coevolution_summary, args.output_dir)
    else:
        print("⚠ Skipping Figures 4-5: Run coevolution_tracker.py first")
    
    figure6_latency_distribution(results, args.output_dir)
    figure7_semantic_scores(results, args.output_dir)
    figure8_confusion_matrix(results, args.output_dir)
    
    print("\n" + "="*60)
    print(f"ALL FIGURES SAVED TO: {args.output_dir}/")
    print("="*60)
    print("\nFormats:")
    print("  - PNG (300 DPI) for presentations")
    print("  - PDF (vector) for journal submission")
    print("\nNext steps:")
    print("  1. Review figures for quality")
    print("  2. Include in LaTeX paper using \\includegraphics")
    print("  3. Add figure captions as specified in paper template")

if __name__ == "__main__":
    main()