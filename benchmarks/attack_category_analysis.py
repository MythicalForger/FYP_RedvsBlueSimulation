#!/usr/bin/env python3
"""
Detailed Attack Category Analysis
==================================
Breaks down detection performance by attack type with statistical analysis.

Generates comprehensive tables showing:
- Per-category detection rates
- Semantic score distributions
- Primary detection mechanism
- False negative analysis

Usage:
    python attack_category_analysis.py --results blue_benchmark_results.jsonl
"""

import json
import argparse
from collections import defaultdict
import statistics

def load_results(filepath):
    """Load benchmark results"""
    results = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                results.append(json.loads(line))
    return results

def analyze_by_category(results):
    """Group and analyze results by attack type"""
    
    # Group by attack type
    by_type = defaultdict(list)
    for r in results:
        if r.get('label') == 'malicious':
            attack_type = r.get('attack_type', 'unknown')
            by_type[attack_type].append(r)
    
    # Analyze each category
    category_stats = []
    
    for attack_type, samples in sorted(by_type.items()):
        total = len(samples)
        
        # Count detections
        blocked = sum(1 for s in samples if s.get('blue_verdict') in ['blocked', 'soft_block'])
        allowed = total - blocked
        
        tpr = blocked / total if total > 0 else 0
        
        # Semantic scores
        sem_scores = [s['semantic_score'] for s in samples if s.get('semantic_score') is not None]
        avg_sem = statistics.mean(sem_scores) if sem_scores else 0
        std_sem = statistics.stdev(sem_scores) if len(sem_scores) > 1 else 0
        
        # Latency
        latencies = [s['latency_s'] for s in samples if 'latency_s' in s]
        avg_lat = statistics.mean(latencies) if latencies else 0
        
        # Detection mechanisms
        structural_blocks = sum(1 for s in samples 
                               if s.get('operation') and 'semantic' not in s.get('operation', ''))
        semantic_blocks = sum(1 for s in samples 
                            if 'semantic_override' in s.get('operation', '') 
                            or 'semantic_flag' in s.get('operation', ''))
        
        primary_mechanism = "Structural" if structural_blocks > semantic_blocks else "Semantic"
        if structural_blocks == semantic_blocks:
            primary_mechanism = "Mixed"
        
        category_stats.append({
            'attack_type': attack_type,
            'total': total,
            'detected': blocked,
            'tpr': round(tpr, 4),
            'avg_semantic_score': round(avg_sem, 4),
            'std_semantic_score': round(std_sem, 4),
            'avg_latency_ms': round(avg_lat * 1000, 2),
            'primary_mechanism': primary_mechanism,
            'structural_blocks': structural_blocks,
            'semantic_blocks': semantic_blocks
        })
    
    return category_stats

def analyze_false_negatives(results):
    """Detailed analysis of false negatives"""
    
    false_negatives = [r for r in results 
                      if r.get('label') == 'malicious' 
                      and r.get('blue_verdict') == 'allowed']
    
    print("\n\n" + "="*80)
    print("FALSE NEGATIVE ANALYSIS")
    print("="*80)
    print(f"\nTotal False Negatives: {len(false_negatives)}")
    
    # Group by attack type
    fn_by_type = defaultdict(int)
    for fn in false_negatives:
        fn_by_type[fn.get('attack_type', 'unknown')] += 1
    
    print("\nFalse Negatives by Attack Type:")
    print(f"{'Attack Type':<30} {'Count':<10} {'Example Attack ID':<30}")
    print("-" * 70)
    
    for attack_type, count in sorted(fn_by_type.items(), key=lambda x: -x[1])[:15]:
        example = next(fn['attack_id'] for fn in false_negatives 
                      if fn.get('attack_type') == attack_type)
        print(f"{attack_type:<30} {count:<10} {example:<30}")
    
    # Sample false negative prompts
    print("\n\nSample False Negative Prompts (Top 10):")
    print("-" * 80)
    
    for fn in false_negatives[:10]:
        prompt = fn.get('prompt', '')
        if len(prompt) > 70:
            prompt = prompt[:67] + "..."
        print(f"Type: {fn.get('attack_type', 'unknown')}")
        print(f"  Prompt: {prompt}")
        print(f"  Attack ID: {fn.get('attack_id')}")
        print()
    
    return false_negatives

def print_category_table(category_stats):
    """Print formatted category performance table"""
    
    print("\n\n" + "="*100)
    print("DETECTION PERFORMANCE BY ATTACK CATEGORY")
    print("="*100)
    
    # Sort by TPR descending
    sorted_stats = sorted(category_stats, key=lambda x: -x['tpr'])
    
    print(f"\n{'Attack Type':<30} {'Total':<8} {'Detected':<10} {'TPR':<8} "
          f"{'Avg Sem':<10} {'Latency(ms)':<12} {'Mechanism':<12}")
    print("-" * 100)
    
    for stat in sorted_stats:
        print(f"{stat['attack_type']:<30} "
              f"{stat['total']:<8} "
              f"{stat['detected']:<10} "
              f"{stat['tpr']:<8.3f} "
              f"{stat['avg_semantic_score']:<10.3f} "
              f"{stat['avg_latency_ms']:<12.2f} "
              f"{stat['primary_mechanism']:<12}")
    
    # Calculate overall stats
    total_samples = sum(s['total'] for s in category_stats)
    total_detected = sum(s['detected'] for s in category_stats)
    overall_tpr = total_detected / total_samples if total_samples > 0 else 0
    
    print("-" * 100)
    print(f"{'OVERALL':<30} {total_samples:<8} {total_detected:<10} {overall_tpr:<8.3f}")

def analyze_mutation_impact(results):
    """Analyze how mutations affect detection per category"""
    
    print("\n\n" + "="*80)
    print("MUTATION IMPACT ANALYSIS")
    print("="*80)
    
    # This requires the attack_id to contain mutation info
    # Example: "prompt_injection_001-mutated" vs "prompt_injection_001-base"
    
    base_attacks = defaultdict(list)
    mutated_attacks = defaultdict(list)
    
    for r in results:
        if r.get('label') == 'malicious':
            attack_id = r.get('attack_id', '')
            attack_type = r.get('attack_type', 'unknown')
            is_blocked = r.get('blue_verdict') in ['blocked', 'soft_block']
            
            # Simple heuristic: check if attack_id contains mutation indicators
            if any(x in attack_id.lower() for x in ['mutated', 'obfuscated', 'compound']):
                mutated_attacks[attack_type].append(is_blocked)
            else:
                base_attacks[attack_type].append(is_blocked)
    
    print(f"\n{'Attack Type':<30} {'Base TPR':<12} {'Mutated TPR':<12} {'Delta':<10}")
    print("-" * 70)
    
    for attack_type in sorted(set(base_attacks.keys()) | set(mutated_attacks.keys())):
        base_tpr = sum(base_attacks[attack_type]) / len(base_attacks[attack_type]) if base_attacks[attack_type] else 0
        mut_tpr = sum(mutated_attacks[attack_type]) / len(mutated_attacks[attack_type]) if mutated_attacks[attack_type] else 0
        delta = mut_tpr - base_tpr
        
        if base_attacks[attack_type] and mutated_attacks[attack_type]:
            print(f"{attack_type:<30} {base_tpr:<12.3f} {mut_tpr:<12.3f} {delta:<10.3f}")

def main():
    parser = argparse.ArgumentParser(description='Detailed attack category analysis')
    parser.add_argument('--results', required=True, help='Path to benchmark results JSONL')
    parser.add_argument('--output', default='category_analysis.json', help='Output file')
    
    args = parser.parse_args()
    
    print("Loading results...")
    results = load_results(args.results)
    print(f"Loaded {len(results)} samples")
    
    # Perform analysis
    category_stats = analyze_by_category(results)
    
    # Print tables
    print_category_table(category_stats)
    
    # False negative analysis
    false_negatives = analyze_false_negatives(results)
    
    # Mutation impact
    analyze_mutation_impact(results)
    
    # Save detailed results
    output_data = {
        'category_stats': category_stats,
        'false_negatives': [
            {
                'attack_id': fn.get('attack_id'),
                'attack_type': fn.get('attack_type'),
                'prompt': fn.get('prompt')
            }
            for fn in false_negatives
        ],
        'total_samples': len(results),
        'total_fn': len(false_negatives)
    }
    
    with open(args.output, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n\nDetailed results saved to {args.output}")

if __name__ == "__main__":
    main()