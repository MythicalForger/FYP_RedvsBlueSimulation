#!/usr/bin/env python3
"""
Red-Blue Co-Evolution Tracker
==============================
Tracks how Red Agent attack weights evolve over multiple training cycles
and how Blue Agent detection effectiveness changes in response.

Demonstrates system stability, convergence, and adaptive behavior.

Usage:
    # Run multiple simulation cycles
    for i in {1..10}; do
        echo "Cycle $i"
        python run_simulation.py --duration 600  # 10 minutes
        python retrainer.py
        python suggestions.py --accept
        python coevolution_tracker.py --cycle $i
    done
    
    # Analyze results
    python coevolution_tracker.py --analyze
"""

import json
import argparse
import os
from collections import defaultdict
import statistics

class CoEvolutionTracker:
    def __init__(self, output_dir='coevolution_data'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def record_cycle(self, cycle_num):
        """Record state after a training cycle"""
        
        cycle_data = {
            'cycle': cycle_num,
            'weights': self.load_current_weights(),
            'detection_performance': self.compute_detection_rate(),
            'attack_distribution': self.compute_attack_distribution(),
            'weight_entropy': self.compute_weight_entropy()
        }
        
        # Save cycle data
        output_file = os.path.join(self.output_dir, f'cycle_{cycle_num:03d}.json')
        with open(output_file, 'w') as f:
            json.dump(cycle_data, f, indent=2)
        
        print(f"\nCycle {cycle_num} recorded:")
        print(f"  Detection Rate: {cycle_data['detection_performance']['tpr']:.3f}")
        print(f"  Weight Entropy: {cycle_data['weight_entropy']:.3f}")
        print(f"  Top Attack: {cycle_data['attack_distribution'][0]['attack_id']}")
        print(f"  Data saved to {output_file}")
        
        return cycle_data
    
    def load_current_weights(self):
        """Load current attack weights from attacks.json"""
        with open('attacks.json', 'r') as f:
            data = json.load(f)
        
        weights = {}
        for attack in data.get('attacks', []):
            weights[attack['id']] = attack.get('weight', 1.0)
        
        return weights
    
    def compute_detection_rate(self):
        """Compute current detection rate from recent logs"""
        
        # Load recent ai_events and alerts
        try:
            with open('logs/ai_events.jsonl', 'r') as f:
                events = [json.loads(line) for line in f if line.strip()]
            
            with open('logs/alerts.jsonl', 'r') as f:
                alerts = [json.loads(line) for line in f if line.strip()]
            
            # Get recent events (last 1000)
            recent_events = events[-1000:] if len(events) > 1000 else events
            
            # Count malicious prompts
            malicious_prompts = [e for e in recent_events if e.get('role') == 'red_request']
            
            # Count blocks
            blocked_ids = {a['id'] for a in alerts}
            blocked = sum(1 for p in malicious_prompts if p['id'] in blocked_ids)
            
            total = len(malicious_prompts)
            tpr = blocked / total if total > 0 else 0
            
            return {
                'total': total,
                'blocked': blocked,
                'tpr': round(tpr, 4)
            }
        
        except FileNotFoundError:
            return {'total': 0, 'blocked': 0, 'tpr': 0}
    
    def compute_attack_distribution(self):
        """Compute current attack weight distribution"""
        weights = self.load_current_weights()
        
        # Sort by weight descending
        sorted_attacks = sorted(weights.items(), key=lambda x: -x[1])
        
        # Get top 20
        top_attacks = [
            {'attack_id': aid, 'weight': round(w, 3)}
            for aid, w in sorted_attacks[:20]
        ]
        
        return top_attacks
    
    def compute_weight_entropy(self):
        """Compute entropy of weight distribution (measure of diversity)"""
        import math
        
        weights = self.load_current_weights()
        weight_values = list(weights.values())
        
        # Normalize to probability distribution
        total = sum(weight_values)
        probs = [w / total for w in weight_values]
        
        # Compute Shannon entropy
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        
        return round(entropy, 4)
    
    def analyze_evolution(self):
        """Analyze evolution across all recorded cycles"""
        
        # Load all cycle data
        cycle_files = sorted([
            f for f in os.listdir(self.output_dir)
            if f.startswith('cycle_') and f.endswith('.json')
        ])
        
        if not cycle_files:
            print("No cycle data found. Run --cycle N first to record cycles.")
            return
        
        cycles = []
        for cf in cycle_files:
            with open(os.path.join(self.output_dir, cf), 'r') as f:
                cycles.append(json.load(f))
        
        print("\n" + "="*80)
        print("RED-BLUE CO-EVOLUTION ANALYSIS")
        print("="*80)
        
        # Detection rate over time
        print("\n\nDETECTION RATE OVER TIME:")
        print(f"{'Cycle':<10} {'TPR':<10} {'Blocked':<10} {'Total':<10}")
        print("-" * 40)
        
        for c in cycles:
            perf = c['detection_performance']
            print(f"{c['cycle']:<10} {perf['tpr']:<10.3f} "
                  f"{perf['blocked']:<10} {perf['total']:<10}")
        
        # Weight entropy over time
        print("\n\nWEIGHT ENTROPY OVER TIME (Higher = More Diverse):")
        print(f"{'Cycle':<10} {'Entropy':<10}")
        print("-" * 20)
        
        for c in cycles:
            print(f"{c['cycle']:<10} {c['weight_entropy']:<10.3f}")
        
        # Top attacks by cycle
        print("\n\nTOP ATTACK BY CYCLE:")
        print(f"{'Cycle':<10} {'Attack ID':<40} {'Weight':<10}")
        print("-" * 60)
        
        for c in cycles:
            top = c['attack_distribution'][0]
            print(f"{c['cycle']:<10} {top['attack_id']:<40} {top['weight']:<10.3f}")
        
        # Weight convergence analysis
        print("\n\nWEIGHT CONVERGENCE ANALYSIS:")
        
        # Track how much weights change between cycles
        weight_changes = []
        for i in range(1, len(cycles)):
            prev_weights = cycles[i-1]['weights']
            curr_weights = cycles[i]['weights']
            
            # Compute total absolute change
            total_change = sum(
                abs(curr_weights.get(aid, 0) - prev_weights.get(aid, 0))
                for aid in set(prev_weights.keys()) | set(curr_weights.keys())
            )
            
            weight_changes.append(total_change)
        
        print(f"\n{'Cycle Transition':<20} {'Total Weight Change':<20}")
        print("-" * 40)
        
        for i, change in enumerate(weight_changes, start=1):
            print(f"{i} -> {i+1:<15} {change:<20.3f}")
        
        # Convergence assessment
        if len(weight_changes) >= 3:
            recent_changes = weight_changes[-3:]
            trend = "DECREASING" if recent_changes[-1] < recent_changes[0] else "INCREASING"
            stability = "STABLE" if statistics.stdev(recent_changes) < 0.5 else "OSCILLATING"
            
            print(f"\nTrend: {trend}")
            print(f"Stability: {stability}")
            
            if trend == "DECREASING" and stability == "STABLE":
                print("Status: System is converging ✓")
            else:
                print("Status: System still adapting")
        
        # Attack type concentration
        print("\n\nATTACK TYPE CONCENTRATION:")
        
        # Calculate how concentrated weights are on top-k attacks
        for c in cycles:
            weights = c['weights']
            sorted_weights = sorted(weights.values(), reverse=True)
            total_weight = sum(sorted_weights)
            
            top5_concentration = sum(sorted_weights[:5]) / total_weight if total_weight > 0 else 0
            top10_concentration = sum(sorted_weights[:10]) / total_weight if total_weight > 0 else 0
            
            print(f"Cycle {c['cycle']}: "
                  f"Top-5: {top5_concentration:.2%}, "
                  f"Top-10: {top10_concentration:.2%}")
        
        # Save summary
        summary = {
            'num_cycles': len(cycles),
            'detection_rate_progression': [
                {'cycle': c['cycle'], 'tpr': c['detection_performance']['tpr']}
                for c in cycles
            ],
            'weight_entropy_progression': [
                {'cycle': c['cycle'], 'entropy': c['weight_entropy']}
                for c in cycles
            ],
            'weight_change_progression': [
                {'transition': f"{i}->{i+1}", 'change': change}
                for i, change in enumerate(weight_changes, start=1)
            ]
        }
        
        summary_file = os.path.join(self.output_dir, 'evolution_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n\nSummary saved to {summary_file}")
        print("\nTo plot evolution:")
        print("  - Detection Rate: Use 'cycle' vs 'tpr' from detection_rate_progression")
        print("  - Weight Entropy: Use 'cycle' vs 'entropy' from weight_entropy_progression")
        print("  - Weight Changes: Use 'transition' vs 'change' from weight_change_progression")

def main():
    parser = argparse.ArgumentParser(description='Red-Blue Co-Evolution Tracker')
    parser.add_argument('--cycle', type=int, help='Record current cycle number')
    parser.add_argument('--analyze', action='store_true', help='Analyze all recorded cycles')
    parser.add_argument('--output-dir', default='coevolution_data', help='Output directory')
    
    args = parser.parse_args()
    
    tracker = CoEvolutionTracker(output_dir=args.output_dir)
    
    if args.cycle is not None:
        tracker.record_cycle(args.cycle)
    elif args.analyze:
        tracker.analyze_evolution()
    else:
        print("Error: Must specify either --cycle N or --analyze")
        print("\nUsage examples:")
        print("  python coevolution_tracker.py --cycle 1      # Record cycle 1")
        print("  python coevolution_tracker.py --analyze      # Analyze all cycles")

if __name__ == "__main__":
    main()