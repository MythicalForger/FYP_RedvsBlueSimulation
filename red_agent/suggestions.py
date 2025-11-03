#!/usr/bin/env python3
"""
accept_suggestions.py (auto mode)

Automatically applies suggestions from attacks_suggested.json
to attacks.json based on defined thresholds.

Usage:
  python3 accept_suggestions.py --suggest ./red_agent/attacks_suggested.json --attacks ./red_agent/attacks.json
"""

import os, json, argparse
from datetime import datetime

AUTO_ACCEPT_DELTA = 0.3        # Accept if |suggested_weight - current_weight| > 0.3
AUTO_ACCEPT_CONF = 0.8         # Accept if confidence or success_rate >= 0.8

def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def apply_suggestions(suggest_path, attacks_path, out_audit_path=None):
    suggestions_doc = load_json(suggest_path)
    if suggestions_doc is None:
        print("❌ No suggestions file found:", suggest_path)
        return
    suggestions = suggestions_doc.get("suggestions", [])

    attacks = load_json(attacks_path) or []
    attacks_map = {a.get("id"): a for a in attacks if a.get("id")}

    print(f"📊 Found {len(suggestions)} suggestions. Attacks list contains {len(attacks)} entries.")
    approved, skipped = [], []

    for s in suggestions:
        aid = s.get("id")
        if not aid:
            continue
        cur = attacks_map.get(aid)
        cur_weight = cur.get("weight", 1.0) if cur else 1.0
        sugg_weight = s.get("suggested_weight", cur_weight)
        conf = s.get("confidence", s.get("success_rate", 0.0))

        delta = abs(sugg_weight - cur_weight)
        should_accept = (delta > AUTO_ACCEPT_DELTA) or (conf >= AUTO_ACCEPT_CONF)

        if should_accept:
            if cur:
                cur["weight"] = sugg_weight
                approved.append({"id": aid, "action": "updated_weight", "new_weight": sugg_weight})
                print(f"✅ Accepted {aid}: weight {cur_weight} → {sugg_weight} (Δ={delta:.2f}, conf={conf})")
            else:
                new = {
                    "id": aid,
                    "template": s.get("template"),
                    "weight": sugg_weight
                }
                attacks.append(new)
                attacks_map[aid] = new
                approved.append({"id": aid, "action": "added", "new_weight": sugg_weight})
                print(f"🆕 Added new attack entry: {aid} (weight={sugg_weight})")
        else:
            skipped.append({"id": aid, "reason": f"Δ={delta:.2f}, conf={conf}"})
            print(f"⏭️ Skipped {aid}: Δ={delta:.2f}, conf={conf}")

    # Write updated attacks.json with backup
    backup = attacks_path + ".bak." + datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    os.rename(attacks_path, backup)
    with open(attacks_path, "w", encoding="utf-8") as f:
        json.dump(attacks, f, indent=2)
    print(f"\n💾 Updated attacks.json; backup saved to {backup}")

    # Write audit file
    if out_audit_path is None:
        out_audit_path = os.path.join(os.path.dirname(attacks_path), "attacks_approved.json")
    audit = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "approved": approved,
        "skipped": skipped,
        "rules": {
            "AUTO_ACCEPT_DELTA": AUTO_ACCEPT_DELTA,
            "AUTO_ACCEPT_CONF": AUTO_ACCEPT_CONF
        }
    }
    with open(out_audit_path, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=2)
    print(f"🧾 Wrote audit log → {out_audit_path}")
    print(f"✅ Total accepted: {len(approved)}, skipped: {len(skipped)}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--suggest", default="./attacks_suggested.json")
    p.add_argument("--attacks", default="./attacks.json")
    args = p.parse_args()
    apply_suggestions(args.suggest, args.attacks)

if __name__ == "__main__":
    main()

