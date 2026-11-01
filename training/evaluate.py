"""Before/after evaluation harness for the Sentinel V4 Laya triage model.

Runs the SAME questions the gate uses (verdict choice + is_attack yes/no +
severity score) over the held-out test split and reports:
  - verdict accuracy, mean confidence of the winning label, mean P(gold)
  - auto-act vs escalate split at the gate's 0.85 threshold (laya_gate.py
    GateThresholds.auto_act) and the accuracy of the auto-acted subset
  - is_attack accuracy (P(true) >= 0.5), mean P(true) for attack / non-attack
  - severity MAE (predicted expected level / 4 vs gold severity 0..1)
  - mean decide() latency per event (all 3 questions in one call)

Usage:
  python evaluate.py --model <checkpoint dir or HF id> --tag baseline
  python evaluate.py --model ./laya-tuned-v1 --tag tuned

Writes <tag>_metrics.json and <tag>_predictions.json next to this script.
The QUESTIONS block below must stay identical to gen_dataset.py / training.
"""
import argparse
import json
import os
import statistics
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AUTO_ACT = 0.85  # laya_gate.GateThresholds.auto_act

QUESTIONS = {
    "verdict": {
        "type": "choice",
        "instructions": "How should the security event in `event` be classified?",
        "criteria": {
            "benign": "routine, expected activity with no sign of attack",
            "suspicious": "unusual activity that might be an attack and needs a look",
            "malicious": "clear evidence of an attack or compromise attempt",
        },
    },
    "is_attack": {
        "type": "noul",
        "instructions": "Is the event in `event` part of an attack?",
    },
    "severity": {
        "type": "score",
        "instructions": "How severe is the threat in the security event in `event`?",
        "criteria": [
            "no threat at all - routine activity",
            "minimal concern",
            "moderate concern - worth investigating",
            "serious threat",
            "critical threat - active compromise or destructive action",
        ],
    },
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", default=os.path.join(HERE, "data_test.jsonl"))
    ap.add_argument("--tag", required=True)
    ap.add_argument("--device", default=None)
    args = ap.parse_args()

    import laya

    rows = [json.loads(l) for l in open(args.data) if l.strip()]
    agent = laya.load(args.model, device=args.device) if args.device else laya.load(args.model)

    preds, lat = [], []
    for i, row in enumerate(rows):
        state = {"event": row["event"]}
        if i < 3:  # warm-up, untimed
            agent.system_one(state, QUESTIONS)
        t0 = time.perf_counter()
        ans = agent.system_one(state, QUESTIONS)["answers"]
        lat.append(time.perf_counter() - t0)
        v = ans["verdict"]
        preds.append({
            "event": row["event"], "family": row["family"],
            "gold_verdict": row["verdict"], "gold_is_attack": row["is_attack"],
            "gold_severity": row["severity"],
            "pred_verdict": v["choice"], "p_verdict": v["probabilities"],
            "p_winner": max(v["probabilities"].values()),
            "p_attack": ans["is_attack"]["noul"],
            "severity_pred": round(ans["severity"]["score"] / 4.0, 4),
        })

    n = len(preds)
    vacc = sum(p["pred_verdict"] == p["gold_verdict"] for p in preds) / n
    auto = [p for p in preds if p["p_winner"] >= AUTO_ACT]
    auto_acc = (sum(p["pred_verdict"] == p["gold_verdict"] for p in auto) / len(auto)) if auto else None
    aacc = sum((p["p_attack"] >= 0.5) == p["gold_is_attack"] for p in preds) / n
    sev_mae = sum(abs(p["severity_pred"] - p["gold_severity"]) for p in preds) / n
    metrics = {
        "model": args.model, "tag": args.tag, "n_test": n,
        "verdict_accuracy": round(vacc, 4),
        "mean_p_winner": round(statistics.mean(p["p_winner"] for p in preds), 4),
        "mean_p_gold_verdict": round(statistics.mean(p["p_verdict"][p["gold_verdict"]] for p in preds), 4),
        "auto_act_rate": round(len(auto) / n, 4),
        "auto_act_accuracy": round(auto_acc, 4) if auto_acc is not None else None,
        "escalate_rate": round(1 - len(auto) / n, 4),
        "is_attack_accuracy": round(aacc, 4),
        "mean_p_attack_when_attack": round(statistics.mean(p["p_attack"] for p in preds if p["gold_is_attack"]), 4),
        "mean_p_attack_when_not": round(statistics.mean(p["p_attack"] for p in preds if not p["gold_is_attack"]), 4),
        "severity_mae": round(sev_mae, 4),
        "latency_s_mean": round(statistics.mean(lat), 3),
        "latency_s_median": round(statistics.median(lat), 3),
    }
    with open(os.path.join(HERE, f"{args.tag}_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    with open(os.path.join(HERE, f"{args.tag}_predictions.json"), "w") as f:
        json.dump(preds, f, indent=1)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
