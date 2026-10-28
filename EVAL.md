# Sentinel V4 — Laya System-1 Triage Model Evaluation (EVAL.md)
*Meta Global AI Developer Hackathon 2026 — Track: Build for Your World*

---

## 🎯 Executive Summary

In **Sentinel V4**, triage speed and alert-fatigue prevention are achieved through a dual-system cognitive architecture:
- **System-1 (Laya)**: A locally fine-tuned, sub-55ms fast triage model running on local consumer hardware (NVIDIA RTX 4050 6GB Laptop GPU).
- **System-2 (Meta Muse Spark)**: Cloud-hosted cognitive reasoning via Meta Model API for deep threat-path explanation, forensic correlation, and containment proposals requiring Human-in-the-Loop (HITL) authorization.

This report documents the held-out evaluation comparing the base foundation model (`convaiinnovations/laya`) against our fine-tuned checkpoint (`laya-tuned-v1`) on 101 strictly held-out test telemetry rows (26 attack families, zero template string overlap with training data).

---

## 📊 Comparative Performance Benchmark

All metrics were computed using the deterministic evaluation harness `training/evaluate.py`. Artifacts and raw predictions are committed under `training/`:

| Metric | Base Model (`convaiinnovations/laya`) | Fine-Tuned Laya (`laya-tuned-v1`) | Absolute Delta | Relative Gain |
| :--- | :---: | :---: | :---: | :---: |
| **Verdict Accuracy** | 69.31% (0.6931) | **88.12%** (0.8812) | **+18.81%** | +27.1% relative |
| **Mean Winner Confidence** | 0.6763 | **0.8880** | **+0.2117** | +31.3% sharper certainty |
| **Mean P(Gold Verdict)** | 0.5682 | **0.8067** | **+0.2385** | +42.0% probability mass on truth |
| **Auto-Act Rate ($\ge 0.85$ threshold)** | 31.68% (0.3168) | **83.17%** (0.8317) | **+51.49%** | **2.6x increase in autonomous triage** |
| **Auto-Act Accuracy** | **93.75%** (0.9375) | **91.67%** (0.9167) | -2.08% | Retains >91% high-precision gate |
| **Escalation Rate to Muse Spark ($< 0.85$)** | 68.32% (0.6832) | **16.83%** (0.1683) | **-51.49%** | **75.4% reduction in triage alert fatigue** |
| **Binary Is-Attack Accuracy** | 89.11% (0.8911) | **91.09%** (0.9109) | **+1.98%** | Robust malicious discriminator |
| **P(Attack) on Real Attacks** | 0.8570 | **0.9572** | **+0.1002** | Extreme sensitivity to active threats |
| **P(Attack) on Benign Events** | 0.1528 | 0.1867 | +0.0339 | Low false-alarm floor |
| **Severity Mean Absolute Error (MAE)** | 0.2388 | **0.1262** | **-0.1126** | **47.1% error reduction** |
| **Mean Latency per Event** | 56 ms (0.056s) | **54 ms (0.054s)** | -2 ms | Steady-state sub-55ms execution |
| **Median Latency per Event** | 52 ms (0.052s) | **51 ms (0.051s)** | -1 ms | High-frequency telemetry ready |

---

## 🔍 Key Architectural Insights

### 1. Alert Fatigue Elimination (83.2% Autonomous Action)
The baseline model only achieved $\ge 0.85$ confidence on 31.7% of events, meaning nearly 70% of routine telemetry was unnecessarily escalated to higher tiers. Fine-tuned Laya reaches $\ge 0.85$ confidence on **83.2% of events** while maintaining **91.7% accuracy** on those decisions. This reduces escalations to Meta Muse Spark from 68.3% down to **16.8%**, reserving LLM tokens and human analyst attention strictly for novel, high-ambiguity threats.

### 2. High-Severity Calibration (47% Error Drop)
Adversary tactics (e.g., VSSAdmin shadow copy deletion, LSASS memory dumping, ransomware dropper execution) are mapped directly to continuous threat severity (0 to 4 scale, normalized 0.0 to 1.0). Tuned Laya cut severity prediction MAE from **0.2388 to 0.1262**, ensuring that true ransomware activity is instantly prioritized with high severity.

### 3. Attack Sensitivity (0.957 P(Attack))
When a true malicious intrusion occurs, the fine-tuned model outputs an average probability of attack of **95.7%** (compared to 85.7% for the baseline). This allows the Sentinel V4 orchestrator to immediately dispatch deceptive honeypot traps and isolate compromised hosts before lateral movement reaches mission-critical domain controllers.

---

## 🔬 Evaluation Protocol & Reproducibility

1. **Test Dataset**: `training/data_test.jsonl` (101 labeled security events).
2. **Deterministic CLI Evaluation**:
   ```bash
   # Run baseline evaluation
   python training/evaluate.py --model convaiinnovations/laya --tag baseline

   # Run fine-tuned evaluation
   python training/evaluate.py --model training/laya-tuned-v1 --tag tuned
   ```
3. **Artifacts Generated**:
   - `training/baseline_metrics.json` & `training/baseline_predictions.json`
   - `training/tuned_metrics.json` & `training/tuned_predictions.json`
