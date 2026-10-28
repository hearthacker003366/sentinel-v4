# Sentinel V4 — AI SOC Copilot (Meta Global AI Developer Hackathon)

> **What was pre-existing vs what was built this week:** Sentinel V3 (the college SOC project — NetworkX threat graphing, GraphSAGE lateral-movement prediction, MCP reasoning, Telegram HITL SOAR) is the pre-existing baseline and lives in a separate repository. **Everything in this repo was built during the hackathon (Oct 26 – Nov 4, 2026):** the dual-system AI SOC copilot below — Laya System-1 triage gate + Muse Spark System-2 reasoning, LLM red-team bots, the orchestrator, and the replay harness.

Purple-team demo: LLM red-team bots attack a **simulated lab network** while an AI SOC copilot (Laya triage + Muse Spark reasoning) defends it, live on a dashboard, with a human approving every action.

## 🏗️ Architecture

```
Simulated lab network (RFC1918 only: 192.168.56.0/24, 10.10.10.0/24)
        │ telemetry                     │ probes
        ▼                               ▼
  triage/  (Laya, System-1)       redteam/  (bots: Muse Spark strategy,
  scores every event in ~ms;       Laya tactics; lab scope is hard-coded)
  auto-act > 0.85 confidence,
  escalate below
        │ uncertain / high-risk
        ▼
  model_adapter/  (Muse Spark, System-2, via Meta Model API)
  threat-path explanation, containment recommendation, remediation drafting.
  Reached ONLY through the adapter — prompts stay model-agnostic and the
  MCP tool interface from Sentinel V3 stays unchanged.
        │ proposed actions
        ▼
  orchestrator/  (Chief Sentinel)
  dry-run containment by default, HITL approval via Telegram
        │
        ▼
  dashboard/  (Day 8: Stitch-built UI)
```

## ✅ What is built and verified

- **`model_adapter/client.py`** — `MuseSparkClient` implementing the `ReasoningClient` protocol. Model pinned to `muse-spark-1.3` (any other model raises `ValueError`); `tool_choice` only `"auto"`; tool names validated; API URLs allow-listed (scheme + host).
- **Security fixes §1.1–§1.7** (verified from code, not from claims):
  - §1.1 prompt-injection tag breakout quarantined (`quarantine_untrusted_text`, `</` escaped).
  - §1.2 containment via typed `ContainmentProposal` bound to an explicit `approval_id` — model prose is non-executable by design.
  - §1.3 model pin + API URL validation.
  - §1.4 lab scope accepts literal lab IPs only (hostnames denied — no DNS rebinding).
  - §1.5 pinned `requirements.txt`.
  - §1.6 non-finite confidence (`inf`/`NaN`) forces escalation (`math.isfinite`).
  - §1.7 SSE multi-line event folding, tool-schema validation, bounded retries with backoff, `raw_decode` JSON parsing.
- **`scripts/replay_scenarios.py`** — Gate 1 replay harness, 3/3 scenarios PASS (verified):
  - Scenario 1 (SSH brute force + lateral movement): PASS, conf 0.87 — dry-run reversible containment with TTL + approval request + threat-path evidence.
  - Scenario 2 (C2 beaconing + exfiltration): PASS, conf 0.82 — targeted isolation with TTL, zero blanket actions.
  - Scenario 3 (benign discriminator): PASS, conf 0.91 — zero containment proposals, zero approval requests, explicit benign classification.
- **Tests: 29/29 pass** (`python -m pytest tests/`), including the three hardening tests that were missing before: tag breakout, multi-line SSE folding, inf/NaN confidence escalation.

## 🤖 Laya (System-1 gate)

Laya is the fine-tuned triage model behind the gate. Training proof screenshots (RTX 4050, redacted):

![Laya GPU training proof, part 1](docs/assets/laya_gpu_training_proof_part1.png)

![Laya GPU training proof, part 2](docs/assets/laya_gpu_training_proof_part2.png)

Held-out evaluation (`evaluate.py` base-vs-tuned on the 105 held-out rows + `EVAL.md`) is still outstanding — no benchmark numbers are claimed until it exists.

## 🧪 Run it

```bash
python -m pytest tests/          # 29 passed
python scripts/replay_scenarios.py   # 3/3 scenarios passed
```

## 📋 Submission

- **Portal:** https://cerebralvalley.ai/e/meta-ai-developer-hackathon/hackathon/submit
- **Deadline:** November 4, 2026, 9:00 PM ET (November 5, 7:30 AM IST).
- **Demo video (3 minutes, required):** opens with the pre-existing-vs-built-this-week line above.
- **Track:** Build for Your World. **Tooling:** Muse Spark series via the Meta Model API; open-weight bonus path via Muse Glimmer / Muse Spark Open on local hardware.

## ⚠️ Rules note
New work only: this repo was created Oct 26, 2026 and contains only hackathon-week work. Pre-existing work (Sentinel V3) is named here and in the video, lives in its own repository, and is not judged. The demo runs standalone with mock/demo data available for judges.
