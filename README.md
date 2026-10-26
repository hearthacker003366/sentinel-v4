# Sentinel V4 — AI SOC Copilot (Meta AI Developer Hackathon)

Purple-team demo: LLM red-team bots attack a **simulated lab network** while an
AI SOC copilot (Laya triage + Muse Spark reasoning) defends it, live on a
dashboard, with a human approving every action.

This repo is the Phase-0 skeleton. The frozen architecture (see the 20-day
runbook) is:

```
Simulated lab network (Docker / VMs, RFC1918 only)
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
  evaluates + prioritizes, requests Telegram HITL approval, then executes
  DRY-RUN containment by default (real action needs an explicit env gate).
        │ live view
        ▼
  dashboard_notes/  (red-vs-blue SOC dashboard — reused from V3, notes here)
```

## Layer rules (do not blur)

- **Laya never makes final judgments.** It triages and gates; low confidence
  always escalates to Muse Spark and, for actions, to the human.
- **Muse Spark never acts directly.** It proposes; the orchestrator +
  Telegram approval decide. Dry-run containment is the default.
- **Red-team bots never leave the simulated lab network.** Scope is enforced
  in code (`redteam/bot.py`), not just in prompts.
- **The NetworkX graph engine from Sentinel V3 is reused untouched.**

## Layout

| Dir | Contents |
|---|---|
| `model_adapter/` | Model-agnostic client interface + Muse Spark implementation |
| `triage/` | Laya gate: choice/score/yes-no calls to `/v1/systemone`, thresholds |
| `redteam/` | Red-team bot personas + lab scope guard |
| `orchestrator/` | Chief Sentinel: evaluation, prioritization, HITL, containment |
| `dashboard_notes/` | Notes for the V3 dashboard reuse / red-vs-blue view |

## Status

Phase 0 (prep). Stubs only — see TODOs in each module. Build runs Oct 26 –
Nov 4, 2026 per the runbook.
