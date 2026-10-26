"""Muse Spark client behind a model-agnostic adapter.

Sentinel V4 talks to its reasoning model ONLY through this module. The rest of
the system depends on the `ReasoningClient` interface below, never on a
vendor SDK, so the model can be swapped (or a fallback added) without
touching the orchestrator, triage, or dashboard. Prompts must stay
model-agnostic, and the MCP tool interface inherited from Sentinel V3 stays
unchanged — the model calls the same tools regardless of provider.

TODO (Phase 1, day 1):
- Implement `MuseSparkClient` against the Meta Model API.
- Pin the model id explicitly (e.g. muse-spark-1.3); never rely on defaults.
- Remember: `tool_choice` accepts only "auto" — design the agent loop so it
  never needs to force a specific tool.
- Tool/function names must match ^[a-zA-Z0-9_.-]+$ with at most one dot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ThreatContext:
    """Everything the reasoning model needs about one escalated case."""

    event_summary: str
    graph_path: list[str] = field(default_factory=list)  # kill-chain nodes from the V3 graph engine
    telemetry: dict = field(default_factory=dict)


@dataclass
class ReasoningResult:
    """Structured output the orchestrator consumes. No free-form actions."""

    explanation: str = ""
    containment_recommendation: str = ""
    remediation_draft: str = ""
    confidence: float = 0.0
    raw: dict = field(default_factory=dict)


class ReasoningClient(Protocol):
    """Interface every model backend must satisfy."""

    def explain_threat_path(self, ctx: ThreatContext) -> ReasoningResult: ...
    def recommend_containment(self, ctx: ThreatContext) -> ReasoningResult: ...
    def draft_remediation(self, ctx: ThreatContext) -> ReasoningResult: ...


class MuseSparkClient:
    """ReasoningClient backed by Muse Spark via the Meta Model API."""

    def __init__(self, api_key: str, model: str = "muse-spark-1.3") -> None:
        self.api_key = api_key
        self.model = model
        # TODO: init the Meta Model API transport here (pooled HTTP client).

    def _reason(self, task: str, ctx: ThreatContext) -> ReasoningResult:
        # TODO: build the model-agnostic prompt for `task`, expose the MCP
        # tools, parse the structured result into ReasoningResult.
        raise NotImplementedError("Muse Spark wiring lands on build day 1")

    def explain_threat_path(self, ctx: ThreatContext) -> ReasoningResult:
        return self._reason("explain_threat_path", ctx)

    def recommend_containment(self, ctx: ThreatContext) -> ReasoningResult:
        return self._reason("recommend_containment", ctx)

    def draft_remediation(self, ctx: ThreatContext) -> ReasoningResult:
        return self._reason("draft_remediation", ctx)
