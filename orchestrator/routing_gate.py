"""Calibrated Routing Gate for Sentinel V4.

Enforces the strict 0.8500 confidence threshold separating local System-1
autonomous triage from System-2 (Meta Muse Spark) escalation.
Guarantees that all System-1 auto-actions are strictly dry-run ONLY.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Route(str, Enum):
    SYSTEM_1_AUTO_ACT = "system_1_auto_act"
    SYSTEM_2_ESCALATE = "system_2_escalate"


GATE_THRESHOLD = 0.8500


@dataclass
class TriageVerdict:
    verdict: str           # benign, suspicious, malicious
    winner_confidence: float  # [0.0, 1.0]
    is_attack: bool
    severity: float        # [0.0, 1.0]
    raw: dict[str, Any] = None


@dataclass
class RoutingDecision:
    route: Route
    winner_confidence: float
    verdict: str
    is_attack: bool
    severity: float
    dry_run: bool
    reason: str
    action_type: str | None = None
    target: str | None = None


def evaluate_routing_gate(triage: TriageVerdict, event_context: dict[str, Any] = None) -> RoutingDecision:
    """Evaluates the 0.85 confidence boundary.

    - winner_confidence >= 0.8500 -> System-1 auto-act (dry_run=True ONLY).
    - winner_confidence < 0.8500 -> System-2 escalation to Meta Muse Spark.
    - Non-finite confidence (inf, -inf, nan) -> System-2 escalation + flag.
    """
    target = (event_context or {}).get("source_ip") or (event_context or {}).get("host")

    try:
        raw_conf = float(triage.winner_confidence)
    except (TypeError, ValueError):
        raw_conf = float("nan")

    # Security (§1.6): Non-finite confidence (inf, -inf, nan) MUST escalate, never auto-act
    if not math.isfinite(raw_conf):
        return RoutingDecision(
            route=Route.SYSTEM_2_ESCALATE,
            winner_confidence=0.0,
            verdict=triage.verdict,
            is_attack=triage.is_attack,
            severity=triage.severity,
            dry_run=True,
            reason="Non-finite confidence detected (inf/nan). Escalating to System-2 as security safeguard.",
            action_type="escalate_muse_spark",
            target=target,
        )

    conf = round(raw_conf, 4)

    if conf >= GATE_THRESHOLD:
        # High confidence -> System-1 handles autonomously (dry-run ONLY)
        if triage.verdict == "malicious" or triage.is_attack:
            action = "simulate_honeypot_divert" if triage.severity < 0.7 else "simulate_host_isolation"
            reason = (
                f"Laya System-1 high certainty ({conf:.4f} >= {GATE_THRESHOLD:.2f}). "
                f"Autonomous dry-run containment applied."
            )
        else:
            action = "log_benign"
            reason = (
                f"Laya System-1 verified benign ({conf:.4f} >= {GATE_THRESHOLD:.2f}). "
                f"Suppressed alert fatigue."
            )

        return RoutingDecision(
            route=Route.SYSTEM_1_AUTO_ACT,
            winner_confidence=conf,
            verdict=triage.verdict,
            is_attack=triage.is_attack,
            severity=triage.severity,
            dry_run=True,  # System-1 is strictly dry-run ONLY
            reason=reason,
            action_type=action,
            target=target,
        )
    else:
        # Ambiguous or novel -> Escalate to Meta Muse Spark System-2
        return RoutingDecision(
            route=Route.SYSTEM_2_ESCALATE,
            winner_confidence=conf,
            verdict=triage.verdict,
            is_attack=triage.is_attack,
            severity=triage.severity,
            dry_run=True,
            reason=(
                f"Laya System-1 ambiguity ({conf:.4f} < {GATE_THRESHOLD:.2f}). "
                f"Escalating to Meta Muse Spark 1.3 for multi-hop reasoning."
            ),
            action_type="escalate_muse_spark",
            target=target,
        )
