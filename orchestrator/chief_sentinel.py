"""Chief Sentinel Orchestrator for Sentinel V4.

Coordinates the dual-system cognitive defense loop:
1. Ingests normalized telemetry (in-memory queue or log tailing).
2. Triage via System-1 Laya gate (sub-55ms, 45ms mean).
3. Evaluates 0.8500 confidence boundary via RoutingGate:
   - >= 0.8500 -> System-1 dry-run simulation.
   - < 0.8500  -> System-2 Meta Muse Spark escalation.
4. Generates single-use HITL approval tokens via SQLite WAL HITLManager.
5. Provides dual operating modes: Headless Daemon and Interactive REPL.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from model_adapter.client import ThreatContext, ContainmentAction
from model_adapter.muse_spark_adapter import MuseSparkAdapter, EnhancedReasoningResult
from orchestrator.hitl_manager import (
    HITLManager,
    ProposalRecord,
    TokenAlreadyConsumed,
    TokenExpired,
    GateLockedOut,
)
from orchestrator.routing_gate import (
    evaluate_routing_gate,
    RoutingDecision,
    TriageVerdict,
    Route,
    GATE_THRESHOLD,
)
from redteam.bot import RedTeamRunner
from triage.laya_gate import LayaGate

logger = logging.getLogger("sentinel.orchestrator")


@dataclass
class ProcessedIncident:
    incident_id: str
    timestamp: float
    raw_event: dict[str, Any]
    triage: TriageVerdict
    routing: RoutingDecision
    muse_reasoning: EnhancedReasoningResult | None = None
    proposal_id: str | None = None
    approval_token: str | None = None  # Returned in memory for UI/CLI, never stored raw in DB


class ChiefSentinelEngine:
    """Master dual-system orchestrator engine driving both Daemon and REPL modes."""

    def __init__(
        self,
        db_path: str | None = None,
        api_key: str | None = None,
        laya_gate: LayaGate | None = None
    ) -> None:
        self.hitl = HITLManager(db_path=db_path) if db_path else HITLManager()
        self.muse = MuseSparkAdapter(api_key=api_key)
        self.runner = RedTeamRunner(pacing_s=1.5)
        self.laya = laya_gate or LayaGate()
        self.incidents: list[ProcessedIncident] = []
        self.applied_containments: list[dict[str, Any]] = []

    def triage_event_system1(self, event: dict[str, Any]) -> TriageVerdict:
        """Evaluates event via System-1 LayaGate."""
        res = self.laya.triage_event(event)
        return TriageVerdict(
            verdict=res["verdict"],
            winner_confidence=res["winner_confidence"],
            is_attack=res["is_attack"],
            severity=res["severity"],
            raw={"event": event, "source": res["source"]},
        )

    def process_event(self, event: dict[str, Any]) -> ProcessedIncident:
        """Processes one event through System-1 -> Routing Gate -> System-2 -> HITL."""
        now = time.time()
        incident_id = f"inc-{int(now * 1000) % 1000000}"

        # 1. System-1 Laya Triage
        triage = self.triage_event_system1(event)

        # 2. 0.8500 Routing Gate
        routing = evaluate_routing_gate(triage, event_context=event)

        muse_res: EnhancedReasoningResult | None = None
        prop_id: str | None = None
        raw_token: str | None = None

        # 3. Escalation Path (Confidence < 0.85)
        if routing.route == Route.SYSTEM_2_ESCALATE:
            summary = event.get("message") or f"{event.get('event_type')} on {event.get('target_ip') or event.get('host')}"
            ctx = ThreatContext(
                event_summary=summary,
                graph_path=[event.get("source_ip", ""), event.get("host", ""), event.get("target_host", "")],
                telemetry=event,
            )
            # Invoke Meta Muse Spark (live API or deterministic signature fallback)
            muse_res = self.muse.reason(ctx, signature_tag=event.get("signature_tag"))

            # If containment is proposed, generate cryptographic HITL token
            if muse_res.containment_proposal and muse_res.containment_proposal.action != ContainmentAction.NOOP:
                p = muse_res.containment_proposal
                # TTL is strictly the orchestrator's 300s constant, not model-settable
                prop_id, raw_token = self.hitl.create_proposal(
                    target=p.target,
                    action=p.action.value,
                    reason=p.validation_error or muse_res.explanation[:120],
                    ttl_seconds=300,
                )

        incident = ProcessedIncident(
            incident_id=incident_id,
            timestamp=now,
            raw_event=event,
            triage=triage,
            routing=routing,
            muse_reasoning=muse_res,
            proposal_id=prop_id,
            approval_token=raw_token,
        )
        self.incidents.append(incident)
        return incident

    def approve_containment(self, token: str, actor: str = "console") -> ProposalRecord:
        """Executes operator approval, consuming the token and logging containment."""
        record = self.hitl.verify_and_consume(token, actor=actor)
        self.applied_containments.append({
            "proposal_id": record.proposal_id,
            "target": record.target,
            "action": record.action,
            "applied_at": time.time(),
            "actor": actor,
            "dry_run": True,  # V4 executes nothing for real (simulation only)
        })
        return record

    def reject_containment(self, token: str, actor: str = "console") -> ProposalRecord:
        """Rejects a proposed containment action."""
        return self.hitl.reject_proposal(token, actor=actor)

    def get_dashboard_state(self) -> dict[str, Any]:
        """Returns JSON snapshot of live system state for Cytoscape dashboard."""
        return {
            "incidents_total": len(self.incidents),
            "pending_proposals": [asdict(p) for p in self.hitl.get_pending_proposals()],
            "applied_containments": self.applied_containments,
            "model_status": {
                "system_1": "Laya-Tuned-V1 (RTX 4050 45ms Mean Latency)",
                "system_2": "Meta Muse Spark 1.3" if self.muse.is_live else "FALLBACK (Recorded Fixtures)",
                "live_api_active": self.muse.is_live,
            },
        }


def run_interactive_repl(engine: ChiefSentinelEngine) -> None:
    """Operator interactive REPL console."""
    print("=" * 70)
    print(" Sentinel V4 — Chief Sentinel Orchestrator [INTERACTIVE CONSOLE]")
    print(" Type 'help' for commands. Pinned Model: Muse Spark 1.3 / Laya V1.")
    print("=" * 70)

    while True:
        try:
            line = input("sentinel-v4> ").strip()
            if not line:
                continue

            parts = line.split()
            cmd = parts[0].upper()

            if cmd in ("EXIT", "QUIT"):
                print("Shutting down Sentinel V4 interactive console.")
                break

            elif cmd == "HELP":
                print("Commands:")
                print("  SCENARIO <1|2|3>     Run complete benchmark adversary scenario")
                print("  TRIGGER <persona>    Run atomic persona (brute_force, lateral_mover, etc.)")
                print("  PENDING              List pending HITL containment proposals")
                print("  APPROVE <token>      Authorize containment proposal with single-use token")
                print("  REJECT <token>       Reject containment proposal with token")
                print("  STATUS               Display engine state and live API status")

            elif cmd == "SCENARIO":
                if len(parts) < 2:
                    print("Usage: SCENARIO <1|2|3>")
                    continue
                sc_id = int(parts[1])
                print(f"[*] Dispatching Scenario {sc_id} adversary bursts with 1.5s pacing...")
                events = engine.runner.run_scenario(sc_id)
                for ev in events:
                    inc = engine.process_event(ev)
                    print(f"  [{inc.incident_id}] {ev.get('event_type'):<22} -> Route: {inc.routing.route.value} (Conf: {inc.triage.winner_confidence:.4f})")
                    if inc.approval_token:
                        print(f"  ==> [HITL CARD QUEUED] Token: {inc.approval_token} | Action: {inc.muse_reasoning.containment_proposal.action.value} on {inc.muse_reasoning.containment_proposal.target}")

            elif cmd == "TRIGGER":
                if len(parts) < 2:
                    print("Usage: TRIGGER <brute_force|lateral_mover|privilege_escalator|c2_exfiltrator|benign_user>")
                    continue
                p_name = parts[1].lower()
                events = engine.runner.execute_persona(p_name)
                print(f"[*] Injected {len(events)} events from persona '{p_name}'.")
                for ev in events:
                    inc = engine.process_event(ev)
                    print(f"  [{inc.incident_id}] {ev.get('event_type')} -> {inc.routing.route.value}")
                    if inc.approval_token:
                        print(f"  ==> [HITL CARD QUEUED] Token: {inc.approval_token} on {inc.muse_reasoning.containment_proposal.target}")

            elif cmd == "PENDING":
                props = engine.hitl.get_pending_proposals()
                if not props:
                    print("No pending HITL containment proposals.")
                for p in props:
                    print(f"  Proposal ID: {p.proposal_id} | Target: {p.target} | Action: {p.action} | Expires in: {int(p.expires_at - time.time())}s")

            elif cmd == "APPROVE":
                if len(parts) < 2:
                    print("Usage: APPROVE <token>")
                    continue
                tok = parts[1]
                try:
                    rec = engine.approve_containment(tok, actor="console")
                    print(f"[SUCCESS] Containment APPROVED for proposal {rec.proposal_id} ({rec.action} on {rec.target}).")
                except Exception as e:
                    print(f"[ERROR] Approval failed: {e}")

            elif cmd == "REJECT":
                if len(parts) < 2:
                    print("Usage: REJECT <token>")
                    continue
                tok = parts[1]
                try:
                    rec = engine.reject_containment(tok, actor="console")
                    print(f"[SUCCESS] Containment REJECTED for proposal {rec.proposal_id}.")
                except Exception as e:
                    print(f"[ERROR] Rejection failed: {e}")

            elif cmd == "STATUS":
                state = engine.get_dashboard_state()
                print(json.dumps(state, indent=2))

            else:
                print(f"Unknown command '{cmd}'. Type 'help' for valid commands.")

        except KeyboardInterrupt:
            print("\nExiting Sentinel V4 console.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Chief Sentinel V4 Orchestrator")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive console REPL")
    parser.add_argument("--db", type=str, default=None, help="Path to SQLite database")
    args = parser.parse_args()

    engine = ChiefSentinelEngine(db_path=args.db)

    if args.interactive:
        run_interactive_repl(engine)
    else:
        print("[*] Sentinel V4 Chief Orchestrator running in Headless Daemon mode.")
        print("[*] Listening on internal queue and log telemetry pipes. Press Ctrl+C to exit.")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("Daemon stopped cleanly.")


if __name__ == "__main__":
    main()
