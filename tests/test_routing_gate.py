import pytest
from orchestrator.routing_gate import (
    evaluate_routing_gate,
    TriageVerdict,
    Route,
    GATE_THRESHOLD,
)


def test_gate_boundary_exact_0_85():
    # Exactly 0.8500 -> System-1 auto-act
    t_exact = TriageVerdict(
        verdict="malicious",
        winner_confidence=0.8500,
        is_attack=True,
        severity=0.8
    )
    dec_exact = evaluate_routing_gate(t_exact, {"host": "lab-win10-03"})
    assert dec_exact.route == Route.SYSTEM_1_AUTO_ACT
    assert dec_exact.dry_run is True

    # Just below: 0.8499 -> System-2 escalate
    t_below = TriageVerdict(
        verdict="malicious",
        winner_confidence=0.8499,
        is_attack=True,
        severity=0.8
    )
    dec_below = evaluate_routing_gate(t_below, {"host": "lab-win10-03"})
    assert dec_below.route == Route.SYSTEM_2_ESCALATE
    assert dec_below.dry_run is True


def test_system1_auto_act_is_dry_run_only():
    t_high = TriageVerdict(
        verdict="malicious",
        winner_confidence=0.9600,
        is_attack=True,
        severity=0.9
    )
    dec = evaluate_routing_gate(t_high, {"source_ip": "192.168.56.20"})
    assert dec.route == Route.SYSTEM_1_AUTO_ACT
    assert dec.dry_run is True  # Immutable safety invariant
    assert "dry-run" in dec.reason.lower()


def test_system1_benign_suppression():
    t_benign = TriageVerdict(
        verdict="benign",
        winner_confidence=0.9200,
        is_attack=False,
        severity=0.0
    )
    dec = evaluate_routing_gate(t_benign, {"host": "lab-db-01"})
    assert dec.route == Route.SYSTEM_1_AUTO_ACT
    assert dec.action_type == "log_benign"
    assert dec.dry_run is True
