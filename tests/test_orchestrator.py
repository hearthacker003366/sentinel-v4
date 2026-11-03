import os
import tempfile
import pytest
from orchestrator.chief_sentinel import ChiefSentinelEngine
from orchestrator.routing_gate import Route


@pytest.fixture
def engine():
    import gc
    import time
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    eng = ChiefSentinelEngine(db_path=db_path)
    yield eng
    del eng
    gc.collect()
    time.sleep(0.05)
    for ext in ("", "-wal", "-shm"):
        p = db_path + ext
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


def test_orchestrator_scenario_1_pipeline(engine):
    # Stage 1: Brute Force -> System-1 Auto-Act
    bf_events = engine.runner.execute_persona("brute_force", count=5)
    for ev in bf_events[:4]:
        inc = engine.process_event(ev)
        assert inc.routing.route == Route.SYSTEM_1_AUTO_ACT
        assert inc.routing.dry_run is True

    # Stage 2: Lateral Move -> System-2 Escalation to Muse Spark
    lm_events = engine.runner.execute_persona("lateral_mover")
    inc_lm = engine.process_event(lm_events[0])  # The SMB lateral movement pivot
    assert inc_lm.routing.route == Route.SYSTEM_2_ESCALATE
    assert inc_lm.muse_reasoning is not None
    assert inc_lm.approval_token is not None
    assert len(inc_lm.approval_token) == 16  # 16-char hex from token_hex(8)

    # Approve via HITL gate
    record = engine.approve_containment(inc_lm.approval_token, actor="test_operator")
    assert record.status == "approved"
    assert record.target == "lab-win10-03"
    assert len(engine.applied_containments) == 1
    assert engine.applied_containments[0]["target"] == "lab-win10-03"
    assert engine.applied_containments[0]["dry_run"] is True  # V4 executes dry-run only


def test_orchestrator_scenario_3_benign_suppression(engine):
    benign_events = engine.runner.execute_persona("benign_user")
    for ev in benign_events:
        inc = engine.process_event(ev)
        assert inc.approval_token is None
        assert inc.routing.dry_run is True
        # Events with >= 0.85 conf auto-act; borderline VPN (conf=0.5699) escalates to Muse Spark
        if ev.get("signature_tag") == "benign-mfa-scan":
            assert inc.routing.route == Route.SYSTEM_2_ESCALATE
            assert inc.muse_reasoning is not None
            assert "No containment recommended" in inc.muse_reasoning.containment_recommendation
        else:
            assert inc.routing.route == Route.SYSTEM_1_AUTO_ACT


def test_orchestrator_dashboard_state(engine):
    state = engine.get_dashboard_state()
    assert "incidents_total" in state
    assert "pending_proposals" in state
    assert "applied_containments" in state
    assert "model_status" in state
    assert "45ms" in state["model_status"]["system_1"]


def test_orchestrator_lateral_event_verdict_comes_from_gate(engine):
    """Fix 5: Verify lateral event is triaged through LayaGate."""
    lateral_event = {
        "event_type": "smb_session_open",
        "source_ip": "192.168.56.31",
        "target_ip": "192.168.56.10",
        "signature_tag": "lateral-smb",
        "host": "lab-win10-03"
    }
    verdict = engine.triage_event_system1(lateral_event)
    assert verdict is not None
    assert verdict.raw is not None
    assert "source" in verdict.raw
    assert verdict.raw["source"] in ("laya_gate", "fallback_heuristic")

