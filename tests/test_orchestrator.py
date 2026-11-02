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
    inc_lm = engine.process_event(lm_events[1])  # The powershell execution
    assert inc_lm.routing.route == Route.SYSTEM_2_ESCALATE
    assert inc_lm.muse_reasoning is not None
    assert inc_lm.approval_token is not None
    assert len(inc_lm.approval_token) == 8

    # Approve via HITL gate
    record = engine.approve_containment(inc_lm.approval_token, actor="test_operator")
    assert record.status == "approved"
    assert record.target == "lab-win10-03"
    assert len(engine.applied_containments) == 1
    assert engine.applied_containments[0]["target"] == "lab-win10-03"


def test_orchestrator_scenario_3_benign_suppression(engine):
    benign_events = engine.runner.execute_persona("benign_user")
    for ev in benign_events:
        inc = engine.process_event(ev)
        assert inc.routing.route == Route.SYSTEM_1_AUTO_ACT
        assert inc.routing.dry_run is True
        assert inc.approval_token is None


def test_orchestrator_dashboard_state(engine):
    state = engine.get_dashboard_state()
    assert "incidents_total" in state
    assert "pending_proposals" in state
    assert "applied_containments" in state
    assert "model_status" in state
    assert "45ms" in state["model_status"]["system_1"]
