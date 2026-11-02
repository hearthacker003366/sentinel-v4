import pytest
from redteam.bot import (
    RedTeamRunner,
    ScopeViolation,
    assert_in_scope,
    PERSONA_REGISTRY,
)


def test_atomic_trigger_determinism():
    runner = RedTeamRunner(pacing_s=1.0)
    for key, persona in PERSONA_REGISTRY.items():
        events = runner.execute_persona(key)
        assert isinstance(events, list)
        assert len(events) > 0
        for ev in events:
            assert "event_type" in ev
            assert "timestamp" in ev
            assert "signature_tag" in ev


def test_lab_scope_violation_raised():
    # External IP (Google DNS)
    with pytest.raises(ScopeViolation):
        assert_in_scope("8.8.8.8")

    # Bench Phase-0 IP outside lab
    with pytest.raises(ScopeViolation):
        assert_in_scope("103.21.244.9")

    # In-scope IPs must pass
    assert str(assert_in_scope("192.168.56.20")) == "192.168.56.20"
    assert str(assert_in_scope("10.10.10.88")) == "10.10.10.88"
    assert str(assert_in_scope("10.10.10.99")) == "10.10.10.99"


def test_persona_out_of_scope_rejection():
    runner = RedTeamRunner(pacing_s=1.0)
    # Attempting to brute-force an out-of-scope target must raise ScopeViolation
    with pytest.raises(ScopeViolation):
        runner.execute_persona("brute_force", target_ip="8.8.8.8")


def test_scenario_execution_scope():
    runner = RedTeamRunner(pacing_s=1.0)
    # Scenario 2 (C2 exfiltration) sinks strictly inside 10.10.10.0/24
    events_s2 = runner.run_scenario(2)
    assert len(events_s2) == 3
    for ev in events_s2:
        dest = ev.get("dest_ip")
        if dest:
            assert dest.startswith("10.10.10.")
