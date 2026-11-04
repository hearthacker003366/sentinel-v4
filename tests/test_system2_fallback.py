import pytest
from model_adapter.client import ThreatContext
from model_adapter.muse_spark_adapter import (
    MuseSparkAdapter,
    FALLBACK_BANNER,
)


def test_system2_fallback_banner_and_signature_keying(monkeypatch, capsys):
    # Ensure no API keys exist in test environment
    monkeypatch.delenv("META_MODEL_API_KEY", raising=False)
    monkeypatch.delenv("MUSE_API_KEY", raising=False)

    adapter = MuseSparkAdapter(api_key=None)
    assert adapter.is_live is False

    # Scenario 1 Match: SMB + PowerShell
    ctx1 = ThreatContext(
        event_summary="SMB session established to lab-dc-01 followed by powershell execution",
        graph_path=["192.168.56.20", "lab-win10-03", "lab-dc-01"]
    )
    res1 = adapter.reason(ctx1)
    captured = capsys.readouterr()

    assert res1.is_recorded_response is True
    assert res1.fallback_banner == FALLBACK_BANNER
    assert FALLBACK_BANNER in captured.out
    assert "lab-win10-03" in res1.explanation
    assert res1.containment_proposal is not None
    assert res1.containment_proposal.target == "lab-win10-03"

    # Scenario 2 Match: C2 Beaconing
    ctx2 = ThreatContext(
        event_summary="Periodic C2 beaconing to 10.10.10.88:8443 and DNS entropy surge",
        telemetry={"dest": "10.10.10.88:8443", "ja3": "cobalt-strike"}
    )
    res2 = adapter.reason(ctx2)
    assert res2.is_recorded_response is True
    assert res2.containment_proposal.target == "10.10.10.88:8443"

    # Scenario 3 Match: Benign MFA
    ctx3 = ThreatContext(
        event_summary="Valid VPN login with verified MFA and scheduled vulnerability scanner",
        telemetry={"user": "prabhu", "mfa": True}
    )
    res3 = adapter.reason(ctx3)
    assert res3.is_recorded_response is True
    assert res3.containment_proposal is None
    assert "No containment recommended" in res3.containment_recommendation


def test_system2_unmapped_fallback_has_no_containment(monkeypatch):
    monkeypatch.delenv("META_MODEL_API_KEY", raising=False)
    monkeypatch.delenv("MUSE_API_KEY", raising=False)

    adapter = MuseSparkAdapter(api_key=None)
    assert adapter.is_live is False

    # Completely unmapped event (does not match SMB, beacon, benign, etc.)
    ctx_unmapped = ThreatContext(
        event_summary="completely unmapped random telemetry event foo bar baz",
        graph_path=[],
        telemetry={"random_field": "unknown_value"}
    )
    res = adapter.reason(ctx_unmapped, signature_tag="unknown-custom-tag")
    assert res.is_recorded_response is True
    assert res.containment_proposal is None
    assert "No containment" in res.containment_recommendation

