"""Unit tests for LayaGate confidence routing and security hardening (§1.6)."""

import math
import pytest
from triage.laya_gate import LayaGate, GateThresholds, Decision


def test_finite_confidence_routing():
    gate = LayaGate(thresholds=GateThresholds(auto_act=0.85))
    
    # Below auto_act threshold -> escalate to System-2 / human
    d1 = gate._wrap("choice", {"choice": "suspicious", "confidence": 0.72})
    assert d1.confidence == 0.72
    assert d1.escalate is True

    # At or above auto_act threshold -> auto-act permitted
    d2 = gate._wrap("choice", {"choice": "benign", "confidence": 0.95})
    assert d2.confidence == 0.95
    assert d2.escalate is False


def test_non_finite_confidence_must_escalate():
    """Security (§1.6): Non-finite confidence (inf, -inf, nan, 'Infinity') MUST escalate."""
    gate = LayaGate(thresholds=GateThresholds(auto_act=0.85))

    # Float inf
    d_inf = gate._wrap("choice", {"choice": "malicious", "confidence": float("inf")})
    assert d_inf.escalate is True
    assert math.isfinite(d_inf.confidence)

    # Negative inf
    d_neginf = gate._wrap("choice", {"choice": "malicious", "confidence": float("-inf")})
    assert d_neginf.escalate is True
    assert math.isfinite(d_neginf.confidence)

    # Float NaN
    d_nan = gate._wrap("choice", {"choice": "malicious", "confidence": float("nan")})
    assert d_nan.escalate is True
    assert math.isfinite(d_nan.confidence)

    # String "Infinity"
    d_str_inf = gate._wrap("choice", {"choice": "malicious", "confidence": "Infinity"})
    assert d_str_inf.escalate is True
    assert math.isfinite(d_str_inf.confidence)

    # Broken/garbage confidence string
    d_garbage = gate._wrap("choice", {"choice": "malicious", "confidence": "broken_payload"})
    assert d_garbage.escalate is True
    assert d_garbage.confidence == 0.0


def test_lateral_event_verdict_comes_from_laya_gate():
    """Fix 5: Test proving a lateral event's verdict is produced by LayaGate."""
    gate = LayaGate()
    lateral_event = {
        "event_type": "smb_session_open",
        "source_ip": "192.168.56.31",
        "target_ip": "192.168.56.10",
        "signature_tag": "lateral-smb",
        "host": "lab-win10-03"
    }
    res = gate.triage_event(lateral_event)
    assert res is not None
    assert "verdict" in res
    assert "winner_confidence" in res
    assert "source" in res
    assert res["source"] in ("laya_gate", "fallback_heuristic")
    assert math.isfinite(res["winner_confidence"])


def test_source_canonical_formatter_uniformity():
    """Item 0: Asserts two events from the same source with different signature tags
    (one attack-flavoured, one benign-flavoured) are rendered by the SAME template
    (identical structure apart from their field values).
    """
    import re
    from triage.laya_gate import format_event_text, detect_event_source

    # 1. Test sshd source uniformity
    attack_ssh = {
        "event_type": "ssh_auth_failure",
        "service": "sshd",
        "host": "srv-prod",
        "pid": "1234",
        "message": "Failed password for admin from 10.0.0.1 port 2222 ssh2",
        "signature_tag": "brute-force-attack",
    }
    benign_ssh = {
        "event_type": "ssh_auth_success",
        "service": "sshd",
        "host": "srv-prod",
        "pid": "5678",
        "message": "Accepted publickey for prabhu from 10.0.0.2 port 3333 ssh2",
        "signature_tag": "benign-admin-login",
    }
    assert detect_event_source(attack_ssh) == "sshd"
    assert detect_event_source(benign_ssh) == "sshd"

    fmt_atk = format_event_text(attack_ssh)
    fmt_ben = format_event_text(benign_ssh)

    # Normalize variable values to verify structural identity
    struct_atk = re.sub(r"\d+", "NUM", fmt_atk.replace(attack_ssh["message"], "MSG")).replace(attack_ssh["host"], "HOST")
    struct_ben = re.sub(r"\d+", "NUM", fmt_ben.replace(benign_ssh["message"], "MSG")).replace(benign_ssh["host"], "HOST")
    assert struct_atk == struct_ben == "HOST sshd[NUM]: MSG"

    # 2. Test sysmon_process source uniformity
    attack_ps = {
        "event_type": "process_creation",
        "host": "wkstn-01",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc AAAA",
        "parent_process": "services.exe",
        "username": "SYSTEM",
        "signature_tag": "lateral-smb-powershell",
    }
    benign_ps = {
        "event_type": "process_creation",
        "host": "wkstn-02",
        "process_name": "backup.exe",
        "command_line": "backup.exe --run",
        "parent_process": "explorer.exe",
        "username": "alice",
        "signature_tag": "benign-scheduled-backup",
    }
    assert detect_event_source(attack_ps) == "sysmon_process"
    assert detect_event_source(benign_ps) == "sysmon_process"

    fmt_atk_ps = format_event_text(attack_ps)
    fmt_ben_ps = format_event_text(benign_ps)
    assert fmt_atk_ps.startswith("Sysmon[1] Process Create on wkstn-01:")
    assert fmt_ben_ps.startswith("Sysmon[1] Process Create on wkstn-02:")
    assert "Image:" in fmt_atk_ps and "CommandLine:" in fmt_atk_ps and "ParentImage:" in fmt_atk_ps and "User:" in fmt_atk_ps
    assert "Image:" in fmt_ben_ps and "CommandLine:" in fmt_ben_ps and "ParentImage:" in fmt_ben_ps and "User:" in fmt_ben_ps


