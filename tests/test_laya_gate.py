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
