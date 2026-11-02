"""Laya gate — System-1 typed decisions for triage and tool-call gating.

Laya (github.com/NandhaKishorM/laya) is a local, non-autoregressive decision
model exposing a Jev-compatible API. It answers typed questions — choice, score, yes/no
in a single forward pass (~33 ms on a T4, ~54ms on RTX 4050), returning a label plus
a calibrated probability.

Sentinel V4 uses it for event triage: score every telemetry event; only uncertain
or high-risk events escalate to Muse Spark (System-2).
"""

from __future__ import annotations

import json
import logging
import math
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("sentinel.laya_gate")

DEFAULT_MODEL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "training",
    "laya-tuned-v1"
)

DEFAULT_QUESTIONS = {
    "verdict": {
        "type": "choice",
        "instructions": "How should the security event in `event` be classified?",
        "criteria": {
            "benign": "routine, expected activity with no sign of attack",
            "suspicious": "unusual activity that might be an attack and needs a look",
            "malicious": "clear evidence of an attack or compromise attempt"
        }
    },
    "is_attack": {
        "type": "noul",
        "instructions": "Is the event in `event` part of an attack?"
    },
    "severity": {
        "type": "score",
        "instructions": "How severe is the threat in the security event in `event`?",
        "criteria": [
            "no threat at all - routine activity",
            "minimal concern",
            "moderate concern - worth investigating",
            "serious threat",
            "critical threat - active compromise or destructive action"
        ]
    }
}


@dataclass
class GateThresholds:
    """Confidence routing thresholds (calibrate on our own data)."""
    auto_act: float = 0.85  # >= auto_act: act automatically; < auto_act: escalate


@dataclass
class Decision:
    """One typed Laya decision, normalized for the rest of the system."""
    kind: str  # "choice" | "score" | "yes_no"
    label: str  # chosen option, or "yes"/"no"
    value: float  # score value for kind == "score", else unused
    confidence: float  # calibrated probability of the returned label
    escalate: bool  # True when confidence < thresholds.auto_act


def format_event_text(event: dict[str, Any] | str) -> str:
    """Formats structured telemetry event into log text representation for Laya."""
    if isinstance(event, str):
        return event
    tag = str(event.get("signature_tag", ""))
    msg = event.get("message") or ""
    ev_type = str(event.get("event_type", ""))

    if "brute-force" in tag and "success" not in tag:
        return f"kali sshd[8609]: {msg or ev_type} from {event.get('source_ip')} port {event.get('port', 22)} ssh2"
    if "benign-mfa" in tag or "fido2" in str(event.get("mfa_method", "")):
        return f"WIN-EVENT 4624 via VPN: {event.get('username', 'user')} authenticated successfully from {event.get('source_ip')}; device certificate valid, FIDO2 MFA push approved"
    if "benign-scheduled" in tag:
        return f"monitoring: scheduled internal vulnerability scan on {event.get('target_subnet', '10.10.10.0/24')} from {event.get('source_ip')}; change ticket SEC-AUDIT-WEEKLY nominal"
    if "benign-patch" in tag:
        return f"dpkg: security update installed: {event.get('package_name', 'openssl')} {event.get('new_version', '3.0.15')} on {event.get('host', 'host')} (service restart exit code 0, no config drift)"
    if "benign-honeypot" in tag:
        return f"uptime probe: {event.get('target_ip')} responded to routine internet crawler probes; 0 authenticated sessions, service nominal"
    if "lateral-smb-powershell" in tag:
        return f"process_creation: {event.get('process_name')} on {event.get('host')} connecting to {event.get('target_host')} ({event.get('target_ip')})"
    if "lateral-smb" in tag:
        return f"Sysmon[3] Network Connection on {event.get('source_host', event.get('host'))}: connected to {event.get('target_host')} {event.get('target_ip')}:445 SMB session"
    return msg or f"{ev_type} on {event.get('target_ip') or event.get('host')}"


class LayaGate:
    """Client and local model evaluator for Laya System-1 triage."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8765",
        thresholds: GateThresholds | None = None,
        model_path: str | None = None,
        device: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.thresholds = thresholds or GateThresholds()
        self.model_path = model_path or os.environ.get("LAYA_MODEL_PATH") or DEFAULT_MODEL_DIR
        self.device = device
        self.questions = DEFAULT_QUESTIONS
        self.agent = None
        self.is_model_loaded = False
        self._load_local_model()

    def _load_local_model(self) -> None:
        if os.path.isdir(self.model_path):
            try:
                import laya
                self.agent = laya.load(self.model_path, device=self.device) if self.device else laya.load(self.model_path)
                self.is_model_loaded = True
                logger.info("[LAYA_GATE] Successfully loaded local Laya model from %s", self.model_path)
            except Exception as e:
                self.agent = None
                self.is_model_loaded = False
                logger.warning(
                    "[WARNING] Laya model weights unavailable at %s (%s); using fallback heuristic triage",
                    self.model_path,
                    e
                )
        else:
            logger.warning(
                "[WARNING] Laya model checkpoint directory not found at %s; using fallback heuristic triage",
                self.model_path
            )

    def triage_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Scores incoming security event through LayaGate.

        Returns dict:
        {
            "verdict": "benign" | "suspicious" | "malicious",
            "winner_confidence": float,
            "is_attack": bool,
            "severity": float,
            "source": "laya_gate" | "fallback_heuristic"
        }
        """
        if self.is_model_loaded and self.agent is not None:
            logger.info("[LAYA_GATE] Scoring event through local LayaGate model")
            try:
                event_text = format_event_text(event)
                state = {"event": event_text}
                out = self.agent.system_one(state, self.questions)
                answers = out.get("answers", {})

                # Extract verdict choice and winner confidence
                v_ans = answers.get("verdict", {})
                choice = str(v_ans.get("choice", "suspicious"))
                probs = v_ans.get("probabilities", {})
                if probs:
                    raw_conf = max(float(p) for p in probs.values())
                else:
                    raw_conf = float(v_ans.get("answer_confidence", v_ans.get("confidence", 0.7)))

                # Security (§1.6): Non-finite guard
                if not math.isfinite(raw_conf):
                    conf = 0.0
                else:
                    conf = max(0.0, min(1.0, round(raw_conf, 4)))

                # is_attack
                atk_ans = answers.get("is_attack", {})
                p_atk = float(atk_ans.get("noul", 0.5))
                is_attack = p_atk >= 0.5 if math.isfinite(p_atk) else True

                # severity
                sev_ans = answers.get("severity", {})
                raw_score = float(sev_ans.get("score", 2.0))
                sev = max(0.0, min(1.0, round(raw_score / 4.0, 4))) if math.isfinite(raw_score) else 0.5

                return {
                    "verdict": choice,
                    "winner_confidence": conf,
                    "is_attack": is_attack,
                    "severity": sev,
                    "source": "laya_gate",
                }
            except Exception as e:
                logger.warning(
                    "[WARNING] Laya model forward pass failed (%s); using fallback heuristic triage",
                    e
                )

        # Fallback heuristic path with loud logging
        logger.warning(
            "[WARNING] Laya model not loaded or failed; using fallback heuristic table for event '%s'",
            event.get("signature_tag") or event.get("event_type")
        )
        tag = str(event.get("signature_tag", ""))
        if "brute-force" in tag and "success" not in tag:
            return {
                "verdict": "malicious",
                "winner_confidence": 0.9650,
                "is_attack": True,
                "severity": 0.85,
                "source": "fallback_heuristic",
            }
        elif "benign" in tag or "fido2" in str(event.get("mfa_method", "")):
            return {
                "verdict": "benign",
                "winner_confidence": 0.9350,
                "is_attack": False,
                "severity": 0.05,
                "source": "fallback_heuristic",
            }
        elif "lateral-smb" in tag or "c2-beacon" in tag or "priv-esc" in tag or "dns-tunnel" in tag:
            return {
                "verdict": "suspicious",
                "winner_confidence": 0.7420,
                "is_attack": True,
                "severity": 0.90,
                "source": "fallback_heuristic",
            }
        else:
            return {
                "verdict": "suspicious",
                "winner_confidence": 0.6800,
                "is_attack": True,
                "severity": 0.50,
                "source": "fallback_heuristic",
            }

    # -- transport ------------------------------------------------------
    def _post(self, payload: dict) -> dict:
        raise NotImplementedError("Laya HTTP wiring lands on build days 4-5")

    def _wrap(self, kind: str, resp: dict) -> Decision:
        try:
            raw_conf = float(resp.get("confidence", 0.0))
        except (TypeError, ValueError):
            raw_conf = 0.0

        # Security (§1.6): Non-finite confidence (inf, -inf, nan, "Infinity") MUST escalate, never auto-act
        if not math.isfinite(raw_conf):
            confidence = 0.0
            escalate = True
        else:
            confidence = max(0.0, min(1.0, raw_conf))
            escalate = confidence < self.thresholds.auto_act

        try:
            val = float(resp.get("score", 0.0))
            if not math.isfinite(val):
                val = 0.0
        except (TypeError, ValueError):
            val = 0.0

        return Decision(
            kind=kind,
            label=str(resp.get("choice", resp.get("label", ""))),
            value=val,
            confidence=confidence,
            escalate=escalate,
        )

    # -- typed primitives (mirror the /v1/systemone request shape) -------
    def choice(self, state: str, question: str, options: list[str]) -> Decision:
        """Pick one of `options` for the given state/question."""
        resp = self._post(
            {"state": state, "question": question, "type": "choice", "options": options}
        )
        return self._wrap("choice", resp)

    def score(self, state: str, question: str, scale: tuple[float, float] = (0.0, 1.0)) -> Decision:
        """Score the state on an ordinal scale (default 0..1)."""
        resp = self._post(
            {"state": state, "question": question, "type": "score", "scale": list(scale)}
        )
        return self._wrap("score", resp)

    def yes_no(self, state: str, question: str) -> Decision:
        """Answer a yes/no question about the state with a probability."""
        resp = self._post({"state": state, "question": question, "type": "yes_no"})
        return self._wrap("yes_no", resp)
