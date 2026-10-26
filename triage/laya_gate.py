"""Laya gate — System-1 typed decisions for triage and tool-call gating.

Laya (github.com/NandhaKishorM/laya) is a local, non-autoregressive decision
model exposing a Jev-compatible HTTP API at `/v1/systemone`. It answers typed
questions — choice, score, yes/no — in a single forward pass (~33 ms on a
T4), returning a label plus a calibrated probability.

Sentinel V4 uses it for exactly two jobs:
1. Event triage: score every telemetry event; only uncertain or high-risk
   events escalate to Muse Spark (System-2).
2. Tool-call gating: score a proposed containment action before it is even
   drafted for human approval.

Laya NEVER makes final judgments. Below the confidence threshold, the case
escalates — that is a design rule, not a fallback.

TODO (Phase 1, days 4-5):
- Implement the HTTP calls (pin the Laya version + checkpoint revision).
- Calibrate thresholds on Sentinel V3 demo data; the defaults below are the
  repo's rule of thumb, not tuned values.
- Add caching: identical states should not be re-scored.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class GateThresholds:
    """Confidence routing thresholds (calibrate on our own data)."""

    auto_act: float = 0.85  # >= auto_act: act automatically
    # < auto_act: escalate to Muse Spark / human


@dataclass
class Decision:
    """One typed Laya decision, normalized for the rest of the system."""

    kind: str  # "choice" | "score" | "yes_no"
    label: str  # chosen option, or "yes"/"no"
    value: float  # score value for kind == "score", else unused
    confidence: float  # calibrated probability of the returned label
    escalate: bool  # True when confidence < thresholds.auto_act


class LayaGate:
    """Thin client for a locally served Laya instance."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8765",
        thresholds: GateThresholds | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.thresholds = thresholds or GateThresholds()

    # -- transport ------------------------------------------------------
    def _post(self, payload: dict) -> dict:
        # TODO: POST {base_url}/v1/systemone with `payload`; return JSON.
        raise NotImplementedError("Laya HTTP wiring lands on build days 4-5")

    def _wrap(self, kind: str, resp: dict) -> Decision:
        confidence = float(resp.get("confidence", 0.0))
        return Decision(
            kind=kind,
            label=str(resp.get("choice", resp.get("label", ""))),
            value=float(resp.get("score", 0.0)),
            confidence=confidence,
            escalate=confidence < self.thresholds.auto_act,
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
