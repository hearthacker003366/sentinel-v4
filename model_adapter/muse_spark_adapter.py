"""Meta Muse Spark 1.3 Adapter with Live Token-Burning and Resilient Signature Fallback.

When META_MODEL_API_KEY or MUSE_API_KEY is present in the environment,
all escalated reasoning requests are streamed directly to the Meta Model API
(model: muse-spark-1.3), consuming real hackathon tokens.

When the key is missing or the endpoint is unreachable, the adapter seamlessly
pivots to deterministic scenario signature keying, prominently stamping:
`[WARNING] LIVE MODEL UNAVAILABLE — RECORDED RESPONSE`
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from .client import (
    MuseSparkClient,
    ThreatContext,
    ReasoningResult,
    ContainmentProposal,
    ContainmentAction,
    DEFAULT_TTL_SECONDS,
)

logger = logging.getLogger("sentinel.muse_spark_adapter")

FALLBACK_BANNER = "[WARNING] LIVE MODEL UNAVAILABLE — RECORDED RESPONSE"
FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "fixtures",
    "scenarios",
)


@dataclass
class EnhancedReasoningResult:
    explanation: str
    containment_recommendation: str
    remediation_draft: str
    confidence: float
    is_recorded_response: bool
    fallback_banner: str | None = None
    containment_proposal: ContainmentProposal | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class MuseSparkAdapter:
    """Production adapter for System-2 cognitive reasoning."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("META_MODEL_API_KEY") or os.environ.get("MUSE_API_KEY")
        self._client: MuseSparkClient | None = None
        self._live_available: bool = False

        if self.api_key:
            try:
                self._client = MuseSparkClient(api_key=self.api_key)
                self._live_available = True
                logger.info("Meta Model API live connection initialized (muse-spark-1.3).")
            except Exception as e:
                logger.warning("Failed to initialize live Meta client (%s). Using fallback engine.", e)
                self._live_available = False
        else:
            logger.info("No META_MODEL_API_KEY detected. Using deterministic signature fallback engine.")

    @property
    def is_live(self) -> bool:
        return self._live_available

    def reason(self, ctx: ThreatContext, signature_tag: str | None = None) -> EnhancedReasoningResult:
        """Executes reasoning: attempts live Meta API first, falls back to signature keying."""
        if self._live_available and self._client:
            try:
                res = self._client.explain_threat_path(ctx)
                return EnhancedReasoningResult(
                    explanation=res.explanation,
                    containment_recommendation=res.containment_recommendation,
                    remediation_draft=res.remediation_draft,
                    confidence=res.confidence,
                    is_recorded_response=False,
                    fallback_banner=None,
                    containment_proposal=res.containment_proposal,
                    raw=res.raw,
                )
            except Exception as e:
                logger.warning("Live Meta Model API call failed (%s). Engaging deterministic signature fallback.", e)

        # Fallback path: Deterministic Scenario Signature Keying
        return self._load_signature_fallback(ctx, signature_tag)

    def _load_signature_fallback(self, ctx: ThreatContext, signature_tag: str | None = None) -> EnhancedReasoningResult:
        """Matches event traits/tags to scenario fixtures."""
        print(f"\n{FALLBACK_BANNER}\n")

        # Determine scenario key from context
        text_corpus = (
            f"{ctx.event_summary} {' '.join(ctx.graph_path)} {json.dumps(ctx.telemetry)} {signature_tag or ''}"
        ).lower()

        if any(k in text_corpus for k in ("smb", "powershell", "lateral", "scenario_1", "192.168.56.20")):
            fixture_name = "scenario_1_muse_response.json"
        elif any(k in text_corpus for k in ("beacon", "dns", "egress", "scenario_2", "10.10.10.88", "c2")):
            fixture_name = "scenario_2_muse_response.json"
        elif any(k in text_corpus for k in ("benign", "vpn", "mfa", "patch", "scenario_3", "scanner")):
            fixture_name = "scenario_3_muse_response.json"
        else:
            # Default to Scenario 1 if completely unmapped
            fixture_name = "scenario_1_muse_response.json"

        fixture_path = os.path.join(FIXTURES_DIR, fixture_name)
        with open(fixture_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        prop_data = data.get("proposal")
        proposal = None
        if prop_data:
            proposal = ContainmentProposal(
                proposal_id=f"prop-fallback-{data['scenario_id']}",
                action=ContainmentAction(prop_data["action"]),
                target=prop_data["target"],
                ttl_seconds=DEFAULT_TTL_SECONDS,
                dry_run=True,
                reversible=True,
                is_executable=False,
            )

        return EnhancedReasoningResult(
            explanation=data["explanation"],
            containment_recommendation=data["containment_recommendation"],
            remediation_draft=data["remediation_draft"],
            confidence=data["confidence"],
            is_recorded_response=True,
            fallback_banner=FALLBACK_BANNER,
            containment_proposal=proposal,
            raw=data,
        )
