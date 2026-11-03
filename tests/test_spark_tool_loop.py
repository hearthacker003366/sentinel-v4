"""Tests for Meta Muse Spark System-2 multi-turn tool-call loop and recovery.

Verifies:
1. Multi-turn recovery from invalid/empty-arg tool calls (Nov 4 bug reproduction):
   - Round 1: Model returns tool call with empty arguments + prose.
   - Round 2: Tool validation error fed back; model retries with valid arguments.
   - Round 3: Model receives tool result and finalizes with typed ContainmentProposal.
2. Bounded budget exhaustion (max 6 rounds):
   - If model keeps emitting tool calls or fails to finalize within 6 rounds,
     finalizes loudly with validation_error / fallback_banner, never a silent NOOP.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model_adapter.client import (
    ContainmentAction,
    MuseSparkClient,
    ThreatContext,
)


def _sse_turn(content: str = "", tool_calls: list[dict] | None = None) -> str:
    """Builds a single-turn SSE response simulating Meta Model API stream."""
    choice: dict = {"delta": {}}
    if content:
        choice["delta"]["content"] = content
    if tool_calls is not None:
        choice["delta"]["tool_calls"] = tool_calls
    return (
        ": ping\n"
        f"data: {json.dumps({'choices': [choice]})}\n"
        "data: [DONE]\n"
    )


class TestSparkToolLoop(unittest.TestCase):
    def setUp(self):
        self.ctx = ThreatContext(
            event_summary="auth.log: 180 failed SSH logins from 192.168.56.20, then successful SMB to lab-dc-01",
            graph_path=["192.168.56.20", "lab-win10-03", "lab-dc-01"],
            telemetry={"host": "lab-win10-03", "source_ip": "192.168.56.20", "target_host": "lab-dc-01"},
        )
        self.client = MuseSparkClient(api_key="test-live-key")

    def test_live_style_tool_call_loop_recovers_from_empty_args_and_proposes_containment(self):
        """Reproduce Nov 4 live bug:
        Round 1: empty arguments on blue.threat_path + prose -> turn must NOT end.
        Round 2: error fed back -> model calls blue.threat_path with valid entity.
        Round 3: model finalizes with valid JSON containment proposal.
        """
        round1_sse = _sse_turn(
            content="I'll map this SMB lateral-movement path to kill-chain stages and identify the likely foothold.",
            tool_calls=[{
                "id": "call_empty_01",
                "type": "function",
                "function": {
                    "name": "blue.threat_path",
                    "arguments": "",  # Empty arguments trigger validation failure
                },
            }],
        )

        round2_sse = _sse_turn(
            content="",
            tool_calls=[{
                "id": "call_valid_02",
                "type": "function",
                "function": {
                    "name": "blue.threat_path",
                    "arguments": json.dumps({"entity": "lab-win10-03", "max_hops": 3}),
                },
            }],
        )

        final_verdict = {
            "explanation": "Threat Path Analysis: Host lab-win10-03 is the primary foothold used to pivot via SMB to lab-dc-01.",
            "containment_recommendation": {
                "action": "isolate_host",
                "target": "lab-win10-03",
                "reason": "Compromised workstation actively pivoting to domain controller",
                "dry_run": True,
                "reversible": True,
                "ttl_seconds": 3600,
            },
            "remediation_draft": "1. Reset admin credentials. 2. Enforce SMB signing.",
            "confidence": 0.94,
        }
        round3_sse = _sse_turn(content=json.dumps(final_verdict), tool_calls=[])

        call_sequence = [round1_sse, round2_sse, round3_sse]

        def mock_call_api(payload, max_retries=3):
            self.assertTrue(len(call_sequence) > 0, "Too many _call_api calls")
            return call_sequence.pop(0)

        with patch.object(self.client, "_call_api", side_effect=mock_call_api) as mocked_api:
            res = self.client.explain_threat_path(self.ctx)

        # Must have completed all 3 turns (recovering from turn 1's validation error)
        self.assertEqual(mocked_api.call_count, 3)

        # Proposal must NOT be NOOP / prose rejection
        self.assertIsNotNone(res.containment_proposal)
        self.assertEqual(res.containment_proposal.action, ContainmentAction.ISOLATE_HOST)
        self.assertEqual(res.containment_proposal.target, "lab-win10-03")
        self.assertIn("lab-win10-03", res.explanation)
        self.assertAlmostEqual(res.confidence, 0.94)

    def test_tool_call_loop_budget_exhaustion_loud_failure(self):
        """When 6-round budget exhausts without final JSON verdict:
        Must finalize with visible loud failure marker, never a quiet NOOP.
        """
        # Endless loop of invalid tool calls
        infinite_tool_sse = _sse_turn(
            content="Still analyzing...",
            tool_calls=[{
                "id": "call_loop",
                "type": "function",
                "function": {
                    "name": "blue.threat_path",
                    "arguments": "",
                },
            }],
        )

        with patch.object(self.client, "_call_api", return_value=infinite_tool_sse) as mocked_api:
            res = self.client.explain_threat_path(self.ctx)

        # Exactly 6 rounds bounded
        self.assertEqual(mocked_api.call_count, 6)

        # Must have loud failure markers
        self.assertIsNotNone(res.containment_proposal)
        self.assertIsNotNone(res.containment_proposal.validation_error)
        self.assertIn("exhausted", res.containment_proposal.validation_error.lower())
        self.assertIn("LOUD FAILURE", res.containment_recommendation)
        self.assertNotIn("No containment recommended", res.containment_recommendation)


if __name__ == "__main__":
    unittest.main()
