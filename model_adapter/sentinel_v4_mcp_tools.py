"""
Sentinel V4 — MCP tool-schema starter pack (DRAFT for review).

Drop this into the `model_adapter/` / orchestrator layer of your sentinel-v4
skeleton. It is the *contract* Muse Spark will call through — keep it stable
once calibrated, because the red-team replay harness and the dashboard will
depend on these shapes.

    sentinel-v4/
      model_adapter/
        __init__.py
        sentinel_v4_mcp_tools.py   # this file

Design contract (frozen architecture, Oct 18 runbook):
  - `blue.*`  — defender/orchestrator tools (telemetry, threat graph, containment)
  - `red.*`   — red-team bot tools, HARD-SCOPED to the simulated lab network
  - `hitl.*`  — human-in-the-loop approvals via the Telegram gateway

Safety invariants baked into every schema:
  1. Every mutating tool defaults to dry_run=true. Real action needs the
     explicit env gate (same pattern as V3's ALLOW_REAL_CONTAINMENT).
  2. Containment is REVERSIBLE and EXPIRING — a proposal carries ttl_seconds
     and auto-rolls back unless the human confirms.
  3. Red-team tools refuse any target outside SENTINEL_LAB_CIDRS (RFC1918
     defaults). Lab-only, always — this is your "lab-only, dry-run default" safe simulation architecture for the judges.
  4. Every event carries a trace_id (see TRACE_ID format) so the dashboard,
     replay harness and audit log can join red actions to blue responses.

Meta Model API gotchas to respect when wiring the adapter (from research):
  - tool_choice supports "auto" only — design prompts so the model reaches
    for tools naturally instead of forcing specific ones.
  - SSE streaming emits a non-standard event — handle it in the adapter
    before you blame your client code.
  - Pin these schemas. A provider-side field rename mid-build silently
    breaks triage (NeetroX warning, Oct 17). Version the registry below.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from typing import Any, Dict, List

TOOL_REGISTRY_VERSION = "0.1.0-draft"  # bump on any schema change; replay harness pins this

# ---------------------------------------------------------------------------
# Safety: lab scope. Red-team tools MUST refuse anything outside these CIDRs.
# Narrowed strictly to simulated lab networks (VirtualBox host-only + isolated range).
# Hard-coded per frozen lab network simulation boundaries.
# ---------------------------------------------------------------------------
LAB_CIDRS = [
    ipaddress.ip_network("192.168.56.0/24"),
    ipaddress.ip_network("10.10.10.0/24"),
]

# Every event the orchestrator emits carries one of these, e.g.
# "st4-20261019-7f3a9c". Dashboard + replay harness join on it.
TRACE_ID_RE = re.compile(r"^st4-\d{8}-[0-9a-f]{6}$")


def in_lab_scope(target: str) -> bool:
    """True only if the target is a literal IP address inside the lab CIDRs (§1.4).

    Call this inside EVERY red.* implementation before touching the network.
    Hostnames are denied outright to prevent DNS rebinding attacks.
    """
    try:
        ip = ipaddress.ip_address(target)
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in LAB_CIDRS)


def validate_trace_id(trace_id: str) -> bool:
    r"""Validate that trace_id conforms to ^st4-\d{8}-[0-9a-f]{6}$ format (§1.4)."""
    if not isinstance(trace_id, str):
        return False
    return bool(TRACE_ID_RE.match(trace_id))


# ---------------------------------------------------------------------------
# JSON Schemas — one per tool. Keep descriptions short; the model reads them.
# ---------------------------------------------------------------------------

BLUE_GET_ALERTS = {
    "name": "blue.get_alerts",
    "description": "Pull triaged alerts from the Laya System-1 layer, newest first.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "min_severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "default": "medium"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            "trace_id": {"type": "string", "description": "Filter to one investigation thread"},
        },
        "required": [],
    },
}

BLUE_THREAT_PATH = {
    "name": "blue.threat_path",
    "description": "Explain the predicted lateral-movement path for an entity using the NetworkX threat graph (kill-chain stages).",
    "inputSchema": {
        "type": "object",
        "properties": {
            "entity": {"type": "string", "description": "Host, user, or IP under investigation"},
            "max_hops": {"type": "integer", "minimum": 1, "maximum": 6, "default": 3},
        },
        "required": ["entity"],
    },
}

BLUE_PROPOSE_CONTAINMENT = {
    "name": "blue.propose_containment",
    "description": "Draft a REVERSIBLE, EXPIRING containment action. Always dry-run first; returns a proposal_id for HITL approval.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host/IP to contain"},
            "action": {"type": "string", "enum": ["isolate_host", "block_ip", "kill_process", "disable_account", "snapshot_first"]},
            "reason": {"type": "string"},
            "ttl_seconds": {"type": "integer", "minimum": 60, "maximum": 86400, "default": 3600,
                            "description": "Auto-rollback after this long unless the human confirms"},
            "trace_id": {"type": "string"},
        },
        "required": ["target", "action", "reason"],
    },
}

HITL_REQUEST_APPROVAL = {
    "name": "hitl.request_approval",
    "description": "Send a containment proposal to the human via the Telegram approval gateway. Returns approval_id; the orchestrator polls hitl.approval_status.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "proposal_id": {"type": "string"},
            "summary": {"type": "string", "description": "One-line, human-readable summary for the Telegram message"},
            "risk": {"type": "string", "enum": ["low", "medium", "high"]},
        },
        "required": ["proposal_id", "summary"],
    },
}

HITL_APPROVAL_STATUS = {
    "name": "hitl.approval_status",
    "description": "Check a pending Telegram approval: approved | denied | expired | pending.",
    "inputSchema": {
        "type": "object",
        "properties": {"approval_id": {"type": "string"}},
        "required": ["approval_id"],
    },
}

BLUE_APPLY_CONTAINMENT = {
    "name": "blue.apply_containment",
    "description": "Execute an approved containment. REQUIRES a valid approval_id unless dry_run=true. Refuses without one.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "proposal_id": {"type": "string"},
            "approval_id": {"type": "string", "description": "From hitl.request_approval; omit only with dry_run=true"},
            "dry_run": {"type": "boolean", "default": True},
        },
        "required": ["proposal_id"],
    },
}

BLUE_REVOKE_CONTAINMENT = {
    "name": "blue.revoke_containment",
    "description": "Roll back a containment (manual revoke or TTL expiry handler).",
    "inputSchema": {
        "type": "object",
        "properties": {"proposal_id": {"type": "string"}, "reason": {"type": "string", "default": "manual revoke"}},
        "required": ["proposal_id"],
    },
}

BLUE_QUERY_TELEMETRY = {
    "name": "blue.query_telemetry",
    "description": "Look up lab telemetry (flows, process events, auth logs) for an entity and time window.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "entity": {"type": "string"},
            "window_minutes": {"type": "integer", "minimum": 1, "maximum": 1440, "default": 30},
            "trace_id": {"type": "string"},
        },
        "required": ["entity"],
    },
}

RED_LIST_LAB_TARGETS = {
    "name": "red.list_lab_targets",
    "description": "List in-scope targets in the SIMULATED lab network. The ONLY discovery entry point for red-team bots.",
    "inputSchema": {
        "type": "object",
        "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}},
        "required": [],
    },
}

RED_RUN_RECON = {
    "name": "red.run_recon",
    "description": "Run one recon step (subfinder/dnsx/httpx/nuclei pattern) against a lab target. REFUSES out-of-scope targets.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Must be inside SENTINEL_LAB_CIDRS or the call is denied"},
            "technique": {"type": "string", "enum": ["subdomain_enum", "port_scan", "service_probe", "vuln_scan"]},
            "trace_id": {"type": "string"},
        },
        "required": ["target", "technique"],
    },
}

RED_REPORT_FINDING = {
    "name": "red.report_finding",
    "description": "Submit a red-team finding to the chief sentinel orchestrator (telemetry contract: what/where/how-severe/evidence).",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "technique": {"type": "string"},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "evidence": {"type": "string", "description": "Commands run + outputs observed, trimmed"},
            "owasp_llm_mapping": {"type": "string", "description": "e.g. LLM05:2025 if the finding touches model behaviour"},
            "trace_id": {"type": "string"},
        },
        "required": ["target", "technique", "severity", "evidence"],
    },
}

RED_KILL_SWITCH = {
    "name": "red.kill_switch",
    "description": "Immediately stop ALL red-team bot activity. Human or orchestrator can invoke at any time.",
    "inputSchema": {"type": "object", "properties": {"reason": {"type": "string", "default": "manual stop"}}, "required": []},
}

TOOLS: List[Dict[str, Any]] = [
    BLUE_GET_ALERTS,
    BLUE_THREAT_PATH,
    BLUE_PROPOSE_CONTAINMENT,
    HITL_REQUEST_APPROVAL,
    HITL_APPROVAL_STATUS,
    BLUE_APPLY_CONTAINMENT,
    BLUE_REVOKE_CONTAINMENT,
    BLUE_QUERY_TELEMETRY,
    RED_LIST_LAB_TARGETS,
    RED_RUN_RECON,
    RED_REPORT_FINDING,
    RED_KILL_SWITCH,
]


def tool_names() -> List[str]:
    return [t["name"] for t in TOOLS]


if __name__ == "__main__":
    # Smoke check: registry is well-formed and lab-scope gate behaves.
    assert len(TOOLS) == 12, f"expected 12 tools, got {len(TOOLS)}"
    assert all(set(t) == {"name", "description", "inputSchema"} for t in TOOLS)
    assert in_lab_scope("192.168.56.10") and in_lab_scope("10.10.10.21")
    assert not in_lab_scope("10.1.2.3") and not in_lab_scope("192.168.1.10")
    assert not in_lab_scope("103.21.244.9") and not in_lab_scope("45.148.10.88")
    assert not in_lab_scope("10.10.4.5") and not in_lab_scope("8.8.8.8") and not in_lab_scope("not-an-ip")
    print(f"OK — registry v{TOOL_REGISTRY_VERSION}: {len(TOOLS)} tools, lab gate sane.")
    print("Tools:", ", ".join(tool_names()))
