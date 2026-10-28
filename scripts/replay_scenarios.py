#!/usr/bin/env python3
"""Sentinel V4 — Days 2-3 three-scenario replay harness.

Feeds each demo scenario from docs/sentinel-v4-days2-3-scenarios.md (in order
1 -> 2 -> 3) as ThreatContext into MuseSparkClient, intercepts and logs every
tool call the model emits, evaluates the verdict against pass/fail criteria,
prints a summary table, and exits non-zero if any scenario fails.

Modes:
  offline (default) — deterministic recorded SSE verdicts injected at the
      _call_api seam (no network, no key). Proves harness + adapter wiring
      (prompt -> SSE extract -> parse -> evaluate), NOT live model judgment.
  live — real MuseSparkClient._reason calls (needs META_MODEL_API_KEY or
      MUSE_API_KEY in env). Non-deterministic; the true Days 2-3 criterion.

Usage:
  python scripts/replay_scenarios.py [--mode offline|live] [--scenario 1|2|3]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Callable
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model_adapter.client import MuseSparkClient, ReasoningResult, ThreatContext

# ---------------------------------------------------------------------------
# Fixture builder: recorded SSE (with transport noise) -> deterministic verdict.
# ---------------------------------------------------------------------------

def _sse_fixture(verdict: dict[str, Any], tools: list[tuple[str, dict[str, Any]]]) -> str:
    calls = [
        {"id": f"call_{i:02d}", "type": "function",
         "function": {"name": name, "arguments": json.dumps(args)}}
        for i, (name, args) in enumerate(tools, 1)
    ]
    lines = [
        ": ping", "", "event: ping",
        "data: " + json.dumps({"choices": [{"delta": {"tool_calls": calls}}]}),
        "",
        "data: " + json.dumps({"choices": [{"delta": {"content": json.dumps(verdict)}}]}),
        "data: [DONE]",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Scenario inputs (alert text verbatim from the Days 2-3 scenario pack).
# ---------------------------------------------------------------------------

S1_SUMMARY = """\
auth.log: 180 failed SSH logins for user `admin` from 192.168.56.20 in 4 minutes, \
then one successful login from the same IP.
EDR: host lab-win10-03 (192.168.56.31) opened an SMB session to lab-dc-01 \
(192.168.56.10), then spawned `powershell -enc <base64>` within 40 s of that login."""

S1_VERDICT = {
    "explanation": "## Brute force -> lateral movement\nKill chain: `192.168.56.20 -> lab-win10-03 -> lab-dc-01` "
        "(initial access via SSH brute force, execution via SMB + encoded PowerShell, lateral movement toward the DC). "
        "The `powershell -enc` within 40 s of the first success implies post-exploitation staging on lab-win10-03; "
        "the DC shows no execution yet, so the workstation is the foothold to contain first.",
    "containment_recommendation": "isolate_host lab-win10-03 (isolate the workstation first, NOT the DC), "
        "disable/reset `admin` credentials, preserve EDR evidence before isolation.",
    "remediation_draft": "Reset `admin` credentials everywhere; harden SMB (signing, lateral-movement rules); "
        "add detection for brute-force -> success -> SMB within 5 minutes.",
    "confidence": 0.87,
}
S1_TOOLS = [
    ("blue.get_alerts", {"min_severity": "high"}),
    ("blue.threat_path", {"entity": "lab-win10-03", "max_hops": 3}),
    ("blue.propose_containment", {"target": "lab-win10-03", "action": "isolate_host",
                                  "reason": "likely foothold; SMB + encoded PS after brute force"}),
    ("hitl.request_approval", {"proposal_id": "prop-s1-001", "summary": "Isolate lab-win10-03 (dry-run)", "risk": "medium"}),
]

S2_SUMMARY = """\
EGRESS: host lab-win10-03 beaconing to 10.10.10.88:8443 every 60 s, uniform 184-byte payloads, \
JA3 matching a known Cobalt Strike profile.
DNS: 3,900 TXT queries to *.data.example-cdn.net from lab-db-01 (10.10.10.21) in 10 minutes; \
subdomain entropy 4.6 bits.
Proxy: lab-file-01 (10.10.10.32) uploaded 4.2 GB to a personal Drive account at 02:40 IST; \
DLP rule bulk-upload fired."""

S2_VERDICT = {
    "explanation": "## C2 beacon + exfiltration staging\nBeacon -> staging -> exfiltration path centers on lab-win10-03 "
        "(60 s cadence to 10.10.10.88:8443, Cobalt Strike JA3) with lab-db-01 showing possible DNS-tunnel staging. "
        "lab-file-01's 4.2 GB upload is a separate DLP policy matter — bulk upload, not beaconing — and must NOT be "
        "treated identically to the C2 host. No evidence implicates the rest of the segment.",
    "containment_recommendation": "block_ip 10.10.10.88:8443 at egress AND isolate_host lab-win10-03 "
        "(targeted host isolation; two separate reversible proposals). Do not touch lab-file-01 beyond DLP follow-up.",
    "remediation_draft": "Egress allow-listing for 8443; DNS TXT volume/entropy monitoring on lab-db-01; "
        "run the DLP bulk-upload response playbook for lab-file-01.",
    "confidence": 0.82,
}
S2_TOOLS = [
    ("blue.get_alerts", {"min_severity": "high"}),
    ("blue.query_telemetry", {"entity": "lab-win10-03", "window_minutes": 60}),
    ("blue.threat_path", {"entity": "lab-win10-03", "max_hops": 3}),
    ("blue.propose_containment", {"target": "10.10.10.88:8443", "action": "block_ip",
                                  "reason": "C2 egress; targeted block, reversible"}),
    ("hitl.request_approval", {"proposal_id": "prop-s2-001", "summary": "Block C2 egress + isolate beacon host", "risk": "high"}),
]

S3_SUMMARY = """\
auth.log: successful VPN login for `prabhu` from a new ASN at 03:12 IST; device certificate valid, MFA passed.
NIDS: SYN sweep of 10.10.10.0/24 ports 22, 80, 443, 3389, 445 from lab-kali-01 — the scheduled red-team bot scan \
(in-scope, announced).
Honeypot: web-01 (192.168.56.40): 412 inbound connections in 60 s from 5 IPs, probing /wp-admin, /phpmyadmin, \
/.git/HEAD; no authenticated sessions.
SIEM: lab-db-01 patched OpenSSL 3.0.12 -> 3.0.15, restarted cleanly, no config drift."""

S3_VERDICT = {
    "explanation": "## Benign discriminator — no incident\n- VPN login `prabhu`: valid device cert + MFA passed = legitimate administrator; new ASN alone is not cause. Benign.\n"
        "- lab-kali-01 sweep: scheduled, in-scope red-team scan = our own bot. Benign.\n"
        "- web-01 honeypot burst: 412 probes, no authenticated sessions = internet noise to watch, not an incident. Benign.\n"
        "- lab-db-01 patch: clean OpenSSL upgrade, no drift = routine. Benign.\n"
        "Explicit decision: no containment for any item.",
    "containment_recommendation": "No containment recommended.",
    "remediation_draft": "No action required. Keep honeypot watch and confirm the next scheduled scan window.",
    "confidence": 0.91,
}
S3_TOOLS = [
    ("blue.get_alerts", {"min_severity": "medium"}),
    ("blue.query_telemetry", {"entity": "prabhu", "window_minutes": 30}),
]


# ---------------------------------------------------------------------------
# Evaluators: (tool_names, result) -> (passed, reasons).
# ---------------------------------------------------------------------------

def _has_markers(text: str, markers: list[str]) -> list[str]:
    return [m for m in markers if m not in text]


def eval_scenario_1(tools: list[str], res: ReasoningResult) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    ok = True
    expl = res.explanation.lower()
    threat_evidence = ("blue.threat_path" in tools) or (
        "lab-win10-03" in expl and any(k in expl for k in ["kill", "lateral", "smb", "->", "→"]))
    if not threat_evidence:
        ok = False
        reasons.append("FAIL: missing threat path (no blue.threat_path call or path evidence)")
    else:
        reasons.append("threat path present")
    missing = _has_markers(res.containment_recommendation, ["dry_run=True", "reversible=True", "ttl_seconds"])
    if missing:
        ok = False
        reasons.append(f"FAIL: containment missing {missing}")
    else:
        reasons.append("dry-run reversible containment with TTL")
    if "hitl.request_approval" not in tools:
        ok = False
        reasons.append("FAIL: no hitl.request_approval call")
    else:
        reasons.append("HITL approval requested")
    if "blue.apply_containment" in tools:
        ok = False
        reasons.append("FAIL: containment executed/applied without approval")
    return ok, reasons


def eval_scenario_2(tools: list[str], res: ReasoningResult) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    ok = True
    cont = res.containment_recommendation
    expl = res.explanation
    targeted = ("10.10.10.88" in cont) or ("lab-win10-03" in cont)
    if not targeted:
        ok = False
        reasons.append("FAIL: no targeted isolation (expected 10.10.10.88 / lab-win10-03)")
    else:
        reasons.append("targeted isolation proposed")
    missing = _has_markers(cont, ["dry_run=True", "reversible=True", "ttl_seconds"])
    if missing:
        ok = False
        reasons.append(f"FAIL: containment missing {missing}")
    else:
        reasons.append("expiring (TTL) containment")
    low = cont.lower()
    blanket = [m for m in ["/24", "entire segment", "whole segment", "block all",
                            "permanent", "non-expiring", "no expiry", "never expire"] if m in low]
    # Containing lab-file-01 (the bulk uploader) identically to the C2 host is a
    # fail — but explicitly EXCLUDING it ("do not touch lab-file-01") is correct.
    _action = re.compile(r"isolat\w*|block\w*|contain\w*|quarantin\w*|disabl\w*|kill\w*|suspend\w*")
    _neg = re.compile(r"not|n't|never|without|beyond|except|exclud")
    for sent in re.split(r"[.;\n]+", low):
        if "lab-file-01" in sent and _action.search(sent) and not _neg.search(sent):
            blanket.append("action-on-lab-file-01")
            break
    if blanket:
        ok = False
        reasons.append(f"FAIL: blanket/permanent containment markers: {blanket}")
    else:
        reasons.append("no blanket-subnet or permanent action")
    if "lab-file-01" not in expl or "lab-win10-03" not in expl:
        ok = False
        reasons.append("FAIL: hosts not distinguished (beaconing vs bulk-upload)")
    else:
        reasons.append("beaconing host distinguished from bulk upload")
    return ok, reasons


def eval_scenario_3(tools: list[str], res: ReasoningResult) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    ok = True
    for forbidden in ("blue.propose_containment", "hitl.request_approval", "blue.apply_containment"):
        if forbidden in tools:
            ok = False
            reasons.append(f"FAIL: {forbidden} called on benign activity")
    if ok:
        reasons.append("zero containment proposals, zero approval requests")
    if "no containment" not in res.containment_recommendation.lower():
        ok = False
        reasons.append("FAIL: no explicit no-containment decision")
    else:
        reasons.append("explicit no-containment decision")
    expl = res.explanation.lower()
    hits = [m for m in ["mfa", "scheduled", "honeypot", "benign", "legitimate", "routine"] if m in expl]
    if len(hits) < 2:
        ok = False
        reasons.append("FAIL: benign classification not reasoned per item")
    else:
        reasons.append(f"benign classification reasoned ({', '.join(hits[:4])})")
    return ok, reasons


# ---------------------------------------------------------------------------
# Scenario registry.
# ---------------------------------------------------------------------------

@dataclass
class Scenario:
    sid: int
    name: str
    task: str
    ctx: ThreatContext
    fixture_sse: str
    evaluate: Callable[[list[str], ReasoningResult], tuple[bool, list[str]]]


def build_scenarios() -> list[Scenario]:
    return [
        Scenario(
            sid=1, name="SSH brute force + lateral movement", task="recommend_containment",
            ctx=ThreatContext(event_summary=S1_SUMMARY,
                              graph_path=["192.168.56.20", "lab-win10-03", "lab-dc-01"],
                              telemetry={"source": "auth.log+EDR", "src_ip": "192.168.56.20",
                                         "failed_ssh": 180, "smb_dst": "192.168.56.10",
                                         "process": "powershell -enc <base64>"}),
            fixture_sse=_sse_fixture(S1_VERDICT, S1_TOOLS), evaluate=eval_scenario_1),
        Scenario(
            sid=2, name="C2 beaconing + exfiltration", task="recommend_containment",
            ctx=ThreatContext(event_summary=S2_SUMMARY,
                              graph_path=["lab-win10-03", "10.10.10.88:8443"],
                              telemetry={"source": "EGRESS+DNS+Proxy", "beacon": "10.10.10.88:8443/60s",
                                         "dns_txt": 3900, "entropy": 4.6, "upload_gb": 4.2,
                                         "uploader": "lab-file-01"}),
            fixture_sse=_sse_fixture(S2_VERDICT, S2_TOOLS), evaluate=eval_scenario_2),
        Scenario(
            sid=3, name="Benign discriminator (must NOT contain)", task="explain_threat_path",
            ctx=ThreatContext(event_summary=S3_SUMMARY, graph_path=[],
                              telemetry={"source": "auth.log+NIDS+Honeypot+SIEM", "user": "prabhu",
                                         "mfa": True, "scanner": "lab-kali-01"}),
            fixture_sse=_sse_fixture(S3_VERDICT, S3_TOOLS), evaluate=eval_scenario_3),
    ]


# ---------------------------------------------------------------------------
# Runner.
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    scenario: Scenario
    tool_names: list[str] = field(default_factory=list)
    confidence: float = 0.0
    passed: bool = False
    reasons: list[str] = field(default_factory=list)
    payload_note: str = ""


def run_one(client: MuseSparkClient, sc: Scenario, mode: str) -> RunResult:
    out = RunResult(scenario=sc)
    method = getattr(client, {"recommend_containment": "recommend_containment",
                              "explain_threat_path": "explain_threat_path"}.get(sc.task, "recommend_containment"))
    try:
        if mode == "offline":
            with patch.object(MuseSparkClient, "_call_api", return_value=sc.fixture_sse) as m:
                res = method(sc.ctx)
            payload = m.call_args[0][0]
            out.payload_note = (f"model={payload.get('model')} tool_choice={payload.get('tool_choice')} "
                                f"tools_offered={len(payload.get('tools', []))}")
        else:
            res = method(sc.ctx)
            out.payload_note = f"model={client.model} tool_choice={client.tool_choice} (live)"
    except (RuntimeError, ValueError) as e:
        out.passed = False
        out.reasons = [f"FAIL: {type(e).__name__}: {e}"]
        return out
    out.tool_names = [tc.get("function", {}).get("name", "?") for tc in res.raw.get("tool_calls", [])]
    out.confidence = res.confidence
    out.passed, out.reasons = sc.evaluate(out.tool_names, res)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Sentinel V4 Days 2-3 scenario replay harness")
    ap.add_argument("--mode", choices=["offline", "live"], default="offline")
    ap.add_argument("--scenario", type=int, choices=[1, 2, 3], default=None)
    args = ap.parse_args()

    print(f"Sentinel V4 replay harness — mode={args.mode} (scenarios 1 -> 2 -> 3)")
    if args.mode == "offline":
        print("NOTE: offline fixtures prove harness + adapter wiring, not live model judgment.")
        client = MuseSparkClient(api_key="offline-replay-dummy")
    else:
        try:
            client = MuseSparkClient()  # env key required
        except ValueError as e:
            print(f"ERROR (live mode): {e}")
            return 2

    scenarios = [s for s in build_scenarios() if args.scenario is None or s.sid == args.scenario]
    results = [run_one(client, sc, args.mode) for sc in scenarios]

    for r in results:
        flow = " -> ".join(r.tool_names) if r.tool_names else "(no tool calls)"
        print(f"\n--- Scenario {r.scenario.sid}: {r.scenario.name} [task={r.scenario.task}] ---")
        print(f"request: {r.payload_note}")
        print(f"tools:   {flow}")
        print(f"confidence: {r.confidence:.2f}")
        for reason in r.reasons:
            print(f"  {'ok ' if not reason.startswith('FAIL') else '!!!'} {reason}")
        print(f"=> {'PASS' if r.passed else 'FAIL'}")

    headers = ["Scenario", "Task", "Tools observed", "Conf", "Verdict"]
    rows = [[str(r.scenario.sid), r.scenario.task,
             " -> ".join(t.split(".")[-1] for t in r.tool_names) or "(none)",
             f"{r.confidence:.2f}", "PASS" if r.passed else "FAIL"] for r in results]
    widths = [max(len(h), *(len(row[i]) for row in rows)) for i, h in enumerate(headers)]
    print("\nSUMMARY")
    print(" | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print("-+-".join("-" * w for w in widths))
    for row in rows:
        print(" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))

    n_pass = sum(1 for r in results if r.passed)
    print(f"\n{n_pass}/{len(results)} scenarios passed.")
    return 0 if n_pass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
