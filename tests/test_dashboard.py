"""Unit tests for Sentinel V4 SOC Dashboard Web Command Server."""

import json
import threading
import time
import urllib.request
import pytest
from dashboard.server import run_dashboard_server


@pytest.fixture(scope="module")
def dashboard_server():
    server = run_dashboard_server(host="127.0.0.1", port=8599)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:8599"
    server.shutdown()
    server.server_close()


def test_dashboard_serves_stitch_index_html(dashboard_server):
    req = urllib.request.urlopen(f"{dashboard_server}/")
    assert req.status == 200
    html = req.read().decode("utf-8")
    assert "SENTINEL V4 // AUTONOMOUS AI SOC COMMAND" in html
    assert "cytoscape" in html
    assert "MUSE SPARK 1.3" in html
    assert "0.85 HITL" in html
    assert "Space Grotesk" in html
    assert "JetBrains Mono" in html

    # Fix 1: Zero external CDN requests, all vendored locally
    assert "https://" not in html
    assert "http://" not in html
    assert "/vendor/cytoscape.min.js" in html
    assert "/vendor/tailwind.js" in html
    assert "/vendor/material-symbols.css" in html
    assert "/vendor/fonts.css" in html

    # Verify static vendor assets are served directly with HTTP 200
    for asset in ("/vendor/cytoscape.min.js", "/vendor/tailwind.js", "/vendor/fonts.css", "/vendor/material-symbols.css"):
        v_req = urllib.request.urlopen(f"{dashboard_server}{asset}")
        assert v_req.status == 200
        assert len(v_req.read()) > 0



def test_dashboard_state_endpoint(dashboard_server):
    req = urllib.request.urlopen(f"{dashboard_server}/v4/state")
    assert req.status == 200
    assert req.headers.get("Access-Control-Allow-Origin") is None
    data = json.loads(req.read().decode("utf-8"))
    assert "summary" in data
    assert "incidents_feed" in data
    assert "graph" in data
    assert len(data["graph"]["nodes"]) >= 9
    assert len(data["graph"]["edges"]) >= 8
    assert data["summary"]["laya_latency"] == "45ms Mean"


def test_dashboard_reset_and_scenario_endpoints(dashboard_server):
    # Test reset
    reset_req = urllib.request.Request(
        f"{dashboard_server}/v4/reset",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(reset_req) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode("utf-8"))
        assert res["status"] == "reset"

    # Test scenario trigger
    sc_req = urllib.request.Request(
        f"{dashboard_server}/v4/scenario",
        data=json.dumps({"scenario_id": 3}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(sc_req) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode("utf-8"))
        assert res["status"] == "running"
        assert res["scenario_id"] == 3


def test_dashboard_is_read_only_and_approve_returns_404(dashboard_server):
    """Fix 3 & Fix 8: Dashboard is read-only. No raw approval_token; /v4/approve returns 404."""
    import urllib.error

    # 1. Trigger persona to generate an incident with potential proposal
    trig_req = urllib.request.Request(
        f"{dashboard_server}/v4/trigger",
        data=json.dumps({"persona": "lateral_mover"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(trig_req) as resp:
        assert resp.status == 200

    time.sleep(0.4)

    # 2. Check /v4/state has no raw approval_token anywhere
    req = urllib.request.urlopen(f"{dashboard_server}/v4/state")
    assert req.status == 200
    raw_json_str = req.read().decode("utf-8")
    assert "approval_token" not in raw_json_str

    data = json.loads(raw_json_str)
    assert data["summary"]["auto_act_rate"] == "83.17%"  # Fix 8: verified 83.17%

    # Fix 8: No node type "honeypot" and no "web-01 (Trap)"
    for node in data["graph"]["nodes"]:
        assert node["data"]["type"] != "honeypot"
        assert "(Trap)" not in node["data"]["label"]

    # 3. POST /v4/approve must return HTTP 404
    approve_req = urllib.request.Request(
        f"{dashboard_server}/v4/approve",
        data=json.dumps({"token": "deadbeef12345678"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(approve_req)
    assert exc_info.value.code == 404


def test_threat_path_derived_dynamically_from_incidents(dashboard_server):
    """Item 1: Assert threat path is derived dynamically from real incidents.
    Addresses NOT in the old literal list must equal returned hops; old literals must not appear.
    """
    import dashboard.server as d_server
    from orchestrator.chief_sentinel import ProcessedIncident
    from orchestrator.routing_gate import TriageVerdict, RoutingDecision, Route

    # Clean engine incidents
    d_server.ENGINE.incidents.clear()

    # Create synthetic lateral attack incidents with unique IPs
    novel_src = "172.16.99.10"
    novel_hop = "jump-host-01"
    novel_dst = "target-dc-99"

    inc1 = ProcessedIncident(
        incident_id="inc-test-1",
        timestamp=time.time(),
        raw_event={
            "event_type": "ssh_auth_failure",
            "source_ip": novel_src,
            "target_host": novel_hop,
            "signature_tag": "ssh-brute",
        },
        triage=TriageVerdict(verdict="malicious", winner_confidence=0.96, is_attack=True, severity=0.8),
        routing=RoutingDecision(route=Route.SYSTEM_1_AUTO_ACT, winner_confidence=0.96, verdict="malicious", is_attack=True, severity=0.8, dry_run=True, reason="auto-act"),
    )
    inc2 = ProcessedIncident(
        incident_id="inc-test-2",
        timestamp=time.time() + 1,
        raw_event={
            "event_type": "smb_session_open",
            "source_host": novel_hop,
            "target_host": novel_dst,
            "signature_tag": "lateral-smb",
        },
        triage=TriageVerdict(verdict="malicious", winner_confidence=0.74, is_attack=True, severity=0.9),
        routing=RoutingDecision(route=Route.SYSTEM_2_ESCALATE, winner_confidence=0.74, verdict="malicious", is_attack=True, severity=0.9, dry_run=True, reason="escalate"),
    )
    d_server.ENGINE.incidents.extend([inc1, inc2])

    req = urllib.request.urlopen(f"{dashboard_server}/v4/state")
    assert req.status == 200
    state = json.loads(req.read().decode("utf-8"))
    hops = state["threat_path_active"]

    # Verify dynamically derived hops
    assert hops == [novel_src, novel_hop, novel_dst]

    # Verify old literals never appear
    old_literals = ["192.168.56.20", "lab-win10-03", "lab-dc-01"]
    for lit in old_literals:
        assert lit not in hops

    # Clean up
    d_server.ENGINE.incidents.clear()


def test_dashboard_state_has_no_64_char_token_hashes(dashboard_server):
    """Item 2: Serialise dashboard state to JSON and assert no 64-char hex token string appears."""
    import re
    import dashboard.server as d_server

    # Create a proposal in engine HITL store
    prop_id, raw_token = d_server.ENGINE.hitl.create_proposal(
        target="lab-win10-03",
        action="isolate_host",
        reason="Test token leak prevention",
        ttl_seconds=300
    )

    req = urllib.request.urlopen(f"{dashboard_server}/v4/state")
    assert req.status == 200
    state_json = req.read().decode("utf-8")

    # Assert no 64-char hex string appears anywhere in the serialized payload
    match_64 = re.findall(r"\b[0-9a-fA-F]{64}\b", state_json)
    assert len(match_64) == 0, f"Found 64-char hex hash(es) in /v4/state: {match_64}"

    # Verify trimmed 8-char hash is present in pending proposals
    state_data = json.loads(state_json)
    proposals = state_data.get("pending_proposals", [])
    test_prop = [p for p in proposals if p["proposal_id"] == prop_id]
    assert len(test_prop) == 1
    assert len(test_prop[0]["token_hash"]) == 8


