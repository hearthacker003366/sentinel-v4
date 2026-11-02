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

