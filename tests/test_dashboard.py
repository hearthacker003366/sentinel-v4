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
