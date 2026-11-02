"""Persona 1: Brute-Force Infiltrator.

Emits rapid failed authentication bursts against user 'admin' on the lab bastion,
followed by a single successful compromise.
"""

from __future__ import annotations

import time
from typing import Any


def trigger_brute_force(
    target_ip: str = "192.168.56.20",
    count: int = 180,
    username: str = "admin",
    src_ip: str = "192.168.56.250",
) -> list[dict[str, Any]]:
    """Generates an atomic batch of failed SSH attempts followed by 1 success."""
    events: list[dict[str, Any]] = []
    base_time = time.time() - (count * 1.2)

    for i in range(count):
        t = base_time + (i * 1.2)
        events.append({
            "event_type": "ssh_auth_failure",
            "source_ip": src_ip,
            "target_ip": target_ip,
            "username": username,
            "service": "sshd",
            "port": 22,
            "status": "FAILED",
            "message": f"Failed password for invalid user {username} from {src_ip} port {40000+i} ssh2",
            "timestamp": t,
            "signature_tag": "brute-force",
        })

    # The single anomalous success
    events.append({
        "event_type": "ssh_auth_success",
        "source_ip": src_ip,
        "target_ip": target_ip,
        "username": username,
        "service": "sshd",
        "port": 22,
        "status": "SUCCESS",
        "message": f"Accepted password for {username} from {src_ip} port 40181 ssh2",
        "timestamp": time.time(),
        "signature_tag": "brute-force-success",
    })

    return events
