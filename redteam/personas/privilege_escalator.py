"""Persona 3: Privilege Escalator.

Executes local host shadow copy deletion via vssadmin and attempts LSASS memory
credential dumping on the target workstation.
"""

from __future__ import annotations

import time
from typing import Any


def trigger_privilege_escalation(
    host: str = "lab-win10-03",
    ip: str = "192.168.56.31",
) -> list[dict[str, Any]]:
    """Generates an atomic batch of host-level privilege escalation telemetry."""
    now = time.time()
    events: list[dict[str, Any]] = [
        {
            "event_type": "process_creation",
            "host": host,
            "source_ip": ip,
            "process_name": "vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "integrity_level": "High",
            "timestamp": now - 10,
            "signature_tag": "priv-esc-shadow-delete",
        },
        {
            "event_type": "lsass_memory_access",
            "host": host,
            "source_ip": ip,
            "source_process": "rundll32.exe",
            "target_process": "lsass.exe",
            "granted_access": "0x1010",
            "timestamp": now,
            "signature_tag": "priv-esc-lsass-dump",
        }
    ]
    return events
