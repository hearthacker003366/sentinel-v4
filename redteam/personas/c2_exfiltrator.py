"""Persona 4: C2 Exfiltrator (Mandatory for Scenario 2).

Generates low-and-slow Cobalt Strike C2 beaconing to 10.10.10.88:8443,
high-entropy DNS TXT tunneling on lab-db-01, and simulated bulk staging
sinking strictly inside the lab segment (10.10.10.99).
"""

from __future__ import annotations

import time
from typing import Any


def trigger_c2_exfiltration(
    src_host: str = "lab-win10-03",
    src_ip: str = "192.168.56.31",
    c2_proxy_ip: str = "10.10.10.88",
    c2_port: int = 8443,
    db_host: str = "lab-db-01",
    db_ip: str = "10.10.10.21",
    file_host: str = "lab-file-01",
    file_ip: str = "10.10.10.32",
    lab_sink_ip: str = "10.10.10.99",
) -> list[dict[str, Any]]:
    """Generates an atomic batch of C2 beaconing and internal bulk data egress."""
    now = time.time()
    events: list[dict[str, Any]] = [
        # 1. Periodic C2 beaconing (Cobalt Strike JA3 profile)
        {
            "event_type": "c2_beacon",
            "host": src_host,
            "source_ip": src_ip,
            "dest_ip": c2_proxy_ip,
            "dest_port": c2_port,
            "protocol": "TLS",
            "cadence_seconds": 60,
            "payload_bytes": 184,
            "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
            "status": "BEACONING",
            "timestamp": now - 120,
            "signature_tag": "c2-beacon",
        },
        # 2. High-entropy DNS TXT tunneling on lab-db-01
        {
            "event_type": "dns_tunnel_query",
            "host": db_host,
            "source_ip": db_ip,
            "dest_ip": "10.10.10.1",
            "query_type": "TXT",
            "query_domain": "a4f89b1c7.data.example-cdn.net",
            "entropy_bits": 4.62,
            "query_volume_10m": 3900,
            "timestamp": now - 60,
            "signature_tag": "dns-tunnel",
        },
        # 3. Bulk file exfiltration staging sinking into lab sink 10.10.10.99
        {
            "event_type": "bulk_egress_upload",
            "host": file_host,
            "source_ip": file_ip,
            "dest_ip": lab_sink_ip,
            "dest_port": 443,
            "bytes_transferred": 4200000000,  # 4.2 GB
            "dlp_rule": "bulk-upload-detected",
            "status": "COMPLETED",
            "timestamp": now,
            "signature_tag": "c2-beacon-dns-tunnel",
        }
    ]
    return events
