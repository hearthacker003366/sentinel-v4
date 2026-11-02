"""Persona 5: Benign User (Mandatory for Scenario 3 — Credibility Discriminator).

Simulates valid corporate remote worker authentication with certificate + MFA,
scheduled internal vulnerability scanner maintenance window from lab-kali-01,
clean OpenSSL updates on lab-db-01, and unauthenticated honeypot noise.

Mandatory Policy Outcome: Zero containment proposals, zero HITL interrupts.
"""

from __future__ import annotations

import time
from typing import Any


def trigger_benign_user(
    username: str = "prabhu",
    src_ip: str = "192.168.56.155",
    scanner_ip: str = "10.10.10.50",
    db_host: str = "lab-db-01",
    db_ip: str = "10.10.10.21",
    honeypot_ip: str = "192.168.56.40",
) -> list[dict[str, Any]]:
    """Generates an atomic batch of legitimate enterprise operations."""
    now = time.time()
    events: list[dict[str, Any]] = [
        # 1. Valid VPN authentication with device cert and hardware MFA
        {
            "event_type": "vpn_login_success",
            "username": username,
            "source_ip": src_ip,
            "device_cert": "VALID_ISSUED_CORP_ROOT_CA",
            "mfa_verified": True,
            "mfa_method": "fido2_webauthn",
            "timestamp": now - 180,
            "signature_tag": "benign-mfa-scan",
        },
        # 2. Scheduled internal vulnerability scan from lab-kali-01
        {
            "event_type": "nids_port_scan",
            "source_ip": scanner_ip,
            "target_subnet": "10.10.10.0/24",
            "scan_type": "SYN_SWEEP",
            "ports_scanned": [22, 80, 443, 3389, 445],
            "authorized_maintenance_window": True,
            "schedule_id": "SEC-AUDIT-WEEKLY",
            "timestamp": now - 120,
            "signature_tag": "benign-scheduled-scan",
        },
        # 3. Clean OpenSSL package update on lab-db-01
        {
            "event_type": "package_update",
            "host": db_host,
            "source_ip": db_ip,
            "package_name": "openssl",
            "old_version": "3.0.12",
            "new_version": "3.0.15",
            "service_restart": "CLEAN_EXIT_0",
            "config_drift": False,
            "timestamp": now - 60,
            "signature_tag": "benign-patch-event",
        },
        # 4. Routine unauthenticated internet honeypot probes
        {
            "event_type": "honeypot_probe_burst",
            "target_ip": honeypot_ip,
            "port": 80,
            "probe_paths": ["/wp-admin", "/phpmyadmin", "/.git/HEAD"],
            "connection_count": 412,
            "authenticated_sessions": 0,
            "timestamp": now,
            "signature_tag": "benign-honeypot-noise",
        }
    ]
    return events
