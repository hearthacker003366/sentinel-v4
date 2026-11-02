"""Red Team Bot Adversary Engine for Sentinel V4.

Simulates adversary personas against the isolated lab network.
SCOPE IS A HARD RULE, ENFORCED IN CODE:
A bot may only ever touch addresses inside LAB_NETWORKS (192.168.56.0/24, 10.10.10.0/24).
Anything outside raises ScopeViolation before a single packet is considered.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .personas.brute_force import trigger_brute_force
from .personas.lateral_mover import trigger_lateral_move
from .personas.privilege_escalator import trigger_privilege_escalation
from .personas.c2_exfiltrator import trigger_c2_exfiltration
from .personas.benign_user import trigger_benign_user

# The ONLY networks a red-team bot may touch: the simulated lab.
LAB_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("192.168.56.0/24"),  # host-only lab segment
    ipaddress.ip_network("10.10.10.0/24"),    # container lab segment
)


class ScopeViolation(RuntimeError):
    """Raised when a bot is asked to touch anything outside the lab."""


def assert_in_scope(target: str) -> ipaddress.IPv4Address:
    """Return the parsed target if it is inside the lab, else raise ScopeViolation."""
    # Strip port if present
    clean_ip = target.split(":")[0].strip()
    try:
        ip = ipaddress.ip_address(clean_ip)
    except ValueError:
        raise ScopeViolation(f"Target '{target}' is not a valid IP literal.")

    if not any(ip in net for net in LAB_NETWORKS):
        raise ScopeViolation(f"Target '{target}' violates lab scope: not in {LAB_NETWORKS}.")
    return ip


def validate_event_scope(event: dict[str, Any]) -> None:
    """Enforces lab scope across all target and destination IPs in an event."""
    for key in ("target_ip", "dest_ip", "destination_ip"):
        val = event.get(key)
        if val and isinstance(val, str):
            assert_in_scope(val)


@dataclass
class AdversaryPersona:
    name: str
    description: str
    trigger_fn: Callable[..., list[dict[str, Any]]]


PERSONA_REGISTRY: dict[str, AdversaryPersona] = {
    "brute_force": AdversaryPersona(
        name="Brute-Force Infiltrator",
        description="Rapid SSH authentication bursts culminating in 1 compromise.",
        trigger_fn=trigger_brute_force,
    ),
    "lateral_mover": AdversaryPersona(
        name="Lateral Mover",
        description="Internal SMB pivot to Domain Controller with obfuscated PowerShell.",
        trigger_fn=trigger_lateral_move,
    ),
    "privilege_escalator": AdversaryPersona(
        name="Privilege Escalator",
        description="Shadow copy deletion via vssadmin and LSASS memory access.",
        trigger_fn=trigger_privilege_escalation,
    ),
    "c2_exfiltrator": AdversaryPersona(
        name="C2 Exfiltrator",
        description="Periodic C2 beaconing, DNS tunneling, and bulk egress sinking into lab.",
        trigger_fn=trigger_c2_exfiltration,
    ),
    "benign_user": AdversaryPersona(
        name="Benign User",
        description="Legitimate MFA VPN login, scheduled vulnerability scan, routine patching.",
        trigger_fn=trigger_benign_user,
    ),
}


class RedTeamRunner:
    """Orchestrates atomic persona triggers with controlled pacing."""

    def __init__(self, pacing_s: float = 1.5) -> None:
        self.pacing_s = max(1.0, min(3.0, pacing_s))  # strictly 1-3s

    def execute_persona(self, persona_key: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Executes an atomic persona trigger and enforces lab scope."""
        persona = PERSONA_REGISTRY.get(persona_key)
        if not persona:
            raise ValueError(f"Unknown persona '{persona_key}'. Available: {list(PERSONA_REGISTRY.keys())}")

        events = persona.trigger_fn(**kwargs)
        for ev in events:
            validate_event_scope(ev)
        return events

    def run_scenario(self, scenario_id: int) -> list[dict[str, Any]]:
        """Runs the multi-stage persona bursts for a scenario with 1-3s pacing."""
        all_events: list[dict[str, Any]] = []

        if scenario_id == 1:
            # Stage 1: Brute Force
            bf_events = self.execute_persona("brute_force")
            all_events.extend(bf_events)
            time.sleep(self.pacing_s)

            # Stage 2: Lateral Movement
            lm_events = self.execute_persona("lateral_mover")
            all_events.extend(lm_events)

        elif scenario_id == 2:
            # Stage 1: C2 Exfiltration Burst (sinking strictly into lab 10.10.10.99)
            c2_events = self.execute_persona("c2_exfiltrator")
            all_events.extend(c2_events)

        elif scenario_id == 3:
            # Stage 1: Benign User Operations (MFA, scan, patch, honeypot)
            benign_events = self.execute_persona("benign_user")
            all_events.extend(benign_events)

        else:
            raise ValueError(f"Invalid scenario_id {scenario_id}; must be 1, 2, or 3.")

        return all_events
