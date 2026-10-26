"""Red-team bot skeleton — purple-team adversary for the demo.

Each bot probes the SIMULATED LAB NETWORK and reports findings to the Chief
Sentinel orchestrator, which evaluates, prioritizes, and responds. Muse
Spark supplies strategy; Laya supplies fast tactical choices.

SCOPE IS A HARD RULE, ENFORCED HERE IN CODE — not in prompts, not in docs:
a bot may only ever touch addresses inside LAB_NETWORKS. Anything outside
raises ScopeViolation before a single packet is considered. There is no
configuration flag that widens this; widening it means editing this file and
reviewing the change like a security change, because it is one.

TODO (Phase 1, days 6-7):
- Bot loop: observe lab state -> Laya tactic choice -> probe -> report.
- Findings format shared with the orchestrator (reuse V3 demo scenarios).
- Planted-vuln checklist so the demo is reproducible.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

# The ONLY networks a red-team bot may touch: the simulated lab.
# RFC1918 ranges used by the V3 demo environment. Keep in sync with the lab
# definition (Docker / VM net), and keep it narrow — never 0.0.0.0/0.
LAB_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("192.168.56.0/24"),  # host-only lab segment
    ipaddress.ip_network("10.10.10.0/24"),  # container lab segment
)


class ScopeViolation(RuntimeError):
    """Raised when a bot is asked to touch anything outside the lab."""


def assert_in_scope(target: str) -> ipaddress.IPv4Address:
    """Return the parsed target if it is inside the lab, else raise."""
    ip = ipaddress.ip_address(target)
    if not any(ip in net for net in LAB_NETWORKS):
        raise ScopeViolation(f"target {target} is outside the simulated lab network")
    return ip


@dataclass
class BotPersona:
    """A named adversary style (e.g. noisy brute-forcer, quiet scanner)."""

    name: str
    style: str  # one-line description fed to the strategy prompt
    preferred_tactics: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """One bot report, consumed by the orchestrator."""

    bot: str
    target: str
    technique: str
    evidence: str
    severity_hint: float = 0.0  # 0..1, orchestrator makes the real call


class RedTeamBot:
    """One adversary in the purple-team exercise."""

    def __init__(self, persona: BotPersona) -> None:
        self.persona = persona

    def choose_tactic(self, state: str) -> str:
        """Pick the next tactic. Tactical choice is Laya's job (System-1)."""
        # TODO: call triage.LayaGate.choice() over persona.preferred_tactics.
        raise NotImplementedError("tactic loop lands on build days 6-7")

    def probe(self, target: str, technique: str) -> Finding:
        """Run one probe against a lab target and report what was found."""
        assert_in_scope(target)  # hard guard — first line, always
        # TODO: execute the simulated probe (V3 attacker tooling, lab only).
        raise NotImplementedError("probe execution lands on build days 6-7")

    def report(self, finding: Finding) -> None:
        """Send a finding to the Chief Sentinel orchestrator."""
        assert_in_scope(finding.target)
        # TODO: hand off to orchestrator intake queue.
        raise NotImplementedError("orchestrator intake lands on build days 6-7")
