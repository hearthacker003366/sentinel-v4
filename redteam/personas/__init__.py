"""Atomic Single-Shot Personas for Sentinel V4 Red Team Adversary Engine."""

from .brute_force import trigger_brute_force
from .lateral_mover import trigger_lateral_move
from .privilege_escalator import trigger_privilege_escalation
from .c2_exfiltrator import trigger_c2_exfiltration
from .benign_user import trigger_benign_user

__all__ = [
    "trigger_brute_force",
    "trigger_lateral_move",
    "trigger_privilege_escalation",
    "trigger_c2_exfiltration",
    "trigger_benign_user",
]
