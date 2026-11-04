"""Human-in-the-Loop (HITL) Subsystem for Sentinel V4.

Manages single-use cryptographic containment approval tokens, short TTLs,
SHA-256 audit logging, and a unified 3-strike lockout shared between
Telegram and the Console REPL.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Optional


DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "sentinel_v4.db"
)
DEFAULT_TOKEN_TTL = 300  # 5 minutes
LOCKOUT_THRESHOLD = 3    # 3 failed strikes
LOCKOUT_DURATION = 900   # 15 minutes


class TokenAlreadyConsumed(Exception):
    """Raised when an approval token is submitted more than once."""
    pass


class TokenExpired(Exception):
    """Raised when an approval token has exceeded its TTL."""
    pass


class GateLockedOut(Exception):
    """Raised when consecutive failed attempts exceed the lockout threshold."""
    pass


@dataclass
class ProposalRecord:
    proposal_id: str
    target: str
    action: str
    reason: str
    token_hash: str
    created_at: float
    expires_at: float
    status: str  # pending, approved, rejected, expired


class HITLManager:
    """Thread-safe and multi-process SQLite-backed HITL gateway."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hitl_proposals (
                    proposal_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    approved_at REAL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hitl_lockout (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    failed_count INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0
                );
            """)
            conn.execute("""
                INSERT OR IGNORE INTO hitl_lockout (id, failed_count, locked_until)
                VALUES (1, 0, 0);
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hitl_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    proposal_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    result TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    timestamp REAL NOT NULL
                );
            """)
            conn.commit()

    @staticmethod
    def hash_token(token: str) -> str:
        """Returns SHA-256 fingerprint of the token. Plaintext is never stored."""
        return hashlib.sha256(token.strip().lower().encode("utf-8")).hexdigest()

    def check_lockout(self) -> None:
        """Raises GateLockedOut if the shared lockout window is active."""
        now = time.time()
        with self._get_connection() as conn:
            cur = conn.execute("SELECT failed_count, locked_until FROM hitl_lockout WHERE id = 1;")
            row = cur.fetchone()
            if row:
                failed_count, locked_until = row
                if locked_until > now:
                    remaining = int(locked_until - now)
                    raise GateLockedOut(
                        f"HITL gate locked out due to {failed_count} failed attempts. "
                        f"Try again in {remaining}s."
                    )
                elif locked_until > 0 and locked_until <= now:
                    # Reset expired lockout
                    conn.execute("UPDATE hitl_lockout SET failed_count = 0, locked_until = 0 WHERE id = 1;")
                    conn.commit()

    def record_failure(self, actor: str = "unknown") -> int:
        """Records a failed attempt; triggers 15m lockout on 3rd failure."""
        now = time.time()
        with self._get_connection() as conn:
            cur = conn.execute("SELECT failed_count, locked_until FROM hitl_lockout WHERE id = 1;")
            failed_count, locked_until = cur.fetchone()

            if locked_until > now:
                return failed_count

            failed_count += 1
            new_locked_until = (now + LOCKOUT_DURATION) if failed_count >= LOCKOUT_THRESHOLD else 0

            conn.execute(
                "UPDATE hitl_lockout SET failed_count = ?, locked_until = ? WHERE id = 1;",
                (failed_count, new_locked_until)
            )
            conn.execute(
                "INSERT INTO hitl_audit (proposal_id, action, target, token_hash, result, actor, timestamp) "
                "VALUES ('UNKNOWN', 'AUTH_FAIL', 'N/A', 'INVALID', 'FAILED_ATTEMPT', ?, ?);",
                (actor, now)
            )
            conn.commit()
            return failed_count

    def reset_lockout(self) -> None:
        """Clears failed attempts upon successful authorized action."""
        with self._get_connection() as conn:
            conn.execute("UPDATE hitl_lockout SET failed_count = 0, locked_until = 0 WHERE id = 1;")
            conn.commit()

    def create_proposal(
        self,
        target: str,
        action: str,
        reason: str,
        ttl_seconds: int = DEFAULT_TOKEN_TTL
    ) -> tuple[str, str]:
        """Creates a proposal, stamps config TTL, generates single-use 16-char token.

        Returns (proposal_id, raw_token). The raw token is returned ONCE for
        dispatch to Telegram/Console and is NEVER saved in the database.
        """
        now = time.time()
        proposal_id = f"prop-{secrets.token_hex(4)}"
        raw_token = secrets.token_hex(8)  # 16-character hex (64 bits of entropy)
        token_hash = self.hash_token(raw_token)
        expires_at = now + ttl_seconds

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO hitl_proposals (
                    proposal_id, target, action, reason, token_hash,
                    created_at, expires_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending');
            """, (proposal_id, target, action, reason, token_hash, now, expires_at))
            conn.commit()

        return proposal_id, raw_token

    def verify_and_consume(self, token: str, actor: str = "console") -> ProposalRecord:
        """Validates token, enforces single-use, binds action/target, and audits.

        Raises GateLockedOut, TokenExpired, or TokenAlreadyConsumed.
        """
        self.check_lockout()
        now = time.time()
        token_hash = self.hash_token(token)

        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT proposal_id, target, action, reason, token_hash,
                       created_at, expires_at, status
                FROM hitl_proposals WHERE token_hash = ?;
            """, (token_hash,))
            row = cur.fetchone()

            if not row:
                self.record_failure(actor=actor)
                raise ValueError("Invalid approval token.")

            prop = ProposalRecord(*row)

            if prop.status == "approved":
                self.record_failure(actor=actor)
                raise TokenAlreadyConsumed(f"Token for proposal {prop.proposal_id} was already consumed.")

            if prop.status == "rejected":
                raise TokenAlreadyConsumed(f"Proposal {prop.proposal_id} was previously rejected.")

            if now > prop.expires_at:
                conn.execute(
                    "UPDATE hitl_proposals SET status = 'expired' WHERE proposal_id = ?;",
                    (prop.proposal_id,)
                )
                conn.commit()
                raise TokenExpired(f"Token for proposal {prop.proposal_id} has expired.")

            # Valid! Consume token immediately
            cur_upd = conn.execute(
                "UPDATE hitl_proposals SET status = 'approved', approved_at = ? WHERE proposal_id = ? AND status = 'pending';",
                (now, prop.proposal_id)
            )
            if cur_upd.rowcount != 1:
                raise TokenAlreadyConsumed(f"Token for proposal {prop.proposal_id} was already consumed.")
            # Log SHA-256 fingerprint only
            conn.execute("""
                INSERT INTO hitl_audit (
                    proposal_id, action, target, token_hash, result, actor, timestamp
                ) VALUES (?, ?, ?, ?, 'APPROVED', ?, ?);
            """, (prop.proposal_id, prop.action, prop.target, token_hash, actor, now))
            conn.commit()

        # Reset failed counter on success
        self.reset_lockout()
        prop.status = "approved"
        return prop

    def reject_proposal(self, token: str, actor: str = "console") -> ProposalRecord:
        """Rejects a proposal, burning the token."""
        self.check_lockout()
        now = time.time()
        token_hash = self.hash_token(token)

        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT proposal_id, target, action, reason, token_hash,
                       created_at, expires_at, status
                FROM hitl_proposals WHERE token_hash = ?;
            """, (token_hash,))
            row = cur.fetchone()

            if not row:
                self.record_failure(actor=actor)
                raise ValueError("Invalid approval token.")

            prop = ProposalRecord(*row)
            if prop.status != "pending":
                raise TokenAlreadyConsumed(f"Proposal {prop.proposal_id} is already in state {prop.status}.")

            cur_upd = conn.execute(
                "UPDATE hitl_proposals SET status = 'rejected' WHERE proposal_id = ? AND status = 'pending';",
                (prop.proposal_id,)
            )
            if cur_upd.rowcount != 1:
                raise TokenAlreadyConsumed(f"Proposal {prop.proposal_id} is already in state {prop.status}.")
            conn.execute("""
                INSERT INTO hitl_audit (
                    proposal_id, action, target, token_hash, result, actor, timestamp
                ) VALUES (?, ?, ?, ?, 'REJECTED', ?, ?);
            """, (prop.proposal_id, prop.action, prop.target, token_hash, actor, now))
            conn.commit()

        self.reset_lockout()
        prop.status = "rejected"
        return prop

    def get_pending_proposals(self) -> list[ProposalRecord]:
        """Returns all non-expired pending proposals."""
        now = time.time()
        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT proposal_id, target, action, reason, token_hash,
                       created_at, expires_at, status
                FROM hitl_proposals
                WHERE status = 'pending' AND expires_at > ?
                ORDER BY created_at DESC;
            """, (now,))
            return [ProposalRecord(*r) for r in cur.fetchall()]
