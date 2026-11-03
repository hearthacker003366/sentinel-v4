"""Telegram HITL Approval Gateway for Sentinel V4.

Connects Human-in-the-Loop containment authorization to Telegram via the SAME
HITLManager SQLite gateway (no second token store).

Features:
- Inline Approve/Reject buttons + text-command fallback (APPROVE <token>, REJECT <token>).
- Strict sender allowlist by Telegram user ID; unauthorized senders ignored.
- Containment card shows: action, target, Laya confidence, Spark reason, DRY-RUN stamp, TTL.
- On decision (approval, rejection, or expiration), the message is edited in place
  with timestamp and SHA-256 token fingerprint (never the raw token).
- Configuration loaded ONLY from environment variables (TELEGRAM_BOT_TOKEN, TELEGRAM_ALLOWED_USER_IDS).
- Pluggable FakeTelegramTransport for hermetic unit testing (zero live network calls).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import urllib.request
from typing import Any, Protocol

from orchestrator.hitl_manager import (
    HITLManager,
    ProposalRecord,
    TokenAlreadyConsumed,
    TokenExpired,
    GateLockedOut,
)

logger = logging.getLogger("sentinel.telegram_gateway")


class TelegramTransport(Protocol):
    """Protocol for sending and editing Telegram messages."""

    def send_message(
        self,
        chat_id: int | str,
        text: str,
        reply_markup: dict[str, Any] | None = None
    ) -> int:
        ...

    def edit_message_text(
        self,
        chat_id: int | str,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None
    ) -> None:
        ...

    def get_updates(
        self,
        offset: int | None = None,
        timeout: int = 25
    ) -> list[dict[str, Any]]:
        ...


class HttpTelegramTransport:
    """Standard HTTP transport for Telegram Bot API using urllib."""

    def __init__(self, bot_token: str) -> None:
        self.bot_token = bot_token
        self.api_url = f"https://api.telegram.org/bot{bot_token}"

    def send_message(
        self,
        chat_id: int | str,
        text: str,
        reply_markup: dict[str, Any] | None = None
    ) -> int:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        req = urllib.request.Request(
            f"{self.api_url}/sendMessage",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return int(data.get("result", {}).get("message_id", 0))

    def edit_message_text(
        self,
        chat_id: int | str,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None
    ) -> None:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        req = urllib.request.Request(
            f"{self.api_url}/editMessageText",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            pass

    def get_updates(
        self,
        offset: int | None = None,
        timeout: int = 25
    ) -> list[dict[str, Any]]:
        url = f"{self.api_url}/getUpdates?timeout={timeout}"
        if offset is not None:
            url += f"&offset={offset}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=timeout + 5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("result", [])
        except Exception as e:
            logger.debug("[TELEGRAM] getUpdates error: %s", e)
            return []


class FakeTelegramTransport:
    """Hermetic in-memory transport for deterministic testing."""

    def __init__(self) -> None:
        self.sent_messages: list[dict[str, Any]] = []
        self.edited_messages: list[dict[str, Any]] = []
        self.queued_updates: list[dict[str, Any]] = []
        self._next_id = 100

    def send_message(
        self,
        chat_id: int | str,
        text: str,
        reply_markup: dict[str, Any] | None = None
    ) -> int:
        self._next_id += 1
        msg = {
            "message_id": self._next_id,
            "chat_id": chat_id,
            "text": text,
            "reply_markup": reply_markup,
        }
        self.sent_messages.append(msg)
        return self._next_id

    def edit_message_text(
        self,
        chat_id: int | str,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None
    ) -> None:
        self.edited_messages.append({
            "message_id": message_id,
            "chat_id": chat_id,
            "text": text,
            "reply_markup": reply_markup,
        })
        for m in self.sent_messages:
            if m["message_id"] == message_id:
                m["text"] = text
                m["reply_markup"] = reply_markup

    def get_updates(
        self,
        offset: int | None = None,
        timeout: int = 25
    ) -> list[dict[str, Any]]:
        updates = list(self.queued_updates)
        self.queued_updates.clear()
        return updates


class TelegramGateway:
    """Manages Telegram containment alerts and human authorizations."""

    def __init__(
        self,
        hitl_manager: HITLManager,
        bot_token: str | None = None,
        allowed_user_ids: list[int] | set[int] | None = None,
        transport: TelegramTransport | None = None,
    ) -> None:
        self.hitl = hitl_manager
        self.bot_token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()

        # Parse allowlist
        if allowed_user_ids is not None:
            self.allowed_user_ids: set[int] = set(allowed_user_ids)
        else:
            raw_ids = os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "")
            self.allowed_user_ids = {
                int(uid.strip())
                for uid in raw_ids.split(",")
                if uid.strip().isdigit()
            }

        if transport is not None:
            self.transport = transport
        elif self.bot_token:
            self.transport = HttpTelegramTransport(self.bot_token)
        else:
            self.transport = FakeTelegramTransport()

        self.sent_cards: dict[str, list[dict[str, Any]]] = {}
        self.default_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip() or (
            next(iter(self.allowed_user_ids)) if self.allowed_user_ids else None
        )

    def is_user_allowed(self, user_id: int) -> bool:
        """Enforces sender allowlist."""
        return user_id in self.allowed_user_ids

    def send_containment_card(
        self,
        chat_id: int | str | None,
        proposal_id: str,
        raw_token: str,
        action: str,
        target: str,
        laya_confidence: float,
        spark_reason: str,
        dry_run: bool = True,
        ttl_seconds: int = 300,
    ) -> int:
        """Sends the HITL containment card with inline buttons."""
        target_chat = chat_id or self.default_chat_id
        if not target_chat:
            logger.warning("[TELEGRAM] No chat_id or allowed_user_ids configured for containment card.")
            return 0

        fingerprint = hashlib.sha256(raw_token.strip().lower().encode("utf-8")).hexdigest()[:8]
        text = (
            f"🚨 SENTINEL V4 // HITL CONTAINMENT AUTHORIZATION\n"
            f"---------------------------------------------\n"
            f"Proposal ID: {proposal_id}\n"
            f"Action: {action}\n"
            f"Target: {target}\n"
            f"System-1 (Laya) Confidence: {laya_confidence:.2%}\n"
            f"System-2 (Spark) Reason: {spark_reason}\n"
            f"Containment TTL: {ttl_seconds}s\n"
            f"[DRY-RUN SIMULATION ONLY]\n"
            f"Token Fingerprint: {fingerprint}\n"
            f"---------------------------------------------\n"
            f"Tap Approve / Reject below or text: APPROVE {raw_token}"
        )
        markup = {
            "inline_keyboard": [
                [
                    {"text": "✅ Approve", "callback_data": f"approve:{raw_token}"},
                    {"text": "❌ Reject", "callback_data": f"reject:{raw_token}"},
                ]
            ]
        }
        msg_id = self.transport.send_message(chat_id=target_chat, text=text, reply_markup=markup)
        if proposal_id not in self.sent_cards:
            self.sent_cards[proposal_id] = []
        self.sent_cards[proposal_id].append({
            "chat_id": target_chat,
            "message_id": msg_id,
            "fingerprint": fingerprint,
            "action": action,
            "target": target,
        })
        return msg_id

    def edit_card_outcome(
        self,
        proposal_id: str,
        status: str,
        actor: str = "console",
        token_fingerprint: str | None = None,
        record: ProposalRecord | None = None,
    ) -> None:
        """Edits active Telegram cards for a resolved proposal (e.g. from console or expiry)."""
        cards = self.sent_cards.get(proposal_id, [])
        ts_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        for card in cards:
            chat_id = card["chat_id"]
            message_id = card["message_id"]
            fp = token_fingerprint or card.get("fingerprint", "")
            action = record.action if record else card.get("action", "")
            target = record.target if record else card.get("target", "")

            if status == "approved":
                text = (
                    f"✅ CONTAINMENT APPROVED\n"
                    f"---------------------------------------------\n"
                    f"Proposal ID: {proposal_id}\n"
                    f"Action: {action}\n"
                    f"Target: {target}\n"
                    f"Decided At: {ts_iso}\n"
                    f"Token Fingerprint: {fp}\n"
                    f"Actor: {actor}\n"
                    f"[DRY-RUN SIMULATION ONLY]"
                )
            elif status == "rejected":
                text = (
                    f"❌ CONTAINMENT REJECTED\n"
                    f"---------------------------------------------\n"
                    f"Proposal ID: {proposal_id}\n"
                    f"Decided At: {ts_iso}\n"
                    f"Token Fingerprint: {fp}\n"
                    f"Actor: {actor}\n"
                    f"[DRY-RUN SIMULATION ONLY]"
                )
            elif status == "expired":
                text = (
                    f"⏱️ CONTAINMENT PROPOSAL EXPIRED\n"
                    f"---------------------------------------------\n"
                    f"Proposal ID: {proposal_id}\n"
                    f"Action: {action}\n"
                    f"Target: {target}\n"
                    f"Expired At: {ts_iso}\n"
                    f"Token Fingerprint: {fp}\n"
                    f"[DRY-RUN SIMULATION ONLY]"
                )
            else:
                continue

            try:
                self.transport.edit_message_text(chat_id, message_id, text, reply_markup=None)
            except Exception as e:
                logger.warning("[TELEGRAM] Failed to edit message %s for proposal %s: %s", message_id, proposal_id, e)

    def poll_updates(
        self,
        offset: int | None = None,
        timeout: int = 25
    ) -> tuple[int | None, list[dict[str, Any]]]:
        """Polls getUpdates via transport and dispatches callbacks/commands.
        Returns (next_offset, list_of_action_results).
        """
        updates = self.transport.get_updates(offset=offset, timeout=timeout)
        next_offset = offset
        results = []
        for update in updates:
            up_id = update.get("update_id")
            if up_id is not None:
                next_offset = up_id + 1

            if "callback_query" in update:
                cb = update["callback_query"]
                user_id = cb.get("from", {}).get("id")
                msg = cb.get("message", {})
                chat_id = msg.get("chat", {}).get("id")
                msg_id = msg.get("message_id")
                cb_data = cb.get("data", "")
                if user_id and chat_id and msg_id:
                    res = self.handle_callback_query(user_id, chat_id, msg_id, cb_data)
                    if res:
                        results.append(res)

            elif "message" in update:
                m = update["message"]
                user_id = m.get("from", {}).get("id")
                chat_id = m.get("chat", {}).get("id")
                text = m.get("text", "")
                reply_to = m.get("reply_to_message", {}).get("message_id")
                if user_id and chat_id and text:
                    res = self.handle_text_command(user_id, chat_id, text, reply_to_message_id=reply_to)
                    if res and "error" in res and self.is_user_allowed(user_id):
                        self.transport.send_message(chat_id, res["error"])
                    elif res:
                        results.append(res)

        return next_offset, results

    def handle_callback_query(
        self,
        user_id: int,
        chat_id: int | str,
        message_id: int,
        callback_data: str,
    ) -> dict[str, Any] | None:
        """Processes inline button press with allowlist check and in-place message edit."""
        if not self.is_user_allowed(user_id):
            logger.warning("[SECURITY] Ignored callback from non-allowlisted Telegram user ID: %d", user_id)
            return None

        parts = callback_data.split(":", 1)
        if len(parts) != 2:
            return {"error": "Invalid callback data"}
        cmd, token = parts[0].lower(), parts[1].strip()
        fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]
        ts_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if cmd == "approve":
            try:
                rec = self.hitl.verify_and_consume(token, actor=f"telegram:{user_id}")
                edited_text = (
                    f"✅ CONTAINMENT APPROVED\n"
                    f"---------------------------------------------\n"
                    f"Proposal ID: {rec.proposal_id}\n"
                    f"Action: {rec.action}\n"
                    f"Target: {rec.target}\n"
                    f"Decided At: {ts_iso}\n"
                    f"Token Fingerprint: {fingerprint}\n"
                    f"Actor: telegram:{user_id}\n"
                    f"[DRY-RUN SIMULATION ONLY]"
                )
                self.transport.edit_message_text(chat_id, message_id, edited_text, reply_markup=None)
                return {"status": "approved", "proposal_id": rec.proposal_id, "record": rec}
            except (TokenAlreadyConsumed, TokenExpired, GateLockedOut, ValueError) as e:
                logger.warning("[TELEGRAM] Approval failed for user %d: %s", user_id, e)
                return {"error": str(e)}

        elif cmd == "reject":
            try:
                rec = self.hitl.reject_proposal(token, actor=f"telegram:{user_id}")
                edited_text = (
                    f"❌ CONTAINMENT REJECTED\n"
                    f"---------------------------------------------\n"
                    f"Proposal ID: {rec.proposal_id}\n"
                    f"Decided At: {ts_iso}\n"
                    f"Token Fingerprint: {fingerprint}\n"
                    f"Actor: telegram:{user_id}\n"
                    f"[DRY-RUN SIMULATION ONLY]"
                )
                self.transport.edit_message_text(chat_id, message_id, edited_text, reply_markup=None)
                return {"status": "rejected", "proposal_id": rec.proposal_id, "record": rec}
            except Exception as e:
                logger.warning("[TELEGRAM] Rejection failed for user %d: %s", user_id, e)
                return {"error": str(e)}

        return {"error": f"Unknown command {cmd}"}

    def handle_text_command(
        self,
        user_id: int,
        chat_id: int | str,
        text: str,
        reply_to_message_id: int | None = None,
    ) -> dict[str, Any] | None:
        """Handles text command fallback (APPROVE <token> / REJECT <token>)."""
        if not self.is_user_allowed(user_id):
            logger.warning("[SECURITY] Ignored text command from non-allowlisted Telegram user ID: %d", user_id)
            return None

        parts = text.strip().split()
        if not parts:
            return None

        cmd = parts[0].upper()
        if cmd not in ("APPROVE", "REJECT") or len(parts) < 2:
            return {"error": "Usage: APPROVE <token> or REJECT <token>"}

        token = parts[1].strip()
        fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]
        ts_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if cmd == "APPROVE":
            try:
                rec = self.hitl.verify_and_consume(token, actor=f"telegram:{user_id}")
                reply_text = (
                    f"✅ CONTAINMENT APPROVED\n"
                    f"Proposal ID: {rec.proposal_id} ({rec.action} on {rec.target})\n"
                    f"Decided At: {ts_iso}\n"
                    f"Token Fingerprint: {fingerprint}\n"
                    f"[DRY-RUN SIMULATION ONLY]"
                )
                if reply_to_message_id:
                    self.transport.edit_message_text(chat_id, reply_to_message_id, reply_text, reply_markup=None)
                else:
                    self.transport.send_message(chat_id, reply_text)
                return {"status": "approved", "proposal_id": rec.proposal_id, "record": rec}
            except Exception as e:
                return {"error": str(e)}

        elif cmd == "REJECT":
            try:
                rec = self.hitl.reject_proposal(token, actor=f"telegram:{user_id}")
                reply_text = (
                    f"❌ CONTAINMENT REJECTED\n"
                    f"Proposal ID: {rec.proposal_id}\n"
                    f"Decided At: {ts_iso}\n"
                    f"Token Fingerprint: {fingerprint}\n"
                    f"[DRY-RUN SIMULATION ONLY]"
                )
                if reply_to_message_id:
                    self.transport.edit_message_text(chat_id, reply_to_message_id, reply_text, reply_markup=None)
                else:
                    self.transport.send_message(chat_id, reply_text)
                return {"status": "rejected", "proposal_id": rec.proposal_id, "record": rec}
            except Exception as e:
                return {"error": str(e)}

    def mark_expired(
        self,
        chat_id: int | str,
        message_id: int,
        proposal_id: str,
        action: str,
        target: str,
        token_fingerprint: str,
    ) -> None:
        """Edits an expired containment proposal message in place."""
        ts_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        text = (
            f"⏱️ CONTAINMENT PROPOSAL EXPIRED\n"
            f"---------------------------------------------\n"
            f"Proposal ID: {proposal_id}\n"
            f"Action: {action}\n"
            f"Target: {target}\n"
            f"Expired At: {ts_iso}\n"
            f"Token Fingerprint: {token_fingerprint}\n"
            f"[DRY-RUN SIMULATION ONLY]"
        )
        self.transport.edit_message_text(chat_id, message_id, text, reply_markup=None)
