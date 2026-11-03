"""Integration tests for Telegram Gateway wired into ChiefSentinelEngine."""

import os
import tempfile
import time
import pytest
from orchestrator.chief_sentinel import ChiefSentinelEngine
from orchestrator.routing_gate import Route
from orchestrator.telegram_gateway import TelegramGateway, FakeTelegramTransport


@pytest.fixture
def engine_with_telegram():
    import gc
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    transport = FakeTelegramTransport()
    # Mock gateway bound to the temp DB
    from orchestrator.hitl_manager import HITLManager
    hitl = HITLManager(db_path=db_path)
    gateway = TelegramGateway(
        hitl_manager=hitl,
        bot_token="fake_bot_token",
        allowed_user_ids=[12345],
        transport=transport,
    )
    gateway.default_chat_id = 9999

    engine = ChiefSentinelEngine(db_path=db_path, telegram_gateway=gateway)
    yield engine, gateway, transport
    engine.stop()
    del engine
    del gateway
    del hitl
    gc.collect()
    time.sleep(0.05)
    for ext in ("", "-wal", "-shm"):
        p = db_path + ext
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


def test_telegram_engine_lateral_card_dispatch_and_callback_approval(engine_with_telegram):
    """Integration requirement:
    Drive real engine through lateral-mover events that produce a proposal.
    Assert:
    (a) Exactly one card was sent through the transport.
    (b) A simulated approve callback consumes the proposal in the HITL store.
    (c) An edit-message call was issued with the outcome.
    """
    engine, gateway, transport = engine_with_telegram

    # Drive engine through lateral-mover persona
    lm_events = engine.runner.execute_persona("lateral_mover")
    inc = engine.process_event(lm_events[0])  # SMB session pivot

    assert inc.routing.route == Route.SYSTEM_2_ESCALATE
    assert inc.proposal_id is not None
    assert inc.approval_token is not None

    # (a) Assert exactly one card was sent through the transport
    assert len(transport.sent_messages) == 1
    sent = transport.sent_messages[0]
    assert sent["chat_id"] == 9999
    assert "🚨 SENTINEL V4 // HITL CONTAINMENT AUTHORIZATION" in sent["text"]
    assert inc.proposal_id in sent["text"]
    assert "isolate_host" in sent["text"]
    assert "lab-win10-03" in sent["text"]
    assert "[DRY-RUN SIMULATION ONLY]" in sent["text"]

    # (b) Simulated approve callback from authorized user 12345 consumes proposal in HITL store
    res = gateway.handle_callback_query(
        user_id=12345,
        chat_id=sent["chat_id"],
        message_id=sent["message_id"],
        callback_data=f"approve:{inc.approval_token}",
    )
    assert res is not None
    assert res["status"] == "approved"
    assert res["proposal_id"] == inc.proposal_id

    # Verify consumed in HITL store (zero pending proposals)
    pending = engine.hitl.get_pending_proposals()
    assert len(pending) == 0

    # (c) Assert an edit-message call was issued with the outcome
    assert len(transport.edited_messages) == 1
    edited = transport.edited_messages[0]
    assert edited["message_id"] == sent["message_id"]
    assert "✅ CONTAINMENT APPROVED" in edited["text"]
    assert inc.proposal_id in edited["text"]
    assert "Actor: telegram:12345" in edited["text"]
    assert "[DRY-RUN SIMULATION ONLY]" in edited["text"]


def test_telegram_engine_console_approval_edits_telegram_card(engine_with_telegram):
    """Assert console approvals edit the Telegram card in place (one source of truth)."""
    engine, gateway, transport = engine_with_telegram

    lm_events = engine.runner.execute_persona("lateral_mover")
    inc = engine.process_event(lm_events[0])

    assert len(transport.sent_messages) == 1
    card_msg_id = transport.sent_messages[0]["message_id"]

    # Approve via CONSOLE
    rec = engine.approve_containment(inc.approval_token, actor="test_operator")
    assert rec.status == "approved"

    # Verify the Telegram card was edited in place
    assert len(transport.edited_messages) == 1
    edited = transport.edited_messages[0]
    assert edited["message_id"] == card_msg_id
    assert "✅ CONTAINMENT APPROVED" in edited["text"]
    assert "Actor: test_operator" in edited["text"]


def test_telegram_engine_disabled_when_env_missing():
    """When env vars are absent and no gateway is passed, gateway is disabled cleanly."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        # Ensure env vars are not set
        old_token = os.environ.pop("TELEGRAM_BOT_TOKEN", None)
        old_ids = os.environ.pop("TELEGRAM_ALLOWED_USER_IDS", None)
        try:
            eng = ChiefSentinelEngine(db_path=db_path)
            assert eng.telegram is None
            # Running events still works in console-only mode
            lm_events = eng.runner.execute_persona("lateral_mover")
            inc = eng.process_event(lm_events[0])
            assert inc.approval_token is not None
            eng.stop()
        finally:
            if old_token:
                os.environ["TELEGRAM_BOT_TOKEN"] = old_token
            if old_ids:
                os.environ["TELEGRAM_ALLOWED_USER_IDS"] = old_ids
    finally:
        for ext in ("", "-wal", "-shm"):
            p = db_path + ext
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
