"""Unit tests for Telegram HITL Gateway using FakeTelegramTransport (zero live calls)."""

import os
import tempfile
import time
import pytest
from orchestrator.hitl_manager import HITLManager
from orchestrator.telegram_gateway import TelegramGateway, FakeTelegramTransport


@pytest.fixture
def hitl_and_gateway():
    import gc
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    mgr = HITLManager(db_path=db_path)
    transport = FakeTelegramTransport()
    gateway = TelegramGateway(
        hitl_manager=mgr,
        bot_token="fake_bot_token",
        allowed_user_ids=[12345, 67890],
        transport=transport
    )
    yield mgr, gateway, transport
    del mgr
    del gateway
    gc.collect()
    time.sleep(0.05)
    for ext in ("", "-wal", "-shm"):
        p = db_path + ext
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


def test_telegram_allowlist_rejection(hitl_and_gateway):
    mgr, gateway, transport = hitl_and_gateway
    prop_id, token = mgr.create_proposal(
        target="192.168.56.31",
        action="isolate_host",
        reason="Suspicious lateral SMB probe"
    )
    msg_id = gateway.send_containment_card(
        chat_id=1001,
        proposal_id=prop_id,
        raw_token=token,
        action="isolate_host",
        target="192.168.56.31",
        laya_confidence=0.742,
        spark_reason="Multi-hop named pipe detection"
    )
    assert len(transport.sent_messages) == 1

    # Unauthorized user 99999 attempts button callback
    res_cb = gateway.handle_callback_query(
        user_id=99999,
        chat_id=1001,
        message_id=msg_id,
        callback_data=f"approve:{token}"
    )
    assert res_cb is None  # Ignored
    assert len(transport.edited_messages) == 0

    # Token must still be pending in hitl_manager
    pending = mgr.get_pending_proposals()
    assert len(pending) == 1
    assert pending[0].proposal_id == prop_id

    # Unauthorized user 99999 attempts text command
    res_txt = gateway.handle_text_command(
        user_id=99999,
        chat_id=1001,
        text=f"APPROVE {token}"
    )
    assert res_txt is None  # Ignored


def test_telegram_button_callback_consumes_token_exactly_once(hitl_and_gateway):
    mgr, gateway, transport = hitl_and_gateway
    prop_id, token = mgr.create_proposal(
        target="192.168.56.31",
        action="isolate_host",
        reason="Suspicious lateral SMB probe"
    )
    msg_id = gateway.send_containment_card(
        chat_id=1001,
        proposal_id=prop_id,
        raw_token=token,
        action="isolate_host",
        target="192.168.56.31",
        laya_confidence=0.742,
        spark_reason="Multi-hop named pipe detection"
    )

    # First authorized click by user 12345
    res = gateway.handle_callback_query(
        user_id=12345,
        chat_id=1001,
        message_id=msg_id,
        callback_data=f"approve:{token}"
    )
    assert res["status"] == "approved"
    assert res["proposal_id"] == prop_id

    # Verify message was edited in place
    assert len(transport.edited_messages) == 1
    edited = transport.edited_messages[0]["text"]
    assert "CONTAINMENT APPROVED" in edited
    assert prop_id in edited
    assert "Decided At" in edited
    assert "Token Fingerprint" in edited
    assert "[DRY-RUN SIMULATION ONLY]" in edited

    # Second click must fail (TokenAlreadyConsumed)
    res_second = gateway.handle_callback_query(
        user_id=12345,
        chat_id=1001,
        message_id=msg_id,
        callback_data=f"approve:{token}"
    )
    assert "error" in res_second
    assert "already consumed" in res_second["error"].lower()


def test_telegram_text_command_fallback(hitl_and_gateway):
    mgr, gateway, transport = hitl_and_gateway
    prop_id, token = mgr.create_proposal(
        target="10.10.10.88",
        action="block_ip",
        reason="C2 beacon sink"
    )
    res = gateway.handle_text_command(
        user_id=67890,
        chat_id=1001,
        text=f"APPROVE {token}"
    )
    assert res["status"] == "approved"
    assert res["proposal_id"] == prop_id

    # Verify proposal is no longer pending
    pending = mgr.get_pending_proposals()
    assert len(pending) == 0


def test_telegram_expiry_edit(hitl_and_gateway):
    mgr, gateway, transport = hitl_and_gateway
    gateway.mark_expired(
        chat_id=1001,
        message_id=101,
        proposal_id="prop-test1234",
        action="isolate_host",
        target="lab-win10-03",
        token_fingerprint="abc12345"
    )
    assert len(transport.edited_messages) == 1
    edited = transport.edited_messages[0]["text"]
    assert "CONTAINMENT PROPOSAL EXPIRED" in edited
    assert "prop-test1234" in edited
    assert "Expired At" in edited
