import os
import time
import pytest
import tempfile
import sqlite3
from orchestrator.hitl_manager import (
    HITLManager,
    TokenAlreadyConsumed,
    TokenExpired,
    GateLockedOut,
)


@pytest.fixture
def hitl_mgr():
    import gc
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    mgr = HITLManager(db_path=db_path)
    yield mgr
    del mgr
    gc.collect()
    time.sleep(0.05)
    for ext in ("", "-wal", "-shm"):
        p = db_path + ext
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


def test_proposal_creation_and_token_format(hitl_mgr):
    prop_id, token = hitl_mgr.create_proposal(
        target="192.168.56.31",
        action="isolate_host",
        reason="Suspicious lateral SMB probe",
        ttl_seconds=300
    )
    assert prop_id.startswith("prop-")
    assert len(token) == 16  # 16-char hex from token_hex(8)
    # Raw token must NOT exist in the database
    with hitl_mgr._get_connection() as conn:
        row = conn.execute("SELECT token_hash FROM hitl_proposals WHERE proposal_id = ?", (prop_id,)).fetchone()
        assert row is not None
        assert row[0] != token
        assert row[0] == hitl_mgr.hash_token(token)


def test_token_single_use(hitl_mgr):
    prop_id, token = hitl_mgr.create_proposal(
        target="192.168.56.31",
        action="isolate_host",
        reason="Test isolation"
    )
    # First consume succeeds
    rec = hitl_mgr.verify_and_consume(token, actor="console")
    assert rec.proposal_id == prop_id
    assert rec.status == "approved"

    # Second consume must raise TokenAlreadyConsumed immediately
    with pytest.raises(TokenAlreadyConsumed):
        hitl_mgr.verify_and_consume(token, actor="console")


def test_shared_lockout_across_telegram_and_console(hitl_mgr):
    # Strike 1 from Telegram
    with pytest.raises(ValueError):
        hitl_mgr.verify_and_consume("badtok01", actor="telegram")

    # Strike 2 from Console
    with pytest.raises(ValueError):
        hitl_mgr.verify_and_consume("badtok02", actor="console")

    # Strike 3 from Telegram
    with pytest.raises(ValueError):
        hitl_mgr.verify_and_consume("badtok03", actor="telegram")

    # Strike 4: Must raise GateLockedOut
    with pytest.raises(GateLockedOut):
        hitl_mgr.verify_and_consume("anytoken", actor="console")


def test_token_expiration(hitl_mgr):
    prop_id, token = hitl_mgr.create_proposal(
        target="192.168.56.31",
        action="isolate_host",
        reason="Short lived",
        ttl_seconds=1
    )
    time.sleep(1.2)
    with pytest.raises(TokenExpired):
        hitl_mgr.verify_and_consume(token, actor="console")


def test_audit_log_stores_hash_only(hitl_mgr):
    prop_id, token = hitl_mgr.create_proposal(
        target="10.10.10.88",
        action="block_ip",
        reason="C2 beacon sink"
    )
    hitl_mgr.verify_and_consume(token, actor="console")

    with hitl_mgr._get_connection() as conn:
        rows = conn.execute("SELECT token_hash FROM hitl_audit WHERE proposal_id = ?", (prop_id,)).fetchall()
        assert len(rows) == 1
        assert rows[0][0] != token
        assert rows[0][0] == hitl_mgr.hash_token(token)
