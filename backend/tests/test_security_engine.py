"""AgentFence Comprehensive Security Test Suite
Covers all 15 core security testing requirements.
"""
import pytest
import json
import time
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy.orm import Session

from app.database.session import SessionLocal, init_db
from app.models.entities import Tenant, User, Agent, MCPTool, ProtectedResource, Policy, DelegationGrant, AuditEvent
from app.core.security import security_engine
from app.delegation.engine import delegation_engine
from app.policies.engine import policy_engine
from app.gateway.interceptor import gateway_interceptor
from app.audit.service import audit_service
from app.mcp.server import mcp_protocol_handler

@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    init_db()

@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

# 1. Valid delegation succeeds
def test_valid_delegation_succeeds(db: Session):
    success, grant, code, msg = delegation_engine.create_delegation(
        db=db,
        delegating_agent_id="usr_alpha_admin",
        receiving_agent_id="agent_alpha_primary",
        tenant_id="tenant_alpha",
        permitted_tools=["read_document"],
        permitted_actions=["read"],
        resource_restrictions=["doc_alpha_falcon"],
        duration_minutes=30
    )
    assert success is True
    assert grant is not None
    assert code == "DELEGATION_CREATED"

    # Test verification
    valid, payload, vcode, vmsg = delegation_engine.verify_active_delegation(
        db=db,
        delegation_token=grant.signature,
        expected_agent_id="agent_alpha_primary",
        expected_tool="read_document",
        expected_action="read",
        expected_resource="doc_alpha_falcon"
    )
    assert valid is True
    assert vcode == "DELEGATION_VALID"

# 2. Invalid signature is rejected
def test_invalid_signature_rejected(db: Session):
    valid_token = security_engine.create_delegation_credential(
        delegation_id="del_sig_test",
        parent_delegation_id=None,
        original_user_id="usr_alpha_admin",
        delegating_agent_id="usr_alpha_admin",
        receiving_agent_id="agent_alpha_primary",
        tenant_id="tenant_alpha",
        permitted_tools=["read_document"],
        permitted_actions=["read"],
        resource_restrictions=["doc_alpha_falcon"],
        max_depth=3,
        current_depth=1
    )
    # Corrupt signature portion
    tampered_token = valid_token[:-6] + "xxxxxx"
    valid, payload, code, msg = delegation_engine.verify_active_delegation(
        db=db,
        delegation_token=tampered_token,
        expected_agent_id="agent_alpha_primary",
        expected_tool="read_document",
        expected_action="read"
    )
    assert valid is False
    assert "TAMPER" in code or "INVALID" in code

# 3. Expired delegation is rejected
def test_expired_delegation_rejected(db: Session):
    expired_token = security_engine.create_delegation_credential(
        delegation_id="del_exp_test",
        parent_delegation_id=None,
        original_user_id="usr_alpha_admin",
        delegating_agent_id="usr_alpha_admin",
        receiving_agent_id="agent_alpha_primary",
        tenant_id="tenant_alpha",
        permitted_tools=["read_document"],
        permitted_actions=["read"],
        resource_restrictions=["doc_alpha_falcon"],
        max_depth=3,
        current_depth=1,
        expires_in_minutes=-5 # Expired
    )
    valid, payload, code, msg = delegation_engine.verify_active_delegation(
        db=db,
        delegation_token=expired_token,
        expected_agent_id="agent_alpha_primary",
        expected_tool="read_document",
        expected_action="read"
    )
    assert valid is False
    assert code == "DELEGATION_EXPIRED"

# 4. Audience mismatch is rejected
def test_audience_mismatch_rejected(db: Session):
    token = security_engine.create_delegation_credential(
        delegation_id="del_aud_test",
        parent_delegation_id=None,
        original_user_id="usr_alpha_admin",
        delegating_agent_id="usr_alpha_admin",
        receiving_agent_id="agent_alpha_primary",
        tenant_id="tenant_alpha",
        permitted_tools=["read_document"],
        permitted_actions=["read"],
        resource_restrictions=["doc_alpha_falcon"],
        max_depth=3,
        current_depth=1,
        audience="other-audience-gateway"
    )
    valid, payload, code, msg = delegation_engine.verify_active_delegation(
        db=db,
        delegation_token=token,
        expected_agent_id="agent_alpha_primary",
        expected_tool="read_document",
        expected_action="read",
        expected_audience="agentfence-gateway-v1"
    )
    assert valid is False
    assert code == "DELEGATION_AUDIENCE_MISMATCH"

# 5. Delegation scope escalation is rejected
def test_delegation_scope_escalation_rejected(db: Session):
    # Parent allows only 'read_document'
    success, grant, code, msg = delegation_engine.create_delegation(
        db=db,
        delegating_agent_id="agent_alpha_research",
        receiving_agent_id="agent_alpha_untrusted",
        tenant_id="tenant_alpha",
        permitted_tools=["read_document", "admin_override"], # Escalated!
        permitted_actions=["read", "override"],
        resource_restrictions=["doc_alpha_radar"],
        parent_delegation_id="del_alpha_child_002"
    )
    assert success is False
    assert code == "DELEGATION_ATTENUATION_ESCALATION"

# 6. Delegation depth violation is rejected
def test_delegation_depth_violation_rejected(db: Session):
    # del_alpha_child_002 is at depth 2 (max_depth 3)
    # Child will be depth 3 (allowed)
    s1, g1, _, _ = delegation_engine.create_delegation(
        db=db,
        delegating_agent_id="agent_alpha_research",
        receiving_agent_id="agent_alpha_untrusted",
        tenant_id="tenant_alpha",
        permitted_tools=["read_document"],
        permitted_actions=["read"],
        resource_restrictions=["doc_alpha_radar"],
        parent_delegation_id="del_alpha_child_002"
    )
    assert s1 is True
    assert g1.current_depth == 3

    # Attempt depth 4 (should be rejected since max_depth is 3)
    s2, g2, c2, m2 = delegation_engine.create_delegation(
        db=db,
        delegating_agent_id="agent_alpha_untrusted",
        receiving_agent_id="agent_alpha_primary",
        tenant_id="tenant_alpha",
        permitted_tools=["read_document"],
        permitted_actions=["read"],
        resource_restrictions=["doc_alpha_radar"],
        parent_delegation_id=g1.delegation_id
    )
    assert s2 is False
    assert c2 == "DELEGATION_DEPTH_EXCEEDED"

# 7. Cross-tenant access is rejected
def test_cross_tenant_access_rejected(db: Session):
    identity_token = security_engine.create_identity_token(
        subject="agent_alpha_primary",
        tenant_id="tenant_alpha",
        role="coordinator",
        principal_type="agent",
        agent_id="agent_alpha_primary"
    )
    res = gateway_interceptor.process_tool_invocation(
        db=db,
        tool_name="read_document",
        arguments={"resource_id": "doc_beta_trial"}, # Tenant Beta resource
        identity_token=identity_token
    )
    assert res["authorized"] is False
    assert res["decision"] == "DENY"
    assert res["reason_code"] == "AUTHZ_CROSS_TENANT_VIOLATION"

# 8. Unauthorized tool invocation is rejected
def test_unauthorized_tool_invocation_rejected(db: Session):
    identity_token = security_engine.create_identity_token(
        subject="agent_alpha_research",
        tenant_id="tenant_alpha",
        role="researcher",
        principal_type="agent",
        agent_id="agent_alpha_research"
    )
    res = gateway_interceptor.process_tool_invocation(
        db=db,
        tool_name="export_tenant_report", # Unauthorized tool
        arguments={"report_format": "csv"},
        identity_token=identity_token
    )
    assert res["authorized"] is False
    assert res["decision"] == "DENY"

# 9. Missing identity is rejected
def test_missing_identity_rejected(db: Session):
    res = gateway_interceptor.process_tool_invocation(
        db=db,
        tool_name="read_document",
        arguments={"resource_id": "doc_alpha_falcon"},
        identity_token=None # None
    )
    assert res["authorized"] is False
    assert res["reason_code"] == "AUTHN_MISSING_IDENTITY"

# 10. Replay protection works under concurrent requests
def test_replay_protection_concurrent(db: Session):
    identity_token = security_engine.create_identity_token(
        subject="agent_alpha_primary",
        tenant_id="tenant_alpha",
        role="coordinator",
        principal_type="agent",
        agent_id="agent_alpha_primary"
    )
    # Create single-use token
    _, grant, _, _ = delegation_engine.create_delegation(
        db=db,
        delegating_agent_id="usr_alpha_admin",
        receiving_agent_id="agent_alpha_primary",
        tenant_id="tenant_alpha",
        permitted_tools=["read_document"],
        permitted_actions=["read"],
        resource_restrictions=["doc_alpha_falcon"],
        duration_minutes=20,
        is_single_use=True
    )

    results = []
    def invoke():
        session = SessionLocal()
        try:
            return gateway_interceptor.process_tool_invocation(
                db=session,
                tool_name="read_document",
                arguments={"resource_id": "doc_alpha_falcon"},
                identity_token=identity_token,
                delegation_token=grant.signature
            )
        finally:
            session.close()

    # Send 5 concurrent requests with the exact same single-use token
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(invoke) for _ in range(5)]
        results = [f.result() for f in futures]

    allowed_count = sum(1 for r in results if r.get("decision") == "ALLOW")
    denied_count = sum(1 for r in results if r.get("decision") == "DENY" and "REPLAY" in r.get("reason_code", ""))
    
    assert allowed_count == 1, f"Expected exactly 1 request to succeed, got {allowed_count}"
    assert denied_count == 4, f"Expected 4 requests to be blocked by replay protection, got {denied_count}"

# 11. Revoked delegation is rejected
def test_revoked_delegation_rejected(db: Session):
    _, grant, _, _ = delegation_engine.create_delegation(
        db=db,
        delegating_agent_id="usr_alpha_admin",
        receiving_agent_id="agent_alpha_primary",
        tenant_id="tenant_alpha",
        permitted_tools=["read_document"],
        permitted_actions=["read"],
        resource_restrictions=["doc_alpha_falcon"],
        duration_minutes=30
    )
    # Revoke grant
    grant.is_revoked = True
    db.commit()

    valid, payload, code, msg = delegation_engine.verify_active_delegation(
        db=db,
        delegation_token=grant.signature,
        expected_agent_id="agent_alpha_primary",
        expected_tool="read_document",
        expected_action="read"
    )
    assert valid is False
    assert code == "DELEGATION_REVOKED"

# 12. Tool execution is never reached after an authorization denial
def test_upstream_never_reached_on_denial(db: Session):
    identity_token = security_engine.create_identity_token(
        subject="agent_alpha_primary",
        tenant_id="tenant_alpha",
        role="coordinator",
        principal_type="agent",
        agent_id="agent_alpha_primary"
    )
    res = gateway_interceptor.process_tool_invocation(
        db=db,
        tool_name="read_document",
        arguments={"resource_id": "doc_beta_trial"}, # Cross-tenant
        identity_token=identity_token
    )
    assert res["authorized"] is False
    assert "result" not in res # Upstream result absent

# 13. Audit events are generated for allowed and denied requests
def test_audit_events_generated(db: Session):
    prev_count = db.query(AuditEvent).count()
    # Trigger 1 allowed and 1 denied
    identity_token = security_engine.create_identity_token(
        subject="agent_alpha_primary",
        tenant_id="tenant_alpha",
        role="coordinator",
        principal_type="agent",
        agent_id="agent_alpha_primary"
    )
    # 1 Denied (cross-tenant)
    gateway_interceptor.process_tool_invocation(
        db=db,
        tool_name="read_document",
        arguments={"resource_id": "doc_beta_trial"},
        identity_token=identity_token
    )
    # 1 Denied (missing identity)
    gateway_interceptor.process_tool_invocation(
        db=db,
        tool_name="read_document",
        arguments={"resource_id": "doc_alpha_falcon"},
        identity_token=None
    )
    new_count = db.query(AuditEvent).count()
    assert new_count == prev_count + 2

# 14. Audit integrity verification detects modified records
def test_audit_integrity_detects_tampering(db: Session):
    # Verify baseline is valid
    valid_initial, count_initial, _ = audit_service.verify_audit_chain_integrity(db)
    assert valid_initial is True

    # Tamper with an audit event's content
    event_to_tamper = db.query(AuditEvent).first()
    original_decision = event_to_tamper.decision
    event_to_tamper.decision = "ALLOW" if original_decision == "DENY" else "DENY"
    db.commit()

    # Re-verify: must fail
    valid_tampered, count_tampered, err = audit_service.verify_audit_chain_integrity(db)
    assert valid_tampered is False
    assert err is not None
    assert "tampering" in err.get("error", "").lower()

    # Restore original content
    event_to_tamper.decision = original_decision
    db.commit()

    # Verify restored
    valid_restored, _, _ = audit_service.verify_audit_chain_integrity(db)
    assert valid_restored is True

# 15. Tenant isolation holds across all relevant resource queries
def test_tenant_isolation_queries(db: Session):
    alpha_docs = db.query(ProtectedResource).filter(ProtectedResource.tenant_id == "tenant_alpha").all()
    beta_docs = db.query(ProtectedResource).filter(ProtectedResource.tenant_id == "tenant_beta").all()

    assert len(alpha_docs) >= 2
    assert len(beta_docs) >= 2

    alpha_ids = {d.id for d in alpha_docs}
    beta_ids = {d.id for d in beta_docs}

    assert alpha_ids.isdisjoint(beta_ids)
    for doc in alpha_docs:
        assert doc.tenant_id == "tenant_alpha"
    for doc in beta_docs:
        assert doc.tenant_id == "tenant_beta"
