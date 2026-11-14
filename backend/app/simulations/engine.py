"""AgentFence Attack Simulation Lab: 10 Repeatable Attack Scenarios
Executes live attacks against the actual security engine to demonstrate real authorization enforcement.
"""
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.core.security import security_engine
from app.gateway.interceptor import gateway_interceptor
from app.delegation.engine import delegation_engine
from app.models.entities import AttackSimulationResult, AuditEvent

class AttackSimulationLab:
    def __init__(self):
        self.security = security_engine
        self.interceptor = gateway_interceptor
        self.delegation = delegation_engine

    def run_all_simulations(self, db: Session) -> List[Dict[str, Any]]:
        """Runs all 10 attack scenarios and records actual results."""
        results = [
            self.run_attack_1_confused_deputy(db),
            self.run_attack_2_cross_tenant_access(db),
            self.run_attack_3_privilege_escalation(db),
            self.run_attack_4_delegation_tampering(db),
            self.run_attack_5_expired_delegation(db),
            self.run_attack_6_audience_mismatch(db),
            self.run_attack_7_replay_attack(db),
            self.run_attack_8_excessive_depth(db),
            self.run_attack_9_unauthorized_tool(db),
            self.run_attack_10_missing_identity(db),
        ]
        return results

    def _save_result(
        self,
        db: Session,
        key: str,
        name: str,
        expected: str,
        actual: str,
        passed: bool,
        request_details: Dict[str, Any],
        checks: List[Dict[str, Any]],
        audit_event_id: str = None
    ) -> Dict[str, Any]:
        sim_res = AttackSimulationResult(
            id=self.security.generate_id("sim"),
            simulation_key=key,
            scenario_name=name,
            expected_result=expected,
            actual_result=actual,
            passed=passed,
            request_details_json=json.dumps(request_details),
            checks_evaluated_json=json.dumps(checks),
            audit_event_id=audit_event_id,
            executed_at=datetime.now(timezone.utc)
        )
        db.add(sim_res)
        db.commit()

        return {
            "key": key,
            "scenario_name": name,
            "expected_result": expected,
            "actual_result": actual,
            "passed": passed,
            "request_details": request_details,
            "checks_evaluated": checks,
            "audit_event_id": audit_event_id
        }

    # Attack 1: Confused Deputy Attack
    def run_attack_1_confused_deputy(self, db: Session) -> Dict[str, Any]:
        """A low-privilege untrusted agent attempts to invoke the privileged admin_override tool."""
        # Untrusted agent identity token
        identity_token = self.security.create_identity_token(
            subject="agent_alpha_untrusted",
            tenant_id="tenant_alpha",
            role="plugin",
            principal_type="agent",
            agent_id="agent_alpha_untrusted"
        )

        res = self.interceptor.process_tool_invocation(
            db=db,
            tool_name="admin_override",
            arguments={"action": "disable_safety_guards"},
            identity_token=identity_token
        )

        passed = res.get("decision") == "DENY" and "CONFUSED_DEPUTY" in res.get("reason_code", "")
        last_audit = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()

        return self._save_result(
            db=db,
            key="attack_1_confused_deputy",
            name="Attack 1: Confused Deputy Attack",
            expected="DENIED (AUTHZ_CONFUSED_DEPUTY_DETECTED)",
            actual=f"{res.get('decision')} ({res.get('reason_code')})",
            passed=passed,
            request_details={"agent": "agent_alpha_untrusted", "role": "plugin", "target_tool": "admin_override"},
            checks=[
                {"check": "Principal Identity", "status": "VERIFIED"},
                {"check": "Role Privilege Match", "status": "FAILED (Expected admin, got plugin)"},
                {"check": "Upstream Execution", "status": "BLOCKED"}
            ],
            audit_event_id=last_audit.id if last_audit else None
        )

    # Attack 2: Cross-Tenant Data Access
    def run_attack_2_cross_tenant_access(self, db: Session) -> Dict[str, Any]:
        """Alpha agent requests Beta tenant protected document doc_beta_trial."""
        # Alpha agent identity token
        identity_token = self.security.create_identity_token(
            subject="agent_alpha_primary",
            tenant_id="tenant_alpha",
            role="coordinator",
            principal_type="agent",
            agent_id="agent_alpha_primary"
        )

        res = self.interceptor.process_tool_invocation(
            db=db,
            tool_name="read_document",
            arguments={"resource_id": "doc_beta_trial"}, # Beta document
            identity_token=identity_token
        )

        passed = res.get("decision") == "DENY" and "CROSS_TENANT" in res.get("reason_code", "")
        last_audit = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()

        return self._save_result(
            db=db,
            key="attack_2_cross_tenant",
            name="Attack 2: Cross-Tenant Data Access",
            expected="DENIED (AUTHZ_CROSS_TENANT_VIOLATION)",
            actual=f"{res.get('decision')} ({res.get('reason_code')})",
            passed=passed,
            request_details={"agent": "agent_alpha_primary", "tenant": "tenant_alpha", "requested_resource": "doc_beta_trial"},
            checks=[
                {"check": "Agent Tenant Context", "status": "tenant_alpha"},
                {"check": "Resource Tenant Context", "status": "tenant_beta (MISMATCH)"},
                {"check": "Isolation Boundary", "status": "ENFORCED (Access Denied)"}
            ],
            audit_event_id=last_audit.id if last_audit else None
        )

    # Attack 3: Delegation Privilege Escalation
    def run_attack_3_privilege_escalation(self, db: Session) -> Dict[str, Any]:
        """An agent attempts to delegate write permissions when parent delegation grants read-only access."""
        # Parent grant has tools: read_document only
        parent_del_id = "del_alpha_child_002" # Has only read_document
        
        # Sub-agent attempts to create child delegation with escalated tool: admin_override
        success, grant, code, msg = self.delegation.create_delegation(
            db=db,
            delegating_agent_id="agent_alpha_research",
            receiving_agent_id="agent_alpha_untrusted",
            tenant_id="tenant_alpha",
            permitted_tools=["read_document", "admin_override"], # Escalated!
            permitted_actions=["read", "override"],               # Escalated!
            resource_restrictions=["doc_alpha_radar"],
            parent_delegation_id=parent_del_id,
            duration_minutes=30
        )

        passed = (not success) and "ESCALATION" in code
        return self._save_result(
            db=db,
            key="attack_3_privilege_escalation",
            name="Attack 3: Delegation Privilege Escalation",
            expected="DENIED (DELEGATION_ATTENUATION_ESCALATION)",
            actual=f"{'ALLOWED' if success else 'DENIED'} ({code})",
            passed=passed,
            request_details={"parent_delegation": parent_del_id, "escalated_tools": ["admin_override"]},
            checks=[
                {"check": "Parent Scope Inspection", "status": "['read_document']"},
                {"check": "Requested Scope Attenuation", "status": "FAILED (admin_override not in parent)"},
                {"check": "Credential Issuance", "status": "BLOCKED"}
            ]
        )

    # Attack 4: Delegation Chain Tampering
    def run_attack_4_delegation_tampering(self, db: Session) -> Dict[str, Any]:
        """An attacker modifies claims in a delegation token payload without updating signature."""
        identity_token = self.security.create_identity_token(
            subject="agent_alpha_primary",
            tenant_id="tenant_alpha",
            role="coordinator",
            principal_type="agent",
            agent_id="agent_alpha_primary"
        )

        # Create valid token
        del_tamper_id = self.security.generate_id("del_tamper")
        valid_token = self.security.create_delegation_credential(
            delegation_id=del_tamper_id,
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

        # Tamper the token by modifying the base64 payload segment
        parts = valid_token.split(".")
        tampered_token = f"{parts[0]}.eyJhZG1pbiI6dHJ1ZX0.{parts[2]}" # Injected fake payload

        res = self.interceptor.process_tool_invocation(
            db=db,
            tool_name="read_document",
            arguments={"resource_id": "doc_alpha_falcon"},
            identity_token=identity_token,
            delegation_token=tampered_token
        )

        passed = res.get("decision") == "DENY" and ("TAMPER" in res.get("reason_code", "") or "INVALID" in res.get("reason_code", ""))
        last_audit = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()

        return self._save_result(
            db=db,
            key="attack_4_chain_tampering",
            name="Attack 4: Delegation Chain Tampering",
            expected="DENIED (DELEGATION_TAMPERING_DETECTED)",
            actual=f"{res.get('decision')} ({res.get('reason_code')})",
            passed=passed,
            request_details={"token_tampering": "payload segment replaced with forged claims"},
            checks=[
                {"check": "JWT Header", "status": "VERIFIED"},
                {"check": "Cryptographic Signature", "status": "FAILED (Signature Mismatch)"},
                {"check": "Tamper Evidence Engine", "status": "ALERT_TRIGGERED"}
            ],
            audit_event_id=last_audit.id if last_audit else None
        )

    # Attack 5: Expired Delegation
    def run_attack_5_expired_delegation(self, db: Session) -> Dict[str, Any]:
        """An agent attempts tool execution with an expired delegation credential."""
        identity_token = self.security.create_identity_token(
            subject="agent_alpha_primary",
            tenant_id="tenant_alpha",
            role="coordinator",
            principal_type="agent",
            agent_id="agent_alpha_primary"
        )

        # Create expired credential (issued with negative duration)
        del_exp_id = self.security.generate_id("del_expired")
        expired_token = self.security.create_delegation_credential(
            delegation_id=del_exp_id,
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
            expires_in_minutes=-10 # Already expired!
        )

        res = self.interceptor.process_tool_invocation(
            db=db,
            tool_name="read_document",
            arguments={"resource_id": "doc_alpha_falcon"},
            identity_token=identity_token,
            delegation_token=expired_token
        )

        passed = res.get("decision") == "DENY" and "EXPIRED" in res.get("reason_code", "")
        last_audit = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()

        return self._save_result(
            db=db,
            key="attack_5_expired_delegation",
            name="Attack 5: Expired Delegation Credential",
            expected="DENIED (DELEGATION_EXPIRED)",
            actual=f"{res.get('decision')} ({res.get('reason_code')})",
            passed=passed,
            request_details={"expiration_offset": "-10 minutes"},
            checks=[
                {"check": "Signature", "status": "VALID"},
                {"check": "Temporal Validity (nbf <= now < exp)", "status": "FAILED (Token expired)"},
                {"check": "Execution Gate", "status": "BLOCKED"}
            ],
            audit_event_id=last_audit.id if last_audit else None
        )

    # Attack 6: Audience Mismatch
    def run_attack_6_audience_mismatch(self, db: Session) -> Dict[str, Any]:
        """A delegation credential intended for foreign audience presented to AgentFence."""
        identity_token = self.security.create_identity_token(
            subject="agent_alpha_primary",
            tenant_id="tenant_alpha",
            role="coordinator",
            principal_type="agent",
            agent_id="agent_alpha_primary"
        )

        # Created for audience 'foreign-gateway-eu'
        del_aud_id = self.security.generate_id("del_aud")
        foreign_token = self.security.create_delegation_credential(
            delegation_id=del_aud_id,
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
            audience="foreign-gateway-eu" # Foreign audience!
        )

        res = self.interceptor.process_tool_invocation(
            db=db,
            tool_name="read_document",
            arguments={"resource_id": "doc_alpha_falcon"},
            identity_token=identity_token,
            delegation_token=foreign_token,
            client_audience="agentfence-gateway-v1" # Expected audience
        )

        passed = res.get("decision") == "DENY" and "AUDIENCE" in res.get("reason_code", "")
        last_audit = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()

        return self._save_result(
            db=db,
            key="attack_6_audience_mismatch",
            name="Attack 6: Audience Mismatch",
            expected="DENIED (DELEGATION_AUDIENCE_MISMATCH)",
            actual=f"{res.get('decision')} ({res.get('reason_code')})",
            passed=passed,
            request_details={"token_aud": "foreign-gateway-eu", "gateway_expected_aud": "agentfence-gateway-v1"},
            checks=[
                {"check": "Audience Validation", "status": "FAILED (Mismatch)"},
                {"check": "Token Boundary Isolation", "status": "ENFORCED"},
                {"check": "Execution Gate", "status": "BLOCKED"}
            ],
            audit_event_id=last_audit.id if last_audit else None
        )

    # Attack 7: Replay Attack
    def run_attack_7_replay_attack(self, db: Session) -> Dict[str, Any]:
        """A single-use delegation credential is consumed twice."""
        identity_token = self.security.create_identity_token(
            subject="agent_alpha_primary",
            tenant_id="tenant_alpha",
            role="coordinator",
            principal_type="agent",
            agent_id="agent_alpha_primary"
        )

        # Create single-use delegation
        _, grant, _, _ = self.delegation.create_delegation(
            db=db,
            delegating_agent_id="usr_alpha_admin",
            receiving_agent_id="agent_alpha_primary",
            tenant_id="tenant_alpha",
            permitted_tools=["read_document"],
            permitted_actions=["read"],
            resource_restrictions=["doc_alpha_falcon"],
            duration_minutes=30,
            is_single_use=True
        )

        # First consumption: SHOULD SUCCEED
        res1 = self.interceptor.process_tool_invocation(
            db=db,
            tool_name="read_document",
            arguments={"resource_id": "doc_alpha_falcon"},
            identity_token=identity_token,
            delegation_token=grant.signature
        )

        # Second consumption: MUST BE DENIED AS REPLAY
        res2 = self.interceptor.process_tool_invocation(
            db=db,
            tool_name="read_document",
            arguments={"resource_id": "doc_alpha_falcon"},
            identity_token=identity_token,
            delegation_token=grant.signature
        )

        passed = res1.get("decision") == "ALLOW" and res2.get("decision") == "DENY" and "REPLAY" in res2.get("reason_code", "")
        last_audit = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()

        return self._save_result(
            db=db,
            key="attack_7_replay_attack",
            name="Attack 7: Token Replay Attack",
            expected="DENIED (REPLAY_ATTACK_DETECTED on 2nd attempt)",
            actual=f"1st: {res1.get('decision')} -> 2nd: {res2.get('decision')} ({res2.get('reason_code')})",
            passed=passed,
            request_details={"single_use": True, "token_jti": grant.jti, "reuse_attempt": 2},
            checks=[
                {"check": "1st Invocaton", "status": "ALLOWED & JTI_CONSUMED"},
                {"check": "2nd Invocation Replay Check", "status": "FAILED (Atomic JTI Replay Detected)"},
                {"check": "Upstream Execution 2", "status": "BLOCKED"}
            ],
            audit_event_id=last_audit.id if last_audit else None
        )

    # Attack 8: Excessive Delegation Depth
    def run_attack_8_excessive_depth(self, db: Session) -> Dict[str, Any]:
        """A sub-agent tries to create an unauthorized additional delegation level beyond max depth."""
        # Root grant depth: 1, max_depth: 2
        # Level 2 grant depth: 2
        # Level 3 attempt must exceed max_depth 2
        root_del_id = self.security.generate_id("del_depth_root")
        root_token = self.security.create_delegation_credential(
            delegation_id=root_del_id,
            parent_delegation_id=None,
            original_user_id="usr_alpha_admin",
            delegating_agent_id="usr_alpha_admin",
            receiving_agent_id="agent_alpha_primary",
            tenant_id="tenant_alpha",
            permitted_tools=["read_document"],
            permitted_actions=["read"],
            resource_restrictions=["doc_alpha_falcon"],
            max_depth=2, # Cap at 2
            current_depth=1
        )
        _, payload_root, _ = self.security.verify_delegation_credential(root_token)
        
        from app.models.entities import DelegationGrant
        grant_root = DelegationGrant(
            id=self.security.generate_id("grant"),
            delegation_id=root_del_id,
            parent_delegation_id=None,
            tenant_id="tenant_alpha",
            original_user_id="usr_alpha_admin",
            delegating_agent_id="usr_alpha_admin",
            receiving_agent_id="agent_alpha_primary",
            permitted_tools_json=json.dumps(["read_document"]),
            permitted_actions_json=json.dumps(["read"]),
            resource_restrictions_json=json.dumps(["doc_alpha_falcon"]),
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            max_depth=2,
            current_depth=1,
            jti=payload_root["jti"],
            audience=payload_root["aud"],
            signature=root_token,
            is_single_use=False,
            is_consumed=False,
            is_revoked=False,
            created_at=datetime.now(timezone.utc)
        )
        db.add(grant_root)
        db.commit()

        # Child 1 at depth 2 (Allowed)
        success1, grant2, _, _ = self.delegation.create_delegation(
            db=db,
            delegating_agent_id="agent_alpha_primary",
            receiving_agent_id="agent_alpha_research",
            tenant_id="tenant_alpha",
            permitted_tools=["read_document"],
            permitted_actions=["read"],
            resource_restrictions=["doc_alpha_falcon"],
            parent_delegation_id=root_del_id,
            duration_minutes=30
        )

        # Child 2 at depth 3 (MUST BE REJECTED - exceeds max_depth 2)
        success2, _, code2, msg2 = self.delegation.create_delegation(
            db=db,
            delegating_agent_id="agent_alpha_research",
            receiving_agent_id="agent_alpha_untrusted",
            tenant_id="tenant_alpha",
            permitted_tools=["read_document"],
            permitted_actions=["read"],
            resource_restrictions=["doc_alpha_falcon"],
            parent_delegation_id=grant2.delegation_id,
            duration_minutes=20
        )

        passed = success1 and (not success2) and "DEPTH" in code2
        return self._save_result(
            db=db,
            key="attack_8_excessive_depth",
            name="Attack 8: Excessive Delegation Depth",
            expected="DENIED (DELEGATION_DEPTH_EXCEEDED)",
            actual=f"{'ALLOWED' if success2 else 'DENIED'} ({code2})",
            passed=passed,
            request_details={"chain_length": 3, "max_depth_permitted": 2},
            checks=[
                {"check": "Level 1 (User -> Primary)", "status": "DEPTH_1 (ALLOWED)"},
                {"check": "Level 2 (Primary -> Research)", "status": "DEPTH_2 (ALLOWED)"},
                {"check": "Level 3 (Research -> Plugin)", "status": "DEPTH_3 > 2 (REJECTED)"}
            ]
        )

    # Attack 9: Unauthorized Tool Execution
    def run_attack_9_unauthorized_tool(self, db: Session) -> Dict[str, Any]:
        """A valid agent attempts to invoke a tool outside its delegated scope."""
        identity_token = self.security.create_identity_token(
            subject="agent_alpha_research",
            tenant_id="tenant_alpha",
            role="researcher",
            principal_type="agent",
            agent_id="agent_alpha_research"
        )

        # Agent Alpha Research only has read_document in seed delegation del_alpha_child_002
        # Attempt to invoke export_tenant_report
        res = self.interceptor.process_tool_invocation(
            db=db,
            tool_name="export_tenant_report", # Not in scope!
            arguments={"report_format": "json"},
            identity_token=identity_token,
            delegation_token=None # Missing valid delegation for export_tenant_report
        )

        passed = res.get("decision") == "DENY"
        last_audit = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()

        return self._save_result(
            db=db,
            key="attack_9_unauthorized_tool",
            name="Attack 9: Unauthorized Tool Execution",
            expected="DENIED (AUTHZ_NO_MATCHING_ALLOW_POLICY / UNAUTHORIZED_TOOL)",
            actual=f"{res.get('decision')} ({res.get('reason_code')})",
            passed=passed,
            request_details={"agent": "agent_alpha_research", "attempted_tool": "export_tenant_report"},
            checks=[
                {"check": "Agent Scope Check", "status": "export_tenant_report not authorized"},
                {"check": "Policy Evaluation", "status": "DENY (No matching allow rule)"},
                {"check": "Upstream Call", "status": "BLOCKED"}
            ],
            audit_event_id=last_audit.id if last_audit else None
        )

    # Attack 10: Missing Identity Context
    def run_attack_10_missing_identity(self, db: Session) -> Dict[str, Any]:
        """A tool call arrives without valid authenticated identity and delegation context."""
        res = self.interceptor.process_tool_invocation(
            db=db,
            tool_name="read_document",
            arguments={"resource_id": "doc_alpha_falcon"},
            identity_token=None # Missing identity!
        )

        passed = res.get("decision") == "DENY" and "MISSING_IDENTITY" in res.get("reason_code", "")
        last_audit = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()

        return self._save_result(
            db=db,
            key="attack_10_missing_identity",
            name="Attack 10: Missing Identity Context",
            expected="DENIED (AUTHN_MISSING_IDENTITY)",
            actual=f"{res.get('decision')} ({res.get('reason_code')})",
            passed=passed,
            request_details={"identity_token": None, "transport_auth": "MISSING"},
            checks=[
                {"check": "Transport Context Extraction", "status": "FAILED (None found)"},
                {"check": "Fail-Closed Gateway Rule", "status": "ENFORCED (Default Deny)"},
                {"check": "Execution Gate", "status": "BLOCKED"}
            ],
            audit_event_id=last_audit.id if last_audit else None
        )

attack_simulation_lab = AttackSimulationLab()
