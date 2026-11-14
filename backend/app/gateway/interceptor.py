"""AgentFence Gateway Interceptor: Authorization Enforcement for MCP Tool Invocations
"""
import uuid
from typing import Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from app.core.security import security_engine
from app.delegation.engine import delegation_engine
from app.policies.engine import policy_engine
from app.audit.service import audit_service
from app.mcp.upstream_mock import upstream_mcp_server
from app.models.entities import MCPTool, ProtectedResource

class GatewayInterceptor:
    def __init__(self):
        self.security = security_engine
        self.delegation = delegation_engine
        self.policy = policy_engine
        self.audit = audit_service
        self.upstream = upstream_mcp_server

    def process_tool_invocation(
        self,
        db: Session,
        tool_name: str,
        arguments: Dict[str, Any],
        identity_token: Optional[str] = None,
        delegation_token: Optional[str] = None,
        client_audience: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Intercepts, authenticates, authorizes, and forwards MCP tool execution."""
        request_id = self.security.generate_id("req")
        corr_id = correlation_id or self.security.generate_id("corr")
        
        # Tool requested action & resource identification
        requested_action = "read"
        if "action" in arguments:
            requested_action = str(arguments["action"])
        elif "query" in arguments or "query_type" in arguments:
            requested_action = "execute"
        elif "report_format" in arguments:
            requested_action = "export"

        resource_id = arguments.get("resource_id") or arguments.get("dataset_id")

        # -------------------------------------------------------------
        # STEP 1: Authentication Resolution (Identity Verification)
        # -------------------------------------------------------------
        if not identity_token:
            # Denied: Missing identity
            denial_msg = "No authenticated identity token supplied in transport context"
            self.audit.log_event(
                db=db,
                request_id=request_id,
                correlation_id=corr_id,
                tenant_id="unauthenticated",
                user_id=None,
                agent_id=None,
                parent_delegation_id=None,
                delegation_id=None,
                mcp_tool_name=tool_name,
                requested_action=requested_action,
                resource_id=resource_id,
                decision="DENY",
                denial_reason=denial_msg,
                attack_classification="missing_identity",
                execution_outcome="blocked"
            )
            return {
                "authorized": False,
                "decision": "DENY",
                "reason_code": "AUTHN_MISSING_IDENTITY",
                "message": denial_msg,
                "correlation_id": corr_id,
                "content": [{"type": "text", "text": f"AgentFence Access Denied: {denial_msg}"}]
            }

        id_valid, id_payload, id_msg = self.security.verify_identity_token(
            identity_token,
            expected_audience=client_audience
        )
        if not id_valid or not id_payload:
            self.audit.log_event(
                db=db,
                request_id=request_id,
                correlation_id=corr_id,
                tenant_id="invalid_token",
                user_id=None,
                agent_id=None,
                parent_delegation_id=None,
                delegation_id=None,
                mcp_tool_name=tool_name,
                requested_action=requested_action,
                resource_id=resource_id,
                decision="DENY",
                denial_reason=id_msg,
                attack_classification="missing_identity",
                execution_outcome="blocked"
            )
            return {
                "authorized": False,
                "decision": "DENY",
                "reason_code": "AUTHN_INVALID_IDENTITY_TOKEN",
                "message": id_msg,
                "correlation_id": corr_id,
                "content": [{"type": "text", "text": f"AgentFence Access Denied: {id_msg}"}]
            }

        # Authenticated principal claims
        tenant_id = id_payload["tid"]
        principal_id = id_payload["sub"]
        principal_type = id_payload.get("ptyp", "user")
        principal_role = id_payload.get("role", "user")
        acting_agent_id = id_payload.get("aid") or principal_id

        # -------------------------------------------------------------
        # STEP 2: Delegation Verification (if delegation token provided or agent)
        # -------------------------------------------------------------
        delegation_payload = None
        delegation_id = None
        parent_del_id = None

        if delegation_token:
            del_valid, del_payload, del_code, del_msg = self.delegation.verify_active_delegation(
                db=db,
                delegation_token=delegation_token,
                expected_agent_id=acting_agent_id,
                expected_tool=tool_name,
                expected_action=requested_action,
                expected_resource=resource_id,
                expected_audience=client_audience
            )

            # Map error code to attack classification
            attack_class = None
            if del_code == "REPLAY_ATTACK_DETECTED":
                attack_class = "replay_attack"
            elif del_code == "DELEGATION_EXPIRED":
                attack_class = "expired_delegation"
            elif del_code == "DELEGATION_AUDIENCE_MISMATCH":
                attack_class = "audience_mismatch"
            elif del_code == "DELEGATION_TAMPERING_DETECTED":
                attack_class = "delegation_tampering"
            elif del_code == "EXCESSIVE_DELEGATION_DEPTH":
                attack_class = "excessive_depth"
            elif del_code == "UNAUTHORIZED_TOOL_EXECUTION":
                attack_class = "unauthorized_tool"
            elif del_code == "RESOURCE_ACCESS_RESTRICTED":
                attack_class = "privilege_escalation"

            if not del_valid:
                self.audit.log_event(
                    db=db,
                    request_id=request_id,
                    correlation_id=corr_id,
                    tenant_id=tenant_id,
                    user_id=del_payload.get("orig_uid") if del_payload else None,
                    agent_id=acting_agent_id,
                    parent_delegation_id=del_payload.get("pdel_id") if del_payload else None,
                    delegation_id=del_payload.get("del_id") if del_payload else None,
                    mcp_tool_name=tool_name,
                    requested_action=requested_action,
                    resource_id=resource_id,
                    decision="DENY",
                    denial_reason=del_msg,
                    attack_classification=attack_class,
                    execution_outcome="blocked"
                )
                return {
                    "authorized": False,
                    "decision": "DENY",
                    "reason_code": del_code,
                    "message": del_msg,
                    "correlation_id": corr_id,
                    "content": [{"type": "text", "text": f"AgentFence Delegation Denied [{del_code}]: {del_msg}"}]
                }

            delegation_payload = del_payload
            delegation_id = del_payload.get("del_id")
            parent_del_id = del_payload.get("pdel_id")

        # -------------------------------------------------------------
        # STEP 3: Policy Decision Engine (RBAC + ABAC + Tenant Isolation)
        # -------------------------------------------------------------
        policy_decision = self.policy.evaluate(
            db=db,
            principal_id=principal_id,
            principal_type=principal_type,
            principal_role=principal_role,
            acting_agent_id=acting_agent_id,
            tenant_id=tenant_id,
            tool_name=tool_name,
            requested_action=requested_action,
            resource_id=resource_id,
            delegation_payload=delegation_payload,
            correlation_id=corr_id
        )

        if policy_decision.decision != "ALLOW":
            attack_class = None
            if policy_decision.reason_code == "AUTHZ_CROSS_TENANT_VIOLATION":
                attack_class = "cross_tenant"
            elif policy_decision.reason_code == "AUTHZ_CONFUSED_DEPUTY_DETECTED":
                attack_class = "confused_deputy"

            self.audit.log_event(
                db=db,
                request_id=request_id,
                correlation_id=corr_id,
                tenant_id=tenant_id,
                user_id=principal_id if principal_type == "user" else (delegation_payload.get("orig_uid") if delegation_payload else None),
                agent_id=acting_agent_id,
                parent_delegation_id=parent_del_id,
                delegation_id=delegation_id,
                mcp_tool_name=tool_name,
                requested_action=requested_action,
                resource_id=resource_id,
                decision="DENY",
                denial_reason=policy_decision.explanation,
                attack_classification=attack_class,
                execution_outcome="blocked"
            )

            return {
                "authorized": False,
                "decision": "DENY",
                "reason_code": policy_decision.reason_code,
                "message": policy_decision.explanation,
                "matched_policy": policy_decision.matched_policy,
                "correlation_id": corr_id,
                "content": [{"type": "text", "text": f"AgentFence Policy Denied [{policy_decision.reason_code}]: {policy_decision.explanation}"}]
            }

        # -------------------------------------------------------------
        # STEP 4: Forward to Upstream MCP Tool Execution (Only When Authorized)
        # -------------------------------------------------------------
        execution_result = self.upstream.execute_tool(
            db=db,
            tool_name=tool_name,
            arguments=arguments,
            tenant_id=tenant_id
        )

        outcome = "success" if not execution_result.get("isError") else "error"

        # Log authorized audit event
        self.audit.log_event(
            db=db,
            request_id=request_id,
            correlation_id=corr_id,
            tenant_id=tenant_id,
            user_id=principal_id if principal_type == "user" else (delegation_payload.get("orig_uid") if delegation_payload else None),
            agent_id=acting_agent_id,
            parent_delegation_id=parent_del_id,
            delegation_id=delegation_id,
            mcp_tool_name=tool_name,
            requested_action=requested_action,
            resource_id=resource_id,
            decision="ALLOW",
            denial_reason=None,
            attack_classification=None,
            execution_outcome=outcome
        )

        return {
            "authorized": True,
            "decision": "ALLOW",
            "reason_code": policy_decision.reason_code,
            "matched_policy": policy_decision.matched_policy,
            "correlation_id": corr_id,
            "result": execution_result
        }

gateway_interceptor = GatewayInterceptor()
