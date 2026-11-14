"""AgentFence Delegation Engine: Attenuation Verification, Depth Enforcement, and Chain Validation
"""
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.models.entities import DelegationGrant, Agent, User
from app.core.security import security_engine

class AttenuationViolationError(Exception):
    def __init__(self, message: str, reason_code: str = "DELEGATION_ATTENUATION_ESCALATION"):
        super().__init__(message)
        self.reason_code = reason_code

class DelegationEngine:
    def __init__(self):
        self.security = security_engine

    def validate_permission_attenuation(
        self,
        parent_grant: DelegationGrant,
        requested_tools: List[str],
        requested_actions: List[str],
        requested_resources: List[str],
        requested_expires_at: datetime,
        requested_tenant_id: str,
        requested_depth: int
    ) -> Tuple[bool, Optional[str]]:
        """Strict permission attenuation enforcement:
        Child delegation MUST NEVER gain more authority than parent.
        """
        # 1. Tenant boundary must remain strictly identical
        if requested_tenant_id != parent_grant.tenant_id:
            return False, f"Delegation cannot cross tenant boundary: parent belongs to '{parent_grant.tenant_id}', requested '{requested_tenant_id}'"

        # 2. Tool permissions must be a subset of parent tools
        parent_tools = set(parent_grant.get_permitted_tools())
        child_tools = set(requested_tools)
        escalated_tools = child_tools - parent_tools
        if escalated_tools:
            return False, f"Permission escalation: child requested tools {list(escalated_tools)} not permitted in parent delegation"

        # 3. Action permissions must be a subset of parent actions
        parent_actions = set(parent_grant.get_permitted_actions())
        child_actions = set(requested_actions)
        escalated_actions = child_actions - parent_actions
        if escalated_actions:
            return False, f"Permission escalation: child requested actions {list(escalated_actions)} not permitted in parent delegation"

        # 4. Resource restrictions must be a subset of parent resources (if parent is restricted)
        parent_resources = set(parent_grant.get_resource_restrictions())
        child_resources = set(requested_resources)
        if parent_resources and "*" not in parent_resources:
            escalated_resources = child_resources - parent_resources
            if escalated_resources:
                return False, f"Permission escalation: child requested access to resources {list(escalated_resources)} outside parent boundary"

        # 5. Expiration cannot exceed parent expiration
        parent_exp = parent_grant.expires_at
        if parent_exp.tzinfo is None:
            parent_exp = parent_exp.replace(tzinfo=timezone.utc)
        req_exp = requested_expires_at
        if req_exp.tzinfo is None:
            req_exp = req_exp.replace(tzinfo=timezone.utc)

        if req_exp > parent_exp:
            return False, f"Permission escalation: child expiration ({req_exp.isoformat()}) exceeds parent expiration ({parent_exp.isoformat()})"

        # 6. Delegation depth limit
        if requested_depth > parent_grant.max_depth:
            return False, f"Delegation depth exceeded: requested depth {requested_depth} exceeds permitted max depth {parent_grant.max_depth}"

        return True, None

    def create_delegation(
        self,
        db: Session,
        delegating_agent_id: str,
        receiving_agent_id: str,
        tenant_id: str,
        permitted_tools: List[str],
        permitted_actions: List[str],
        resource_restrictions: List[str],
        parent_delegation_id: Optional[str] = None,
        duration_minutes: int = 60,
        is_single_use: bool = False,
        audience: Optional[str] = None
    ) -> Tuple[bool, Optional[DelegationGrant], str, str]:
        """Creates a signed delegation credential with strict attenuation checks."""
        now = datetime.now(timezone.utc)
        requested_expires = now + (timedelta(minutes=duration_minutes) if 'timedelta' in globals() else __import__('datetime').timedelta(minutes=duration_minutes))
        
        # Verify receiving agent exists in same tenant
        rcv_agent = db.query(Agent).filter(Agent.id == receiving_agent_id, Agent.tenant_id == tenant_id).first()
        if not rcv_agent:
            return False, None, "INVALID_RECEIVING_AGENT", f"Receiving agent '{receiving_agent_id}' does not exist in tenant '{tenant_id}'"

        if not rcv_agent.is_active:
            return False, None, "AGENT_INACTIVE", f"Receiving agent '{receiving_agent_id}' is deactivated"

        current_depth = 1
        max_depth = 3
        original_user_id = delegating_agent_id

        # If child delegation, validate against parent
        if parent_delegation_id:
            parent_grant = db.query(DelegationGrant).filter(
                DelegationGrant.delegation_id == parent_delegation_id,
                DelegationGrant.tenant_id == tenant_id
            ).first()

            if not parent_grant:
                return False, None, "PARENT_DELEGATION_NOT_FOUND", f"Parent delegation '{parent_delegation_id}' not found in tenant '{tenant_id}'"

            if parent_grant.is_revoked:
                return False, None, "PARENT_DELEGATION_REVOKED", f"Parent delegation '{parent_delegation_id}' is revoked"

            # Check if parent is expired
            parent_exp = parent_grant.expires_at
            if parent_exp.tzinfo is None:
                parent_exp = parent_exp.replace(tzinfo=timezone.utc)
            if parent_exp < now:
                return False, None, "PARENT_DELEGATION_EXPIRED", f"Parent delegation '{parent_delegation_id}' has already expired"

            # Automatically clamp child expiration to at most parent expiration
            if requested_expires > parent_exp:
                requested_expires = parent_exp

            current_depth = parent_grant.current_depth + 1
            max_depth = parent_grant.max_depth
            original_user_id = parent_grant.original_user_id

            # Enforce attenuation
            is_valid_att, err_msg = self.validate_permission_attenuation(
                parent_grant=parent_grant,
                requested_tools=permitted_tools,
                requested_actions=permitted_actions,
                requested_resources=resource_restrictions,
                requested_expires_at=requested_expires,
                requested_tenant_id=tenant_id,
                requested_depth=current_depth
            )
            if not is_valid_att:
                code = "DELEGATION_DEPTH_EXCEEDED" if "depth" in (err_msg or "").lower() else "DELEGATION_ATTENUATION_ESCALATION"
                return False, None, code, err_msg or "Permission attenuation violation"

        delegation_id = self.security.generate_id("del")
        token = self.security.create_delegation_credential(
            delegation_id=delegation_id,
            parent_delegation_id=parent_delegation_id,
            original_user_id=original_user_id,
            delegating_agent_id=delegating_agent_id,
            receiving_agent_id=receiving_agent_id,
            tenant_id=tenant_id,
            permitted_tools=permitted_tools,
            permitted_actions=permitted_actions,
            resource_restrictions=resource_restrictions,
            max_depth=max_depth,
            current_depth=current_depth,
            audience=audience,
            expires_in_minutes=duration_minutes,
            is_single_use=is_single_use
        )

        _, payload, _ = self.security.verify_delegation_credential(token, expected_audience=audience)

        grant = DelegationGrant(
            id=self.security.generate_id("grant"),
            delegation_id=delegation_id,
            parent_delegation_id=parent_delegation_id,
            tenant_id=tenant_id,
            original_user_id=original_user_id,
            delegating_agent_id=delegating_agent_id,
            receiving_agent_id=receiving_agent_id,
            permitted_tools_json=json.dumps(permitted_tools),
            permitted_actions_json=json.dumps(permitted_actions),
            resource_restrictions_json=json.dumps(resource_restrictions),
            issued_at=now,
            expires_at=requested_expires,
            max_depth=max_depth,
            current_depth=current_depth,
            jti=payload["jti"],
            audience=payload["aud"],
            signature=token,
            is_single_use=is_single_use,
            is_consumed=False,
            is_revoked=False,
            created_at=now
        )
        db.add(grant)
        db.commit()
        db.refresh(grant)
        return True, grant, "DELEGATION_CREATED", "Delegation created successfully"

    def verify_active_delegation(
        self,
        db: Session,
        delegation_token: str,
        expected_agent_id: str,
        expected_tool: str,
        expected_action: str,
        expected_resource: Optional[str] = None,
        expected_audience: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], str, str]:
        """Cryptographically verifies delegation token, attenuation chain, and scope."""
        # 1. Cryptographic token verification
        valid, payload, msg = self.security.verify_delegation_credential(
            delegation_token,
            expected_audience=expected_audience
        )
        if not valid or not payload:
            if "expired" in msg.lower():
                return False, None, "DELEGATION_EXPIRED", msg
            elif "audience" in msg.lower():
                return False, None, "DELEGATION_AUDIENCE_MISMATCH", msg
            elif "tamper" in msg.lower() or "signature" in msg.lower():
                return False, None, "DELEGATION_TAMPERING_DETECTED", msg
            return False, None, "DELEGATION_TOKEN_INVALID", msg

        del_id = payload.get("del_id")
        jti = payload.get("jti")
        token_tid = payload.get("tid")
        rcv_aid = payload.get("rcv_aid")
        exp_timestamp = payload.get("exp", 0)

        # 2. Check receiving agent matches
        if rcv_aid != expected_agent_id:
            return False, payload, "AGENT_IDENTITY_MISMATCH", f"Delegation token issued to '{rcv_aid}', but presented by '{expected_agent_id}'"

        # 3. Check delegation record in DB
        grant = db.query(DelegationGrant).filter(
            DelegationGrant.delegation_id == del_id,
            DelegationGrant.tenant_id == token_tid
        ).first()

        if not grant:
            return False, payload, "DELEGATION_NOT_FOUND", f"Delegation grant '{del_id}' not found in tenant registry"

        if grant.is_revoked:
            return False, payload, "DELEGATION_REVOKED", f"Delegation '{del_id}' was revoked by administrator"

        # 4. Check Single-Use / Replay Protection
        if grant.is_single_use:
            if grant.is_consumed:
                return False, payload, "REPLAY_ATTACK_DETECTED", f"Single-use delegation '{del_id}' has already been consumed"
            
            # Atomic in-memory check
            replay_ok, replay_msg = self.security.check_and_consume_jti(jti, exp_timestamp)
            if not replay_ok:
                return False, payload, "REPLAY_ATTACK_DETECTED", replay_msg

            grant.is_consumed = True
            db.commit()

        # 5. Delegation Depth limit check
        if grant.current_depth > grant.max_depth:
            return False, payload, "EXCESSIVE_DELEGATION_DEPTH", f"Delegation depth {grant.current_depth} exceeds max allowed depth {grant.max_depth}"

        # 6. Tool scope check
        permitted_tools = grant.get_permitted_tools()
        if expected_tool not in permitted_tools and "*" not in permitted_tools:
            return False, payload, "UNAUTHORIZED_TOOL_EXECUTION", f"Tool '{expected_tool}' is not in delegated tool scope {permitted_tools}"

        # 7. Action scope check
        permitted_actions = grant.get_permitted_actions()
        if expected_action not in permitted_actions and "*" not in permitted_actions:
            return False, payload, "UNAUTHORIZED_ACTION", f"Action '{expected_action}' is not in delegated actions {permitted_actions}"

        # 8. Resource restriction check
        if expected_resource:
            permitted_resources = grant.get_resource_restrictions()
            if permitted_resources and "*" not in permitted_resources:
                if expected_resource not in permitted_resources:
                    return False, payload, "RESOURCE_ACCESS_RESTRICTED", f"Resource '{expected_resource}' is restricted by delegation boundary {permitted_resources}"

        # 9. Verify full parent chain recursion
        curr_pdel_id = grant.parent_delegation_id
        while curr_pdel_id:
            parent = db.query(DelegationGrant).filter(
                DelegationGrant.delegation_id == curr_pdel_id,
                DelegationGrant.tenant_id == token_tid
            ).first()
            if not parent:
                return False, payload, "BROKEN_DELEGATION_CHAIN", f"Ancestor delegation '{curr_pdel_id}' missing in chain"
            if parent.is_revoked:
                return False, payload, "PARENT_DELEGATION_REVOKED", f"Ancestor delegation '{curr_pdel_id}' in chain is revoked"
            curr_pdel_id = parent.parent_delegation_id

        return True, payload, "DELEGATION_VALID", "Delegation credentials and hierarchy verified"

delegation_engine = DelegationEngine()
