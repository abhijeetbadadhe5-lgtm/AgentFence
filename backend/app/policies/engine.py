"""AgentFence Policy Decision Engine: RBAC & ABAC Policy Decision Point (PDP)
"""
import fnmatch
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from app.models.entities import Policy, ProtectedResource

@dataclass
class PolicyDecision:
    decision: str  # ALLOW | DENY
    reason_code: str
    explanation: str
    matched_policy: Optional[str]
    principal: str
    tenant: str
    tool: str
    action: str
    resource: Optional[str]
    correlation_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class PolicyEngine:
    def evaluate(
        self,
        db: Session,
        principal_id: str,
        principal_type: str,
        principal_role: str,
        acting_agent_id: Optional[str],
        tenant_id: str,
        tool_name: str,
        requested_action: str,
        resource_id: Optional[str] = None,
        delegation_payload: Optional[Dict[str, Any]] = None,
        correlation_id: str = "corr_default"
    ) -> PolicyDecision:
        """Evaluates RBAC and ABAC policies with deny-by-default semantics."""
        # 1. Base identity verification
        if not principal_id or not tenant_id:
            return PolicyDecision(
                decision="DENY",
                reason_code="AUTHZ_MISSING_IDENTITY",
                explanation="Request lacks authenticated principal or tenant context",
                matched_policy=None,
                principal=principal_id or "anonymous",
                tenant=tenant_id or "unknown",
                tool=tool_name,
                action=requested_action,
                resource=resource_id,
                correlation_id=correlation_id
            )

        # 2. Strict Cross-Tenant Isolation Enforcement
        if resource_id:
            resource = db.query(ProtectedResource).filter(ProtectedResource.id == resource_id).first()
            if resource:
                if resource.tenant_id != tenant_id:
                    return PolicyDecision(
                        decision="DENY",
                        reason_code="AUTHZ_CROSS_TENANT_VIOLATION",
                        explanation=(
                            f"Cross-tenant access blocked: Principal '{principal_id}' belongs to tenant '{tenant_id}', "
                            f"but target resource '{resource_id}' belongs to tenant '{resource.tenant_id}'."
                        ),
                        matched_policy="pol_strict_tenant_isolation",
                        principal=principal_id,
                        tenant=tenant_id,
                        tool=tool_name,
                        action=requested_action,
                        resource=resource_id,
                        correlation_id=correlation_id
                    )

        # 3. Confused Deputy Check
        # If an agent invokes a high-risk administrative tool without admin role
        if tool_name == "admin_override" and principal_role != "admin":
            return PolicyDecision(
                decision="DENY",
                reason_code="AUTHZ_CONFUSED_DEPUTY_DETECTED",
                explanation=f"Confused Deputy blocked: Agent '{acting_agent_id or principal_id}' with role '{principal_role}' attempted to execute privileged administrative tool '{tool_name}'",
                matched_policy=None,
                principal=principal_id,
                tenant=tenant_id,
                tool=tool_name,
                action=requested_action,
                resource=resource_id,
                correlation_id=correlation_id
            )

        # 4. Fetch Active Tenant Policies sorted by Priority (lower number = higher priority)
        policies = db.query(Policy).filter(
            Policy.tenant_id == tenant_id,
            Policy.is_active == True
        ).order_by(Policy.priority.asc()).all()

        matching_denials = []
        matching_allows = []

        for pol in policies:
            # Check principal type
            if pol.principal_type not in ("*", principal_type):
                continue
            # Check principal id
            if pol.principal_id not in ("*", principal_id):
                continue
            # Check role
            if pol.role not in ("*", principal_role):
                continue
            # Check tool pattern (supports glob wildcard)
            if not fnmatch.fnmatch(tool_name, pol.tool_pattern):
                continue
            # Check action pattern
            if not fnmatch.fnmatch(requested_action, pol.action_pattern):
                continue
            # Check resource pattern
            if resource_id and not fnmatch.fnmatch(resource_id, pol.resource_pattern):
                continue

            # Check ABAC conditions
            conditions = pol.get_conditions()
            if conditions.get("tenant_mismatch"):
                # Only matches if there is an actual tenant mismatch with the resource
                if not resource_id:
                    continue
                res_obj = db.query(ProtectedResource).filter(ProtectedResource.id == resource_id).first()
                if not res_obj or res_obj.tenant_id == tenant_id:
                    continue  # Same tenant: tenant_mismatch condition is not met

            if conditions.get("requires_delegation") and not delegation_payload:
                continue

            if pol.effect == "DENY":
                matching_denials.append(pol)
            elif pol.effect == "ALLOW":
                matching_allows.append(pol)

        # Explicit DENY takes absolute precedence
        if matching_denials:
            highest_deny = matching_denials[0]
            return PolicyDecision(
                decision="DENY",
                reason_code="AUTHZ_EXPLICIT_DENY_POLICY",
                explanation=f"Denied by explicit policy '{highest_deny.name}' ({highest_deny.id}): {highest_deny.description or 'No description'}",
                matched_policy=highest_deny.id,
                principal=principal_id,
                tenant=tenant_id,
                tool=tool_name,
                action=requested_action,
                resource=resource_id,
                correlation_id=correlation_id
            )

        # Check for matching ALLOW
        if matching_allows:
            highest_allow = matching_allows[0]
            return PolicyDecision(
                decision="ALLOW",
                reason_code="AUTHZ_PERMITTED_BY_POLICY",
                explanation=f"Authorized by policy '{highest_allow.name}' ({highest_allow.id})",
                matched_policy=highest_allow.id,
                principal=principal_id,
                tenant=tenant_id,
                tool=tool_name,
                action=requested_action,
                resource=resource_id,
                correlation_id=correlation_id
            )

        # Deny by default
        return PolicyDecision(
            decision="DENY",
            reason_code="AUTHZ_NO_MATCHING_ALLOW_POLICY",
            explanation=f"Default deny: No active authorization policy allows '{principal_id}' ({principal_role}) to invoke '{tool_name}' on resource '{resource_id or 'none'}'",
            matched_policy=None,
            principal=principal_id,
            tenant=tenant_id,
            tool=tool_name,
            action=requested_action,
            resource=resource_id,
            correlation_id=correlation_id
        )

policy_engine = PolicyEngine()
