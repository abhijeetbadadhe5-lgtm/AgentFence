"""AgentFence REST API Router: Complete Endpoints for Security Gateway Operations
"""
import json
from typing import Dict, Any, Optional, List
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.database.session import get_db
from app.models.entities import Tenant, User, Agent, MCPTool, ProtectedResource, Policy, DelegationGrant, AuditEvent, AttackSimulationResult
from app.core.security import security_engine
from app.delegation.engine import delegation_engine
from app.policies.engine import policy_engine
from app.audit.service import audit_service
from app.gateway.interceptor import gateway_interceptor
from app.mcp.server import mcp_protocol_handler
from app.simulations.engine import attack_simulation_lab

# --- Helper to extract bearer token ---
def extract_auth_tokens(request: Request) -> Dict[str, Optional[str]]:
    auth_header = request.headers.get("Authorization", "")
    identity_token = None
    if auth_header.startswith("Bearer "):
        identity_token = auth_header[7:].strip()
    delegation_token = request.headers.get("X-Delegation-Token")
    return {"identity_token": identity_token, "delegation_token": delegation_token}

# 1. Health Endpoint
async def health(request: Request):
    return JSONResponse({
        "status": "healthy",
        "service": "AgentFence Security Gateway",
        "version": "1.0.0",
        "protocol": "MCP 2024-11-05",
        "engine": "Delegation-Aware Authorization PDP"
    })

# 2. Authentication Login (Dev/Demo flow)
async def login(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    username = body.get("username")
    tenant_id = body.get("tenant_id")
    agent_id = body.get("agent_id")

    with get_db() as db:
        if agent_id:
            agent = db.query(Agent).filter(Agent.id == agent_id).first()
            if not agent:
                return JSONResponse({"error": f"Agent '{agent_id}' not found"}, status_code=404)
            token = security_engine.create_identity_token(
                subject=agent.id,
                tenant_id=agent.tenant_id,
                role=agent.role,
                principal_type="agent",
                agent_id=agent.id
            )
            return JSONResponse({
                "access_token": token,
                "token_type": "bearer",
                "principal_type": "agent",
                "subject": agent.id,
                "tenant_id": agent.tenant_id,
                "role": agent.role
            })

        user = db.query(User).filter(User.username == username).first()
        if not user:
            return JSONResponse({"error": f"User '{username}' not found"}, status_code=404)

        token = security_engine.create_identity_token(
            subject=user.id,
            tenant_id=user.tenant_id,
            role=user.role,
            principal_type="user"
        )
        return JSONResponse({
            "access_token": token,
            "token_type": "bearer",
            "principal_type": "user",
            "subject": user.id,
            "tenant_id": user.tenant_id,
            "role": user.role,
            "is_admin": user.is_admin
        })

# 3. Tenant Management
async def list_tenants(request: Request):
    with get_db() as db:
        tenants = db.query(Tenant).all()
        data = [
            {
                "id": t.id,
                "name": t.name,
                "slug": t.slug,
                "description": t.description,
                "status": t.status,
                "users_count": len(t.users),
                "agents_count": len(t.agents),
                "resources_count": len(t.resources),
                "policies_count": len(t.policies)
            }
            for t in tenants
        ]
        return JSONResponse(data)

async def get_tenant_details(request: Request):
    tenant_id = request.path_params["id"]
    with get_db() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            return JSONResponse({"error": "Tenant not found"}, status_code=404)
        return JSONResponse({
            "id": tenant.id,
            "name": tenant.name,
            "slug": tenant.slug,
            "description": tenant.description,
            "status": tenant.status,
            "users": [{"id": u.id, "username": u.username, "email": u.email, "role": u.role} for u in tenant.users],
            "agents": [{"id": a.id, "name": a.name, "type": a.agent_type, "role": a.role, "active": a.is_active} for a in tenant.agents],
            "resources": [{"id": r.id, "name": r.name, "sensitivity": r.sensitivity_level} for r in tenant.resources],
            "policies": [{"id": p.id, "name": p.name, "effect": p.effect, "tool_pattern": p.tool_pattern} for p in tenant.policies]
        })

# 4. Agent Registry
async def list_agents(request: Request):
    tenant_filter = request.query_params.get("tenant_id")
    with get_db() as db:
        query = db.query(Agent)
        if tenant_filter:
            query = query.filter(Agent.tenant_id == tenant_filter)
        agents = query.all()
        return JSONResponse([
            {
                "id": a.id,
                "tenant_id": a.tenant_id,
                "name": a.name,
                "agent_type": a.agent_type,
                "role": a.role,
                "description": a.description,
                "is_active": a.is_active
            }
            for a in agents
        ])

# 5. MCP Tool Registry
async def list_tools(request: Request):
    with get_db() as db:
        tools = db.query(MCPTool).all()
        return JSONResponse([
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "parameters_schema": t.get_parameters_schema(),
                "required_scopes": t.get_required_scopes(),
                "risk_level": t.risk_level,
                "upstream_endpoint": t.upstream_endpoint,
                "is_enabled": t.is_enabled
            }
            for t in tools
        ])

# 6. Delegation Management
async def create_delegation(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    with get_db() as db:
        success, grant, code, msg = delegation_engine.create_delegation(
            db=db,
            delegating_agent_id=body.get("delegating_agent_id"),
            receiving_agent_id=body.get("receiving_agent_id"),
            tenant_id=body.get("tenant_id"),
            permitted_tools=body.get("permitted_tools", []),
            permitted_actions=body.get("permitted_actions", ["read"]),
            resource_restrictions=body.get("resource_restrictions", []),
            parent_delegation_id=body.get("parent_delegation_id"),
            duration_minutes=int(body.get("duration_minutes", 60)),
            is_single_use=bool(body.get("is_single_use", False)),
            audience=body.get("audience")
        )

        if not success:
            return JSONResponse({"success": False, "code": code, "error": msg}, status_code=403)

        return JSONResponse({
            "success": True,
            "delegation_id": grant.delegation_id,
            "parent_delegation_id": grant.parent_delegation_id,
            "tenant_id": grant.tenant_id,
            "delegating_agent_id": grant.delegating_agent_id,
            "receiving_agent_id": grant.receiving_agent_id,
            "permitted_tools": grant.get_permitted_tools(),
            "permitted_actions": grant.get_permitted_actions(),
            "resource_restrictions": grant.get_resource_restrictions(),
            "current_depth": grant.current_depth,
            "max_depth": grant.max_depth,
            "jti": grant.jti,
            "expires_at": grant.expires_at.isoformat(),
            "is_single_use": grant.is_single_use,
            "signature": grant.signature
        })

async def list_delegations(request: Request):
    tenant_filter = request.query_params.get("tenant_id")
    with get_db() as db:
        query = db.query(DelegationGrant)
        if tenant_filter:
            query = query.filter(DelegationGrant.tenant_id == tenant_filter)
        grants = query.order_by(DelegationGrant.created_at.desc()).all()
        return JSONResponse([
            {
                "id": g.id,
                "delegation_id": g.delegation_id,
                "parent_delegation_id": g.parent_delegation_id,
                "tenant_id": g.tenant_id,
                "original_user_id": g.original_user_id,
                "delegating_agent_id": g.delegating_agent_id,
                "receiving_agent_id": g.receiving_agent_id,
                "permitted_tools": g.get_permitted_tools(),
                "permitted_actions": g.get_permitted_actions(),
                "resource_restrictions": g.get_resource_restrictions(),
                "current_depth": g.current_depth,
                "max_depth": g.max_depth,
                "is_single_use": g.is_single_use,
                "is_consumed": g.is_consumed,
                "is_revoked": g.is_revoked,
                "expires_at": g.expires_at.isoformat(),
                "signature": g.signature
            }
            for g in grants
        ])

async def revoke_delegation(request: Request):
    del_id = request.path_params["id"]
    with get_db() as db:
        grant = db.query(DelegationGrant).filter(DelegationGrant.delegation_id == del_id).first()
        if not grant:
            return JSONResponse({"error": "Delegation not found"}, status_code=404)
        grant.is_revoked = True
        db.commit()
        return JSONResponse({"success": True, "message": f"Delegation '{del_id}' revoked successfully"})

# 7. Policy Management & Simulator
async def list_policies(request: Request):
    tenant_filter = request.query_params.get("tenant_id")
    with get_db() as db:
        query = db.query(Policy)
        if tenant_filter:
            query = query.filter(Policy.tenant_id == tenant_filter)
        policies = query.order_by(Policy.priority.asc()).all()
        return JSONResponse([
            {
                "id": p.id,
                "tenant_id": p.tenant_id,
                "name": p.name,
                "description": p.description,
                "effect": p.effect,
                "principal_type": p.principal_type,
                "principal_id": p.principal_id,
                "role": p.role,
                "tool_pattern": p.tool_pattern,
                "action_pattern": p.action_pattern,
                "resource_pattern": p.resource_pattern,
                "conditions": p.get_conditions(),
                "priority": p.priority,
                "is_active": p.is_active
            }
            for p in policies
        ])

async def toggle_policy(request: Request):
    pol_id = request.path_params["id"]
    with get_db() as db:
        policy = db.query(Policy).filter(Policy.id == pol_id).first()
        if not policy:
            return JSONResponse({"error": "Policy not found"}, status_code=404)
        policy.is_active = not policy.is_active
        db.commit()
        return JSONResponse({"id": policy.id, "name": policy.name, "is_active": policy.is_active})

async def simulate_policy(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    with get_db() as db:
        decision = policy_engine.evaluate(
            db=db,
            principal_id=body.get("principal_id", "test_user"),
            principal_type=body.get("principal_type", "user"),
            principal_role=body.get("principal_role", "user"),
            acting_agent_id=body.get("acting_agent_id"),
            tenant_id=body.get("tenant_id", "tenant_alpha"),
            tool_name=body.get("tool_name", "read_document"),
            requested_action=body.get("action", "read"),
            resource_id=body.get("resource_id"),
            correlation_id=security_engine.generate_id("sim_corr")
        )
        return JSONResponse(decision.to_dict())

# 8. Live Audit Events & Chain Integrity
async def list_audit_events(request: Request):
    limit = int(request.query_params.get("limit", 100))
    tenant_filter = request.query_params.get("tenant_id")
    tool_filter = request.query_params.get("tool")
    decision_filter = request.query_params.get("decision")

    with get_db() as db:
        query = db.query(AuditEvent)
        if tenant_filter:
            query = query.filter(AuditEvent.tenant_id == tenant_filter)
        if tool_filter:
            query = query.filter(AuditEvent.mcp_tool_name == tool_filter)
        if decision_filter:
            query = query.filter(AuditEvent.decision == decision_filter)

        events = query.order_by(AuditEvent.seq.desc()).limit(limit).all()
        return JSONResponse([
            {
                "id": e.id,
                "seq": e.seq,
                "request_id": e.request_id,
                "correlation_id": e.correlation_id,
                "timestamp": e.timestamp,
                "tenant_id": e.tenant_id,
                "user_id": e.user_id,
                "agent_id": e.agent_id,
                "delegation_id": e.delegation_id,
                "tool": e.mcp_tool_name,
                "action": e.requested_action,
                "resource_id": e.resource_id,
                "decision": e.decision,
                "denial_reason": e.denial_reason,
                "attack_classification": e.attack_classification,
                "execution_outcome": e.execution_outcome,
                "previous_record_hash": e.previous_record_hash,
                "record_hash": e.record_hash
            }
            for e in events
        ])

async def verify_audit_integrity(request: Request):
    with get_db() as db:
        valid, count, err = audit_service.verify_audit_chain_integrity(db)
        last_ev = db.query(AuditEvent).order_by(AuditEvent.seq.desc()).first()
        return JSONResponse({
            "is_valid": valid,
            "records_verified": count,
            "chain_head_hash": last_ev.record_hash if last_ev else None,
            "error_details": err,
            "message": "Audit ledger cryptographic integrity verified successfully." if valid else "Audit tampering detected!"
        })

# 9. Security Metrics Overview
async def get_security_metrics(request: Request):
    with get_db() as db:
        metrics = audit_service.get_security_metrics(db)
        return JSONResponse(metrics)

# 10. Attack Simulation Lab
async def run_simulations(request: Request):
    scenario_key = request.query_params.get("scenario")
    with get_db() as db:
        if scenario_key:
            # Map key to specific scenario
            method_map = {
                "attack_1": attack_simulation_lab.run_attack_1_confused_deputy,
                "attack_2": attack_simulation_lab.run_attack_2_cross_tenant_access,
                "attack_3": attack_simulation_lab.run_attack_3_privilege_escalation,
                "attack_4": attack_simulation_lab.run_attack_4_delegation_tampering,
                "attack_5": attack_simulation_lab.run_attack_5_expired_delegation,
                "attack_6": attack_simulation_lab.run_attack_6_audience_mismatch,
                "attack_7": attack_simulation_lab.run_attack_7_replay_attack,
                "attack_8": attack_simulation_lab.run_attack_8_excessive_depth,
                "attack_9": attack_simulation_lab.run_attack_9_unauthorized_tool,
                "attack_10": attack_simulation_lab.run_attack_10_missing_identity,
            }
            fn = method_map.get(scenario_key)
            if not fn:
                return JSONResponse({"error": f"Unknown scenario key '{scenario_key}'"}, status_code=400)
            result = fn(db)
            return JSONResponse([result])

        results = attack_simulation_lab.run_all_simulations(db)
        return JSONResponse(results)

async def list_simulation_results(request: Request):
    with get_db() as db:
        sims = db.query(AttackSimulationResult).order_by(AttackSimulationResult.executed_at.desc()).limit(20).all()
        return JSONResponse([
            {
                "id": s.id,
                "simulation_key": s.simulation_key,
                "scenario_name": s.scenario_name,
                "expected_result": s.expected_result,
                "actual_result": s.actual_result,
                "passed": s.passed,
                "request_details": json.loads(s.request_details_json),
                "checks_evaluated": json.loads(s.checks_evaluated_json),
                "audit_event_id": s.audit_event_id,
                "executed_at": s.executed_at.isoformat()
            }
            for s in sims
        ])

# 11. MCP Gateway Invocations (REST & JSON-RPC)
async def mcp_tool_call(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    tokens = extract_auth_tokens(request)
    identity_token = tokens["identity_token"] or body.get("identity_token")
    delegation_token = tokens["delegation_token"] or body.get("delegation_token")

    with get_db() as db:
        result = gateway_interceptor.process_tool_invocation(
            db=db,
            tool_name=body.get("tool_name"),
            arguments=body.get("arguments", {}),
            identity_token=identity_token,
            delegation_token=delegation_token,
            client_audience=body.get("audience")
        )
        status_code = 200 if result.get("authorized") else 403
        return JSONResponse(result, status_code=status_code)

async def mcp_jsonrpc_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}}, status_code=400)

    tokens = extract_auth_tokens(request)
    identity_token = tokens["identity_token"] or request.headers.get("X-Identity-Token")
    delegation_token = tokens["delegation_token"]

    with get_db() as db:
        response_rpc = mcp_protocol_handler.handle_jsonrpc(
            db=db,
            request_data=body,
            identity_token=identity_token,
            delegation_token=delegation_token
        )
        return JSONResponse(response_rpc)
