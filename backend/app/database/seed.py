"""AgentFence Seed Data: Tenants Alpha & Beta, Users, Agents, Tools, Policies, and Resources
"""
import json
from datetime import datetime, timezone, timedelta
from app.database.session import get_db, init_db
from app.models.entities import Tenant, User, Agent, MCPTool, ProtectedResource, Policy, DelegationGrant
from app.core.security import security_engine

def seed_database(force: bool = False):
    init_db()
    with get_db() as db:
        if force:
            from app.models.entities import AuditEvent, DelegationGrant, Policy, ProtectedResource, MCPTool, Agent, User, Tenant
            db.query(AuditEvent).delete()
            db.query(DelegationGrant).delete()
            db.query(Policy).delete()
            db.query(ProtectedResource).delete()
            db.query(MCPTool).delete()
            db.query(Agent).delete()
            db.query(User).delete()
            db.query(Tenant).delete()
            db.flush()
        elif db.query(Tenant).count() > 0:
            print("Database already contains data. Skipping seed.")
            return

        print("Seeding AgentFence database...")
        now = datetime.now(timezone.utc)
        default_pwd_hash = security_engine.hash_secret("Password123!")

        # 1. Tenants
        tenant_alpha = Tenant(
            id="tenant_alpha",
            name="Tenant Alpha - Aerospace & Defense Systems",
            slug="alpha",
            description="Aerospace engineering, autonomous defense telemetry, and avionics data.",
            status="active",
            created_at=now
        )
        tenant_beta = Tenant(
            id="tenant_beta",
            name="Tenant Beta - Healthcare & Biotech Labs",
            slug="beta",
            description="Clinical trials, oncology research, genomics, and HIPAA-protected health records.",
            status="active",
            created_at=now
        )
        db.add_all([tenant_alpha, tenant_beta])
        db.flush()

        # 2. Users
        users = [
            User(
                id="usr_alpha_admin",
                tenant_id="tenant_alpha",
                username="alpha_admin",
                email="admin@alpha-defense.internal",
                role="admin",
                is_admin=True,
                password_hash=default_pwd_hash,
                created_at=now
            ),
            User(
                id="usr_alpha_analyst",
                tenant_id="tenant_alpha",
                username="alpha_analyst",
                email="analyst@alpha-defense.internal",
                role="analyst",
                is_admin=False,
                password_hash=default_pwd_hash,
                created_at=now
            ),
            User(
                id="usr_alpha_eng",
                tenant_id="tenant_alpha",
                username="alpha_engineer",
                email="engineer@alpha-defense.internal",
                role="engineer",
                is_admin=False,
                password_hash=default_pwd_hash,
                created_at=now
            ),
            User(
                id="usr_beta_admin",
                tenant_id="tenant_beta",
                username="beta_admin",
                email="admin@beta-health.internal",
                role="admin",
                is_admin=True,
                password_hash=default_pwd_hash,
                created_at=now
            ),
            User(
                id="usr_beta_researcher",
                tenant_id="tenant_beta",
                username="beta_researcher",
                email="researcher@beta-health.internal",
                role="researcher",
                is_admin=False,
                password_hash=default_pwd_hash,
                created_at=now
            ),
        ]
        db.add_all(users)
        db.flush()

        # 3. Agents
        agents = [
            Agent(
                id="agent_alpha_primary",
                tenant_id="tenant_alpha",
                name="Alpha Mission Coordinator Agent",
                agent_type="primary",
                role="coordinator",
                description="Primary autonomous mission agent for aerospace telemetry & engineering documentation.",
                is_active=True,
                created_at=now
            ),
            Agent(
                id="agent_alpha_research",
                tenant_id="tenant_alpha",
                name="Alpha Radar Research Sub-Agent",
                agent_type="subagent",
                role="researcher",
                description="Sub-agent restricted to research-level radar schematics.",
                is_active=True,
                created_at=now
            ),
            Agent(
                id="agent_alpha_untrusted",
                tenant_id="tenant_alpha",
                name="Alpha Untrusted 3rd-Party Plugin",
                agent_type="restricted",
                role="plugin",
                description="Low-privilege external calculation plugin agent.",
                is_active=True,
                created_at=now
            ),
            Agent(
                id="agent_beta_primary",
                tenant_id="tenant_beta",
                name="Beta Clinical Trial Coordinator",
                agent_type="primary",
                role="coordinator",
                description="Primary coordinator agent managing patient cohorts and clinical protocol execution.",
                is_active=True,
                created_at=now
            ),
            Agent(
                id="agent_beta_analytics",
                tenant_id="tenant_beta",
                name="Beta Genomic Data Analyst Sub-Agent",
                agent_type="subagent",
                role="analyst",
                description="Sub-agent delegated to execute statistical calculations over genomic sequences.",
                is_active=True,
                created_at=now
            ),
        ]
        db.add_all(agents)
        db.flush()

        # 4. MCP Tools
        mcp_tools = [
            MCPTool(
                id="tool_read_document",
                name="read_document",
                description="Read content of a protected document within the authenticated tenant boundary.",
                parameters_schema_json=json.dumps({
                    "type": "object",
                    "properties": {
                        "resource_id": {"type": "string", "description": "Unique identifier of the protected document"}
                    },
                    "required": ["resource_id"]
                }),
                required_scopes_json=json.dumps(["documents:read"]),
                risk_level="medium",
                upstream_endpoint="mock://sample-upstream-mcp/tools/read_document",
                is_enabled=True,
                created_at=now
            ),
            MCPTool(
                id="tool_search_knowledge_base",
                name="search_knowledge_base",
                description="Perform semantic keyword queries against the tenant document catalog.",
                parameters_schema_json=json.dumps({
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query terms"},
                        "limit": {"type": "integer", "default": 5}
                    },
                    "required": ["query"]
                }),
                required_scopes_json=json.dumps(["knowledge:search"]),
                risk_level="low",
                upstream_endpoint="mock://sample-upstream-mcp/tools/search_knowledge_base",
                is_enabled=True,
                created_at=now
            ),
            MCPTool(
                id="tool_execute_analytics_query",
                name="execute_analytics_query",
                description="Execute read-only analytical aggregations over tenant dataset metrics.",
                parameters_schema_json=json.dumps({
                    "type": "object",
                    "properties": {
                        "query_type": {"type": "string"},
                        "dataset_id": {"type": "string"}
                    },
                    "required": ["query_type", "dataset_id"]
                }),
                required_scopes_json=json.dumps(["analytics:execute"]),
                risk_level="medium",
                upstream_endpoint="mock://sample-upstream-mcp/tools/execute_analytics_query",
                is_enabled=True,
                created_at=now
            ),
            MCPTool(
                id="tool_export_tenant_report",
                name="export_tenant_report",
                description="Export regulatory compliance audit pack for the current tenant.",
                parameters_schema_json=json.dumps({
                    "type": "object",
                    "properties": {
                        "report_format": {"type": "string", "enum": ["json", "csv"]}
                    },
                    "required": ["report_format"]
                }),
                required_scopes_json=json.dumps(["reports:export"]),
                risk_level="high",
                upstream_endpoint="mock://sample-upstream-mcp/tools/export_tenant_report",
                is_enabled=True,
                created_at=now
            ),
            MCPTool(
                id="tool_admin_override",
                name="admin_override",
                description="High-privilege gateway parameter override and security bypass testing.",
                parameters_schema_json=json.dumps({
                    "type": "object",
                    "properties": {
                        "action": {"type": "string"}
                    },
                    "required": ["action"]
                }),
                required_scopes_json=json.dumps(["admin:override"]),
                risk_level="critical",
                upstream_endpoint="mock://sample-upstream-mcp/tools/admin_override",
                is_enabled=True,
                created_at=now
            ),
        ]
        db.add_all(mcp_tools)
        db.flush()

        # 5. Protected Resources
        resources = [
            ProtectedResource(
                id="doc_alpha_falcon",
                tenant_id="tenant_alpha",
                name="Project Falcon Autonomous Flight Blueprint",
                resource_type="document",
                sensitivity_level="secret",
                owner_id="usr_alpha_admin",
                content="[RESTRICTED ALPHA-DEFENSE]: Project Falcon Mach 4.2 flight trajectory specifications, payload telemetry, and autonomous guidance coordinates.",
                created_at=now
            ),
            ProtectedResource(
                id="doc_alpha_radar",
                tenant_id="tenant_alpha",
                name="Alpha Phased Array Radar Architecture",
                resource_type="document",
                sensitivity_level="confidential",
                owner_id="usr_alpha_eng",
                content="[CONFIDENTIAL ALPHA-DEFENSE]: Next-generation GaN active electronically scanned array radar transceiver schematic.",
                created_at=now
            ),
            ProtectedResource(
                id="doc_beta_trial",
                tenant_id="tenant_beta",
                name="Beta-709 Oncology Clinical Trial Results",
                resource_type="document",
                sensitivity_level="confidential",
                owner_id="usr_beta_admin",
                content="[PHI/HIPAA PROTECTED BETA-HEALTH]: Double-blind Phase III randomized cohort study on CAR-T immunotherapy response rates.",
                created_at=now
            ),
            ProtectedResource(
                id="doc_beta_genomics",
                tenant_id="tenant_beta",
                name="Beta Synthetic CRISPR Sequence Catalog",
                resource_type="document",
                sensitivity_level="secret",
                owner_id="usr_beta_researcher",
                content="[PROPRIETARY BETA-BIOTECH]: Target base-pair sequence vectors for lung adenocarcinoma oncogene editing.",
                created_at=now
            ),
        ]
        db.add_all(resources)
        db.flush()

        # 6. Authorization Policies (RBAC + ABAC)
        policies = [
            # Strict cross-tenant DENY
            Policy(
                id="pol_alpha_tenant_boundary",
                tenant_id="tenant_alpha",
                name="Alpha Strict Tenant Isolation",
                description="Deny any principal or agent attempting to access resources belonging to a foreign tenant.",
                effect="DENY",
                principal_type="*",
                principal_id="*",
                role="*",
                tool_pattern="*",
                action_pattern="*",
                resource_pattern="*",
                conditions_json=json.dumps({"tenant_mismatch": True}),
                priority=1,
                is_active=True,
                created_at=now
            ),
            Policy(
                id="pol_beta_tenant_boundary",
                tenant_id="tenant_beta",
                name="Beta Strict Tenant Isolation",
                description="Deny any principal or agent attempting to access resources belonging to a foreign tenant.",
                effect="DENY",
                principal_type="*",
                principal_id="*",
                role="*",
                tool_pattern="*",
                action_pattern="*",
                resource_pattern="*",
                conditions_json=json.dumps({"tenant_mismatch": True}),
                priority=1,
                is_active=True,
                created_at=now
            ),
            # Alpha Primary Agent Policy: can read and search documents in Alpha
            Policy(
                id="pol_alpha_agent_read",
                tenant_id="tenant_alpha",
                name="Alpha Agent Document Read Policy",
                description="Permit Alpha agents with valid delegation to read Alpha documents.",
                effect="ALLOW",
                principal_type="agent",
                principal_id="agent_alpha_primary",
                role="coordinator",
                tool_pattern="read_document",
                action_pattern="read",
                resource_pattern="doc_alpha_*",
                conditions_json=json.dumps({"requires_delegation": True}),
                priority=50,
                is_active=True,
                created_at=now
            ),
            # Alpha Research Agent: can only read radar schematics
            Policy(
                id="pol_alpha_subagent_read",
                tenant_id="tenant_alpha",
                name="Alpha Sub-Agent Attenuated Read",
                description="Permit Alpha research sub-agent to access radar schematics only.",
                effect="ALLOW",
                principal_type="agent",
                principal_id="agent_alpha_research",
                role="researcher",
                tool_pattern="read_document",
                action_pattern="read",
                resource_pattern="doc_alpha_radar",
                conditions_json=json.dumps({"requires_delegation": True}),
                priority=60,
                is_active=True,
                created_at=now
            ),
            # Beta Primary Agent Policy
            Policy(
                id="pol_beta_agent_read",
                tenant_id="tenant_beta",
                name="Beta Clinical Agent Read Policy",
                description="Permit Beta coordinator agents to read Beta clinical trial resources.",
                effect="ALLOW",
                principal_type="agent",
                principal_id="agent_beta_primary",
                role="coordinator",
                tool_pattern="read_document",
                action_pattern="read",
                resource_pattern="doc_beta_*",
                conditions_json=json.dumps({"requires_delegation": True}),
                priority=50,
                is_active=True,
                created_at=now
            ),
            # Beta Analytics Sub-Agent Policy
            Policy(
                id="pol_beta_subagent_analytics",
                tenant_id="tenant_beta",
                name="Beta Analytics Sub-Agent Policy",
                description="Permit Beta analytics agent to execute queries on Beta data.",
                effect="ALLOW",
                principal_type="agent",
                principal_id="agent_beta_analytics",
                role="analyst",
                tool_pattern="execute_analytics_query",
                action_pattern="execute",
                resource_pattern="*",
                conditions_json=json.dumps({"requires_delegation": True}),
                priority=55,
                is_active=True,
                created_at=now
            ),
        ]
        db.add_all(policies)
        db.flush()

        # 7. Initial Seed Delegation Chain
        # Human User (usr_alpha_admin) -> Primary Agent (agent_alpha_primary)
        # Granted: read_document, search_knowledge_base | actions: read, search | resources: doc_alpha_falcon, doc_alpha_radar
        parent_del_id = "del_alpha_root_001"
        parent_token = security_engine.create_delegation_credential(
            delegation_id=parent_del_id,
            parent_delegation_id=None,
            original_user_id="usr_alpha_admin",
            delegating_agent_id="usr_alpha_admin", # Direct user delegation
            receiving_agent_id="agent_alpha_primary",
            tenant_id="tenant_alpha",
            permitted_tools=["read_document", "search_knowledge_base"],
            permitted_actions=["read", "search"],
            resource_restrictions=["doc_alpha_falcon", "doc_alpha_radar"],
            max_depth=3,
            current_depth=1,
            expires_in_minutes=525600
        )
        _, parent_payload, _ = security_engine.verify_delegation_credential(parent_token)

        grant_root = DelegationGrant(
            id="grant_root_alpha",
            delegation_id=parent_del_id,
            parent_delegation_id=None,
            tenant_id="tenant_alpha",
            original_user_id="usr_alpha_admin",
            delegating_agent_id="usr_alpha_admin",
            receiving_agent_id="agent_alpha_primary",
            permitted_tools_json=json.dumps(["read_document", "search_knowledge_base"]),
            permitted_actions_json=json.dumps(["read", "search"]),
            resource_restrictions_json=json.dumps(["doc_alpha_falcon", "doc_alpha_radar"]),
            issued_at=now,
            expires_at=now + timedelta(days=365),
            max_depth=3,
            current_depth=1,
            jti=parent_payload["jti"],
            audience=parent_payload["aud"],
            signature=parent_token,
            is_single_use=False,
            is_consumed=False,
            is_revoked=False,
            created_at=now
        )
        db.add(grant_root)

        # Child delegation: Primary Agent (agent_alpha_primary) -> Research Agent (agent_alpha_research)
        # Attenuated: only read_document | action: read | resource: doc_alpha_radar only | depth: 2
        child_del_id = "del_alpha_child_002"
        child_token = security_engine.create_delegation_credential(
            delegation_id=child_del_id,
            parent_delegation_id=parent_del_id,
            original_user_id="usr_alpha_admin",
            delegating_agent_id="agent_alpha_primary",
            receiving_agent_id="agent_alpha_research",
            tenant_id="tenant_alpha",
            permitted_tools=["read_document"],
            permitted_actions=["read"],
            resource_restrictions=["doc_alpha_radar"],
            max_depth=3,
            current_depth=2,
            expires_in_minutes=525600
        )
        _, child_payload, _ = security_engine.verify_delegation_credential(child_token)

        grant_child = DelegationGrant(
            id="grant_child_alpha",
            delegation_id=child_del_id,
            parent_delegation_id=parent_del_id,
            tenant_id="tenant_alpha",
            original_user_id="usr_alpha_admin",
            delegating_agent_id="agent_alpha_primary",
            receiving_agent_id="agent_alpha_research",
            permitted_tools_json=json.dumps(["read_document"]),
            permitted_actions_json=json.dumps(["read"]),
            resource_restrictions_json=json.dumps(["doc_alpha_radar"]),
            issued_at=now,
            expires_at=now + timedelta(days=365),
            max_depth=3,
            current_depth=2,
            jti=child_payload["jti"],
            audience=child_payload["aud"],
            signature=child_token,
            is_single_use=False,
            is_consumed=False,
            is_revoked=False,
            created_at=now
        )
        db.add(grant_child)

        db.commit()
        print("Database seed completed successfully.")

if __name__ == "__main__":
    seed_database()
