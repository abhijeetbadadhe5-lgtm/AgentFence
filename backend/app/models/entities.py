"""AgentFence Database Models: Multi-tenant, Identity, Delegation, Policies, Resources, Audits
"""
from datetime import datetime, timezone
import json
from typing import List, Optional
from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Text, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from app.models.base import Base

def utcnow():
    return datetime.now(timezone.utc)

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    slug = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(32), default="active", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    agents = relationship("Agent", back_populates="tenant", cascade="all, delete-orphan")
    resources = relationship("ProtectedResource", back_populates="tenant", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="tenant", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    username = Column(String(64), nullable=False)
    email = Column(String(128), nullable=False)
    role = Column(String(64), default="user", nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    tenant = relationship("Tenant", back_populates="users")

class Agent(Base):
    __tablename__ = "agents"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    agent_type = Column(String(64), default="assistant", nullable=False) # primary | subagent | restricted
    role = Column(String(64), default="agent", nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    tenant = relationship("Tenant", back_populates="agents")

class MCPTool(Base):
    __tablename__ = "mcp_tools"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=False)
    parameters_schema_json = Column(Text, default="{}", nullable=False)
    required_scopes_json = Column(Text, default="[]", nullable=False)
    risk_level = Column(String(32), default="medium", nullable=False) # low | medium | high | critical
    upstream_endpoint = Column(String(256), nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    def get_parameters_schema(self):
        try:
            return json.loads(self.parameters_schema_json)
        except Exception:
            return {}

    def get_required_scopes(self) -> List[str]:
        try:
            return json.loads(self.required_scopes_json)
        except Exception:
            return []

class DelegationGrant(Base):
    __tablename__ = "delegation_grants"

    id = Column(String(64), primary_key=True)
    delegation_id = Column(String(64), unique=True, nullable=False, index=True)
    parent_delegation_id = Column(String(64), nullable=True, index=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    original_user_id = Column(String(64), nullable=False, index=True)
    delegating_agent_id = Column(String(64), nullable=False, index=True)
    receiving_agent_id = Column(String(64), nullable=False, index=True)
    permitted_tools_json = Column(Text, default="[]", nullable=False)
    permitted_actions_json = Column(Text, default="[]", nullable=False)
    resource_restrictions_json = Column(Text, default="[]", nullable=False)
    issued_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    max_depth = Column(Integer, default=3, nullable=False)
    current_depth = Column(Integer, default=1, nullable=False)
    jti = Column(String(64), unique=True, nullable=False, index=True)
    audience = Column(String(128), nullable=False)
    signature = Column(Text, nullable=False)
    is_single_use = Column(Boolean, default=False, nullable=False)
    is_consumed = Column(Boolean, default=False, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    def get_permitted_tools(self) -> List[str]:
        try:
            return json.loads(self.permitted_tools_json)
        except Exception:
            return []

    def get_permitted_actions(self) -> List[str]:
        try:
            return json.loads(self.permitted_actions_json)
        except Exception:
            return []

    def get_resource_restrictions(self) -> List[str]:
        try:
            return json.loads(self.resource_restrictions_json)
        except Exception:
            return []

class Policy(Base):
    __tablename__ = "policies"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    effect = Column(String(16), default="ALLOW", nullable=False) # ALLOW | DENY
    principal_type = Column(String(32), default="*", nullable=False) # user | agent | *
    principal_id = Column(String(64), default="*", nullable=False)
    role = Column(String(64), default="*", nullable=False)
    tool_pattern = Column(String(128), default="*", nullable=False)
    action_pattern = Column(String(64), default="*", nullable=False)
    resource_pattern = Column(String(128), default="*", nullable=False)
    conditions_json = Column(Text, default="{}", nullable=False)
    priority = Column(Integer, default=100, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    tenant = relationship("Tenant", back_populates="policies")

    def get_conditions(self):
        try:
            return json.loads(self.conditions_json)
        except Exception:
            return {}

class ProtectedResource(Base):
    __tablename__ = "protected_resources"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    resource_type = Column(String(64), default="document", nullable=False)
    sensitivity_level = Column(String(32), default="confidential", nullable=False) # public | internal | confidential | secret
    owner_id = Column(String(64), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    tenant = relationship("Tenant", back_populates="resources")

class AuditEvent(Base):
    __tablename__ = "audit_events"

    seq = Column(Integer, primary_key=True, autoincrement=True)
    id = Column(String(64), unique=True, nullable=False, index=True)
    request_id = Column(String(64), nullable=False, index=True)
    correlation_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(String(32), nullable=False)
    tenant_id = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=True)
    agent_id = Column(String(64), nullable=True)
    parent_delegation_id = Column(String(64), nullable=True)
    delegation_id = Column(String(64), nullable=True)
    mcp_tool_name = Column(String(128), nullable=False)
    requested_action = Column(String(64), nullable=False)
    resource_id = Column(String(64), nullable=True)
    decision = Column(String(16), nullable=False) # ALLOW | DENY
    denial_reason = Column(Text, nullable=True)
    attack_classification = Column(String(64), nullable=True)
    execution_outcome = Column(String(64), default="not_executed", nullable=False)
    previous_record_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False, unique=True, index=True)

class ReplayIdentifier(Base):
    __tablename__ = "replay_identifiers"

    id = Column(String(64), primary_key=True)
    jti = Column(String(64), unique=True, nullable=False, index=True)
    delegation_id = Column(String(64), nullable=False, index=True)
    consumer_agent_id = Column(String(64), nullable=False)
    consumed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

class AttackSimulationResult(Base):
    __tablename__ = "attack_simulation_results"

    id = Column(String(64), primary_key=True)
    simulation_key = Column(String(64), nullable=False, index=True)
    scenario_name = Column(String(128), nullable=False)
    expected_result = Column(String(32), nullable=False)
    actual_result = Column(String(32), nullable=False)
    passed = Column(Boolean, nullable=False)
    request_details_json = Column(Text, default="{}", nullable=False)
    checks_evaluated_json = Column(Text, default="[]", nullable=False)
    audit_event_id = Column(String(64), nullable=True)
    executed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
