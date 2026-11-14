/**
 * AgentFence Frontend API Client Service
 */

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://127.0.0.1:8080'
  : '';

export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  protocol: string;
  engine: string;
}

export interface SecurityMetrics {
  total_requests: number;
  allowed_requests: number;
  denied_requests: number;
  security_incidents: {
    cross_tenant_attempts: number;
    confused_deputy_attempts: number;
    privilege_escalation_attempts: number;
    replay_attempts: number;
  };
  tool_distribution: Array<{ tool: string; count: number }>;
  recent_events: Array<{
    id: string;
    timestamp: string;
    tenant_id: string;
    agent_id: string;
    tool: string;
    action: string;
    resource_id?: string;
    decision: string;
    reason?: string;
    attack_classification?: string;
  }>;
}

export interface TenantInfo {
  id: string;
  name: string;
  slug: string;
  description: string;
  status: string;
  users_count: number;
  agents_count: number;
  resources_count: number;
  policies_count: number;
}

export interface AgentInfo {
  id: string;
  tenant_id: string;
  name: string;
  agent_type: string;
  role: string;
  description: string;
  is_active: boolean;
}

export interface MCPToolInfo {
  id: string;
  name: string;
  description: string;
  parameters_schema: any;
  required_scopes: string[];
  risk_level: string;
  upstream_endpoint: string;
  is_enabled: boolean;
}

export interface DelegationGrantInfo {
  id: string;
  delegation_id: string;
  parent_delegation_id?: string;
  tenant_id: string;
  original_user_id: string;
  delegating_agent_id: string;
  receiving_agent_id: string;
  permitted_tools: string[];
  permitted_actions: string[];
  resource_restrictions: string[];
  current_depth: number;
  max_depth: number;
  is_single_use: boolean;
  is_consumed: boolean;
  is_revoked: boolean;
  expires_at: string;
  signature: string;
}

export interface PolicyInfo {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  effect: 'ALLOW' | 'DENY';
  principal_type: string;
  principal_id: string;
  role: string;
  tool_pattern: string;
  action_pattern: string;
  resource_pattern: string;
  conditions: any;
  priority: number;
  is_active: boolean;
}

export interface AuditEventInfo {
  id: string;
  seq: number;
  request_id: string;
  correlation_id: string;
  timestamp: string;
  tenant_id: string;
  user_id?: string;
  agent_id?: string;
  delegation_id?: string;
  tool: string;
  action: string;
  resource_id?: string;
  decision: 'ALLOW' | 'DENY';
  denial_reason?: string;
  attack_classification?: string;
  execution_outcome: string;
  previous_record_hash: string;
  record_hash: string;
}

export interface AttackSimulationResult {
  key: string;
  scenario_name: string;
  expected_result: string;
  actual_result: string;
  passed: boolean;
  request_details: any;
  checks_evaluated: Array<{ check: string; status: string }>;
  audit_event_id?: string;
}

export const api = {
  async getHealth(): Promise<HealthStatus> {
    const res = await fetch(`${API_BASE}/api/v1/health`);
    return res.json();
  },

  async getMetrics(): Promise<SecurityMetrics> {
    const res = await fetch(`${API_BASE}/api/v1/metrics/overview`);
    return res.json();
  },

  async getTenants(): Promise<TenantInfo[]> {
    const res = await fetch(`${API_BASE}/api/v1/tenants`);
    return res.json();
  },

  async getTenantDetails(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/api/v1/tenants/${id}`);
    return res.json();
  },

  async getAgents(tenantId?: string): Promise<AgentInfo[]> {
    const url = tenantId ? `${API_BASE}/api/v1/agents?tenant_id=${tenantId}` : `${API_BASE}/api/v1/agents`;
    const res = await fetch(url);
    return res.json();
  },

  async getTools(): Promise<MCPToolInfo[]> {
    const res = await fetch(`${API_BASE}/api/v1/tools`);
    return res.json();
  },

  async getDelegations(tenantId?: string): Promise<DelegationGrantInfo[]> {
    const url = tenantId ? `${API_BASE}/api/v1/delegations?tenant_id=${tenantId}` : `${API_BASE}/api/v1/delegations`;
    const res = await fetch(url);
    return res.json();
  },

  async createDelegation(data: any): Promise<any> {
    const res = await fetch(`${API_BASE}/api/v1/delegations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return res.json();
  },

  async revokeDelegation(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/api/v1/delegations/revoke/${id}`, { method: 'POST' });
    return res.json();
  },

  async getPolicies(tenantId?: string): Promise<PolicyInfo[]> {
    const url = tenantId ? `${API_BASE}/api/v1/policies?tenant_id=${tenantId}` : `${API_BASE}/api/v1/policies`;
    const res = await fetch(url);
    return res.json();
  },

  async togglePolicy(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/api/v1/policies/${id}/toggle`, { method: 'POST' });
    return res.json();
  },

  async simulatePolicy(params: any): Promise<any> {
    const res = await fetch(`${API_BASE}/api/v1/policies/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    return res.json();
  },

  async getAuditEvents(filters?: { tenant_id?: string; tool?: string; decision?: string }): Promise<AuditEventInfo[]> {
    const params = new URLSearchParams();
    if (filters?.tenant_id && filters.tenant_id !== 'ALL') params.append('tenant_id', filters.tenant_id);
    if (filters?.tool && filters.tool !== 'ALL') params.append('tool', filters.tool);
    if (filters?.decision && filters.decision !== 'ALL') params.append('decision', filters.decision);
    const res = await fetch(`${API_BASE}/api/v1/audit/events?${params.toString()}`);
    return res.json();
  },

  async verifyAuditIntegrity(): Promise<any> {
    const res = await fetch(`${API_BASE}/api/v1/audit/verify`);
    return res.json();
  },

  async runAttackSimulations(scenarioKey?: string): Promise<AttackSimulationResult[]> {
    const url = scenarioKey ? `${API_BASE}/api/v1/simulations/run?scenario=${scenarioKey}` : `${API_BASE}/api/v1/simulations/run`;
    const res = await fetch(url, { method: 'POST' });
    return res.json();
  },

  async getSimulationResults(): Promise<any[]> {
    const res = await fetch(`${API_BASE}/api/v1/simulations/results`);
    return res.json();
  },
};
