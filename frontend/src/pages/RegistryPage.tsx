import React, { useEffect, useState } from 'react';
import { api, AgentInfo, MCPToolInfo } from '../services/api';

export default function RegistryPage() {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [tools, setTools] = useState<MCPToolInfo[]>([]);

  useEffect(() => {
    const load = async () => {
      const [a, t] = await Promise.all([api.getAgents(), api.getTools()]);
      setAgents(a);
      setTools(t);
    };
    load();
  }, []);

  return (
    <div>
      <div className="card-panel">
        <h3 className="card-title">Registered AI Agents</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Agent ID</th>
              <th>Tenant</th>
              <th>Name</th>
              <th>Type</th>
              <th>Role</th>
              <th>Description</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.id}>
                <td><span className="code-pill">{a.id}</span></td>
                <td><span className="code-pill">{a.tenant_id}</span></td>
                <td><strong>{a.name}</strong></td>
                <td><span className="badge badge-info">{a.agent_type}</span></td>
                <td>{a.role}</td>
                <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{a.description}</td>
                <td><span className="badge badge-allow">ACTIVE</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card-panel">
        <h3 className="card-title">Registered MCP Tools</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Tool Name</th>
              <th>Description</th>
              <th>Required Scopes</th>
              <th>Risk Level</th>
              <th>Upstream Endpoint</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {tools.map((t) => (
              <tr key={t.id}>
                <td><span className="code-pill">{t.name}</span></td>
                <td style={{ fontSize: '12px' }}>{t.description}</td>
                <td>{t.required_scopes.map((s) => <span key={s} className="code-pill">{s}</span>)}</td>
                <td>
                  <span className={`badge ${t.risk_level === 'critical' ? 'badge-deny' : t.risk_level === 'high' ? 'badge-warn' : 'badge-info'}`}>
                    {t.risk_level}
                  </span>
                </td>
                <td style={{ fontSize: '11.5px', color: 'var(--text-dim)' }}>{t.upstream_endpoint}</td>
                <td><span className="badge badge-allow">ENABLED</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
