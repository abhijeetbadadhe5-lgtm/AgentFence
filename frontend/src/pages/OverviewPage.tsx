import React, { useEffect, useState } from 'react';
import { api, SecurityMetrics } from '../services/api';
import { TabType } from '../App';

interface OverviewPageProps {
  onNavigate: (tab: TabType) => void;
}

export default function OverviewPage({ onNavigate }: OverviewPageProps) {
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [auditStatus, setAuditStatus] = useState<string>('Verifying SHA-256 hash chain...');
  const [isValidChain, setIsValidChain] = useState<boolean>(true);

  const loadData = async () => {
    try {
      const data = await api.getMetrics();
      setMetrics(data);
      const audit = await api.verifyAuditIntegrity();
      setIsValidChain(audit.is_valid);
      if (audit.is_valid) {
        setAuditStatus(`Cryptographically Verified: ${audit.records_verified} sequential records linked from Genesis.`);
      } else {
        setAuditStatus(`Audit Tampering Detected at Record ${audit.error_details?.event_id}!`);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const totalIncidents = metrics
    ? metrics.security_incidents.cross_tenant_attempts +
      metrics.security_incidents.confused_deputy_attempts +
      metrics.security_incidents.privilege_escalation_attempts +
      metrics.security_incidents.replay_attempts
    : 0;

  return (
    <div>
      <div className="grid-cards">
        <div className="stat-card">
          <div className="stat-header">Total MCP Requests</div>
          <div className="stat-value">{metrics?.total_requests ?? '-'}</div>
          <div className="stat-footer">Gateway Tool Invocations</div>
        </div>
        <div className="stat-card">
          <div className="stat-header">Authorized (ALLOW)</div>
          <div className="stat-value" style={{ color: 'var(--status-allow)' }}>{metrics?.allowed_requests ?? '-'}</div>
          <div className="stat-footer">Forwarded to Upstream Tools</div>
        </div>
        <div className="stat-card">
          <div className="stat-header">Blocked (DENY)</div>
          <div className="stat-value" style={{ color: 'var(--status-deny)' }}>{metrics?.denied_requests ?? '-'}</div>
          <div className="stat-footer">Scope & Policy Violations</div>
        </div>
        <div className="stat-card">
          <div className="stat-header">Security Incidents</div>
          <div className="stat-value" style={{ color: 'var(--status-warn)' }}>{totalIncidents}</div>
          <div className="stat-footer">Attacks Blocked by Gateway</div>
        </div>
      </div>

      <div className="card-panel" style={{ borderLeft: '4px solid var(--accent-cyan)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '4px' }}>
            Tamper-Evident Audit Ledger Integrity
          </h3>
          <p style={{ fontSize: '12.5px', color: isValidChain ? 'var(--status-allow)' : 'var(--status-deny)' }}>
            {auditStatus}
          </p>
        </div>
        <button className="btn btn-primary" onClick={loadData}>Verify Hash Chain</button>
      </div>

      <div className="card-panel">
        <div className="card-title">
          <span>Recent Security Audit Events</span>
          <button className="btn btn-secondary" onClick={() => onNavigate('audit')}>View All Events</button>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Tenant</th>
              <th>Agent / Principal</th>
              <th>Tool</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Decision</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {metrics?.recent_events.map((e) => (
              <tr key={e.id}>
                <td style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{e.timestamp.split('T')[1]?.substring(0, 8)}</td>
                <td><span className="code-pill">{e.tenant_id}</span></td>
                <td><strong>{e.agent_id || 'user'}</strong></td>
                <td><span className="code-pill">{e.tool}</span></td>
                <td>{e.action}</td>
                <td>{e.resource_id ? <span className="code-pill">{e.resource_id}</span> : '-'}</td>
                <td>
                  <span className={`badge ${e.decision === 'ALLOW' ? 'badge-allow' : 'badge-deny'}`}>
                    {e.decision}
                  </span>
                </td>
                <td style={{ fontSize: '11.5px', color: e.decision === 'ALLOW' ? 'var(--status-allow)' : 'var(--status-deny)' }}>
                  {e.reason || 'Authorized'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
