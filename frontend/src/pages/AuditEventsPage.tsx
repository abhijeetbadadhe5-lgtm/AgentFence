import React, { useEffect, useState } from 'react';
import { api, AuditEventInfo } from '../services/api';

export default function AuditEventsPage() {
  const [events, setEvents] = useState<AuditEventInfo[]>([]);
  const [tenantFilter, setTenantFilter] = useState('ALL');
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const [toolFilter, setToolFilter] = useState('ALL');

  const fetchEvents = async () => {
    try {
      const data = await api.getAuditEvents({
        tenant_id: tenantFilter,
        decision: decisionFilter,
        tool: toolFilter,
      });
      setEvents(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [tenantFilter, decisionFilter, toolFilter]);

  const handleVerify = async () => {
    const res = await api.verifyAuditIntegrity();
    if (res.is_valid) {
      alert(`Audit Ledger Integrity Verified!\n\nStatus: VALID\nTotal Records: ${res.records_verified}\nChain Head: ${res.chain_head_hash}`);
    } else {
      alert(`Tampering detected at record: ${res.error_details?.event_id}`);
    }
  };

  return (
    <div className="card-panel">
      <div style={{ display: 'flex', gap: '12px', marginBottom: '20px', flexWrap: 'wrap', alignItems: 'center' }}>
        <select className="form-select" style={{ width: '180px' }} value={tenantFilter} onChange={(e) => setTenantFilter(e.target.value)}>
          <option value="ALL">All Tenants</option>
          <option value="tenant_alpha">Tenant Alpha</option>
          <option value="tenant_beta">Tenant Beta</option>
        </select>
        <select className="form-select" style={{ width: '160px' }} value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)}>
          <option value="ALL">All Decisions</option>
          <option value="ALLOW">ALLOW Only</option>
          <option value="DENY">DENY Only</option>
        </select>
        <select className="form-select" style={{ width: '220px' }} value={toolFilter} onChange={(e) => setToolFilter(e.target.value)}>
          <option value="ALL">All Tools</option>
          <option value="read_document">read_document</option>
          <option value="search_knowledge_base">search_knowledge_base</option>
          <option value="execute_analytics_query">execute_analytics_query</option>
          <option value="export_tenant_report">export_tenant_report</option>
          <option value="admin_override">admin_override</option>
        </select>
        <button className="btn btn-secondary" onClick={fetchEvents}>Refresh</button>
        <button className="btn btn-primary" style={{ marginLeft: 'auto' }} onClick={handleVerify}>Verify Hash Chain</button>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Seq</th>
            <th>Timestamp</th>
            <th>Tenant</th>
            <th>Agent / Principal</th>
            <th>Tool</th>
            <th>Action</th>
            <th>Resource</th>
            <th>Decision</th>
            <th>Reason & Classification</th>
            <th>Hash Pointer</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td><strong>#{e.seq}</strong></td>
              <td style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{e.timestamp.replace('T', ' ').substring(0, 19)}</td>
              <td><span className="code-pill">{e.tenant_id}</span></td>
              <td>{e.agent_id || e.user_id || 'system'}</td>
              <td><span className="code-pill">{e.tool}</span></td>
              <td>{e.action}</td>
              <td>{e.resource_id ? <span className="code-pill">{e.resource_id}</span> : '-'}</td>
              <td>
                <span className={`badge ${e.decision === 'ALLOW' ? 'badge-allow' : 'badge-deny'}`}>
                  {e.decision}
                </span>
              </td>
              <td style={{ fontSize: '11.5px' }}>
                {e.denial_reason || 'Policy Permit'}{' '}
                {e.attack_classification && <span className="badge badge-warn">{e.attack_classification}</span>}
              </td>
              <td><span className="code-pill" title={`Hash: ${e.record_hash}`}>{e.record_hash.substring(0, 10)}...</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
