import React, { useEffect, useState } from 'react';
import { api, DelegationGrantInfo } from '../services/api';

export default function DelegationExplorerPage() {
  const [grants, setGrants] = useState<DelegationGrantInfo[]>([]);
  const [showModal, setShowModal] = useState(false);
  const [tenant, setTenant] = useState('tenant_alpha');
  const [delegator, setDelegator] = useState('agent_alpha_primary');
  const [receiver, setReceiver] = useState('agent_alpha_research');
  const [parent, setParent] = useState('del_alpha_root_001');
  const [tools, setTools] = useState('read_document');
  const [resources, setResources] = useState('doc_alpha_radar');
  const [duration, setDuration] = useState(30);

  const fetchGrants = async () => {
    try {
      const data = await api.getDelegations();
      setGrants(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchGrants();
  }, []);

  const handleRevoke = async (id: string) => {
    if (!confirm(`Revoke delegation ${id}?`)) return;
    await api.revokeDelegation(id);
    fetchGrants();
  };

  const handleCreate = async () => {
    try {
      const res = await api.createDelegation({
        tenant_id: tenant,
        delegating_agent_id: delegator,
        receiving_agent_id: receiver,
        parent_delegation_id: parent || null,
        permitted_tools: tools.split(',').map((s) => s.trim()).filter(Boolean),
        permitted_actions: ['read'],
        resource_restrictions: resources.split(',').map((s) => s.trim()).filter(Boolean),
        duration_minutes: duration,
      });
      if (res.success) {
        alert(`Delegation Created!\nID: ${res.delegation_id}\nDepth: ${res.current_depth}/${res.max_depth}`);
        setShowModal(false);
        fetchGrants();
      } else {
        alert(`DELEGATION REJECTED:\n\nCode: ${res.code}\nReason: ${res.error}`);
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontSize: '16px', fontWeight: 700 }}>Hierarchical Delegation Chains</h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Cryptographically signed delegation chains with real-time permission attenuation.
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>Issue New Delegation</button>
      </div>

      <div className="card-panel">
        <h3 className="card-title">Active Delegation Grants</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Delegation ID</th>
              <th>Parent ID</th>
              <th>Tenant</th>
              <th>Delegator</th>
              <th>Receiver</th>
              <th>Tools Scope</th>
              <th>Depth</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.id}>
                <td><span className="code-pill">{g.delegation_id}</span></td>
                <td>{g.parent_delegation_id ? <span className="code-pill">{g.parent_delegation_id}</span> : '- (Root)'}</td>
                <td><span className="code-pill">{g.tenant_id}</span></td>
                <td>{g.delegating_agent_id}</td>
                <td><strong>{g.receiving_agent_id}</strong></td>
                <td>{g.permitted_tools.map((t) => <span key={t} className="code-pill">{t}</span>)}</td>
                <td><span className="badge badge-info">{g.current_depth} / {g.max_depth}</span></td>
                <td>
                  <span className={`badge ${g.is_revoked ? 'badge-deny' : 'badge-allow'}`}>
                    {g.is_revoked ? 'Revoked' : 'Active'}
                  </span>
                </td>
                <td>
                  {!g.is_revoked && (
                    <button className="btn btn-danger" style={{ padding: '3px 8px', fontSize: '11px' }} onClick={() => handleRevoke(g.delegation_id)}>
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '16px' }}>Issue Attenuated Delegation</h3>
            <div className="form-group">
              <label className="form-label">Tenant</label>
              <select className="form-select" value={tenant} onChange={(e) => setTenant(e.target.value)}>
                <option value="tenant_alpha">Tenant Alpha</option>
                <option value="tenant_beta">Tenant Beta</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Delegating Agent (Parent)</label>
              <input type="text" className="form-input" value={delegator} onChange={(e) => setDelegator(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Receiving Agent (Child)</label>
              <input type="text" className="form-input" value={receiver} onChange={(e) => setReceiver(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Parent Delegation ID</label>
              <input type="text" className="form-input" value={parent} onChange={(e) => setParent(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Permitted Tools (comma separated)</label>
              <input type="text" className="form-input" value={tools} onChange={(e) => setTools(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Resource Restrictions (comma separated)</label>
              <input type="text" className="form-input" value={resources} onChange={(e) => setResources(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Duration (Minutes)</label>
              <input type="number" className="form-input" value={duration} onChange={(e) => setDuration(parseInt(e.target.value))} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
              <button className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleCreate}>Create Signed Delegation</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
