import React, { useEffect, useState } from 'react';
import { api, TenantInfo } from '../services/api';

export default function TenantManagementPage() {
  const [tenants, setTenants] = useState<TenantInfo[]>([]);

  useEffect(() => {
    const load = async () => {
      const data = await api.getTenants();
      setTenants(data);
    };
    load();
  }, []);

  return (
    <div className="card-panel">
      <h3 className="card-title">Multi-Tenant Isolation Boundaries</h3>
      <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '18px' }}>
        AgentFence enforces strict physical and query-level tenant isolation. Tokens, agent identities, and delegations are strictly scoped.
      </p>

      <div className="grid-cards">
        {tenants.map((t) => (
          <div key={t.id} className="card-panel" style={{ marginBottom: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700 }}>{t.name}</h3>
              <span className="badge badge-info">ID: {t.id}</span>
            </div>
            <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', marginBottom: '16px' }}>{t.description}</p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px', fontSize: '12.5px' }}>
              <div style={{ background: '#0f172a', padding: '10px', borderRadius: '6px' }}><strong>Users:</strong> {t.users_count}</div>
              <div style={{ background: '#0f172a', padding: '10px', borderRadius: '6px' }}><strong>Agents:</strong> {t.agents_count}</div>
              <div style={{ background: '#0f172a', padding: '10px', borderRadius: '6px' }}><strong>Protected Resources:</strong> {t.resources_count}</div>
              <div style={{ background: '#0f172a', padding: '10px', borderRadius: '6px' }}><strong>Active Policies:</strong> {t.policies_count}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
