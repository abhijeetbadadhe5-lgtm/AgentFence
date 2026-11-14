import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import OverviewPage from './pages/OverviewPage';
import AuditEventsPage from './pages/AuditEventsPage';
import DelegationExplorerPage from './pages/DelegationExplorerPage';
import PolicyManagementPage from './pages/PolicyManagementPage';
import RegistryPage from './pages/RegistryPage';
import AttackLabPage from './pages/AttackLabPage';
import TenantManagementPage from './pages/TenantManagementPage';

export type TabType = 'overview' | 'audit' | 'delegation' | 'policy' | 'registry' | 'attack-lab' | 'tenants';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabType>('overview');

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} onSelectTab={setActiveTab} />
      <main className="main-content">
        <header className="top-bar">
          <div className="page-title">
            <span style={{ color: 'var(--accent-cyan)' }}>AgentFence</span> — AI Agent Security Gateway
          </div>
          <div className="top-bar-right">
            <span className="badge badge-info">MCP 2024-11-05</span>
            <span className="badge badge-allow">Hash-Chained Audit</span>
            <a href="/docs" target="_blank" rel="noreferrer" className="btn btn-secondary" style={{ textDecoration: 'none' }}>
              API Docs
            </a>
          </div>
        </header>

        <div className="content-body">
          {activeTab === 'overview' && <OverviewPage onNavigate={setActiveTab} />}
          {activeTab === 'audit' && <AuditEventsPage />}
          {activeTab === 'delegation' && <DelegationExplorerPage />}
          {activeTab === 'policy' && <PolicyManagementPage />}
          {activeTab === 'registry' && <RegistryPage />}
          {activeTab === 'attack-lab' && <AttackLabPage />}
          {activeTab === 'tenants' && <TenantManagementPage />}
        </div>
      </main>
    </div>
  );
}
