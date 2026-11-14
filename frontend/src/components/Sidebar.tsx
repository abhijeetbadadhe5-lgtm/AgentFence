import React from 'react';
import { TabType } from '../App';

interface SidebarProps {
  activeTab: TabType;
  onSelectTab: (tab: TabType) => void;
}

export default function Sidebar({ activeTab, onSelectTab }: SidebarProps) {
  const navItems: Array<{ id: TabType; label: string; icon: string }> = [
    { id: 'overview', label: 'Overview', icon: 'fa-chart-line' },
    { id: 'audit', label: 'Live Audit Events', icon: 'fa-list-check' },
    { id: 'delegation', label: 'Delegation Explorer', icon: 'fa-diagram-project' },
    { id: 'policy', label: 'Policy Management', icon: 'fa-scale-balanced' },
    { id: 'registry', label: 'Agents & Tools', icon: 'fa-cubes-stacked' },
    { id: 'attack-lab', label: 'Attack Simulation Lab', icon: 'fa-flask-vial' },
    { id: 'tenants', label: 'Tenant Management', icon: 'fa-building-shield' },
  ];

  return (
    <aside className="sidebar">
      <div className="brand-header">
        <div className="brand-icon">AF</div>
        <div>
          <div className="brand-title">AgentFence</div>
          <div className="brand-subtitle">MCP Security Gateway</div>
        </div>
      </div>
      <ul className="nav-links">
        {navItems.map((item) => (
          <li
            key={item.id}
            className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
            onClick={() => onSelectTab(item.id)}
          >
            <span>{item.label}</span>
          </li>
        ))}
      </ul>
      <div className="sidebar-footer">
        <div><strong>Status:</strong> Gateway Active</div>
        <div style={{ marginTop: '4px' }}><strong>Engine:</strong> Fail-Closed PDP</div>
      </div>
    </aside>
  );
}
