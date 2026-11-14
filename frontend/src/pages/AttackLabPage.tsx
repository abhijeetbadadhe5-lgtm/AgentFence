import React, { useState } from 'react';
import { api, AttackSimulationResult } from '../services/api';

const SCENARIOS = [
  { key: 'attack_1', name: 'Attack 1: Confused Deputy Attack', desc: 'Low-privilege agent attempts to invoke privileged admin_override' },
  { key: 'attack_2', name: 'Attack 2: Cross-Tenant Data Access', desc: 'Alpha agent attempts to read Beta protected document doc_beta_trial' },
  { key: 'attack_3', name: 'Attack 3: Delegation Privilege Escalation', desc: 'Sub-agent tries to expand scope beyond parent delegation grant' },
  { key: 'attack_4', name: 'Attack 4: Delegation Chain Tampering', desc: 'Attacker tampers with JWT claims after credential signature' },
  { key: 'attack_5', name: 'Attack 5: Expired Delegation', desc: 'Agent attempts invocation using expired delegation credential' },
  { key: 'attack_6', name: 'Attack 6: Audience Mismatch', desc: 'Delegation credential intended for foreign gateway presented to AgentFence' },
  { key: 'attack_7', name: 'Attack 7: Token Replay Attack', desc: 'Single-use delegation credential consumed a second time' },
  { key: 'attack_8', name: 'Attack 8: Excessive Delegation Depth', desc: 'Sub-agent attempts creating child delegation exceeding max depth limit' },
  { key: 'attack_9', name: 'Attack 9: Unauthorized Tool Execution', desc: 'Agent invokes tool not included in delegated tool permissions' },
  { key: 'attack_10', name: 'Attack 10: Missing Identity Context', desc: 'Tool call arrives without authenticated identity token' },
];

export default function AttackLabPage() {
  const [results, setResults] = useState<Record<string, AttackSimulationResult>>({});
  const [loading, setLoading] = useState(false);

  const runAll = async () => {
    setLoading(true);
    try {
      const data = await api.runAttackSimulations();
      const map: Record<string, AttackSimulationResult> = {};
      data.forEach((r) => {
        // Find matching key
        for (const s of SCENARIOS) {
          if (r.key.includes(s.key)) {
            map[s.key] = r;
            break;
          }
        }
      });
      setResults(map);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const runSingle = async (key: string) => {
    try {
      const data = await api.runAttackSimulations(key);
      if (data && data.length > 0) {
        setResults((prev) => ({ ...prev, [key]: data[0] }));
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div>
      <div className="card-panel" style={{ borderLeft: '4px solid var(--status-deny)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '4px' }}>Attack Simulation Lab (10 Live Scenarios)</h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Executes real attack requests against the gateway to demonstrate actual authorization enforcement.
          </p>
        </div>
        <button className="btn btn-primary" style={{ background: 'linear-gradient(135deg, #b91c1c, #ef4444)' }} onClick={runAll} disabled={loading}>
          {loading ? 'Executing Scenarios...' : 'Execute All 10 Attacks'}
        </button>
      </div>

      <div className="card-panel">
        <h3 className="card-title">Attack Execution Matrix</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Scenario Name</th>
              <th>Expected Result</th>
              <th>Actual Result</th>
              <th>Status</th>
              <th>Evaluated Security Checks</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {SCENARIOS.map((s, idx) => {
              const res = results[s.key];
              return (
                <tr key={s.key}>
                  <td><strong>{idx + 1}</strong></td>
                  <td>
                    <strong>{s.name}</strong>
                    <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{s.desc}</div>
                  </td>
                  <td><span className="badge badge-deny">DENIED</span></td>
                  <td>{res ? <span className="code-pill">{res.actual_result}</span> : <span style={{ color: 'var(--text-dim)' }}>Ready</span>}</td>
                  <td>
                    {res ? (
                      <span className={`badge ${res.passed ? 'badge-allow' : 'badge-deny'}`}>
                        {res.passed ? 'PASSED (BLOCKED)' : 'FAILED (EXPLOITED)'}
                      </span>
                    ) : (
                      <span className="badge badge-info">PENDING</span>
                    )}
                  </td>
                  <td style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                    {res ? (
                      res.checks_evaluated.map((c, i) => (
                        <div key={i}>• {c.check}: <strong>{c.status}</strong></div>
                      ))
                    ) : (
                      '-'
                    )}
                  </td>
                  <td>
                    <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: '11.5px' }} onClick={() => runSingle(s.key)}>
                      Run
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
