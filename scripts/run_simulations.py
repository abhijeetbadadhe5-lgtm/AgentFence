"""AgentFence Attack Simulation Runner Script
"""
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.database.session import get_db, init_db
from app.simulations.engine import attack_simulation_lab

def main():
    init_db()
    with get_db() as db:
        print("=" * 70)
        print("AGENTFENCE ATTACK SIMULATION LAB - LIVE RUN")
        print("=" * 70)
        results = attack_simulation_lab.run_all_simulations(db)
        passed_count = sum(1 for r in results if r["passed"])
        print(f"Executed: {len(results)} attack scenarios | Passed: {passed_count}/{len(results)}\n")
        for idx, r in enumerate(results, start=1):
            status = "PASSED [BLOCKED]" if r["passed"] else "FAILED [EXPLOITED]"
            print(f"[{idx}/10] {r['scenario_name']}")
            print(f"     Expected: {r['expected_result']}")
            print(f"     Actual:   {r['actual_result']}")
            print(f"     Status:   {status}\n")
        print("=" * 70)

if __name__ == "__main__":
    main()
