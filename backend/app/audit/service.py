"""AgentFence Audit & Security Monitoring Service: Hash-Chained Tamper-Evident Records & Metrics
"""
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from app.models.entities import AuditEvent
from app.core.config import settings
from app.core.security import security_engine

class AuditService:
    def __init__(self):
        self.genesis_hash = settings.AUDIT_GENESIS_HASH
        self._lock = threading.Lock()

    def log_event(
        self,
        db: Session,
        request_id: str,
        correlation_id: str,
        tenant_id: str,
        user_id: Optional[str],
        agent_id: Optional[str],
        parent_delegation_id: Optional[str],
        delegation_id: Optional[str],
        mcp_tool_name: str,
        requested_action: str,
        resource_id: Optional[str],
        decision: str,
        denial_reason: Optional[str] = None,
        attack_classification: Optional[str] = None,
        execution_outcome: str = "not_executed"
    ) -> AuditEvent:
        """Appends a new hash-chained audit event to the ledger."""
        with self._lock:
            now_iso = datetime.now(timezone.utc).isoformat()

            # Fetch the previous record to get its hash
            last_event = db.query(AuditEvent).order_by(AuditEvent.seq.desc()).first()
            prev_hash = last_event.record_hash if last_event else self.genesis_hash

            # Compute hash-chain link
            record_hash = security_engine.calculate_audit_hash(
                previous_hash=prev_hash,
                request_id=request_id,
                timestamp=now_iso,
                tenant_id=tenant_id,
                user_id=user_id,
                agent_id=agent_id,
                tool_name=mcp_tool_name,
                requested_action=requested_action,
                resource_id=resource_id,
                decision=decision,
                denial_reason=denial_reason
            )

            event = AuditEvent(
                id=security_engine.generate_id("aud"),
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now_iso,
                tenant_id=tenant_id,
                user_id=user_id,
                agent_id=agent_id,
                parent_delegation_id=parent_delegation_id,
                delegation_id=delegation_id,
                mcp_tool_name=mcp_tool_name,
                requested_action=requested_action,
                resource_id=resource_id,
                decision=decision,
                denial_reason=denial_reason,
                attack_classification=attack_classification,
                execution_outcome=execution_outcome,
                previous_record_hash=prev_hash,
                record_hash=record_hash
            )

            db.add(event)
            db.commit()
            db.refresh(event)
            return event

    def verify_audit_chain_integrity(self, db: Session) -> Tuple[bool, int, Optional[Dict[str, Any]]]:
        """Traverses the full audit log and verifies hash-chain integrity."""
        events = db.query(AuditEvent).order_by(AuditEvent.seq.asc()).all()
        if not events:
            return True, 0, None

        expected_prev_hash = self.genesis_hash

        for idx, ev in enumerate(events):
            # Check previous hash pointer
            if ev.previous_record_hash != expected_prev_hash:
                return False, idx, {
                    "event_id": ev.id,
                    "error": "Broken previous hash pointer",
                    "stored_previous_hash": ev.previous_record_hash,
                    "expected_previous_hash": expected_prev_hash
                }

            # Recalculate hash of this record
            calculated_hash = security_engine.calculate_audit_hash(
                previous_hash=ev.previous_record_hash,
                request_id=ev.request_id,
                timestamp=ev.timestamp,
                tenant_id=ev.tenant_id,
                user_id=ev.user_id,
                agent_id=ev.agent_id,
                tool_name=ev.mcp_tool_name,
                requested_action=ev.requested_action,
                resource_id=ev.resource_id,
                decision=ev.decision,
                denial_reason=ev.denial_reason
            )

            if calculated_hash != ev.record_hash:
                return False, idx, {
                    "event_id": ev.id,
                    "error": "Record content hash mismatch / data tampering detected",
                    "stored_hash": ev.record_hash,
                    "calculated_hash": calculated_hash
                }

            expected_prev_hash = ev.record_hash

        return True, len(events), None

    def get_security_metrics(self, db: Session) -> Dict[str, Any]:
        """Computes live security metrics from the audit ledger."""
        total_requests = db.query(AuditEvent).count()
        allowed_requests = db.query(AuditEvent).filter(AuditEvent.decision == "ALLOW").count()
        denied_requests = db.query(AuditEvent).filter(AuditEvent.decision == "DENY").count()

        # Attack classifications
        cross_tenant_attempts = db.query(AuditEvent).filter(
            AuditEvent.denial_reason.ilike("%cross-tenant%") |
            (AuditEvent.attack_classification == "cross_tenant")
        ).count()

        confused_deputy_attempts = db.query(AuditEvent).filter(
            AuditEvent.denial_reason.ilike("%confused deputy%") |
            (AuditEvent.attack_classification == "confused_deputy")
        ).count()

        escalation_attempts = db.query(AuditEvent).filter(
            AuditEvent.denial_reason.ilike("%escalation%") |
            (AuditEvent.attack_classification == "privilege_escalation")
        ).count()

        replay_attempts = db.query(AuditEvent).filter(
            AuditEvent.denial_reason.ilike("%replay%") |
            (AuditEvent.attack_classification == "replay_attack")
        ).count()

        # Tool invocations count
        tool_counts = db.query(
            AuditEvent.mcp_tool_name,
            func.count(AuditEvent.id)
        ).group_by(AuditEvent.mcp_tool_name).all()

        tool_distribution = [{"tool": t, "count": c} for t, c in tool_counts]

        # Recent 10 events
        recent_events = db.query(AuditEvent).order_by(AuditEvent.seq.desc()).limit(10).all()

        return {
            "total_requests": total_requests,
            "allowed_requests": allowed_requests,
            "denied_requests": denied_requests,
            "security_incidents": {
                "cross_tenant_attempts": cross_tenant_attempts,
                "confused_deputy_attempts": confused_deputy_attempts,
                "privilege_escalation_attempts": escalation_attempts,
                "replay_attempts": replay_attempts,
            },
            "tool_distribution": tool_distribution,
            "recent_events": [
                {
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "tenant_id": e.tenant_id,
                    "agent_id": e.agent_id,
                    "tool": e.mcp_tool_name,
                    "action": e.requested_action,
                    "resource_id": e.resource_id,
                    "decision": e.decision,
                    "reason": e.denial_reason,
                    "attack_classification": e.attack_classification
                }
                for e in recent_events
            ]
        }

audit_service = AuditService()
