"""Response engine: policy -> dedup -> adapter -> audit."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from soclab.adapters.firewall import AdapterResult, FirewallAdapter, create_firewall_adapter
from soclab.config import Settings
from soclab.domain.alert import AlertSeverity, SecurityAlert
from soclab.services.audit import AuditLogger
from soclab.services.dedup import AlertDeduplicator
from soclab.services.evidence import EvidenceCollector
from soclab.services.policy import ResponseAction, ResponsePolicy


@dataclass(frozen=True)
class ResponseOutcome:
    """What the SOAR layer decided and whether it executed anything."""

    alert_id: str
    severity: AlertSeverity
    action: ResponseAction
    requested_action: ResponseAction
    target_ip: str | None
    executed: bool
    dry_run: bool
    duplicate: bool
    protected: bool
    adapter: str
    reason: str
    evidence_path: str | None = None

    def as_audit_event(self) -> dict[str, Any]:
        event = asdict(self)
        event["severity"] = self.severity.value
        event["action"] = self.action.value
        event["requested_action"] = self.requested_action.value
        return event


class ResponseService:
    """Decides and (in live mode) executes the response for one alert."""

    def __init__(
        self,
        *,
        policy: ResponsePolicy,
        adapter: FirewallAdapter,
        deduplicator: AlertDeduplicator,
        audit: AuditLogger,
        evidence: EvidenceCollector | None = None,
    ) -> None:
        self._policy = policy
        self._adapter = adapter
        self._dedup = deduplicator
        self._audit = audit
        self._evidence = evidence

    @property
    def dry_run(self) -> bool:
        return self._adapter.dry_run

    @property
    def adapter_name(self) -> str:
        return self._adapter.name

    @property
    def processed_alert_count(self) -> int:
        return self._dedup.count()

    def readiness_problems(self) -> list[str]:
        problems: list[str] = []
        if not self._audit.is_writable():
            problems.append(f"audit log is not writable: {self._audit.path}")
        if not self._dedup.is_writable():
            problems.append(f"dedup database is not writable: {self._dedup.path}")
        return problems

    def handle(self, alert: SecurityAlert) -> ResponseOutcome:
        decision = self._policy.evaluate(alert)

        if self._dedup.is_duplicate(alert.alert_id):
            outcome = ResponseOutcome(
                alert_id=alert.alert_id,
                severity=alert.severity,
                action=ResponseAction.NONE,
                requested_action=decision.requested_action,
                target_ip=decision.target_ip,
                executed=False,
                dry_run=self._adapter.dry_run,
                duplicate=True,
                protected=decision.protected,
                adapter=self._adapter.name,
                reason="duplicate alert_id ignored",
            )
            self._audit.record(outcome.as_audit_event())
            return outcome

        executed = False
        reason = decision.reason

        if decision.action is ResponseAction.BLOCK_IP and decision.target_ip is not None:
            result = self._adapter.block_ip(decision.target_ip)
            executed = result.executed
            reason = f"{decision.reason} ({result.message})"

        evidence_path: str | None = None
        if (
            self._evidence is not None
            and alert.severity in {AlertSeverity.HIGH, AlertSeverity.CRITICAL}
        ):
            try:
                saved = self._evidence.save(
                    alert,
                    action=decision.action.value,
                    requested_action=decision.requested_action.value,
                    target_ip=decision.target_ip,
                    executed=executed,
                    dry_run=self._adapter.dry_run,
                    protected=decision.protected,
                    adapter=self._adapter.name,
                    reason=reason,
                )
                evidence_path = str(saved)
            except OSError:
                evidence_path = None

        outcome = ResponseOutcome(
            alert_id=alert.alert_id,
            severity=alert.severity,
            action=decision.action,
            requested_action=decision.requested_action,
            target_ip=decision.target_ip,
            executed=executed,
            dry_run=self._adapter.dry_run,
            duplicate=False,
            protected=decision.protected,
            adapter=self._adapter.name,
            reason=reason,
            evidence_path=evidence_path,
        )
        self._audit.record(outcome.as_audit_event())
        return outcome

    def unblock(self, ip: str) -> AdapterResult:
        """Remove a firewall block for one IP and record the operator action."""
        result = self._adapter.unblock_ip(ip)
        self._audit.record(
            {
                "alert_id": f"unblock-{ip}",
                "severity": "INFO",
                "action": "UNBLOCK_IP",
                "requested_action": "UNBLOCK_IP",
                "target_ip": ip,
                "executed": result.executed,
                "dry_run": result.dry_run,
                "duplicate": False,
                "protected": False,
                "adapter": result.adapter,
                "reason": result.message,
            }
        )
        return result


def build_response_service(settings: Settings) -> ResponseService:
    """Wire the Stage 3 services from configuration."""
    return ResponseService(
        policy=ResponsePolicy(protected_networks=settings.protected_networks),
        adapter=create_firewall_adapter(dry_run=settings.response_dry_run),
        deduplicator=AlertDeduplicator(
            settings.state_db_path,
            ttl_seconds=settings.dedup_ttl_seconds,
        ),
        audit=AuditLogger(settings.audit_log_path),
        evidence=EvidenceCollector(settings.evidence_dir),
    )
