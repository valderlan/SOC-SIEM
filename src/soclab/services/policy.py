"""Response policy: severity to action mapping plus IP protection."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from soclab.domain.alert import AlertSeverity, SecurityAlert
from soclab.domain.networks import (
    DEFAULT_PROTECTED_NETWORKS,
    IPNetwork,
    is_protected,
    parse_network_list,
)


class ResponseAction(StrEnum):
    """Actions the SOAR layer may take for an alert."""

    NONE = "NONE"
    LOG = "LOG"
    NOTIFY = "NOTIFY"
    BLOCK_IP = "BLOCK_IP"


SEVERITY_ACTIONS: dict[AlertSeverity, ResponseAction] = {
    AlertSeverity.LOW: ResponseAction.LOG,
    AlertSeverity.MEDIUM: ResponseAction.LOG,
    AlertSeverity.HIGH: ResponseAction.NOTIFY,
    AlertSeverity.CRITICAL: ResponseAction.BLOCK_IP,
}


@dataclass(frozen=True)
class ResponseDecision:
    alert_id: str
    severity: AlertSeverity
    action: ResponseAction
    requested_action: ResponseAction
    target_ip: str | None
    reason: str
    protected: bool = False


class ResponsePolicy:
    """Deterministic severity mapping with a hard safety net for protected IPs."""

    def __init__(
        self, *, protected_networks: str | Iterable[IPNetwork] = DEFAULT_PROTECTED_NETWORKS
    ) -> None:
        self._networks: tuple[IPNetwork, ...] = (
            parse_network_list(protected_networks)
            if isinstance(protected_networks, str)
            else tuple(protected_networks)
        )

    @property
    def protected_networks(self) -> tuple[IPNetwork, ...]:
        return self._networks

    def evaluate(self, alert: SecurityAlert) -> ResponseDecision:
        requested = SEVERITY_ACTIONS[alert.severity]
        target = str(alert.src_ip) if alert.src_ip is not None else None

        if requested is not ResponseAction.BLOCK_IP:
            return ResponseDecision(
                alert_id=alert.alert_id,
                severity=alert.severity,
                action=requested,
                requested_action=requested,
                target_ip=target,
                reason=f"{alert.severity.value} severity requires {requested.value}",
            )

        if target is None:
            return self._downgrade(
                alert, requested, target, "block skipped: alert has no source IP"
            )

        if is_protected(target, self._networks):
            return self._downgrade(
                alert,
                requested,
                target,
                f"block skipped: {target} is a protected/administrative address",
                protected=True,
            )

        return ResponseDecision(
            alert_id=alert.alert_id,
            severity=alert.severity,
            action=ResponseAction.BLOCK_IP,
            requested_action=requested,
            target_ip=target,
            reason=f"{alert.severity.value} severity requires BLOCK_IP for {target}",
        )

    @staticmethod
    def _downgrade(
        alert: SecurityAlert,
        requested: ResponseAction,
        target: str | None,
        reason: str,
        *,
        protected: bool = False,
    ) -> ResponseDecision:
        return ResponseDecision(
            alert_id=alert.alert_id,
            severity=alert.severity,
            action=ResponseAction.NOTIFY,
            requested_action=requested,
            target_ip=target,
            reason=reason,
            protected=protected,
        )
