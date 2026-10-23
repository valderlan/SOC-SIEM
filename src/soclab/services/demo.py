"""End-to-end Stage 3 demo: policy decisions, dedup, protection and webhook API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import uuid4

from soclab.config import Settings
from soclab.domain.alert import AlertSeverity, SecurityAlert
from soclab.services.api_smoke import ApiSmokeCheck, ensure_webhook_token, run_api_smoke
from soclab.services.policy import ResponseAction
from soclab.services.response import ResponseOutcome, ResponseService


@dataclass(frozen=True)
class DemoExpectation:
    label: str
    alert: SecurityAlert
    expected_action: ResponseAction
    expected_duplicate: bool = False
    expected_protected: bool = False


@dataclass
class DemoStep:
    expectation: DemoExpectation
    outcome: ResponseOutcome

    @property
    def passed(self) -> bool:
        expected = self.expectation
        outcome = self.outcome
        return (
            outcome.action is expected.expected_action
            and outcome.duplicate is expected.expected_duplicate
            and outcome.protected is expected.expected_protected
            # dry-run guarantee: nothing may reach the real firewall
            and not outcome.executed
        )


@dataclass
class DemoReport:
    run_id: str
    steps: list[DemoStep] = field(default_factory=list)
    api_checks: list[ApiSmokeCheck] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(step.passed for step in self.steps) and all(
            check.passed for check in self.api_checks
        )

    @property
    def failures(self) -> list[str]:
        problems = [
            f"{step.expectation.label}: got {step.outcome.action.value}"
            for step in self.steps
            if not step.passed
        ]
        problems.extend(
            f"{check.name}: {check.detail}"
            for check in self.api_checks
            if not check.passed
        )
        return problems


def build_shuffle_payload(*, alert_id: str) -> dict[str, Any]:
    """Shuffle/Wazuh-style body used to exercise the mapper through the API."""
    return {
        "execution_id": "soclab-demo-execution",
        "workflow": "SOC Lab - Stage 3 demo",
        "alert": {
            "alert_id": alert_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "wazuh",
            "rule": {
                "id": "5712",
                "level": 13,
                "description": "Simulated SSH brute force from the internet",
            },
            "srcip": "203.0.113.99",
            "dstip": "10.0.0.10",
        },
    }


def build_demo_expectations(*, run_id: str) -> list[DemoExpectation]:
    now = datetime.now(UTC)
    critical = SecurityAlert(
        alert_id=f"demo-{run_id}-critical",
        timestamp=now,
        source="suricata",
        severity=AlertSeverity.CRITICAL,
        src_ip=ip_address("203.0.113.99"),
        src_port=44321,
        dst_ip=ip_address("10.0.0.10"),
        dst_port=22,
        protocol="TCP",
        signature="ET SCAN Simulated SSH brute force",
        signature_id=2001219,
        category="Attempted Administrator Privilege Gain",
    )

    def built(
        label: str,
        severity: AlertSeverity,
        src_ip: str,
        signature: str,
        expected: ResponseAction,
        *,
        alert: SecurityAlert | None = None,
        duplicate: bool = False,
        protected: bool = False,
    ) -> DemoExpectation:
        return DemoExpectation(
            label=label,
            alert=alert
            or SecurityAlert(
                alert_id=f"demo-{run_id}-{label}",
                timestamp=now,
                source="suricata",
                severity=severity,
                src_ip=ip_address(src_ip),
                dst_ip=ip_address("10.0.0.10"),
                protocol="TCP",
                signature=signature,
            ),
            expected_action=expected,
            expected_duplicate=duplicate,
            expected_protected=protected,
        )

    return [
        built("low", AlertSeverity.LOW, "198.51.100.11", "Port scan", ResponseAction.LOG),
        built(
            "medium", AlertSeverity.MEDIUM, "198.51.100.12", "Suspicious TLS", ResponseAction.LOG
        ),
        built(
            "high", AlertSeverity.HIGH, "203.0.113.7", "Exploit attempt", ResponseAction.NOTIFY
        ),
        built(
            "critical",
            AlertSeverity.CRITICAL,
            "203.0.113.99",
            "SSH brute force",
            ResponseAction.BLOCK_IP,
            alert=critical,
        ),
        built(
            "duplicate",
            AlertSeverity.CRITICAL,
            "203.0.113.99",
            "SSH brute force",
            ResponseAction.NONE,
            alert=critical,
            duplicate=True,
        ),
        built(
            "protected",
            AlertSeverity.CRITICAL,
            "127.0.0.1",
            "Local admin session",
            ResponseAction.NOTIFY,
            protected=True,
        ),
    ]


def run_demo(
    *,
    service: ResponseService,
    settings: Settings,
    run_id: str | None = None,
) -> DemoReport:
    """Run every Stage 3 decision path plus an in-process webhook round trip."""
    identifier = run_id or uuid4().hex[:8]
    report = DemoReport(run_id=identifier)

    for expectation in build_demo_expectations(run_id=identifier):
        report.steps.append(
            DemoStep(expectation=expectation, outcome=service.handle(expectation.alert))
        )

    report.api_checks = run_api_smoke(
        settings=ensure_webhook_token(settings),
        response_service=service,
        alert_payload=build_shuffle_payload(alert_id=f"demo-{identifier}-webhook"),
    )
    return report
