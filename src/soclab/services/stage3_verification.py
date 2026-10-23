"""Stage 3 verification: policy, protection, dedup, audit and webhook API."""

from __future__ import annotations

import json
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path

from rich.console import Console

from soclab.adapters.firewall import (
    DryRunFirewallAdapter,
    build_block_command,
    create_firewall_adapter,
)
from soclab.config import Settings, get_settings_optional
from soclab.domain.alert import AlertSeverity, SecurityAlert
from soclab.exceptions import SocLabError
from soclab.services.api_smoke import ApiSmokeCheck, ensure_webhook_token, run_api_smoke
from soclab.services.audit import AuditLogger
from soclab.services.dedup import AlertDeduplicator
from soclab.services.demo import build_shuffle_payload, run_demo
from soclab.services.policy import SEVERITY_ACTIONS, ResponseAction, ResponsePolicy
from soclab.services.response import ResponseService, build_response_service
from soclab.services.stage1_verification import (
    CheckResult,
    CheckStatus,
    CommandResult,
    Stage1VerificationService,
    find_project_root,
)

PUBLIC_TEST_IP = "203.0.113.99"
PROTECTED_TEST_IPS = ("127.0.0.1", "10.1.2.3", "::1")


@dataclass
class Stage3VerificationReport:
    checks: dict[str, CheckResult] = field(default_factory=dict)
    quick_mode: bool = False
    demo_mode: bool = False
    api_checks: list[ApiSmokeCheck] = field(default_factory=list)
    total_duration_seconds: float = 0.0
    status_label: str = "NOT READY"

    @property
    def required_failures(self) -> list[CheckResult]:
        return [
            check
            for check in self.checks.values()
            if check.required and check.status == CheckStatus.FAIL
        ]

    @property
    def has_required_failures(self) -> bool:
        return len(self.required_failures) > 0


class Stage3VerificationService:
    SettingsLoader = Callable[[], Settings]

    def __init__(
        self,
        *,
        console: Console | None = None,
        project_root: Path | None = None,
        command_runner: Callable[[list[str], Path | None], CommandResult] | None = None,
        settings_loader: SettingsLoader = get_settings_optional,
    ) -> None:
        self._console = console or Console()
        self._project_root = (project_root or find_project_root()).resolve()
        self._settings_loader = settings_loader
        # shortcut: pytest/ruff/mypy checks already exist in Stage 1 and are reused.
        self._stage1 = Stage1VerificationService(
            console=self._console,
            project_root=self._project_root,
            command_runner=command_runner,
            settings_loader=settings_loader,
        )

    def verify(
        self,
        *,
        quick: bool = False,
        demo: bool = False,
        verbose: bool = False,
    ) -> Stage3VerificationReport:
        started = time.perf_counter()
        report = Stage3VerificationReport(quick_mode=quick, demo_mode=demo)
        self._render_header()

        settings: Settings | None
        configuration, settings = self._check_configuration()
        report.checks[configuration.key] = configuration
        self._render_section("[1/6] Checking Stage 3 configuration", [configuration])

        with tempfile.TemporaryDirectory(prefix="soclab-stage3-") as tmp:
            scratch = Path(tmp)
            service = (
                build_response_service(self._scoped_settings(settings, scratch))
                if settings is not None
                else None
            )

            policy = self._check_policy(settings)
            report.checks[policy.key] = policy

            protection = self._check_protection(settings)
            report.checks[protection.key] = protection
            self._render_section(
                "[2/6] Checking response policy", [policy, protection]
            )

            dedup = self._check_dedup(scratch)
            report.checks[dedup.key] = dedup

            audit = self._check_audit(scratch)
            report.checks[audit.key] = audit

            dry_run = self._check_dry_run()
            report.checks[dry_run.key] = dry_run
            self._render_section(
                "[3/6] Checking dedup, audit and firewall adapters",
                [dedup, audit, dry_run],
            )

            api = self._check_api(settings, service)
            report.checks[api.key] = api
            self._render_section("[4/6] Checking webhook API (in-process)", [api])

            if demo and settings is not None and service is not None:
                demo_check = self._check_demo(settings, service)
                report.checks[demo_check.key] = demo_check
                self._render_section("[5/6] Running end-to-end demo", [demo_check])
            elif demo:
                skipped_demo = self._stage1._skipped_result(
                    "demo", "End-to-end demo", "Skipped: configuration failed."
                )
                report.checks[skipped_demo.key] = skipped_demo
                self._render_section("[5/6] Running end-to-end demo", [skipped_demo])

        quality = self._stage1._check_quality(verbose=verbose, quick=quick)
        for result in quality:
            report.checks[result.key] = result
        self._render_section("[6/6] Running quality checks", quality)

        report.total_duration_seconds = time.perf_counter() - started
        status = self._stage_status(report)
        report.status_label = (
            "NOT READY" if status == CheckStatus.FAIL else "READY (dry-run)"
        )
        self._render_summary(report)
        return report

    def _scoped_settings(self, settings: Settings, scratch: Path) -> Settings:
        """Verification always uses temporary state and forces dry-run."""
        return settings.model_copy(
            update={
                "audit_log_path": scratch / "logs" / "audit.jsonl",
                "state_db_path": scratch / "runtime" / "soclab_state.db",
                "response_dry_run": True,
            }
        )

    def _check_configuration(self) -> tuple[CheckResult, Settings | None]:
        started = time.perf_counter()
        try:
            settings = self._settings_loader()
        except SocLabError as exc:
            return (
                CheckResult(
                    key="configuration",
                    name="Stage 3 configuration",
                    status=CheckStatus.FAIL,
                    message=str(exc),
                    duration_seconds=time.perf_counter() - started,
                ),
                None,
            )

        details = [
            ("API bind", f"{settings.api_host}:{settings.api_port}"),
            ("Response mode", "dry-run" if settings.response_dry_run else "LIVE"),
            ("Audit log", str(settings.audit_log_path)),
            ("Dedup database", str(settings.state_db_path)),
            ("Protected networks", settings.protected_networks),
        ]

        token_configured = bool(settings.webhook_token.get_secret_value())
        details.append(("Webhook token", "configured" if token_configured else "not configured"))

        if not token_configured:
            status = CheckStatus.WARN
            message = (
                "SOCLAB_WEBHOOK_TOKEN is not set; /api/v1/alerts answers 503 until "
                "it is configured."
            )
        elif not settings.response_dry_run:
            status = CheckStatus.WARN
            message = (
                "Live firewall mode is configured. Verification still runs in dry-run "
                "and never changes the host firewall."
            )
        else:
            status = CheckStatus.PASS
            message = "Stage 3 configuration is valid and running in dry-run mode."

        return (
            CheckResult(
                key="configuration",
                name="Stage 3 configuration",
                status=status,
                message=message,
                details=details,
                duration_seconds=time.perf_counter() - started,
            ),
            settings,
        )

    @staticmethod
    def _policy(settings: Settings | None) -> ResponsePolicy:
        return ResponsePolicy(
            protected_networks=(
                settings.protected_networks
                if settings is not None
                else ResponsePolicy().protected_networks
            )
        )

    def _check_policy(self, settings: Settings | None) -> CheckResult:
        started = time.perf_counter()
        policy = self._policy(settings)
        details: list[tuple[str, str]] = []
        mismatches: list[str] = []

        for severity, expected in SEVERITY_ACTIONS.items():
            decision = policy.evaluate(_alert(severity=severity, src_ip=PUBLIC_TEST_IP))
            details.append((severity.value, f"{decision.action.value} (expected {expected.value})"))
            if decision.action is not expected:
                mismatches.append(f"{severity.value} -> {decision.action.value}")

        return CheckResult(
            key="policy",
            name="Response policy matrix",
            status=CheckStatus.FAIL if mismatches else CheckStatus.PASS,
            message=(
                "Unexpected actions: " + ", ".join(mismatches)
                if mismatches
                else "LOW/MEDIUM -> LOG, HIGH -> NOTIFY, CRITICAL -> BLOCK_IP."
            ),
            details=details,
            duration_seconds=time.perf_counter() - started,
        )

    def _check_protection(self, settings: Settings | None) -> CheckResult:
        started = time.perf_counter()
        policy = self._policy(settings)
        details: list[tuple[str, str]] = []
        failures: list[str] = []

        for address in PROTECTED_TEST_IPS:
            decision = policy.evaluate(
                _alert(severity=AlertSeverity.CRITICAL, src_ip=address)
            )
            details.append((address, f"{decision.action.value} (protected={decision.protected})"))
            if decision.action is ResponseAction.BLOCK_IP or not decision.protected:
                failures.append(address)

        public = policy.evaluate(
            _alert(severity=AlertSeverity.CRITICAL, src_ip=PUBLIC_TEST_IP)
        )
        details.append((PUBLIC_TEST_IP, f"{public.action.value} (public address)"))
        if public.action is not ResponseAction.BLOCK_IP:
            failures.append(PUBLIC_TEST_IP)

        return CheckResult(
            key="protection",
            name="Protected IP guard",
            status=CheckStatus.FAIL if failures else CheckStatus.PASS,
            message=(
                "Wrong decisions for: " + ", ".join(failures)
                if failures
                else "Loopback and administrative ranges are never blocked."
            ),
            details=details,
            duration_seconds=time.perf_counter() - started,
        )

    def _check_dedup(self, scratch: Path) -> CheckResult:
        started = time.perf_counter()
        dedup = AlertDeduplicator(scratch / "dedup" / "state.db")
        first = dedup.is_duplicate("verify-alert-1")
        second = dedup.is_duplicate("verify-alert-1")
        other = dedup.is_duplicate("verify-alert-2")
        passed = not first and second and not other

        return CheckResult(
            key="dedup",
            name="SQLite deduplication",
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            message=(
                "Repeated alert_id values are ignored."
                if passed
                else "Deduplication did not behave as expected."
            ),
            details=[
                ("First delivery", "new" if not first else "duplicate"),
                ("Repeated delivery", "duplicate" if second else "new"),
                ("Other alert_id", "new" if not other else "duplicate"),
            ],
            duration_seconds=time.perf_counter() - started,
        )

    def _check_audit(self, scratch: Path) -> CheckResult:
        started = time.perf_counter()
        path = scratch / "logs" / "audit.jsonl"
        logger = AuditLogger(path)
        logger.record({"alert_id": "verify-audit", "action": "LOG", "reason": "verification"})

        lines: list[str] = []
        if path.is_file():
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
        valid = False
        if len(lines) == 1:
            try:
                valid = json.loads(lines[0]).get("alert_id") == "verify-audit"
            except json.JSONDecodeError:
                valid = False

        return CheckResult(
            key="audit",
            name="JSONL audit trail",
            status=CheckStatus.PASS if valid else CheckStatus.FAIL,
            message=(
                "Decision written to the audit log."
                if valid
                else "Audit log entry missing or invalid."
            ),
            details=[("Audit file", str(path)), ("Lines", str(len(lines)))],
            duration_seconds=time.perf_counter() - started,
        )

    def _check_dry_run(self) -> CheckResult:
        started = time.perf_counter()
        linux = DryRunFirewallAdapter(platform_name="Linux").block_ip(PUBLIC_TEST_IP)
        windows = DryRunFirewallAdapter(platform_name="Windows").block_ip(PUBLIC_TEST_IP)
        default_adapter = create_firewall_adapter(dry_run=True)

        passed = (
            isinstance(default_adapter, DryRunFirewallAdapter)
            and not linux.executed
            and not windows.executed
            and linux.dry_run
            and build_block_command("Linux", PUBLIC_TEST_IP) is not None
            and build_block_command("Windows", PUBLIC_TEST_IP) is not None
        )

        return CheckResult(
            key="dry_run",
            name="Dry-run firewall adapter",
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            message=(
                "Default adapter simulates the block and never touches the firewall."
                if passed
                else "Dry-run adapter did not behave safely."
            ),
            details=[
                ("Linux command", linux.command),
                ("Windows command", windows.command),
                ("Executed", f"linux={linux.executed} windows={windows.executed}"),
            ],
            duration_seconds=time.perf_counter() - started,
        )

    def _check_api(
        self, settings: Settings | None, service: ResponseService | None
    ) -> CheckResult:
        started = time.perf_counter()
        if settings is None or service is None:
            return self._stage1._skipped_result(
                "api", "Webhook API", "Skipped: configuration failed."
            )

        try:
            checks = run_api_smoke(
                settings=ensure_webhook_token(settings),
                response_service=service,
                alert_payload=build_shuffle_payload(alert_id="verify-webhook"),
            )
        except Exception as exc:  # report any API boot failure as FAIL
            return CheckResult(
                key="api",
                name="Webhook API",
                status=CheckStatus.FAIL,
                message=f"API smoke test failed to start: {exc}",
                duration_seconds=time.perf_counter() - started,
            )

        failures = [check for check in checks if not check.passed]
        return CheckResult(
            key="api",
            name="Webhook API",
            status=CheckStatus.FAIL if failures else CheckStatus.PASS,
            message=(
                "; ".join(f"{check.name} ({check.detail})" for check in failures)
                if failures
                else "Token enforcement and alert ingestion behave as expected."
            ),
            details=[(check.name, check.detail) for check in checks],
            duration_seconds=time.perf_counter() - started,
        )

    def _check_demo(self, settings: Settings, service: ResponseService) -> CheckResult:
        started = time.perf_counter()
        try:
            report = run_demo(service=service, settings=settings)
        except Exception as exc:  # demo failures must not traceback
            return CheckResult(
                key="demo",
                name="End-to-end demo",
                status=CheckStatus.FAIL,
                message=f"Demo failed: {exc}",
                duration_seconds=time.perf_counter() - started,
            )

        return CheckResult(
            key="demo",
            name="End-to-end demo",
            status=CheckStatus.PASS if report.passed else CheckStatus.FAIL,
            message=(
                "All demo decisions matched expectations."
                if report.passed
                else "; ".join(report.failures)
            ),
            details=[
                (step.expectation.label, step.outcome.action.value)
                for step in report.steps
            ],
            duration_seconds=time.perf_counter() - started,
        )

    def _stage_status(self, report: Stage3VerificationReport) -> CheckStatus:
        if report.has_required_failures:
            return CheckStatus.FAIL
        warnings = [
            check for check in report.checks.values() if check.status == CheckStatus.WARN
        ]
        return CheckStatus.WARN if warnings else CheckStatus.PASS

    def _render_header(self) -> None:
        self._console.rule("[bold]Open SOC Lab - Stage 3 verification[/bold]")

    def _render_section(self, title: str, results: list[CheckResult]) -> None:
        self._console.print(f"\n[bold]{title}[/bold]")
        for result in results:
            style = {
                CheckStatus.PASS: "green",
                CheckStatus.WARN: "yellow",
                CheckStatus.FAIL: "red",
                CheckStatus.SKIP: "cyan",
            }[result.status]
            self._console.print(
                f"  {result.name:.<30} [{style}]{result.status.value}[/{style}] "
                f"{result.message}"
            )
            for label, value in result.details:
                if label in {"Output", "Detail"}:
                    continue
                self._console.print(f"    {label}: {value}")

    def _render_summary(self, report: Stage3VerificationReport) -> None:
        self._console.rule("[bold]FINAL RESULT[/bold]")
        order = [
            "configuration",
            "policy",
            "protection",
            "dedup",
            "audit",
            "dry_run",
            "api",
            "demo",
            "pytest",
            "ruff",
            "mypy",
        ]
        for key in order:
            check = report.checks.get(key)
            if check is None:
                continue
            style = {
                CheckStatus.PASS: "green",
                CheckStatus.WARN: "yellow",
                CheckStatus.FAIL: "red",
                CheckStatus.SKIP: "cyan",
            }[check.status]
            self._console.print(
                f"{check.name:.<32} [{style}]{check.status.value:.<6}[/{style}] "
                f"{check.duration_seconds:.1f}s"
            )

        warnings = [
            check for check in report.checks.values() if check.status == CheckStatus.WARN
        ]
        failures = [
            check for check in report.checks.values() if check.status == CheckStatus.FAIL
        ]
        self._console.print("")
        self._console.print("Warnings:")
        for check in warnings:
            self._console.print(f"  - {check.name}: {check.message}")
        if not warnings:
            self._console.print("  - none")
        self._console.print("Failures:")
        for check in failures:
            self._console.print(f"  - {check.name}: {check.message}")
        if not failures:
            self._console.print("  - none")

        final = self._stage_status(report)
        color = {
            CheckStatus.PASS: "green",
            CheckStatus.WARN: "yellow",
            CheckStatus.FAIL: "red",
        }[final]
        self._console.print("")
        self._console.print(
            f"Stage 3 ...................... [{color}]{final.value}[/{color}]"
        )
        self._console.print(
            f"Total verification time ...... {report.total_duration_seconds:.1f}s"
        )


def _alert(*, severity: AlertSeverity, src_ip: str) -> SecurityAlert:
    return SecurityAlert(
        alert_id=f"verify-{severity.value.lower()}-{src_ip}",
        timestamp=datetime.now(UTC),
        source="verification",
        severity=severity,
        src_ip=ip_address(src_ip),
    )
