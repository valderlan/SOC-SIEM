"""Stage 4 end-to-end verification across Wazuh, Suricata, Shuffle, Mailpit, and Dashboards."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from rich.console import Console

from soclab.clients.wazuh import WazuhClient
from soclab.config import Settings, get_settings_optional
from soclab.exceptions import SocLabError
from soclab.services.nids import NidsService
from soclab.services.provision import SHUFFLE_WORKFLOW_NAME, WAZUH_MANAGER_CONTAINER
from soclab.services.stage1_verification import (
    CheckResult,
    CheckStatus,
    CommandResult,
    Stage1VerificationService,
    find_project_root,
)

REQUIRED_SERVICES = (
    "linux-target",
    "soclab",
    "mailpit",
    "shuffle-opensearch",
    "shuffle-backend",
    "shuffle-frontend",
    "shuffle-orborus",
    "kali-attacker",
)


@dataclass
class Stage4VerificationReport:
    checks: dict[str, CheckResult] = field(default_factory=dict)
    quick_mode: bool = False
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


class Stage4VerificationService:
    CommandRunner = Callable[[list[str], Path | None], CommandResult]
    SettingsLoader = Callable[[], Settings]

    def __init__(
        self,
        *,
        console: Console | None = None,
        project_root: Path | None = None,
        command_runner: CommandRunner | None = None,
        settings_loader: SettingsLoader = get_settings_optional,
    ) -> None:
        self._console = console or Console()
        self._project_root = (project_root or find_project_root()).resolve()
        self._settings_loader = settings_loader
        self._stage1 = Stage1VerificationService(
            console=self._console,
            project_root=self._project_root,
            command_runner=command_runner,
            settings_loader=settings_loader,
        )
        self._runner = command_runner or self._stage1._command_runner

    def verify(
        self,
        *,
        quick: bool = False,
        verbose: bool = False,
    ) -> Stage4VerificationReport:
        started = time.perf_counter()
        report = Stage4VerificationReport(quick_mode=quick)
        self._console.rule("[bold]Open SOC Lab - Stage 4 End-to-End Verification[/bold]")

        settings = self._settings_loader()

        containers_check = self._check_compose_containers()
        report.checks[containers_check.key] = containers_check
        self._render_section("[1/6] Checking containerized lab stack", [containers_check])

        wazuh_check, integration_check = self._check_wazuh_and_integration(settings)
        report.checks[wazuh_check.key] = wazuh_check
        report.checks[integration_check.key] = integration_check
        self._render_section(
            "[2/6] Checking Wazuh endpoints & Shuffle integration",
            [wazuh_check, integration_check],
        )

        suricata_check = self._check_live_suricata()
        report.checks[suricata_check.key] = suricata_check
        self._render_section("[3/6] Checking live Suricata NIDS telemetry", [suricata_check])

        soar_checks = self._check_soar_services()
        for check in soar_checks:
            report.checks[check.key] = check
        self._render_section("[4/6] Checking Shuffle, SOC Lab API & Mailpit", soar_checks)

        dashboard_check = self._check_dashboard_saved_objects(settings)
        report.checks[dashboard_check.key] = dashboard_check
        self._render_section("[5/6] Checking Wazuh Dashboard visualizations", [dashboard_check])

        quality_checks = self._stage1._check_quality(verbose=verbose, quick=quick)
        for check in quality_checks:
            report.checks[check.key] = check
        self._render_section("[6/6] Running quality checks", quality_checks)

        report.total_duration_seconds = time.perf_counter() - started
        report.status_label = "NOT READY" if report.has_required_failures else "READY"
        self._render_summary(report)
        return report

    def _check_compose_containers(self) -> CheckResult:
        started = time.perf_counter()
        ps = self._runner(
            ["docker", "compose", "--profile", "full", "ps", "--format", "json"],
            self._project_root,
        )
        if ps.returncode != 0:
            return CheckResult(
                key="compose_stack",
                name="Docker Compose stack",
                status=CheckStatus.FAIL,
                message="Could not inspect compose --profile full containers.",
                duration_seconds=time.perf_counter() - started,
            )

        rows = self._stage1._parse_compose_json(ps.stdout)
        states: dict[str, str] = {}
        for row in rows:
            service = str(row.get("Service") or row.get("service") or "").strip()
            state = str(row.get("State") or row.get("state") or "").strip().lower()
            if service:
                states[service] = state

        missing = [
            svc for svc in REQUIRED_SERVICES if states.get(svc) != "running"
        ]
        if missing:
            return CheckResult(
                key="compose_stack",
                name="Docker Compose stack",
                status=CheckStatus.FAIL,
                message=f"Services not running: {', '.join(missing)}",
                details=[(svc, states.get(svc, "missing")) for svc in REQUIRED_SERVICES],
                duration_seconds=time.perf_counter() - started,
            )

        return CheckResult(
            key="compose_stack",
            name="Docker Compose stack",
            status=CheckStatus.PASS,
            message=f"All {len(REQUIRED_SERVICES)} lab services are running.",
            duration_seconds=time.perf_counter() - started,
        )

    def _check_wazuh_and_integration(self, settings: Settings) -> tuple[CheckResult, CheckResult]:
        started = time.perf_counter()
        try:
            with WazuhClient(settings) as client:
                agents = client.agents()
        except SocLabError as exc:
            return (
                CheckResult(
                    key="wazuh_endpoints",
                    name="Wazuh enrolled endpoints",
                    status=CheckStatus.FAIL,
                    message=str(exc),
                    duration_seconds=time.perf_counter() - started,
                ),
                self._stage1._skipped_result(
                    "wazuh_shuffle_integration",
                    "Wazuh -> Shuffle integration",
                    "Skipped: Wazuh API check failed.",
                ),
            )

        active_real = [a for a in agents if a.id != "000" and a.status.lower() == "active"]
        if not active_real:
            endpoint_check = CheckResult(
                key="wazuh_endpoints",
                name="Wazuh enrolled endpoints",
                status=CheckStatus.WARN,
                message="No active enrolled endpoint beyond manager 000.",
                required=False,
                duration_seconds=time.perf_counter() - started,
            )
        else:
            names = ", ".join(f"{a.name}({a.id})" for a in active_real)
            endpoint_check = CheckResult(
                key="wazuh_endpoints",
                name="Wazuh enrolled endpoints",
                status=CheckStatus.PASS,
                message=f"Active endpoints: {names}",
                duration_seconds=time.perf_counter() - started,
            )

        int_started = time.perf_counter()
        conf = self._runner(
            ["docker", "exec", WAZUH_MANAGER_CONTAINER, "cat", "/var/ossec/etc/ossec.conf"],
            None,
        )
        rules = self._runner(
            [
                "docker",
                "exec",
                WAZUH_MANAGER_CONTAINER,
                "sh",
                "-c",
                "test -f /var/ossec/etc/rules/local_rules.xml && /var/ossec/bin/wazuh-analysisd -t",
            ],
            None,
        )
        has_shuffle = conf.returncode == 0 and "<name>shuffle</name>" in conf.stdout
        has_rules = rules.returncode == 0
        if has_shuffle and has_rules:
            int_check = CheckResult(
                key="wazuh_shuffle_integration",
                name="Wazuh -> Shuffle integration",
                status=CheckStatus.PASS,
                message="local_rules.xml and Shuffle <integration> block are active.",
                duration_seconds=time.perf_counter() - int_started,
            )
        else:
            int_check = CheckResult(
                key="wazuh_shuffle_integration",
                name="Wazuh -> Shuffle integration",
                status=CheckStatus.FAIL,
                message=(
                    "Missing local_rules.xml or <integration><name>shuffle</name>; "
                    "run 'soclab lab provision'."
                ),
                duration_seconds=time.perf_counter() - int_started,
            )
        return endpoint_check, int_check

    def _check_live_suricata(self) -> CheckResult:
        started = time.perf_counter()
        eve_path = self._project_root / "runtime" / "suricata" / "eve.json"
        if not eve_path.is_file():
            return CheckResult(
                key="live_suricata",
                name="Live Suricata EVE log",
                status=CheckStatus.FAIL,
                message=f"Live Suricata file not found at {eve_path}.",
                duration_seconds=time.perf_counter() - started,
            )
        summary = NidsService().validate_eve_file(eve_path)
        if summary.valid_json == 0:
            return CheckResult(
                key="live_suricata",
                name="Live Suricata EVE log",
                status=CheckStatus.WARN,
                message="eve.json exists but has no parsed events yet.",
                required=False,
                duration_seconds=time.perf_counter() - started,
            )
        return CheckResult(
            key="live_suricata",
            name="Live Suricata EVE log",
            status=CheckStatus.PASS,
            message=(
                f"Live EVE OK: lines={summary.total_lines}, "
                f"alerts={summary.normalized_alerts}"
            ),
            duration_seconds=time.perf_counter() - started,
        )

    def _check_soar_services(self) -> list[CheckResult]:
        results: list[CheckResult] = []

        # 1. SOC Lab API /ready
        started = time.perf_counter()
        try:
            ready = httpx.get("http://127.0.0.1:8080/ready", timeout=5.0)
            if ready.status_code == 200:
                body = ready.json()
                results.append(
                    CheckResult(
                        key="soclab_api",
                        name="SOC Lab API (/ready)",
                        status=CheckStatus.PASS,
                        message=(
                            f"ready (adapter={body.get('adapter')}, "
                            f"dry_run={body.get('dry_run')})"
                        ),
                        duration_seconds=time.perf_counter() - started,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        key="soclab_api",
                        name="SOC Lab API (/ready)",
                        status=CheckStatus.FAIL,
                        message=f"HTTP {ready.status_code}: {ready.text[:160]}",
                        duration_seconds=time.perf_counter() - started,
                    )
                )
        except httpx.HTTPError as exc:
            results.append(
                CheckResult(
                    key="soclab_api",
                    name="SOC Lab API (/ready)",
                    status=CheckStatus.FAIL,
                    message=str(exc),
                    duration_seconds=time.perf_counter() - started,
                )
            )

        # 2. Shuffle UI + Workflow
        s_started = time.perf_counter()
        try:
            ui = httpx.get("http://127.0.0.1:3001/", timeout=5.0)
            with httpx.Client(base_url="http://127.0.0.1:5001", timeout=10.0) as client:
                login = client.post(
                    "/api/v1/login",
                    json={
                        "username": os.getenv("SHUFFLE_DEFAULT_USERNAME", "admin"),
                        "password": os.getenv(
                            "SHUFFLE_DEFAULT_PASSWORD", "soclab-shuffle-admin"
                        ),
                    },
                )
                workflows = client.get("/api/v1/workflows").json() if login.is_success else []
                wf_ok = any(wf.get("name") == SHUFFLE_WORKFLOW_NAME for wf in workflows)
            if ui.status_code == 200 and wf_ok:
                results.append(
                    CheckResult(
                        key="shuffle_soar",
                        name="Shuffle UI & Workflow",
                        status=CheckStatus.PASS,
                        message=f"UI 200 and workflow '{SHUFFLE_WORKFLOW_NAME}' active.",
                        duration_seconds=time.perf_counter() - s_started,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        key="shuffle_soar",
                        name="Shuffle UI & Workflow",
                        status=CheckStatus.FAIL,
                        message=f"ui={ui.status_code}, workflow_found={wf_ok}",
                        duration_seconds=time.perf_counter() - s_started,
                    )
                )
        except httpx.HTTPError as exc:
            results.append(
                CheckResult(
                    key="shuffle_soar",
                    name="Shuffle UI & Workflow",
                    status=CheckStatus.FAIL,
                    message=str(exc),
                    duration_seconds=time.perf_counter() - s_started,
                )
            )

        # 3. Mailpit Webmail
        m_started = time.perf_counter()
        try:
            mp = httpx.get("http://127.0.0.1:8025/api/v1/messages", timeout=5.0)
            results.append(
                CheckResult(
                    key="mailpit",
                    name="Mailpit local email UI",
                    status=CheckStatus.PASS if mp.status_code == 200 else CheckStatus.FAIL,
                    message=f"HTTP {mp.status_code} (http://127.0.0.1:8025)",
                    duration_seconds=time.perf_counter() - m_started,
                )
            )
        except httpx.HTTPError as exc:
            results.append(
                CheckResult(
                    key="mailpit",
                    name="Mailpit local email UI",
                    status=CheckStatus.FAIL,
                    message=str(exc),
                    duration_seconds=time.perf_counter() - m_started,
                )
            )

        return results

    def _check_dashboard_saved_objects(self, settings: Settings) -> CheckResult:
        started = time.perf_counter()
        dashboard_user = os.getenv("SOCLAB_DASHBOARD_USER", "admin")
        dashboard_pass = os.getenv("SOCLAB_DASHBOARD_PASSWORD", "SecretPassword")
        try:
            resp = httpx.get(
                "https://127.0.0.1/api/saved_objects/dashboard/dashboard-soclab-overview",
                auth=(dashboard_user, dashboard_pass),
                verify=settings.httpx_verify,
                timeout=10.0,
            )
            if resp.status_code == 200:
                return CheckResult(
                    key="dashboard_overview",
                    name="Wazuh SOC Overview Dashboard",
                    status=CheckStatus.PASS,
                    message="Custom dashboard 'Open SOC Lab - SOC Overview' imported.",
                    duration_seconds=time.perf_counter() - started,
                )
            return CheckResult(
                key="dashboard_overview",
                name="Wazuh SOC Overview Dashboard",
                status=CheckStatus.FAIL,
                message=f"HTTP {resp.status_code}; run 'soclab lab provision'.",
                duration_seconds=time.perf_counter() - started,
            )
        except httpx.HTTPError as exc:
            return CheckResult(
                key="dashboard_overview",
                name="Wazuh SOC Overview Dashboard",
                status=CheckStatus.FAIL,
                message=str(exc),
                duration_seconds=time.perf_counter() - started,
            )

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
                f"  {result.name:.<34} [{style}]{result.status.value}[/{style}] {result.message}"
            )

    def _render_summary(self, report: Stage4VerificationReport) -> None:
        self._console.rule("[bold]FINAL RESULT[/bold]")
        color = "green" if report.status_label == "READY" else "red"
        self._console.print(f"STAGE 4 STATUS: [{color}]{report.status_label}[/{color}]")
        self._console.print(f"Total time: {report.total_duration_seconds:.1f}s")
