"""Cross-platform Stage 1 verification for SOC Lab."""

from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from soclab.clients.wazuh import WazuhClient
from soclab.config import ENV_FILE_PATH, Settings, get_settings
from soclab.exceptions import ConfigurationError, SocLabError
from soclab.models import Agent, RuleMatch
from soclab.services.events import sample_failed_ssh_event


class CheckStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class CheckResult:
    key: str
    name: str
    status: CheckStatus
    message: str = ""
    details: list[tuple[str, str]] = field(default_factory=list)
    duration_seconds: float = 0.0
    required: bool = True


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


@dataclass
class VerificationReport:
    checks: dict[str, CheckResult] = field(default_factory=dict)
    total_duration_seconds: float = 0.0
    quick_mode: bool = False

    @property
    def required_failures(self) -> list[CheckResult]:
        return [
            check
            for check in self.checks.values()
            if check.required and check.status == CheckStatus.FAIL
        ]

    @property
    def warnings(self) -> list[CheckResult]:
        return [
            check for check in self.checks.values() if check.status == CheckStatus.WARN
        ]

    @property
    def failures(self) -> list[CheckResult]:
        return [
            check for check in self.checks.values() if check.status == CheckStatus.FAIL
        ]

    @property
    def has_required_failures(self) -> bool:
        return len(self.required_failures) > 0


CommandRunner = Callable[[list[str], Path | None], CommandResult]
SettingsLoader = Callable[[], Settings]
ClientFactory = Callable[[Settings], WazuhClient]


def find_project_root(start: Path | None = None) -> Path:
    """Find project root by searching for pyproject.toml."""
    origin = start or Path(__file__).resolve()
    for candidate in [origin, *origin.parents]:
        marker = candidate / "pyproject.toml"
        if marker.is_file():
            return candidate
    return Path.cwd().resolve()


class Stage1VerificationService:
    def __init__(
        self,
        *,
        console: Console | None = None,
        project_root: Path | None = None,
        command_runner: CommandRunner | None = None,
        settings_loader: SettingsLoader = get_settings,
        client_factory: ClientFactory = WazuhClient,
    ) -> None:
        self._console = console or Console()
        self._project_root = (project_root or find_project_root()).resolve()
        self._command_runner = command_runner or self._run_command
        self._settings_loader = settings_loader
        self._client_factory = client_factory

    def verify(
        self,
        *,
        quick: bool = False,
        verbose: bool = False,
        send_event: bool = False,
        confirmed_send: bool = False,
        ensure_agent: bool = False,
        agent_manager: str = "127.0.0.1",
        agent_name: str | None = None,
    ) -> VerificationReport:
        started = time.perf_counter()
        report = VerificationReport(quick_mode=quick)

        self._render_header()
        self._render_environment()

        docker_cli = self._check_docker_cli(verbose=verbose)
        report.checks[docker_cli.key] = docker_cli

        docker_engine = self._check_docker_engine(
            verbose=verbose, docker_cli_ok=docker_cli.status == CheckStatus.PASS
        )
        report.checks[docker_engine.key] = docker_engine

        docker_compose = self._check_docker_compose(
            verbose=verbose,
            docker_cli_ok=docker_cli.status == CheckStatus.PASS,
        )
        report.checks[docker_compose.key] = docker_compose
        self._render_section(
            "[1/8] Checking Docker",
            [docker_cli, docker_engine, docker_compose],
        )

        wazuh_infra = self._check_wazuh_infrastructure()
        report.checks[wazuh_infra.key] = wazuh_infra

        container_results = self._check_wazuh_containers(
            verbose=verbose,
            docker_engine_ok=docker_engine.status == CheckStatus.PASS,
            docker_compose_ok=docker_compose.status == CheckStatus.PASS,
            wazuh_infra_ok=wazuh_infra.status == CheckStatus.PASS,
        )
        for result in container_results:
            report.checks[result.key] = result
        self._render_section(
            "[2/8] Checking Wazuh infrastructure and containers",
            [wazuh_infra, *container_results],
        )

        settings_result = self._check_configuration()
        report.checks[settings_result.key] = settings_result
        self._render_section("[3/8] Checking SOC Lab configuration", [settings_result])

        api_result: CheckResult
        agents_result: CheckResult
        logtest_result: CheckResult
        event_result: CheckResult

        if settings_result.status != CheckStatus.PASS:
            api_result = self._skipped_result(
                "wazuh_api", "Wazuh API", "Skipped: configuration failed."
            )
            agents_result = self._skipped_result(
                "agents", "Agents", "Skipped: Wazuh API check failed."
            )
            logtest_result = self._skipped_result(
                "logtest", "Wazuh Logtest", "Skipped: Wazuh API check failed."
            )
            event_result = self._skipped_result(
                "real_event",
                "Real event test",
                "Skipped: Wazuh API check failed.",
                required=False,
            )
        else:
            settings = self._settings_loader()
            api_result, agents_result, logtest_result, event_result = (
                self._check_wazuh_runtime(
                    settings=settings,
                    verbose=verbose,
                    send_event=send_event,
                    confirmed_send=confirmed_send,
                    ensure_agent=ensure_agent,
                    agent_manager=agent_manager,
                    agent_name=agent_name,
                )
            )

        report.checks[api_result.key] = api_result
        report.checks[agents_result.key] = agents_result
        report.checks[logtest_result.key] = logtest_result
        report.checks[event_result.key] = event_result
        self._render_section("[4/8] Checking Wazuh API", [api_result])
        self._render_section("[5/8] Checking Wazuh agents", [agents_result])
        self._render_section("[6/8] Testing Wazuh rules", [logtest_result])
        self._render_section("[7/8] Optional real event", [event_result])

        quality_results = self._check_quality(verbose=verbose, quick=quick)
        for result in quality_results:
            report.checks[result.key] = result
        self._render_section("[8/8] Running quality checks", quality_results)

        report.total_duration_seconds = time.perf_counter() - started
        self._render_summary(report)
        return report

    def _render_header(self) -> None:
        self._console.rule("[bold]Open SOC Lab - Stage 1 Verification[/bold]")

    def _render_section(self, title: str, results: list[CheckResult]) -> None:
        self._console.print(title)
        for result in results:
            self._line_status(result.name, result.status, result.duration_seconds)
            if result.message:
                self._line_info("Message", result.message)
            for detail_name, detail_value in result.details:
                self._line_info(detail_name, detail_value)
        self._console.print("")

    def _render_environment(self) -> None:
        self._console.print("Platform:")
        self._line_info("OS", platform.system())
        self._line_info("Python", platform.python_version())
        self._line_info("Project", str(self._project_root))
        self._console.print("")

    def _check_docker_cli(self, *, verbose: bool) -> CheckResult:
        started = time.perf_counter()
        result = self._command_runner(["docker", "--version"], None)
        if result.returncode == 0:
            return CheckResult(
                key="docker_cli",
                name="Docker CLI",
                status=CheckStatus.PASS,
                message="Docker CLI available.",
                duration_seconds=time.perf_counter() - started,
            )

        message = "Docker CLI is not installed or not available in PATH."
        details = self._command_details(result, verbose=verbose)
        return CheckResult(
            key="docker_cli",
            name="Docker CLI",
            status=CheckStatus.FAIL,
            message=message,
            details=details,
            duration_seconds=time.perf_counter() - started,
        )

    def _check_docker_engine(
        self, *, verbose: bool, docker_cli_ok: bool
    ) -> CheckResult:
        if not docker_cli_ok:
            return self._skipped_result(
                "docker_engine", "Docker Engine", "Skipped: Docker CLI failed."
            )

        started = time.perf_counter()
        result = self._command_runner(["docker", "version"], None)
        if result.returncode == 0:
            return CheckResult(
                key="docker_engine",
                name="Docker Engine",
                status=CheckStatus.PASS,
                message="Docker engine is running.",
                duration_seconds=time.perf_counter() - started,
            )

        guidance = (
            "Docker is installed, but the Docker engine is not running. Start Docker Desktop."
            if platform.system().lower().startswith("win")
            else (
                "Docker is installed, but the Docker engine is not running. "
                "Check the Docker service."
            )
        )
        return CheckResult(
            key="docker_engine",
            name="Docker Engine",
            status=CheckStatus.FAIL,
            message=guidance,
            details=self._command_details(result, verbose=verbose),
            duration_seconds=time.perf_counter() - started,
        )

    def _check_docker_compose(
        self, *, verbose: bool, docker_cli_ok: bool
    ) -> CheckResult:
        if not docker_cli_ok:
            return self._skipped_result(
                "docker_compose", "Docker Compose", "Skipped: Docker CLI failed."
            )

        started = time.perf_counter()
        result = self._command_runner(["docker", "compose", "version"], None)
        if result.returncode == 0:
            return CheckResult(
                key="docker_compose",
                name="Docker Compose",
                status=CheckStatus.PASS,
                message="Docker Compose available.",
                duration_seconds=time.perf_counter() - started,
            )

        return CheckResult(
            key="docker_compose",
            name="Docker Compose",
            status=CheckStatus.FAIL,
            message="Docker Compose is unavailable.",
            details=self._command_details(result, verbose=verbose),
            duration_seconds=time.perf_counter() - started,
        )

    def _check_wazuh_infrastructure(self) -> CheckResult:
        started = time.perf_counter()
        single_node = self._project_root / "infra" / "wazuh-docker" / "single-node"
        compose_files = [
            single_node / "docker-compose.yml",
            single_node / "compose.yml",
            single_node / "compose.yaml",
        ]

        if not single_node.is_dir() or not any(
            path.is_file() for path in compose_files
        ):
            details = [
                ("Windows", ".\\scripts\\bootstrap_wazuh.ps1"),
                ("Linux", "Use the documented Wazuh bootstrap/install procedure."),
            ]
            return CheckResult(
                key="wazuh_infra",
                name="Wazuh infrastructure",
                status=CheckStatus.FAIL,
                message=f"Wazuh infrastructure not found in {single_node}",
                details=details,
                duration_seconds=time.perf_counter() - started,
            )

        return CheckResult(
            key="wazuh_infra",
            name="Wazuh infrastructure",
            status=CheckStatus.PASS,
            message=str(single_node),
            duration_seconds=time.perf_counter() - started,
        )

    def _check_wazuh_containers(
        self,
        *,
        verbose: bool,
        docker_engine_ok: bool,
        docker_compose_ok: bool,
        wazuh_infra_ok: bool,
    ) -> list[CheckResult]:
        if not (docker_engine_ok and docker_compose_ok and wazuh_infra_ok):
            return [
                self._skipped_result(
                    "wazuh_manager",
                    "Wazuh Manager",
                    "Skipped: Docker/infra requirements failed.",
                ),
                self._skipped_result(
                    "wazuh_indexer",
                    "Wazuh Indexer",
                    "Skipped: Docker/infra requirements failed.",
                ),
                self._skipped_result(
                    "wazuh_dashboard",
                    "Wazuh Dashboard",
                    "Skipped: Docker/infra requirements failed.",
                ),
            ]

        compose_dir = self._project_root / "infra" / "wazuh-docker" / "single-node"
        ps_json = self._command_runner(
            ["docker", "compose", "ps", "--format", "json"], compose_dir
        )
        services: dict[str, str] = {}
        status_by_service: dict[str, str] = {}

        if ps_json.returncode == 0:
            parsed = self._parse_compose_json(ps_json.stdout)
            for row in parsed:
                service_name = str(
                    row.get("Service") or row.get("service") or ""
                ).strip()
                if not service_name:
                    continue
                status_value = str(
                    row.get("State")
                    or row.get("state")
                    or row.get("Status")
                    or row.get("status")
                    or ""
                ).strip()
                services[service_name] = service_name
                status_by_service[service_name] = status_value

        if not services:
            ps_table = self._command_runner(["docker", "compose", "ps"], compose_dir)
            if ps_table.returncode != 0:
                fail_details = self._command_details(ps_table, verbose=verbose)
                return [
                    CheckResult(
                        key="wazuh_manager",
                        name="Wazuh Manager",
                        status=CheckStatus.FAIL,
                        message="Could not inspect Wazuh containers.",
                        details=fail_details,
                        required=True,
                    ),
                    self._skipped_result(
                        "wazuh_indexer",
                        "Wazuh Indexer",
                        "Skipped: compose status unavailable.",
                    ),
                    self._skipped_result(
                        "wazuh_dashboard",
                        "Wazuh Dashboard",
                        "Skipped: compose status unavailable.",
                    ),
                ]
            text = ps_table.stdout.lower()
            for service in ("wazuh.manager", "wazuh.indexer", "wazuh.dashboard"):
                if service in text:
                    status_by_service[service] = "up" if "up" in text else "unknown"

        return [
            self._classify_container(
                "wazuh_manager", "Wazuh Manager", status_by_service.get("wazuh.manager")
            ),
            self._classify_container(
                "wazuh_indexer", "Wazuh Indexer", status_by_service.get("wazuh.indexer")
            ),
            self._classify_container(
                "wazuh_dashboard",
                "Wazuh Dashboard",
                status_by_service.get("wazuh.dashboard"),
            ),
        ]

    def _classify_container(
        self, key: str, name: str, state: str | None
    ) -> CheckResult:
        state_value = (state or "not found").strip().lower()
        if state is None:
            return CheckResult(
                key=key,
                name=name,
                status=CheckStatus.FAIL,
                message="Container not found.",
            )

        if any(flag in state_value for flag in ("running", "healthy", "up")):
            return CheckResult(
                key=key, name=name, status=CheckStatus.PASS, message=state
            )
        if any(flag in state_value for flag in ("starting", "created", "initial")):
            return CheckResult(
                key=key, name=name, status=CheckStatus.WARN, message=state
            )
        if any(flag in state_value for flag in ("exited", "dead", "restarting")):
            return CheckResult(
                key=key, name=name, status=CheckStatus.FAIL, message=state
            )
        return CheckResult(key=key, name=name, status=CheckStatus.WARN, message=state)

    def _check_configuration(self) -> CheckResult:
        started = time.perf_counter()
        try:
            settings = self._settings_loader()
        except ConfigurationError as exc:
            return CheckResult(
                key="configuration",
                name="Configuration",
                status=CheckStatus.FAIL,
                message=str(exc),
                details=[("Env file", str(ENV_FILE_PATH.resolve()))],
                duration_seconds=time.perf_counter() - started,
            )

        password_value = settings.wazuh_password.get_secret_value().strip()
        password_configured = bool(
            password_value and password_value.upper() != "CHANGE_ME"
        )
        status = CheckStatus.PASS if password_configured else CheckStatus.FAIL
        message = (
            "Configuration loaded."
            if password_configured
            else "Wazuh API password is missing."
        )

        tls_label = "enabled" if settings.wazuh_verify_tls else "disabled"
        details = [
            ("Wazuh URL", str(settings.wazuh_url)),
            ("Wazuh user", settings.wazuh_username),
            ("TLS verification", tls_label),
            ("HTTP timeout", f"{settings.http_timeout_seconds:g}s"),
            ("Max agents", str(settings.max_agents)),
            ("Password", "configured" if password_configured else "missing"),
        ]

        if not password_configured:
            details.append(("Env file", str(ENV_FILE_PATH.resolve())))

        return CheckResult(
            key="configuration",
            name="Configuration",
            status=status,
            message=message,
            details=details,
            duration_seconds=time.perf_counter() - started,
        )

    def _check_wazuh_runtime(
        self,
        *,
        settings: Settings,
        verbose: bool,
        send_event: bool,
        confirmed_send: bool,
        ensure_agent: bool,
        agent_manager: str,
        agent_name: str | None,
    ) -> tuple[CheckResult, CheckResult, CheckResult, CheckResult]:
        api_started = time.perf_counter()
        try:
            with self._client_factory(settings) as client:
                info = client.api_info()
                agents = client.agents()
                if ensure_agent and not self._has_real_agents(agents):
                    install_result = self._try_install_local_agent(
                        manager_host=agent_manager,
                        agent_name=agent_name,
                        verbose=verbose,
                    )
                    if install_result.status == CheckStatus.PASS:
                        time.sleep(3)
                        agents = client.agents()
                logtest = client.logtest(sample_failed_ssh_event())
                event_result = self._run_optional_event_send(
                    client=client,
                    send_event=send_event,
                    confirmed_send=confirmed_send,
                )
        except SocLabError as exc:
            api_result = CheckResult(
                key="wazuh_api",
                name="Wazuh API",
                status=CheckStatus.FAIL,
                message=str(exc),
                duration_seconds=time.perf_counter() - api_started,
            )
            agents_result = self._skipped_result(
                "agents", "Agents", "Skipped: Wazuh API failed."
            )
            if ensure_agent:
                agents_result.details.append(
                    ("Agent auto-install", "Skipped: Wazuh API failed.")
                )
            logtest_result = self._skipped_result(
                "logtest", "Wazuh Logtest", "Skipped: Wazuh API failed."
            )
            event_result = self._skipped_result(
                "real_event",
                "Real event test",
                "Skipped: Wazuh API failed.",
                required=False,
            )
            return api_result, agents_result, logtest_result, event_result

        api_data = info.get("data", {}) if isinstance(info.get("data"), dict) else {}
        version = (
            str(api_data.get("api_version")) if api_data.get("api_version") else "-"
        )
        manager = str(api_data.get("hostname")) if api_data.get("hostname") else "-"

        api_result = CheckResult(
            key="wazuh_api",
            name="Wazuh API",
            status=CheckStatus.PASS,
            message="Wazuh authentication and API checks passed.",
            details=[
                ("Authentication", "PASS"),
                ("Wazuh API", "PASS"),
                ("API version", version),
                ("Manager", manager),
            ],
            duration_seconds=time.perf_counter() - api_started,
        )

        agents_result = self._classify_agents(agents)
        if ensure_agent:
            install_status = "installed/checked"
            if not self._has_real_agents(agents):
                install_status = "attempted but no real endpoint detected yet"
            agents_result.details.append(("Agent auto-install", install_status))
        logtest_result = self._classify_logtest(logtest)
        return api_result, agents_result, logtest_result, event_result

    def _has_real_agents(self, agents: list[Agent]) -> bool:
        return any(agent.id != "000" for agent in agents)

    def _try_install_local_agent(
        self,
        *,
        manager_host: str,
        agent_name: str | None,
        verbose: bool,
    ) -> CheckResult:
        started = time.perf_counter()
        os_name = platform.system().lower()

        if os_name.startswith("win"):
            script = (
                self._project_root / "scripts" / "windows" / "install_wazuh_agent.ps1"
            )
            args = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-Manager",
                manager_host,
            ]
            if agent_name:
                args.extend(["-AgentName", agent_name])
        elif os_name in {"linux", "linux2"}:
            script = (
                self._project_root
                / "scripts"
                / "linux"
                / "install_wazuh_agent_debian.sh"
            )
            args = ["sudo", "bash", str(script), manager_host]
            if agent_name:
                args.append(agent_name)
        else:
            return CheckResult(
                key="agent_install",
                name="Agent auto-install",
                status=CheckStatus.WARN,
                message=f"Unsupported platform for auto-install: {platform.system()}",
                duration_seconds=time.perf_counter() - started,
                required=False,
            )

        if not script.is_file():
            return CheckResult(
                key="agent_install",
                name="Agent auto-install",
                status=CheckStatus.WARN,
                message=f"Agent installer script not found: {script}",
                duration_seconds=time.perf_counter() - started,
                required=False,
            )

        result = self._command_runner(args, self._project_root)
        details = self._command_details(result, verbose=verbose)
        if result.returncode == 0:
            return CheckResult(
                key="agent_install",
                name="Agent auto-install",
                status=CheckStatus.PASS,
                message="Local agent installation completed.",
                details=details,
                duration_seconds=time.perf_counter() - started,
                required=False,
            )

        return CheckResult(
            key="agent_install",
            name="Agent auto-install",
            status=CheckStatus.WARN,
            message="Automatic local agent installation failed.",
            details=details,
            duration_seconds=time.perf_counter() - started,
            required=False,
        )

    def _classify_agents(self, agents: list[Agent]) -> CheckResult:
        started = time.perf_counter()
        real_agents = [agent for agent in agents if agent.id != "000"]
        statuses = [agent.status.lower() for agent in real_agents]
        active = sum(status == "active" for status in statuses)
        disconnected = sum(status == "disconnected" for status in statuses)
        never_connected = sum(status == "never connected" for status in statuses)

        if len(real_agents) == 0:
            status = CheckStatus.WARN
            message = (
                "No real endpoints enrolled. "
                "Only the internal manager agent (000) may be present."
            )
        elif active == 0:
            status = CheckStatus.FAIL
            message = "Agents are registered, but none are active."
        elif active < len(real_agents):
            status = CheckStatus.WARN
            message = "Some agents are not active."
        else:
            status = CheckStatus.PASS
            message = "All enrolled agents are active."

        details = [
            ("Registered", str(len(real_agents))),
            (
                "Internal manager agent",
                (
                    "present"
                    if any(agent.id == "000" for agent in agents)
                    else "not present"
                ),
            ),
            ("Active", str(active)),
            ("Disconnected", str(disconnected)),
            ("Never connected", str(never_connected)),
            (
                "Agent OS",
                ", ".join(
                    sorted(
                        {
                            agent.os_label
                            for agent in real_agents
                            if agent.os_label != "-"
                        }
                    )
                )
                or "-",
            ),
        ]

        return CheckResult(
            key="agents",
            name="Agents",
            status=status,
            message=message,
            details=details,
            duration_seconds=time.perf_counter() - started,
            required=False,
        )

    def _classify_logtest(self, match: RuleMatch) -> CheckResult:
        started = time.perf_counter()
        if match.matched:
            status = CheckStatus.PASS
            message = "Wazuh rule matched the test event."
        elif match.decoder:
            status = CheckStatus.WARN
            message = "Event decoded but no rule match was reported."
        else:
            status = CheckStatus.FAIL
            message = "Wazuh logtest did not decode or match the event."

        details = [
            ("Wazuh Logtest", status.value),
            ("Decoder", match.decoder or "-"),
            ("Rule match", "PASS" if match.matched else "FAIL"),
            ("Rule ID", match.rule_id or "-"),
            ("Level", str(match.level) if match.level is not None else "-"),
        ]

        return CheckResult(
            key="logtest",
            name="Wazuh Logtest",
            status=status,
            message=message,
            details=details,
            duration_seconds=time.perf_counter() - started,
        )

    def _run_optional_event_send(
        self,
        *,
        client: WazuhClient,
        send_event: bool,
        confirmed_send: bool,
    ) -> CheckResult:
        if not send_event:
            return self._skipped_result(
                "real_event",
                "Real event test",
                "Skipped: use --send-event to enable this optional check.",
                required=False,
            )
        if not confirmed_send:
            return self._skipped_result(
                "real_event",
                "Real event test",
                "Skipped: user did not confirm event sending.",
                required=False,
            )

        started = time.perf_counter()
        response = client.send_event(sample_failed_ssh_event())
        affected_data = (
            response.get("data", {}) if isinstance(response.get("data"), dict) else {}
        )
        affected = str(affected_data.get("total_affected_items", "-"))

        return CheckResult(
            key="real_event",
            name="Real event test",
            status=CheckStatus.PASS,
            message="Demonstration event sent successfully.",
            details=[("Affected items", affected)],
            duration_seconds=time.perf_counter() - started,
            required=False,
        )

    def _check_quality(self, *, verbose: bool, quick: bool) -> list[CheckResult]:
        if quick:
            return [
                self._skipped_result("pytest", "Pytest", "Skipped in quick mode."),
                self._skipped_result("ruff", "Ruff", "Skipped in quick mode."),
                self._skipped_result("mypy", "Mypy", "Skipped in quick mode."),
            ]

        return [
            self._run_tool_check(
                key="pytest",
                name="Pytest",
                args=[
                    sys.executable,
                    "-m",
                    "pytest",
                    "--basetemp",
                    str(self._project_root / ".pytest_tmp"),
                ],
                cwd=self._project_root,
                verbose=verbose,
                summary_parser=self._parse_pytest_summary,
            ),
            self._run_tool_check(
                key="ruff",
                name="Ruff",
                args=[sys.executable, "-m", "ruff", "check", "."],
                cwd=self._project_root,
                verbose=verbose,
                summary_parser=self._parse_ruff_summary,
            ),
            self._run_tool_check(
                key="mypy",
                name="Mypy",
                args=[sys.executable, "-m", "mypy", "src"],
                cwd=self._project_root,
                verbose=verbose,
                summary_parser=self._parse_mypy_summary,
            ),
        ]

    def _run_tool_check(
        self,
        *,
        key: str,
        name: str,
        args: list[str],
        cwd: Path,
        verbose: bool,
        summary_parser: Callable[[str], str],
    ) -> CheckResult:
        started = time.perf_counter()
        result = self._command_runner(args, cwd)

        output = "\n".join(
            part for part in (result.stdout, result.stderr) if part
        ).strip()
        summary = summary_parser(output)
        details = self._command_details(result, verbose=verbose)

        if summary:
            details.insert(0, ("Summary", summary))

        status = CheckStatus.PASS if result.returncode == 0 else CheckStatus.FAIL
        message = "Check passed." if status == CheckStatus.PASS else "Check failed."
        return CheckResult(
            key=key,
            name=name,
            status=status,
            message=message,
            details=details,
            duration_seconds=time.perf_counter() - started,
        )

    def _render_summary(self, report: VerificationReport) -> None:
        self._console.rule("[bold]FINAL RESULT[/bold]")
        summary_order = [
            "docker_cli",
            "docker_engine",
            "docker_compose",
            "wazuh_manager",
            "wazuh_indexer",
            "wazuh_dashboard",
            "configuration",
            "wazuh_api",
            "agents",
            "logtest",
            "real_event",
            "pytest",
            "ruff",
            "mypy",
        ]

        for key in summary_order:
            check = report.checks.get(key)
            if check is None:
                continue
            self._line_status(check.name, check.status, check.duration_seconds)

        self._console.print("")

        warnings = report.warnings
        failures = report.failures

        if warnings:
            self._console.print("Warnings:")
            for item in warnings:
                self._console.print(f"  - {item.name}: {item.message}")
        else:
            self._console.print("Warnings:\n  - none")

        if failures:
            self._console.print("Failures:")
            for item in failures:
                self._console.print(f"  - {item.name}: {item.message}")
        else:
            self._console.print("Failures:\n  - none")

        self._console.print("")
        self._render_demo_readiness(report)

        stage_status = self._stage_status(report)
        status_text = self._style_status(stage_status)
        self._console.print(f"\nStage 1 ...................... {status_text}")
        self._console.print(
            f"Total verification time ...... {report.total_duration_seconds:.1f}s"
        )

    def _render_demo_readiness(self, report: VerificationReport) -> None:
        self._console.print("Demo readiness:")
        dashboard = report.checks.get("wazuh_dashboard")
        api = report.checks.get("wazuh_api")
        agents = report.checks.get("agents")
        logtest = report.checks.get("logtest")
        real_event = report.checks.get("real_event")

        self._line_info("Wazuh Dashboard", self._ready_label(dashboard))
        self._line_info("Wazuh API", self._ready_label(api))
        self._line_info("Active endpoint", self._ready_label(agents))
        self._line_info("Wazuh rule test", self._ready_label(logtest))
        self._line_info(
            "Real event demo",
            (
                "OPTIONAL"
                if real_event is None or real_event.status == CheckStatus.SKIP
                else self._ready_label(real_event)
            ),
        )

    def _stage_status(self, report: VerificationReport) -> CheckStatus:
        if report.has_required_failures:
            return CheckStatus.FAIL
        if report.quick_mode:
            return CheckStatus.WARN

        required_for_ready = [
            "docker_engine",
            "wazuh_manager",
            "wazuh_indexer",
            "wazuh_dashboard",
            "configuration",
            "wazuh_api",
            "logtest",
            "pytest",
            "ruff",
            "mypy",
        ]

        if all(
            (check := report.checks.get(key)) is not None
            and check.status == CheckStatus.PASS
            for key in required_for_ready
        ):
            return CheckStatus.PASS
        return CheckStatus.WARN

    def _ready_label(self, check: CheckResult | None) -> str:
        if check is None:
            return "NOT READY"
        return "READY" if check.status == CheckStatus.PASS else "NOT READY"

    def _line_status(
        self, label: str, status: CheckStatus, duration_seconds: float
    ) -> None:
        self._console.print(
            f"{label:.<30} {self._style_status(status):<12} {duration_seconds:.1f}s"
        )

    def _line_info(self, label: str, value: str) -> None:
        self._console.print(f"  {label:.<28} {value}")

    def _style_status(self, status: CheckStatus) -> str:
        color = {
            CheckStatus.PASS: "green",
            CheckStatus.WARN: "yellow",
            CheckStatus.FAIL: "red",
            CheckStatus.SKIP: "cyan",
        }[status]
        return f"[{color}]{status.value}[/{color}]"

    def _skipped_result(
        self, key: str, name: str, message: str, *, required: bool = True
    ) -> CheckResult:
        return CheckResult(
            key=key,
            name=name,
            status=CheckStatus.SKIP,
            message=message,
            required=required,
        )

    def _run_command(self, args: list[str], cwd: Path | None) -> CommandResult:
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                args,
                cwd=str(cwd) if cwd is not None else None,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            duration = time.perf_counter() - started
            return CommandResult(
                returncode=127, stdout="", stderr=str(exc), duration_seconds=duration
            )

        duration = time.perf_counter() - started
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_seconds=duration,
        )

    def _command_details(
        self, result: CommandResult, *, verbose: bool
    ) -> list[tuple[str, str]]:
        output = "\n".join(
            part for part in (result.stdout, result.stderr) if part
        ).strip()
        if not output:
            return []

        if verbose:
            return [("Output", output)]

        lines = output.splitlines()
        excerpt = "\n".join(lines[:8])
        if len(lines) > 8:
            excerpt += "\n..."
        return [("Output", excerpt)]

    def _parse_compose_json(self, payload: str) -> list[dict[str, Any]]:
        text = payload.strip()
        if not text:
            return []

        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass

        rows: list[dict[str, Any]] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                parsed_line = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed_line, dict):
                rows.append(parsed_line)
        return rows

    def _parse_pytest_summary(self, output: str) -> str:
        if not output:
            return ""
        match = re.search(r"(\d+\s+passed(?:,\s+\d+\s+warnings?)?)", output)
        if match:
            return match.group(1)
        match = re.search(r"(\d+\s+failed.*)", output)
        if match:
            return match.group(1)
        return ""

    def _parse_ruff_summary(self, output: str) -> str:
        if not output:
            return ""
        if "All checks passed" in output:
            return "All checks passed"
        match = re.search(r"Found\s+(\d+)\s+error", output)
        if match:
            return f"{match.group(1)} violations"
        return ""

    def _parse_mypy_summary(self, output: str) -> str:
        if not output:
            return ""
        for line in output.splitlines():
            if line.startswith("Success:") or line.startswith("Found "):
                return line.strip()
        return ""

    def _check_wazuh_runtime_summary_table(self, agents: list[Agent]) -> Table:
        table = Table(title="Wazuh agents", show_header=True)
        table.add_column("ID")
        table.add_column("NAME")
        table.add_column("OS")
        table.add_column("STATUS")
        for agent in agents:
            table.add_row(agent.id, agent.name, agent.os_label, agent.status)
        return table
