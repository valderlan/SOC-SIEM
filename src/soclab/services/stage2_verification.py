from __future__ import annotations

import io
import platform
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from soclab.config import Settings, get_settings_optional
from soclab.services.nids import EveValidationSummary, NidsService, NidsStatus
from soclab.services.stage1_verification import (
    CheckResult,
    CheckStatus,
    CommandResult,
    Stage1VerificationService,
    find_project_root,
)


@dataclass
class Stage2VerificationReport:
    checks: dict[str, CheckResult] = field(default_factory=dict)
    quick_mode: bool = False
    demo_mode_requested: bool = False
    effective_demo_mode: bool = False
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


class Stage2VerificationService:
    CommandRunner = Callable[[list[str], Path | None], CommandResult]
    SettingsLoader = Callable[[], Settings]

    def __init__(
        self,
        *,
        console: Console | None = None,
        project_root: Path | None = None,
        command_runner: CommandRunner | None = None,
        settings_loader: SettingsLoader = get_settings_optional,
        nids_service: NidsService | None = None,
    ) -> None:
        self._console = console or Console()
        self._project_root = (project_root or find_project_root()).resolve()
        self._command_runner = command_runner or self._run_command
        self._settings_loader = settings_loader
        self._nids = nids_service or NidsService()

    def verify(
        self,
        *,
        quick: bool = False,
        demo: bool = False,
        verbose: bool = False,
    ) -> Stage2VerificationReport:
        started = time.perf_counter()
        report = Stage2VerificationReport(
            quick_mode=quick,
            demo_mode_requested=demo,
        )

        self._render_header()
        self._render_environment()

        settings = self._settings_loader()
        runtime_path = Path(settings.suricata_eve_path)
        runtime_status = self._nids.status(
            enabled=settings.suricata_enabled,
            eve_path=runtime_path,
        )

        os_name = platform.system().lower()
        fixture_path = self._nids.demo_eve_path(self._project_root)
        runtime_available = (
            runtime_status.enabled
            and runtime_status.file_found
            and runtime_status.readable
        )

        effective_demo_mode = demo or (
            not runtime_available and os_name.startswith("win")
        )
        report.effective_demo_mode = effective_demo_mode

        stage1_results = self._run_stage1_summary(verbose=verbose)
        for result in stage1_results:
            if effective_demo_mode:
                result.required = False
            report.checks[result.key] = result
        self._render_section("Stage 1", stage1_results)

        runtime_check = self._build_runtime_check(
            requested_demo=demo,
            effective_demo_mode=effective_demo_mode,
            status=runtime_status,
        )
        report.checks[runtime_check.key] = runtime_check

        dataset_check = self._build_dataset_check(
            effective_demo_mode=effective_demo_mode,
            fixture_path=fixture_path,
        )
        report.checks[dataset_check.key] = dataset_check

        selected_path = fixture_path if effective_demo_mode else runtime_path
        parsing_check, normalization_check, summary = self._run_eve_checks(
            selected_path
        )
        report.checks[parsing_check.key] = parsing_check
        report.checks[normalization_check.key] = normalization_check

        self._render_section(
            "NIDS",
            [runtime_check, dataset_check, parsing_check, normalization_check],
        )

        events_result = CheckResult(
            key="events_summary",
            name="Events processed",
            status=CheckStatus.PASS,
            message="EVE processing summary",
            details=[
                ("Source file", str(selected_path)),
                ("Total processed", str(summary.total_lines)),
                ("Alert events", str(summary.alert_events)),
                ("Ignored events", str(summary.ignored_events)),
                ("Invalid JSON", str(summary.invalid_json)),
            ],
            required=False,
        )
        report.checks[events_result.key] = events_result
        self._render_section("Events", [events_result])

        integration_checks = self._run_integration_checks(
            effective_demo_mode=effective_demo_mode,
            eve_path=runtime_path,
        )
        for check in integration_checks:
            report.checks[check.key] = check
        self._render_section("Integration", integration_checks)

        quality_checks = self._run_quality_checks(quick=quick, verbose=verbose)
        for check in quality_checks:
            report.checks[check.key] = check
        self._render_section("Quality", quality_checks)

        report.total_duration_seconds = time.perf_counter() - started
        report.status_label = self._resolve_status_label(report)
        self._render_summary(report)
        return report

    def _render_header(self) -> None:
        self._console.rule("[bold]Open SOC Lab - Stage 2 Verification[/bold]")

    def _render_environment(self) -> None:
        self._console.print("Environment")
        self._line_info("Platform", platform.system())
        self._line_info("Python", platform.python_version())
        self._line_info("Project", str(self._project_root))
        self._console.print("")

    def _render_section(self, title: str, results: list[CheckResult]) -> None:
        self._console.print(title)
        for result in results:
            self._line_status(result.name, result.status, result.duration_seconds)
            if result.message:
                self._line_info("Message", result.message)
            for detail_name, detail_value in result.details:
                self._line_info(detail_name, detail_value)
        self._console.print("")

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

    def _run_stage1_summary(self, *, verbose: bool) -> list[CheckResult]:
        silent_console = Console(
            file=io.StringIO(),
            no_color=True,
            force_terminal=False,
        )
        stage1 = Stage1VerificationService(
            console=silent_console,
            project_root=self._project_root,
            command_runner=self._command_runner,
        )
        report = stage1.verify(
            quick=True,
            verbose=verbose,
            send_event=False,
            confirmed_send=False,
            ensure_agent=False,
            agent_manager="127.0.0.1",
            agent_name=None,
        )

        mapped: list[CheckResult] = []
        for key, label in [
            ("wazuh_api", "Wazuh API"),
            ("wazuh_manager", "Wazuh Manager"),
            ("wazuh_indexer", "Wazuh Indexer"),
            ("wazuh_dashboard", "Dashboard"),
        ]:
            original = report.checks.get(key)
            if original is None:
                mapped.append(
                    CheckResult(
                        key=f"stage1_{key}",
                        name=label,
                        status=CheckStatus.SKIP,
                        message="Stage 1 check not available.",
                        required=False,
                    )
                )
                continue

            mapped.append(
                CheckResult(
                    key=f"stage1_{key}",
                    name=label,
                    status=original.status,
                    message=original.message,
                    details=original.details,
                    duration_seconds=original.duration_seconds,
                    required=True,
                )
            )
        return mapped

    def _build_runtime_check(
        self,
        *,
        requested_demo: bool,
        effective_demo_mode: bool,
        status: NidsStatus,
    ) -> CheckResult:
        if requested_demo:
            return CheckResult(
                key="suricata_runtime",
                name="Suricata runtime",
                status=CheckStatus.SKIP,
                message="Skipped because --demo was requested.",
                details=[("Configured EVE path", str(status.eve_path))],
                required=False,
            )

        if effective_demo_mode and not status.file_found:
            return CheckResult(
                key="suricata_runtime",
                name="Suricata runtime",
                status=CheckStatus.WARN,
                message=(
                    "Runtime EVE file not found; using demo dataset for this platform."
                ),
                details=[("Configured EVE path", str(status.eve_path))],
                required=False,
            )

        if status.enabled and status.file_found and status.readable:
            return CheckResult(
                key="suricata_runtime",
                name="Suricata runtime",
                status=CheckStatus.PASS,
                message="Runtime EVE source is available.",
                details=[("Configured EVE path", str(status.eve_path))],
                required=True,
            )

        return CheckResult(
            key="suricata_runtime",
            name="Suricata runtime",
            status=CheckStatus.FAIL,
            message="Runtime EVE source is unavailable.",
            details=[("Configured EVE path", str(status.eve_path))],
            required=True,
        )

    def _build_dataset_check(
        self,
        *,
        effective_demo_mode: bool,
        fixture_path: Path,
    ) -> CheckResult:
        if not effective_demo_mode:
            return CheckResult(
                key="demo_dataset",
                name="Demo dataset",
                status=CheckStatus.SKIP,
                message="Skipped in real runtime mode.",
                required=False,
            )

        if fixture_path.is_file():
            return CheckResult(
                key="demo_dataset",
                name="Demo dataset",
                status=CheckStatus.PASS,
                message="Fixture dataset is available.",
                details=[("Fixture", str(fixture_path))],
                required=True,
            )

        return CheckResult(
            key="demo_dataset",
            name="Demo dataset",
            status=CheckStatus.FAIL,
            message="Fixture dataset not found.",
            details=[("Fixture", str(fixture_path))],
            required=True,
        )

    def _run_eve_checks(
        self, path: Path
    ) -> tuple[CheckResult, CheckResult, EveValidationSummary]:
        started = time.perf_counter()
        try:
            summary = self._nids.validate_eve_file(path)
        except OSError as exc:
            parsing = CheckResult(
                key="eve_parsing",
                name="EVE parsing",
                status=CheckStatus.FAIL,
                message=f"Failed to open EVE file: {exc}",
                duration_seconds=time.perf_counter() - started,
                required=True,
            )
            normalization = CheckResult(
                key="eve_normalization",
                name="EVE normalization",
                status=CheckStatus.SKIP,
                message="Skipped: parsing failed.",
                required=True,
            )
            empty = EveValidationSummary(path=path)
            return parsing, normalization, empty

        parsing_status = (
            CheckStatus.PASS if summary.valid_json > 0 else CheckStatus.FAIL
        )
        parsing = CheckResult(
            key="eve_parsing",
            name="EVE parsing",
            status=parsing_status,
            message=(
                "Parsed EVE JSON lines."
                if parsing_status == CheckStatus.PASS
                else "No valid JSON lines found."
            ),
            details=[
                ("Total lines", str(summary.total_lines)),
                ("Valid JSON", str(summary.valid_json)),
                ("Invalid JSON", str(summary.invalid_json)),
            ],
            duration_seconds=time.perf_counter() - started,
            required=True,
        )

        normalization_status = (
            CheckStatus.PASS if summary.normalized_alerts > 0 else CheckStatus.WARN
        )
        normalization = CheckResult(
            key="eve_normalization",
            name="EVE normalization",
            status=normalization_status,
            message=(
                "Alerts normalized successfully."
                if normalization_status == CheckStatus.PASS
                else "No normalized alerts were generated."
            ),
            details=[
                ("Alert events", str(summary.alert_events)),
                ("Normalized alerts", str(summary.normalized_alerts)),
                ("Ignored events", str(summary.ignored_events)),
            ],
            duration_seconds=time.perf_counter() - started,
            required=True,
        )

        return parsing, normalization, summary

    def _run_integration_checks(
        self,
        *,
        effective_demo_mode: bool,
        eve_path: Path,
    ) -> list[CheckResult]:
        if effective_demo_mode:
            return [
                CheckResult(
                    key="wazuh_agent",
                    name="Wazuh Agent",
                    status=CheckStatus.SKIP,
                    message="Skipped in demo mode.",
                    required=False,
                ),
                CheckResult(
                    key="suricata_wazuh",
                    name="Suricata -> Wazuh",
                    status=CheckStatus.SKIP,
                    message="Skipped in demo mode.",
                    required=False,
                ),
            ]

        integration = self._nids.check_wazuh_integration(eve_path=eve_path)
        if not integration.config_found:
            return [
                CheckResult(
                    key="wazuh_agent",
                    name="Wazuh Agent",
                    status=CheckStatus.WARN,
                    message="Wazuh agent configuration file not found.",
                    required=False,
                ),
                CheckResult(
                    key="suricata_wazuh",
                    name="Suricata -> Wazuh",
                    status=CheckStatus.FAIL,
                    message="Could not validate ossec.conf integration block.",
                    required=True,
                ),
            ]

        agent_status = (
            CheckStatus.PASS if integration.config_found else CheckStatus.WARN
        )
        agent_check = CheckResult(
            key="wazuh_agent",
            name="Wazuh Agent",
            status=agent_status,
            message="Wazuh agent configuration is present.",
            details=[("Config file", str(integration.config_path))],
            required=False,
        )

        configured = (
            integration.eve_configured and integration.json_log_format_configured
        )
        integration_status = CheckStatus.PASS if configured else CheckStatus.WARN
        integration_check = CheckResult(
            key="suricata_wazuh",
            name="Suricata -> Wazuh",
            status=integration_status,
            message=(
                "Suricata EVE JSON is configured in Wazuh agent."
                if configured
                else "Wazuh localfile JSON block for EVE is incomplete."
            ),
            details=[
                (
                    "EVE location block",
                    "present" if integration.eve_configured else "missing",
                ),
                (
                    "JSON log format",
                    "present" if integration.json_log_format_configured else "missing",
                ),
            ],
            required=True,
        )

        return [agent_check, integration_check]

    def _run_quality_checks(self, *, quick: bool, verbose: bool) -> list[CheckResult]:
        if quick:
            return [
                CheckResult(
                    key="pytest",
                    name="Pytest",
                    status=CheckStatus.SKIP,
                    message="Skipped in quick mode.",
                    required=False,
                ),
                CheckResult(
                    key="ruff",
                    name="Ruff",
                    status=CheckStatus.SKIP,
                    message="Skipped in quick mode.",
                    required=False,
                ),
                CheckResult(
                    key="mypy",
                    name="Mypy",
                    status=CheckStatus.SKIP,
                    message="Skipped in quick mode.",
                    required=False,
                ),
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
                verbose=verbose,
                summary_parser=self._parse_pytest_summary,
            ),
            self._run_tool_check(
                key="ruff",
                name="Ruff",
                args=[sys.executable, "-m", "ruff", "check", "."],
                verbose=verbose,
                summary_parser=self._parse_ruff_summary,
            ),
            self._run_tool_check(
                key="mypy",
                name="Mypy",
                args=[sys.executable, "-m", "mypy", "src"],
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
        verbose: bool,
        summary_parser: Callable[[str], str],
    ) -> CheckResult:
        started = time.perf_counter()
        result = self._command_runner(args, self._project_root)
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
            required=True,
        )

    def _resolve_status_label(self, report: Stage2VerificationReport) -> str:
        if report.has_required_failures:
            return "NOT READY"
        if report.effective_demo_mode:
            return "READY FOR DEMO"
        return "READY"

    def _render_summary(self, report: Stage2VerificationReport) -> None:
        self._console.rule("[bold]FINAL RESULT[/bold]")
        label = report.status_label
        if label == "READY":
            color = "green"
        elif label == "READY FOR DEMO":
            color = "yellow"
        else:
            color = "red"
        self._console.print(f"STAGE 2 STATUS: [{color}]{label}[/{color}]")
        self._console.print(f"Total time: {report.total_duration_seconds:.1f} seconds")

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
                returncode=127,
                stdout="",
                stderr=str(exc),
                duration_seconds=duration,
            )

        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_seconds=time.perf_counter() - started,
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
