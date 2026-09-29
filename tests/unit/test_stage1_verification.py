from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest
from rich.console import Console

from soclab.config import Settings
from soclab.exceptions import ConfigurationError, WazuhRequestError
from soclab.models import Agent, RuleMatch
from soclab.services.stage1_verification import (
    CheckStatus,
    CommandResult,
    Stage1VerificationService,
)


def _project_layout(root: Path) -> None:
    (root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    single_node = root / "infra" / "wazuh-docker" / "single-node"
    single_node.mkdir(parents=True, exist_ok=True)
    (single_node / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")


class DummyClient:
    def __init__(
        self,
        *,
        info: dict[str, object] | None = None,
        agents: list[Agent] | None = None,
        match: RuleMatch | None = None,
        fail_on_api: Exception | None = None,
    ) -> None:
        self._info = info or {
            "data": {"api_version": "4.14.8", "hostname": "wazuh.manager"}
        }
        self._agents = agents if agents is not None else []
        self._match = match or RuleMatch(
            matched=True, decoder="sshd", rule_id="5710", level=5
        )
        self._fail_on_api = fail_on_api
        self.sent_events = 0

    def __enter__(self) -> DummyClient:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def api_info(self) -> dict[str, object]:
        if self._fail_on_api is not None:
            raise self._fail_on_api
        return self._info

    def agents(self) -> list[Agent]:
        return self._agents

    def logtest(self, event: str) -> RuleMatch:
        return self._match

    def send_event(self, event: str) -> dict[str, object]:
        self.sent_events += 1
        return {"data": {"total_affected_items": 1}, "error": 0}


def _console() -> Console:
    return Console(file=io.StringIO(), no_color=True, force_terminal=False)


def _settings() -> Settings:
    return Settings(
        wazuh_url="https://127.0.0.1:55000",
        wazuh_username="wazuh-wui",
        wazuh_password="secret",
        wazuh_verify_tls=False,
        max_agents=500,
    )


def _runner_for_success() -> callable:
    def run(args: list[str], cwd: Path | None) -> CommandResult:
        command = tuple(args)
        if command == ("docker", "--version"):
            return CommandResult(0, "Docker version 29.0", "", 0.01)
        if command == ("docker", "version"):
            return CommandResult(0, "Client/Server", "", 0.02)
        if command == ("docker", "compose", "version"):
            return CommandResult(0, "Docker Compose v2", "", 0.01)
        if command == ("docker", "compose", "ps", "--format", "json"):
            payload = """
            [
              {"Service": "wazuh.manager", "State": "running"},
              {"Service": "wazuh.indexer", "State": "running"},
              {"Service": "wazuh.dashboard", "State": "running"}
            ]
            """
            return CommandResult(0, payload, "", 0.03)
        if (
            len(command) == 5
            and command[0:3] == (sys.executable, "-m", "pytest")
            and command[3] == "--basetemp"
        ):
            return CommandResult(0, "13 passed in 0.25s", "", 0.2)
        if command == (sys.executable, "-m", "ruff", "check", "."):
            return CommandResult(0, "All checks passed!", "", 0.1)
        if command == (sys.executable, "-m", "mypy", "src"):
            return CommandResult(
                0, "Success: no issues found in 10 source files", "", 0.2
            )
        return CommandResult(1, "", f"unexpected command: {args}", 0.01)

    return run


def test_verify_pass_full(tmp_path: Path) -> None:
    _project_layout(tmp_path)
    client = DummyClient(
        agents=[
            Agent(id="001", name="linux", status="active", os={"name": "Ubuntu"}),
            Agent(id="002", name="win", status="active", os={"name": "Windows"}),
        ]
    )

    service = Stage1VerificationService(
        console=_console(),
        project_root=tmp_path,
        command_runner=_runner_for_success(),
        settings_loader=_settings,
        client_factory=lambda settings: client,
    )

    report = service.verify(quick=False, verbose=False)

    assert report.has_required_failures is False
    assert report.checks["wazuh_api"].status == CheckStatus.PASS
    assert report.checks["logtest"].status == CheckStatus.PASS
    assert report.checks["pytest"].status == CheckStatus.PASS


def test_verify_warn_zero_agents(tmp_path: Path) -> None:
    _project_layout(tmp_path)
    client = DummyClient(agents=[])

    service = Stage1VerificationService(
        console=_console(),
        project_root=tmp_path,
        command_runner=_runner_for_success(),
        settings_loader=_settings,
        client_factory=lambda settings: client,
    )

    report = service.verify(quick=True)

    assert report.checks["agents"].status == CheckStatus.WARN
    assert report.has_required_failures is False


def test_verify_warn_when_only_internal_manager_agent_exists(tmp_path: Path) -> None:
    _project_layout(tmp_path)
    client = DummyClient(
        agents=[
            Agent(
                id="000",
                name="wazuh.manager",
                status="active",
                os={"name": "Amazon Linux"},
            )
        ]
    )

    service = Stage1VerificationService(
        console=_console(),
        project_root=tmp_path,
        command_runner=_runner_for_success(),
        settings_loader=_settings,
        client_factory=lambda settings: client,
    )

    report = service.verify(quick=True)

    assert report.checks["agents"].status == CheckStatus.WARN
    assert report.checks["agents"].details[0] == ("Registered", "0")


def test_verify_docker_unavailable_skips_containers(tmp_path: Path) -> None:
    _project_layout(tmp_path)

    def runner(args: list[str], cwd: Path | None) -> CommandResult:
        command = tuple(args)
        if command == ("docker", "--version"):
            return CommandResult(1, "", "docker not found", 0.01)
        return CommandResult(0, "", "", 0.01)

    service = Stage1VerificationService(
        console=_console(),
        project_root=tmp_path,
        command_runner=runner,
        settings_loader=_settings,
        client_factory=lambda settings: DummyClient(),
    )

    report = service.verify(quick=True)

    assert report.checks["docker_cli"].status == CheckStatus.FAIL
    assert report.checks["docker_engine"].status == CheckStatus.SKIP
    assert report.checks["wazuh_manager"].status == CheckStatus.SKIP


def test_verify_configuration_failure_skips_api(tmp_path: Path) -> None:
    _project_layout(tmp_path)

    def bad_settings() -> Settings:
        raise ConfigurationError("Wazuh API password is not configured.")

    service = Stage1VerificationService(
        console=_console(),
        project_root=tmp_path,
        command_runner=_runner_for_success(),
        settings_loader=bad_settings,
        client_factory=lambda settings: DummyClient(),
    )

    report = service.verify(quick=True)

    assert report.checks["configuration"].status == CheckStatus.FAIL
    assert report.checks["wazuh_api"].status == CheckStatus.SKIP
    assert report.checks["logtest"].status == CheckStatus.SKIP


def test_verify_api_failure_marks_fail_and_skips_dependents(tmp_path: Path) -> None:
    _project_layout(tmp_path)
    client = DummyClient(
        fail_on_api=WazuhRequestError("could not connect to Wazuh API")
    )

    service = Stage1VerificationService(
        console=_console(),
        project_root=tmp_path,
        command_runner=_runner_for_success(),
        settings_loader=_settings,
        client_factory=lambda settings: client,
    )

    report = service.verify(quick=True)

    assert report.checks["wazuh_api"].status == CheckStatus.FAIL
    assert report.checks["agents"].status == CheckStatus.SKIP
    assert report.checks["logtest"].status == CheckStatus.SKIP


def test_quick_mode_skips_quality_checks(tmp_path: Path) -> None:
    _project_layout(tmp_path)
    client = DummyClient(agents=[Agent(id="001", name="linux", status="active")])

    service = Stage1VerificationService(
        console=_console(),
        project_root=tmp_path,
        command_runner=_runner_for_success(),
        settings_loader=_settings,
        client_factory=lambda settings: client,
    )

    report = service.verify(quick=True)

    assert report.checks["pytest"].status == CheckStatus.SKIP
    assert report.checks["ruff"].status == CheckStatus.SKIP
    assert report.checks["mypy"].status == CheckStatus.SKIP


def test_does_not_send_event_by_default(tmp_path: Path) -> None:
    _project_layout(tmp_path)
    client = DummyClient(agents=[Agent(id="001", name="linux", status="active")])

    service = Stage1VerificationService(
        console=_console(),
        project_root=tmp_path,
        command_runner=_runner_for_success(),
        settings_loader=_settings,
        client_factory=lambda settings: client,
    )

    report = service.verify(quick=True, send_event=False)

    assert report.checks["real_event"].status == CheckStatus.SKIP
    assert client.sent_events == 0


def test_send_event_with_confirmation_runs_once(tmp_path: Path) -> None:
    _project_layout(tmp_path)
    client = DummyClient(agents=[Agent(id="001", name="linux", status="active")])

    service = Stage1VerificationService(
        console=_console(),
        project_root=tmp_path,
        command_runner=_runner_for_success(),
        settings_loader=_settings,
        client_factory=lambda settings: client,
    )

    report = service.verify(quick=True, send_event=True, confirmed_send=True)

    assert report.checks["real_event"].status == CheckStatus.PASS
    assert client.sent_events == 1


def test_ensure_agent_attempt_marks_warning_when_no_real_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project_layout(tmp_path)
    client = DummyClient(
        agents=[Agent(id="000", name="wazuh.manager", status="active")]
    )
    monkeypatch.setattr(
        "soclab.services.stage1_verification.platform.system", lambda: "Windows"
    )

    service = Stage1VerificationService(
        console=_console(),
        project_root=tmp_path,
        command_runner=_runner_for_success(),
        settings_loader=_settings,
        client_factory=lambda settings: client,
    )

    report = service.verify(quick=True, ensure_agent=True, agent_manager="127.0.0.1")

    assert report.checks["agents"].status == CheckStatus.WARN
    assert (
        "Agent auto-install",
        "attempted but no real endpoint detected yet",
    ) in report.checks["agents"].details
