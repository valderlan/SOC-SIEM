from __future__ import annotations

from contextlib import AbstractContextManager

import pytest
from typer.testing import CliRunner

from soclab import cli
from soclab.config import Settings
from soclab.exceptions import ConfigurationError, WazuhRequestError
from soclab.services.stage1_verification import (
    CheckResult,
    CheckStatus,
    VerificationReport,
)

runner = CliRunner()


class FailingClient(AbstractContextManager[object]):
    def __enter__(self) -> object:
        raise WazuhRequestError(
            "Wazuh request failed: GET /: could not connect to Wazuh API. "
            "Check if Wazuh is running and reachable on the configured URL."
        )

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None


def test_config_masks_password(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        wazuh_url="https://127.0.0.1:55000",
        wazuh_username="wazuh-wui",
        wazuh_password="super-secret",
        wazuh_verify_tls=False,
        http_timeout_seconds=10,
        max_agents=500,
    )

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    result = runner.invoke(cli.app, ["config"])

    assert result.exit_code == 0
    assert "Password" in result.stdout
    assert "********" in result.stdout
    assert "super-secret" not in result.stdout


def test_config_reports_missing_password_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_config_error() -> Settings:
        raise ConfigurationError("Wazuh API password is not configured.")

    monkeypatch.setattr(
        cli,
        "get_settings",
        raise_config_error,
    )

    result = runner.invoke(cli.app, ["config"])

    assert result.exit_code == 1
    assert "ERROR:" in result.stdout
    assert "Wazuh API password is not configured." in result.stdout
    assert "Traceback" not in result.stdout


def test_health_reports_unavailable_api_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "_client", lambda: FailingClient())

    result = runner.invoke(cli.app, ["health"])

    assert result.exit_code == 1
    assert "ERROR:" in result.stdout
    assert "could not connect to Wazuh API" in result.stdout
    assert "Traceback" not in result.stdout


def test_stage1_verify_returns_zero_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeService:
        def __init__(self, *, console: object) -> None:
            self.console = console

        def verify(
            self,
            *,
            quick: bool,
            verbose: bool,
            send_event: bool,
            confirmed_send: bool,
            ensure_agent: bool,
            agent_manager: str,
            agent_name: str | None,
        ) -> VerificationReport:
            report = VerificationReport()
            report.checks["configuration"] = CheckResult(
                key="configuration",
                name="Configuration",
                status=CheckStatus.PASS,
                required=True,
            )
            return report

    monkeypatch.setattr(cli, "Stage1VerificationService", FakeService)
    result = runner.invoke(cli.app, ["stage1", "verify", "--quick"])

    assert result.exit_code == 0


def test_stage1_verify_returns_one_on_required_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeService:
        def __init__(self, *, console: object) -> None:
            self.console = console

        def verify(
            self,
            *,
            quick: bool,
            verbose: bool,
            send_event: bool,
            confirmed_send: bool,
            ensure_agent: bool,
            agent_manager: str,
            agent_name: str | None,
        ) -> VerificationReport:
            report = VerificationReport()
            report.checks["docker_engine"] = CheckResult(
                key="docker_engine",
                name="Docker Engine",
                status=CheckStatus.FAIL,
                required=True,
            )
            return report

    monkeypatch.setattr(cli, "Stage1VerificationService", FakeService)
    result = runner.invoke(cli.app, ["stage1", "verify", "--quick"])

    assert result.exit_code == 1
