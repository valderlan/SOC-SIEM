from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr

from soclab.config import Settings
from soclab.exceptions import ConfigurationError
from soclab.services.demo import run_demo
from soclab.services.response import build_response_service
from soclab.services.stage3_verification import Stage3VerificationService


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        webhook_token=SecretStr("verify-token"),
        audit_log_path=tmp_path / "logs" / "audit.jsonl",
        state_db_path=tmp_path / "runtime" / "state.db",
    )


def test_stage3_quick_verification_is_ready(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = Stage3VerificationService(settings_loader=lambda: settings)

    report = service.verify(quick=True, demo=True)

    assert report.has_required_failures is False
    assert report.status_label == "READY (dry-run)"
    assert report.checks["policy"].status.value == "PASS"
    assert report.checks["protection"].status.value == "PASS"
    assert report.checks["dedup"].status.value == "PASS"
    assert report.checks["audit"].status.value == "PASS"
    assert report.checks["dry_run"].status.value == "PASS"
    assert report.checks["api"].status.value == "PASS"
    assert report.checks["demo"].status.value == "PASS"
    # verification may not pollute the real audit log or dedup database
    assert not (tmp_path / "logs" / "audit.jsonl").exists()


def test_stage3_verification_fails_without_configuration() -> None:
    def raise_error() -> Settings:
        raise ConfigurationError("configuration is broken")

    report = Stage3VerificationService(settings_loader=raise_error).verify(quick=True)

    assert report.has_required_failures is True
    assert report.status_label == "NOT READY"
    assert report.checks["configuration"].status.value == "FAIL"
    assert report.checks["api"].status.value == "SKIP"


def test_demo_covers_every_decision_path(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = build_response_service(settings)

    report = run_demo(service=service, settings=settings)

    assert report.passed is True
    assert [step.outcome.action.value for step in report.steps] == [
        "LOG",
        "LOG",
        "NOTIFY",
        "BLOCK_IP",
        "NONE",
        "NOTIFY",
    ]
    assert all(step.outcome.executed is False for step in report.steps)
    assert (tmp_path / "logs" / "audit.jsonl").is_file()
