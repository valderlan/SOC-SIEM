from __future__ import annotations

import io
from pathlib import Path

import pytest
from rich.console import Console

from soclab.config import Settings
from soclab.services.nids import NidsService, WazuhIntegrationStatus
from soclab.services.stage1_verification import (
    CheckResult,
    CheckStatus,
    VerificationReport,
)
from soclab.services.stage2_verification import Stage2VerificationService


def _write_fixture(
    project_root: Path,
    *,
    relative_path: str = "tests/fixtures/suricata/eve.json",
) -> Path:
    fixture = project_root / relative_path
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_text(
        '{"timestamp":"2026-10-08T10:20:11+00:00","event_type":"alert","src_ip":"192.0.2.10","dest_ip":"198.51.100.20","proto":"TCP","alert":{"severity":2,"signature":"demo","signature_id":1}}\n',
        encoding="utf-8",
    )
    return fixture


def _fake_stage1_report(status: CheckStatus) -> VerificationReport:
    report = VerificationReport()
    for key, name in [
        ("wazuh_api", "Wazuh API"),
        ("wazuh_manager", "Wazuh Manager"),
        ("wazuh_indexer", "Wazuh Indexer"),
        ("wazuh_dashboard", "Wazuh Dashboard"),
    ]:
        report.checks[key] = CheckResult(
            key=key,
            name=name,
            status=status,
            required=True,
        )
    return report


def test_stage2_verify_demo_mode_ready_for_demo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    _write_fixture(tmp_path)

    class FakeStage1Service:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        def verify(self, **kwargs: object) -> VerificationReport:
            return _fake_stage1_report(CheckStatus.FAIL)

    monkeypatch.setattr(
        "soclab.services.stage2_verification.Stage1VerificationService",
        FakeStage1Service,
    )

    settings = Settings(
        wazuh_password="secret",
        suricata_enabled=True,
        suricata_eve_path=tmp_path / "missing.json",
    )

    service = Stage2VerificationService(
        console=Console(file=io.StringIO(), no_color=True, force_terminal=False),
        project_root=tmp_path,
        settings_loader=lambda: settings,
    )

    report = service.verify(quick=True, demo=True, verbose=False)

    assert report.status_label == "READY FOR DEMO"
    assert report.checks["demo_dataset"].status == CheckStatus.PASS
    assert report.checks["suricata_runtime"].status == CheckStatus.SKIP


def test_stage2_verify_runtime_missing_fails_on_linux(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")

    class FakeStage1Service:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        def verify(self, **kwargs: object) -> VerificationReport:
            return _fake_stage1_report(CheckStatus.PASS)

    monkeypatch.setattr(
        "soclab.services.stage2_verification.Stage1VerificationService",
        FakeStage1Service,
    )
    monkeypatch.setattr(
        "soclab.services.stage2_verification.platform.system", lambda: "Linux"
    )

    settings = Settings(
        wazuh_password="secret",
        suricata_enabled=True,
        suricata_eve_path=tmp_path / "not-found.json",
    )

    service = Stage2VerificationService(
        console=Console(file=io.StringIO(), no_color=True, force_terminal=False),
        project_root=tmp_path,
        settings_loader=lambda: settings,
    )

    report = service.verify(quick=True, demo=False, verbose=False)

    assert report.status_label == "NOT READY"
    assert report.checks["suricata_runtime"].status == CheckStatus.FAIL


def test_stage2_verify_real_mode_ready_when_runtime_and_integration_ok(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    runtime_file = _write_fixture(tmp_path, relative_path="runtime/eve.json")

    class FakeStage1Service:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        def verify(self, **kwargs: object) -> VerificationReport:
            return _fake_stage1_report(CheckStatus.PASS)

    class ReadyNidsService(NidsService):
        def check_wazuh_integration(
            self,
            *,
            eve_path: Path,
            ossec_conf_path: Path | None = None,
        ) -> WazuhIntegrationStatus:
            return WazuhIntegrationStatus(
                config_path=Path("/var/ossec/etc/ossec.conf"),
                config_found=True,
                eve_configured=True,
                json_log_format_configured=True,
            )

    monkeypatch.setattr(
        "soclab.services.stage2_verification.Stage1VerificationService",
        FakeStage1Service,
    )
    monkeypatch.setattr(
        "soclab.services.stage2_verification.platform.system", lambda: "Linux"
    )

    settings = Settings(
        wazuh_password="secret",
        suricata_enabled=True,
        suricata_eve_path=runtime_file,
    )

    service = Stage2VerificationService(
        console=Console(file=io.StringIO(), no_color=True, force_terminal=False),
        project_root=tmp_path,
        settings_loader=lambda: settings,
        nids_service=ReadyNidsService(),
    )

    report = service.verify(quick=True, demo=False, verbose=False)

    assert report.status_label == "READY"
    assert report.checks["suricata_runtime"].status == CheckStatus.PASS
    assert report.checks["suricata_wazuh"].status == CheckStatus.PASS
