from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console

from soclab.config import Settings
from soclab.services.stage1_verification import CheckStatus, CommandResult
from soclab.services.stage4_verification import Stage4VerificationService


def test_stage4_verification_fails_when_containers_missing(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")

    def fake_runner(args: list[str], _cwd: Path | None) -> CommandResult:
        return CommandResult(
            returncode=1, stdout="", stderr="docker unavailable", duration_seconds=0.0
        )

    service = Stage4VerificationService(
        console=Console(file=io.StringIO(), no_color=True, force_terminal=False),
        project_root=tmp_path,
        command_runner=fake_runner,
        settings_loader=lambda: Settings(wazuh_password="secret"),
    )

    report = service.verify(quick=True)

    assert report.has_required_failures is True
    assert report.status_label == "NOT READY"
    assert report.checks["compose_stack"].status == CheckStatus.FAIL
