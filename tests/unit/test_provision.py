from __future__ import annotations

from pathlib import Path

import pytest

from soclab.config import Settings
from soclab.services.provision import (
    LabProvisionService,
    build_shuffle_workflow_definition,
    upsert_shuffle_integration,
)


def test_upsert_shuffle_integration_inserts_and_replaces_idempotently() -> None:
    sample_conf = (
        "<ossec_config>\n"
        "  <global><jsonout_output>yes</jsonout_output></global>\n"
        "</ossec_config>\n"
        "<ossec_config>\n"
        "  <localfile><location>/var/ossec/logs/active-responses.log</location></localfile>\n"
        "</ossec_config>\n"
    )

    first = upsert_shuffle_integration(
        sample_conf, hook_url="http://shuffle-backend:5001/api/v1/hooks/webhook_111", level=6
    )
    assert first.count("<name>shuffle</name>") == 1
    assert "http://shuffle-backend:5001/api/v1/hooks/webhook_111" in first
    assert first.index("<integration>") < first.index("</ossec_config>")

    second = upsert_shuffle_integration(
        first, hook_url="http://shuffle-backend:5001/api/v1/hooks/webhook_222", level=6
    )
    assert second.count("<name>shuffle</name>") == 1
    assert "webhook_111" not in second
    assert "webhook_222" in second


def test_build_shuffle_workflow_definition_includes_mailpit_and_optional_chat() -> None:
    apps = {
        "http": {
            "id": "http-id",
            "app_version": "1.4.0",
            "actions": [
                {
                    "name": "POST",
                    "parameters": [
                        {"name": "url", "value": ""},
                        {"name": "headers", "value": ""},
                        {"name": "body", "value": ""},
                        {"name": "verify", "value": ""},
                    ],
                }
            ],
        },
        "email": {
            "id": "email-id",
            "app_version": "1.3.0",
            "actions": [
                {
                    "name": "send_email_smtp",
                    "parameters": [
                        {"name": "username", "value": ""},
                        {"name": "password", "value": ""},
                        {"name": "smtp_host", "value": ""},
                        {"name": "smtp_port", "value": ""},
                        {"name": "recipient", "value": ""},
                        {"name": "subject", "value": ""},
                        {"name": "body", "value": ""},
                        {"name": "ssl_verify", "value": ""},
                        {"name": "body_type", "value": ""},
                    ],
                }
            ],
        },
    }

    without_chat = build_shuffle_workflow_definition(
        workflow_id="wf-1",
        trigger_id="trig-1",
        apps=apps,
        webhook_token="secret-token",
    )
    assert len(without_chat["actions"]) == 2
    assert len(without_chat["branches"]) == 3
    assert "http://shuffle-backend:5001/api/v1/hooks/webhook_trig-1" in str(
        without_chat["triggers"]
    )

    with_chat = build_shuffle_workflow_definition(
        workflow_id="wf-1",
        trigger_id="trig-1",
        apps=apps,
        webhook_token="secret-token",
        chat_webhook_url="https://discord.example/api/webhooks/123",
    )
    assert len(with_chat["actions"]) == 3
    assert len(with_chat["branches"]) == 5
    assert with_chat["actions"][2]["label"] == "notify_chat"


def test_provision_import_dashboard_respects_tls_setting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ndjson = tmp_path / "infra" / "wazuh-dashboard" / "soclab-dashboard.ndjson"
    ndjson.parent.mkdir(parents=True)
    ndjson.write_text("{}\n", encoding="utf-8")

    captured: list[object] = []

    def fake_post(url: str, **kwargs: object) -> object:
        captured.append(kwargs.get("verify"))
        return type(
            "Resp",
            (),
            {"is_error": False, "status_code": 200, "json": lambda self: {"successCount": 8}},
        )()

    monkeypatch.setattr("soclab.services.provision.httpx.post", fake_post)
    settings = Settings(wazuh_password="secret", wazuh_verify_tls=True)
    service = LabProvisionService(settings=settings, project_root=tmp_path)

    assert service._import_dashboard() == 8
    assert captured == [True]
