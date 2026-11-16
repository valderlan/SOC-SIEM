"""Idempotent Stage 4 lab provisioning for Wazuh, Shuffle SOAR, and Dashboards."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from soclab.config import Settings
from soclab.exceptions import SocLabError
from soclab.services.stage1_verification import CommandResult, find_project_root

WAZUH_MANAGER_CONTAINER = "single-node-wazuh.manager-1"
SHUFFLE_WORKFLOW_NAME = "SOC Lab - Wazuh Automated Response"
SOCLAB_NETWORK_NAME = "soclab-net"
COMMAND_TIMEOUT_SECONDS = 60

_SHUFFLE_INTEGRATION_RE = re.compile(
    r"\s*<integration>\s*<name>shuffle</name>.*?</integration>",
    flags=re.DOTALL,
)


@dataclass
class ProvisionReport:
    network_connected: bool = False
    rules_updated: bool = False
    integration_updated: bool = False
    wazuh_restarted: bool = False
    shuffle_workflow_id: str = ""
    shuffle_hook_url: str = ""
    dashboard_imported: int = 0
    warnings: list[str] = field(default_factory=list)


def upsert_shuffle_integration(
    ossec_conf: str,
    *,
    hook_url: str,
    level: int = 6,
) -> str:
    """Insert or replace the Shuffle <integration> block in Wazuh ossec.conf."""
    cleaned = _SHUFFLE_INTEGRATION_RE.sub("", ossec_conf)
    block = (
        "\n  <integration>\n"
        "    <name>shuffle</name>\n"
        f"    <hook_url>{hook_url}</hook_url>\n"
        f"    <level>{level}</level>\n"
        "    <alert_format>json</alert_format>\n"
        "  </integration>\n"
    )
    target = "</ossec_config>"
    idx = cleaned.find(target)
    if idx == -1:
        raise SocLabError("Could not find </ossec_config> closing tag in ossec.conf.")
    return cleaned[:idx] + block + cleaned[idx:]


def build_shuffle_workflow_definition(
    *,
    workflow_id: str,
    trigger_id: str,
    apps: dict[str, dict[str, Any]],
    webhook_token: str,
    chat_webhook_url: str = "",
) -> dict[str, Any]:
    """Build the Shuffle workflow payload wired to SOC Lab API, Mailpit, and optional chat."""
    http_app = apps["http"]
    email_app = apps["email"]
    post_action = _find_action(http_app, "POST")
    smtp_action = _find_action(email_app, "send_email_smtp")

    http_node_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{workflow_id}:soclab_decision"))
    email_node_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{workflow_id}:notify_mailpit"))
    chat_node_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{workflow_id}:notify_chat"))

    actions: list[dict[str, Any]] = [
        {
            "id": http_node_id,
            "app_name": "http",
            "app_version": http_app["app_version"],
            "app_id": http_app["id"],
            "name": "POST",
            "label": "soclab_decision",
            "environment": "SOCLab",
            "isStartNode": True,
            "is_valid": True,
            "sharing": True,
            "parameters": _override_parameters(
                post_action["parameters"],
                {
                    "url": "http://soclab:8080/api/v1/alerts",
                    "headers": (
                        "Content-Type: application/json\n"
                        f"X-SOCLAB-TOKEN: {webhook_token}"
                    ),
                    "body": "$exec",
                    "verify": "false",
                },
            ),
            "position": {"x": 320, "y": 220},
        },
        {
            "id": email_node_id,
            "app_name": "email",
            "app_version": email_app["app_version"],
            "app_id": email_app["id"],
            "name": "send_email_smtp",
            "label": "notify_mailpit",
            "environment": "SOCLab",
            "isStartNode": False,
            "is_valid": True,
            "sharing": True,
            "parameters": _override_parameters(
                smtp_action["parameters"],
                {
                    "username": "soclab@soclab.local",
                    "password": "soclab",
                    "smtp_host": "mailpit",
                    "smtp_port": "1025",
                    "recipient": "analysts@soclab.local",
                    "subject": (
                        "[SOC Lab] $soclab_decision.body.severity - "
                        "$soclab_decision.body.action ($soclab_decision.body.target_ip)"
                    ),
                    "body": (
                        "Alert ID: $soclab_decision.body.alert_id\n"
                        "Severity: $soclab_decision.body.severity\n"
                        "Action: $soclab_decision.body.action\n"
                        "Target IP: $soclab_decision.body.target_ip\n"
                        "Executed: $soclab_decision.body.executed\n"
                        "Adapter: $soclab_decision.body.adapter\n"
                        "Evidence: $soclab_decision.body.evidence_path\n"
                        "Reason: $soclab_decision.body.reason"
                    ),
                    "ssl_verify": "false",
                    "body_type": "plain",
                },
            ),
            "position": {"x": 620, "y": 140},
        },
    ]

    branches: list[dict[str, Any]] = [
        {
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{workflow_id}:b_trigger")),
            "source_id": trigger_id,
            "destination_id": http_node_id,
            "conditions": [],
        },
        _action_branch(
            branch_key=f"{workflow_id}:b_email_block",
            source_id=http_node_id,
            destination_id=email_node_id,
            expected_action="BLOCK_IP",
        ),
        _action_branch(
            branch_key=f"{workflow_id}:b_email_notify",
            source_id=http_node_id,
            destination_id=email_node_id,
            expected_action="NOTIFY",
        ),
    ]

    if chat_webhook_url.strip():
        chat_message = (
            "[SOC Lab] $soclab_decision.body.severity | "
            "Action=$soclab_decision.body.action | "
            "IP=$soclab_decision.body.target_ip | "
            "$soclab_decision.body.reason"
        )
        actions.append(
            {
                "id": chat_node_id,
                "app_name": "http",
                "app_version": http_app["app_version"],
                "app_id": http_app["id"],
                "name": "POST",
                "label": "notify_chat",
                "environment": "SOCLab",
                "isStartNode": False,
                "is_valid": True,
                "sharing": True,
                "parameters": _override_parameters(
                    post_action["parameters"],
                    {
                        "url": chat_webhook_url.strip(),
                        "headers": "Content-Type: application/json",
                        "body": f'{{"content": "{chat_message}", "text": "{chat_message}"}}',
                        "verify": "true",
                    },
                ),
                "position": {"x": 620, "y": 320},
            }
        )
        branches.extend(
            [
                _action_branch(
                    branch_key=f"{workflow_id}:b_chat_block",
                    source_id=http_node_id,
                    destination_id=chat_node_id,
                    expected_action="BLOCK_IP",
                ),
                _action_branch(
                    branch_key=f"{workflow_id}:b_chat_notify",
                    source_id=http_node_id,
                    destination_id=chat_node_id,
                    expected_action="NOTIFY",
                ),
            ]
        )

    hook_url = f"http://shuffle-backend:5001/api/v1/hooks/webhook_{trigger_id}"
    return {
        "id": workflow_id,
        "name": SHUFFLE_WORKFLOW_NAME,
        "description": (
            "Receives Wazuh SIEM alerts, invokes SOC Lab SOAR API for policy/blocking, "
            "and notifies analysts via Mailpit SMTP and optional chat webhook."
        ),
        "start": http_node_id,
        "actions": actions,
        "branches": branches,
        "triggers": [
            {
                "id": trigger_id,
                "app_name": "Webhook",
                "name": "Wazuh Alerts Webhook",
                "trigger_type": "WEBHOOK",
                "status": "running",
                "start": http_node_id,
                "parameters": [{"name": "url", "value": hook_url}],
                "position": {"x": 110, "y": 220},
            }
        ],
    }


def _find_action(app: dict[str, Any], action_name: str) -> dict[str, Any]:
    for action in app.get("actions", []):
        if action.get("name") == action_name:
            return dict(action)
    raise SocLabError(f"Shuffle app {app.get('name')} is missing action {action_name}")


def _override_parameters(
    template_params: list[dict[str, Any]],
    overrides: dict[str, str],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for param in template_params:
        copied = dict(param)
        name = str(copied.get("name", ""))
        if name in overrides:
            copied["value"] = overrides[name]
        result.append(copied)
    return result


def _action_branch(
    *,
    branch_key: str,
    source_id: str,
    destination_id: str,
    expected_action: str,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, branch_key)),
        "source_id": source_id,
        "destination_id": destination_id,
        "conditions": [
            {
                "source": {"value": "$soclab_decision.body.action"},
                "condition": {"value": "equals"},
                "destination": {"value": expected_action},
            }
        ],
    }


CommandRunner = Callable[[list[str]], CommandResult]


class LabProvisionService:
    """Connects Docker networks, provisions Shuffle workflow, Wazuh rules, and Dashboards."""

    def __init__(
        self,
        *,
        settings: Settings,
        project_root: Path | None = None,
        command_runner: CommandRunner | None = None,
        shuffle_url: str = "http://127.0.0.1:5001",
        dashboard_url: str = "https://127.0.0.1",
    ) -> None:
        self._settings = settings
        self._root = (project_root or find_project_root()).resolve()
        self._run = command_runner or _default_command_runner
        self._shuffle_url = shuffle_url.rstrip("/")
        self._dashboard_url = dashboard_url.rstrip("/")

    def provision(self) -> ProvisionReport:
        report = ProvisionReport()
        token = self._settings.webhook_token.get_secret_value().strip()
        if not token or token.upper() == "CHANGE_ME":
            raise SocLabError(
                "SOCLAB_WEBHOOK_TOKEN must be configured in .env before provisioning Shuffle."
            )

        report.network_connected = self._connect_wazuh_network()
        workflow_id, hook_url = self._provision_shuffle(token=token)
        report.shuffle_workflow_id = workflow_id
        report.shuffle_hook_url = hook_url

        rules_changed = self._sync_wazuh_rules()
        integration_changed = self._sync_wazuh_integration(hook_url=hook_url)
        report.rules_updated = rules_changed
        report.integration_updated = integration_changed

        if rules_changed or integration_changed:
            self._validate_and_restart_wazuh()
            report.wazuh_restarted = True

        report.dashboard_imported = self._import_dashboard()
        return report

    def _connect_wazuh_network(self) -> bool:
        inspect = self._run(
            [
                "docker",
                "inspect",
                "-f",
                "{{json .NetworkSettings.Networks}}",
                WAZUH_MANAGER_CONTAINER,
            ]
        )
        if inspect.returncode != 0:
            raise SocLabError(
                f"Wazuh manager container '{WAZUH_MANAGER_CONTAINER}' is not running."
            )
        if SOCLAB_NETWORK_NAME in inspect.stdout:
            return True

        connect = self._run(
            [
                "docker",
                "network",
                "connect",
                "--alias",
                "wazuh.manager",
                SOCLAB_NETWORK_NAME,
                WAZUH_MANAGER_CONTAINER,
            ]
        )
        if connect.returncode != 0 and "already exists" not in connect.stderr:
            raise SocLabError(
                f"Failed connecting {WAZUH_MANAGER_CONTAINER} to {SOCLAB_NETWORK_NAME}: "
                f"{connect.stderr.strip()}"
            )
        return True

    def _sync_wazuh_rules(self) -> bool:
        local_rules = self._root / "infra" / "wazuh-custom" / "local_rules.xml"
        if not local_rules.is_file():
            raise SocLabError(f"Custom rules file not found: {local_rules}")

        desired = local_rules.read_text(encoding="utf-8")
        current = self._run(
            [
                "docker",
                "exec",
                WAZUH_MANAGER_CONTAINER,
                "cat",
                "/var/ossec/etc/rules/local_rules.xml",
            ]
        )
        if current.returncode == 0 and current.stdout.strip() == desired.strip():
            return False

        copied = self._run(
            [
                "docker",
                "cp",
                str(local_rules),
                f"{WAZUH_MANAGER_CONTAINER}:/var/ossec/etc/rules/local_rules.xml",
            ]
        )
        if copied.returncode != 0:
            raise SocLabError(f"Failed copying local_rules.xml: {copied.stderr.strip()}")

        chown = self._run(
            [
                "docker",
                "exec",
                WAZUH_MANAGER_CONTAINER,
                "sh",
                "-c",
                "chown root:wazuh /var/ossec/etc/rules/local_rules.xml && "
                "chmod 660 /var/ossec/etc/rules/local_rules.xml",
            ]
        )
        if chown.returncode != 0:
            raise SocLabError(f"Failed setting permissions on local_rules.xml: {chown.stderr}")
        return True

    def _sync_wazuh_integration(self, *, hook_url: str) -> bool:
        read_conf = self._run(
            [
                "docker",
                "exec",
                WAZUH_MANAGER_CONTAINER,
                "cat",
                "/var/ossec/etc/ossec.conf",
            ]
        )
        if read_conf.returncode != 0:
            raise SocLabError(f"Could not read manager ossec.conf: {read_conf.stderr.strip()}")

        updated = upsert_shuffle_integration(read_conf.stdout, hook_url=hook_url, level=6)
        if updated.strip() == read_conf.stdout.strip():
            return False

        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=".conf", delete=False, newline="\n"
        ) as handle:
            handle.write(updated)
            temp_path = Path(handle.name)

        try:
            copied = self._run(
                [
                    "docker",
                    "cp",
                    str(temp_path),
                    f"{WAZUH_MANAGER_CONTAINER}:/var/ossec/etc/ossec.conf",
                ]
            )
            if copied.returncode != 0:
                raise SocLabError(f"Failed updating manager ossec.conf: {copied.stderr.strip()}")
            self._run(
                [
                    "docker",
                    "exec",
                    WAZUH_MANAGER_CONTAINER,
                    "sh",
                    "-c",
                    "chown root:wazuh /var/ossec/etc/ossec.conf && "
                    "chmod 660 /var/ossec/etc/ossec.conf",
                ]
            )
        finally:
            temp_path.unlink(missing_ok=True)
        return True

    def _validate_and_restart_wazuh(self) -> None:
        test_cfg = self._run(
            [
                "docker",
                "exec",
                WAZUH_MANAGER_CONTAINER,
                "/var/ossec/bin/wazuh-analysisd",
                "-t",
            ]
        )
        if test_cfg.returncode != 0:
            raise SocLabError(
                f"Wazuh manager config validation failed: {test_cfg.stderr or test_cfg.stdout}"
            )
        restarted = self._run(
            [
                "docker",
                "exec",
                WAZUH_MANAGER_CONTAINER,
                "/var/ossec/bin/wazuh-control",
                "restart",
            ]
        )
        if restarted.returncode != 0:
            raise SocLabError(
                f"Failed restarting Wazuh manager: {restarted.stderr or restarted.stdout}"
            )

    def _provision_shuffle(self, *, token: str) -> tuple[str, str]:
        username = os.getenv("SHUFFLE_DEFAULT_USERNAME", "admin")
        password = os.getenv("SHUFFLE_DEFAULT_PASSWORD", "soclab-shuffle-admin")
        chat_webhook = self._settings.chat_webhook_url or os.getenv(
            "SOCLAB_CHAT_WEBHOOK_URL", ""
        )

        try:
            with httpx.Client(base_url=self._shuffle_url, timeout=20.0) as client:
                login = client.post(
                    "/api/v1/login",
                    json={"username": username, "password": password},
                )
                if login.is_error:
                    raise SocLabError(
                        f"Shuffle login failed (HTTP {login.status_code}): {login.text[:200]}"
                    )

                apps_resp = client.get("/api/v1/apps")
                apps_resp.raise_for_status()
                apps = {
                    str(app.get("name")): app
                    for app in apps_resp.json()
                    if app.get("name") in {"http", "email"}
                }
                if "http" not in apps or "email" not in apps:
                    raise SocLabError(
                        "Shuffle has not finished loading 'http' and 'email' apps yet; "
                        "wait ~30s and retry."
                    )

                workflows = client.get("/api/v1/workflows").json()
                existing = next(
                    (wf for wf in workflows if wf.get("name") == SHUFFLE_WORKFLOW_NAME),
                    None,
                )

                if existing is not None:
                    workflow_id = str(existing["id"])
                    triggers = existing.get("triggers") or []
                    trigger_id = (
                        str(triggers[0]["id"])
                        if triggers and triggers[0].get("id")
                        else str(uuid.uuid4())
                    )
                else:
                    created = client.post(
                        "/api/v1/workflows",
                        json={"name": SHUFFLE_WORKFLOW_NAME, "description": "SOC Lab SOAR"},
                    )
                    created.raise_for_status()
                    workflow_id = str(created.json()["id"])
                    trigger_id = str(uuid.uuid4())

                definition = build_shuffle_workflow_definition(
                    workflow_id=workflow_id,
                    trigger_id=trigger_id,
                    apps=apps,
                    webhook_token=token,
                    chat_webhook_url=chat_webhook,
                )
                hook_url = str(definition["triggers"][0]["parameters"][0]["value"])
                start_node = str(definition["start"])

                client.post(
                    "/api/v1/hooks/new",
                    json={
                        "id": trigger_id,
                        "type": "webhook",
                        "name": "Wazuh Alerts Webhook",
                        "status": "running",
                        "start": start_node,
                        "workflow": workflow_id,
                    },
                )

                current = client.get(f"/api/v1/workflows/{workflow_id}").json()
                current.update(definition)
                saved = client.put(f"/api/v1/workflows/{workflow_id}", json=current)
                saved.raise_for_status()
                return workflow_id, hook_url
        except httpx.HTTPError as exc:
            raise SocLabError(f"Could not provision Shuffle SOAR: {exc}") from exc

    def _import_dashboard(self) -> int:
        ndjson_path = self._root / "infra" / "wazuh-dashboard" / "soclab-dashboard.ndjson"
        if not ndjson_path.is_file():
            raise SocLabError(f"Dashboard NDJSON not found: {ndjson_path}")

        dashboard_user = os.getenv("SOCLAB_DASHBOARD_USER", "admin")
        dashboard_pass = os.getenv("SOCLAB_DASHBOARD_PASSWORD", "SecretPassword")

        try:
            with ndjson_path.open("rb") as handle:
                response = httpx.post(
                    f"{self._dashboard_url}/api/saved_objects/_import?overwrite=true",
                    auth=(dashboard_user, dashboard_pass),
                    headers={"osd-xsrf": "true"},
                    files={"file": (ndjson_path.name, handle, "application/ndjson")},
                    verify=self._settings.httpx_verify,
                    timeout=20.0,
                )
        except httpx.HTTPError as exc:
            raise SocLabError(f"Could not import Wazuh Dashboard objects: {exc}") from exc

        if response.is_error:
            raise SocLabError(
                f"Wazuh Dashboard import failed (HTTP {response.status_code}): "
                f"{response.text[:300]}"
            )
        payload = response.json()
        return int(payload.get("successCount", 0))


def _default_command_runner(args: list[str]) -> CommandResult:
    completed = subprocess.run(
        args,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_seconds=0.0,
    )
