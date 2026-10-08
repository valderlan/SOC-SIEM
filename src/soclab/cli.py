import json
import platform
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from soclab import __version__
from soclab.clients.wazuh import WazuhClient
from soclab.config import Settings, get_settings, get_settings_optional
from soclab.domain.alert import AlertSeverity, SecurityAlert
from soclab.exceptions import SocLabError
from soclab.services.events import sample_failed_ssh_event
from soclab.services.health import build_health_report
from soclab.services.nids import AlertFilters, NidsService, format_size, parse_ip_filter
from soclab.services.stage1_verification import Stage1VerificationService
from soclab.services.stage2_verification import Stage2VerificationService

app = typer.Typer(
    name="soclab",
    help="Open SOC Lab - Stage 1: Wazuh HIDS/SIEM demonstrator.",
    no_args_is_help=True,
)
event_app = typer.Typer(help="Validate or inject controlled demo events.")
app.add_typer(event_app, name="event")
stage1_app = typer.Typer(help="Run Stage 1 verification checks.")
app.add_typer(stage1_app, name="stage1")
nids_app = typer.Typer(help="Run Stage 2 NIDS checks and Suricata utilities.")
app.add_typer(nids_app, name="nids")
stage2_app = typer.Typer(help="Run Stage 2 verification checks.")
app.add_typer(stage2_app, name="stage2")
console = Console()


def _client() -> WazuhClient:
    return WazuhClient(get_settings())


def _fail(exc: Exception) -> None:
    console.print(f"[bold red]ERROR:[/bold red] {exc}")
    raise typer.Exit(code=1) from exc


def _nids_service() -> NidsService:
    return NidsService()


def _nids_settings() -> Settings:
    return get_settings_optional()


def _parse_severity_filter(value: str | None) -> AlertSeverity | None:
    if value is None:
        return None
    normalized = value.strip().upper()
    try:
        return AlertSeverity(normalized)
    except ValueError as exc:
        raise typer.BadParameter(
            "Severity must be one of: low, medium, high, critical."
        ) from exc


def _render_alerts_table(*, alerts: list[SecurityAlert], title: str) -> None:
    table = Table(title=title)
    table.add_column("TIME")
    table.add_column("SEVERITY")
    table.add_column("SRC")
    table.add_column("DST")
    table.add_column("PROTO")
    table.add_column("SIGNATURE")

    for alert in alerts:
        timestamp = alert.timestamp.astimezone().strftime("%H:%M:%S")
        table.add_row(
            timestamp,
            alert.severity.value,
            str(alert.src_ip) if alert.src_ip is not None else "-",
            str(alert.dst_ip) if alert.dst_ip is not None else "-",
            alert.protocol or "-",
            (alert.signature or "-")[:70],
        )

    console.print(table)


@app.command()
def version() -> None:
    """Show application version."""
    console.print(__version__)


@app.command()
def config() -> None:
    """Show non-secret effective configuration."""
    try:
        settings = get_settings()
    except SocLabError as exc:
        _fail(exc)
        return

    table = Table(title="SOC Lab configuration")
    table.add_column("Setting")
    table.add_column("Value")
    table.add_row("Wazuh URL", str(settings.wazuh_url))
    table.add_row("Wazuh user", settings.wazuh_username)
    table.add_row("TLS verification", str(settings.wazuh_verify_tls))
    table.add_row("CA bundle", str(settings.wazuh_ca_bundle or "-"))
    table.add_row("HTTP timeout", f"{settings.http_timeout_seconds:g}s")
    table.add_row("Max agents", str(settings.max_agents))
    table.add_row("Suricata enabled", str(settings.suricata_enabled))
    table.add_row("Suricata EVE path", str(settings.suricata_eve_path))
    table.add_row("Suricata interface", settings.suricata_interface or "-")
    table.add_row("Password", "********")
    console.print(table)


@app.command()
def health() -> None:
    """Check Wazuh API connectivity and summarize enrolled agent state."""
    try:
        with _client() as client:
            report = build_health_report(client)
    except SocLabError as exc:
        _fail(exc)
        return

    table = Table(title="Open SOC Lab - Stage 1 health")
    table.add_column("Check")
    table.add_column("Result")
    table.add_row("Wazuh API", "[green]OK[/green]")
    table.add_row("API version", report.api_version or "-")
    table.add_row("Manager", report.manager_hostname or "-")
    table.add_row("Agents", str(report.total_agents))
    table.add_row("Active", f"[green]{report.active_agents}[/green]")
    table.add_row("Disconnected", f"[yellow]{report.disconnected_agents}[/yellow]")
    table.add_row("Never connected", f"[red]{report.never_connected_agents}[/red]")
    console.print(table)


@app.command()
def agents(
    status: Annotated[
        str | None,
        typer.Option(help="Optional local filter, e.g. active or disconnected."),
    ] = None,
) -> None:
    """List Wazuh agents, including Linux and Windows endpoints."""
    try:
        with _client() as client:
            items = client.agents()
    except SocLabError as exc:
        _fail(exc)
        return

    if status:
        items = [agent for agent in items if agent.status.lower() == status.lower()]

    table = Table(title="Wazuh agents")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("IP")
    table.add_column("OS")
    table.add_column("Status")
    table.add_column("Agent version")

    for agent in items:
        normalized = agent.status.lower()
        style = "green" if normalized == "active" else "yellow"
        if normalized in {"never connected", "disconnected"}:
            style = "red"
        table.add_row(
            agent.id,
            agent.name,
            agent.ip or "-",
            agent.os_label,
            f"[{style}]{agent.status}[/{style}]",
            agent.version or "-",
        )

    console.print(table)
    console.print(f"Total shown: {len(items)}")


@event_app.command("test")
def test_event(
    message: Annotated[
        str | None,
        typer.Option(
            "--message", "-m", help="Custom syslog event. Uses SSH sample if omitted."
        ),
    ] = None,
) -> None:
    """Run an event through Wazuh logtest without creating a live alert."""
    event = message or sample_failed_ssh_event()
    try:
        with _client() as client:
            match = client.logtest(event)
    except SocLabError as exc:
        _fail(exc)
        return

    console.print("[bold]Event[/bold]")
    console.print(event)
    if not match.matched:
        console.print("\n[yellow]No Wazuh rule matched this event.[/yellow]")
        raise typer.Exit(code=2)

    table = Table(title="Wazuh logtest result")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Matched", "[green]yes[/green]")
    table.add_row("Rule ID", match.rule_id or "-")
    table.add_row("Level", str(match.level) if match.level is not None else "-")
    table.add_row("Description", match.description or "-")
    table.add_row("Decoder", match.decoder or "-")
    console.print(table)


@event_app.command("send")
def send_event(
    message: Annotated[
        str | None,
        typer.Option(
            "--message", "-m", help="Custom event. Uses SSH sample if omitted."
        ),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip the confirmation prompt."),
    ] = False,
) -> None:

    event = message or sample_failed_ssh_event()
    console.print("Event to send:")
    console.print(event)
    if not yes and not typer.confirm("Send this event to the Wazuh analysis engine?"):
        raise typer.Abort()

    try:
        with _client() as client:
            result = client.send_event(event)
    except SocLabError as exc:
        _fail(exc)
        return

    console.print("[green]Event accepted by Wazuh.[/green]")
    console.print_json(json.dumps(result, default=str))


@nids_app.command("status")
def nids_status() -> None:

    try:
        settings = _nids_settings()
    except SocLabError as exc:
        _fail(exc)
        return

    service = _nids_service()
    status = service.status(
        enabled=settings.suricata_enabled,
        eve_path=Path(settings.suricata_eve_path),
    )

    table = Table(title="Open SOC Lab - NIDS Status")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Suricata enabled", "YES" if status.enabled else "NO")
    table.add_row("EVE path", str(status.eve_path))
    table.add_row("EVE file", "FOUND" if status.file_found else "NOT FOUND")
    table.add_row("File size", format_size(status.size_bytes))
    table.add_row(
        "Last modification",
        (
            status.last_modification.strftime("%Y-%m-%d %H:%M:%S")
            if status.last_modification is not None
            else "-"
        ),
    )
    table.add_row("Readable", "YES" if status.readable else "NO")
    console.print(table)


@nids_app.command("validate")
def nids_validate(
    file: Annotated[
        Path,
        typer.Argument(help="Path to a Suricata EVE JSON file."),
    ],
) -> None:
    """Validate a Suricata EVE JSON file with tolerant parsing stats."""
    service = _nids_service()

    try:
        summary = service.validate_eve_file(file)
    except OSError as exc:
        _fail(exc)
        return

    table = Table(title="Suricata EVE validation")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("File", str(summary.path))
    table.add_row("Total lines", str(summary.total_lines))
    table.add_row("Valid JSON", str(summary.valid_json))
    table.add_row("Invalid JSON", str(summary.invalid_json))
    table.add_row("Alert events", str(summary.alert_events))
    table.add_row("Ignored events", str(summary.ignored_events))
    table.add_row("Normalized alerts", str(summary.normalized_alerts))
    console.print(table)

    passed = summary.validation_passed
    status = "PASS" if passed else "FAIL"
    color = "green" if passed else "red"
    console.print(f"Validation result ............ [{color}]{status}[/{color}]")
    raise typer.Exit(code=0 if passed else 1)


@nids_app.command("alerts")
def nids_alerts(
    limit: Annotated[
        int | None,
        typer.Option("--limit", help="Maximum alerts to show (latest N)."),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity", help="Filter by severity: low, medium, high, critical."
        ),
    ] = None,
    src_ip: Annotated[
        str | None,
        typer.Option("--src-ip", help="Filter by source IP."),
    ] = None,
    dst_ip: Annotated[
        str | None,
        typer.Option("--dst-ip", help="Filter by destination IP."),
    ] = None,
    follow: Annotated[
        bool,
        typer.Option("--follow", help="Follow EVE file updates in near real-time."),
    ] = False,
) -> None:

    try:
        settings = _nids_settings()
    except SocLabError as exc:
        _fail(exc)
        return

    service = _nids_service()
    eve_path = Path(settings.suricata_eve_path)
    if not eve_path.is_file() and platform.system().lower().startswith("win"):
        fixture = service.demo_eve_path(Path(__file__).resolve().parents[2])
        if fixture.is_file():
            console.print(
                "[yellow]Runtime EVE file not found on Windows. Using demo fixture.[/yellow]"
            )
            eve_path = fixture

    if not eve_path.is_file():
        console.print(f"[bold red]ERROR:[/bold red] EVE file not found: {eve_path}")
        raise typer.Exit(code=1)

    try:
        filters = AlertFilters(
            limit=limit,
            severity=_parse_severity_filter(severity),
            src_ip=parse_ip_filter(src_ip),
            dst_ip=parse_ip_filter(dst_ip),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if follow:
        console.print(f"Following alerts from: {eve_path}")
        console.print("Press Ctrl+C to stop.")
        try:
            for alert in service.follow_alerts(
                eve_path,
                filters=filters,
                start_at_end=True,
            ):
                console.print(
                    " | ".join(
                        [
                            alert.timestamp.astimezone().strftime("%H:%M:%S"),
                            alert.severity.value,
                            str(alert.src_ip) if alert.src_ip is not None else "-",
                            str(alert.dst_ip) if alert.dst_ip is not None else "-",
                            alert.protocol or "-",
                            (alert.signature or "-")[:70],
                        ]
                    )
                )
        except KeyboardInterrupt:
            console.print("[yellow]Follow stopped by user.[/yellow]")
        return

    alerts = service.list_alerts(eve_path, filters=filters)
    if not alerts:
        console.print("No alerts matched the selected filters.")
        return

    _render_alerts_table(alerts=alerts, title="Open SOC Lab - NIDS Alerts")
    console.print(f"Total shown: {len(alerts)}")


@nids_app.command("demo")
def nids_demo() -> None:
    """Run a complete Stage 2 demo using the local fixture dataset."""
    service = _nids_service()
    fixture = service.demo_eve_path(Path(__file__).resolve().parents[2])

    try:
        summary = service.validate_eve_file(fixture, collect_alerts=True)
    except OSError as exc:
        _fail(exc)
        return

    console.print("[bold]Open SOC Lab - Stage 2 Demo[/bold]")
    console.print(f"Loaded events ................. {summary.total_lines}")
    console.print(f"Alerts detected ............... {summary.normalized_alerts}")
    console.print(f"Ignored events ................ {summary.ignored_events}")
    console.print(f"Invalid lines ................. {summary.invalid_json}")

    if summary.alerts:
        _render_alerts_table(alerts=summary.alerts, title="Normalized alerts")

    passed = summary.validation_passed and summary.normalized_alerts > 0
    status = "PASS" if passed else "FAIL"
    color = "green" if passed else "red"
    console.print(f"Demo result ................... [{color}]{status}[/{color}]")
    raise typer.Exit(code=0 if passed else 1)


@nids_app.command("wazuh-status")
def nids_wazuh_status(
    ossec_conf: Annotated[
        Path | None,
        typer.Option("--ossec-conf", help="Optional explicit path to ossec.conf."),
    ] = None,
) -> None:

    try:
        settings = _nids_settings()
    except SocLabError as exc:
        _fail(exc)
        return

    service = _nids_service()
    integration = service.check_wazuh_integration(
        eve_path=Path(settings.suricata_eve_path),
        ossec_conf_path=ossec_conf,
    )

    api_ok = False
    api_message = "Unavailable"
    try:
        with WazuhClient(settings) as client:
            client.api_info()
        api_ok = True
        api_message = "PASS"
    except SocLabError as exc:
        api_message = f"WARN ({exc})"

    table = Table(title="Open SOC Lab - NIDS Wazuh integration")
    table.add_column("Check")
    table.add_column("Result")
    table.add_row("Wazuh API", "PASS" if api_ok else api_message)
    table.add_row(
        "Linux sensor",
        "active" if integration.config_found else "not detected",
    )
    table.add_row(
        "EVE integration",
        (
            "configured"
            if integration.eve_configured and integration.json_log_format_configured
            else "missing"
        ),
    )
    table.add_row("ossec.conf", str(integration.config_path or "-"))
    console.print(table)


@stage2_app.command("verify")
def stage2_verify(
    quick: Annotated[
        bool,
        typer.Option(
            "--quick", help="Run quick checks only (skip pytest, ruff, mypy)."
        ),
    ] = False,
    demo: Annotated[
        bool,
        typer.Option("--demo", help="Force demo mode using local fixture data."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Show detailed subprocess output."),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable color output for this run."),
    ] = False,
) -> None:
    """Run an end-to-end Stage 2 verification report for Windows and Linux."""
    local_console = Console(no_color=no_color)
    service = Stage2VerificationService(console=local_console)

    report = service.verify(quick=quick, demo=demo, verbose=verbose)
    raise typer.Exit(code=0 if report.status_label != "NOT READY" else 1)


@stage1_app.command("verify")
def stage1_verify(
    quick: Annotated[
        bool,
        typer.Option(
            "--quick", help="Run quick checks only (skip pytest, ruff, mypy)."
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Show detailed subprocess output."),
    ] = False,
    send_event: Annotated[
        bool,
        typer.Option(
            "--send-event",
            help="Optionally send a real demonstration event to Wazuh.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes", "-y", help="Auto-confirm event sending when --send-event is used."
        ),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable color output for this run."),
    ] = False,
    watch: Annotated[
        bool,
        typer.Option("--watch", help="Re-run verification continuously."),
    ] = False,
    interval: Annotated[
        int,
        typer.Option("--interval", help="Seconds between checks in watch mode."),
    ] = 30,
    ensure_agent: Annotated[
        bool,
        typer.Option(
            "--ensure-agent",
            help="When no real endpoint is enrolled, try to install a local agent.",
        ),
    ] = False,
    agent_manager: Annotated[
        str,
        typer.Option(
            "--agent-manager",
            help="Wazuh manager host/IP used by automatic agent install.",
        ),
    ] = "127.0.0.1",
    agent_name: Annotated[
        str | None,
        typer.Option(
            "--agent-name",
            help="Optional endpoint name used by automatic agent install.",
        ),
    ] = None,
) -> None:
    """Run an end-to-end Stage 1 verification report for Windows and Linux."""
    local_console = Console(no_color=no_color)

    confirmed_send = False
    if send_event:
        confirmed_send = yes or typer.confirm(
            "Send a demonstration event to Wazuh?",
            default=False,
        )

    confirmed_ensure_agent = False
    if ensure_agent:
        confirmed_ensure_agent = yes or typer.confirm(
            "If no real endpoint is enrolled, try installing a local Wazuh agent?",
            default=False,
        )

    if interval < 1:
        local_console.print(
            "[bold red]ERROR:[/bold red] --interval must be >= 1 second."
        )
        raise typer.Exit(code=1)

    service = Stage1VerificationService(console=local_console)
    try:
        report = service.verify(
            quick=quick,
            verbose=verbose,
            send_event=send_event,
            confirmed_send=confirmed_send,
            ensure_agent=confirmed_ensure_agent,
            agent_manager=agent_manager,
            agent_name=agent_name,
        )

        while watch:
            local_console.print(
                "\n[cyan]"
                f"Waiting {interval}s before next verification. "
                "Press Ctrl+C to stop."
                "[/cyan]"
            )
            time.sleep(interval)
            local_console.clear()
            report = service.verify(
                quick=quick,
                verbose=verbose,
                send_event=send_event,
                confirmed_send=confirmed_send,
                ensure_agent=False,
                agent_manager=agent_manager,
                agent_name=agent_name,
            )
    except KeyboardInterrupt:
        local_console.print(
            "[bold yellow]Verification interrupted by user.[/bold yellow]"
        )
        raise typer.Exit(code=1) from None

    raise typer.Exit(code=1 if report.has_required_failures else 0)
