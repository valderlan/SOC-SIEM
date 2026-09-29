import json
import time
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from soclab import __version__
from soclab.clients.wazuh import WazuhClient
from soclab.config import get_settings
from soclab.exceptions import SocLabError
from soclab.services.events import sample_failed_ssh_event
from soclab.services.health import build_health_report
from soclab.services.stage1_verification import Stage1VerificationService

app = typer.Typer(
    name="soclab",
    help="Open SOC Lab - Stage 1: Wazuh HIDS/SIEM demonstrator.",
    no_args_is_help=True,
)
event_app = typer.Typer(help="Validate or inject controlled demo events.")
app.add_typer(event_app, name="event")
stage1_app = typer.Typer(help="Run Stage 1 verification checks.")
app.add_typer(stage1_app, name="stage1")
console = Console()


def _client() -> WazuhClient:
    return WazuhClient(get_settings())


def _fail(exc: Exception) -> None:
    console.print(f"[bold red]ERROR:[/bold red] {exc}")
    raise typer.Exit(code=1) from exc


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
    """Forward one controlled event to Wazuh analysisd so it can become a live alert."""
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
