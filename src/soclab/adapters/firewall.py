"""Firewall response adapters. Dry-run is the default and never touches the host."""

from __future__ import annotations

import platform
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from ipaddress import ip_address

from soclab.exceptions import ConfigurationError

COMMAND_TIMEOUT_SECONDS = 15


@dataclass(frozen=True)
class AdapterResult:
    adapter: str
    executed: bool
    dry_run: bool
    command: str
    message: str


class FirewallAdapter(ABC):
    """Interface every response adapter implements."""

    name: str
    dry_run: bool = False

    @abstractmethod
    def block_ip(self, ip: str) -> AdapterResult:
        """Block inbound traffic from one IP address."""


def build_block_command(platform_name: str, ip: str) -> list[str] | None:
    """Build the native command that blocks an IP, or None on unsupported hosts."""
    normalized = platform_name.lower()
    if normalized.startswith("win"):
        return [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "New-NetFirewallRule -DisplayName "
                f"'SOCLab-Block-{ip}' -Direction Inbound -Action Block "
                f"-RemoteAddress {ip}"
            ),
        ]
    if normalized.startswith("linux"):
        family = "ip6" if ":" in ip else "ip"
        return ["nft", "add", "rule", "inet", "filter", "input", family, "saddr", ip, "drop"]
    return None


def _validated(ip: str) -> str | None:
    """Return the canonical IP or None. Adapters never build commands from raw text."""
    try:
        return str(ip_address(ip))
    except ValueError:
        return None


class DryRunFirewallAdapter(FirewallAdapter):
    """Default adapter: reports the command it would run and changes nothing."""

    name = "dry-run"
    dry_run = True

    def __init__(self, *, platform_name: str | None = None) -> None:
        self._platform = platform_name or platform.system()

    def block_ip(self, ip: str) -> AdapterResult:
        target = _validated(ip)
        if target is None:
            return self._refused(ip)
        command = build_block_command(self._platform, target)
        return AdapterResult(
            adapter=self.name,
            executed=False,
            dry_run=True,
            command=" ".join(command) if command is not None else "-",
            message=f"dry-run: would block {target}"
            if command is not None
            else f"dry-run: no firewall adapter for platform {self._platform}",
        )

    def _refused(self, ip: str) -> AdapterResult:
        return AdapterResult(
            adapter=self.name,
            executed=False,
            dry_run=True,
            command="-",
            message=f"dry-run: refused invalid IP {ip!r}",
        )


class _CommandFirewallAdapter(FirewallAdapter):
    """Runs the native block command. Requires firewall/admin privileges."""

    platform_name: str

    def block_ip(self, ip: str) -> AdapterResult:
        target = _validated(ip)
        if target is None:
            return AdapterResult(
                adapter=self.name,
                executed=False,
                dry_run=False,
                command="-",
                message=f"refused invalid IP {ip!r}",
            )

        command = build_block_command(self.platform_name, target)
        if command is None:
            raise ConfigurationError(
                f"No firewall command available for platform {self.platform_name}"
            )

        try:
            completed = subprocess.run(
                command,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return AdapterResult(
                adapter=self.name,
                executed=False,
                dry_run=False,
                command=" ".join(command),
                message=f"command failed: {exc}",
            )

        output = (completed.stderr or completed.stdout).strip().replace("\n", " ")[:200]
        message = (
            "block applied"
            if completed.returncode == 0
            else f"exit {completed.returncode}: {output}"
        )
        return AdapterResult(
            adapter=self.name,
            executed=completed.returncode == 0,
            dry_run=False,
            command=" ".join(command),
            message=message,
        )


class WindowsFirewallAdapter(_CommandFirewallAdapter):
    """Windows Defender Firewall through New-NetFirewallRule."""

    name = "windows-powershell"
    platform_name = "windows"


class LinuxFirewallAdapter(_CommandFirewallAdapter):
    """nftables rule insertion."""

    name = "linux-nftables"
    platform_name = "linux"


def create_firewall_adapter(
    *, dry_run: bool = True, platform_name: str | None = None
) -> FirewallAdapter:
    """Return a dry-run adapter unless live mode was explicitly requested."""
    if dry_run:
        return DryRunFirewallAdapter(platform_name=platform_name)

    name = (platform_name or platform.system()).lower()
    if name.startswith("win"):
        return WindowsFirewallAdapter()
    if name.startswith("linux"):
        return LinuxFirewallAdapter()
    raise ConfigurationError(
        f"Live firewall response is not supported on {name or 'unknown platform'}; "
        "keep SOCLAB_RESPONSE_DRY_RUN=true."
    )
