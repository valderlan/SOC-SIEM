"""Firewall response adapters. Dry-run is the default and never touches the host."""

from __future__ import annotations

import platform
import re
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

    def unblock_ip(self, ip: str) -> AdapterResult:
        """Remove an existing block for one IP address."""
        return AdapterResult(
            adapter=self.name,
            executed=False,
            dry_run=self.dry_run,
            command="-",
            message=f"unblock not supported by adapter {self.name}",
        )


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


def build_unblock_command(platform_name: str, ip: str) -> list[str] | None:
    """Build the native command that removes an IP block, or None on unsupported hosts."""
    normalized = platform_name.lower()
    if normalized.startswith("win"):
        return [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "Remove-NetFirewallRule -DisplayName "
                f"'SOCLab-Block-{ip}' -ErrorAction Stop"
            ),
        ]
    if normalized.startswith("linux"):
        return ["nft", "-a", "list", "chain", "inet", "filter", "input"]
    return None


def find_nft_rule_handles(chain_output: str, ip: str) -> list[str]:
    """Extract nftables rule handles matching ``saddr <ip> ... drop``."""
    family = "ip6" if ":" in ip else "ip"
    pattern = re.compile(
        rf"\b{family}\s+saddr\s+{re.escape(ip)}\b.*\bdrop\b.*#\s*handle\s+(\d+)\b"
    )
    handles: list[str] = []
    for line in chain_output.splitlines():
        match = pattern.search(line)
        if match:
            handles.append(match.group(1))
    return handles


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

    def unblock_ip(self, ip: str) -> AdapterResult:
        target = _validated(ip)
        if target is None:
            return self._refused(ip)
        command = build_unblock_command(self._platform, target)
        return AdapterResult(
            adapter=self.name,
            executed=False,
            dry_run=True,
            command=" ".join(command) if command is not None else "-",
            message=f"dry-run: would unblock {target}"
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
    """Runs native firewall commands. Requires firewall/admin privileges."""

    platform_name: str

    def _invalid_ip_result(self, ip: str) -> AdapterResult:
        return AdapterResult(
            adapter=self.name,
            executed=False,
            dry_run=False,
            command="-",
            message=f"refused invalid IP {ip!r}",
        )

    def _run_process(
        self, command: list[str]
    ) -> tuple[subprocess.CompletedProcess[str] | None, AdapterResult | None]:
        try:
            completed = subprocess.run(
                command,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
            return completed, None
        except (OSError, subprocess.SubprocessError) as exc:
            return None, AdapterResult(
                adapter=self.name,
                executed=False,
                dry_run=False,
                command=" ".join(command),
                message=f"command failed: {exc}",
            )

    def _execute(self, command: list[str], *, success_message: str) -> AdapterResult:
        completed, err = self._run_process(command)
        if err is not None:
            return err
        assert completed is not None
        output = (completed.stderr or completed.stdout).strip().replace("\n", " ")[:200]
        message = (
            success_message
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

    def block_ip(self, ip: str) -> AdapterResult:
        target = _validated(ip)
        if target is None:
            return self._invalid_ip_result(ip)

        command = build_block_command(self.platform_name, target)
        if command is None:
            raise ConfigurationError(
                f"No firewall command available for platform {self.platform_name}"
            )
        return self._execute(command, success_message="block applied")


class WindowsFirewallAdapter(_CommandFirewallAdapter):
    """Windows Defender Firewall through New-NetFirewallRule."""

    name = "windows-powershell"
    platform_name = "windows"

    def unblock_ip(self, ip: str) -> AdapterResult:
        target = _validated(ip)
        if target is None:
            return self._invalid_ip_result(ip)
        command = build_unblock_command(self.platform_name, target)
        assert command is not None
        return self._execute(command, success_message="unblock applied")


class LinuxFirewallAdapter(_CommandFirewallAdapter):
    """nftables rule insertion and removal."""

    name = "linux-nftables"
    platform_name = "linux"

    def _ensure_chain(self) -> AdapterResult | None:
        listed, err = self._run_process(
            ["nft", "-a", "list", "chain", "inet", "filter", "input"]
        )
        if err is not None:
            return err
        assert listed is not None
        if listed.returncode == 0:
            return None
        for cmd in (
            ["nft", "add", "table", "inet", "filter"],
            [
                "nft",
                "add",
                "chain",
                "inet",
                "filter",
                "input",
                "{ type filter hook input priority 0 ; policy accept ; }",
            ],
        ):
            res = self._execute(cmd, success_message="ok")
            if not res.executed:
                return res
        return None

    def block_ip(self, ip: str) -> AdapterResult:
        target = _validated(ip)
        if target is None:
            return self._invalid_ip_result(ip)

        chain_err = self._ensure_chain()
        if chain_err is not None:
            return chain_err

        listed, err = self._run_process(
            ["nft", "-a", "list", "chain", "inet", "filter", "input"]
        )
        if err is not None:
            return err
        assert listed is not None
        if listed.returncode == 0 and find_nft_rule_handles(listed.stdout, target):
            command = build_block_command(self.platform_name, target)
            return AdapterResult(
                adapter=self.name,
                executed=True,
                dry_run=False,
                command=" ".join(command) if command is not None else "-",
                message="block already present",
            )

        return super().block_ip(target)

    def unblock_ip(self, ip: str) -> AdapterResult:
        target = _validated(ip)
        if target is None:
            return self._invalid_ip_result(ip)
        list_cmd = ["nft", "-a", "list", "chain", "inet", "filter", "input"]
        listed, err = self._run_process(list_cmd)
        if err is not None:
            return err
        assert listed is not None
        if listed.returncode != 0:
            output = (listed.stderr or listed.stdout).strip().replace("\n", " ")[:200]
            return AdapterResult(
                adapter=self.name,
                executed=False,
                dry_run=False,
                command=" ".join(list_cmd),
                message=f"exit {listed.returncode}: {output}",
            )

        handles = find_nft_rule_handles(listed.stdout, target)
        if not handles:
            return AdapterResult(
                adapter=self.name,
                executed=False,
                dry_run=False,
                command=" ".join(list_cmd),
                message=f"no block rule found for {target}",
            )

        last_result: AdapterResult | None = None
        for handle in handles:
            del_cmd = ["nft", "delete", "rule", "inet", "filter", "input", "handle", handle]
            last_result = self._execute(del_cmd, success_message="unblock applied")
            if not last_result.executed:
                return last_result

        assert last_result is not None
        return AdapterResult(
            adapter=self.name,
            executed=True,
            dry_run=False,
            command=last_result.command,
            message=f"removed {len(handles)} block rule(s) for {target}",
        )


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
