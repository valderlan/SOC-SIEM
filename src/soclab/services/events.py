"""Deterministic event samples used by the classroom demo."""

from datetime import datetime


def sample_failed_ssh_event() -> str:
    """Return a syslog line designed to match Wazuh's SSH authentication rules."""
    timestamp = datetime.now().astimezone().strftime("%b %d %H:%M:%S")
    return (
        f"{timestamp} linux-agent sshd[4242]: "
        "Failed password for invalid user soclab-demo from 198.51.100.23 port 54321 ssh2"
    )
