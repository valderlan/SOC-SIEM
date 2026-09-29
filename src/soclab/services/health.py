"""Health aggregation logic."""

from soclab.clients.wazuh import WazuhClient
from soclab.models import HealthReport


def build_health_report(client: WazuhClient) -> HealthReport:
    """Query API metadata and agents and return a compact health report."""
    info = client.api_info()
    agents = client.agents()

    data = info.get("data", {})
    data = data if isinstance(data, dict) else {}

    statuses = [agent.status.lower() for agent in agents]
    return HealthReport(
        api_ok=True,
        api_version=str(data.get("api_version")) if data.get("api_version") else None,
        manager_hostname=str(data.get("hostname")) if data.get("hostname") else None,
        total_agents=len(agents),
        active_agents=sum(status == "active" for status in statuses),
        disconnected_agents=sum(status == "disconnected" for status in statuses),
        never_connected_agents=sum(status == "never connected" for status in statuses),
    )
