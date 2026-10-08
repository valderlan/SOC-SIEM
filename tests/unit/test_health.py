from typing import Any

from soclab.models import Agent
from soclab.services.health import build_health_report


class FakeClient:
    def api_info(self) -> dict[str, Any]:
        return {"error": 0, "data": {"api_version": "4.14.8", "hostname": "manager-1"}}

    def agents(self) -> list[Agent]:
        return [
            Agent(id="001", name="linux", status="active"),
            Agent(id="002", name="windows", status="active"),
            Agent(id="003", name="old", status="disconnected"),
        ]


def test_health_report_counts_statuses() -> None:
    report = build_health_report(FakeClient())  # type: ignore[arg-type]

    assert report.api_ok is True
    assert report.total_agents == 3
    assert report.active_agents == 2
    assert report.disconnected_agents == 1
