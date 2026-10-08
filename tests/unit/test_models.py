from soclab.models import Agent


def test_agent_normalizes_os_and_keepalive() -> None:
    agent = Agent.model_validate(
        {
            "id": "001",
            "name": "linux-client",
            "ip": "10.0.0.10",
            "status": "active",
            "version": "Wazuh v4.14.8",
            "lastKeepAlive": "2026-09-27T12:00:00Z",
            "os": {"name": "Ubuntu 24.04", "platform": "ubuntu"},
        }
    )

    assert agent.os_label == "Ubuntu 24.04"
    assert agent.last_keep_alive == "2026-09-27T12:00:00Z"
