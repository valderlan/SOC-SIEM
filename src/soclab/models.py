from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AgentOS(BaseModel):

    model_config = ConfigDict(extra="ignore")

    name: str | None = None
    platform: str | None = None
    version: str | None = None


class Agent(BaseModel):

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str
    name: str
    ip: str | None = None
    status: str = "unknown"
    version: str | None = None
    last_keep_alive: str | None = Field(default=None, alias="lastKeepAlive")
    os: AgentOS | None = None

    @property
    def os_label(self) -> str:
        if self.os is None:
            return "-"
        return self.os.name or self.os.platform or "-"


class RuleMatch(BaseModel):

    matched: bool
    rule_id: str | None = None
    level: int | None = None
    description: str | None = None
    decoder: str | None = None
    token: str | None = None
    raw_output: dict[str, Any] = Field(default_factory=dict)


class HealthReport(BaseModel):

    api_ok: bool
    api_version: str | None = None
    manager_hostname: str | None = None
    total_agents: int = 0
    active_agents: int = 0
    disconnected_agents: int = 0
    never_connected_agents: int = 0
