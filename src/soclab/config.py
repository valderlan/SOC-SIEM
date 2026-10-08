"""Configuration loaded from environment variables and .env."""

from functools import lru_cache
from pathlib import Path
from typing import Self

from pydantic import AnyHttpUrl, Field, SecretStr, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from soclab.exceptions import ConfigurationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE_PATH = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """Runtime settings for the CLI.

    All variables use the SOCLAB_ prefix. Example: SOCLAB_WAZUH_URL.
    """

    model_config = SettingsConfigDict(
        env_file=ENV_FILE_PATH,
        env_prefix="SOCLAB_",
        extra="ignore",
        case_sensitive=False,
    )

    wazuh_url: AnyHttpUrl = Field(default=AnyHttpUrl("https://127.0.0.1:55000"))
    wazuh_username: str = Field(default="wazuh-wui", min_length=1)
    wazuh_password: SecretStr
    wazuh_verify_tls: bool = False
    wazuh_ca_bundle: Path | None = None
    http_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    max_agents: int = Field(default=500, ge=1, le=5000)

    @model_validator(mode="after")
    def validate_tls(self) -> Self:
        if self.wazuh_ca_bundle is not None and not self.wazuh_ca_bundle.is_file():
            raise ValueError(f"CA bundle not found: {self.wazuh_ca_bundle}")
        return self

    @property
    def httpx_verify(self) -> bool | str:
        if self.wazuh_ca_bundle is not None:
            return str(self.wazuh_ca_bundle)
        return self.wazuh_verify_tls


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings with a friendly configuration error."""
    try:
        return Settings()  # type: ignore[call-arg]
    except ValidationError as exc:
        missing_fields = {
            str(error.get("loc", [""])[0])
            for error in exc.errors()
            if error.get("type") == "missing"
        }
        if "wazuh_password" in missing_fields:
            message = (
                "Wazuh API password is not configured.\n\n"
                "Configure SOCLAB_WAZUH_PASSWORD in:\n"
                f"{ENV_FILE_PATH.resolve()}\n\n"
                "Example:\n"
                "SOCLAB_WAZUH_PASSWORD=<your-wazuh-api-password>"
            )
            raise ConfigurationError(message) from exc
        raise ConfigurationError(str(exc)) from exc
    except Exception as exc:  # Pydantic exposes several validation exception types.
        raise ConfigurationError(str(exc)) from exc
