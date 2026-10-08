from functools import lru_cache
from pathlib import Path
from typing import Self

from pydantic import AnyHttpUrl, Field, SecretStr, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from soclab.exceptions import ConfigurationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE_PATH = PROJECT_ROOT / ".env"


class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=ENV_FILE_PATH,
        env_prefix="SOCLAB_",
        extra="ignore",
        case_sensitive=False,
    )

    wazuh_url: AnyHttpUrl = Field(default=AnyHttpUrl("https://127.0.0.1:55000"))
    wazuh_username: str = Field(default="wazuh-wui", min_length=1)
    wazuh_password: SecretStr = Field(default=SecretStr("CHANGE_ME"))
    wazuh_verify_tls: bool = False
    wazuh_ca_bundle: Path | None = None
    http_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    max_agents: int = Field(default=500, ge=1, le=5000)
    suricata_enabled: bool = True
    suricata_eve_path: Path = Field(default=Path("/var/log/suricata/eve.json"))
    suricata_interface: str | None = None

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
    """Return strict cached settings used by Stage 1 and Wazuh API commands."""
    return _load_settings(require_wazuh_password=True)


@lru_cache(maxsize=1)
def get_settings_optional() -> Settings:
    """Return cached settings without requiring Wazuh password.

    Stage 2 demo/NIDS commands can run without API credentials.
    """
    return _load_settings(require_wazuh_password=False)


def _load_settings(*, require_wazuh_password: bool) -> Settings:
    """Load settings and optionally enforce Wazuh API password presence."""
    try:
        settings = Settings()
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
    except Exception as exc:
        raise ConfigurationError(str(exc)) from exc

    password_value = settings.wazuh_password.get_secret_value().strip()
    if require_wazuh_password and (
        not password_value or password_value.upper() == "CHANGE_ME"
    ):
        message = (
            "Wazuh API password is not configured.\n\n"
            "Configure SOCLAB_WAZUH_PASSWORD in:\n"
            f"{ENV_FILE_PATH.resolve()}\n\n"
            "Example:\n"
            "SOCLAB_WAZUH_PASSWORD=<your-wazuh-api-password>"
        )
        raise ConfigurationError(message)

    return settings
