from pathlib import Path

import pytest

from soclab.config import ENV_FILE_PATH, Settings, get_settings
from soclab.exceptions import ConfigurationError


def test_settings_reads_soclab_environment_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOCLAB_WAZUH_URL", "https://10.0.0.5:55000")
    monkeypatch.setenv("SOCLAB_WAZUH_USERNAME", "wazuh-wui")
    monkeypatch.setenv("SOCLAB_WAZUH_PASSWORD", "super-secret")
    monkeypatch.setenv("SOCLAB_WAZUH_VERIFY_TLS", "false")
    monkeypatch.setenv("SOCLAB_HTTP_TIMEOUT_SECONDS", "11")
    monkeypatch.setenv("SOCLAB_MAX_AGENTS", "321")

    settings = Settings()

    assert str(settings.wazuh_url) == "https://10.0.0.5:55000/"
    assert settings.wazuh_username == "wazuh-wui"
    assert settings.wazuh_password.get_secret_value() == "super-secret"
    assert settings.wazuh_verify_tls is False
    assert settings.http_timeout_seconds == 11
    assert settings.max_agents == 321


def test_settings_secret_is_not_exposed_in_repr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOCLAB_WAZUH_PASSWORD", "super-secret")

    settings = Settings()
    public = repr(settings)

    assert "super-secret" not in public
    assert "********" in public


def test_get_settings_missing_password_has_friendly_message(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(Settings.model_config, "env_file", tmp_path / ".env")
    monkeypatch.delenv("SOCLAB_WAZUH_PASSWORD", raising=False)
    get_settings.cache_clear()

    with pytest.raises(ConfigurationError) as exc:
        get_settings()

    message = str(exc.value)
    assert "Wazuh API password is not configured." in message
    assert "SOCLAB_WAZUH_PASSWORD" in message
    assert str(ENV_FILE_PATH.resolve()) in message

    get_settings.cache_clear()
