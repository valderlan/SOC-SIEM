"""Application-specific exceptions."""


class SocLabError(Exception):
    """Base exception for expected SOC Lab failures."""


class ConfigurationError(SocLabError):
    """Raised when required configuration is invalid or missing."""


class WazuhError(SocLabError):
    """Base exception for Wazuh communication failures."""


class WazuhAuthenticationError(WazuhError):
    """Raised when Wazuh API authentication fails."""


class WazuhRequestError(WazuhError):
    """Raised when a Wazuh API request fails."""
