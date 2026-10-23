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


class AlertMappingError(SocLabError):
    """Raised when an inbound webhook payload cannot become a SecurityAlert."""


class ResponseError(SocLabError):
    """Raised when the response engine cannot decide or execute an action."""
