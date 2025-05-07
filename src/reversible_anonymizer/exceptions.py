"""Custom exceptions for the reversible_anonymizer package."""

class ServiceNotEnabledError(Exception):
    """Raised when required Google Cloud services are not enabled."""
    pass

class AnonymizationError(Exception):
    """Raised when anonymization fails."""
    pass

class DeAnonymizationError(Exception):
    """Raised when de-anonymization fails."""
    pass