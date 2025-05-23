"""
ReversibleAnonymizer: Enterprise-grade text anonymization using Google Cloud DLP.

This package provides tools for anonymizing sensitive information in text
while allowing for reversible de-anonymization.
"""

from .anonymizer import ReversibleAnonymizer
from .common import (
    AnonymizerMode,
    InfoTypeCategory,
    ReversibleAnonymizerError,
    ServiceNotEnabledError,
    AnonymizationError,
    DeAnonymizationError,
    InfoTypeNotSupportedError,
    StorageError,
    ConfigurationError,
)
from .models import AnonymizationResult
from .infotypes.catalog import InfoTypeCatalog

__version__ = "1.0.0"
__author__ = "Omotayo Aina <ainaomotayo@secureaiguard.com>"

__all__ = [
    "ReversibleAnonymizer",
    "AnonymizerMode",
    "InfoTypeCategory",
    "InfoTypeCatalog",
    "ReversibleAnonymizerError",
    "ServiceNotEnabledError",
    "AnonymizationError",
    "DeAnonymizationError",
    "InfoTypeNotSupportedError",
    "StorageError",
    "ConfigurationError",
    "AnonymizationResult",
]