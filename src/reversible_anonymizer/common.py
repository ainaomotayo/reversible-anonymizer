from typing import Optional, List, Dict, Any, Union, TypedDict, Tuple
import uuid
import concurrent.futures
import time
import logging
from datetime import datetime
import hashlib
from faker import Faker
from google.cloud import dlp_v2, firestore
import google.api_core.exceptions as google_exceptions
from abc import ABC, abstractmethod
from enum import Enum
import json
import os
from collections import OrderedDict


class AnonymizerMode(Enum):
    """Operation modes for the anonymizer."""
    STRICT = "strict"  # Throw errors on failures
    TOLERANT = "tolerant"  # Continue despite partial failures
    AUDIT = "audit"  # Only detect without anonymizing (for testing)


class InfoTypeCategory(Enum):
    """Categories for organizing info types."""
    PERSON = "Person Information"
    FINANCIAL = "Financial Information"
    HEALTH = "Health Information"
    CREDENTIALS = "Credentials"
    LOCATION = "Location Information"
    DOCUMENT = "Document Identifiers"
    ETHNIC = "Ethnic Information"
    GOVERNMENT = "Government Issued IDs"
    NETWORKING = "Networking Information"
    OTHER = "Other Identifiers"


class ReversibleAnonymizerError(Exception):
    """Base exception for all reversible anonymizer errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.details = details or {}
        super().__init__(message)


class ServiceNotEnabledError(ReversibleAnonymizerError):
    """Raised when required Google Cloud services are not enabled."""
    pass


class AnonymizationError(ReversibleAnonymizerError):
    """Raised when anonymization fails."""
    pass


class DeAnonymizationError(ReversibleAnonymizerError):
    """Raised when de-anonymization fails."""
    pass


class InfoTypeNotSupportedError(ReversibleAnonymizerError):
    """Raised when an unsupported info type is requested."""
    pass


class StorageError(ReversibleAnonymizerError):
    """Raised when there's an error with the storage adapter."""
    pass


class ConfigurationError(ReversibleAnonymizerError):
    """Raised when there's a configuration error."""
    pass


class AnonymizerLogger:
    """Logger for the anonymizer with structured log support."""

    def __init__(
            self,
            name: str = "reversible_anonymizer",
            level: int = logging.INFO,
            structured: bool = False,
            log_file: Optional[str] = None
    ):
        """Initialize the logger."""
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.structured = structured

        # Add console handler if no handlers exist
        if not self.logger.handlers:
            # Console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)

            # Set formatter based on structured flag
            if structured:
                formatter = logging.Formatter('%(message)s')
            else:
                formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

            # File handler if specified
            if log_file:
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(level)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

    def _format_structured(self, message: str, extra: Optional[Dict[str, Any]] = None) -> str:
        """Format log message as JSON."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "message": message
        }
        if extra:
            data.update(extra)
        return json.dumps(data)

    def info(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log an info message."""
        if self.structured and extra:
            message = self._format_structured(message, extra)
            self.logger.info(message)
        else:
            self.logger.info(message, extra=extra)

    def error(self, message: str, extra: Optional[Dict[str, Any]] = None, exc_info: bool = False) -> None:
        """Log an error message."""
        if self.structured and extra:
            if exc_info:
                import traceback
                extra["exception"] = traceback.format_exc()
            message = self._format_structured(message, extra)
            self.logger.error(message)
        else:
            self.logger.error(message, exc_info=exc_info, extra=extra)

    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log a warning message."""
        if self.structured and extra:
            message = self._format_structured(message, extra)
            self.logger.warning(message)
        else:
            self.logger.warning(message, extra=extra)

    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log a debug message."""
        if self.structured and extra:
            message = self._format_structured(message, extra)
            self.logger.debug(message)
        else:
            self.logger.debug(message, extra=extra)