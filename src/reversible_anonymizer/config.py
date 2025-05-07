import json
import os
from typing import Dict, Any, List
from .infotypes.catalog import InfoTypeCatalog
from .common import AnonymizerMode


class AnonymizerConfig:
    """Configuration class for the anonymizer."""

    @classmethod
    def from_file(cls, config_path: str) -> Dict[str, Any]:
        """Load configuration from a JSON file."""
        with open(config_path, 'r') as f:
            config_dict = json.load(f)
        return config_dict

    @classmethod
    def from_env(cls) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        # Cache configuration
        cache_type = os.environ.get("ANONYMIZER_CACHE_TYPE", "memory").lower()
        cache_config = {}

        if cache_type == "memory":
            cache_config["capacity"] = int(os.environ.get("ANONYMIZER_CACHE_CAPACITY", "1000"))
            cache_config["ttl"] = int(os.environ.get("ANONYMIZER_CACHE_TTL", "3600"))
        elif cache_type == "memcache":
            cache_config["host"] = os.environ.get("ANONYMIZER_MEMCACHE_HOST")
            cache_config["port"] = int(os.environ.get("ANONYMIZER_MEMCACHE_PORT", "11211"))
            cache_config["instance_id"] = os.environ.get("ANONYMIZER_MEMCACHE_INSTANCE")
            cache_config["region"] = os.environ.get("ANONYMIZER_MEMCACHE_REGION", "us-central1")
            cache_config["create_if_missing"] = os.environ.get("ANONYMIZER_MEMCACHE_CREATE", "false").lower() == "true"
            cache_config["node_count"] = int(os.environ.get("ANONYMIZER_MEMCACHE_NODES", "1"))
            cache_config["node_cpu"] = int(os.environ.get("ANONYMIZER_MEMCACHE_CPU", "1"))
            cache_config["node_memory_gb"] = int(os.environ.get("ANONYMIZER_MEMCACHE_MEMORY", "1"))
            cache_config["ttl"] = int(os.environ.get("ANONYMIZER_CACHE_TTL", "3600"))

        return {
            "project": os.environ.get("ANONYMIZER_PROJECT"),
            "info_types": os.environ.get("ANONYMIZER_INFO_TYPES", "").split(",") if os.environ.get(
                "ANONYMIZER_INFO_TYPES") else None,
            "collection_name": os.environ.get("ANONYMIZER_COLLECTION", "anonymization_mappings"),
            "location": os.environ.get("ANONYMIZER_LOCATION", "global"),
            "mode": os.environ.get("ANONYMIZER_MODE", "strict"),
            "storage_type": os.environ.get("ANONYMIZER_STORAGE_TYPE", "firestore"),
            "encryption_key": os.environ.get("ANONYMIZER_ENCRYPTION_KEY"),
            "use_realistic_fake_data": os.environ.get("ANONYMIZER_USE_REALISTIC_FAKE_DATA", "true").lower() == "true",
            "faker_seed": int(os.environ.get("ANONYMIZER_FAKER_SEED")) if os.environ.get(
                "ANONYMIZER_FAKER_SEED") else None,
            "faker_locale": os.environ.get("ANONYMIZER_FAKER_LOCALE", "").split(",") if os.environ.get(
                "ANONYMIZER_FAKER_LOCALE") else None,
            "async_storage_updates": os.environ.get("ANONYMIZER_ASYNC_STORAGE", "false").lower() == "true",
            "cache_type": cache_type,
            "cache_config": cache_config
        }

    @classmethod
    def validate_config(cls, config: Dict[str, Any]) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []

        # Check required fields
        if not config.get("project"):
            errors.append("Missing required field: project")

        # Validate info_types
        info_types = config.get("info_types") or []
        if info_types:
            for info_type in info_types:
                if isinstance(info_type, str):
                    if not InfoTypeCatalog.is_valid_infotype(info_type):
                        errors.append(f"Invalid info type: {info_type}")
                elif isinstance(info_type, dict):
                    if "name" not in info_type:
                        errors.append(f"Missing 'name' in info type: {info_type}")
                    elif not InfoTypeCatalog.is_valid_infotype(info_type["name"]):
                        errors.append(f"Invalid info type: {info_type['name']}")
                else:
                    errors.append(f"Invalid info type format: {info_type}")

        # Validate mode
        valid_modes = [mode.value for mode in AnonymizerMode]
        mode = config.get("mode", "strict")
        if mode not in valid_modes:
            errors.append(f"Invalid mode: {mode}. Must be one of {valid_modes}")

        # Validate storage_type
        valid_storage_types = ["firestore", "memory"]
        storage_type = config.get("storage_type", "firestore")
        if storage_type not in valid_storage_types:
            errors.append(f"Invalid storage_type: {storage_type}. Must be one of {valid_storage_types}")

        # Validate cache_type
        valid_cache_types = ["memory", "memcache"]
        cache_type = config.get("cache_type", "memory")
        if cache_type not in valid_cache_types:
            errors.append(f"Invalid cache_type: {cache_type}. Must be one of {valid_cache_types}")

        # Validate memcache configuration if used
        if cache_type == "memcache":
            cache_config = config.get("cache_config", {})
            if not (cache_config.get("host") or cache_config.get("instance_id")):
                errors.append("Memcache requires either host or instance_id to be specified")

        # Validate numeric fields
        try:
            if "cache_size" in config and int(config["cache_size"]) <= 0:
                errors.append("cache_size must be a positive integer")
        except (ValueError, TypeError):
            errors.append("cache_size must be a valid integer")

        try:
            if "cache_ttl" in config and int(config["cache_ttl"]) <= 0:
                errors.append("cache_ttl must be a positive integer")
        except (ValueError, TypeError):
            errors.append("cache_ttl must be a valid integer")

        try:
            if "faker_seed" in config and config["faker_seed"] is not None:
                int(config["faker_seed"])  # Just to verify it's a valid integer
        except (ValueError, TypeError):
            errors.append("faker_seed must be a valid integer or None")

        return errors







# import json
# import os
# from typing import Dict, Any, List
# from .infotypes.catalog import InfoTypeCatalog
# from .common import AnonymizerMode
#
#
# class AnonymizerConfig:
#     """Configuration class for the anonymizer."""
#
#     @classmethod
#     def from_file(cls, config_path: str) -> Dict[str, Any]:
#         """Load configuration from a JSON file."""
#         with open(config_path, 'r') as f:
#             config_dict = json.load(f)
#         return config_dict
#
#     @classmethod
#     def from_env(cls) -> Dict[str, Any]:
#         """Load configuration from environment variables."""
#         return {
#             "project": os.environ.get("ANONYMIZER_PROJECT"),
#             "info_types": os.environ.get("ANONYMIZER_INFO_TYPES", "").split(",") if os.environ.get(
#                 "ANONYMIZER_INFO_TYPES") else None,
#             "collection_name": os.environ.get("ANONYMIZER_COLLECTION", "anonymization_mappings"),
#             "location": os.environ.get("ANONYMIZER_LOCATION", "global"),
#             "mode": os.environ.get("ANONYMIZER_MODE", "strict"),
#             "storage_type": os.environ.get("ANONYMIZER_STORAGE_TYPE", "firestore"),
#             "encryption_key": os.environ.get("ANONYMIZER_ENCRYPTION_KEY"),
#             "cache_size": int(os.environ.get("ANONYMIZER_CACHE_SIZE", "1000")),
#             "cache_ttl": int(os.environ.get("ANONYMIZER_CACHE_TTL", "3600")),
#             "use_realistic_fake_data": os.environ.get("ANONYMIZER_USE_REALISTIC_FAKE_DATA", "true").lower() == "true",
#             "faker_seed": int(os.environ.get("ANONYMIZER_FAKER_SEED")) if os.environ.get(
#                 "ANONYMIZER_FAKER_SEED") else None,
#             "faker_locale": os.environ.get("ANONYMIZER_FAKER_LOCALE", "").split(",") if os.environ.get(
#                 "ANONYMIZER_FAKER_LOCALE") else None,
#         }
#
#     @classmethod
#     def validate_config(cls, config: Dict[str, Any]) -> List[str]:
#         """Validate configuration and return list of errors."""
#         errors = []
#
#         # Check required fields
#         if not config.get("project"):
#             errors.append("Missing required field: project")
#
#         # Validate info_types
#         info_types = config.get("info_types") or []
#         if info_types:
#             for info_type in info_types:
#                 if isinstance(info_type, str):
#                     if not InfoTypeCatalog.is_valid_infotype(info_type):
#                         errors.append(f"Invalid info type: {info_type}")
#                 elif isinstance(info_type, dict):
#                     if "name" not in info_type:
#                         errors.append(f"Missing 'name' in info type: {info_type}")
#                     elif not InfoTypeCatalog.is_valid_infotype(info_type["name"]):
#                         errors.append(f"Invalid info type: {info_type['name']}")
#                 else:
#                     errors.append(f"Invalid info type format: {info_type}")
#
#         # Validate mode
#         valid_modes = [mode.value for mode in AnonymizerMode]
#         mode = config.get("mode", "strict")
#         if mode not in valid_modes:
#             errors.append(f"Invalid mode: {mode}. Must be one of {valid_modes}")
#
#         # Validate storage_type
#         valid_storage_types = ["firestore", "memory"]
#         storage_type = config.get("storage_type", "firestore")
#         if storage_type not in valid_storage_types:
#             errors.append(f"Invalid storage_type: {storage_type}. Must be one of {valid_storage_types}")
#
#         # Validate numeric fields
#         try:
#             if "cache_size" in config and int(config["cache_size"]) <= 0:
#                 errors.append("cache_size must be a positive integer")
#         except (ValueError, TypeError):
#             errors.append("cache_size must be a valid integer")
#
#         try:
#             if "cache_ttl" in config and int(config["cache_ttl"]) <= 0:
#                 errors.append("cache_ttl must be a positive integer")
#         except (ValueError, TypeError):
#             errors.append("cache_ttl must be a valid integer")
#
#         try:
#             if "faker_seed" in config and config["faker_seed"] is not None:
#                 int(config["faker_seed"])  # Just to verify it's a valid integer
#         except (ValueError, TypeError):
#             errors.append("faker_seed must be a valid integer or None")
#
#         return errors






# import json
# import os
# from typing import Dict, Any, List
# from .infotypes.catalog import InfoTypeCatalog
# from .common import AnonymizerMode
#
#
# class AnonymizerConfig:
#     """Configuration class for the anonymizer."""
#
#     @classmethod
#     def from_file(cls, config_path: str) -> Dict[str, Any]:
#         """Load configuration from a JSON file."""
#         with open(config_path, 'r') as f:
#             config_dict = json.load(f)
#         return config_dict
#
#     @classmethod
#     def from_env(cls) -> Dict[str, Any]:
#         """Load configuration from environment variables."""
#         return {
#             "project": os.environ.get("ANONYMIZER_PROJECT"),
#             "info_types": os.environ.get("ANONYMIZER_INFO_TYPES", "").split(",") if os.environ.get(
#                 "ANONYMIZER_INFO_TYPES") else None,
#             "collection_name": os.environ.get("ANONYMIZER_COLLECTION", "anonymization_mappings"),
#             "location": os.environ.get("ANONYMIZER_LOCATION", "global"),
#             "mode": os.environ.get("ANONYMIZER_MODE", "strict"),
#             "storage_type": os.environ.get("ANONYMIZER_STORAGE_TYPE", "firestore"),
#             "encryption_key": os.environ.get("ANONYMIZER_ENCRYPTION_KEY"),
#             "cache_size": int(os.environ.get("ANONYMIZER_CACHE_SIZE", "1000")),
#             "cache_ttl": int(os.environ.get("ANONYMIZER_CACHE_TTL", "3600")),
#         }
#
#     @classmethod
#     def validate_config(cls, config: Dict[str, Any]) -> List[str]:
#         """Validate configuration and return list of errors."""
#         errors = []
#
#         # Check required fields
#         if not config.get("project"):
#             errors.append("Missing required field: project")
#
#         # Validate info_types
#         info_types = config.get("info_types") or []
#         if info_types:
#             for info_type in info_types:
#                 if isinstance(info_type, str):
#                     if not InfoTypeCatalog.is_valid_infotype(info_type):
#                         errors.append(f"Invalid info type: {info_type}")
#                 elif isinstance(info_type, dict):
#                     if "name" not in info_type:
#                         errors.append(f"Missing 'name' in info type: {info_type}")
#                     elif not InfoTypeCatalog.is_valid_infotype(info_type["name"]):
#                         errors.append(f"Invalid info type: {info_type['name']}")
#                 else:
#                     errors.append(f"Invalid info type format: {info_type}")
#
#         # Validate mode
#         valid_modes = [mode.value for mode in AnonymizerMode]
#         mode = config.get("mode", "strict")
#         if mode not in valid_modes:
#             errors.append(f"Invalid mode: {mode}. Must be one of {valid_modes}")
#
#         # Validate storage_type
#         valid_storage_types = ["firestore", "memory"]
#         storage_type = config.get("storage_type", "firestore")
#         if storage_type not in valid_storage_types:
#             errors.append(f"Invalid storage_type: {storage_type}. Must be one of {valid_storage_types}")
#
#         # Validate numeric fields
#         try:
#             if "cache_size" in config and int(config["cache_size"]) <= 0:
#                 errors.append("cache_size must be a positive integer")
#         except (ValueError, TypeError):
#             errors.append("cache_size must be a valid integer")
#
#         try:
#             if "cache_ttl" in config and int(config["cache_ttl"]) <= 0:
#                 errors.append("cache_ttl must be a positive integer")
#         except (ValueError, TypeError):
#             errors.append("cache_ttl must be a valid integer")
#
#         return errors





# """Configuration settings for the reversible_anonymizer package."""
#
# DEFAULT_INFO_TYPES = [
#     {"name": "PERSON_NAME"},
#     {"name": "PHONE_NUMBER"},
#     {"name": "FIRST_NAME"},
#     {"name": "LAST_NAME"},
# ]
#
# REQUIRED_SERVICES = [
#     "aiplatform.googleapis.com",
#     "firestore.googleapis.com",
#     "dlp.googleapis.com",
# ]
#
# DEFAULT_COLLECTION_NAME = "mappings"
# DEFAULT_LOCATION = "global"