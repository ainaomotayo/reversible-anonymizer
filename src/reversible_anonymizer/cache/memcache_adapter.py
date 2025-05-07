from typing import Optional, Dict, Any, List, Tuple
import time
import json
import logging
import subprocess
import threading
import base64
from concurrent.futures import ThreadPoolExecutor

try:
    import memcache
    from google.cloud import service_usage_v1
    from google.cloud import memcache_v1
    from google.api_core.exceptions import NotFound, PermissionDenied

    MEMCACHE_AVAILABLE = True
except ImportError:
    MEMCACHE_AVAILABLE = False

from .base import CacheAdapter
from ..common import ServiceNotEnabledError, ConfigurationError


class MemcacheAdapter(CacheAdapter):
    """Google Cloud Memcache adapter."""

    def __init__(
            self,
            project_id: str,
            host: Optional[str] = None,
            port: int = 11211,
            instance_id: Optional[str] = None,
            region: str = "us-central1",
            create_if_missing: bool = False,
            node_count: int = 1,
            node_cpu: int = 1,
            node_memory_gb: int = 1,
            default_ttl: int = 3600,
            check_service: bool = True,
            debug: bool = False
    ):
        """
        Initialize Google Cloud Memcache adapter.

        Args:
            project_id: Google Cloud project ID
            host: Memcache host IP (required if instance_id not provided)
            port: Memcache port (default: 11211)
            instance_id: Memcache instance ID for auto-discovery (if host not provided)
            region: Google Cloud region for Memcache instance
            create_if_missing: Whether to create a new instance if one doesn't exist
            node_count: Number of nodes if creating a new instance
            node_cpu: CPU count per node if creating a new instance
            node_memory_gb: Memory in GB per node if creating a new instance
            default_ttl: Default time-to-live in seconds
            check_service: Whether to check if Memcache service is enabled
            debug: Whether to enable debug logging
        """
        if not MEMCACHE_AVAILABLE:
            raise ImportError("Memcache functionality requires python-memcached and google-cloud-memcache packages")

        self.project_id = project_id
        self.instance_id = instance_id
        self.region = region
        self.create_if_missing = create_if_missing
        self.node_count = node_count
        self.node_cpu = node_cpu
        self.node_memory_gb = node_memory_gb
        self.default_ttl = default_ttl
        self.debug = debug

        # Check if Memcache service is enabled
        if check_service:
            self._check_memcache_service()

        # Initialize client with provided host:port or discover from instance
        if host:
            self.host = host
            self.port = port
            self.client = memcache.Client([(host, port)], debug=0)
        elif instance_id:
            # Get host:port from instance ID
            self.host, self.port = self._discover_memcache_endpoint()
            self.client = memcache.Client([(self.host, self.port)], debug=0)
        else:
            raise ConfigurationError("Either host or instance_id must be provided")

        # Verify connection
        if not self.health_check():
            raise ConfigurationError("Could not connect to Memcache instance")

    def _sanitize_key(self, key: str) -> str:
        """
        Sanitize a key for use with Memcached.
        Memcached doesn't allow spaces or control characters in keys.
        """
        # Base64 encode the key to ensure it's valid for Memcached
        # This is reversible and preserves uniqueness
        sanitized = base64.b64encode(key.encode('utf-8')).decode('ascii')
        if self.debug:
            logging.debug(f"Sanitized key: '{key}' -> '{sanitized}'")
        return sanitized

    def _desanitize_key(self, sanitized_key: str) -> str:
        """Convert a sanitized key back to the original."""
        try:
            return base64.b64decode(sanitized_key.encode('ascii')).decode('utf-8')
        except:
            return sanitized_key  # Return as is if not base64 encoded

    def _check_memcache_service(self) -> None:
        """Check if Memcache service is enabled."""
        try:
            client = service_usage_v1.ServiceUsageClient()
            name = f"projects/{self.project_id}/services/memcache.googleapis.com"

            # Create a request object instead of passing name directly
            request = service_usage_v1.GetServiceRequest(name=name)
            response = client.get_service(request=request)

            if response.state != service_usage_v1.State.ENABLED:
                if self.create_if_missing:
                    self._enable_memcache_service()
                else:
                    raise ServiceNotEnabledError(
                        "Memcache service is not enabled. "
                        "Enable it with 'gcloud services enable memcache.googleapis.com'"
                    )
        except NotFound:
            if self.create_if_missing:
                self._enable_memcache_service()
            else:
                raise ServiceNotEnabledError("Memcache service is not enabled")
        except PermissionDenied:
            logging.warning(
                "Insufficient permissions to check Memcache service. "
                "Assuming it's enabled."
            )

    def _enable_memcache_service(self) -> None:
        """Enable Memcache service."""
        try:
            result = subprocess.run(
                ["gcloud", "services", "enable", "memcache.googleapis.com",
                 f"--project={self.project_id}"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise ServiceNotEnabledError(
                    f"Failed to enable Memcache service: {result.stderr}"
                )
            logging.info("Successfully enabled Memcache service")
        except Exception as e:
            raise ServiceNotEnabledError(f"Failed to enable Memcache service: {str(e)}")

    def _discover_memcache_endpoint(self) -> Tuple[str, int]:
        """Discover Memcache endpoint from instance ID."""
        try:
            client = memcache_v1.CloudMemcacheClient()
            name = f"projects/{self.project_id}/locations/{self.region}/instances/{self.instance_id}"

            try:
                # Use proper request object pattern
                request = memcache_v1.GetInstanceRequest(name=name)
                instance = client.get_instance(request=request)
            except NotFound:
                if self.create_if_missing:
                    instance = self._create_memcache_instance()
                else:
                    raise ConfigurationError(
                        f"Memcache instance {self.instance_id} not found "
                        f"in project {self.project_id}, region {self.region}"
                    )

            # Get the discovery endpoint
            discovery_endpoint = instance.discovery_endpoint
            if not discovery_endpoint:
                # If no discovery endpoint, use the first node's IP
                if instance.nodes:
                    host = instance.nodes[0].host
                    port = 11211  # Default Memcache port
                    return host, port

            # Parse the discovery endpoint (typically host:port format)
            parts = discovery_endpoint.split(':')
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 11211

            return host, port
        except Exception as e:
            raise ConfigurationError(f"Failed to discover Memcache endpoint: {str(e)}")

    def _create_memcache_instance(self) -> Any:
        """Create a new Memcache instance."""
        try:
            client = memcache_v1.CloudMemcacheClient()
            parent = f"projects/{self.project_id}/locations/{self.region}"

            # Define instance configuration
            instance = {
                "name": f"{parent}/instances/{self.instance_id}",
                "node_count": self.node_count,
                "node_config": {
                    "cpu_count": self.node_cpu,
                    "memory_size_mb": self.node_memory_gb * 1024,
                }
            }

            # Create the instance using proper request pattern
            request = memcache_v1.CreateInstanceRequest(
                parent=parent,
                instance_id=self.instance_id,
                instance=instance
            )
            operation = client.create_instance(request=request)

            logging.info(f"Creating Memcache instance {self.instance_id}...")
            result = operation.result()  # Wait for completion
            logging.info(f"Memcache instance created: {result.name}")

            return result
        except Exception as e:
            raise ConfigurationError(f"Failed to create Memcache instance: {str(e)}")

    def get(self, key: str) -> Optional[str]:
        """Get a value from Memcache."""
        try:
            sanitized_key = self._sanitize_key(key)
            value = self.client.get(sanitized_key)
            if value is None:
                return None

            # Convert bytes to string if needed
            if isinstance(value, bytes):
                value = value.decode('utf-8')

            return value
        except Exception as e:
            logging.warning(f"Memcache get error: {str(e)}")
            return None

    def put(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Put a value in Memcache."""
        try:
            sanitized_key = self._sanitize_key(key)
            expiry = ttl if ttl is not None else self.default_ttl
            return self.client.set(sanitized_key, value, time=expiry)
        except Exception as e:
            logging.warning(f"Memcache put error: {str(e)}")
            return False

    def delete(self, key: str) -> bool:
        """Delete a key from Memcache."""
        try:
            sanitized_key = self._sanitize_key(key)
            return self.client.delete(sanitized_key)
        except Exception as e:
            logging.warning(f"Memcache delete error: {str(e)}")
            return False

    def clear(self) -> None:
        """Clear all items from Memcache (flush)."""
        try:
            self.client.flush_all()
        except Exception as e:
            logging.warning(f"Memcache clear error: {str(e)}")

    def batch_get(self, keys: List[str]) -> Dict[str, str]:
        """Get multiple keys at once."""
        try:
            # Sanitize all keys
            sanitized_keys = [self._sanitize_key(k) for k in keys]

            # Create a mapping from sanitized keys back to original keys
            sanitized_to_original = {self._sanitize_key(k): k for k in keys}

            # Get values using sanitized keys
            sanitized_values = self.client.get_multi(sanitized_keys)

            # Convert back to original keys
            result = {}
            for sanitized_key, value in sanitized_values.items():
                original_key = sanitized_to_original.get(sanitized_key)
                if original_key:
                    if isinstance(value, bytes):
                        result[original_key] = value.decode('utf-8')
                    else:
                        result[original_key] = value

            return result
        except Exception as e:
            logging.warning(f"Memcache batch_get error: {str(e)}")
            return {}

    def batch_put(self, key_values: Dict[str, str], ttl: Optional[int] = None) -> bool:
        """Put multiple key-value pairs at once."""
        try:
            # Sanitize all keys
            sanitized_dict = {self._sanitize_key(k): v for k, v in key_values.items()}

            expiry = ttl if ttl is not None else self.default_ttl
            return self.client.set_multi(sanitized_dict, time=expiry)
        except Exception as e:
            logging.warning(f"Memcache batch_put error: {str(e)}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get Memcache statistics."""
        try:
            stats = self.client.get_stats()
            if stats:
                # Extract relevant stats from the first server
                server_stats = stats[0][1]  # (server, stats_dict)
                return {
                    "type": "memcache",
                    "host": self.host,
                    "port": self.port,
                    "curr_items": int(server_stats.get(b'curr_items', 0)),
                    "get_hits": int(server_stats.get(b'get_hits', 0)),
                    "get_misses": int(server_stats.get(b'get_misses', 0)),
                    "total_items": int(server_stats.get(b'total_items', 0)),
                    "bytes": int(server_stats.get(b'bytes', 0)),
                    "limit_maxbytes": int(server_stats.get(b'limit_maxbytes', 0)),
                    "evictions": int(server_stats.get(b'evictions', 0)),
                    "default_ttl": self.default_ttl
                }
            return {
                "type": "memcache",
                "host": self.host,
                "port": self.port,
                "default_ttl": self.default_ttl,
                "error": "No stats available"
            }
        except Exception as e:
            return {
                "type": "memcache",
                "host": self.host,
                "port": self.port,
                "default_ttl": self.default_ttl,
                "error": str(e)
            }

    def health_check(self) -> bool:
        """Check if Memcache is available and working."""
        try:
            # Try to set and get a test value
            test_key = "_health_check_"
            test_value = "ok"

            success = self.client.set(test_key, test_value)
            if not success:
                return False

            value = self.client.get(test_key)
            if value != test_value:
                return False

            return True
        except Exception:
            return False









# from typing import Optional, Dict, Any, List, Tuple
# import time
# import json
# import logging
# import subprocess
# import threading
# from concurrent.futures import ThreadPoolExecutor
#
# try:
#     import memcache
#     from google.cloud import service_usage_v1
#     from google.cloud import memcache_v1
#     from google.api_core.exceptions import NotFound, PermissionDenied
#
#     MEMCACHE_AVAILABLE = True
# except ImportError:
#     MEMCACHE_AVAILABLE = False
#
# from .base import CacheAdapter
# from ..common import ServiceNotEnabledError, ConfigurationError
#
#
# class MemcacheAdapter(CacheAdapter):
#     """Google Cloud Memcache adapter."""
#
#     def __init__(
#             self,
#             project_id: str,
#             host: Optional[str] = None,
#             port: int = 11211,
#             instance_id: Optional[str] = None,
#             region: str = "us-central1",
#             create_if_missing: bool = False,
#             node_count: int = 1,
#             node_cpu: int = 1,
#             node_memory_gb: int = 1,
#             default_ttl: int = 3600,
#             check_service: bool = True
#     ):
#         """
#         Initialize Google Cloud Memcache adapter.
#
#         Args:
#             project_id: Google Cloud project ID
#             host: Memcache host IP (required if instance_id not provided)
#             port: Memcache port (default: 11211)
#             instance_id: Memcache instance ID for auto-discovery (if host not provided)
#             region: Google Cloud region for Memcache instance
#             create_if_missing: Whether to create a new instance if one doesn't exist
#             node_count: Number of nodes if creating a new instance
#             node_cpu: CPU count per node if creating a new instance
#             node_memory_gb: Memory in GB per node if creating a new instance
#             default_ttl: Default time-to-live in seconds
#             check_service: Whether to check if Memcache service is enabled
#         """
#         if not MEMCACHE_AVAILABLE:
#             raise ImportError("Memcache functionality requires python-memcached and google-cloud-memcache packages")
#
#         self.project_id = project_id
#         self.instance_id = instance_id
#         self.region = region
#         self.create_if_missing = create_if_missing
#         self.node_count = node_count
#         self.node_cpu = node_cpu
#         self.node_memory_gb = node_memory_gb
#         self.default_ttl = default_ttl
#
#         # Check if Memcache service is enabled
#         if check_service:
#             self._check_memcache_service()
#
#         # Initialize client with provided host:port or discover from instance
#         if host:
#             self.host = host
#             self.port = port
#             self.client = memcache.Client([(host, port)], debug=0)
#         elif instance_id:
#             # Get host:port from instance ID
#             self.host, self.port = self._discover_memcache_endpoint()
#             self.client = memcache.Client([(self.host, self.port)], debug=0)
#         else:
#             raise ConfigurationError("Either host or instance_id must be provided")
#
#         # Verify connection
#         if not self.health_check():
#             raise ConfigurationError("Could not connect to Memcache instance")
#
#     def _check_memcache_service(self) -> None:
#         """Check if Memcache service is enabled."""
#         try:
#             client = service_usage_v1.ServiceUsageClient()
#             name = f"projects/{self.project_id}/services/memcache.googleapis.com"
#
#             # Create a request object instead of passing name directly
#             request = service_usage_v1.GetServiceRequest(name=name)
#             response = client.get_service(request=request)
#
#             if response.state != service_usage_v1.State.ENABLED:
#                 if self.create_if_missing:
#                     self._enable_memcache_service()
#                 else:
#                     raise ServiceNotEnabledError(
#                         "Memcache service is not enabled. "
#                         "Enable it with 'gcloud services enable memcache.googleapis.com'"
#                     )
#         except NotFound:
#             if self.create_if_missing:
#                 self._enable_memcache_service()
#             else:
#                 raise ServiceNotEnabledError("Memcache service is not enabled")
#         except PermissionDenied:
#             logging.warning(
#                 "Insufficient permissions to check Memcache service. "
#                 "Assuming it's enabled."
#             )
#
#     def _enable_memcache_service(self) -> None:
#         """Enable Memcache service."""
#         try:
#             result = subprocess.run(
#                 ["gcloud", "services", "enable", "memcache.googleapis.com",
#                  f"--project={self.project_id}"],
#                 capture_output=True,
#                 text=True
#             )
#             if result.returncode != 0:
#                 raise ServiceNotEnabledError(
#                     f"Failed to enable Memcache service: {result.stderr}"
#                 )
#             logging.info("Successfully enabled Memcache service")
#         except Exception as e:
#             raise ServiceNotEnabledError(f"Failed to enable Memcache service: {str(e)}")
#
#     def _discover_memcache_endpoint(self) -> Tuple[str, int]:
#         """Discover Memcache endpoint from instance ID."""
#         try:
#             client = memcache_v1.CloudMemcacheClient()
#             name = f"projects/{self.project_id}/locations/{self.region}/instances/{self.instance_id}"
#
#             try:
#                 # Use proper request object pattern
#                 request = memcache_v1.GetInstanceRequest(name=name)
#                 instance = client.get_instance(request=request)
#             except NotFound:
#                 if self.create_if_missing:
#                     instance = self._create_memcache_instance()
#                 else:
#                     raise ConfigurationError(
#                         f"Memcache instance {self.instance_id} not found "
#                         f"in project {self.project_id}, region {self.region}"
#                     )
#
#             # Get the discovery endpoint
#             discovery_endpoint = instance.discovery_endpoint
#             if not discovery_endpoint:
#                 # If no discovery endpoint, use the first node's IP
#                 if instance.nodes:
#                     host = instance.nodes[0].host
#                     port = 11211  # Default Memcache port
#                     return host, port
#
#             # Parse the discovery endpoint (typically host:port format)
#             parts = discovery_endpoint.split(':')
#             host = parts[0]
#             port = int(parts[1]) if len(parts) > 1 else 11211
#
#             return host, port
#         except Exception as e:
#             raise ConfigurationError(f"Failed to discover Memcache endpoint: {str(e)}")
#
#     def _create_memcache_instance(self) -> Any:
#         """Create a new Memcache instance."""
#         try:
#             client = memcache_v1.CloudMemcacheClient()
#             parent = f"projects/{self.project_id}/locations/{self.region}"
#
#             # Define instance configuration
#             instance = {
#                 "name": f"{parent}/instances/{self.instance_id}",
#                 "node_count": self.node_count,
#                 "node_config": {
#                     "cpu_count": self.node_cpu,
#                     "memory_size_mb": self.node_memory_gb * 1024,
#                 }
#             }
#
#             # Create the instance using proper request pattern
#             request = memcache_v1.CreateInstanceRequest(
#                 parent=parent,
#                 instance_id=self.instance_id,
#                 instance=instance
#             )
#             operation = client.create_instance(request=request)
#
#             logging.info(f"Creating Memcache instance {self.instance_id}...")
#             result = operation.result()  # Wait for completion
#             logging.info(f"Memcache instance created: {result.name}")
#
#             return result
#         except Exception as e:
#             raise ConfigurationError(f"Failed to create Memcache instance: {str(e)}")
#
#     # Rest of the methods remain unchanged
#
#     def _sanitize_key(self, key: str) -> str:
#         """
#         Sanitize a key for use with Memcached.
#         Memcached doesn't allow spaces or control characters in keys.
#         """
#         import base64
#         # Base64 encode the key to ensure it's valid for Memcached
#         # This is reversible and preserves uniqueness
#         sanitized = base64.b64encode(key.encode('utf-8')).decode('ascii')
#         return sanitized
#
#     def _desanitize_key(self, sanitized_key: str) -> str:
#         """Convert a sanitized key back to the original."""
#         import base64
#         try:
#             return base64.b64decode(sanitized_key.encode('ascii')).decode('utf-8')
#         except:
#             return sanitized_key  # Return as is if not base64 encoded
#
#     def get(self, key: str) -> Optional[str]:
#         """Get a value from Memcache."""
#         try:
#             sanitized_key = self._sanitize_key(key)
#             value = self.client.get(sanitized_key)
#             if value is None:
#                 return None
#
#             # Convert bytes to string if needed
#             if isinstance(value, bytes):
#                 value = value.decode('utf-8')
#
#             return value
#         except Exception as e:
#             logging.warning(f"Memcache get error: {str(e)}")
#             return None
#
#     def put(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
#         """Put a value in Memcache."""
#         try:
#             sanitized_key = self._sanitize_key(key)
#             expiry = ttl if ttl is not None else self.default_ttl
#             return self.client.set(sanitized_key, value, time=expiry)
#         except Exception as e:
#             logging.warning(f"Memcache put error: {str(e)}")
#             return False
#
#     def delete(self, key: str) -> bool:
#         """Delete a key from Memcache."""
#         try:
#             sanitized_key = self._sanitize_key(key)
#             return self.client.delete(sanitized_key)
#         except Exception as e:
#             logging.warning(f"Memcache delete error: {str(e)}")
#             return False
#
#     def batch_get(self, keys: List[str]) -> Dict[str, str]:
#         """Get multiple keys at once."""
#         try:
#             # Sanitize all keys
#             sanitized_keys = [self._sanitize_key(k) for k in keys]
#
#             # Create a mapping from sanitized keys back to original keys
#             sanitized_to_original = {self._sanitize_key(k): k for k in keys}
#
#             # Get values using sanitized keys
#             sanitized_values = self.client.get_multi(sanitized_keys)
#
#             # Convert back to original keys
#             result = {}
#             for sanitized_key, value in sanitized_values.items():
#                 original_key = sanitized_to_original.get(sanitized_key)
#                 if original_key:
#                     if isinstance(value, bytes):
#                         result[original_key] = value.decode('utf-8')
#                     else:
#                         result[original_key] = value
#
#             return result
#         except Exception as e:
#             logging.warning(f"Memcache batch_get error: {str(e)}")
#             return {}
#
#     def batch_put(self, key_values: Dict[str, str], ttl: Optional[int] = None) -> bool:
#         """Put multiple key-value pairs at once."""
#         try:
#             # Sanitize all keys
#             sanitized_dict = {self._sanitize_key(k): v for k, v in key_values.items()}
#
#             expiry = ttl if ttl is not None else self.default_ttl
#             return self.client.set_multi(sanitized_dict, time=expiry)
#         except Exception as e:
#             logging.warning(f"Memcache batch_put error: {str(e)}")
#             return False
#
#     # def get(self, key: str) -> Optional[str]:
#     #     """Get a value from Memcache."""
#     #     try:
#     #         value = self.client.get(key)
#     #         if value is None:
#     #             return None
#     #
#     #         # Convert bytes to string if needed
#     #         if isinstance(value, bytes):
#     #             value = value.decode('utf-8')
#     #
#     #         return value
#     #     except Exception as e:
#     #         logging.warning(f"Memcache get error: {str(e)}")
#     #         return None
#     #
#     # def put(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
#     #     """Put a value in Memcache."""
#     #     try:
#     #         expiry = ttl if ttl is not None else self.default_ttl
#     #         return self.client.set(key, value, time=expiry)
#     #     except Exception as e:
#     #         logging.warning(f"Memcache put error: {str(e)}")
#     #         return False
#     #
#     # def delete(self, key: str) -> bool:
#     #     """Delete a key from Memcache."""
#     #     try:
#     #         return self.client.delete(key)
#     #     except Exception as e:
#     #         logging.warning(f"Memcache delete error: {str(e)}")
#     #         return False
#     #
#     # def clear(self) -> None:
#     #     """Clear all items from Memcache (flush)."""
#     #     try:
#     #         self.client.flush_all()
#     #     except Exception as e:
#     #         logging.warning(f"Memcache clear error: {str(e)}")
#     #
#     # def batch_get(self, keys: List[str]) -> Dict[str, str]:
#     #     """Get multiple keys at once."""
#     #     try:
#     #         values = self.client.get_multi(keys)
#     #
#     #         # Convert bytes to strings if needed
#     #         result = {}
#     #         for key, value in values.items():
#     #             if isinstance(value, bytes):
#     #                 result[key] = value.decode('utf-8')
#     #             else:
#     #                 result[key] = value
#     #
#     #         return result
#     #     except Exception as e:
#     #         logging.warning(f"Memcache batch_get error: {str(e)}")
#     #         return {}
#     #
#     # def batch_put(self, key_values: Dict[str, str], ttl: Optional[int] = None) -> bool:
#     #     """Put multiple key-value pairs at once."""
#     #     try:
#     #         expiry = ttl if ttl is not None else self.default_ttl
#     #         return self.client.set_multi(key_values, time=expiry)
#     #     except Exception as e:
#     #         logging.warning(f"Memcache batch_put error: {str(e)}")
#     #         return False
#
#     def get_stats(self) -> Dict[str, Any]:
#         """Get Memcache statistics."""
#         try:
#             stats = self.client.get_stats()
#             if stats:
#                 # Extract relevant stats from the first server
#                 server_stats = stats[0][1]  # (server, stats_dict)
#                 return {
#                     "type": "memcache",
#                     "host": self.host,
#                     "port": self.port,
#                     "curr_items": int(server_stats.get(b'curr_items', 0)),
#                     "get_hits": int(server_stats.get(b'get_hits', 0)),
#                     "get_misses": int(server_stats.get(b'get_misses', 0)),
#                     "total_items": int(server_stats.get(b'total_items', 0)),
#                     "bytes": int(server_stats.get(b'bytes', 0)),
#                     "limit_maxbytes": int(server_stats.get(b'limit_maxbytes', 0)),
#                     "evictions": int(server_stats.get(b'evictions', 0)),
#                     "default_ttl": self.default_ttl
#                 }
#             return {
#                 "type": "memcache",
#                 "host": self.host,
#                 "port": self.port,
#                 "default_ttl": self.default_ttl,
#                 "error": "No stats available"
#             }
#         except Exception as e:
#             return {
#                 "type": "memcache",
#                 "host": self.host,
#                 "port": self.port,
#                 "default_ttl": self.default_ttl,
#                 "error": str(e)
#             }
#
#     def health_check(self) -> bool:
#         """Check if Memcache is available and working."""
#         try:
#             # Try to set and get a test value
#             test_key = "_health_check_"
#             test_value = "ok"
#
#             success = self.client.set(test_key, test_value)
#             if not success:
#                 return False
#
#             value = self.client.get(test_key)
#             if value != test_value:
#                 return False
#
#             return True
#         except Exception:
#             return False






# from typing import Optional, Dict, Any, List, Tuple
# import time
# import json
# import logging
# import subprocess
# import threading
# from concurrent.futures import ThreadPoolExecutor
#
# try:
#     import memcache
#     from google.cloud import service_usage_v1
#     from google.cloud import memcache_v1
#     from google.api_core.exceptions import NotFound, PermissionDenied
#
#     MEMCACHE_AVAILABLE = True
# except ImportError:
#     MEMCACHE_AVAILABLE = False
#
# from .base import CacheAdapter
# from ..common import ServiceNotEnabledError, ConfigurationError
#
#
# class MemcacheAdapter(CacheAdapter):
#     """Google Cloud Memcache adapter."""
#
#     def __init__(
#             self,
#             project_id: str,
#             host: Optional[str] = None,
#             port: int = 11211,
#             instance_id: Optional[str] = None,
#             region: str = "us-central1",
#             create_if_missing: bool = False,
#             node_count: int = 1,
#             node_cpu: int = 1,
#             node_memory_gb: int = 1,
#             default_ttl: int = 3600,
#             check_service: bool = True
#     ):
#         """
#         Initialize Google Cloud Memcache adapter.
#
#         Args:
#             project_id: Google Cloud project ID
#             host: Memcache host IP (required if instance_id not provided)
#             port: Memcache port (default: 11211)
#             instance_id: Memcache instance ID for auto-discovery (if host not provided)
#             region: Google Cloud region for Memcache instance
#             create_if_missing: Whether to create a new instance if one doesn't exist
#             node_count: Number of nodes if creating a new instance
#             node_cpu: CPU count per node if creating a new instance
#             node_memory_gb: Memory in GB per node if creating a new instance
#             default_ttl: Default time-to-live in seconds
#             check_service: Whether to check if Memcache service is enabled
#         """
#         if not MEMCACHE_AVAILABLE:
#             raise ImportError("Memcache functionality requires python-memcached and google-cloud-memcache packages")
#
#         self.project_id = project_id
#         self.instance_id = instance_id
#         self.region = region
#         self.create_if_missing = create_if_missing
#         self.node_count = node_count
#         self.node_cpu = node_cpu
#         self.node_memory_gb = node_memory_gb
#         self.default_ttl = default_ttl
#
#         # Check if Memcache service is enabled
#         if check_service:
#             self._check_memcache_service()
#
#         # Initialize client with provided host:port or discover from instance
#         if host:
#             self.host = host
#             self.port = port
#             self.client = memcache.Client([(host, port)], debug=0)
#         elif instance_id:
#             # Get host:port from instance ID
#             self.host, self.port = self._discover_memcache_endpoint()
#             self.client = memcache.Client([(self.host, self.port)], debug=0)
#         else:
#             raise ConfigurationError("Either host or instance_id must be provided")
#
#         # Verify connection
#         if not self.health_check():
#             raise ConfigurationError("Could not connect to Memcache instance")
#
#     def _check_memcache_service(self) -> None:
#         """Check if Memcache service is enabled."""
#         try:
#             client = service_usage_v1.ServiceUsageClient()
#             name = f"projects/{self.project_id}/services/memcache.googleapis.com"
#             response = client.get_service(name=name)
#
#             if response.state != service_usage_v1.State.ENABLED:
#                 if self.create_if_missing:
#                     self._enable_memcache_service()
#                 else:
#                     raise ServiceNotEnabledError(
#                         "Memcache service is not enabled. "
#                         "Enable it with 'gcloud services enable memcache.googleapis.com'"
#                     )
#         except NotFound:
#             if self.create_if_missing:
#                 self._enable_memcache_service()
#             else:
#                 raise ServiceNotEnabledError("Memcache service is not enabled")
#         except PermissionDenied:
#             logging.warning(
#                 "Insufficient permissions to check Memcache service. "
#                 "Assuming it's enabled."
#             )
#
#     def _enable_memcache_service(self) -> None:
#         """Enable Memcache service."""
#         try:
#             result = subprocess.run(
#                 ["gcloud", "services", "enable", "memcache.googleapis.com",
#                  f"--project={self.project_id}"],
#                 capture_output=True,
#                 text=True
#             )
#             if result.returncode != 0:
#                 raise ServiceNotEnabledError(
#                     f"Failed to enable Memcache service: {result.stderr}"
#                 )
#             logging.info("Successfully enabled Memcache service")
#         except Exception as e:
#             raise ServiceNotEnabledError(f"Failed to enable Memcache service: {str(e)}")
#
#     def _discover_memcache_endpoint(self) -> Tuple[str, int]:
#         """Discover Memcache endpoint from instance ID."""
#         try:
#             client = memcache_v1.CloudMemcacheClient()
#             name = f"projects/{self.project_id}/locations/{self.region}/instances/{self.instance_id}"
#
#             try:
#                 instance = client.get_instance(name=name)
#             except NotFound:
#                 if self.create_if_missing:
#                     instance = self._create_memcache_instance()
#                 else:
#                     raise ConfigurationError(
#                         f"Memcache instance {self.instance_id} not found "
#                         f"in project {self.project_id}, region {self.region}"
#                     )
#
#             # Get the discovery endpoint
#             discovery_endpoint = instance.discovery_endpoint
#             if not discovery_endpoint:
#                 # If no discovery endpoint, use the first node's IP
#                 if instance.nodes:
#                     host = instance.nodes[0].host
#                     port = 11211  # Default Memcache port
#                     return host, port
#
#             # Parse the discovery endpoint (typically host:port format)
#             parts = discovery_endpoint.split(':')
#             host = parts[0]
#             port = int(parts[1]) if len(parts) > 1 else 11211
#
#             return host, port
#         except Exception as e:
#             raise ConfigurationError(f"Failed to discover Memcache endpoint: {str(e)}")
#
#     def _create_memcache_instance(self) -> Any:
#         """Create a new Memcache instance."""
#         try:
#             client = memcache_v1.CloudMemcacheClient()
#             parent = f"projects/{self.project_id}/locations/{self.region}"
#
#             # Define instance configuration
#             instance = {
#                 "name": f"{parent}/instances/{self.instance_id}",
#                 "node_count": self.node_count,
#                 "node_config": {
#                     "cpu_count": self.node_cpu,
#                     "memory_size_mb": self.node_memory_gb * 1024,
#                 }
#             }
#
#             # Create the instance
#             operation = client.create_instance(
#                 parent=parent,
#                 instance_id=self.instance_id,
#                 instance=instance
#             )
#
#             logging.info(f"Creating Memcache instance {self.instance_id}...")
#             result = operation.result()  # Wait for completion
#             logging.info(f"Memcache instance created: {result.name}")
#
#             return result
#         except Exception as e:
#             raise ConfigurationError(f"Failed to create Memcache instance: {str(e)}")
#
#     def get(self, key: str) -> Optional[str]:
#         """Get a value from Memcache."""
#         try:
#             value = self.client.get(key)
#             if value is None:
#                 return None
#
#             # Convert bytes to string if needed
#             if isinstance(value, bytes):
#                 value = value.decode('utf-8')
#
#             return value
#         except Exception as e:
#             logging.warning(f"Memcache get error: {str(e)}")
#             return None
#
#     def put(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
#         """Put a value in Memcache."""
#         try:
#             expiry = ttl if ttl is not None else self.default_ttl
#             return self.client.set(key, value, time=expiry)
#         except Exception as e:
#             logging.warning(f"Memcache put error: {str(e)}")
#             return False
#
#     def delete(self, key: str) -> bool:
#         """Delete a key from Memcache."""
#         try:
#             return self.client.delete(key)
#         except Exception as e:
#             logging.warning(f"Memcache delete error: {str(e)}")
#             return False
#
#     def clear(self) -> None:
#         """Clear all items from Memcache (flush)."""
#         try:
#             self.client.flush_all()
#         except Exception as e:
#             logging.warning(f"Memcache clear error: {str(e)}")
#
#     def batch_get(self, keys: List[str]) -> Dict[str, str]:
#         """Get multiple keys at once."""
#         try:
#             values = self.client.get_multi(keys)
#
#             # Convert bytes to strings if needed
#             result = {}
#             for key, value in values.items():
#                 if isinstance(value, bytes):
#                     result[key] = value.decode('utf-8')
#                 else:
#                     result[key] = value
#
#             return result
#         except Exception as e:
#             logging.warning(f"Memcache batch_get error: {str(e)}")
#             return {}
#
#     def batch_put(self, key_values: Dict[str, str], ttl: Optional[int] = None) -> bool:
#         """Put multiple key-value pairs at once."""
#         try:
#             expiry = ttl if ttl is not None else self.default_ttl
#             return self.client.set_multi(key_values, time=expiry)
#         except Exception as e:
#             logging.warning(f"Memcache batch_put error: {str(e)}")
#             return False
#
#     def get_stats(self) -> Dict[str, Any]:
#         """Get Memcache statistics."""
#         try:
#             stats = self.client.get_stats()
#             if stats:
#                 # Extract relevant stats from the first server
#                 server_stats = stats[0][1]  # (server, stats_dict)
#                 return {
#                     "type": "memcache",
#                     "host": self.host,
#                     "port": self.port,
#                     "curr_items": int(server_stats.get(b'curr_items', 0)),
#                     "get_hits": int(server_stats.get(b'get_hits', 0)),
#                     "get_misses": int(server_stats.get(b'get_misses', 0)),
#                     "total_items": int(server_stats.get(b'total_items', 0)),
#                     "bytes": int(server_stats.get(b'bytes', 0)),
#                     "limit_maxbytes": int(server_stats.get(b'limit_maxbytes', 0)),
#                     "evictions": int(server_stats.get(b'evictions', 0)),
#                     "default_ttl": self.default_ttl
#                 }
#             return {
#                 "type": "memcache",
#                 "host": self.host,
#                 "port": self.port,
#                 "default_ttl": self.default_ttl,
#                 "error": "No stats available"
#             }
#         except Exception as e:
#             return {
#                 "type": "memcache",
#                 "host": self.host,
#                 "port": self.port,
#                 "default_ttl": self.default_ttl,
#                 "error": str(e)
#             }
#
#     def health_check(self) -> bool:
#         """Check if Memcache is available and working."""
#         try:
#             # Try to set and get a test value
#             test_key = "_health_check_"
#             test_value = "ok"
#
#             success = self.client.set(test_key, test_value)
#             if not success:
#                 return False
#
#             value = self.client.get(test_key)
#             if value != test_value:
#                 return False
#
#             return True
#         except Exception:
#             return False