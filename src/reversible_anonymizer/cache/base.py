from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List


class CacheAdapter(ABC):
    """Base cache adapter interface for anonymization mappings."""

    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """Get a value from cache."""
        pass

    @abstractmethod
    def put(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Put a value in cache with optional TTL in seconds."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all items from the cache."""
        pass

    @abstractmethod
    def batch_get(self, keys: List[str]) -> Dict[str, str]:
        """Get multiple keys at once. Returns a dictionary of found keys."""
        pass

    @abstractmethod
    def batch_put(self, key_values: Dict[str, str], ttl: Optional[int] = None) -> bool:
        """Put multiple key-value pairs at once."""
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check if cache is available and working."""
        pass