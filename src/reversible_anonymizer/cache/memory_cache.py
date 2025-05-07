from typing import Optional, Dict, Any, List, Tuple
import time
from collections import OrderedDict

from .base import CacheAdapter


class MemoryCacheAdapter(CacheAdapter):
    """In-memory cache adapter using LRU strategy."""

    def __init__(self, capacity: int = 1000, default_ttl: int = 3600):
        """
        Initialize LRU cache.

        Args:
            capacity: Maximum number of items in cache
            default_ttl: Default time-to-live in seconds (default: 1 hour)
        """
        self.capacity = capacity
        self.default_ttl = default_ttl
        self.cache: OrderedDict[str, Tuple[str, float]] = OrderedDict()

    def get(self, key: str) -> Optional[str]:
        """Get a value from the cache."""
        if key not in self.cache:
            return None

        value, timestamp = self.cache[key]

        # Check if item has expired
        if time.time() - timestamp > self.default_ttl:
            self.cache.pop(key)
            return None

        # Move to end (most recently used)
        self.cache.move_to_end(key)
        return value

    def put(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Put a value in the cache."""
        try:
            if key in self.cache:
                self.cache.pop(key)
            elif len(self.cache) >= self.capacity:
                # Remove least recently used item
                self.cache.popitem(last=False)

            self.cache[key] = (value, time.time())
            return True
        except Exception:
            return False

    def delete(self, key: str) -> bool:
        """Remove a key from the cache."""
        if key in self.cache:
            self.cache.pop(key)
            return True
        return False

    def clear(self) -> None:
        """Clear all items from the cache."""
        self.cache.clear()

    def batch_get(self, keys: List[str]) -> Dict[str, str]:
        """Get multiple keys at once."""
        result = {}
        for key in keys:
            value = self.get(key)
            if value is not None:
                result[key] = value
        return result

    def batch_put(self, key_values: Dict[str, str], ttl: Optional[int] = None) -> bool:
        """Put multiple key-value pairs at once."""
        try:
            for key, value in key_values.items():
                self.put(key, value, ttl)
            return True
        except Exception:
            return False

    def __len__(self) -> int:
        """Return the number of items in the cache."""
        return len(self.cache)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        valid_items = 0
        expired_items = 0

        current_time = time.time()
        for _, (_, timestamp) in self.cache.items():
            if current_time - timestamp <= self.default_ttl:
                valid_items += 1
            else:
                expired_items += 1

        return {
            "type": "memory",
            "total_items": len(self.cache),
            "valid_items": valid_items,
            "expired_items": expired_items,
            "capacity": self.capacity,
            "ttl": self.default_ttl,
            "usage_percent": (len(self.cache) / self.capacity) * 100 if self.capacity > 0 else 0
        }

    def health_check(self) -> bool:
        """Check if cache is available and working."""
        return True  # In-memory cache is always available