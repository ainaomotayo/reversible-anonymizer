from typing import Optional, Dict, Any, Tuple, TypedDict, List
from collections import OrderedDict
import time


class AnonymizationResult(TypedDict):
    """Type definition for detailed anonymization result."""
    anonymized_text: str
    findings: List[Dict[str, Any]]
    stats: Dict[str, Any]
    run_id: str


class LRUCache:
    """LRU (Least Recently Used) cache implementation."""

    def __init__(self, capacity: int = 1000, ttl: int = 3600):
        """
        Initialize LRU cache.

        Args:
            capacity: Maximum number of items in cache
            ttl: Time-to-live in seconds (default: 1 hour)
        """
        self.capacity = capacity
        self.ttl = ttl
        self.cache: OrderedDict[Any, Tuple[Any, float]] = OrderedDict()

    def get(self, key: Any) -> Optional[Any]:
        """Get a value from the cache."""
        if key not in self.cache:
            return None

        value, timestamp = self.cache[key]

        # Check if item has expired
        if time.time() - timestamp > self.ttl:
            self.cache.pop(key)
            return None

        # Move to end (most recently used)
        self.cache.move_to_end(key)
        return value

    def put(self, key: Any, value: Any) -> None:
        """Add a value to the cache."""
        if key in self.cache:
            self.cache.pop(key)
        elif len(self.cache) >= self.capacity:
            # Remove least recently used item
            self.cache.popitem(last=False)

        self.cache[key] = (value, time.time())

    def invalidate(self, key: Any) -> bool:
        """Remove a key from the cache."""
        if key in self.cache:
            self.cache.pop(key)
            return True
        return False

    def clear(self) -> None:
        """Clear all items from the cache."""
        self.cache.clear()

    def __len__(self) -> int:
        """Return the number of items in the cache."""
        return len(self.cache)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        valid_items = 0
        expired_items = 0

        current_time = time.time()
        for _, (_, timestamp) in self.cache.items():
            if current_time - timestamp <= self.ttl:
                valid_items += 1
            else:
                expired_items += 1

        return {
            "total_items": len(self.cache),
            "valid_items": valid_items,
            "expired_items": expired_items,
            "capacity": self.capacity,
            "ttl": self.ttl,
            "usage_percent": (len(self.cache) / self.capacity) * 100 if self.capacity > 0 else 0
        }





# # src/reversible_anonymizer/models.py
# from typing import Optional, Dict, Any, Tuple, TypedDict, List
# from collections import OrderedDict
# import time
#
# class AnonymizationResult(TypedDict):
#     """Type definition for detailed anonymization result."""
#     anonymized_text: str
#     findings: List[Dict[str, Any]]
#     stats: Dict[str, Any]
#     run_id: str
#
# class LRUCache:
#     """LRU (Least Recently Used) cache implementation."""
#
#     def __init__(self, capacity: int = 1000, ttl: int = 3600):
#         """
#         Initialize LRU cache.
#
#         Args:
#             capacity: Maximum number of items in cache
#             ttl: Time-to-live in seconds (default: 1 hour)
#         """
#         self.capacity = capacity
#         self.ttl = ttl
#         self.cache: OrderedDict[Any, Tuple[Any, float]] = OrderedDict()
#
#     def get(self, key: Any) -> Optional[Any]:
#         """Get a value from the cache."""
#         if key not in self.cache:
#             return None
#
#         value, timestamp = self.cache[key]
#
#         # Check if item has expired
#         if time.time() - timestamp > self.ttl:
#             self.cache.pop(key)
#             return None
#
#         # Move to end (most recently used)
#         self.cache.move_to_end(key)
#         return value
#
#     def put(self, key: Any, value: Any) -> None:
#         """Add a value to the cache."""
#         if key in self.cache:
#             self.cache.pop(key)
#         elif len(self.cache) >= self.capacity:
#             # Remove least recently used item
#             self.cache.popitem(last=False)
#
#         self.cache[key] = (value, time.time())
#
#     def invalidate(self, key: Any) -> bool:
#         """Remove a key from the cache."""
#         if key in self.cache:
#             self.cache.pop(key)
#             return True
#         return False
#
#     def clear(self) -> None:
#         """Clear all items from the cache."""
#         self.cache.clear()
#
#     def __len__(self) -> int:
#         """Return the number of items in the cache."""
#         return len(self.cache)
#
#     def get_stats(self) -> Dict[str, Any]:
#         """Get cache statistics."""
#         valid_items = 0
#         expired_items = 0
#
#         current_time = time.time()
#         for _, (_, timestamp) in self.cache.items():
#             if current_time - timestamp <= self.ttl:
#                 valid_items += 1
#             else:
#                 expired_items += 1
#
#         return {
#             "total_items": len(self.cache),
#             "valid_items": valid_items,
#             "expired_items": expired_items,
#             "capacity": self.capacity,
#             "ttl": self.ttl,
#             "usage_percent": (len(self.cache) / self.capacity) * 100 if self.capacity > 0 else 0
#         }