"""Storage adapters for anonymization mappings."""
from .base import StorageAdapter, MemoryAdapter
from .firestore_adapter import FirestoreAdapter
from .secure_firestore_adapter import SecureFirestoreAdapter

__all__ = [
    "StorageAdapter",
    "MemoryAdapter",
    "FirestoreAdapter",
    "SecureFirestoreAdapter"
]