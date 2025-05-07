from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
import time


class StorageAdapter(ABC):
    """Base storage adapter for anonymization mappings."""

    @abstractmethod
    def store_mapping(self, fake_data: str, original_data: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store a mapping between fake and original data."""
        pass

    @abstractmethod
    def get_original_data(self, fake_data: str) -> Optional[str]:
        """Retrieve original data for given fake data."""
        pass

    @abstractmethod
    def batch_store_mappings(self, mappings: Dict[str, str], metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store multiple mappings efficiently."""
        pass

    @abstractmethod
    def batch_get_originals(self, fake_data_list: List[str]) -> Dict[str, str]:
        """Retrieve multiple original values efficiently."""
        pass

    @abstractmethod
    def delete_mapping(self, fake_data: str) -> bool:
        """Delete a mapping."""
        pass

    @abstractmethod
    def get_all_mappings(self, limit: Optional[int] = None) -> Dict[str, str]:
        """Retrieve all mappings."""
        pass

    @abstractmethod
    def batch_get_fake_data_for_originals(self, original_data_list: List[str]) -> Dict[str, str]:
        """Retrieve fake data for given original values efficiently."""
        pass


class MemoryAdapter(StorageAdapter):
    """In-memory storage adapter for testing."""

    def __init__(self):
        """Initialize the in-memory storage."""
        self.mappings: Dict[str, Dict[str, Any]] = {}

    def store_mapping(self, fake_data: str, original_data: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store a mapping in memory."""
        self.mappings[fake_data] = {
            "original_data": original_data,
            "timestamp": time.time(),
            "metadata": metadata or {}
        }

    def get_original_data(self, fake_data: str) -> Optional[str]:
        """Retrieve original data from memory."""
        if fake_data in self.mappings:
            return self.mappings[fake_data]["original_data"]
        return None

    def batch_store_mappings(self, mappings: Dict[str, str], metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store multiple mappings in memory."""
        for fake_data, original_data in mappings.items():
            self.store_mapping(fake_data, original_data, metadata)

    def batch_get_originals(self, fake_data_list: List[str]) -> Dict[str, str]:
        """Retrieve multiple original values from memory."""
        return {
            fake_data: self.mappings[fake_data]["original_data"]
            for fake_data in fake_data_list
            if fake_data in self.mappings
        }

    def delete_mapping(self, fake_data: str) -> bool:
        """Delete a mapping from memory."""
        if fake_data in self.mappings:
            del self.mappings[fake_data]
            return True
        return False

    def get_all_mappings(self, limit: Optional[int] = None) -> Dict[str, str]:
        """Retrieve all mappings from memory."""
        result = {
            fake_data: data["original_data"]
            for fake_data, data in self.mappings.items()
        }

        if limit and len(result) > limit:
            items = list(result.items())[:limit]
            result = dict(items)

        return result


    def batch_get_fake_data_for_originals(self, original_data_list: List[str]) -> Dict[str, str]:
        """Retrieve fake data for given original values from memory."""
        result = {}

        # Build reverse index from original data to fake data
        original_to_fake = {}
        for fake_data, data in self.mappings.items():
            original_to_fake[data["original_data"]] = fake_data

        # Look up each original data
        for original_data in original_data_list:
            if original_data in original_to_fake:
                result[original_data] = original_to_fake[original_data]

        return result