import logging
from typing import Optional, Dict, List, Any
from .firestore_adapter import FirestoreAdapter


class SecureFirestoreAdapter(FirestoreAdapter):
    """Firestore adapter with encryption for sensitive mappings."""

    def __init__(
            self,
            project: str,
            collection_name: str,
            encryption_key: Optional[str] = None
    ):
        """Initialize the secure Firestore adapter with encryption."""
        super().__init__(project, collection_name)

        # Setup encryption if key is provided
        self.encryption_enabled = False
        if encryption_key:
            try:
                from cryptography.fernet import Fernet
                self.fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
                self.encryption_enabled = True
            except ImportError:
                logging.warning("cryptography package not found; encryption disabled")
            except Exception as e:
                logging.warning(f"Failed to initialize encryption: {str(e)}")

    def _encrypt(self, data: str) -> str:
        """Encrypt data if encryption is enabled."""
        if self.encryption_enabled:
            from cryptography.fernet import Fernet
            return self.fernet.encrypt(data.encode()).decode()
        return data

    def _decrypt(self, data: str) -> str:
        """Decrypt data if encryption is enabled."""
        if self.encryption_enabled:
            from cryptography.fernet import Fernet
            return self.fernet.decrypt(data.encode()).decode()
        return data

    def store_mapping(self, fake_data: str, original_data: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store mapping with encryption."""
        encrypted_data = self._encrypt(original_data)
        super().store_mapping(fake_data, encrypted_data, metadata)

    def get_original_data(self, fake_data: str) -> Optional[str]:
        """Retrieve and decrypt original data."""
        encrypted_data = super().get_original_data(fake_data)
        if encrypted_data:
            return self._decrypt(encrypted_data)
        return None

    def batch_store_mappings(self, mappings: Dict[str, str], metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store multiple mappings with encryption."""
        encrypted_mappings = {
            fake_data: self._encrypt(original_data)
            for fake_data, original_data in mappings.items()
        }
        super().batch_store_mappings(encrypted_mappings, metadata)

    def batch_get_originals(self, fake_data_list: List[str]) -> Dict[str, str]:
        """Retrieve and decrypt multiple original values."""
        encrypted_data = super().batch_get_originals(fake_data_list)
        return {
            fake_data: self._decrypt(data)
            for fake_data, data in encrypted_data.items()
        }

    def get_all_mappings(self, limit: Optional[int] = None) -> Dict[str, str]:
        """Retrieve and decrypt all mappings."""
        encrypted_data = super().get_all_mappings(limit)
        return {
            fake_data: self._decrypt(data)
            for fake_data, data in encrypted_data.items()
        }

    def batch_get_fake_data_for_originals(self, original_data_list: List[str]) -> Dict[str, str]:
        """Retrieve fake data for given original values, handling encrypted data."""
        # First, get all mappings
        all_mappings = self.get_all_mappings(limit=5000)

        # Create a reverse mapping
        reverse_map = {original: fake for fake, original in all_mappings.items()}

        # Look up each original data
        result = {}
        for original_data in original_data_list:
            if original_data in reverse_map:
                result[original_data] = reverse_map[original_data]

        return result