from typing import Optional, Dict, List, Any
from google.cloud import firestore
from ..common import StorageError
from .base import StorageAdapter


class FirestoreAdapter(StorageAdapter):
    """Firestore storage adapter for anonymization mappings."""

    def __init__(
            self,
            project: str,
            collection_name: str,
    ):
        """Initialize the Firestore adapter."""
        self.db = firestore.Client(project=project)
        self.collection_name = collection_name

    def store_mapping(self, fake_data: str, original_data: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store a mapping in Firestore."""
        try:
            doc_ref = self.db.collection(self.collection_name).document(fake_data)
            data = {
                "original_data": original_data,
                "created_at": firestore.SERVER_TIMESTAMP,
                "metadata": metadata or {}
            }
            doc_ref.set(data)
        except Exception as e:
            raise StorageError(f"Failed to store mapping: {str(e)}")

    def get_original_data(self, fake_data: str) -> Optional[str]:
        """Retrieve original data from Firestore."""
        try:
            doc_ref = self.db.collection(self.collection_name).document(fake_data)
            doc = doc_ref.get()
            if doc.exists:
                data = doc.to_dict()
                return data.get("original_data")
            return None
        except Exception as e:
            raise StorageError(f"Failed to retrieve mapping: {str(e)}")

    def batch_store_mappings(self, mappings: Dict[str, str], metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store multiple mappings in Firestore using batched writes."""
        try:
            # Use batched writes for efficiency (Firestore limit: 500 operations per batch)
            batch = self.db.batch()
            count = 0

            for fake_data, original_data in mappings.items():
                doc_ref = self.db.collection(self.collection_name).document(fake_data)
                data = {
                    "original_data": original_data,
                    "created_at": firestore.SERVER_TIMESTAMP,
                    "metadata": metadata or {}
                }
                batch.set(doc_ref, data)
                count += 1

                # Commit when reaching batch limit
                if count >= 500:
                    batch.commit()
                    batch = self.db.batch()
                    count = 0

            # Commit any remaining operations
            if count > 0:
                batch.commit()
        except Exception as e:
            raise StorageError(f"Failed to store batch mappings: {str(e)}")

    def batch_get_originals(self, fake_data_list: List[str]) -> Dict[str, str]:
        """Retrieve multiple original values from Firestore efficiently."""
        result = {}
        try:
            # Process in chunks of 100 due to Firestore limitations
            for i in range(0, len(fake_data_list), 100):
                chunk = fake_data_list[i:i + 100]

                # Get all documents in one call
                refs = [self.db.collection(self.collection_name).document(fake_data) for fake_data in chunk]
                docs = self.db.get_all(refs)

                for doc in docs:
                    if doc.exists:
                        data = doc.to_dict()
                        result[doc.id] = data.get("original_data")

            return result
        except Exception as e:
            raise StorageError(f"Failed to retrieve batch mappings: {str(e)}")

    def delete_mapping(self, fake_data: str) -> bool:
        """Delete a mapping from Firestore."""
        try:
            doc_ref = self.db.collection(self.collection_name).document(fake_data)
            doc = doc_ref.get()
            if doc.exists:
                doc_ref.delete()
                return True
            return False
        except Exception as e:
            raise StorageError(f"Failed to delete mapping: {str(e)}")

    def get_all_mappings(self, limit: Optional[int] = None) -> Dict[str, str]:
        """Retrieve all mappings from Firestore."""
        try:
            query = self.db.collection(self.collection_name)
            if limit:
                query = query.limit(limit)

            docs = query.stream()

            result = {}
            for doc in docs:
                data = doc.to_dict()
                result[doc.id] = data.get("original_data")

            return result
        except Exception as e:
            raise StorageError(f"Failed to retrieve all mappings: {str(e)}")

    def batch_get_fake_data_for_originals(self, original_data_list: List[str]) -> Dict[str, str]:
        """Retrieve fake data for given original values from Firestore."""
        result = {}
        try:
            # Get chunks of original data to avoid query size limits
            for i in range(0, len(original_data_list), 10):
                chunk = original_data_list[i:i + 10]

                # Run a query to find documents with matching original_data
                query = self.db.collection(self.collection_name)

                # Use in operator for efficient querying
                query = query.where("original_data", "in", chunk)

                # Execute query
                docs = query.stream()

                # Process results
                for doc in docs:
                    data = doc.to_dict()
                    if "original_data" in data:
                        result[data["original_data"]] = doc.id

            return result
        except Exception as e:
            raise StorageError(f"Failed to retrieve mappings: {str(e)}")