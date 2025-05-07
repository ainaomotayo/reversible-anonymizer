"""Example usage of the ReversibleAnonymizer package."""
from reversible_anonymizer import ReversibleAnonymizer
import json


def basic_usage():
    """Demonstrate basic usage of the anonymizer."""
    try:
        # Initialize with default settings (uses realistic fake data)
        anonymizer = ReversibleAnonymizer(project="your-project-id")

        # Sample text with sensitive information
        text = """
        Hello, my name is John Smith and I live at 123 Main Street, New York.
        You can reach me at john.smith@example.com or call me at (555) 123-4567.
        My SSN is 123-45-6789 and my credit card number is 4111-1111-1111-1111.
        """

        print("Original text:", text)

        # Anonymize text
        anonymized = anonymizer.anonymize(text)
        print("\nAnonymized text (with realistic fake data):", anonymized)

        # De-anonymize text
        deanonymized = anonymizer.deanonymize(anonymized)
        print("\nDe-anonymized text:", deanonymized)

    except Exception as e:
        print(f"Error: {str(e)}")


def advanced_usage():
    """Demonstrate advanced usage with custom settings."""
    try:
        # Initialize with custom settings
        anonymizer = ReversibleAnonymizer(
            project="your-project-id",
            info_types=["PERSON_NAME", "EMAIL_ADDRESS", "PHONE_NUMBER",
                        "US_SOCIAL_SECURITY_NUMBER", "CREDIT_CARD_NUMBER", "STREET_ADDRESS"],
            collection_name="custom_mappings",
            location="us-central1",
            cache_size=5000,
            mode="strict",
            encryption_key="your-encryption-key",  # For secure storage
            use_realistic_fake_data=True  # Use Faker to generate realistic data (default)
        )

        # Sample text with sensitive information
        text = """
        Hello, my name is John Smith and I live at 123 Main Street, New York.
        You can reach me at john.smith@example.com or call me at (555) 123-4567.
        My SSN is 123-45-6789 and my credit card number is 4111-1111-1111-1111.
        """

        # Anonymize with detailed results
        result = anonymizer.anonymize(text, detailed_result=True)
        print("Anonymization result:")
        print(json.dumps(result, indent=2))

        # Batch processing
        texts = [
            "My name is John Smith",
            "My email is john.smith@example.com",
            "My phone is (555) 123-4567"
        ]

        anonymized_batch = anonymizer.anonymize_batch(texts)
        print("\nBatch anonymization results:")
        for i, anon_text in enumerate(anonymized_batch):
            print(f"  {i + 1}. {anon_text}")

        # Show available info types
        print("\nAvailable info type categories:")
        for category in anonymizer.get_categories():
            print(f"  - {category}")

    except Exception as e:
        print(f"Error: {str(e)}")


def compare_faker_vs_token():
    """Compare realistic faker-generated data vs token-based fake data."""
    try:
        # Sample text with sensitive information
        text = """
        Hello, my name is Jane Smith. My email is jane.smith@example.com.
        My phone number is 555-123-4567 and my credit card is 4111-1111-1111-1111.
        """

        # Create anonymizer with realistic fake data (default)
        print("=== Using Realistic Fake Data ===")
        faker_anonymizer = ReversibleAnonymizer(
            project="your-project-id",
            check_services=False,
            storage_type="memory",
            use_realistic_fake_data=True
        )

        anonymized_realistic = faker_anonymizer.anonymize(text)
        print(f"Anonymized text:\n{anonymized_realistic}\n")

        # Create anonymizer with token-based fake data
        print("\n=== Using Token-Based Fake Data ===")
        token_anonymizer = ReversibleAnonymizer(
            project="your-project-id",
            check_services=False,
            storage_type="memory",
            use_realistic_fake_data=False
        )

        anonymized_token = token_anonymizer.anonymize(text)
        print(f"Anonymized text:\n{anonymized_token}\n")

        # Both should deanonymize correctly
        print("\nBoth approaches support full deanonymization:")
        print(
            f"Realistic deanonymization matches original: {faker_anonymizer.deanonymize(anonymized_realistic) == text}")
        print(f"Token-based deanonymization matches original: {token_anonymizer.deanonymize(anonymized_token) == text}")

    except Exception as e:
        print(f"Error: {str(e)}")


def environment_configuration():
    """Demonstrate configuration from environment variables."""
    import os

    # Set environment variables
    os.environ["ANONYMIZER_PROJECT"] = "your-project-id"
    os.environ["ANONYMIZER_INFO_TYPES"] = "PERSON_NAME,EMAIL_ADDRESS,PHONE_NUMBER"
    os.environ["ANONYMIZER_COLLECTION"] = "env_mappings"
    os.environ["ANONYMIZER_MODE"] = "tolerant"
    # Configure faker options
    os.environ["ANONYMIZER_USE_REALISTIC_FAKE_DATA"] = "true"
    os.environ["ANONYMIZER_FAKER_LOCALE"] = "en_US"
    os.environ["ANONYMIZER_FAKER_SEED"] = "123456"  # For reproducible fake data

    try:
        # Create anonymizer from environment variables
        anonymizer = ReversibleAnonymizer.from_config()

        # Use the anonymizer
        text = "My name is Jane Doe, email jane.doe@example.com"

        anonymized = anonymizer.anonymize(text)
        print("Anonymized text:", anonymized)

    except Exception as e:
        print(f"Error: {str(e)}")


def main():
    """Run all examples."""
    print("=== BASIC USAGE ===")
    basic_usage()

    print("\n\n=== ADVANCED USAGE ===")
    advanced_usage()

    print("\n\n=== FAKER VS TOKEN COMPARISON ===")
    compare_faker_vs_token()

    print("\n\n=== ENVIRONMENT CONFIGURATION ===")
    environment_configuration()


if __name__ == "__main__":
    main()




# """Example usage of the ReversibleAnonymizer package."""
# from reversible_anonymizer import ReversibleAnonymizer
# import json
#
#
# def basic_usage():
#     """Demonstrate basic usage of the anonymizer."""
#     try:
#         # Initialize with default settings
#         anonymizer = ReversibleAnonymizer(project="your-project-id")
#
#         # Sample text with sensitive information
#         text = """
#         Hello, my name is John Smith and I live at 123 Main Street, New York.
#         You can reach me at john.smith@example.com or call me at (555) 123-4567.
#         My SSN is 123-45-6789 and my credit card number is 4111-1111-1111-1111.
#         """
#
#         print("Original text:", text)
#
#         # Anonymize text
#         anonymized = anonymizer.anonymize(text)
#         print("\nAnonymized text:", anonymized)
#
#         # De-anonymize text
#         deanonymized = anonymizer.deanonymize(anonymized)
#         print("\nDe-anonymized text:", deanonymized)
#
#     except Exception as e:
#         print(f"Error: {str(e)}")
#
#
# def advanced_usage():
#     """Demonstrate advanced usage with custom settings."""
#     try:
#         # Initialize with custom settings
#         anonymizer = ReversibleAnonymizer(
#             project="your-project-id",
#             info_types=["PERSON_NAME", "EMAIL_ADDRESS", "PHONE_NUMBER",
#                         "US_SOCIAL_SECURITY_NUMBER", "CREDIT_CARD_NUMBER", "STREET_ADDRESS"],
#             collection_name="custom_mappings",
#             location="us-central1",
#             cache_size=5000,
#             mode="strict",
#             encryption_key="your-encryption-key"  # For secure storage
#         )
#
#         # Sample text with sensitive information
#         text = """
#         Hello, my name is John Smith and I live at 123 Main Street, New York.
#         You can reach me at john.smith@example.com or call me at (555) 123-4567.
#         My SSN is 123-45-6789 and my credit card number is 4111-1111-1111-1111.
#         """
#
#         # Anonymize with detailed results
#         result = anonymizer.anonymize(text, detailed_result=True)
#         print("Anonymization result:")
#         print(json.dumps(result, indent=2))
#
#         # Batch processing
#         texts = [
#             "My name is John Smith",
#             "My email is john.smith@example.com",
#             "My phone is (555) 123-4567"
#         ]
#
#         anonymized_batch = anonymizer.anonymize_batch(texts)
#         print("\nBatch anonymization results:")
#         for i, anon_text in enumerate(anonymized_batch):
#             print(f"  {i + 1}. {anon_text}")
#
#         # Show available info types
#         print("\nAvailable info type categories:")
#         for category in anonymizer.get_categories():
#             print(f"  - {category}")
#
#     except Exception as e:
#         print(f"Error: {str(e)}")
#
#
# def environment_configuration():
#     """Demonstrate configuration from environment variables."""
#     import os
#
#     # Set environment variables
#     os.environ["ANONYMIZER_PROJECT"] = "your-project-id"
#     os.environ["ANONYMIZER_INFO_TYPES"] = "PERSON_NAME,EMAIL_ADDRESS,PHONE_NUMBER"
#     os.environ["ANONYMIZER_COLLECTION"] = "env_mappings"
#     os.environ["ANONYMIZER_MODE"] = "tolerant"
#
#     try:
#         # Create anonymizer from environment variables
#         anonymizer = ReversibleAnonymizer.from_config()
#
#         # Use the anonymizer
#         text = "My name is Jane Doe, email jane.doe@example.com"
#
#         anonymized = anonymizer.anonymize(text)
#         print("Anonymized text:", anonymized)
#
#     except Exception as e:
#         print(f"Error: {str(e)}")
#
#
# def main():
#     """Run all examples."""
#     print("=== BASIC USAGE ===")
#     basic_usage()
#
#     print("\n\n=== ADVANCED USAGE ===")
#     advanced_usage()
#
#     print("\n\n=== ENVIRONMENT CONFIGURATION ===")
#     environment_configuration()
#
#
# if __name__ == "__main__":
#     main()