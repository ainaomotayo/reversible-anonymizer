from reversible_anonymizer import ReversibleAnonymizer


# Initialize with Memcache
def test_memcache_anonymizer():
    # Initialize with Memcache
    anonymizer = ReversibleAnonymizer(
        project="your-project-id",
        # Standard options
        info_types=["PERSON_NAME", "EMAIL_ADDRESS", "PHONE_NUMBER"],
        use_realistic_fake_data=True,
        # Cache configuration
        cache_type="memcache",
        cache_config={
            "instance_id": "anonymizer-cache",  # Instance name in Google Cloud
            "region": "us-central1",
            # Or directly use host/port if you know them:
            # "host": "10.123.45.67",
            # "port": 11211,
            "create_if_missing": True,  # Auto-create the instance if it doesn't exist
            "ttl": 86400  # 24 hours cache TTL
        },
        # Enable async storage updates for better performance
        async_storage_updates=True
    )

    # Example text with sensitive information
    text = """
    Hello, my name is John Smith and I live at 123 Main Street.
    My email is john.smith@example.com and my phone number is (555) 123-4567.
    """

    # Anonymize with detailed results
    result = anonymizer.anonymize(text, detailed_result=True)
    print(f"Anonymized text: {result['anonymized_text']}")
    print(f"Cache stats: {result['stats']['cache_status']}")

    # Process multiple texts to demonstrate cache reuse
    texts = [
        "John Smith has been our customer for 3 years.",
        "Please forward this document to john.smith@example.com.",
        "Call John at (555) 123-4567 for more information."
    ]

    for i, text in enumerate(texts):
        print(f"\nProcessing text {i + 1}:")
        result = anonymizer.anonymize(text, detailed_result=True)
        print(f"Anonymized: {result['anonymized_text']}")
        print(f"Cache hits: {result['stats']['cache_hits']}")
        print(f"Storage hits: {result['stats']['storage_hits']}")
        print(f"New generations: {result['stats']['new_generations']}")


if __name__ == "__main__":
    test_memcache_anonymizer()