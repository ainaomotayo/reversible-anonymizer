from reversible_anonymizer import ReversibleAnonymizer


def main():
    try:
        # Initialize anonymizer
        anonymizer = ReversibleAnonymizer(
            project="your-project-id",  # Replace with your GCP project ID
            info_types=[
                {"name": "PERSON_NAME"},
                {"name": "PHONE_NUMBER"}
            ]
        )

        # Test text
        original_text = "Hello, my name is John Doe. Call me at 123-456-7890"

        # Anonymize
        print("Original text:", original_text)
        anonymized_text = anonymizer.anonymize(original_text)
        print("Anonymized text:", anonymized_text)

        # De-anonymize
        recovered_text = anonymizer.deanonymize(anonymized_text)
        print("De-anonymized text:", recovered_text)

    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()