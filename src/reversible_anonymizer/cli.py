"""Command-line interface for the anonymizer."""
import argparse
import sys
import json
from typing import List, Optional
import os
from pathlib import Path

# Import the main package components
# Note: This assumes the package is properly installed
from reversible_anonymizer import (
    ReversibleAnonymizer,
    InfoTypeCatalog,
    InfoTypeCategory,
    AnonymizationError,
    DeAnonymizationError,
    ConfigurationError
)


def list_info_types(args) -> int:
    """List supported info types."""
    try:
        # Create anonymizer instance
        anonymizer = ReversibleAnonymizer(
            project=args.project,
            check_services=False
        )

        # Get info types by category if specified
        if args.category:
            try:
                info_types = anonymizer.get_infotypes_by_category(args.category)
                title = f"Info Types - Category: {args.category}"
            except ValueError:
                print(f"Error: Invalid category '{args.category}'")
                print("Available categories:")
                for cat in anonymizer.get_categories():
                    print(f"  - {cat}")
                return 1
        else:
            info_types = anonymizer.get_supported_infotypes()
            title = "All Supported Info Types"

        # Output in requested format
        if args.json:
            result = {
                "info_types": info_types,
                "category": args.category if args.category else "all",
                "count": len(info_types)
            }
            print(json.dumps(result, indent=2))
        else:
            print(f"\n{title}\n" + "=" * len(title))

            # Group by category if showing all
            if not args.category:
                by_category = {}
                for category in anonymizer.get_categories():
                    by_category[category] = anonymizer.get_infotypes_by_category(category)

                for category, types in by_category.items():
                    print(f"\n{category}:")
                    for info_type in sorted(types):
                        print(f"  - {info_type}")
            else:
                for info_type in sorted(info_types):
                    print(f"  - {info_type}")

            print(f"\nTotal: {len(info_types)} info types")

        return 0

    except Exception as e:
        print(f"Error: {str(e)}")
        return 1


def anonymize_text(args) -> int:
    """Anonymize text from input file or stdin."""
    try:
        # Read input text
        if args.input == "-":
            input_text = sys.stdin.read()
        else:
            with open(args.input, 'r', encoding='utf-8') as file:
                input_text = file.read()

        # Parse info types if specified
        info_types = None
        if args.info_types:
            info_types = [it.strip() for it in args.info_types.split(",")]

        # Create anonymizer
        anonymizer = ReversibleAnonymizer(
            project=args.project,
            info_types=info_types,
            mode="tolerant" if args.tolerant else "strict"
        )

        # Process text
        result = anonymizer.anonymize(input_text, detailed_result=args.json)

        # Write output
        if args.json:
            output = json.dumps(result, indent=2)
        else:
            output = result if isinstance(result, str) else result["anonymized_text"]

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as file:
                file.write(output)
        else:
            print(output)

        return 0

    except Exception as e:
        print(f"Error: {str(e)}")
        return 1


def deanonymize_text(args) -> int:
    """De-anonymize text from input file or stdin."""
    try:
        # Read input text
        if args.input == "-":
            input_text = sys.stdin.read()
        else:
            with open(args.input, 'r', encoding='utf-8') as file:
                input_text = file.read()

        # Create anonymizer
        anonymizer = ReversibleAnonymizer(
            project=args.project,
            mode="tolerant" if args.tolerant else "strict"
        )

        # Process text
        result = anonymizer.deanonymize(input_text)

        # Write output
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as file:
                file.write(result)
        else:
            print(result)

        return 0

    except Exception as e:
        print(f"Error: {str(e)}")
        return 1


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="ReversibleAnonymizer: A tool for text anonymization and de-anonymization"
    )

    parser.add_argument("--project", "-p", required=True,
                        help="Google Cloud project ID")
    parser.add_argument("--config", "-c",
                        help="Path to configuration file")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # List info types command
    list_parser = subparsers.add_parser("list-info-types",
                                        help="List supported info types")
    list_parser.add_argument("--category", help="Filter by category")
    list_parser.add_argument("--json", action="store_true",
                             help="Output in JSON format")

    # Anonymize command
    anonymize_parser = subparsers.add_parser("anonymize",
                                             help="Anonymize text")
    anonymize_parser.add_argument("--input", "-i", required=True,
                                  help="Input file path or - for stdin")
    anonymize_parser.add_argument("--output", "-o",
                                  help="Output file path (default: stdout)")
    anonymize_parser.add_argument("--info-types",
                                  help="Comma-separated list of info types")
    anonymize_parser.add_argument("--json", action="store_true",
                                  help="Return detailed JSON result")
    anonymize_parser.add_argument("--tolerant", action="store_true",
                                  help="Continue despite errors")

    # De-anonymize command
    deanonymize_parser = subparsers.add_parser("deanonymize",
                                               help="De-anonymize text")
    deanonymize_parser.add_argument("--input", "-i", required=True,
                                    help="Input file path or - for stdin")
    deanonymize_parser.add_argument("--output", "-o",
                                    help="Output file path (default: stdout)")
    deanonymize_parser.add_argument("--tolerant", action="store_true",
                                    help="Continue despite errors")

    # Parse arguments and execute
    args = parser.parse_args()

    if args.command == "list-info-types":
        return list_info_types(args)
    elif args.command == "anonymize":
        return anonymize_text(args)
    elif args.command == "deanonymize":
        return deanonymize_text(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())