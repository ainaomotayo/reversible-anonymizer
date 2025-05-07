from typing import List, Dict, Tuple, Optional, Any
from ..common import InfoTypeCategory, InfoTypeNotSupportedError


class InfoTypeCatalog:
    """Complete catalog of Google DLP info types."""

    # Complete catalog of all Google DLP info types by category
    CATALOG = {
        InfoTypeCategory.PERSON: [
            "PERSON_NAME", "FIRST_NAME", "LAST_NAME", "EMAIL_ADDRESS",
            "PHONE_NUMBER", "AGE", "DATE_OF_BIRTH", "GENDER", "NATIONALITY",
            "MARRIAGE_STATUS"
        ],
        InfoTypeCategory.FINANCIAL: [
            "CREDIT_CARD_NUMBER", "IBAN_CODE", "US_BANK_ACCOUNT_NUMBER",
            "US_BANK_ROUTING_NUMBER", "SWIFT_CODE", "CURRENCY",
            "AMERICAN_BANKERS_CUSIP_ID", "CANADA_BANK_ACCOUNT",
            "FRANCE_TAX_IDENTIFICATION_NUMBER", "JAPAN_BANK_ACCOUNT",
            "UK_TAXPAYER_REFERENCE", "US_EMPLOYERS_IDENTIFICATION_NUMBER",
            "CRYPTO_CURRENCY_ADDRESS"
        ],
        InfoTypeCategory.HEALTH: [
            "MEDICAL_RECORD_NUMBER", "HEALTH_INSURANCE_CLAIM_NUMBER",
            "PATIENT_ID", "US_HEALTHCARE_NPI", "DEA_NUMBER", "PRESCRIPTION_ID",
            "MEDICAL_TERM", "MEDICAL_TREATMENT", "DIAGNOSIS"
        ],
        InfoTypeCategory.CREDENTIALS: [
            "AUTH_TOKEN", "AWS_CREDENTIALS", "AZURE_AUTH_TOKEN",
            "HTTP_COOKIE", "HTTP_BASIC_AUTH_HEADER", "JSON_WEB_TOKEN", "API_KEY",
            "OAUTH_CLIENT_ID", "OAUTH_CLIENT_SECRET", "PASSWORD", "USERNAME"
        ],
        InfoTypeCategory.LOCATION: [
            "LOCATION", "STREET_ADDRESS", "ZIPCODE", "CITY", "COUNTRY", "COUNTY",
            "CONTINENT", "POSTAL_CODE", "LANDMARK", "LAT_LONG_COORDINATES",
            "GPS_COORDINATES"
        ],
        InfoTypeCategory.DOCUMENT: [
            "DOCUMENT_ID", "PDF_FILE_PATH", "SPREADSHEET_URL", "STORAGE_SIGNED_URL",
            "FILE_PATH", "CLOUD_STORAGE_URL", "DOCUMENT_TITLE"
        ],
        InfoTypeCategory.ETHNIC: [
            "ETHNIC_GROUP", "RACE", "RELIGION", "POLITICAL_AFFILIATION"
        ],
        InfoTypeCategory.GOVERNMENT: [
            "US_SOCIAL_SECURITY_NUMBER", "US_PASSPORT", "US_DRIVERS_LICENSE_NUMBER",
            "UK_NATIONAL_INSURANCE_NUMBER", "UK_PASSPORT", "UK_DRIVERS_LICENSE",
            "CANADA_PASSPORT", "CANADA_SOCIAL_INSURANCE", "CANADA_DRIVERS_LICENSE",
            "FRANCE_PASSPORT", "FRANCE_CNI", "FRANCE_NIR",
            "GERMANY_PASSPORT", "GERMANY_IDENTITY_CARD", "GERMANY_DRIVERS_LICENSE",
            "GERMANY_TAX_IDENTIFICATION_NUMBER", "JAPAN_PASSPORT", "JAPAN_DRIVERS_LICENSE",
            "JAPAN_MY_NUMBER", "MEXICO_PASSPORT", "NETHERLANDS_PASSPORT",
            "NETHERLANDS_CITIZENS_SERVICE_NUMBER", "SPAIN_PASSPORT", "SPAIN_DNI",
            "SPAIN_NIE", "SPAIN_NIF", "SPAIN_DRIVERS_LICENSE", "SPAIN_SOCIAL_SECURITY_NUMBER"
        ],
        InfoTypeCategory.NETWORKING: [
            "IP_ADDRESS", "MAC_ADDRESS", "URL", "DOMAIN_NAME", "PORT",
            "USER_AGENT", "HOSTNAME"
        ],
        InfoTypeCategory.OTHER: [
            "DATE", "TIME", "VAT_NUMBER", "IBAN_NUMBER", "SWIFT_BIC",
            "ORGANIZATION_NAME", "COMPANY_NAME", "VEHICLE_IDENTIFICATION_NUMBER",
            "INTERNATIONAL_PHONE_NUMBER", "IMEI_HARDWARE_ID", "ADVERTISING_ID",
            "VAT_ID"
        ]
    }

    @classmethod
    def get_all_infotypes(cls) -> List[str]:
        """Get list of all supported info types."""
        result = []
        for types in cls.CATALOG.values():
            result.extend(types)
        return sorted(result)

    @classmethod
    def get_infotypes_by_category(cls, category) -> List[str]:
        """Get info types for a specific category."""
        if isinstance(category, str):
            try:
                category = InfoTypeCategory(category)
            except ValueError:
                raise InfoTypeNotSupportedError(f"Invalid category: {category}")

        return sorted(cls.CATALOG.get(category, []))

    @classmethod
    def get_category_for_infotype(cls, info_type: str) -> Optional[InfoTypeCategory]:
        """Find the category for a given info type."""
        for category, types in cls.CATALOG.items():
            if info_type in types:
                return category
        return None

    @classmethod
    def get_categories(cls) -> List[InfoTypeCategory]:
        """Get all available categories."""
        return list(cls.CATALOG.keys())

    @classmethod
    def is_valid_infotype(cls, info_type: str) -> bool:
        """Check if an info type is valid."""
        return info_type in cls.get_all_infotypes()

    @classmethod
    def verify_infotypes(cls, info_types: List[str]) -> Tuple[List[str], List[str]]:
        """
        Verify a list of info types and return valid and invalid ones.

        Returns:
            Tuple of (valid_infotypes, invalid_infotypes)
        """
        all_types = set(cls.get_all_infotypes())
        valid = []
        invalid = []

        for info_type in info_types:
            if info_type in all_types:
                valid.append(info_type)
            else:
                invalid.append(info_type)

        return valid, invalid

    @classmethod
    def get_common_infotypes(cls) -> List[str]:
        """Get a list of commonly used info types."""
        common_types = [
            "PERSON_NAME", "EMAIL_ADDRESS", "PHONE_NUMBER",
            "CREDIT_CARD_NUMBER", "US_SOCIAL_SECURITY_NUMBER",
            "STREET_ADDRESS", "LOCATION", "IP_ADDRESS"
        ]
        return common_types