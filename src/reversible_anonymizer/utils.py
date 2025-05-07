"""Utility functions for the reversible_anonymizer package."""
from google.cloud import service_usage_v1
from .exceptions import ServiceNotEnabledError


def check_required_services(project_id: str, required_services: list) -> None:
    """Check if required Google Cloud services are enabled."""
    client = service_usage_v1.ServiceUsageClient()
    parent = f"projects/{project_id}"

    for service in required_services:
        request = service_usage_v1.GetServiceRequest(
            name=f"{parent}/services/{service}"
        )
        try:
            response = client.get_service(request=request)
            if not response.state.STATE_ENABLED:
                raise ServiceNotEnabledError(
                    f"Service {service} is not enabled for project {project_id}"
                )
        except Exception as e:
            raise ServiceNotEnabledError(
                f"Error checking service {service}: {str(e)}"
            )