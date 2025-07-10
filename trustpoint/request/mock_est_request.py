import os
from django.http import HttpRequest
from request.request_context import RequestContext
from http_request_validator import EstHttpRequestValidator


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "trustpoint.settings")

def create_mock_request(headers: dict, body: bytes) -> HttpRequest:
    """Create a mock Django HttpRequest object with custom headers and body."""
    request = HttpRequest()
    request.headers = headers
    request.read = lambda: body
    return request


def mock_est_request(content_type="application/pkcs7-mime", accept="application/pkcs7-mime", body=None) -> HttpRequest:
    """Create a mock EST HttpRequest object with default or custom headers and body."""
    est_headers = {
        "Content-Type": content_type,
        "Accept": accept,
    }
    est_body = body or b"Default EST payload."
    return create_mock_request(est_headers, est_body)


if __name__ == "__main__":
    print("Running EST request validation example...")
    est_request = mock_est_request(body=b"Some EST-specific payload.")

    est_context = RequestContext()
    est_validator = EstHttpRequestValidator()

    try:
        est_validator.validate(est_request, est_context)
        print("EST request validation succeeded!")
        print("Context after validation:", est_context.to_dict())
    except ValueError as e:
        print("EST request validation failed:", e)

    print("\n")
