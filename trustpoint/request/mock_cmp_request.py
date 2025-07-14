import os

from django.http import HttpRequest
from http_request_validator import CmpHttpRequestValidator

from request.request_context import RequestContext

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trustpoint.settings')

def create_mock_request(headers: dict, body: bytes) -> HttpRequest:
    """Create a mock Django HttpRequest object with custom headers and body."""
    request = HttpRequest()
    request.headers = headers
    request.read = lambda: body
    return request


def mock_cmp_request(content_type='application/pkixcmp', accept='application/pkixcmp', body=None) -> HttpRequest:
    """Create a mock CMP HttpRequest object with default or custom headers and body."""
    cmp_headers = {
        'Content-Type': content_type,
        'Accept': accept,
    }
    cmp_body = body or b'Default CMP payload.'
    return create_mock_request(cmp_headers, cmp_body)


if __name__ == '__main__':
    print('Running CMP request validation example...')
    cmp_request = mock_cmp_request(body=b'Some CMP-specific payload.')

    cmp_context = RequestContext()
    cmp_validator = CmpHttpRequestValidator()

    try:
        cmp_validator.validate(cmp_request, cmp_context)
        print('CMP request validation succeeded!')
        print('Context after validation:', cmp_context.to_dict())
    except ValueError as e:
        print('CMP request validation failed:', e)
