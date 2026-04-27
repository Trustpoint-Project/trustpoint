"""OCSP message responder for Trustpoint (RFC 6960)."""
from trustpoint.request.message_parser.ocsp import parse_ocsp_request
from trustpoint.request.message_builder.ocsp import build_ocsp_response

class OcspMessageResponder:
    """Handles OCSP request parsing and response building."""
    def handle(self, data: bytes) -> bytes:
        """Parse OCSP request and build response."""
        ocsp_req = parse_ocsp_request(data)
        return build_ocsp_response(ocsp_req)
