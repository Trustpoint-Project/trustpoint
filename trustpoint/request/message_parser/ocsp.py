"""OCSP message parser for Trustpoint (RFC 6960)."""
from cryptography import x509
from cryptography.x509.ocsp import OCSPRequest

def parse_ocsp_request(data: bytes) -> OCSPRequest:
    """Parse DER-encoded OCSP request."""
    return x509.ocsp.load_der_ocsp_request(data)
