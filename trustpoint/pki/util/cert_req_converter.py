"""Adapter to convert from CertificateSigningRequest to JSON certificate request dict."""

import logging
from typing import Any

from cryptography import x509

logger = logging.getLogger(__name__)

class JSONCertRequestConverter:
    """Adapter to convert from CertificateSigningRequest to JSON certificate request dict."""

    @staticmethod
    def to_json(csr: x509.CertificateSigningRequest | x509.CertificateBuilder) -> dict[str, Any]:
        """Convert a CSR to a JSON request dict."""
        if isinstance(csr, x509.CertificateBuilder):
            subject_dn = csr._subject_name  # noqa: SLF001
            extensions = csr._extensions  # noqa: SLF001
        else:
            subject_dn = csr.subject
            extensions = csr.extensions

        req = {'type': 'cert_request', 'subj': {}, 'ext': {}}
        for attr in subject_dn or []:
            req['subj'][attr.oid.dotted_string] = attr.value
        for ext in extensions:
            # Most essential extensions to handle:
            # SAN, KeyUsage, ExtendedKeyUsage, BasicConstraints, SKI, AKI, CRLDistributionPoints, AIA
            if isinstance(ext.value, x509.SubjectAlternativeName):
                san: dict[str, list[str]] = {}
                for name in ext.value:
                    if isinstance(name, x509.DNSName):
                        san.setdefault('dns_names', []).append(name.value)
                    elif isinstance(name, x509.RFC822Name):
                        san.setdefault('rfc822_names', []).append(name.value)
                    elif isinstance(name, x509.UniformResourceIdentifier):
                        san.setdefault('uris', []).append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        san.setdefault('ip_addresses', []).append(str(name.value))
                    else:
                        san.setdefault('other_names', []).append(str(name.value))
                req['ext']['san'] = san
            else:
                logger.debug('JSON Cert Request Adapter: Skipping unsupported extension: %s', ext.oid.dotted_string)

        return req
