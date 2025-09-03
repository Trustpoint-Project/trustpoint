"""Adapter to convert from CertificateSigningRequest to JSON certificate request dict."""

import logging
from typing import Any

from cryptography import x509
from trustpoint_core.oid import NameOid

from pki.util.cert_profile import JSONProfileVerifier

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
                san['critical'] = ext.critical
                req['ext']['san'] = san
            else:
                logger.debug('JSON Cert Request Adapter: Skipping unsupported extension: %s', ext.oid.dotted_string)

        return req

    @staticmethod
    def from_json(json: dict[str, Any]) -> x509.CertificateBuilder:
        """Convert a JSON request dict to a CertificateBuilder."""
        json = JSONProfileVerifier.validate_request(json) # normalize aliases and validate

        builder = x509.CertificateBuilder()
        subj = json.get('subject', {})
        name_attributes = []
        for key, value in subj.items():
            oid = NameOid[key.upper()].value
            name_attributes.append(x509.NameAttribute(x509.ObjectIdentifier(oid.dotted_string), value))
        if name_attributes:
            builder = builder.subject_name(x509.Name(name_attributes))

        ext = json.get('extensions', {})
        for ext_name, ext_value in ext.items():
            critical = ext_value.get('critical', False)
            if ext_name == 'subject_alternative_name':
                san_list: list[x509.GeneralName] = []
                for san_type, san_values in ext_value.items():
                    if san_type == 'dns_names':
                        san_list.extend([x509.DNSName(v) for v in san_values])
                    elif san_type == 'rfc822_names':
                        san_list.extend([x509.RFC822Name(v) for v in san_values])
                    elif san_type == 'uris':
                        san_list.extend([x509.UniformResourceIdentifier(v) for v in san_values])
                    elif san_type == 'ip_addresses':
                        import ipaddress

                        san_list.extend([x509.IPAddress(ipaddress.ip_address(v)) for v in san_values])
                    else:
                        logger.debug('JSON Cert Request Adapter: Skipping unsupported SAN type: %s', san_type)
                if san_list:
                    builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=critical)
            else:
                logger.debug('JSON Cert Request Adapter: Skipping unsupported extension: %s', ext_name)

        return builder
