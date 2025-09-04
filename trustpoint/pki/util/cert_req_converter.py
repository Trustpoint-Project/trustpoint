"""Adapter to convert from CertificateSigningRequest to JSON certificate request dict."""

import logging
from typing import Any

from cryptography import x509
from trustpoint_core.oid import NameOid

from pki.util.cert_profile import JSONProfileVerifier
from pki.util.ext_oids import ExtendedKeyUsageOid

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
        req_ext = {}
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
                req_ext['san'] = san
            elif isinstance(ext.value, x509.KeyUsage):
                ku = {}
                if ext.value.digital_signature:
                    ku['digital_signature'] = True
                if ext.value.content_commitment:
                    ku['content_commitment'] = True
                if ext.value.key_encipherment:
                    ku['key_encipherment'] = True
                if ext.value.data_encipherment:
                    ku['data_encipherment'] = True
                if ext.value.key_agreement:
                    ku['key_agreement'] = True
                    if ext.value.encipher_only:
                        ku['encipher_only'] = True
                    if ext.value.decipher_only:
                        ku['decipher_only'] = True
                if ext.value.key_cert_sign:
                    ku['key_cert_sign'] = True
                if ext.value.crl_sign:
                    ku['crl_sign'] = True
                req_ext['key_usage'] = ku
            elif isinstance(ext.value, x509.ExtendedKeyUsage):
                eku = [ExtendedKeyUsageOid(oid.dotted_string).name.lower() for oid in ext.value]
                req_ext['extended_key_usage'] = {'usages': eku, 'critical': ext.critical}
            elif isinstance(ext.value, x509.BasicConstraints):
                bc = {'ca': ext.value.ca, 'critical': ext.critical}
                if ext.value.path_length is not None:
                    bc['path_length'] = ext.value.path_length
                req_ext['basic_constraints'] = bc
            else:
                logger.debug('JSON Cert Request Adapter: Skipping unsupported extension: %s', ext.oid.dotted_string)
        req['ext'] = req_ext

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
            elif ext_name == 'key_usage':
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=ext_value.get('digital_signature', False),
                        content_commitment=ext_value.get('content_commitment', False),
                        key_encipherment=ext_value.get('key_encipherment', False),
                        data_encipherment=ext_value.get('data_encipherment', False),
                        key_agreement=ext_value.get('key_agreement', False),
                        key_cert_sign=ext_value.get('key_cert_sign', False),
                        crl_sign=ext_value.get('crl_sign', False),
                        encipher_only=ext_value.get('encipher_only', False),
                        decipher_only=ext_value.get('decipher_only', False),
                    ),
                    critical=critical,
                )
            elif ext_name == 'extended_key_usage':
                eku_oids: list[x509.ObjectIdentifier] = []
                for usage_str in ext_value.get('usages', []):
                    try:
                        eku_oids.append(x509.ObjectIdentifier(ExtendedKeyUsageOid[usage_str.upper()].value))
                    except KeyError:
                        eku_oids.append(x509.ObjectIdentifier(usage_str))
                builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=critical)
            elif ext_name == 'basic_constraints':
                builder = builder.add_extension(
                    x509.BasicConstraints(
                        ca=ext_value.get('ca', False),
                        path_length=ext_value.get('path_length', None),
                    ),
                    critical=critical,
                )
            else:
                logger.debug('JSON Cert Request Adapter: Skipping unsupported extension: %s', ext_name)

        return builder
