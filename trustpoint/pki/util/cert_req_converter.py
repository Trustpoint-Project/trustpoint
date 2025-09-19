"""Adapter to convert from CertificateSigningRequest to JSON certificate request dict."""

import datetime
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
    def to_json(csr: x509.CertificateSigningRequest | x509.CertificateBuilder | None) -> dict[str, Any]:
        """Convert a CSR to a JSON request dict."""
        if csr is None:
            exc_msg = 'CSR is None'
            raise ValueError(exc_msg)
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
    def _subject_from_json(json: dict[str, Any], builder: x509.CertificateBuilder) -> x509.CertificateBuilder:
        subj = json.get('subject', {})
        name_attributes = []
        for key, value in subj.items():
            oid = NameOid[key.upper()].value
            name_attributes.append(x509.NameAttribute(x509.ObjectIdentifier(oid.dotted_string), value))
        if name_attributes:
            builder = builder.subject_name(x509.Name(name_attributes))
        return builder

    @staticmethod
    def _ext_from_json(json: dict[str, Any], builder: x509.CertificateBuilder) -> x509.CertificateBuilder:
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
            elif ext_name == 'crl_distribution_points':
                crl_uris = ext_value.get('uris', [])
                if crl_uris:
                    dp_list = [x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(uri)],
                                                       relative_name=None, reasons=None, crl_issuer=None)
                               for uri in crl_uris]
                    builder = builder.add_extension(x509.CRLDistributionPoints(dp_list), critical=critical)
            else:
                logger.debug('JSON Cert Request Adapter: Skipping unsupported extension: %s', ext_name)
        return builder

    @staticmethod
    def _validity_from_json(json: dict[str, Any], builder: x509.CertificateBuilder) -> x509.CertificateBuilder:
        """Parses validity from JSON and applies it to the builder.

        For relative periods, this sets not_before to now - 1 hour and not_after to now + period.
        Therefore, it should be called just before signing the certificate.
        """
        validity = json.get('validity', {})
        if validity.get('not_before') and validity.get('not_after'):
            builder = builder.not_valid_before(validity['not_before'])
            builder = builder.not_valid_after(validity['not_after'])
        else:
            validity_period = 0
            if validity.get('duration'):
                validity_period = validity['duration']
            else:
                days = validity.get('days', 0)
                hours = validity.get('hours', 0)
                minutes = validity.get('minutes', 0)
                seconds = validity.get('seconds', 0)
                validity_seconds = days * 86400 + hours * 3600 + minutes * 60 + seconds
                validity_period = datetime.timedelta(seconds=validity_seconds)
            if validity_period == 0 or validity_period == datetime.timedelta(seconds=0):
                exc_msg = 'Validity period must be specified in the profile.'
                raise ValueError(exc_msg)

            default_backdate = datetime.timedelta(hours=1)

            builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC) - default_backdate)
            builder = builder.not_valid_after(
                datetime.datetime.now(datetime.UTC) + validity_period
            )
        return builder

    @staticmethod
    def from_json(json: dict[str, Any]) -> x509.CertificateBuilder:
        """Convert a JSON request dict to a CertificateBuilder."""
        json = JSONProfileVerifier.validate_request(json) # normalize aliases and validate

        builder = JSONCertRequestConverter._subject_from_json(json, x509.CertificateBuilder())

        builder = JSONCertRequestConverter._ext_from_json(json, builder)

        return JSONCertRequestConverter._validity_from_json(json, builder)
