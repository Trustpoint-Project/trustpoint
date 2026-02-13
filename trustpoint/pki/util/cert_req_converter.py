"""Adapter to convert from CertificateSigningRequest to JSON certificate request dict."""

import datetime
import ipaddress
import logging
from typing import Any

from cryptography import x509
from trustpoint_core.oid import NameOid

from pki.util.cert_profile import CERT_PROFILE_KEYWORDS, JSONProfileVerifier
from pki.util.ext_oids import ExtendedKeyUsageOid

logger = logging.getLogger(__name__)

class JSONCertRequestConverter:
    """Adapter to convert from CertificateSigningRequest to JSON certificate request dict."""

    @staticmethod
    def _san_value_to_json(san: x509.SubjectAlternativeName) -> dict[str, Any]:
        san_dict: dict[str, Any] = {}
        for name in san:
            if isinstance(name, x509.DNSName):
                san_dict.setdefault('dns_names', []).append(name.value)
            elif isinstance(name, x509.RFC822Name):
                san_dict.setdefault('rfc822_names', []).append(name.value)
            elif isinstance(name, x509.UniformResourceIdentifier):
                san_dict.setdefault('uris', []).append(name.value)
            elif isinstance(name, x509.IPAddress):
                san_dict.setdefault('ip_addresses', []).append(str(name.value))
            else:
                san_dict.setdefault('other_names', []).append(str(name.value))
        return san_dict

    @staticmethod
    def _ku_value_to_json(ku: x509.KeyUsage) -> dict[str, Any]:
        ku_dict: dict[str, Any] = {}
        if ku.digital_signature:
            ku_dict['digital_signature'] = True
        if ku.content_commitment:
            ku_dict['content_commitment'] = True
        if ku.key_encipherment:
            ku_dict['key_encipherment'] = True
        if ku.data_encipherment:
            ku_dict['data_encipherment'] = True
        if ku.key_agreement:
            ku_dict['key_agreement'] = True
            if ku.encipher_only:
                ku_dict['encipher_only'] = True
            if ku.decipher_only:
                ku_dict['decipher_only'] = True
        if ku.key_cert_sign:
            ku_dict['key_cert_sign'] = True
        if ku.crl_sign:
            ku_dict['crl_sign'] = True
        return ku_dict

    @staticmethod
    def _extensions_to_json(extensions: list[x509.Extension[Any]]) -> dict[str, Any]:
        req_ext = {}
        for ext in extensions:
            # Most essential extensions to handle:
            # SAN, KeyUsage, ExtendedKeyUsage, BasicConstraints, SKI, AKI, CRLDistributionPoints, AIA
            if isinstance(ext.value, x509.SubjectAlternativeName):
                san: dict[str, Any] = JSONCertRequestConverter._san_value_to_json(ext.value)
                san['critical'] = ext.critical
                req_ext['san'] = san
            elif isinstance(ext.value, x509.KeyUsage):
                ku = JSONCertRequestConverter._ku_value_to_json(ext.value)
                ku['critical'] = ext.critical
                req_ext['key_usage'] = ku
            elif isinstance(ext.value, x509.ExtendedKeyUsage):
                eku = [ExtendedKeyUsageOid(oid.dotted_string).name.lower() for oid in ext.value]
                req_ext['extended_key_usage'] = {'usages': eku, 'critical': ext.critical}
            elif isinstance(ext.value, x509.BasicConstraints):
                if ext.value.ca:
                    # If requesting CAs is required, implement additional safeguards first
                    # (only if {"ca": true} is explicitly set in the profile)
                    exc_msg = 'Safeguard: Requesting CA certificates is not allowed.'
                    raise ValueError(exc_msg)
                bc: dict[str, Any] = {'ca': ext.value.ca, 'critical': ext.critical}
                if ext.value.path_length is not None:
                    bc['path_length'] = ext.value.path_length
                req_ext['basic_constraints'] = bc
            else:
                logger.debug('JSON Cert Request Adapter: Skipping unsupported extension: %s', ext.oid.dotted_string)
        return req_ext

    @staticmethod
    def to_json(csr: x509.CertificateSigningRequest | x509.CertificateBuilder | None) -> dict[str, Any]:
        """Convert a CSR to a JSON request dict."""
        if csr is None:
            exc_msg = 'CSR is None'
            raise ValueError(exc_msg)
        if isinstance(csr, x509.CertificateBuilder):
            subject_dn = csr._subject_name  # noqa: SLF001
            extensions = list(csr._extensions)  # noqa: SLF001
        else:
            subject_dn = csr.subject
            extensions = list(csr.extensions)

        req = {'type': 'cert_request', 'subj': {}, 'ext': {}}
        subj_dict: dict[str, str] = {}
        for attr in subject_dn or []:
            subj_dict[attr.oid.dotted_string] = attr.value
        req['subj'] = subj_dict
        req['ext'] = JSONCertRequestConverter._extensions_to_json(extensions)

        return req

    @staticmethod
    def _subject_from_json(json: dict[str, Any], builder: x509.CertificateBuilder) -> x509.CertificateBuilder:
        """Constructs and sets the subject name of an X.509 certificate builder from a JSON dictionary."""
        subj = json.get('subject', {})
        name_attributes = []
        for key, value in subj.items():
            if key in CERT_PROFILE_KEYWORDS:
                continue
            oid = NameOid[key.upper()].value
            name_attributes.append(x509.NameAttribute(x509.ObjectIdentifier(oid.dotted_string), value))
        if name_attributes:
            builder = builder.subject_name(x509.Name(name_attributes))
        return builder

    @staticmethod
    def _general_name_from_json(ext_value: dict[str, Any]) -> list[x509.GeneralName]:
        """Converts SAN values from JSON to a list of x509.GeneralName objects."""
        general_names: list[x509.GeneralName] = []
        for san_type, san_values in ext_value.items():
            if san_type == 'dns_names':
                general_names.extend([x509.DNSName(v) for v in san_values])
            elif san_type == 'rfc822_names':
                general_names.extend([x509.RFC822Name(v) for v in san_values])
            elif san_type == 'uris':
                general_names.extend([x509.UniformResourceIdentifier(v) for v in san_values])
            elif san_type == 'ip_addresses':
                general_names.extend([x509.IPAddress(ipaddress.ip_address(v)) for v in san_values])
            else:
                logger.debug('JSON Cert Request Converter: Skipping unsupported SAN type: %s', san_type)
        return general_names

    @staticmethod
    def _ku_from_json(ext_value: dict[str, Any]) -> x509.KeyUsage:
        """Converts Key Usage values from JSON to an x509.KeyUsage object."""
        return x509.KeyUsage(
            digital_signature=ext_value.get('digital_signature', False),
            content_commitment=ext_value.get('content_commitment', False),
            key_encipherment=ext_value.get('key_encipherment', False),
            data_encipherment=ext_value.get('data_encipherment', False),
            key_agreement=ext_value.get('key_agreement', False),
            key_cert_sign=ext_value.get('key_cert_sign', False),
            crl_sign=ext_value.get('crl_sign', False),
            encipher_only=ext_value.get('encipher_only', False),
            decipher_only=ext_value.get('decipher_only', False),
        )

    @staticmethod
    def _ext_from_json(  # noqa: C901
        json: dict[str, Any],
        builder: x509.CertificateBuilder,
        *,
        allow_ca_cert: bool = False
    ) -> x509.CertificateBuilder:
        """Processes JSON data to add X.509 certificate extensions to a CertificateBuilder.

        Args:
            json: JSON dictionary containing extension data
            builder: Certificate builder to add extensions to
            allow_ca_cert: Whether to allow CA certificate requests (use for legitimate CA cert enrollment)

        Returns:
            Updated certificate builder with extensions added
        """
        ext = json.get('extensions', {})
        for ext_name, ext_value in ext.items():
            critical = ext_value.get('critical', False)
            if ext_name == 'subject_alternative_name':
                san_list: list[x509.GeneralName] = JSONCertRequestConverter._general_name_from_json(ext_value)
                if san_list:
                    builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=critical)
            elif ext_name == 'key_usage':
                builder = builder.add_extension(
                    JSONCertRequestConverter._ku_from_json(ext_value),
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
                ca = ext_value.get('ca', False)
                if ca and not allow_ca_cert:
                    # Safeguard: CA certificate requests are blocked by default
                    # Use allow_ca_certificate_request flag in context for legitimate CA cert requests
                    exc_msg = 'Safeguard: Requesting CA certificates is not allowed.'
                    raise ValueError(exc_msg)
                builder = builder.add_extension(
                    x509.BasicConstraints(
                        ca=ca,
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
    def validity_period_from_json(validity: dict[str, Any]) -> datetime.timedelta:
        """Parses validity period from JSON."""
        validity_period: datetime.timedelta
        if validity.get('duration'):
            validity_period = datetime.timedelta(seconds=validity['duration'])
        else:
            days = validity.get('days', 0)
            hours = validity.get('hours', 0)
            minutes = validity.get('minutes', 0)
            seconds = validity.get('seconds', 0)
            validity_seconds = days * 86400 + hours * 3600 + minutes * 60 + seconds
            validity_period = datetime.timedelta(seconds=validity_seconds)
        if validity_period == datetime.timedelta(seconds=0):
            exc_msg = 'Validity period must be specified in the profile.'
            raise ValueError(exc_msg)
        return validity_period

    @staticmethod
    def _validity_from_json(json: dict[str, Any], builder: x509.CertificateBuilder) -> x509.CertificateBuilder:
        """Parses validity from JSON and applies it to the builder.

        For relative periods, this sets not_before to now - 1 hour and not_after to now + period.
        Therefore, it should be called just before signing the certificate.
        """
        validity = json.get('validity', {})
        if validity.get('not_before') and validity.get('not_after'):
            builder = builder.not_valid_before(validity['not_before'])
            return builder.not_valid_after(validity['not_after'])

        validity_period = JSONCertRequestConverter.validity_period_from_json(validity)

        default_backdate = datetime.timedelta(hours=1)

        builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC) - default_backdate)
        return builder.not_valid_after(
            datetime.datetime.now(datetime.UTC) + validity_period
        )

    @staticmethod
    def from_json(json: dict[str, Any], *, allow_ca_cert: bool = False) -> x509.CertificateBuilder:
        """Convert a JSON request dict to a CertificateBuilder.

        Args:
            json: JSON dictionary containing certificate request data
            allow_ca_cert: Whether to allow CA certificate requests (use for legitimate CA cert enrollment)

        Returns:
            Certificate builder with all data from JSON applied
        """
        json = JSONProfileVerifier.validate_request(json) # normalize aliases and validate

        builder = JSONCertRequestConverter._subject_from_json(json, x509.CertificateBuilder())

        builder = JSONCertRequestConverter._ext_from_json(json, builder, allow_ca_cert=allow_ca_cert)

        return JSONCertRequestConverter._validity_from_json(json, builder)


class JSONCertRequestCommandExtractor:
    """Adapter to extract defaults and values from a profile for use in OpenSSL commands (help pages)."""

    @staticmethod
    def sample_request_to_openssl_subj(sample_req: dict[str, Any]) -> str:
        """Convert profile subject to OpenSSL command line subject string."""
        subj = sample_req.get('subject', {})
        subj_str = ''
        for name_identifier, value in subj.items():
            if name_identifier in CERT_PROFILE_KEYWORDS:
                continue
            first, *others = name_identifier.split('_')
            name_camel = ''.join([first.lower(), *map(str.capitalize, others)])
            subj_str += f'/{name_camel}={value}'
        if not subj_str:
            subj_str = '/'
        return subj_str

    @staticmethod
    def sample_request_to_openssl_cmp_sans(sample_req: dict[str, Any]) -> str:
        """Convert profile SANs to OpenSSL CMP command line -sans string."""
        ext = sample_req.get('extensions', {})
        san = ext.get('subject_alternative_name', {})
        san_parts = ''
        for san_type, san_values in san.items():
            if san_type in {'dns_names', 'uris', 'ip_addresses'}:
                san_parts += san_values + ' ' if isinstance(san_values, str) else ''.join([f'{v} ' for v in san_values])
            else:
                logger.debug('JSON Cert Request Command Extractor: Skipping SAN type: %s', san_type)
        if san.get('critical', False):
            san_parts = 'critical, ' + san_parts
        return san_parts.strip()

    @staticmethod
    def sample_request_to_openssl_req_sans(sample_req: dict[str, Any]) -> str:
        """Convert profile SANs to OpenSSL req command line -addext string."""
        ext = sample_req.get('extensions', {})
        san = ext.get('subject_alternative_name', {})
        san_parts = ''
        for san_type, san_values in san.items():
            if san_type in 'dns_names':
                san_parts += f'DNS:{san_values}, ' if isinstance(san_values, str) \
                    else ''.join([f'DNS:{v}, ' for v in san_values])
            elif san_type == 'uris':
                san_parts += f'URI:{san_values}, ' if isinstance(san_values, str) \
                    else ''.join([f'URI:{v}, ' for v in san_values])
            elif san_type == 'ip_addresses':
                san_parts += f'IP:{san_values}, ' if isinstance(san_values, str) \
                    else ''.join([f'IP:{v}, ' for v in san_values])
            else:
                logger.debug('JSON Cert Request Command Extractor: Skipping SAN type: %s', san_type)
        if san.get('critical', False):
            san_parts = 'critical, ' + san_parts
        return san_parts.rstrip(', ')

    @staticmethod
    def sample_request_to_openssl_days(sample_req: dict[str, Any]) -> int:
        """Extract validity days from profile for OpenSSL CMP command line -days option."""
        validity = sample_req.get('validity', {})
        validity_period = JSONCertRequestConverter.validity_period_from_json(validity)
        return validity_period.days
