"""Provides classes for parsing CMP PKI messages."""

import ipaddress
from typing import Any, Never, get_args

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.x509.oid import ExtensionOID
from pyasn1.codec.ber import decoder as ber_decoder  # type: ignore[import-untyped]
from pyasn1.codec.der import decoder as der_decoder  # type: ignore[import-untyped]
from pyasn1.codec.der import encoder as der_encoder
from pyasn1_modules import rfc2459, rfc2511, rfc4210  # type: ignore[import-untyped]

from cmp.util import NameParser
from request.request_context import BaseRequestContext, CmpBaseRequestContext, CmpCertificateRequestContext
from trustpoint.logger import LoggerMixin

from .base import CertProfileParsing, CompositeParsing, DomainParsing, ParsingComponent


class CmpPkiMessageParsing(ParsingComponent, LoggerMixin):
    """Component for parsing CMP-specific PKI messages."""

    def parse(self, context: BaseRequestContext) -> None:
        """Parse a CMP PKI message."""
        if not isinstance(context, CmpBaseRequestContext):
            exc_msg = 'CmpPkiMessageParsing requires a CmpBaseRequestContext.'
            raise TypeError(exc_msg)

        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('CMP PKI message parsing failed: Raw message is missing')
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            self.logger.warning('CMP PKI message parsing failed: Raw message body is missing')
            raise ValueError(error_message)

        try:
            body_size = len(context.raw_message.body)
            serialized_message, _ = ber_decoder.decode(context.raw_message.body, asn1Spec=rfc4210.PKIMessage())
            context.parsed_message = serialized_message

            self._extract_signer_certificate(context)

            self.logger.info('CMP PKI message parsing successful: Parsed %d bytes', body_size)
        except (ValueError, TypeError) as e:
            error_message = 'Failed to parse the CMP message. It seems to be corrupted.'
            self.logger.exception('CMP PKI message parsing failed')
            raise ValueError(error_message) from e

    def _extract_signer_certificate(self, context: CmpBaseRequestContext) -> None:
        """Extract the CMP signer certificate from extraCerts if available (optional)."""
        try:
            if not context.parsed_message or not hasattr(context.parsed_message, '__getitem__'):
                self.logger.debug('Parsed message is not indexable, skipping extraCerts extraction')
                return
            extra_certs = context.parsed_message['extraCerts']
            if extra_certs is None or len(extra_certs) == 0:
                self.logger.debug('No extra certificates found in CMP message')
                return

            cmp_signer_extra_cert = extra_certs[0]
            der_cmp_signer_cert = der_encoder.encode(cmp_signer_extra_cert)
            cmp_signer_cert = x509.load_der_x509_certificate(der_cmp_signer_cert)
            context.client_certificate = cmp_signer_cert

            if len(extra_certs) > 1:
                intermediate_certs = []
                for i, cert_asn1 in enumerate(extra_certs[1:], start=1):
                    try:
                        der_cert = der_encoder.encode(cert_asn1)
                        intermediate_cert = x509.load_der_x509_certificate(der_cert)
                        intermediate_certs.append(intermediate_cert)
                        self.logger.debug('Loaded intermediate certificate %d from extraCerts', i)
                    except Exception as e:
                        error_message = f'Failed to extract intermediate certificate {i} from extraCerts: {e}'
                        self.logger.exception(error_message)
                        raise ValueError(error_message) from e

                context.client_intermediate_certificate = intermediate_certs
                self.logger.debug(
                    'Successfully extracted %d intermediate certificates from extraCerts', len(intermediate_certs))

            self.logger.debug('Successfully extracted CMP signer certificate from extraCerts')

        except Exception as e:
            error_message = f'Failed to extract CMP signer certificate: {e}'
            self.logger.exception(error_message)
            raise ValueError(error_message) from e


class CmpHeaderValidation(ParsingComponent, LoggerMixin):
    """Component for validating CMP message headers."""

    def __init__(self, cmp_message_version: int = 2, transaction_id_length: int = 16,
                 sender_nonce_length: int = 16, implicit_confirm_oid: str = '1.3.6.1.5.5.7.4.13',
                 implicit_confirm_str_value: str = '0x0500') -> None:
        """Initialize the CMP header validation component with configurable parameters.

        Args:
            cmp_message_version: Expected CMP message version (default: 2)
            transaction_id_length: Expected transaction ID length in bytes (default: 16)
            sender_nonce_length: Expected sender nonce length in bytes (default: 16)
            implicit_confirm_oid: Expected implicit confirm OID (default: '1.3.6.1.5.5.7.4.13')
            implicit_confirm_str_value: Expected implicit confirm string value (default: 'NULL')
        """
        self.cmp_message_version = cmp_message_version
        self.transaction_id_length = transaction_id_length
        self.sender_nonce_length = sender_nonce_length
        self.implicit_confirm_oid = implicit_confirm_oid
        self.implicit_confirm_str_value = implicit_confirm_str_value

    def parse(self, context: BaseRequestContext) -> None:
        """Validate the CMP message header."""
        if not isinstance(context, CmpBaseRequestContext):
            exc_msg = 'CmpHeaderValidation requires a CmpBaseRequestContext.'
            raise TypeError(exc_msg)

        if context.parsed_message is None:
            error_message = 'Parsed message is missing from the context.'
            self.logger.warning('CMP header validation failed: Parsed message is missing')
            raise ValueError(error_message)

        try:
            self._check_header(context.parsed_message)
            self.logger.info('CMP header validation successful')
        except ValueError:
            self.logger.exception('CMP header validation failed')
            raise

    def _raise_validation_error(self, message: str) -> None:
        """Helper function to raise a ValueError with the given message."""
        raise ValueError(message)

    def _check_header(self, serialized_pyasn1_message: rfc4210.PKIMessage) -> None:
        """Checks some parts of the header."""
        if serialized_pyasn1_message['header']['pvno'] != self.cmp_message_version:
            err_msg = 'pvno fail'
            raise ValueError(err_msg)

        transaction_id = serialized_pyasn1_message['header']['transactionID'].asOctets()
        if len(transaction_id) != self.transaction_id_length:
            err_msg = 'transactionID fail'
            raise ValueError(err_msg)

        sender_nonce = serialized_pyasn1_message['header']['senderNonce'].asOctets()
        if len(sender_nonce) != self.sender_nonce_length:
            err_msg = 'senderNonce fail'
            raise ValueError(err_msg)

        implicit_confirm_entry = None
        for entry in serialized_pyasn1_message['header']['generalInfo']:
            if entry['infoType'].prettyPrint() == self.implicit_confirm_oid:
                implicit_confirm_entry = entry
                break
        if implicit_confirm_entry is None:
            err_msg = 'implicit confirm missing'
            raise ValueError(err_msg)

        if implicit_confirm_entry['infoValue'].prettyPrint() != self.implicit_confirm_str_value:
            err_msg = 'implicit confirm entry fail'
            raise ValueError(err_msg)


class CmpCertificateBodyValidation(LoggerMixin):
    """Sub-component for validating CMP certificate body for IR and CR message types."""

    def __init__(self, cert_template_version: int = 2) -> None:
        """Initialize the CMP IR/CR body validation component.

        Args:
            cert_template_version: Expected certificate template version (default: 2)
        """
        self.cert_template_version = cert_template_version

    def _validate_cert_req_messages(self, cert_req_messages: list[rfc2511.CertReqMsg]) -> None:
        """Validate the certificate request messages structure."""
        if len(cert_req_messages) > 1:
            self._raise_value_error('Multiple CertReqMessages found.')

        if len(cert_req_messages) < 1:
            self._raise_value_error('No CertReqMessages found.')

    def _validate_cert_request(self, cert_req_msg: rfc2511.CertReqMsg) -> x509.CertificateBuilder:
        """Validate the certificate request message details."""
        if cert_req_msg['certReqId'] != 0:
            self._raise_validation_error('certReqId must be 0.')

        if not cert_req_msg['certTemplate'].hasValue():
            self._raise_validation_error('certTemplate must be contained in IR/CR CertReqMessage.')

        cert_req_template = cert_req_msg['certTemplate']

        if (cert_req_template['version'].hasValue() and
                cert_req_template['version'] != self.cert_template_version):
            self._raise_validation_error('Version must be 2 if supplied in certificate request.')

        return self._cert_template_to_builder(cert_req_template)

    def _cert_template_to_builder(
            self,
            cert_template: rfc2511.CertTemplate
    ) -> x509.CertificateBuilder:

        if cert_template['subject'].hasValue():
            try:
                subject = NameParser.parse_name(cert_template['subject'])
            except Exception:
                self.logger.exception('Error parsing ASN.1 name')
                raise
        else:
            subject = x509.Name([])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)

        if cert_template['extensions'].hasValue():
            extensions = self._parse_cert_template_extensions(cert_template['extensions'])
            for extension in extensions:
                builder = builder.add_extension(extension.value, extension.critical)

        cert_template_pubkey = cert_template['publicKey']
        if not cert_template_pubkey.hasValue():
            err_msg = 'Public key missing in CMP certTemplate.'
            raise ValueError(err_msg)

        try:
            spki = rfc2511.SubjectPublicKeyInfo()
            spki.setComponentByName('algorithm', cert_template_pubkey['algorithm'])
            spki.setComponentByName('subjectPublicKey', cert_template_pubkey['subjectPublicKey'])
            spki_der = der_encoder.encode(spki)
            public_key = load_der_public_key(spki_der)
        except Exception as e:
            error_message = f'Failed to parse public key from CMP certTemplate: {e}'
            self.logger.exception(error_message)
            raise ValueError(error_message) from e

        if not isinstance(public_key, get_args(CertificatePublicKeyTypes)):
            err_msg = f'Unsupported public key type in CMP certTemplate: {type(public_key)}.'
            raise TypeError(err_msg)

        return builder.public_key(public_key)

    def _raise_validation_error(self, message: str) -> Never:
        """Helper function to raise a ValueError with the given message."""
        raise ValueError(message)

    def _parse_cert_template_extensions(self, extensions_asn1: rfc2459.Extensions) -> list[x509.Extension[Any]]:  # noqa: C901 - Core workflow orchestration requires multiple validation and conditional paths
        """Parse ASN.1 extensions from certTemplate into cryptography extension objects using fallback approach."""
        extensions_list = []

        try:
            for extension in extensions_asn1:
                ext_oid = str(extension['extnID'])
                is_critical = str(extension['critical']) == 'True' if extension['critical'].hasValue() else False
                ext_value_bytes = bytes(extension['extnValue'])

                try:
                    extension_obj: x509.Extension[Any]
                    if ext_oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string:
                        extension_obj = self._parse_subject_alternative_name(ext_value_bytes, critical=is_critical)
                    elif ext_oid == ExtensionOID.BASIC_CONSTRAINTS.dotted_string:
                        extension_obj = self._parse_basic_constraints(ext_value_bytes, critical=is_critical)
                    elif ext_oid == ExtensionOID.KEY_USAGE.dotted_string:
                        extension_obj = self._parse_key_usage(ext_value_bytes, critical=is_critical)
                    elif ext_oid == ExtensionOID.EXTENDED_KEY_USAGE.dotted_string:
                        extension_obj = self._parse_extended_key_usage(ext_value_bytes, critical=is_critical)
                    elif ext_oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string:
                        extension_obj = self._parse_subject_key_identifier(ext_value_bytes, critical=is_critical)
                    elif ext_oid == ExtensionOID.CERTIFICATE_POLICIES.dotted_string:
                        extension_obj = self._parse_certificate_policies(ext_value_bytes, critical=is_critical)
                    else:
                        self._raise_not_implemented_error(f'Extension with OID {ext_oid} is not supported')
                    if extension_obj:
                        extensions_list.append(extension_obj)
                except Exception as e:
                    self.logger.exception('Error parsing extension', extra={'exception': str(e)})
                    raise

        except Exception as e:
            self.logger.exception('Error parsing extensions', extra={'exception': str(e)})
            raise

        self.logger.info('Successfully parsed %i extensions', len(extensions_list))
        return extensions_list

    def _parse_subject_alternative_name(
        self, value: bytes, *, critical: bool
    ) -> x509.Extension[x509.SubjectAlternativeName]:
        """Parse Subject Alternative Name extension manually using the working approach."""
        try:
            san_asn1, _ = der_decoder.decode(value, asn1Spec=rfc2459.SubjectAltName())
            general_names = self._extract_general_names(san_asn1)
            if not general_names:
                self.logger.warning('No valid SAN entries found')

            san_extension = x509.SubjectAlternativeName(general_names)
            return x509.Extension(
                oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                critical=critical,
                value=san_extension
            )
        except Exception:
            self.logger.exception('Failed to parse SAN extension.')
            raise

    def _extract_general_names(self, san_asn1: rfc2459.SubjectAltName) -> list[x509.GeneralName]:
        """Extract general names from SAN ASN.1 structure."""
        ipv4_byte_length = 4
        ipv6_byte_length = 16
        general_names: list[x509.GeneralName] = []

        for general_name in san_asn1:
            name_type = general_name.getName()
            name_value = general_name.getComponent()

            if name_type == 'iPAddress':
                self._handle_ip_address(name_value, general_names, ipv4_byte_length, ipv6_byte_length)
            elif name_type == 'dNSName':
                general_names.append(x509.DNSName(str(name_value)))
            elif name_type == 'uniformResourceIdentifier':
                general_names.append(x509.UniformResourceIdentifier(str(name_value)))
            elif name_type == 'rfc822Name':
                general_names.append(x509.RFC822Name(str(name_value)))
            else:
                self.logger.warning('Unsupported SAN type: %s', name_type)

        return general_names

    def _handle_ip_address(
        self,
        name_value: Any,
        general_names: list[x509.GeneralName],
        ipv4_byte_length: int,
        ipv6_byte_length: int
    ) -> None:
        """Handle IP address parsing for SAN."""
        try:
            ip_bytes = name_value.asOctets()
            if len(ip_bytes) == ipv4_byte_length:
                ipv4_addr = ipaddress.IPv4Address(ip_bytes)
                general_names.append(x509.IPAddress(ipv4_addr))
            elif len(ip_bytes) == ipv6_byte_length:
                ipv6_addr = ipaddress.IPv6Address(ip_bytes)
                general_names.append(x509.IPAddress(ipv6_addr))
            else:
                self.logger.warning('Unknown IP address length: %(ip_length)s',
                                    extra={'ip_length': len(ip_bytes)})
        except (ValueError, TypeError) as ip_error:
            self.logger.warning('Failed to parse IP address: %(error)s',
                                extra={'error': str(ip_error)})

    def _parse_basic_constraints(
        self, value: bytes, *, critical: bool
    ) -> x509.Extension[x509.BasicConstraints]:
        """Parse Basic Constraints extension manually."""
        try:
            basic_constraints_asn1, _ = der_decoder.decode(value, asn1Spec=rfc2459.BasicConstraints())
            is_ca = bool(basic_constraints_asn1.getComponentByName('cA'))
            path_length = None
            if basic_constraints_asn1.getComponentByName('pathLenConstraint').hasValue():
                path_length = int(basic_constraints_asn1.getComponentByName('pathLenConstraint'))

            basic_constraints = x509.BasicConstraints(ca=is_ca, path_length=path_length)
            return x509.Extension(
                oid=ExtensionOID.BASIC_CONSTRAINTS,
                critical=critical,
                value=basic_constraints
            )
        except Exception:
            self.logger.exception('Failed to parse Basic Constraints extension.')
            raise

    @staticmethod
    def _get_usage_flag(asn1: rfc2459.KeyUsage, name: str) -> bool:
        idx = rfc2459.KeyUsage.namedValues[name]
        return bool(asn1[idx]) if idx < len(asn1) else False

    def _parse_key_usage(self, value: bytes, *, critical: bool) -> x509.Extension[x509.KeyUsage]:
        """Parse Key Usage extension manually."""
        try:
            key_usage_asn1, _ = der_decoder.decode(value, asn1Spec=rfc2459.KeyUsage())

            key_usage = x509.KeyUsage(
                digital_signature=self._get_usage_flag(key_usage_asn1, 'digitalSignature'),
                content_commitment=self._get_usage_flag(key_usage_asn1, 'nonRepudiation'),
                key_encipherment=self._get_usage_flag(key_usage_asn1, 'keyEncipherment'),
                data_encipherment=self._get_usage_flag(key_usage_asn1, 'dataEncipherment'),
                key_agreement=self._get_usage_flag(key_usage_asn1, 'keyAgreement'),
                key_cert_sign=self._get_usage_flag(key_usage_asn1, 'keyCertSign'),
                crl_sign=self._get_usage_flag(key_usage_asn1, 'cRLSign'),
                encipher_only=self._get_usage_flag(key_usage_asn1, 'encipherOnly'),
                decipher_only=self._get_usage_flag(key_usage_asn1, 'decipherOnly')
            )

            return x509.Extension(
                oid=ExtensionOID.KEY_USAGE,
                critical=critical,
                value=key_usage
            )
        except Exception:
            self.logger.exception('Failed to parse Key Usage extension.')
            raise

    def _parse_extended_key_usage(self, value: bytes, *, critical: bool) -> x509.Extension[x509.ExtendedKeyUsage]:
        """Parse Extended Key Usage extension manually."""
        try:
            eku_asn1, _ = der_decoder.decode(value, asn1Spec=rfc2459.ExtKeyUsageSyntax())
            eku_oids = []

            for i in range(len(eku_asn1)):
                eku_oid = str(eku_asn1.getComponentByPosition(i))
                eku_oids.append(x509.ObjectIdentifier(eku_oid))

            extended_key_usage = x509.ExtendedKeyUsage(eku_oids)

            return x509.Extension(
                oid=ExtensionOID.EXTENDED_KEY_USAGE,
                critical=critical,
                value=extended_key_usage
            )
        except Exception:
            self.logger.exception('Failed to parse Extended Key Usage extension.')
            raise

    def _parse_subject_key_identifier(
        self, value: bytes, *, critical: bool
    ) -> x509.Extension[x509.SubjectKeyIdentifier]:
        """Parse Subject Key Identifier extension manually."""
        try:
            ski_asn1, _ = der_decoder.decode(value, asn1Spec=rfc2459.SubjectKeyIdentifier())
            ski_bytes = bytes(ski_asn1)

            subject_key_identifier = x509.SubjectKeyIdentifier(digest=ski_bytes)

            return x509.Extension(
                oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                critical=critical,
                value=subject_key_identifier
            )
        except Exception:
            self.logger.exception('Failed to parse Subject Key Identifier extension.')
            raise

    def _parse_certificate_policies(self, value: bytes, *, critical: bool) -> x509.Extension[x509.CertificatePolicies]:
        """Parse Certificate Policies extension manually."""
        try:
            cert_policies, _ = ber_decoder.decode(value, asn1Spec=rfc2459.CertificatePolicies())

            policy_information_list = []

            for i in range(len(cert_policies)):
                policy_info = cert_policies.getComponentByPosition(i)

                policy_oid = str(policy_info.getComponentByName('policyIdentifier'))

                if policy_info.getComponentByName('policyQualifiers').hasValue():
                    error_message = f'Policy qualifiers are not supported for policy {policy_oid}'
                    self.logger.error(error_message)
                    self._raise_value_error(error_message)

                policy_info_obj = x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier(policy_oid),
                    policy_qualifiers=None
                )
                policy_information_list.append(policy_info_obj)

            certificate_policies = x509.CertificatePolicies(policy_information_list)
            oid = ExtensionOID.CERTIFICATE_POLICIES

            if not isinstance(oid, x509.ObjectIdentifier):
                self.logger.warning('Invalid OID type: %(oid_type)s',
                                    extra={'oid_type': type(oid).__name__})
                self._raise_value_error('Invalid OID type')

            return x509.Extension(
                oid=oid,
                critical=critical,
                value=certificate_policies
            )

        except Exception:
            self.logger.exception('Failed to parse Certificate Policies extension')
            raise

    def _raise_value_error(self, message: str) -> Never:
        """Helper function to raise a ValueError with the given message."""
        raise ValueError(message)

    def _raise_not_implemented_error(self, message: str) -> None:
        """Helper function to raise NotImplementedError with a given message."""
        raise NotImplementedError(message)

    def parse_ircr_body(self, context: CmpCertificateRequestContext, pki_body: rfc4210.PKIBody, body_type: str) -> None:
        """Extract the certificate request messages from CMP IR/CR body."""
        cert_req_messages = pki_body[body_type]
        self._validate_cert_req_messages(cert_req_messages)

        cert_req_msg = cert_req_messages[0]['certReq']
        request_builder = self._validate_cert_request(cert_req_msg)

        context.cert_requested = request_builder


class CmpBodyValidation(ParsingComponent, LoggerMixin):
    """Component for validating CMP body based on operation context."""

    def parse(self, context: BaseRequestContext) -> CmpBaseRequestContext:
        """Validate the CMP body type and extract the appropriate body."""
        if not isinstance(context, CmpBaseRequestContext):
            exc_msg = 'CmpBodyValidation requires a CmpBaseRequestContext.'
            raise TypeError(exc_msg)

        if context.parsed_message is None:
            error_message = 'Parsed message is missing from the context.'
            self.logger.warning('CMP body type validation failed: Parsed message is missing')
            self._raise_value_error(error_message)

        try:
            if not hasattr(context.parsed_message, '__getitem__'):
                error_message = 'Parsed message is not a CMP message structure.'
                self.logger.warning('CMP body type validation failed: Invalid message structure')
                self._raise_value_error(error_message)

            parsed_message = context.parsed_message
            if not hasattr(parsed_message, '__getitem__'):
                error_message = 'Parsed message is not indexable.'
                self.logger.warning('CMP body type validation failed: Message not indexable')
                self._raise_value_error(error_message)

            pki_body = parsed_message['body']

            body_type = pki_body.getName()

            self._validate_body_type_supported(body_type)

            if not context.operation:
                inferred_operation = self._operation_from_body_type(body_type)
                context.operation = inferred_operation
                self.logger.debug('Inferred operation from body type: %s', inferred_operation)

            # Validate body type matches operation
            self._validate_operation_body_match(context.operation, body_type)

            if body_type in ('ir', 'cr'):
                context = context.narrow(CmpCertificateRequestContext)
                CmpCertificateBodyValidation().parse_ircr_body(context, pki_body, body_type)
            elif body_type == 'rr':
                self._raise_not_implemented_error('CMP RR is not implemented yet.')

            self.logger.info('CMP body type validation successful: %s body extracted', body_type.upper())

        except ValueError as e:
            self.logger.exception('CMP body type validation failed', extra={'error': str(e)})
            raise

        self.logger.debug('Context obj type: %s', type(context).__name__)
        return context

    def _validate_body_type_supported(self, body_type: str) -> None:
        """Validate that the CMP body type is supported by the request pipeline."""
        if body_type not in ('ir', 'cr'):
            err_msg = f'Unsupported CMP body type: {body_type}'
            self._raise_value_error(err_msg)

    def _operation_from_body_type(self, body_type: str) -> str | None:
        """Map CMP body type to operation."""
        if body_type == 'ir':
            return 'initialization'
        if body_type == 'cr':
            return 'certification'
        if body_type == 'rr':
            return 'revocation'
        err_msg = f'Unsupported CMP body type: {body_type}'
        self._raise_value_error(err_msg)
        return None

    def _validate_operation_body_match(self, operation: str | None, body_type: str) -> None:
        """Validate that the operation matches the body type."""
        if operation == 'initialization':
            if body_type != 'ir':
                err_msg = f'Expected CMP IR body for initialization operation, but got CMP {body_type.upper()} body.'
                raise ValueError(err_msg)
            return
        if operation == 'certification':
            if body_type != 'cr':
                err_msg = f'Expected CMP CR body for certification operation, but got CMP {body_type.upper()} body.'
                raise ValueError(err_msg)
            return
        if operation == 'revocation':
            if body_type != 'rr':
                err_msg = f'Expected CMP RR body for revocation operation, but got CMP {body_type.upper()} body.'
                raise ValueError(err_msg)
            return

    def _raise_value_error(self, message: str) -> Never:
        """Helper function to raise a ValueError with the given message."""
        raise ValueError(message)

    def _raise_not_implemented_error(self, message: str) -> None:
        """Helper function to raise NotImplementedError with a given message."""
        raise NotImplementedError(message)


class CmpMessageParser(CompositeParsing):
    """Parser for CMP-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the composite parser with the default set of parsing components."""
        super().__init__()
        self.add(CmpPkiMessageParsing())
        self.add(CmpHeaderValidation())
        self.add(CmpBodyValidation())
        self.add(DomainParsing())
        self.add(CertProfileParsing())
