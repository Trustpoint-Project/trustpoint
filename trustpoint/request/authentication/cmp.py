"""Provides the 'CmpAuthentication' class using the Composite pattern for modular CMP authentication."""

from typing import Never

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1_modules import rfc4210  # type: ignore[import-untyped]
from trustpoint_core.oid import AlgorithmIdentifier, HashAlgorithm, HmacAlgorithm, SignatureSuite

from devices.models import DeviceModel
from onboarding.models import (
    NoOnboardingConfigModel,
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
)
from pki.util.idevid import IDevIDAuthenticator
from request.request_context import (
    BaseRequestContext,
    CmpBaseRequestContext,
    CmpCertificateRequestContext,
    CmpRevocationRequestContext,
)
from trustpoint.logger import LoggerMixin

from .base import AuthenticationComponent, ClientCertificateAuthentication, CompositeAuthentication


class CmpAuthenticationBase(AuthenticationComponent, LoggerMixin):
    """Base class for CMP authentication components with common functionality."""

    def _is_aoki_request(self, context: CmpBaseRequestContext) -> bool:
        """Determine if this is an AOKI request based on domain name and URL path."""
        domain_name = context.domain_str
        request_path = getattr(context, 'request_path', None)

        if hasattr(context, 'raw_message') and context.raw_message:
            request_path = context.raw_message.path

        return bool(domain_name == '.aoki' and request_path and '/p/.aoki/initialization' in request_path)

    def _verify_protection_signature(self, parsed_message: rfc4210.PKIMessage,
                                     cmp_signer_cert: x509.Certificate) -> None:
        """Verifies the message signature of a CMP message using signature-based protection."""
        protected_part = rfc4210.ProtectedPart()
        protected_part['header'] = parsed_message['header']
        protected_part['infoValue'] = parsed_message['body']
        encoded_protected_part = encoder.encode(protected_part)

        protection_value = parsed_message['protection'].asOctets()
        signature_suite = SignatureSuite.from_certificate(cmp_signer_cert)

        hash_algorithm = signature_suite.algorithm_identifier.hash_algorithm
        if hash_algorithm is None:
            err_msg = 'Failed to get the corresponding hash algorithm.'
            raise ValueError(err_msg)

        public_key = cmp_signer_cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature=protection_value,
                data=encoded_protected_part,
                padding=padding.PKCS1v15(),
                algorithm=hash_algorithm.hash_algorithm(),
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature=protection_value,
                data=encoded_protected_part,
                signature_algorithm=ec.ECDSA(hash_algorithm.hash_algorithm()),
            )
        else:
            err_msg = 'Cannot verify signature due to unsupported public key type.'
            raise TypeError(err_msg)

    def _extract_extra_certs(
            self, context: CmpBaseRequestContext) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Extract and validate extra certificates from the CMP message.

        The first certificate is considered the CMP signer certificate, and the rest are intermediates.
        """
        if not context or not context.parsed_message:
            err_msg = 'Missing parsed message in context.'
            self._raise_value_error(err_msg)

        if not isinstance(context.parsed_message, rfc4210.PKIMessage):
            err_msg = 'Invalid parsed message type.'
            self._raise_value_error(err_msg)

        extra_certs = context.parsed_message['extraCerts']
        if extra_certs is None or len(extra_certs) == 0:
            err_msg = 'No extra certificates found in the PKIMessage.'
            self._raise_value_error(err_msg)

        cmp_signer_extra_cert = extra_certs[0]
        cmp_signer_cert = x509.load_der_x509_certificate(encoder.encode(cmp_signer_extra_cert))

        intermediate_certs = []
        loaded_cert = None
        for cert in extra_certs[1:]:
            loaded_cert = x509.load_der_x509_certificate(encoder.encode(cert))
            if loaded_cert.subject.public_bytes() != loaded_cert.issuer.public_bytes():
                intermediate_certs.append(loaded_cert)

        if not cmp_signer_cert:
            self._raise_value_error('CMP signer certificate missing in extra certs.')

        return cmp_signer_cert, intermediate_certs

    def _verify_protection_and_finalize(
        self, context: CmpBaseRequestContext, cmp_signer_cert: x509.Certificate, device: DeviceModel
    ) -> None:
        """Verify protection signature and finalize authentication."""
        # Verify protection signature
        self._verify_protection_signature(
            parsed_message=context.parsed_message,
            cmp_signer_cert=cmp_signer_cert
        )

        if not device.domain:
            self._raise_value_error('Device is not part of any domain.')

        if not context.domain:
            context.domain = device.domain

        self.logger.info(
            'Successfully authenticated device via CMP signature-based certification',
            extra={'device_common_name': device.common_name})
        context.device = device
        context.client_certificate = cmp_signer_cert

    def _raise_value_error(self, message: str) -> Never:
        """Helper method to log and raise a ValueError."""
        self.logger.warning(message)
        raise ValueError(message)

    def _raise_type_error(self, message: str) -> Never:
        """Helper method to log and raise a TypeError."""
        self.logger.warning(message)
        raise TypeError(message)


class CmpSharedSecretAuthentication(CmpAuthenticationBase):
    """Handles CMP authentication using shared secrets with HMAC-based protection."""

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate using CMP shared secret HMAC protection."""
        if not isinstance(context, CmpBaseRequestContext):
            exc_msg = 'CmpSharedSecretAuthentication requires a CmpBaseRequestContext.'
            raise TypeError(exc_msg)

        if not self._validate_context(context):
            return

        try:
            sender_kid = self._extract_sender_kid(context)
            device = self._get_device(sender_kid)
            device_config = self._validate_device_configuration(device, sender_kid)
            self._verify_hmac_protection(context, device_config.cmp_shared_secret)
            self._finalize_authentication(context, device, sender_kid)

        except (DeviceModel.DoesNotExist, ValueError, TypeError) as e:
            self._handle_authentication_error(e)
        except Exception as e:  # noqa: BLE001
            self._handle_unexpected_error(e)

    def _validate_context(self, context: CmpBaseRequestContext) -> bool:
        """Validate the context for CMP shared secret authentication."""
        if context.protocol != 'cmp':
            error_message = 'CMP shared secret authentication requires CMP protocol.'
            self.logger.warning("Invalid protocol '%s' for CMP authentication", context.protocol)
            raise ValueError(error_message)

        if not context.parsed_message:
            error_message = 'CMP shared secret authentication requires a parsed message.'
            self.logger.warning('No parsed message available for CMP authentication')
            raise ValueError(error_message)

        if not isinstance(context.parsed_message, rfc4210.PKIMessage):
            error_message = 'CMP shared secret authentication requires a PKIMessage.'
            self.logger.warning("Invalid message type '%s' for CMP authentication", type(context.parsed_message))
            raise TypeError(error_message)

        protection_algorithm = AlgorithmIdentifier.from_dotted_string(
            context.parsed_message['header']['protectionAlg']['algorithm'].prettyPrint()
        )

        if protection_algorithm != AlgorithmIdentifier.PASSWORD_BASED_MAC:
            # Not a password-based MAC protected message, skip this authentication method
            return False

        if self._is_aoki_request(context):
            error_message = 'AOKI only supported with signature-based protection (IDevID).'
            self.logger.warning(error_message)
            self._raise_cmp_error(error_message)

        return True

    def _raise_value_error(self, message: str) -> Never:
        """Raise a ValueError with the given message."""
        self.logger.warning(message)
        raise ValueError(message)

    def _extract_sender_kid(self, context: CmpBaseRequestContext) -> int:
        """Extract sender KID from CMP message header."""
        try:
            if not isinstance(context.parsed_message, rfc4210.PKIMessage):
                error_message = 'CMP shared secret authentication failed: Invalid parsed message type.'
                self._raise_value_error(error_message)
            return int(context.parsed_message['header']['senderKID'].prettyPrint())
        except (ValueError, TypeError) as e:
            error_message = ('CMP shared secret authentication failed: '
                           'Invalid or missing senderKID in message header.')
            self.logger.warning('CMP message missing or has invalid senderKID')
            raise ValueError(error_message) from e

    def _get_device(self, sender_kid: int) -> DeviceModel:
        """Get device by sender KID."""
        try:
            return DeviceModel.objects.get(pk=sender_kid)
        except DeviceModel.DoesNotExist:
            error_message = f'CMP shared secret authentication failed: Device with ID {sender_kid} not found.'
            self.logger.warning(error_message)
            raise ValueError(error_message) from None

    def _validate_device_configuration(self, device: DeviceModel, sender_kid: int
                                       ) -> OnboardingConfigModel | NoOnboardingConfigModel:
        """Validate device has required shared secret configuration."""
        device_config = device.onboarding_config or device.no_onboarding_config
        if not device_config or not device_config.cmp_shared_secret:
            error_message = 'CMP shared secret authentication failed: Device has no shared secret configured.'
            self.logger.warning(
                'Device %s (ID: %s) has no CMP shared secret configured', device.common_name, sender_kid)
            self._raise_cmp_error(error_message)
        return device_config

    def _verify_hmac_protection(self, context: CmpBaseRequestContext, shared_secret: str) -> None:
        """Verify HMAC-based protection and store shared secret for response."""
        self._verify_protection_shared_secret(context.parsed_message, shared_secret)
        context.cmp_shared_secret = shared_secret

    def _finalize_authentication(self, context: CmpBaseRequestContext, device: DeviceModel, sender_kid: int) -> None:
        """Finalize authentication by setting device in context and logging success."""
        self.logger.info(
            'Successfully authenticated device %s (ID: %s) via CMP shared secret', device.common_name, sender_kid)
        context.device = device
        if not context.domain:
            context.domain = device.domain

    def _handle_authentication_error(self, error: Exception) -> None:
        """Handle known authentication errors."""
        if 'senderKID' in str(error):
            error_message = ('CMP shared secret authentication failed: '
                           'Invalid or missing senderKID in message header.')
            self.logger.warning('CMP message missing or has invalid senderKID')
        else:
            error_message = f'CMP shared secret authentication failed: {error}'
            self.logger.warning('CMP shared secret authentication error: %s', error)
        raise ValueError(error_message) from error

    def _handle_unexpected_error(self, error: Exception) -> None:
        """Handle unexpected errors during authentication."""
        error_message = 'CMP shared secret authentication failed due to unexpected error'
        self.logger.exception('Unexpected error during CMP shared secret authentication')
        raise ValueError(error_message) from error

    def _raise_cmp_error(self, message: str) -> Never:
        """Raise CMP authentication error."""
        raise ValueError(message)

    @staticmethod
    def _verify_protection_shared_secret(
            parsed_message: rfc4210.PKIMessage, shared_secret: str) -> hmac.HMAC:
        """Verifies the HMAC-based protection of a CMP message using a shared secret.

        Returns a new HMAC object that can be used to sign the response message.
        """
        pbm_parameters_bitstring = parsed_message['header']['protectionAlg']['parameters']
        decoded_pbm, _ = decoder.decode(pbm_parameters_bitstring, asn1Spec=rfc4210.PBMParameter())

        salt = decoded_pbm['salt'].asOctets()
        try:
            owf = HashAlgorithm.from_dotted_string(decoded_pbm['owf']['algorithm'].prettyPrint())
        except Exception as exception:
            err_msg = 'owf algorithm not supported.'
            raise ValueError(err_msg) from exception

        iteration_count = int(decoded_pbm['iterationCount'])

        shared_secret_bytes = shared_secret.encode()
        salted_secret = shared_secret_bytes + salt
        hmac_key = salted_secret
        for _ in range(iteration_count):
            hasher = hashes.Hash(owf.hash_algorithm())
            hasher.update(hmac_key)
            hmac_key = hasher.finalize()

        hmac_algorithm_oid = decoded_pbm['mac']['algorithm'].prettyPrint()
        try:
            hmac_algorithm = HmacAlgorithm.from_dotted_string(hmac_algorithm_oid)
        except Exception as exception:
            err_msg = 'hmac algorithm not supported.'
            raise ValueError(err_msg) from exception

        protected_part = rfc4210.ProtectedPart()
        protected_part['header'] = parsed_message['header']
        protected_part['infoValue'] = parsed_message['body']
        encoded_protected_part = encoder.encode(protected_part)

        protection_value = parsed_message['protection'].asOctets()

        hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
        hmac_gen.update(encoded_protected_part)

        try:
            hmac_gen.verify(protection_value)
        except InvalidSignature as exception:
            err_msg = f'hmac verification failed: {exception}'
            raise ValueError(err_msg) from exception

        return hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())


class CmpSignatureBasedInitializationAuthentication(CmpAuthenticationBase):
    """Handles CMP signature-based authentication for initialization requests using IDevID certificates."""

    def __init__(self) -> None:
        """Initialize the CMP signature-based authentication component."""


    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate using CMP signature-based protection for initialization requests."""
        if not isinstance(context, CmpCertificateRequestContext):
            exc_msg = 'CmpSignatureBasedInitializationAuthentication requires a CmpCertificateRequestContext.'
            raise TypeError(exc_msg)

        if not self._should_authenticate(context):
            return

        cmp_signer_cert, intermediate_certs = self._extract_extra_certs(context)
        context.client_certificate = cmp_signer_cert
        device = self._authenticate_and_verify_device(context, cmp_signer_cert, intermediate_certs)
        self.logger.info(
            'Successfully authenticated device via CMP signature-based initialization',
            extra={'device_common_name': device.common_name})
        context.device = device

    def _authenticate_and_verify_device(self,
                                        context: CmpCertificateRequestContext,
                                        cmp_signer_cert: x509.Certificate,
                                        intermediate_certs: list[x509.Certificate]) -> DeviceModel:
        """Authenticate and verify the device."""
        try:
            device = self._process_device_authentication(context, cmp_signer_cert, intermediate_certs)
        except Exception as e:  # noqa: BLE001
            self._handle_authentication_error(e)
        else:
            return device

    def _process_device_authentication(
        self, context: CmpCertificateRequestContext,
        cmp_signer_cert: x509.Certificate, intermediate_certs: list[x509.Certificate]
    ) -> DeviceModel:
        """Process device authentication using certificates."""
        device = self._authenticate_device(context, cmp_signer_cert, intermediate_certs)
        self._verify_device_configuration(device)
        self._verify_protection_signature(context.parsed_message, cmp_signer_cert)
        return device

    def _handle_authentication_error(self, error: Exception) -> Never:
        """Handle authentication errors by logging and raising a ValueError."""
        error_message = f'CMP signature-based initialization authentication failed: {error}'
        self.logger.warning(error_message)
        raise ValueError(error_message) from error

    def _should_authenticate(self, context: CmpCertificateRequestContext) -> bool:
        """Validate the context for CMP IR authentication."""
        if context.protocol != 'cmp':
            self._raise_value_error('CMP sig-based authentication requires CMP protocol.')

        if context.operation != 'initialization':
            return False

        if not context.parsed_message:
            self._raise_value_error('CMP sig-based authentication requires a parsed message.')

        if not isinstance(context.parsed_message, rfc4210.PKIMessage):
            self._raise_value_error('CMP sig-based authentication requires a PKIMessage.')

        return True

    def _authenticate_device(self, context: CmpCertificateRequestContext, cmp_signer_cert: x509.Certificate,
                             intermediate_certs: list[x509.Certificate]) -> DeviceModel:
        """Authenticate the device using IDevID."""
        is_aoki = self._is_aoki_request(context)
        device = IDevIDAuthenticator.authenticate_idevid_from_x509(
            idevid_cert=cmp_signer_cert,
            intermediate_cas=intermediate_certs,
            domain=None if is_aoki else context.domain,
            onboarding_protocol=OnboardingProtocol.CMP_IDEVID,
            pki_protocol=OnboardingPkiProtocol.CMP,
        )

        if not device.domain:
            self._raise_value_error('Device domain is not set.')

        if not context.domain and device.domain:
            context.domain = device.domain

        return device

    def _verify_device_configuration(self, device: DeviceModel) -> None:
        """Verify the device's configuration and protocols."""
        if not device.onboarding_config:
            self._raise_value_error('The corresponding device is not configured to use the onboarding mechanism.')

        if device.onboarding_config.onboarding_protocol != OnboardingProtocol.CMP_IDEVID:
            self._raise_value_error('Wrong onboarding protocol.')

        if not device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP):
            self._raise_value_error('PKI protocol CMP expected, but got something else.')


class CmpSignatureBasedCertificationAuthentication(CmpAuthenticationBase):
    """Handles CMP signature-based authentication for certification requests using domain credentials."""

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate using CMP signature-based protection for certification requests."""
        if not isinstance(context, CmpCertificateRequestContext):
            exc_msg = 'CmpSignatureBasedCertificationAuthentication requires a CmpCertificateRequestContext.'
            raise TypeError(exc_msg)

        if not self._should_authenticate(context):
            return

        try:
            cmp_signer_cert, _ = self._extract_extra_certs(context)
            context.client_certificate = cmp_signer_cert
            device = self._authenticate_device(context)
            self._verify_protection_and_finalize(context, cmp_signer_cert, device)

        except Exception as e:
            error_message = f'CMP signature-based certification authentication failed: {e}'
            self.logger.warning(error_message)
            raise ValueError(error_message) from e

    def _should_authenticate(self, context: CmpCertificateRequestContext) -> bool:
        """Check if this authentication method should be applied."""
        if context.protocol != 'cmp':
            return False

        if context.operation != 'certification':
            return False

        if not context.parsed_message:
            error_message = 'CMP shared secret authentication requires a parsed message.'
            self.logger.warning('No parsed message available for CMP authentication')
            self._raise_value_error(error_message)

        if not isinstance(context.parsed_message, rfc4210.PKIMessage):
            error_message = 'CMP shared secret authentication requires a PKIMessage.'
            self.logger.warning("Invalid message type '%s' for CMP authentication", type(context.parsed_message))
            self._raise_value_error(error_message)

        # Check if this is signature-based protection
        protection_algorithm = AlgorithmIdentifier.from_dotted_string(
            context.parsed_message['header']['protectionAlg']['algorithm'].prettyPrint()
        )

        if protection_algorithm == AlgorithmIdentifier.PASSWORD_BASED_MAC:
            # This is password-based MAC protection, not signature-based
            return False

        # Check application certificate template is present
        if not context.cert_profile_str:
            error_message = 'Missing application certificate template.'
            self.logger.warning(
                'CMP signature-based certification failed: Missing application certificate template')
            self._raise_value_error(error_message)

        return True

    def _authenticate_device(self, context: CmpCertificateRequestContext) -> DeviceModel:
        """Authenticate the device using the CMP signer certificate."""
        cmp_signer_cert = context.client_certificate
        if not cmp_signer_cert:
            err_msg = 'CMP signer certificate is missing in context client_certificate.'
            self._raise_value_error(err_msg)
        device_info = self._extract_device_info(cmp_signer_cert)
        if device_info['device_id'] is None:
            self.logger.warning(
                'Device ID missing in CMP signer cert subject. Falling back to fingerprint-based DB lookup.'
            )
            ClientCertificateAuthentication().authenticate(context)
            if context.device:
                return context.device

        device = self._lookup_device(device_info)
        self._validate_device(device, device_info, cmp_signer_cert)
        return device

    def _extract_device_info(self, cmp_signer_cert: x509.Certificate) -> dict[str, str | int | None]:
        """Extract device information from certificate subject."""
        try:
            subj = cmp_signer_cert.subject

            user_ids = subj.get_attributes_for_oid(x509.NameOID.USER_ID)
            device_id = user_ids[0].value if user_ids else None

            serial_nos = subj.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)
            serial_no_raw = serial_nos[0].value if serial_nos else None

            domain_components = subj.get_attributes_for_oid(x509.NameOID.DOMAIN_COMPONENT)
            domain_name_raw = domain_components[0].value if domain_components else None

            common_names = subj.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            common_name = common_names[0].value if common_names else None

            if isinstance(device_id, bytes):
                device_id = device_id.decode()

            # Parse serial number value
            device_serial_number = serial_no_raw.decode() if isinstance(serial_no_raw, bytes) else serial_no_raw

            # Parse domain name value
            domain_name = domain_name_raw.decode() if isinstance(domain_name_raw, bytes) else domain_name_raw

            # Parse common name value
            common_name_value = common_name.decode() if isinstance(common_name, bytes) else common_name

        except (IndexError, ValueError) as e:
            err_msg = f'Failed to extract device information from certificate: {e}'
            self._raise_value_error(err_msg)
        else:
            return {
                'device_id': device_id,
                'serial_number': device_serial_number,
                'domain_name': domain_name,
                'common_name': common_name_value
            }

    def _lookup_device(self, device_info: dict[str, str | int | None]) -> DeviceModel:
        """Look up the device by ID."""
        device_model = None
        if device_info['device_id']:
            try:
                device_model = DeviceModel.objects.get(pk=device_info['device_id'])
            except DeviceModel.DoesNotExist:
                device_model = None
                self.logger.warning(
                    'Device with ID %s not found in database.',
                    device_info['device_id']
                )

        if not device_model:
            error_message = 'Device not found.'
            self.logger.warning(
                'CMP signature-based certification failed: Device not found',
                extra={'device_id': device_info['device_id']}
            )
            self._raise_value_error(error_message)

        return device_model

    def _validate_device(
            self, device: DeviceModel, device_info: dict[str, str | int | None], cmp_signer_cert: x509.Certificate
        ) -> None:
        """Validate device properties and certificate."""
        # Validate device serial number
        if device_info['serial_number'] and device_info['serial_number'] != device.serial_number:
            err_msg = 'SN mismatch'
            self.logger.warning('CMP signature-based certification failed', extra={'error_message': err_msg})
            self._raise_value_error(err_msg)

        # Validate device domain
        if not device.domain:
            err_msg = 'The device is not part of any domain.'
            self.logger.warning('CMP signature-based certification failed', extra={'error_message': err_msg})
            self._raise_value_error(err_msg)

        if device_info['domain_name'] and device_info['domain_name'] != device.domain.unique_name:
            err_msg = 'Domain mismatch.'
            self.logger.warning('CMP signature-based certification failed', extra={'error_message': err_msg})
            self._raise_value_error(err_msg)

        # Verify certificate was issued by domain's issuing CA
        issuing_ca_credential = device.domain.get_issuing_ca_or_value_error().get_credential()
        issuing_ca_cert = issuing_ca_credential.get_certificate()
        cmp_signer_cert.verify_directly_issued_by(issuing_ca_cert)

        # Device configuration validation
        if not device.onboarding_config:
            error_message = 'The corresponding device is not configured to use the onboarding mechanism.'
            self._raise_value_error(error_message)

        if not device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP):
            error_message = 'PKI protocol CMP client certificate expected, but got something else.'
            self.logger.warning(
                'Device has wrong PKI protocol',
                extra={
                    'device_common_name': device.common_name,
                    'device_pki_protocol': device.onboarding_config.get_pki_protocols()
                }
            )
            self._raise_value_error(error_message)


class CmpSignatureBasedRevocationAuthentication(CmpAuthenticationBase):
    """Handles CMP signature-based authentication for revocation requests using domain credentials."""

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate using CMP signature-based protection for revocation requests."""
        if not isinstance(context, CmpRevocationRequestContext):
            exc_msg = 'CmpSignatureBasedRevocationAuthentication requires a CmpRevocationRequestContext.'
            raise TypeError(exc_msg)

        if not self._should_authenticate(context):
            return

        cmp_signer_cert, _ = self._extract_extra_certs(context)
        context.client_certificate = cmp_signer_cert
        device = self._authenticate_device(context)
        self._verify_protection_and_finalize(context, cmp_signer_cert, device)

    def _should_authenticate(self, context: CmpRevocationRequestContext) -> bool:
        """Check if this authentication method should be applied."""
        if context.protocol != 'cmp':
            return False

        if context.operation != 'revocation':
            return False

        if not context.parsed_message:
            error_message = 'CMP signature-based revocation authentication requires a parsed message.'
            self.logger.warning('No parsed message available for CMP authentication')
            self._raise_value_error(error_message)

        if not isinstance(context.parsed_message, rfc4210.PKIMessage):
            error_message = 'CMP signature-based revocation authentication requires a PKIMessage.'
            self.logger.warning("Invalid message type '%s' for CMP authentication", type(context.parsed_message))
            self._raise_value_error(error_message)

        return True

    def _authenticate_device(self, context: CmpRevocationRequestContext) -> DeviceModel:
        """Authenticate the device using the CMP signer certificate."""
        cmp_signer_cert = context.client_certificate
        if not cmp_signer_cert:
            err_msg = 'CMP signer certificate is missing in context client_certificate.'
            self._raise_value_error(err_msg)

        ClientCertificateAuthentication(domain_credential_only=False).authenticate(context)

        if not context.device:
            err_msg = 'Device authentication failed using CMP signer certificate.'
            self._raise_value_error(err_msg)
        return context.device


class CmpAuthentication(CompositeAuthentication):
    """Composite authenticator specifically for CMP requests, combining various authentication methods."""

    def __init__(self) -> None:
        """Initialize the CMP authenticator with a set of authentication methods."""
        super().__init__()
        self.add(CmpSharedSecretAuthentication())
        self.add(CmpSignatureBasedInitializationAuthentication())
        self.add(CmpSignatureBasedCertificationAuthentication())
        self.add(CmpSignatureBasedRevocationAuthentication())
