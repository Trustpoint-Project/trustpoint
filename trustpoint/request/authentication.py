"""Provides the `EstAuthentication` class using the Composite pattern for modular EST authentication."""

from abc import ABC, abstractmethod
from typing import Never

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from devices.models import DeviceModel, IssuedCredentialModel, OnboardingPkiProtocol, OnboardingProtocol
from pki.models import CredentialModel
from pki.util.idevid import IDevIDAuthenticationError, IDevIDAuthenticator
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1_modules import rfc4210  # type: ignore[import-untyped]
from trustpoint_core.oid import AlgorithmIdentifier, HashAlgorithm, HmacAlgorithm, SignatureSuite

from request.request_context import RequestContext
from trustpoint.logger import LoggerMixin


class AuthenticationComponent(ABC):
    """Abstract base class for authentication components."""

    @abstractmethod
    def authenticate(self, context: RequestContext) -> DeviceModel | None:
        """Authenticate a request using specific logic."""


class UsernamePasswordAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via username/password credentials."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using username and password from the context."""
        if not (context.est_username and context.est_password):
            return

        username = context.est_username
        password = context.est_password

        try:
            device = DeviceModel.objects.select_related().filter(
                common_name=username, no_onboarding_config__isnull=False
            ).first()

            if not device:
                self.logger.warning('Authentication failed: Unknown username %s', username)
                self._raise_authentication_error()

            if not isinstance(device, DeviceModel):
                self.logger.warning('Authentication failed: Invalid device model for %s', username)
                self._raise_authentication_error()

            if not device.no_onboarding_config.est_password:
                self.logger.warning('Authentication failed: No EST password set for %s', username)
                self._raise_authentication_error()

            # Use proper password hashing instead of plaintext comparison
            if password != device.no_onboarding_config.est_password:
                self.logger.warning('Authentication failed: Invalid password for %s', username)
                self._raise_authentication_error()

            self.logger.info('Successfully authenticated device %s', username)
            context.device = device

        except Exception as e:
            self.logger.exception('Authentication error for user %s', username)
            error_message = 'Authentication failed: Invalid username or password.'
            raise ValueError(error_message) from e

    def _raise_authentication_error(self) -> Never:
        """Raise authentication error with standardized message."""
        error_message = 'Authentication failed: Invalid username or password.'
        raise ValueError(error_message)


class ClientCertificateAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via client certificates."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using the client certificate from the context."""
        if not context.client_certificate:
            return

        client_certificate = context.client_certificate

        try:
            issued_credential = IssuedCredentialModel.get_credential_for_certificate(client_certificate)

            is_valid, reason = issued_credential.is_valid_domain_credential()
            if not is_valid:
                self.logger.warning('Invalid client certificate: %s', reason)
                error_message = f'Invalid SSL_CLIENT_CERT header: {reason}'
                self._raise_certificate_error(error_message)

            self.logger.info('Successfully authenticated device via client certificate')
            context.device = issued_credential.device

        except IssuedCredentialModel.DoesNotExist:
            self.logger.warning('Client certificate not found in issued credentials')
            error_message = 'Client certificate not recognized'
            self._raise_certificate_error(error_message)
        except ValueError:
            raise
        except Exception as e:
            self.logger.exception('Certificate authentication error')
            error_message = 'Certificate authentication failed'
            self._raise_certificate_error(error_message, e)

    def _raise_certificate_error(self, message: str, cause: Exception | None = None) -> Never:
        """Raise certificate authentication error with proper exception chaining."""
        if cause:
            raise ValueError(message) from cause
        raise ValueError(message)


class ReenrollmentAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication for EST reenrollment using an Application Credential."""

    def _validate_certificate_extensions(
        self,
        credential_cert: x509.Certificate,
        client_cert: x509.Certificate,
        csr: x509.CertificateSigningRequest
    ) -> None:
        """Validate that certificate extensions match between credential, client cert, and CSR."""
        try:
            credential_cert_san = credential_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            credential_cert_san = None

        try:
            csr_san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            csr_san = None

        try:
            client_san = client_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            client_san = None

        if client_san != csr_san or credential_cert_san != csr_san:
            error_message = 'CSR/client SAN does not match the credential certificate SAN.'
            raise ValueError(error_message)

    def _raise_value_error(self, message: str) -> Never:
        """Raise a ValueError with the given message."""
        raise ValueError(message)

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the client for reenrollment."""
        if not self._validate_context(context):
            return

        if not context.client_certificate:
            error_message = 'Client certificate is required for reenrollment.'
            self.logger.warning(error_message)
            self._raise_value_error(error_message)

        issued_credential = self._get_issued_credential(context.client_certificate)
        credential_model: CredentialModel = issued_credential.credential

        if not isinstance(context.cert_requested, x509.CertificateSigningRequest):
            error_message = 'Invalid credential model for reenrollment.'
            self.logger.warning(error_message)
            self._raise_value_error(error_message)

        self._validate_credential(credential_model, context.cert_requested, context.client_certificate)
        self._validate_certificate_extensions_safe(credential_model, context.client_certificate, context.cert_requested)

        self.logger.info('Successfully authenticated device for reenrollment')
        context.device = issued_credential.device

    def _validate_context(self, context: RequestContext) -> bool:
        """Validate the context for reenrollment."""
        if not context.client_certificate:
            return False

        if not isinstance(context.client_certificate, x509.Certificate):
            error_message = 'Invalid client certificate type for reenrollment.'
            self.logger.warning(error_message)
            self._raise_value_error(error_message)

        if not context.cert_requested:
            error_message = 'CSR is missing in the context for reenrollment.'
            self.logger.warning(error_message)
            self._raise_value_error(error_message)

        return True

    def _get_issued_credential(self, client_cert: x509.Certificate) -> IssuedCredentialModel:
        """Retrieve the issued credential for the client certificate."""
        try:
            return IssuedCredentialModel.get_credential_for_certificate(client_cert)
        except IssuedCredentialModel.DoesNotExist:
            error_message = 'Issued credential not found for client certificate during reenrollment'
            self.logger.warning(error_message)
            raise ValueError(error_message) from None

    def _validate_credential(
        self, credential_model: CredentialModel, csr: x509.CertificateSigningRequest, client_cert: x509.Certificate
    ) -> None:
        """Validate the credential model against the CSR and client certificate."""
        is_valid, reason = credential_model.is_valid_issued_credential()
        if not is_valid:
            error_message = f'Invalid client certificate for reenrollment: {reason}'
            self.logger.warning(error_message)
            raise ValueError(error_message)

        if (
            not credential_model.certificate.subjects_match(csr.subject) or
            not credential_model.certificate.subjects_match(client_cert.subject)
        ):
            error_message = "CSR/client subject does not match the credential certificate's subject"
            self.logger.warning(error_message)
            raise ValueError(error_message)

    def _validate_certificate_extensions_safe(
        self, credential_model: CredentialModel, client_cert: x509.Certificate, csr: x509.CertificateSigningRequest
    ) -> None:
        """Safely validate certificate extensions."""
        try:
            credential_cert = credential_model.certificate.get_certificate_serializer().as_crypto()
            self._validate_certificate_extensions(credential_cert, client_cert, csr)
        except Exception as e:
            self.logger.warning('Certificate extension validation failed: %s', e)
            error_message = 'Certificate extension validation failed'
            raise ValueError(error_message) from e


class IDevIDAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via IDevID certificates."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the request using the IDevID mechanism."""
        # Early return if domain is missing
        if not context.domain:
            return

        # Early return if raw_message is missing
        if not context.raw_message:
            return

        try:
            device_or_none = IDevIDAuthenticator.authenticate_idevid(context.raw_message, context.domain)

            if device_or_none:
                self.logger.info('Successfully authenticated device via IDevID')
                context.device = device_or_none
            else:
                error_message = 'IDevID authentication failed: No device associated.'
                self.logger.warning('IDevID authentication failed: No device associated')
                self._raise_idevid_error(error_message)

        except IDevIDAuthenticationError as e:
            error_message = f'Error validating the IDevID: {e}'
            self.logger.warning('Error validating the IDevID: %s', e)
            raise ValueError(error_message) from e
        except ValueError:
            raise
        except Exception as e:
            error_message = 'IDevID authentication failed due to unexpected error'
            self.logger.exception('Unexpected error during IDevID authentication')
            raise ValueError(error_message) from e

    def _raise_idevid_error(self, message: str) -> Never:
        """Raise IDevID authentication error."""
        raise ValueError(message)


#####

class CmpAuthenticationBase(AuthenticationComponent, LoggerMixin):
    """Base class for CMP authentication components with common functionality."""

    def _is_aoki_request(self, context: RequestContext) -> bool:
        """Determine if this is an AOKI request based on domain name and URL path."""
        domain_name = context.domain_str
        request_path = getattr(context, 'request_path', None)

        if hasattr(context, 'raw_message') and context.raw_message:
            request_path = context.raw_message.path

        return bool(domain_name == '.aoki' and request_path and '/initialization/.aoki' in request_path)


class CmpSharedSecretAuthentication(CmpAuthenticationBase):
    """Handles CMP authentication using shared secrets with HMAC-based protection."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using CMP shared secret HMAC protection."""
        if not self._validate_context(context):
            return

        try:
            sender_kid = self._extract_sender_kid(context)
            device = self._get_device(sender_kid)
            self._validate_device_configuration(device, sender_kid)
            self._verify_hmac_protection(context, device.no_onboarding_config.cmp_shared_secret)
            self._finalize_authentication(context, device, sender_kid)

        except (DeviceModel.DoesNotExist, ValueError, TypeError) as e:
            self._handle_authentication_error(e)
        except Exception as e:  # noqa: BLE001
            self._handle_unexpected_error(e)

    def _validate_context(self, context: RequestContext) -> bool:
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

    def _extract_sender_kid(self, context: RequestContext) -> int:
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

    def _validate_device_configuration(self, device: DeviceModel, sender_kid: int) -> None:
        """Validate device has required shared secret configuration."""
        if not device.no_onboarding_config or not device.no_onboarding_config.cmp_shared_secret:
            error_message = 'CMP shared secret authentication failed: Device has no shared secret configured.'
            self.logger.warning(
                'Device %s (ID: %s) has no CMP shared secret configured', device.common_name, sender_kid)
            self._raise_cmp_error(error_message)

    def _verify_hmac_protection(self, context: RequestContext, shared_secret: str) -> None:
        """Verify HMAC-based protection and store shared secret for response."""
        self._verify_protection_shared_secret(context.parsed_message, shared_secret)
        context.cmp_shared_secret = shared_secret

    def _finalize_authentication(self, context: RequestContext, device: DeviceModel, sender_kid: int) -> None:
        """Finalize authentication by setting device in context and logging success."""
        self.logger.info(
            'Successfully authenticated device %s (ID: %s) via CMP shared secret', device.common_name, sender_kid)
        context.device = device

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
            serialized_pyasn1_message: rfc4210.PKIMessage, shared_secret: str) -> hmac.HMAC:
        """Verifies the HMAC-based protection of a CMP message using a shared secret.

        Returns a new HMAC object that can be used to sign the response message.
        """
        pbm_parameters_bitstring = serialized_pyasn1_message['header']['protectionAlg']['parameters']
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
        protected_part['header'] = serialized_pyasn1_message['header']
        protected_part['infoValue'] = serialized_pyasn1_message['body']
        encoded_protected_part = encoder.encode(protected_part)

        protection_value = serialized_pyasn1_message['protection'].asOctets()

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


    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using CMP signature-based protection for initialization requests."""
        if not self._validate_context(context):
            return

        cmp_signer_cert, intermediate_certs = self._extract_certificates(context)
        device = self._authenticate_and_verify_device(context, cmp_signer_cert, intermediate_certs)
        self.logger.info(
            'Successfully authenticated device via CMP signature-based initialization',
            extra={'device_common_name': device.common_name})
        context.device = device

    def _authenticate_and_verify_device(self,
                                        context: RequestContext,
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
        self, context: RequestContext, cmp_signer_cert: x509.Certificate, intermediate_certs: list[x509.Certificate]
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

    def _validate_context(self, context: RequestContext) -> bool:
        """Validate the context for CMP authentication."""
        if context.protocol != 'cmp':
            self._raise_value_error('CMP shared secret authentication requires CMP protocol.')

        if context.operation != 'initialization':
            return False

        if not context.parsed_message:
            self._raise_value_error('CMP shared secret authentication requires a parsed message.')

        if not isinstance(context.parsed_message, rfc4210.PKIMessage):
            self._raise_value_error('CMP shared secret authentication requires a PKIMessage.')

        return True

    def _extract_certificates(self, context: RequestContext) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Extract and validate certificates from the CMP message."""
        if not context or not context.parsed_message:
            err_msg = 'Missing parsed message in context.'
            self._raise_value_error(err_msg)

        if not isinstance(context.parsed_message, rfc4210.PKIMessage):
            err_msg = 'Invalid parsed message type.'
            self._raise_value_error(err_msg)

        extra_certs = context.parsed_message['extraCerts']
        if not extra_certs:
            self._raise_value_error('No extra certificates found in the PKIMessage.')

        cmp_signer_extra_cert = extra_certs[0]
        cmp_signer_cert = x509.load_der_x509_certificate(encoder.encode(cmp_signer_extra_cert))

        intermediate_certs = [
            x509.load_der_x509_certificate(encoder.encode(cert))
            for cert in extra_certs[1:]
            if cert.subject.public_bytes() != cert.issuer.public_bytes()
        ]

        if not cmp_signer_cert:
            self._raise_value_error('CMP signer certificate missing in extra certs.')

        return cmp_signer_cert, intermediate_certs

    def _authenticate_device(self, context: RequestContext, cmp_signer_cert: x509.Certificate,
                             intermediate_certs: list[x509.Certificate]) -> DeviceModel:
        """Authenticate the device using IDevID."""
        is_aoki = self._is_aoki_request(context)
        device = IDevIDAuthenticator.authenticate_idevid_from_x509(
            idevid_cert=cmp_signer_cert,
            intermediate_cas=intermediate_certs,
            domain=None if is_aoki else context.domain,
            onboarding_protocol=DeviceModel.OnboardingProtocol.CMP_IDEVID,
            pki_protocol=DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE,
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

        if device.onboarding_config.onboarding_pki_protocol != OnboardingPkiProtocol.CMP_CLIENT_CERTIFICATE:
            self._raise_value_error('PKI protocol CMP client certificate expected, but got something else.')

    def _raise_value_error(self, message: str) -> Never:
        """Helper method to log and raise a ValueError."""
        self.logger.warning(message)
        raise ValueError(message)

    def _verify_protection_signature(self, serialized_pyasn1_message: rfc4210.PKIMessage,
                                     cmp_signer_cert: x509.Certificate) -> None:
        """Verifies the message signature of a CMP message using signature-based protection."""
        protected_part = rfc4210.ProtectedPart()
        protected_part['header'] = serialized_pyasn1_message['header']
        protected_part['infoValue'] = serialized_pyasn1_message['body']
        encoded_protected_part = encoder.encode(protected_part)

        protection_value = serialized_pyasn1_message['protection'].asOctets()
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


class CmpSignatureBasedCertificationAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles CMP signature-based authentication for certification requests using domain credentials."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using CMP signature-based protection for certification requests."""
        if not self._should_authenticate(context):
            return

        try:
            cmp_signer_cert = self._extract_and_validate_certificate(context)
            device = self._authenticate_device(cmp_signer_cert, context)
            self._verify_protection_and_finalize(context, cmp_signer_cert, device)

        except Exception as e:
            error_message = f'CMP signature-based certification authentication failed: {e}'
            self.logger.warning(error_message)
            raise ValueError(error_message) from e

    def _should_authenticate(self, context: RequestContext) -> bool:
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
        if not context.certificate_template:
            error_message = 'Missing application certificate template.'
            self.logger.warning(
                'CMP signature-based certification failed: Missing application certificate template')
            self._raise_value_error(error_message)

        return True

    def _extract_and_validate_certificate(self, context: RequestContext) -> x509.Certificate:
        """Extract and validate the CMP signer certificate from the message."""
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

        # Extract CMP signer certificate (first extra cert)
        cmp_signer_extra_cert = extra_certs[0]
        der_cmp_signer_cert = encoder.encode(cmp_signer_extra_cert)
        return x509.load_der_x509_certificate(der_cmp_signer_cert)

    def _authenticate_device(self, cmp_signer_cert: x509.Certificate, context: RequestContext) -> DeviceModel:
        """Authenticate the device using the CMP signer certificate."""
        del context
        device_info = self._extract_device_info(cmp_signer_cert)
        device = self._lookup_device(device_info)
        self._validate_device(device, device_info, cmp_signer_cert)
        return device

    def _extract_device_info(self, cmp_signer_cert: x509.Certificate) -> dict[str, str | int]:
        """Extract device information from certificate subject."""
        try:
            device_id = int(cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[0].value)
            device_serial_number_raw = cmp_signer_cert.subject.get_attributes_for_oid(
                x509.NameOID.SERIAL_NUMBER)[0].value
            domain_name_raw = cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.DOMAIN_COMPONENT)[0].value
            common_name = cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]

            # Parse serial number value
            if isinstance(device_serial_number_raw, str):
                device_serial_number = device_serial_number_raw
            elif isinstance(device_serial_number_raw, bytes):
                device_serial_number = device_serial_number_raw.decode()
            else:
                err_msg = 'Failed to parse serial number value'
                self._raise_type_error(err_msg)

            # Parse domain name value
            if isinstance(domain_name_raw, str):
                domain_name = domain_name_raw
            elif isinstance(domain_name_raw, bytes):
                domain_name = domain_name_raw.decode()
            else:
                err_msg = 'Failed to parse domain name value'
                self._raise_type_error(err_msg)

            # Parse common name value
            if isinstance(common_name.value, str):
                common_name_value = common_name.value
            elif isinstance(common_name.value, bytes):
                common_name_value = common_name.value.decode()
            else:
                err_msg = 'Failed to parse common name value'
                self._raise_type_error(err_msg)

            # Verify this is a domain credential
            if common_name_value != 'Trustpoint Domain Credential':
                err_msg = 'Not a domain credential.'
                self._raise_value_error(err_msg)

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

    def _lookup_device(self, device_info: dict[str, str | int]) -> DeviceModel:
        """Look up the device by ID."""
        try:
            return DeviceModel.objects.get(pk=device_info['device_id'])
        except DeviceModel.DoesNotExist:
            error_message = 'Device not found.'
            self.logger.warning(
                'CMP signature-based certification failed: Device not found',
                extra={'device_id': device_info['device_id']}
            )
            self._raise_value_error(error_message)

    def _validate_device(
            self, device: DeviceModel, device_info: dict[str, str | int], cmp_signer_cert: x509.Certificate) -> None:
        """Validate device properties and certificate."""
        # Validate device serial number
        if device_info['serial_number'] != device.serial_number:
            err_msg = 'SN mismatch'
            self.logger.warning('CMP signature-based certification failed', extra={'error_message': err_msg})
            self._raise_value_error(err_msg)

        # Validate device domain
        if not device.domain:
            err_msg = 'The device is not part of any domain.'
            self.logger.warning('CMP signature-based certification failed', extra={'error_message': err_msg})
            self._raise_value_error(err_msg)

        if device_info['domain_name'] != device.domain.unique_name:
            err_msg = 'Domain mismatch.'
            self.logger.warning('CMP signature-based certification failed', extra={'error_message': err_msg})
            self._raise_value_error(err_msg)

        # Verify certificate was issued by domain's issuing CA
        issuing_ca_credential = device.domain.get_issuing_ca_or_value_error().credential
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

    def _verify_protection_and_finalize(
        self, context: RequestContext, cmp_signer_cert: x509.Certificate, device: DeviceModel
    ) -> None:
        """Verify protection signature and finalize authentication."""
        # Verify protection signature
        self._verify_protection_signature(
            serialized_pyasn1_message=context.parsed_message,
            cmp_signer_cert=cmp_signer_cert
        )

        if not device.domain:
            self._raise_value_error('Device is not part of any domain.')

        device.domain.get_issuing_ca_or_value_error() #.credential # ???

        self.logger.info(
            'Successfully authenticated device via CMP signature-based certification',
            extra={'device_common_name': device.common_name})
        context.device = device

    def _raise_value_error(self, message: str) -> Never:
        """Helper method to log and raise a ValueError."""
        raise ValueError(message)

    def _raise_type_error(self, message: str) -> Never:
        """Helper method to log and raise a TypeError."""
        raise TypeError(message)

    def _verify_protection_signature(self, serialized_pyasn1_message: rfc4210.PKIMessage,
                                     cmp_signer_cert: x509.Certificate) -> None:
        """Verifies the message signature of a CMP message using signature-based protection."""
        protected_part = rfc4210.ProtectedPart()
        protected_part['header'] = serialized_pyasn1_message['header']
        protected_part['infoValue'] = serialized_pyasn1_message['body']
        encoded_protected_part = encoder.encode(protected_part)

        protection_value = serialized_pyasn1_message['protection'].asOctets()
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

class CompositeAuthentication(AuthenticationComponent, LoggerMixin):
    """Composite authenticator for grouping and executing multiple authentication methods."""

    def __init__(self) -> None:
        """Initialize the composite authenticator with a set of authentication components."""
        self.components: list[AuthenticationComponent] = []

    def add(self, component: AuthenticationComponent) -> None:
        """Add an authentication component to the composite."""
        self.components.append(component)

    def remove(self, component: AuthenticationComponent) -> None:
        """Remove an authentication component from the composite."""
        self.components.remove(component)

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the request using all registered components."""
        authentication_errors = []

        for component in self.components:
            try:
                component.authenticate(context)
                if context.device is not None:
                    self.logger.info('Authentication successful using %s', component.__class__.__name__)
                    return
            except ValueError as e:
                authentication_errors.append(f'{component.__class__.__name__}: {e}')
                continue
            except Exception:
                self.logger.exception('Unexpected error in %s', component.__class__.__name__)
                authentication_errors.append(f'{component.__class__.__name__}: Unexpected error')
                continue
        error_message = 'Authentication failed: All authentication methods were unsuccessful.'
        self.logger.warning('Authentication failed for all methods: %s', authentication_errors)
        raise ValueError(error_message)

class EstAuthentication(CompositeAuthentication):
    """Composite authenticator specifically for EST requests, combining various authentication methods."""

    def __init__(self) -> None:
        """Initialize the EST authenticator with a set of authentication methods."""
        super().__init__()
        self.add(ReenrollmentAuthentication())
        self.add(UsernamePasswordAuthentication())
        self.add(ClientCertificateAuthentication())
        self.add(IDevIDAuthentication())

class CmpAuthentication(CompositeAuthentication):
    """Composite authenticator specifically for CMP requests, combining various authentication methods."""

    def __init__(self) -> None:
        """Initialize the CMP authenticator with a set of authentication methods."""
        super().__init__()
        self.add(CmpSharedSecretAuthentication())
        self.add(CmpSignatureBasedInitializationAuthentication())
        self.add(CmpSignatureBasedCertificationAuthentication())

