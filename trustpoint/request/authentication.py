"""Provides the `EstAuthentication` class using the Composite pattern for modular EST authentication."""

from abc import ABC, abstractmethod
from functools import lru_cache
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from pyasn1_modules import rfc4210
from trustpoint_core.oid import HmacAlgorithm, HashAlgorithm, AlgorithmIdentifier, SignatureSuite
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]

from devices.models import DeviceModel, IssuedCredentialModel
from pki.util.idevid import IDevIDAuthenticationError, IDevIDAuthenticator
from django.contrib.auth.hashers import check_password
from trustpoint.logger import LoggerMixin
from cryptography.hazmat.primitives import hashes, hmac

from request.request_context import RequestContext

if TYPE_CHECKING:
    from pki.models import CredentialModel



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
            return None

        username = context.est_username
        password = context.est_password

        try:
            device = DeviceModel.objects.select_related().filter(
                common_name=username
            ).first()

            if not device:
                self.logger.warning(f"Authentication failed: Unknown username {username}")
                raise ValueError('Authentication failed: Invalid username or password.')

            # Use proper password hashing instead of plaintext comparison
            if password != device.est_password:
                self.logger.warning(f"Authentication failed: Invalid password for {username}")
                raise ValueError('Authentication failed: Invalid username or password.')

            self.logger.info(f"Successfully authenticated device {username}")
            context.device = device

        except Exception as e:
            self.logger.error(f"Authentication error for user {username}: {e}")
            error_message = 'Authentication failed: Invalid username or password.'
            raise ValueError(error_message) from e


class ClientCertificateAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via client certificates."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using the client certificate from the context."""
        if not context.client_certificate:
            return None

        client_certificate = context.client_certificate

        try:
            issued_credential = IssuedCredentialModel.get_credential_for_certificate(client_certificate)

            is_valid, reason = issued_credential.is_valid_domain_credential()
            if not is_valid:
                self.logger.warning(f"Invalid client certificate: {reason}")
                error_message = f'Invalid SSL_CLIENT_CERT header: {reason}'
                raise ValueError(error_message)

            self.logger.info("Successfully authenticated device via client certificate")
            context.device = issued_credential.device

        except IssuedCredentialModel.DoesNotExist:
            self.logger.warning("Client certificate not found in issued credentials")
            error_message = 'Client certificate not recognized'
            raise ValueError(error_message) from None
        except ValueError:
            raise
        except Exception as e:
            self.logger.error(f"Certificate authentication error: {e}")
            error_message = 'Certificate authentication failed'
            raise ValueError(error_message) from e


class ReenrollmentAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication for EST reenrollment using an Application Credential."""

    def _validate_certificate_extensions(self, credential_cert, client_cert, csr):
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


    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the client for reenrollment."""
        client_cert = context.client_certificate
        if not client_cert:
            return None

        csr = context.cert_requested
        if not csr:
            error_message = 'CSR is missing in the context for reenrollment.'
            self.logger.warning(error_message)
            raise ValueError(error_message)

        try:
            issued_credential = IssuedCredentialModel.get_credential_for_certificate(client_cert)
        except IssuedCredentialModel.DoesNotExist:
            error_message = "Issued credential not found for client certificate during reenrollment"
            self.logger.warning(error_message)
            raise ValueError(error_message) from None

        credential_model: CredentialModel = issued_credential.credential

        is_valid, reason = credential_model.is_valid_issued_credential()
        if not is_valid:
            error_message = f"Invalid client certificate for reenrollment: {reason}"
            self.logger.warning(error_message)
            raise ValueError(error_message)

        # Verify that the client certificate and CSR subjects match the existing issued credential
        if (
            not credential_model.certificate.subjects_match(csr.subject) or
            not credential_model.certificate.subjects_match(client_cert.subject)
        ):
            error_message = "CSR/client subject does not match the credential certificate's subject"
            self.logger.warning(error_message)
            raise ValueError(error_message)

        try:
            credential_cert = credential_model.certificate.get_certificate_serializer().as_crypto()
            self._validate_certificate_extensions(credential_cert, client_cert, csr)
        except Exception as e:
            self.logger.warning(f"Certificate extension validation failed: {e}")
            error_message = 'Certificate extension validation failed'
            raise ValueError(error_message) from e

        self.logger.info("Successfully authenticated device for reenrollment")
        context.device = issued_credential.device


class IDevIDAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via IDevID certificates."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the request using the IDevID mechanism."""
        # Early return if domain is missing
        if not context.domain:
            return None

        # Early return if raw_message is missing
        if not context.raw_message:
            return None

        try:
            device_or_none = IDevIDAuthenticator.authenticate_idevid(context.raw_message, context.domain)

            if device_or_none:
                self.logger.info("Successfully authenticated device via IDevID")
                context.device = device_or_none
            else:
                error_message = 'IDevID authentication failed: No device associated.'
                self.logger.warning("IDevID authentication failed: No device associated")
                raise ValueError(error_message)

        except IDevIDAuthenticationError as e:
            error_message = f'Error validating the IDevID: {e}'
            self.logger.warning(f'Error validating the IDevID: {e}')
            raise ValueError(error_message) from e
        except ValueError:
            raise
        except Exception as e:
            error_message = 'IDevID authentication failed due to unexpected error'
            self.logger.error(f"Unexpected error during IDevID authentication: {e}")
            raise ValueError(error_message) from e


#####

class CmpAuthenticationBase(AuthenticationComponent, LoggerMixin):
    """Base class for CMP authentication components with common functionality."""

    def _is_aoki_request(self, context: RequestContext) -> bool:
        """Determine if this is an AOKI request based on domain name and URL path."""
        domain_name = context.domain_str
        request_path = getattr(context, 'request_path', None)

        if hasattr(context, 'raw_message') and context.raw_message:
            request_path = context.raw_message.path

        if domain_name == '.aoki' and request_path and '/initialization/.aoki' in request_path:
            return True

        return False


class CmpSharedSecretAuthentication(CmpAuthenticationBase):
    """Handles CMP authentication using shared secrets with HMAC-based protection."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using CMP shared secret HMAC protection."""

        if context.protocol != 'cmp':
            error_message = 'CMP shared secret authentication requires CMP protocol.'
            self.logger.warning(f"Invalid protocol '{context.protocol}' for CMP authentication")
            raise ValueError(error_message)

        if not context.parsed_message:
            error_message = 'CMP shared secret authentication requires a parsed message.'
            self.logger.warning("No parsed message available for CMP authentication")
            raise ValueError(error_message)

        if not isinstance(context.parsed_message, rfc4210.PKIMessage):
            error_message = 'CMP shared secret authentication requires a PKIMessage.'
            self.logger.warning(f"Invalid message type '{type(context.parsed_message)}' for CMP authentication")
            raise ValueError(error_message)

        try:

            protection_algorithm = AlgorithmIdentifier.from_dotted_string(
                context.parsed_message['header']['protectionAlg']['algorithm'].prettyPrint()
            )

            if protection_algorithm != AlgorithmIdentifier.PASSWORD_BASED_MAC:
                # Not a password-based MAC protected message, skip this authentication method
                return None

            is_aoki = self._is_aoki_request(context)

            if is_aoki:
                error_message = 'AOKI only supported with signature-based protection (IDevID).'
                self.logger.warning(error_message)
                raise ValueError(error_message)

            # Extract the sender KID from the CMP message header to identify the device
            sender_kid = int(context.parsed_message['header']['senderKID'].prettyPrint())

            device = DeviceModel.objects.get(pk=sender_kid)
            shared_secret = device.cmp_shared_secret

            if not shared_secret:
                error_message = 'CMP shared secret authentication failed: Device has no shared secret configured.'
                self.logger.warning(
                    f"Device {device.common_name} (ID: {sender_kid}) has no CMP shared secret configured")
                raise ValueError(error_message)

            # Verify the HMAC-based protection and get HMAC object for response
            hmac_obj = self._verify_protection_shared_secret(
                context.parsed_message,
                shared_secret
            )

            context.cmp_shared_secret = shared_secret

            self.logger.info(
                f"Successfully authenticated device {device.common_name} (ID: {sender_kid}) via CMP shared secret")
            context.device = device

        except DeviceModel.DoesNotExist:
            error_message = f'CMP shared secret authentication failed: Device with ID {sender_kid} not found.'
            self.logger.warning(error_message)
            raise ValueError(error_message) from None
        except (ValueError, TypeError) as e:
            if 'senderKID' in str(e):
                error_message = 'CMP shared secret authentication failed: Invalid or missing senderKID in message header.'
                self.logger.warning("CMP message missing or has invalid senderKID")
            else:
                error_message = f'CMP shared secret authentication failed: {e}'
                self.logger.warning(f"CMP shared secret authentication error: {e}")
            raise ValueError(error_message) from e
        except Exception as e:
            error_message = 'CMP shared secret authentication failed due to unexpected error'
            self.logger.error(f"Unexpected error during CMP shared secret authentication: {e}")
            raise ValueError(error_message) from e

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

        if context.protocol != 'cmp':
            error_message = 'CMP shared secret authentication requires CMP protocol.'
            self.logger.warning(f"Invalid protocol '{context.protocol}' for CMP authentication")
            raise ValueError(error_message)

        if context.operation != 'initialization':
            return None

        if not context.parsed_message:
            error_message = 'CMP shared secret authentication requires a parsed message.'
            self.logger.warning("No parsed message available for CMP authentication")
            raise ValueError(error_message)

        if not isinstance(context.parsed_message, rfc4210.PKIMessage):
            error_message = 'CMP shared secret authentication requires a PKIMessage.'
            self.logger.warning(f"Invalid message type '{type(context.parsed_message)}' for CMP authentication")
            raise ValueError(error_message)


        try:
            # Check if this is signature-based protection
            protection_algorithm = AlgorithmIdentifier.from_dotted_string(
                context.parsed_message['header']['protectionAlg']['algorithm'].prettyPrint()
            )

            if protection_algorithm == AlgorithmIdentifier.PASSWORD_BASED_MAC:
                # This is password-based MAC protection, not signature-based
                return None

            is_aoki = self._is_aoki_request(context)

            # Extract and validate extra certificates
            extra_certs = context.parsed_message['extraCerts']
            if extra_certs is None or len(extra_certs) == 0:
                err_msg = 'No extra certificates found in the PKIMessage.'
                raise ValueError(err_msg)

            # Extract CMP signer certificate (first extra cert)
            cmp_signer_extra_cert = extra_certs[0]
            der_cmp_signer_cert = encoder.encode(cmp_signer_extra_cert)
            cmp_signer_cert = x509.load_der_x509_certificate(der_cmp_signer_cert)

            # Extract intermediate certificates (remaining extra certs)
            intermediate_certs = []
            for extra_cert in extra_certs[1:]:
                der_extra_cert = encoder.encode(extra_cert)
                loaded_extra_cert = x509.load_der_x509_certificate(der_extra_cert)
                # Do not include self-signed certs
                if loaded_extra_cert.subject.public_bytes() != loaded_extra_cert.issuer.public_bytes():
                    intermediate_certs.append(loaded_extra_cert)

            if not cmp_signer_cert:
                err_msg = 'CMP signer certificate missing in extra certs.'
                raise ValueError(err_msg)

            # Authenticate using IDevID
            device = IDevIDAuthenticator.authenticate_idevid_from_x509(
                idevid_cert=cmp_signer_cert,
                intermediate_cas=intermediate_certs,
                domain=None if is_aoki else context.domain,
                onboarding_protocol=DeviceModel.OnboardingProtocol.CMP_IDEVID,
                pki_protocol=DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE,
            )

            if not device.domain:
                err_msg = 'Device domain is not set.'
                raise ValueError(err_msg)

            # Update context domain if needed
            if not context.domain and device.domain:
                context.domain = device.domain

            # Device sanity checks
            if not device.domain_credential_onboarding:
                err_msg = 'The corresponding device is not configured to use the onboarding mechanism.'
                raise ValueError(err_msg)

            if device.onboarding_protocol != DeviceModel.OnboardingProtocol.CMP_IDEVID:
                err_msg = 'Wrong onboarding protocol.'
                raise ValueError(err_msg)

            if device.pki_protocol != DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE:
                err_msg = 'PKI protocol CMP client certificate expected, but got something else.'
                raise ValueError(err_msg)

            # Verify protection signature
            self._verify_protection_signature(
                serialized_pyasn1_message=context.parsed_message,
                cmp_signer_cert=cmp_signer_cert
            )

            # Store certificates in context for later use
            context.cmp_signer_cert = cmp_signer_cert
            context.intermediate_certs = intermediate_certs

            self.logger.info(
                f"Successfully authenticated device {device.common_name} via CMP signature-based initialization")
            context.device = device

        except Exception as e:
            error_message = f'CMP signature-based initialization authentication failed: {e}'
            self.logger.warning(error_message)
            raise ValueError(error_message) from e

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
        if context.protocol != 'cmp':
            return None

        if context.operation != 'certification':
            return None

        if not context.parsed_message:
            error_message = 'CMP shared secret authentication requires a parsed message.'
            self.logger.warning("No parsed message available for CMP authentication")
            raise ValueError(error_message)

        if not isinstance(context.parsed_message, rfc4210.PKIMessage):
            error_message = 'CMP shared secret authentication requires a PKIMessage.'
            self.logger.warning(f"Invalid message type '{type(context.parsed_message)}' for CMP authentication")
            raise ValueError(error_message)

        try:
            # Check if this is signature-based protection
            protection_algorithm = AlgorithmIdentifier.from_dotted_string(
                context.parsed_message['header']['protectionAlg']['algorithm'].prettyPrint()
            )

            if protection_algorithm == AlgorithmIdentifier.PASSWORD_BASED_MAC:
                # This is password-based MAC protection, not signature-based
                return None

            # Check application certificate template is present
            if not context.certificate_template:
                error_message = 'Missing application certificate template.'
                self.logger.warning(
                    "CMP signature-based certification failed: Missing application certificate template")
                raise ValueError(error_message)

            # Extract and validate extra certificates
            extra_certs = context.parsed_message['extraCerts']
            if extra_certs is None or len(extra_certs) == 0:
                err_msg = 'No extra certificates found in the PKIMessage.'
                raise ValueError(err_msg)

            # Extract CMP signer certificate (first extra cert)
            cmp_signer_extra_cert = extra_certs[0]
            der_cmp_signer_cert = encoder.encode(cmp_signer_extra_cert)
            cmp_signer_cert = x509.load_der_x509_certificate(der_cmp_signer_cert)

            # Extract device information from certificate subject
            device_id = int(cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[0].value)
            device_serial_number = cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
            domain_name = cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.DOMAIN_COMPONENT)[0].value
            common_name = cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]

            # Parse common name value
            if isinstance(common_name.value, str):
                common_name_value = common_name.value
            elif isinstance(common_name.value, bytes):
                common_name_value = common_name.value.decode()
            else:
                err_msg = 'Failed to parse common name value'
                raise TypeError(err_msg)

            # Verify this is a domain credential
            if common_name_value != 'Trustpoint Domain Credential':
                err_msg = 'Not a domain credential.'
                raise ValueError(err_msg)

            # Look up device by ID
            try:
                device = DeviceModel.objects.get(pk=device_id)
            except DeviceModel.DoesNotExist:
                error_message = 'Device not found.'
                self.logger.warning(f"CMP signature-based certification failed: Device {device_id} not found")
                raise ValueError(error_message)

            # Validate device serial number
            if device_serial_number != device.serial_number:
                err_msg = 'SN mismatch'
                self.logger.warning(f"CMP signature-based certification failed: {err_msg}")
                raise ValueError(err_msg)

            # Validate device domain
            if not device.domain:
                err_msg = 'The device is not part of any domain.'
                self.logger.warning(f"CMP signature-based certification failed: {err_msg}")
                raise ValueError(err_msg)

            if domain_name != device.domain.unique_name:
                err_msg = 'Domain mismatch.'
                self.logger.warning(f"CMP signature-based certification failed: {err_msg}")
                raise ValueError(err_msg)

            # Verify certificate was issued by domain's issuing CA
            issuing_ca_credential = device.domain.get_issuing_ca_or_value_error().credential
            issuing_ca_cert = issuing_ca_credential.get_certificate()
            cmp_signer_cert.verify_directly_issued_by(issuing_ca_cert)

            # Device configuration validation
            if not device.domain_credential_onboarding:
                error_message = 'The corresponding device is not configured to use the onboarding mechanism.'
                self.logger.warning(f"Device {device.common_name} not configured for onboarding")
                raise ValueError(error_message)

            if device.pki_protocol != DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE:
                error_message = 'PKI protocol CMP client certificate expected, but got something else.'
                self.logger.warning(f"Device {device.common_name} has wrong PKI protocol: {device.pki_protocol}")
                raise ValueError(error_message)

            # Verify protection signature
            self._verify_protection_signature(
                serialized_pyasn1_message=context.parsed_message,
                cmp_signer_cert=cmp_signer_cert
            )

            # Store certificates and credentials in context for later use
            context.cmp_signer_cert = cmp_signer_cert
            context.issuing_ca_credential = issuing_ca_credential
            context.issuing_ca_cert = issuing_ca_cert

            self.logger.info(
                f"Successfully authenticated device {device.common_name} via CMP signature-based certification")
            context.device = device

        except Exception as e:
            error_message = f'CMP signature-based certification authentication failed: {e}'
            self.logger.warning(error_message)
            raise ValueError(error_message) from e

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
                    self.logger.info(f"Authentication successful using {component.__class__.__name__}")
                    return
            except ValueError as e:
                authentication_errors.append(f"{component.__class__.__name__}: {e}")
                continue
            except Exception as e:
                self.logger.error(f"Unexpected error in {component.__class__.__name__}: {e}")
                authentication_errors.append(f"{component.__class__.__name__}: Unexpected error")
                continue
        error_message = 'Authentication failed: All authentication methods were unsuccessful.'
        self.logger.warning(f"Authentication failed for all methods: {authentication_errors}")
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

