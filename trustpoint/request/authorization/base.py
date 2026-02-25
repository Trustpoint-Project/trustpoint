"""Provides the `AuthorizationComponent` class for authorization logic."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.base import CertificateBuilder
from trustpoint_core.oid import HashAlgorithm, NamedCurve

from aoki.views import AokiServiceMixin
from request.profile_validator import ProfileValidator
from request.request_context import BaseCertificateRequestContext, BaseRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from management.models import SecurityConfig

_CertRequest = x509.CertificateSigningRequest | CertificateBuilder

class AuthorizationComponent(ABC):
    """Abstract base class for authorization components."""

    @abstractmethod
    def authorize(self, context: BaseRequestContext) -> None:
        """Execute authorization logic."""

class ProtocolAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the request is under the correct protocol: CMP or EST."""

    def __init__(self, allowed_protocols: list[str]) -> None:
        """Initialize the authorization component with a list of allowed protocols."""
        self.allowed_protocols = allowed_protocols

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the protocol."""
        protocol = context.protocol

        if not protocol:
            error_message = 'Protocol information is missing. Authorization denied.'
            self.logger.warning('Protocol authorization failed: Protocol information is missing')
            raise ValueError(error_message)

        if protocol not in self.allowed_protocols:
            error_message = (
                f"Unauthorized protocol: '{protocol}'. "
                f"Allowed protocols: {', '.join(self.allowed_protocols)}."
            )
            self.logger.warning(
                'Protocol authorization failed: %(protocol)s not in allowed protocols %(allowed_protocols)s',
                extra={'protocol': protocol, 'allowed_protocols': self.allowed_protocols})
            raise ValueError(error_message)

        self.logger.debug('Protocol authorization successful for protocol: %(protocol)s',
                          extra={'protocol': protocol})


class CertificateProfileAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the device is allowed to use the requested certificate profile."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the certificate profile."""
        if not isinstance(context, BaseCertificateRequestContext):
            # Not a certificate request context; skip profile authorization
            return

        requested_profile = context.cert_profile_str

        if not requested_profile:
            error_message = 'Certificate profile is missing in the context. Authorization denied.'
            self.logger.warning('Certificate profile authorization failed: Profile information is missing')
            raise ValueError(error_message)

        if not context.domain:
            error_message = 'Domain information is missing in the context. Authorization denied.'
            self.logger.warning('Certificate profile authorization failed: Domain information is missing')
            raise ValueError(error_message)

        try:
            context.certificate_profile_model = context.domain.get_allowed_cert_profile(requested_profile)
        except ValueError as e:
            context.http_response_content = f'Not authorized for requested certificate profile "{requested_profile}".'
            context.http_response_status = 403
            error_message = (
                f"Unauthorized certificate profile: '{requested_profile}'. "
                f"Allowed profiles: {', '.join(context.domain.get_allowed_cert_profile_names())}."
            )
            self.logger.warning(error_message)
            raise ValueError(error_message) from e

        ProfileValidator.validate(context)

        self.logger.debug(
            'Certificate profile authorization successful for profile: %s',
            requested_profile
        )


class DomainScopeValidation(AuthorizationComponent, LoggerMixin):
    """Ensures the request is within the authorized domain."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the domain scope."""
        authenticated_device = context.device
        requested_domain = context.domain

        if not authenticated_device:
            error_message = 'Authenticated device is missing in the context. Authorization denied.'
            self.logger.warning('Domain scope validation failed: Authenticated device is missing')
            raise ValueError(error_message)

        if not requested_domain:
            error_message = 'Requested domain is missing in the context. Authorization denied.'
            self.logger.warning('Domain scope validation failed: Requested domain is missing')
            raise ValueError(error_message)

        device_domain = authenticated_device.domain

        if not device_domain or device_domain != requested_domain:
            error_message = (
                f"Unauthorized requested domain: '{requested_domain}'. "
                f"Device domain: '{device_domain}'."
            )
            self.logger.warning(
                "Domain scope validation failed: Device domain %s doesn't match requested domain %s",
                device_domain, requested_domain
            )
            raise ValueError(error_message)

        self.logger.debug(
            'Domain scope validation successful: Device %s authorized for domain %s',
            authenticated_device.common_name, requested_domain
        )


class DevOwnerIDAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensure that if this is an AOKI request, we have a matching DevOwnerID to the IDevID."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the DevOwnerID corresponding to the client certificate."""
        if context.protocol != 'cmp':
            return
        if context.domain_str != '.aoki':
            return

        client_cert = context.client_certificate

        if not client_cert:
            error_message = 'Client certificate is missing in the context. Authorization denied.'
            self.logger.warning('DevOwnerID authorization failed: Client certificate is missing')
            raise ValueError(error_message)

        owner_credential = AokiServiceMixin.get_owner_credential(client_cert)
        if not owner_credential:
            err_msg = 'No DevOwnerID credential present for this IDevID.'
            context.http_response_content = err_msg
            context.http_response_status = 403
            self.logger.warning(err_msg)
            raise ValueError(err_msg)

        context.owner_credential = owner_credential

class SecurityConfigAuthorization(AuthorizationComponent, LoggerMixin):
    """Validates a certificate request against the active :class:`~management.models.SecurityConfig` policy."""

    _EC_CURVE_OID_MAP: ClassVar[dict[type[ec.EllipticCurve], str]] = {
        ec.SECP192R1: NamedCurve.SECP192R1.dotted_string,
        ec.SECP224R1: NamedCurve.SECP224R1.dotted_string,
        ec.SECP256K1: NamedCurve.SECP256K1.dotted_string,
        ec.SECP256R1: NamedCurve.SECP256R1.dotted_string,
        ec.SECP384R1: NamedCurve.SECP384R1.dotted_string,
        ec.SECP521R1: NamedCurve.SECP521R1.dotted_string,
        ec.BrainpoolP256R1: NamedCurve.BRAINPOOLP256R1.dotted_string,
        ec.BrainpoolP384R1: NamedCurve.BRAINPOOLP384R1.dotted_string,
        ec.BrainpoolP512R1: NamedCurve.BRAINPOOLP512R1.dotted_string,
    }

    _HASH_OID_MAP: ClassVar[dict[str, str]] = {
        'md5':    HashAlgorithm.MD5.dotted_string,
        'sha1':   HashAlgorithm.SHA1.dotted_string,
        'sha224': HashAlgorithm.SHA224.dotted_string,
        'sha256': HashAlgorithm.SHA256.dotted_string,
        'sha384': HashAlgorithm.SHA384.dotted_string,
        'sha512': HashAlgorithm.SHA512.dotted_string,
    }

    def authorize(self, context: BaseRequestContext) -> None:
        """Run all applicable :class:`SecurityConfig` policy checks."""
        if not isinstance(context, BaseCertificateRequestContext):
            self.logger.debug(
                'SecurityConfigAuthorization: skipping non-certificate context (%s)',
                context.__class__.__name__,
            )
            return

        csr: _CertRequest | None = (
            context.cert_requested
            if isinstance(context.cert_requested, (x509.CertificateSigningRequest, CertificateBuilder))
            else None
        )

        from management.models import SecurityConfig  # noqa: PLC0415

        try:
            cfg: SecurityConfig = SecurityConfig.objects.get()
        except SecurityConfig.DoesNotExist:
            self.logger.warning(
                'SecurityConfigAuthorization: no SecurityConfig row found; skipping checks.'
            )
            return
        except SecurityConfig.MultipleObjectsReturned:
            cfg = SecurityConfig.objects.first()  # type: ignore[assignment]
            self.logger.warning(
                'SecurityConfigAuthorization: multiple SecurityConfig rows found; using first.'
            )

        self._check_key_constraints(csr, cfg)
        self._check_signature_algorithm(csr, cfg)
        self._check_ca_issuance(csr, cfg)

    @staticmethod
    def _get_public_key(
        req: _CertRequest,
    ) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey | None:
        """Return the public key from either a CSR or a :class:`CertificateBuilder`."""
        if isinstance(req, x509.CertificateSigningRequest):
            pk = req.public_key()
            if isinstance(pk, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
                return pk
            return None
        raw_pk = req._public_key  # noqa: SLF001
        if isinstance(raw_pk, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            return raw_pk
        return None

    @staticmethod
    def _get_signature_hash_name(req: _CertRequest) -> str | None:
        """Return the lower-case hash algorithm name used in the request's signature."""
        if isinstance(req, x509.CertificateSigningRequest):
            sig_hash = req.signature_hash_algorithm
            return sig_hash.name if sig_hash is not None else None
        # TODO (FHK): CertificateBuilder has no signature yet — hash algorithm is chosen at sign() time.  # noqa: FIX002
        return None

    @classmethod
    def _ec_curve_oid(cls, key: ec.EllipticCurvePublicKey) -> str | None:
        """Return the dotted-string OID for an EC public key's curve, or ``None`` if unknown."""
        return cls._EC_CURVE_OID_MAP.get(type(key.curve))

    @classmethod
    def _hash_oid(cls, hash_name: str) -> str | None:
        """Return the dotted-string OID for a hash algorithm name (e.g. ``'sha256'``), or ``None``."""
        return cls._HASH_OID_MAP.get(hash_name.lower().replace('-', ''))

    def _check_key_constraints(
        self,
        csr: _CertRequest | None,
        cfg: SecurityConfig,
    ) -> None:
        """Enforce RSA minimum key size and ECC curve restrictions."""
        if csr is None:
            return

        public_key = self._get_public_key(csr)
        if public_key is None:
            return

        if isinstance(public_key, rsa.RSAPublicKey):
            min_size = cfg.rsa_minimum_key_size
            if min_size is None:
                msg = 'RSA keys are not permitted by the active security policy.'
                self.logger.warning('SecurityConfigAuthorization: %s', msg)
                raise ValueError(msg)
            key_size = public_key.key_size
            if key_size < min_size:
                msg = (
                    f'RSA key size {key_size} bits is below the minimum of '
                    f'{min_size} bits required by the active security policy.'
                )
                self.logger.warning('SecurityConfigAuthorization: %s', msg)
                raise ValueError(msg)

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            not_permitted: list[str] = cfg.not_permitted_ecc_curve_oids or []
            if not_permitted:
                curve_oid = self._ec_curve_oid(public_key)
                if curve_oid and curve_oid in not_permitted:
                    curve_name = type(public_key.curve).__name__
                    msg = (
                        f"ECC curve '{curve_name}' is not permitted by the active security policy."
                    )
                    self.logger.warning('SecurityConfigAuthorization: %s', msg)
                    raise ValueError(msg)

    def _check_signature_algorithm(
        self,
        csr: _CertRequest | None,
        cfg: SecurityConfig,
    ) -> None:
        """Enforce signature hash algorithm restrictions from the request."""
        if csr is None:
            return

        not_permitted: list[str] = cfg.not_permitted_signature_algorithm_oids or []
        if not not_permitted:
            return

        hash_name = self._get_signature_hash_name(csr)
        if hash_name is None:
            return

        hash_oid = self._hash_oid(hash_name)
        if hash_oid and hash_oid in not_permitted:
            msg = (
                f"Signature hash algorithm '{hash_name}' is not permitted "
                f'by the active security policy.'
            )
            self.logger.warning('SecurityConfigAuthorization: %s', msg)
            raise ValueError(msg)


    @staticmethod
    def _get_extensions(req: _CertRequest) -> x509.Extensions:
        """Return the extensions from either a CSR or a :class:`CertificateBuilder`."""
        if isinstance(req, x509.CertificateSigningRequest):
            return req.extensions
        raw: list[x509.Extension[x509.ExtensionType]] = list(req._extensions)  # noqa: SLF001
        return x509.Extensions(raw)

    def _check_ca_issuance(
        self,
        csr: _CertRequest | None,
        cfg: SecurityConfig,
    ) -> None:
        """Reject CA certificate requests when :attr:`SecurityConfig.allow_ca_issuance` is ``False``."""
        if cfg.allow_ca_issuance or csr is None:
            return

        for ext in self._get_extensions(csr):
            if isinstance(ext.value, x509.BasicConstraints) and ext.value.ca:
                msg = (
                    'CA certificate issuance (BasicConstraints ca=True) is not permitted '
                    'by the active security policy.'
                )
                self.logger.warning('SecurityConfigAuthorization: %s', msg)
                raise ValueError(msg)


class CompositeAuthorization(AuthorizationComponent, LoggerMixin):
    """Composite authorization handler for grouping and executing multiple authorization components."""

    def __init__(self) -> None:
        """Initialize the composite authorization handler with an empty list of components."""
        self.components: list[AuthorizationComponent] = []

    def add(self, component: AuthorizationComponent) -> None:
        """Add a new authorization component to the composite."""
        self.components.append(component)

    def remove(self, component: AuthorizationComponent) -> None:
        """Remove an authorization component from the composite."""
        if component in self.components:
            self.components.remove(component)
            self.logger.debug('Removed authorization component', extra={'component_name': component.__class__.__name__})
        else:
            error_message = f'Attempted to remove non-existent authorization component: {component.__class__.__name__}'
            self.logger.warning(error_message)
            raise ValueError(error_message)

    def authorize(self, context: BaseRequestContext) -> None:
        """Iterate through all child authorization components and execute their authorization logic."""
        self.logger.debug('Starting composite authorization with %d components', len(self.components))

        for i, component in enumerate(self.components):
            try:
                component.authorize(context)
                self.logger.debug('Authorization component passed',
                                  extra={'component_name': component.__class__.__name__})
            except ValueError as e:
                error_message = f'{component.__class__.__name__}: {e}'
                self.logger.warning('Authorization component failed',
                                    extra={'component_name': component.__class__.__name__, 'error_message': str(e)})
                self.logger.exception(
                    'Composite authorization failed at component %d/%d: %s',
                    i + 1, len(self.components), component.__class__.__name__)
                raise ValueError(error_message) from e
            except Exception as e:
                error_message = f'Unexpected error in {component.__class__.__name__}: {e}'
                self.logger.exception(
                    'Unexpected error in authorization component %s',
                    component.__class__.__name__
                )
                self.logger.exception(
                    'Composite authorization failed at component %d/%d: %s',
                    i + 1, len(self.components), component.__class__.__name__)
                raise ValueError(error_message) from e

        self.logger.info('Composite authorization successful. All %d components passed', len(self.components))
