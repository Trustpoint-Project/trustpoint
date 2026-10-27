# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides the `AuthorizationComponent` class for authorization logic."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.x509.base import CertificateBuilder

from aoki.views import AokiServiceMixin
from management.models import SecurityConfig
from pki.models import IssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.security_policy import (
    CryptographicPolicy,
    curve_oid_for_key,
    enforce_cryptographic_policy,
    hash_oid_for_name,
    public_key_facts,
    signature_facts,
)
from request.profile_validator import ProfileValidator
from request.request_context import BaseCertificateRequestContext, BaseRequestContext
from trustpoint.logger import LoggerMixin

_CertRequest = x509.CertificateSigningRequest | CertificateBuilder

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ec

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

        if not context.domain:
            error_message = 'Domain information is missing in the context. Authorization denied.'
            self.logger.warning('Certificate profile authorization failed: Domain information is missing')
            raise ValueError(error_message)

        if not context.device:
            error_message = 'Device information is missing in the context. Authorization denied.'
            self.logger.warning('Certificate profile authorization failed: Device information is missing')
            raise ValueError(error_message)

        if not requested_profile and context.domain_str == '.aoki':
            # For AOKI requests, if no profile is specified, default to the domain credential profile
            requested_profile = context.domain.get_domain_credential_profile_name()
            context.cert_profile_str = requested_profile

        if not requested_profile:
            error_message = 'Certificate profile is missing in the context. Authorization denied.'
            self.logger.warning('Certificate profile authorization failed: Profile information is missing')
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

        if (not context.device.onboarding_config
            and context.certificate_profile_model.credential_type
            == CertificateProfileModel.ProfileCredentialType.DOMAIN):
            context.http_response_content = f'Not authorized for requested certificate profile "{requested_profile}".'
            context.http_response_status = 403
            error_message = (
                f"No-Onboarding Device '{context.device.common_name}' "
                f"is not allowed to request domain credential profiles."
            )
            self.logger.warning(error_message)
            raise ValueError(error_message)

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


class OnboardingDomainCredentialAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures that a device requiring onboarding has a valid domain credential first."""

    _DEFAULT_DOMAIN_CREDENTIAL_PROFILES: frozenset[str] = frozenset({
        'domain_credential',
    })

    def authorize(self, context: BaseRequestContext) -> None:
        """Reject enrollment when the onboarding device lacks a valid domain credential."""
        if not isinstance(context, BaseCertificateRequestContext):
            return

        device = context.device
        if device is None or device.onboarding_config is None:
            return

        profile_model = context.certificate_profile_model
        if profile_model is None:
            return

        domain_cred_profile_names = set(self._DEFAULT_DOMAIN_CREDENTIAL_PROFILES)
        if context.domain is not None:
            domain_cred_profile_names.add(context.domain.get_domain_credential_profile_name())

        if profile_model.unique_name in domain_cred_profile_names:
            return

        domain_creds = IssuedCredentialModel.objects.filter(
            device=device,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            credential__certificate__isnull=False,
        ).select_related('credential__certificate')

        has_valid = any(cred.is_valid_domain_credential()[0] for cred in domain_creds)

        if not has_valid:
            error_message = (
                f"Device '{device.common_name}' requires onboarding but has no valid domain credential. "
                f"A domain credential must be issued before enrolling for profile "
                f"'{profile_model.unique_name}'."
            )
            self.logger.warning(
                'Onboarding domain credential authorization failed for device %s: '
                'no valid domain credential found',
                device.common_name,
            )
            context.http_response_content = error_message
            context.http_response_status = 403
            raise ValueError(error_message)



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

        owner_credential = (
            AokiServiceMixin.get_owner_credential(client_cert)
            or AokiServiceMixin.get_domain_based_owner_credential(context.domain)
        )
        if not owner_credential:
            err_msg = 'No DevOwnerID credential present for this IDevID.'
            context.http_response_content = err_msg
            context.http_response_status = 403
            self.logger.warning(err_msg)
            raise ValueError(err_msg)

        context.owner_credential = owner_credential

class SecurityConfigAuthorization(AuthorizationComponent, LoggerMixin):
    """Validates a certificate request against the active :class:`~management.models.SecurityConfig` policy."""

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

        policy = CryptographicPolicy.from_config(cfg)
        key = self._get_public_key(csr) if csr is not None else None
        enforce_cryptographic_policy(
            policy,
            key=public_key_facts(key) if key is not None else None,
            signature=signature_facts(csr) if isinstance(csr, x509.CertificateSigningRequest) else None,
        )

        profile_validated = context.cert_requested_profile_validated
        ca_check_target: _CertRequest | None = (
            profile_validated
            if isinstance(profile_validated, (x509.CertificateSigningRequest, CertificateBuilder))
            else csr
        )
        self._check_ca_issuance(ca_check_target, cfg)

    @staticmethod
    def _get_public_key(req: _CertRequest) -> object | None:
        """Read a CSR key, or the optional key on an unsigned builder."""
        return req.public_key() if isinstance(req, x509.CertificateSigningRequest) else req._public_key  # noqa: SLF001

    @staticmethod
    def _ec_curve_oid(key: ec.EllipticCurvePublicKey) -> str | None:
        """Retain the existing helper while delegating to the shared OID registry."""
        return curve_oid_for_key(key)

    @staticmethod
    def _hash_oid(hash_name: str) -> str | None:
        """Retain the existing helper while delegating digest normalization."""
        return hash_oid_for_name(hash_name)

    def _check_key_constraints(self, csr: _CertRequest | None, cfg: SecurityConfig) -> None:
        """Enforce the shared key policy when a request already has a public key."""
        if csr is not None and (key := self._get_public_key(csr)) is not None:
            enforce_cryptographic_policy(CryptographicPolicy.from_config(cfg), key=public_key_facts(key))

    def _check_signature_algorithm(self, csr: _CertRequest | None, cfg: SecurityConfig) -> None:
        """Enforce the shared signature policy on signed CSRs."""
        if isinstance(csr, x509.CertificateSigningRequest):
            enforce_cryptographic_policy(CryptographicPolicy.from_config(cfg), signature=signature_facts(csr))

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
