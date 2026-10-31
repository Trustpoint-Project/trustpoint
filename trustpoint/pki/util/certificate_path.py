# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Certificate-path validation for upstream-issued device credentials."""

from cryptography import x509
from cryptography.x509.general_name import UnsupportedGeneralNameType
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import Criticality, ExtensionPolicy, Policy, PolicyBuilder, Store, VerificationError

_MINIMUM_ISSUED_PATH_LENGTH = 2


def _validate_optional_san(
    _policy: Policy,
    certificate: x509.Certificate,
    extension: x509.ExtensionType | None,
) -> None:
    """Allow DN-only identities while retaining RFC 5280's empty-subject rules."""
    if extension is None:
        if not certificate.subject:
            msg = 'An empty certificate subject requires a critical subjectAltName.'
            raise ValueError(msg)
        return
    if not isinstance(extension, x509.SubjectAlternativeName) or not extension:
        msg = 'Certificate subjectAltName must contain at least one name.'
        raise ValueError(msg)
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    if not certificate.subject and not san.critical:
        msg = 'An empty certificate subject requires a critical subjectAltName.'
        raise ValueError(msg)


def _leaf_extended_key_usage(certificate: x509.Certificate) -> set[x509.ObjectIdentifier] | None:
    """Return the credential's authorized purposes without imposing a TLS role."""
    try:
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return None
    if not usage:
        msg = 'Certificate extendedKeyUsage must not be empty.'
        raise ValueError(msg)
    return set(usage)


def validate_issued_certificate_path(
    leaf: x509.Certificate,
    trust_anchors: list[x509.Certificate],
    intermediates: list[x509.Certificate],
) -> list[x509.Certificate]:
    """Build and validate an end-entity path to an explicitly configured CA anchor.

    Return the verified path in leaf-first order. Enrollment profile validation
    separately binds the subject, key and extensions to the authorized request;
    this verifier must support server, client and non-TLS credentials alike.
    Unsupported critical extensions and certificate-policy constraints fail
    closed. Revocation checking is outside this path-validation operation.
    """
    leaf_eku = _leaf_extended_key_usage(leaf)

    def validate_ca_eku(
        _policy: Policy,
        _certificate: x509.Certificate,
        extension: x509.ExtensionType | None,
    ) -> None:
        """Require constrained issuers to permit every purpose claimed by the leaf."""
        if extension is None:
            return
        if not isinstance(extension, x509.ExtendedKeyUsage) or not extension:
            msg = 'CA extendedKeyUsage must not be empty.'
            raise ValueError(msg)
        if ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in extension:
            return
        if leaf_eku is None or not leaf_eku <= set(extension):
            msg = 'Certificate extendedKeyUsage exceeds its issuing CA constraints.'
            raise ValueError(msg)

    # Keep the library's CA signing, critical-extension and name-constraint
    # validators. Only replace its TLS-client-specific purpose restrictions.
    ca_policy = ExtensionPolicy.webpki_defaults_ca().may_be_present(
        x509.ExtendedKeyUsage,
        Criticality.AGNOSTIC,
        validate_ca_eku,
    )
    ee_policy = (
        ExtensionPolicy.webpki_defaults_ee()
        .may_be_present(x509.SubjectAlternativeName, Criticality.AGNOSTIC, _validate_optional_san)
        .may_be_present(x509.ExtendedKeyUsage, Criticality.AGNOSTIC, None)
    )
    # The underlying verifier does not implement certificate-policy processing.
    # Reject constraints even when non-critical rather than silently ignore them.
    for extension_type in (x509.PolicyConstraints, x509.InhibitAnyPolicy):
        ca_policy = ca_policy.require_not_present(extension_type)
        ee_policy = ee_policy.require_not_present(extension_type)

    try:
        verified = (
            PolicyBuilder()
            .store(Store(trust_anchors))
            .extension_policies(ca_policy=ca_policy, ee_policy=ee_policy)
            .build_client_verifier()
            .verify(leaf, intermediates)
        )
    except (VerificationError, UnsupportedGeneralNameType, ValueError) as exc:
        msg = 'Upstream-issued certificate does not chain to the configured issuing truststore with a valid path.'
        raise ValueError(msg) from exc

    if len(verified.chain) < _MINIMUM_ISSUED_PATH_LENGTH:
        msg = 'Upstream-issued certificate must chain to a configured CA, not be trusted directly.'
        raise ValueError(msg)
    return verified.chain
