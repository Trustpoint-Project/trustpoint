# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Security invariants for EST/CMP request processing.

This module centralises the hardening controls derived from the Trustpoint
request-workflow threat review.  It intentionally sits around the existing
parser/authentication/authorization components so the security properties are
visible at the protocol orchestration boundary.
"""

from __future__ import annotations

import datetime as dt
import hmac as stdlib_hmac
from typing import TYPE_CHECKING, Protocol, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa
from django.conf import settings
from django.db import transaction
from django.urls import Resolver404, resolve
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1_modules import rfc4210  # type: ignore[import-untyped]
from trustpoint_core.oid import AlgorithmIdentifier, HashAlgorithm, SignatureSuite

from cmp.confirmation import require_awaiting_confirmation
from cmp.models import CmpTransactionModel
from cmp.util import PKI_STATUS_REJECTION, cmp_hmac_algorithm
from devices.secrets import retire_onboarding_secrets
from management.models import SecurityConfig
from onboarding.enums import OnboardingPkiProtocol, OnboardingProtocol, OnboardingStatus
from onboarding.models import OnboardingConfigModel
from pki.models import CaModel, IssuedCredentialModel
from pki.util.idevid import IDevIDAuthenticationError, IDevIDAuthenticator
from request.authentication.base import ClientCertificateAuthentication, IDevIDAuthentication
from request.authentication.cmp import (
    CmpSharedSecretAuthentication,
    CmpSignatureBasedCertificationAuthentication,
    CmpSignatureBasedInitializationAuthentication,
    CmpSignatureBasedPollAuthentication,
    CmpSignatureBasedRevocationAuthentication,
)
from request.authentication.est import ReenrollmentAuthentication, UsernamePasswordAuthentication
from request.cmp_transaction_state import CmpTransactionState
from request.request_context import (
    BaseCertificateRequestContext,
    CmpBaseRequestContext,
    CmpCertConfRequestContext,
    CmpCertificateRequestContext,
    CmpPollRequestContext,
    CmpRevocationRequestContext,
    EstBaseRequestContext,
    EstCertificateRequestContext,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

    from pki.models import TruststoreModel


# Conservative defaults. Deployments can override these in Django settings.
CMP_PBM_MIN_ITERATIONS = int(getattr(settings, 'TRUSTPOINT_CMP_PBM_MIN_ITERATIONS', 1))
CMP_PBM_MAX_ITERATIONS = int(getattr(settings, 'TRUSTPOINT_CMP_PBM_MAX_ITERATIONS', 100_000))
CMP_PBM_MIN_SALT_BYTES = int(getattr(settings, 'TRUSTPOINT_CMP_PBM_MIN_SALT_BYTES', 8))
CMP_PBM_MAX_SALT_BYTES = int(getattr(settings, 'TRUSTPOINT_CMP_PBM_MAX_SALT_BYTES', 64))
ALLOW_PBM_REVOCATION = bool(getattr(settings, 'TRUSTPOINT_CMP_ALLOW_PBM_REVOCATION', False))

_ALLOWED_PBM_OWF = {
    value
    for name in ('SHA256', 'SHA384', 'SHA512', 'SHA3_256', 'SHA3_384', 'SHA3_512')
    if (value := getattr(HashAlgorithm, name, None)) is not None
}

_EXPECTED_SECURITY_CONFIG_COUNT = 1
_EXPECTED_CERT_REQ_MESSAGES = 1

_CERTCONF_ALLOWED_DIGESTS: dict[HashAlgorithm, type[hashes.HashAlgorithm]] = {
    HashAlgorithm.SHA224: hashes.SHA224,
    HashAlgorithm.SHA256: hashes.SHA256,
    HashAlgorithm.SHA384: hashes.SHA384,
    HashAlgorithm.SHA512: hashes.SHA512,
    HashAlgorithm.SHA3_224: hashes.SHA3_224,
    HashAlgorithm.SHA3_256: hashes.SHA3_256,
    HashAlgorithm.SHA3_384: hashes.SHA3_384,
    HashAlgorithm.SHA3_512: hashes.SHA3_512,
}


def require_single_security_config(context: BaseCertificateRequestContext) -> None:
    """Fail closed unless exactly one SecurityConfig exists.

    TP-TA-12: certificate issuance must never become less restrictive merely
    because policy configuration is missing or ambiguous.
    """
    count = SecurityConfig.objects.count()
    if count != _EXPECTED_SECURITY_CONFIG_COUNT:
        context.error('Security policy is unavailable.', http_status=503)
        msg = f'Expected exactly one SecurityConfig row, found {count}.'
        raise ValueError(msg)


def _is_pbm(context: CmpBaseRequestContext) -> bool:
    message = context.parsed_message
    if not isinstance(message, rfc4210.PKIMessage):
        msg = 'CMP message is missing or invalid.'
        raise TypeError(msg)
    oid = message['header']['protectionAlg']['algorithm'].prettyPrint()
    return AlgorithmIdentifier.from_dotted_string(oid) == AlgorithmIdentifier.PASSWORD_BASED_MAC


def validate_cmp_pbm_parameters(context: CmpBaseRequestContext) -> None:
    """Bound attacker-controlled PBM work before authentication.

    TP-TA-04: unauthenticated requests must not be able to request unbounded
    key-derivation work.
    """
    if not _is_pbm(context):
        return

    message = cast('rfc4210.PKIMessage', context.parsed_message)
    parameters = message['header']['protectionAlg']['parameters']
    decoded_pbm, remainder = decoder.decode(parameters, asn1Spec=rfc4210.PBMParameter())
    if remainder:
        msg = 'Unexpected trailing data in CMP PBM parameters.'
        raise ValueError(msg)

    salt = decoded_pbm['salt'].asOctets()
    if not CMP_PBM_MIN_SALT_BYTES <= len(salt) <= CMP_PBM_MAX_SALT_BYTES:
        msg = f'CMP PBM salt length must be between {CMP_PBM_MIN_SALT_BYTES} and {CMP_PBM_MAX_SALT_BYTES} bytes.'
        raise ValueError(msg)

    iteration_count = int(decoded_pbm['iterationCount'])
    if not CMP_PBM_MIN_ITERATIONS <= iteration_count <= CMP_PBM_MAX_ITERATIONS:
        msg = f'CMP PBM iterationCount must be between {CMP_PBM_MIN_ITERATIONS} and {CMP_PBM_MAX_ITERATIONS}.'
        raise ValueError(msg)

    owf = HashAlgorithm.from_dotted_string(decoded_pbm['owf']['algorithm'].prettyPrint())
    if owf not in _ALLOWED_PBM_OWF:
        msg = f'CMP PBM OWF {owf} is not permitted.'
        raise ValueError(msg)

    mac = cmp_hmac_algorithm(decoded_pbm['mac']['algorithm'].prettyPrint())
    permitted = SecurityConfig.objects.get().permitted_cmp_hmac_algorithms
    allowed_macs = {cmp_hmac_algorithm(oid) for oid in permitted}
    if mac not in allowed_macs:
        msg = f'CMP PBM MAC {mac} is not permitted.'
        raise ValueError(msg)


def authenticate_est_request(context: EstCertificateRequestContext) -> None:
    """Authenticate EST without cross-mechanism downgrade.

    TP-TA-02 / TP-TA-05: reenrollment requires the existing application
    credential; simple enrollment uses one explicitly presented mechanism and
    retired onboarding passwords are not accepted after onboarding.
    """
    if context.operation == 'simplereenroll':
        if context.client_certificate is None:
            msg = 'EST simplereenroll requires a client certificate.'
            raise ValueError(msg)
        ReenrollmentAuthentication().authenticate(context)
        return

    if context.operation != 'simpleenroll':
        msg = f'Unsupported EST authentication operation: {context.operation}.'
        raise ValueError(msg)

    if context.client_certificate is not None:
        # A presented certificate is authoritative. Do not silently downgrade to
        # a Basic credential if certificate authentication fails.
        try:
            IssuedCredentialModel.get_credential_for_certificate(context.client_certificate)
        except IssuedCredentialModel.DoesNotExist:
            IDevIDAuthentication().authenticate(context)
        else:
            ClientCertificateAuthentication().authenticate(context)
        return

    if context.est_username and context.est_password:
        UsernamePasswordAuthentication().authenticate(context)
        _reject_retired_onboarding_secret(context)
        return

    msg = 'No permitted EST authentication mechanism was presented.'
    raise ValueError(msg)


def _reject_retired_onboarding_secret(context: EstBaseRequestContext | CmpBaseRequestContext) -> None:
    device = context.device
    config = device.onboarding_config if device is not None else None
    if isinstance(config, OnboardingConfigModel) and config.onboarding_status == OnboardingStatus.ONBOARDED:
        msg = 'Onboarding credential is retired for this device.'
        raise ValueError(msg)


def _extract_cmp_signer(context: CmpBaseRequestContext) -> tuple[x509.Certificate, list[x509.Certificate]]:
    helper = CmpSignatureBasedRevocationAuthentication()
    return helper._extract_extra_certs(context)  # noqa: SLF001


def _verify_declared_signature_algorithm(
    context: CmpBaseRequestContext,
    signer_cert: x509.Certificate,
) -> None:
    """Require the declared CMP protection algorithm to match verifier semantics.

    TP-TA-11: the message-declared algorithm, signer key type and the algorithm
    actually used by the current verifier must agree.
    """
    message = context.parsed_message
    if not isinstance(message, rfc4210.PKIMessage):
        msg = 'CMP message is missing or invalid.'
        raise TypeError(msg)

    declared_oid = message['header']['protectionAlg']['algorithm'].prettyPrint()
    declared = AlgorithmIdentifier.from_dotted_string(declared_oid)
    if declared == AlgorithmIdentifier.PASSWORD_BASED_MAC:
        msg = 'Expected signature-based CMP protection, got PBM.'
        raise ValueError(msg)

    public_key = signer_cert.public_key()
    mldsa_algorithms = (
        (mldsa.MLDSA44PublicKey, AlgorithmIdentifier.ML_DSA_44),
        (mldsa.MLDSA65PublicKey, AlgorithmIdentifier.ML_DSA_65),
        (mldsa.MLDSA87PublicKey, AlgorithmIdentifier.ML_DSA_87),
    )
    for key_type, algorithm in mldsa_algorithms:
        if isinstance(public_key, key_type):
            if declared != algorithm:
                msg = 'CMP protectionAlg is incompatible with the ML-DSA signer key.'
                raise ValueError(msg)
            return

    current_suite = SignatureSuite.from_certificate(signer_cert)
    expected_hash = current_suite.algorithm_identifier.hash_algorithm
    declared_hash = declared.hash_algorithm
    if expected_hash is None or declared_hash is None or expected_hash != declared_hash:
        msg = 'CMP protectionAlg does not match the signature verifier hash algorithm.'
        raise ValueError(msg)

    name = declared.name.upper()
    if isinstance(public_key, rsa.RSAPublicKey) and 'RSA' not in name:
        msg = 'CMP protectionAlg is incompatible with the RSA signer key.'
        raise ValueError(msg)
    if isinstance(public_key, ec.EllipticCurvePublicKey) and 'ECDSA' not in name:
        msg = 'CMP protectionAlg is incompatible with the EC signer key.'
        raise ValueError(msg)


def _require_active_issued_signer(context: CmpBaseRequestContext, *, domain_only: bool) -> None:
    cert = context.client_certificate
    if cert is None:
        msg = 'CMP signer certificate is missing.'
        raise ValueError(msg)
    try:
        issued = IssuedCredentialModel.get_credential_for_certificate(cert)
    except IssuedCredentialModel.DoesNotExist as exc:
        msg = 'CMP signer certificate is not a Trustpoint-issued credential.'
        raise ValueError(msg) from exc

    if domain_only:
        valid, reason = issued.is_valid_domain_credential()
    else:
        valid, reason = issued.credential.is_valid_issued_credential()
    if not valid:
        msg = f'CMP signer credential is not active: {reason}'
        raise ValueError(msg)
    device = context.device
    domain = context.domain
    if device is not None and issued.device_id != device.id:
        msg = 'CMP signer credential belongs to a different device.'
        raise ValueError(msg)
    if domain is not None and issued.domain_id != domain.id:
        msg = 'CMP signer credential belongs to a different domain.'
        raise ValueError(msg)


def authenticate_cmp_request(  # noqa: C901, PLR0912
    context: CmpBaseRequestContext,
) -> None:
    """Authenticate CMP using an operation-bound mechanism.

    TP-TA-02, TP-TA-05, TP-TA-08 and TP-TA-11 are enforced here.
    """
    validate_cmp_pbm_parameters(context)

    if isinstance(context, CmpCertConfRequestContext):
        _authenticate_certconf(context)
        return

    pbm = _is_pbm(context)

    if isinstance(context, CmpPollRequestContext):
        if pbm:
            CmpSharedSecretAuthentication().authenticate(context)
            _reject_retired_onboarding_secret(context)
        else:
            CmpSignatureBasedPollAuthentication().authenticate(context)
            signer, _ = _extract_cmp_signer(context)
            _verify_declared_signature_algorithm(context, signer)
            _require_active_issued_signer(context, domain_only=True)
        return

    if isinstance(context, CmpRevocationRequestContext):
        if pbm and not ALLOW_PBM_REVOCATION:
            msg = 'PBM-protected CMP revocation is disabled by policy.'
            raise ValueError(msg)
        if pbm:
            CmpSharedSecretAuthentication().authenticate(context)
            _reject_retired_onboarding_secret(context)
        else:
            CmpSignatureBasedRevocationAuthentication().authenticate(context)
            signer, _ = _extract_cmp_signer(context)
            _verify_declared_signature_algorithm(context, signer)
            _require_active_issued_signer(context, domain_only=False)
        return

    if not isinstance(context, CmpCertificateRequestContext):
        msg = 'Unsupported CMP context for authentication.'
        raise TypeError(msg)

    if context.operation == 'initialization':
        if pbm:
            CmpSharedSecretAuthentication().authenticate(context)
            _reject_retired_onboarding_secret(context)
        else:
            CmpSignatureBasedInitializationAuthentication().authenticate(context)
            signer, _ = _extract_cmp_signer(context)
            _verify_declared_signature_algorithm(context, signer)
        return

    if context.operation == 'certification':
        if pbm:
            CmpSharedSecretAuthentication().authenticate(context)
            _reject_retired_onboarding_secret(context)
        else:
            CmpSignatureBasedCertificationAuthentication().authenticate(context)
            signer, _ = _extract_cmp_signer(context)
            _verify_declared_signature_algorithm(context, signer)
            _require_active_issued_signer(context, domain_only=True)
        return

    msg = f'Unsupported CMP authentication operation: {context.operation}.'
    raise ValueError(msg)


def _is_configured_cmp_ra_sender(context: CmpCertificateRequestContext) -> bool:
    """Recognize an authenticated upstream sender from an existing local RA configuration.

    senderKID alone is not a local device relationship: its value belongs to
    the remote server. Require the verified credential and target domain to
    match as well, so an unrelated RA with the same numeric ID grants no trust.
    """
    device = context.device
    domain = context.domain
    if device is None or device.pk is None or domain is None or device.domain_id != domain.pk:
        return False
    secret = context.cmp_shared_secret
    if not secret:
        return False
    configured_ras = CaModel.objects.filter(
        ca_type=CaModel.CaTypeChoice.REMOTE_CMP_RA,
        is_active=True,
        cmp_sender_kid=device.pk,
    ).select_related('no_onboarding_config')
    for ra in configured_ras:
        config = ra.no_onboarding_config
        if config is None or not config.cmp_shared_secret:
            continue
        if not stdlib_hmac.compare_digest(secret.encode(), config.cmp_shared_secret.encode()):
            continue
        try:
            endpoint = resolve(ra.remote_path)
        except Resolver404:
            continue
        if endpoint.app_name == 'cmp' and endpoint.kwargs.get('domain') == domain.unique_name:
            return True
    return False


def validate_cmp_proof_of_possession(context: CmpBaseRequestContext) -> None:  # noqa: C901
    """Verify CRMF signature PoP for IR/CR requests.

    TP-TA-06: device authentication is not proof of possession of the newly
    requested private key.  Downstream ``raVerified`` is rejected by default.
    """
    if not isinstance(context, CmpCertificateRequestContext):
        return
    if context.cmp_body_type not in {'ir', 'cr'}:
        return
    if not isinstance(context.parsed_message, rfc4210.PKIMessage):
        msg = 'CMP message is missing or invalid.'
        raise TypeError(msg)

    cert_req_messages = context.parsed_message['body'][context.cmp_body_type]
    if len(cert_req_messages) != _EXPECTED_CERT_REQ_MESSAGES:
        msg = 'Exactly one CertReqMsg is required.'
        raise ValueError(msg)

    cert_req_msg = cert_req_messages[0]
    popo = cert_req_msg['pop']
    if not popo.hasValue():
        msg = 'CMP certificate request is missing ProofOfPossession.'
        raise ValueError(msg)

    popo_name = popo.getName()
    if popo_name == 'raVerified':
        if (context.device is not None and context.device.can_assert_cmp_ra_verified) or _is_configured_cmp_ra_sender(
            context
        ):
            return
        msg = 'Downstream raVerified ProofOfPossession is not permitted.'
        raise ValueError(msg)
    if popo_name != 'signature':
        msg = f'Unsupported CMP ProofOfPossession type: {popo_name}.'
        raise ValueError(msg)

    signing_key = popo['signature']
    signed_object = signing_key['poposkInput'] if signing_key['poposkInput'].hasValue() else cert_req_msg['certReq']
    signed_bytes = encoder.encode(signed_object)
    signature = signing_key['signature'].asOctets()
    algorithm = AlgorithmIdentifier.from_dotted_string(signing_key['algorithmIdentifier']['algorithm'].prettyPrint())

    cert_request = context.cert_requested
    if not isinstance(cert_request, x509.CertificateBuilder):
        msg = 'CMP requested certificate builder is unavailable for ProofOfPossession verification.'
        raise TypeError(msg)
    public_key = cert_request._public_key  # noqa: SLF001
    if public_key is None:
        msg = 'CMP requested public key is unavailable for ProofOfPossession verification.'
        raise ValueError(msg)

    _verify_cmp_pop_signature(public_key, algorithm, signature, signed_bytes)


def _verify_cmp_pop_signature(
    public_key: CertificatePublicKeyTypes,
    algorithm: AlgorithmIdentifier,
    signature: bytes,
    signed_bytes: bytes,
) -> None:
    """Verify CRMF PoP with the declared algorithm and the requested public key."""
    hash_algorithm = algorithm.hash_algorithm
    if isinstance(public_key, rsa.RSAPublicKey):
        if 'RSA' not in algorithm.name.upper() or hash_algorithm is None:
            msg = 'CMP PoP algorithm is incompatible with the requested RSA key.'
            raise ValueError(msg)
        public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_algorithm.hash_algorithm())
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if 'ECDSA' not in algorithm.name.upper() or hash_algorithm is None:
            msg = 'CMP PoP algorithm is incompatible with the requested EC key.'
            raise ValueError(msg)
        public_key.verify(signature, signed_bytes, ec.ECDSA(hash_algorithm.hash_algorithm()))
    elif isinstance(public_key, (mldsa.MLDSA44PublicKey, mldsa.MLDSA65PublicKey, mldsa.MLDSA87PublicKey)):
        expected = {
            mldsa.MLDSA44PublicKey: AlgorithmIdentifier.ML_DSA_44,
            mldsa.MLDSA65PublicKey: AlgorithmIdentifier.ML_DSA_65,
            mldsa.MLDSA87PublicKey: AlgorithmIdentifier.ML_DSA_87,
        }
        if not any(isinstance(public_key, key_type) and algorithm == oid for key_type, oid in expected.items()):
            msg = 'CMP PoP algorithm is incompatible with the requested ML-DSA key.'
            raise ValueError(msg)
        public_key.verify(signature, signed_bytes)
    else:
        msg = f'Unsupported CMP PoP public key type: {type(public_key)}.'
        raise TypeError(msg)


def validate_cmp_transaction_freshness(context: CmpBaseRequestContext) -> CmpTransactionModel | None:
    """Validate transaction and nonce continuity, expiring overdue confirmations.

    TP-TA-03: stateful follow-up messages require transactionID plus the
    expected recipNonce and a fresh senderNonce.
    """
    if not isinstance(context, (CmpPollRequestContext, CmpCertConfRequestContext)):
        return None
    transaction_id = str(context.cmp_transaction_id or '').strip().lower()
    if not transaction_id:
        msg = 'CMP follow-up request is missing transactionID.'
        raise ValueError(msg)
    tx = CmpTransactionState.get_by_transaction_id(transaction_id)
    if tx is None:
        msg = 'CMP transaction does not exist.'
        raise ValueError(msg)
    message = context.parsed_message
    if not isinstance(message, rfc4210.PKIMessage):
        msg = 'CMP message is missing or invalid.'
        raise TypeError(msg)

    sender_nonce = message['header']['senderNonce'].asOctets()
    recip_nonce_field = message['header']['recipNonce']
    if not recip_nonce_field.hasValue():
        msg = 'CMP follow-up request is missing recipNonce.'
        raise ValueError(msg)
    recip_nonce = recip_nonce_field.asOctets()

    if not tx.last_server_nonce:
        msg = 'CMP transaction has no server nonce to continue from.'
        raise ValueError(msg)
    if not stdlib_hmac.compare_digest(bytes(tx.last_server_nonce), recip_nonce):
        msg = 'CMP recipNonce does not match the previous server senderNonce.'
        raise ValueError(msg)
    if tx.last_client_nonce and stdlib_hmac.compare_digest(bytes(tx.last_client_nonce), sender_nonce):
        msg = 'CMP senderNonce was already used for this transaction.'
        raise ValueError(msg)
    return tx


def mark_cmp_client_nonce(context: CmpBaseRequestContext) -> None:
    """Persist the authenticated follow-up request senderNonce."""
    if not isinstance(context, (CmpPollRequestContext, CmpCertConfRequestContext)):
        return
    tx = validate_cmp_transaction_freshness(context)
    if tx is None or not isinstance(context.parsed_message, rfc4210.PKIMessage):
        return
    tx.last_client_nonce = context.parsed_message['header']['senderNonce'].asOctets()
    tx.save(update_fields=['last_client_nonce', 'updated_at'])


def record_cmp_response_nonce(context: CmpBaseRequestContext) -> None:
    """Persist the server senderNonce after a response has been built."""
    tx = getattr(context, 'cmp_transaction', None)
    if tx is None and context.cmp_transaction_id:
        tx = CmpTransactionState.get_by_transaction_id(str(context.cmp_transaction_id).lower())
    if tx is None:
        return
    response_body = getattr(context, 'http_response_content', None)
    if not isinstance(response_body, (bytes, bytearray)):
        return
    try:
        response_message, remainder = decoder.decode(bytes(response_body), asn1Spec=rfc4210.PKIMessage())
    except Exception:  # noqa: BLE001
        return
    if remainder:
        return
    if response_message['header']['senderNonce'].hasValue():
        tx.last_server_nonce = response_message['header']['senderNonce'].asOctets()
    if isinstance(context.parsed_message, rfc4210.PKIMessage):
        tx.last_client_nonce = context.parsed_message['header']['senderNonce'].asOctets()
    tx.save(update_fields=['last_server_nonce', 'last_client_nonce', 'updated_at'])


def _certconf_hash_algorithm(
    context: CmpCertConfRequestContext,
    certificate: x509.Certificate,
) -> hashes.HashAlgorithm:
    """Use hashAlg or the issued certificate's signature digest (RFC 9480 Section 2.10)."""
    if context.cert_hash_algorithm_oid:
        algorithm = HashAlgorithm.from_dotted_string(context.cert_hash_algorithm_oid)
    else:
        signature_hash = certificate.signature_hash_algorithm
        if signature_hash is None:
            msg = 'certConf hashAlg is required for certificates whose signature algorithm has no implicit hash.'
            raise ValueError(msg)
        if not isinstance(signature_hash, tuple(_CERTCONF_ALLOWED_DIGESTS.values())):
            msg = 'certConf hash algorithm is not permitted.'
            raise ValueError(msg)
        return signature_hash
    factory = _CERTCONF_ALLOWED_DIGESTS.get(algorithm)
    if factory is None:
        msg = 'certConf hash algorithm is not permitted.'
        raise ValueError(msg)
    return factory()


def _authenticate_certconf(  # noqa: C901, PLR0912, PLR0915
    context: CmpCertConfRequestContext,
) -> None:
    """Authenticate certConf independently from certHash lookup.

    TP-TA-07: certHash identifies the certificate; it must never establish the
    caller identity.  Protection and transaction binding are validated first.
    """
    tx = validate_cmp_transaction_freshness(context)
    if tx is None:
        msg = 'certConf is not bound to an issued CMP transaction.'
        raise ValueError(msg)
    if isinstance(tx, CmpTransactionModel):
        require_awaiting_confirmation(tx)
    final_certificate = tx.final_certificate
    if final_certificate is None:
        msg = 'certConf is not bound to an issued CMP transaction.'
        raise ValueError(msg)
    if context.cert_req_id != tx.cert_req_id:
        msg = 'certConf certReqId does not match the CMP transaction.'
        raise ValueError(msg)
    if not context.cert_hash:
        msg = 'certConf is missing certHash.'
        raise ValueError(msg)

    certificate = final_certificate.get_certificate_serializer().as_crypto()
    digest = hashes.Hash(_certconf_hash_algorithm(context, certificate))
    digest.update(certificate.public_bytes(serialization.Encoding.DER))
    if not stdlib_hmac.compare_digest(digest.finalize(), context.cert_hash):
        msg = 'certConf certHash does not match the certificate issued in this transaction.'
        raise ValueError(msg)

    context.device = tx.device
    context.domain = tx.domain
    context.cmp_transaction = tx

    if _is_pbm(context):
        device = tx.device
        if device is None:
            msg = 'certConf transaction has no device for PBM authentication.'
            raise ValueError(msg)
        config = device.onboarding_config or device.no_onboarding_config
        secret = getattr(config, 'cmp_shared_secret', '') if config is not None else ''
        if not secret:
            msg = 'No CMP shared secret is available for certConf authentication.'
            raise ValueError(msg)
        validate_cmp_pbm_parameters(context)
        CmpSharedSecretAuthentication()._verify_hmac_protection(context, secret)  # noqa: SLF001
        _reject_retired_onboarding_secret(context)
        return

    signer, intermediates = _extract_cmp_signer(context)
    _verify_declared_signature_algorithm(context, signer)
    CmpSignatureBasedRevocationAuthentication()._verify_protection_signature(  # noqa: SLF001
        cast('rfc4210.PKIMessage', context.parsed_message), signer
    )

    # Prefer a currently active Trustpoint-issued signer. During certificate
    # confirmation for an initialization transaction, the signer may instead be
    # the same IDevID used for onboarding.
    try:
        issued = IssuedCredentialModel.get_credential_for_certificate(signer)
    except IssuedCredentialModel.DoesNotExist as lookup_exc:
        if tx.device is None:
            msg = 'certConf transaction has no device.'
            raise TypeError(msg) from lookup_exc
        try:
            idevid_device = IDevIDAuthenticator.authenticate_idevid_from_x509(
                idevid_cert=signer,
                intermediate_cas=intermediates,
                domain=tx.domain,
                onboarding_protocol=OnboardingProtocol.CMP_IDEVID,
                pki_protocol=OnboardingPkiProtocol.CMP,
            )
        except (IDevIDAuthenticationError, TypeError, ValueError) as exc:
            msg = 'certConf signer is not authorized for the CMP transaction.'
            raise ValueError(msg) from exc
        if idevid_device.pk != tx.device_id:
            msg = 'certConf IDevID belongs to a different device.'
            raise TypeError(msg) from lookup_exc
    else:
        valid, reason = issued.credential.is_valid_issued_credential()
        if not valid:
            msg = f'certConf signer credential is not active: {reason}'
            raise ValueError(msg)
        if issued.device_id != tx.device_id or issued.domain_id != tx.domain_id:
            msg = 'certConf signer is outside the original transaction scope.'
            raise ValueError(msg)

    context.client_certificate = signer


def _retire_onboarding_secrets(config: OnboardingConfigModel) -> None:

    retire_onboarding_secrets(config)


def retire_bootstrap_credential_after_domain_identity(context: BaseCertificateRequestContext) -> None:
    """Retire onboarding-only secrets after successful domain credential issuance.

    TP-TA-05: bootstrap material is a lifecycle stage, not a permanent parallel
    identity proof. NoOnboardingConfigModel is intentionally unaffected. CMP
    transactions that require an explicit certConf retain the bootstrap secret
    until that confirmation has been authenticated and accepted.
    """
    device = context.device
    domain = context.domain
    profile = context.certificate_profile_model
    issued_certificate = context.issued_certificate
    if device is None or domain is None or profile is None or issued_certificate is None:
        return
    config = device.onboarding_config
    if not isinstance(config, OnboardingConfigModel):
        return
    if profile.unique_name != domain.get_domain_credential_profile_name():
        return
    if isinstance(context, CmpCertificateRequestContext) and not context.implicit_confirm:
        return

    _retire_onboarding_secrets(config)


def retire_bootstrap_credential_after_certconf(context: CmpCertConfRequestContext) -> None:
    """Retire CMP bootstrap credentials after an accepted explicit certConf."""
    if context.cert_conf_status == PKI_STATUS_REJECTION:
        return
    transaction_record = context.cmp_transaction
    if transaction_record is None or transaction_record.operation != 'initialization':
        return
    device = transaction_record.device
    if device is None:
        return
    config = device.onboarding_config
    if not isinstance(config, OnboardingConfigModel):
        return
    _retire_onboarding_secrets(config)


def _public_key_bytes(public_key: CertificatePublicKeyTypes) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_trust_anchors(truststore: TruststoreModel) -> list[x509.Certificate]:
    return [
        entry.certificate.get_certificate_serializer().as_crypto()
        for entry in truststore.truststoreordermodel_set.order_by('order')
    ]


def _verify_chain_to_truststore(
    leaf: x509.Certificate,
    trust_anchors: list[x509.Certificate],
    intermediates: list[x509.Certificate],
) -> None:
    trusted = {cert.fingerprint(hashes.SHA256()) for cert in trust_anchors}
    pool = [*trust_anchors, *intermediates]
    current = leaf
    seen: set[bytes] = set()
    for _ in range(len(pool) + 1):
        current_fp = current.fingerprint(hashes.SHA256())
        if current_fp in seen:
            break
        seen.add(current_fp)
        issuer = None
        for candidate in pool:
            try:
                current.verify_directly_issued_by(candidate)
            except (InvalidSignature, ValueError, TypeError):
                continue
            issuer = candidate
            break
        if issuer is None:
            break
        if issuer.fingerprint(hashes.SHA256()) in trusted:
            return
        current = issuer
    msg = 'Upstream-issued certificate does not chain to the configured issuing truststore.'
    raise ValueError(msg)


def _validate_profile_preservation(context: BaseCertificateRequestContext, issued: x509.Certificate) -> None:
    builder = context.cert_requested_profile_validated
    if not isinstance(builder, x509.CertificateBuilder):
        msg = 'Profile-validated certificate request is missing.'
        raise TypeError(msg)

    expected_subject = builder._subject_name  # noqa: SLF001
    if expected_subject is not None and issued.subject != expected_subject:
        msg = 'Upstream CA changed the certificate subject authorized by Trustpoint.'
        raise TypeError(msg)

    security_critical = (
        x509.SubjectAlternativeName,
        x509.BasicConstraints,
        x509.KeyUsage,
        x509.ExtendedKeyUsage,
    )
    for expected_ext in builder._extensions:  # noqa: SLF001
        if not isinstance(expected_ext.value, security_critical):
            continue
        try:
            actual_ext = issued.extensions.get_extension_for_oid(expected_ext.oid)
        except x509.ExtensionNotFound as exc:
            msg = f'Upstream CA removed required extension {expected_ext.oid.dotted_string}.'
            raise ValueError(msg) from exc
        if actual_ext.value != expected_ext.value or actual_ext.critical != expected_ext.critical:
            msg = f'Upstream CA changed security-critical extension {expected_ext.oid.dotted_string}.'
            raise ValueError(msg)

    try:
        basic_constraints = issued.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        basic_constraints = None
    if basic_constraints is not None and basic_constraints.ca:
        msg = 'Upstream CA returned a CA certificate for a device credential request.'
        raise ValueError(msg)

    _validate_upstream_validity(builder, issued)


def _validate_upstream_validity(builder: x509.CertificateBuilder, issued: x509.Certificate) -> None:
    """Enforce the authorized lifetime and reject certificates invalid at delivery."""
    expected_not_before = builder._not_valid_before  # noqa: SLF001
    expected_not_after = builder._not_valid_after  # noqa: SLF001
    if expected_not_before is not None and expected_not_after is not None:
        maximum_lifetime = expected_not_after - expected_not_before
        if issued.not_valid_after_utc - issued.not_valid_before_utc > maximum_lifetime:
            msg = 'Upstream CA exceeded the validity period authorized by Trustpoint.'
            raise ValueError(msg)
    now = dt.datetime.now(dt.UTC)
    if not issued.not_valid_before_utc <= now <= issued.not_valid_after_utc:
        msg = 'Upstream-issued certificate is not currently valid.'
        raise ValueError(msg)


def validate_upstream_issuance_result(context: BaseCertificateRequestContext) -> None:
    """Validate an upstream RA result before the surrounding transaction commits.

    TP-TA-09 / TP-TA-10: TLS to the upstream service is not sufficient.  The
    returned credential must remain bound to the downstream key, configured CA
    trust and Trustpoint-authorized profile semantics.
    """
    domain = context.domain
    issued_certificate = context.issued_certificate
    if domain is None or issued_certificate is None:
        return
    issuing_ca = domain.issuing_ca
    if issuing_ca is None:
        return
    if issuing_ca.ca_type not in {CaModel.CaTypeChoice.REMOTE_EST_RA, CaModel.CaTypeChoice.REMOTE_CMP_RA}:
        return

    request = context.cert_requested
    if isinstance(request, x509.CertificateBuilder):
        requested_key = request._public_key  # noqa: SLF001
    elif isinstance(request, x509.CertificateSigningRequest):
        requested_key = request.public_key()
    else:
        msg = 'Original certificate request is unavailable for upstream result validation.'
        raise TypeError(msg)
    if requested_key is None:
        msg = 'Original certificate request does not contain a public key.'
        raise ValueError(msg)
    if _public_key_bytes(issued_certificate.public_key()) != _public_key_bytes(requested_key):
        msg = 'Upstream-issued certificate public key does not match the downstream request.'
        raise ValueError(msg)

    truststore = issuing_ca.chain_truststore
    # CMP stores issuer trust in the protocol configuration; EST stores it in
    # chain_truststore and uses the protocol truststore for the HTTPS endpoint.
    if issuing_ca.ca_type == CaModel.CaTypeChoice.REMOTE_CMP_RA and issuing_ca.no_onboarding_config:
        truststore = issuing_ca.no_onboarding_config.trust_store or truststore
    if truststore is None:
        msg = 'Upstream issuing truststore is not configured.'
        raise ValueError(msg)
    _verify_chain_to_truststore(
        issued_certificate,
        _load_trust_anchors(truststore),
        context.issued_certificate_chain or [],
    )
    _validate_profile_preservation(context, issued_certificate)


class CertificateOperationProcessor(Protocol):
    """Structural protocol for certificate operation processors."""

    def process_operation(self, context: BaseCertificateRequestContext) -> None:
        """Process a certificate operation."""


def process_certificate_operation_atomically(
    context: BaseCertificateRequestContext,
    processor: CertificateOperationProcessor,
) -> None:
    """Run issuance and post-issuance validation in one database transaction."""
    issuing_ca = context.domain.issuing_ca if context.domain is not None else None
    if issuing_ca is not None and issuing_ca.ca_type in {
        CaModel.CaTypeChoice.REMOTE_EST_RA,
        CaModel.CaTypeChoice.REMOTE_CMP_RA,
    }:
        # The remote processor validates the response before atomically saving it.
        # Holding a transaction across HTTP can deadlock a CA on this database.
        processor.process_operation(context)
        return
    with transaction.atomic():
        processor.process_operation(context)
        retire_bootstrap_credential_after_domain_identity(context)
