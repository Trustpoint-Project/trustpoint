# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Processing of SCEP PKIOperation messages (PKCSReq and RenewalReq) on top of the shared enrollment pipeline."""
from __future__ import annotations

import datetime
import hashlib
import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AttributeOID
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from devices.models import DeviceModel
from management.models.audit_log import AuditLog
from onboarding.enums import NoOnboardingPkiProtocol, OnboardingPkiProtocol
from pki.models import IssuedCredentialModel
from pki.models.certificate import CertificateModel
from request.authorization import ScepAuthorization
from request.operation_processor.general import OperationProcessor
from request.profile_validator import ProfileValidator
from request.request_context import ScepCertificateRequestContext
from scep.protocol.cms import (
    KeyTransRecipient,
    ParsedPkiMessage,
    PasswordRecipient,
    build_cert_rep,
    build_degenerate_certificates_only,
    check_public_key_policy,
    decrypt_pkcs_pki_envelope,
    parse_pki_message,
    verify_signature,
)
from scep.protocol.errors import ScepMalformedMessageError, ScepProtocolError
from scep.protocol.oids import CONTENT_TYPE_PKI_MESSAGE, FailInfo, MessageType, PkiStatus
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from django.http import HttpRequest

    from onboarding.models import ScepEnrollmentModelMixin
    from pki.models import CertificateProfileModel, CredentialModel, DomainModel
_CLOCK_SKEW = datetime.timedelta(days=1)
_ACCEPTED_CSR_HASHES = (hashes.SHA256, hashes.SHA384, hashes.SHA512)
_GENERIC_FAILURE_TEXT = 'The request could not be processed.'
_INVALID_AUTHORIZATION = 'The enrollment authorization is not valid.'
def get_scep_config(device: DeviceModel) -> Any | None:
    """Return the device's onboarding / no-onboarding config if SCEP is enabled in its PKI protocols."""
    if device.onboarding_config is not None:
        enabled = device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.SCEP)
        return device.onboarding_config if enabled else None
    if device.no_onboarding_config is not None:
        enabled = device.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.SCEP)
        return device.no_onboarding_config if enabled else None
    return None
@dataclass(frozen=True)
class ScepHttpResult:
    """HTTP level outcome of a PKIOperation."""
    body: bytes
    status: int = 200
    content_type: str = CONTENT_TYPE_PKI_MESSAGE
@dataclass(frozen=True)
class _Authenticated:
    device: DeviceModel
    config: ScepEnrollmentModelMixin
    operation: str
    profile: CertificateProfileModel | None
class _DeviceKnownError(Exception):
    """Wraps a protocol error raised after the device was identified, so the audit entry can reference it."""
    def __init__(self, device: DeviceModel, error: ScepProtocolError) -> None:
        super().__init__(str(error))
        self.device = device
        self.error = error
class _ReplayError(Exception):
    """A concurrent request already completed this transaction."""
class ScepPkiOperationHandler(LoggerMixin):
    """Validate, authorize and answer one SCEP PKIOperation request."""
    def __init__(
        self, domain: DomainModel, credential: CredentialModel, request: HttpRequest, cert_profile: str | None = None
    ) -> None:
        """Bind the handler to a domain, its SCEP server credential, the request and the URL's profile name."""
        self.domain = domain
        self.request = request
        self.cert_profile = cert_profile
        server_key = credential.get_private_key()
        if not isinstance(server_key, rsa.RSAPrivateKey):
            msg = 'The SCEP server key must be an RSA key.'
            raise TypeError(msg)
        self.server_key = server_key
        self.server_cert = credential.get_certificate()
    # ------------------------------------------------------------------ entry point
    def handle(self, body: bytes) -> ScepHttpResult:
        """Process the POST body; protocol failures are returned as CertRep FAILURE."""
        try:
            message = parse_pki_message(body)
        except ScepMalformedMessageError:
            self.logger.warning('SCEP: malformed pkiMessage rejected for domain %s', self.domain.unique_name)
            self._notify_failure()
            return ScepHttpResult(b'Malformed SCEP message.', status=400, content_type='text/plain')
        device: DeviceModel | None = None
        try:
            return self._process(message)
        except _DeviceKnownError as exc:
            device = exc.device
            failure = exc.error
        except ScepProtocolError as exc:
            failure = exc
        except Exception:
            self.logger.exception('SCEP: unexpected error while processing a request')
            failure = ScepProtocolError(FailInfo.BAD_REQUEST, _GENERIC_FAILURE_TEXT)
        self.logger.warning(
            'SCEP rejected transaction %s: fail_info=%s, reason=%s',
            message.transaction_id,
            failure.fail_info.name,
            failure.text,
        )
        self._audit_rejection(message, failure, device)
        operations: dict[int, str] = {MessageType.PKCS_REQ: 'pkcsreq', MessageType.RENEWAL_REQ: 'renewalreq'}
        operation = operations.get(message.message_type)
        self._notify_failure(device, operation)
        return self._failure_response(message, failure)

    def _notify_failure(self, device: DeviceModel | None = None, operation: str | None = None) -> None:
        """Report a final failure, including CertRep failures returned with HTTP 200."""
        from request.notifications import notify_request_failure  # noqa: PLC0415

        notify_request_failure(ScepCertificateRequestContext(domain=self.domain, device=device, operation=operation))
    # ------------------------------------------------------------------ pipeline
    def _process(self, message: ParsedPkiMessage) -> ScepHttpResult:
        signer = verify_signature(message)
        self.logger.info(
            'SCEP operation: transaction_id=%s, message_type=%s, signer_subject=%s',
            message.transaction_id,
            message.message_type,
            signer.subject.rfc4514_string(),
        )
        if message.message_type not in {MessageType.PKCS_REQ, MessageType.RENEWAL_REQ}:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'Unsupported SCEP message type.')
        if message.enveloped_data is None:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'The request carries no pkcsPKIEnvelope.')
        csr_der = decrypt_pkcs_pki_envelope(message.enveloped_data, self.server_key, self.server_cert)
        csr = self._load_csr(csr_der)
        if message.message_type == MessageType.PKCS_REQ:
            try:
                signer.verify_directly_issued_by(signer)
            except (ValueError, TypeError, x509.InvalidVersion):
                # Certificate-authenticated PKCSReq from clients such as sscep.
                # _authenticate_renewal validates Trustpoint ownership,
                # certificate status, domain, and the requested identity.
                authenticated = self._authenticate_renewal(signer, csr)
            else:
                authenticated = self._authenticate_initial(message, signer, csr)
        else:
            authenticated = self._authenticate_renewal(signer, csr)
        try:
            return self._authorize_and_issue(message, signer, csr, csr_der, authenticated)
        except ScepProtocolError as exc:
            raise _DeviceKnownError(authenticated.device, exc) from exc
    @staticmethod
    def _lookup_transaction(config: ScepEnrollmentModelMixin, transaction_id: str) -> dict[str, Any] | None:
        entry = (config.scep_transactions or {}).get(transaction_id)
        return entry if isinstance(entry, dict) else None
    def _authorize_and_issue(
        self,
        message: ParsedPkiMessage,
        signer: x509.Certificate,
        csr: x509.CertificateSigningRequest,
        csr_der: bytes,
        authenticated: _Authenticated,
    ) -> ScepHttpResult:
        config = authenticated.config
        device = authenticated.device
        profile = authenticated.profile
        if profile is None:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, _INVALID_AUTHORIZATION)
        message_type = MessageType(message.message_type)
        request_digest = self._request_digest(message_type, signer, csr_der)
        existing = self._lookup_transaction(config, message.transaction_id)
        if existing is not None:
            return self._answer_retry(existing, message, signer, authenticated, request_digest)
        if authenticated.operation == 'pkcsreq' and not config.can_authorize_scep_enrollment():
            raise ScepProtocolError(FailInfo.BAD_REQUEST, _INVALID_AUTHORIZATION)
        ctx = ScepCertificateRequestContext(
            raw_message=self.request,
            protocol='scep',
            operation=authenticated.operation,
            domain_str=self.domain.unique_name,
            domain=self.domain,
            device=device,
            cert_profile_str=profile.unique_name,
            cert_requested=csr,
            scep_transaction_id=message.transaction_id,
            scep_message_type=int(message_type),
            scep_signer_certificate=signer,
        )
        try:
            ScepAuthorization().authorize(ctx)
        except ValueError as exc:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'The request was rejected by the enrollment policy.') from exc
        try:
            self._issue_certificate_transaction(config, message, message_type, ctx, request_digest)
        except _ReplayError:
            fresh = type(config).objects.get(pk=config.pk)
            entry = self._lookup_transaction(fresh, message.transaction_id)
            if entry is None:
                raise ScepProtocolError(FailInfo.BAD_REQUEST, _GENERIC_FAILURE_TEXT) from None
            replay_auth = _Authenticated(device, fresh, authenticated.operation, profile)
            return self._answer_retry(entry, message, signer, replay_auth, request_digest)
        except ScepProtocolError:
            raise
        except Exception as exc:
            self.logger.exception('SCEP: issuance failed')
            raise ScepProtocolError(FailInfo.BAD_REQUEST, _GENERIC_FAILURE_TEXT) from exc
        if ctx.issued_certificate is None:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, _GENERIC_FAILURE_TEXT)
        AuditLog.create_entry(
            operation_type=(
                AuditLog.OperationType.SCEP_ENROLLMENT
                if authenticated.operation == 'pkcsreq'
                else AuditLog.OperationType.SCEP_RENEWAL
            ),
            target=device,
            target_display=f'Device: {device.common_name} | Domain: {self.domain.unique_name} | Protocol: scep',
            details={
                'transaction_id': message.transaction_id,
                'operation': authenticated.operation,
                'certificate_profile': profile.unique_name,
                'serial_number': format(ctx.issued_certificate.serial_number, 'x'),
            },
        )
        return self._success_response(
            message,
            [ctx.issued_certificate],
            self._recipient(signer, config),
        )
    def _issue_certificate_transaction(
        self,
        config: ScepEnrollmentModelMixin,
        message: ParsedPkiMessage,
        message_type: MessageType,
        ctx: ScepCertificateRequestContext,
        request_digest: str,
    ) -> None:
        """Issue once per transaction ID and atomically persist the result."""
        with transaction.atomic():
            # Lock the concrete model row, not the abstract enrollment mixin.
            locked = type(config).objects.select_for_update().get(pk=config.pk)
            if self._lookup_transaction(locked, message.transaction_id) is not None:
                raise _ReplayError
            if ctx.operation == 'pkcsreq' and (
                not locked.can_authorize_scep_enrollment()
                or locked.scep_secret_version != config.scep_secret_version
                or locked.scep_challenge_digest != config.scep_challenge_digest
            ):
                raise ScepProtocolError(FailInfo.BAD_REQUEST, _INVALID_AUTHORIZATION)
            if ctx.cert_profile_str is None:
                raise ScepProtocolError(FailInfo.BAD_REQUEST, _INVALID_AUTHORIZATION)
            ctx.certificate_profile_model = self.domain.get_allowed_cert_profile(ctx.cert_profile_str)
            ProfileValidator.validate(ctx)
            OperationProcessor().process_operation(ctx)
            if ctx.issued_certificate is None:
                msg = 'Certificate issuance returned no certificate.'
                raise ValueError(msg)
            transactions = dict(locked.scep_transactions or {})
            transactions[message.transaction_id] = {
                'message_type': int(message_type),
                'digest': request_digest,
                'cert_sha256': ctx.issued_certificate.fingerprint(hashes.SHA256()).hex().upper(),
            }
            locked.scep_transactions = transactions
            update_fields = ['scep_transactions']
            if ctx.operation == 'pkcsreq':
                locked.scep_challenge_consumed_at = timezone.now()
                update_fields.append('scep_challenge_consumed_at')
            locked.save(update_fields=update_fields)
            config.scep_transactions = transactions
            if ctx.operation == 'pkcsreq':
                config.scep_challenge_consumed_at = locked.scep_challenge_consumed_at
    # ------------------------------------------------------------------ authentication
    def _device_for_challenge(self, challenge: str) -> DeviceModel | None:
        digest = hashlib.sha256(challenge.encode('utf-8')).hexdigest()
        for lookup in ('no_onboarding_config__scep_challenge_digest', 'onboarding_config__scep_challenge_digest'):
            device = (
                DeviceModel.objects.select_related('onboarding_config', 'no_onboarding_config', 'domain')
                .filter(domain=self.domain, **{lookup: digest})
                .first()
            )
            if device is not None:
                return device
        return None
    def _authenticate_initial(
        self, message: ParsedPkiMessage, signer: x509.Certificate, csr: x509.CertificateSigningRequest
    ) -> _Authenticated:
        self._check_self_signed_signer(signer, csr)
        challenge = self._challenge_password(csr)
        if not challenge:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'A challengePassword is required.')
        device = self._device_for_challenge(challenge)
        config = get_scep_config(device) if device is not None else None
        if device is None or config is None or not hmac.compare_digest(
            config.scep_challenge.encode(), challenge.encode()
        ):
            raise ScepProtocolError(FailInfo.BAD_REQUEST, _INVALID_AUTHORIZATION)
        entry = self._lookup_transaction(config, message.transaction_id)
        is_retry = entry is not None and entry.get('message_type') == int(MessageType.PKCS_REQ)
        if not config.can_authorize_scep_enrollment() and not is_retry:
            raise _DeviceKnownError(device, ScepProtocolError(FailInfo.BAD_REQUEST, _INVALID_AUTHORIZATION))
        return _Authenticated(device, config, 'pkcsreq', self._requested_profile(device))
    def _requested_profile(self, device: DeviceModel) -> CertificateProfileModel:
        """The profile named in the URL; it must be allowed in the domain."""
        error = _DeviceKnownError(
            device,
            ScepProtocolError(
                FailInfo.BAD_REQUEST,
                'A certificate profile allowed in the domain is required in the URL.',
            ),
        )
        if not self.cert_profile:
            raise error
        try:
            return self.domain.get_allowed_cert_profile(self.cert_profile)
        except ValueError:
            raise error from None
    def _check_self_signed_signer(self, signer: x509.Certificate, csr: x509.CertificateSigningRequest) -> None:
        """RFC 8894 section 2.3: the initial signer is a self-signed certificate matching the CSR key and subject."""
        try:
            signer.verify_directly_issued_by(signer)
        except (ValueError, TypeError, x509.InvalidVersion):
            raise ScepProtocolError(
                FailInfo.BAD_MESSAGE_CHECK, 'The initial signer certificate must be self-signed.'
            ) from None
        now = timezone.now()
        if signer.not_valid_after_utc < now or signer.not_valid_before_utc - _CLOCK_SKEW > now:
            raise ScepProtocolError(FailInfo.BAD_TIME, 'The signer certificate is not currently valid.')
        try:
            key_usage = signer.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            key_usage = None
        if key_usage is not None and not key_usage.digital_signature:
            raise ScepProtocolError(FailInfo.BAD_MESSAGE_CHECK, 'The signer certificate must allow digitalSignature.')
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        der = serialization.Encoding.DER
        if signer.public_key().public_bytes(der, spki) != csr.public_key().public_bytes(der, spki):
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'The signer certificate key must match the CSR key.')
        if signer.subject != csr.subject:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'The signer certificate subject must match the CSR subject.')
    def _authenticate_renewal(self, signer: x509.Certificate, csr: x509.CertificateSigningRequest) -> _Authenticated:
        """Authenticate with an existing valid certificate by its IssuedCredentialModel."""
        try:
            issued = IssuedCredentialModel.get_credential_for_certificate(signer)
        except IssuedCredentialModel.DoesNotExist:
            raise ScepProtocolError(FailInfo.BAD_CERT_ID, 'The signer certificate is not known.') from None
        device = DeviceModel.objects.select_related(
            'onboarding_config', 'no_onboarding_config'
        ).get(pk=issued.device_id)
        fingerprint = signer.fingerprint(hashes.SHA256()).hex().upper()
        config = get_scep_config(device)
        if config is None:
            raise ScepProtocolError(FailInfo.BAD_CERT_ID, 'SCEP is not enabled for the signer certificate owner.')
        def reject(text: str) -> _DeviceKnownError:
            return _DeviceKnownError(device, ScepProtocolError(FailInfo.BAD_REQUEST, text))
        cert_model = CertificateModel.objects.filter(sha256_fingerprint=fingerprint).first()
        if (
            cert_model is None
            or cert_model.certificate_status != CertificateModel.CertificateStatus.OK
            or issued.domain_id != self.domain.pk
            or device.domain_id != self.domain.pk
            or config.scep_challenge_consumed_at is None
        ):
            msg = 'The signer certificate is not valid for renewal.'
            raise reject(msg)
        csr_san = self._san(csr)
        if not cert_model.subjects_match(csr.subject) or (csr_san is not None and csr_san != self._san(signer)):
            msg = 'The CSR identity does not match the existing certificate.'
            raise reject(msg)
        return _Authenticated(device, config, 'renewalreq', self._renewal_profile(issued, reject))
    def _renewal_profile(self, issued: IssuedCredentialModel, reject: Any) -> CertificateProfileModel:
        """The profile retained on the issued credential; it must still be allowed in the domain."""
        name = issued.issued_using_cert_profile
        allowed = (
            self.domain.certificate_profiles.select_related('certificate_profile')
            .filter(Q(certificate_profile__display_name=name) | Q(certificate_profile__unique_name=name))
            .first()
        )
        if allowed is None:
            msg = 'The certificate profile of the existing certificate is no longer allowed.'
            raise reject(msg)
        return allowed.certificate_profile
    @staticmethod
    def _san(obj: x509.Certificate | x509.CertificateSigningRequest) -> x509.SubjectAlternativeName | None:
        try:
            return obj.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            return None
    # ------------------------------------------------------------------ CSR handling
    @staticmethod
    def _load_csr(csr_der: bytes) -> x509.CertificateSigningRequest:
        try:
            csr = x509.load_der_x509_csr(csr_der)
        except ValueError:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'Malformed PKCS #10 request.') from None
        if not csr.is_signature_valid:
            raise ScepProtocolError(FailInfo.BAD_MESSAGE_CHECK, 'The PKCS #10 signature is invalid.')
        if not isinstance(csr.signature_hash_algorithm, _ACCEPTED_CSR_HASHES):
            raise ScepProtocolError(FailInfo.BAD_ALG, 'The PKCS #10 request must be signed with SHA-2.')
        check_public_key_policy(csr.public_key())
        return csr
    @staticmethod
    def _challenge_password(csr: x509.CertificateSigningRequest) -> str | None:
        try:
            raw = csr.attributes.get_attribute_for_oid(AttributeOID.CHALLENGE_PASSWORD)
        except x509.AttributeNotFound:
            return None
        try:
            return raw.value.decode('utf-8')
        except UnicodeDecodeError:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'Malformed challengePassword.') from None
    # ------------------------------------------------------------------ transactions and responses
    @staticmethod
    def _request_digest(message_type: MessageType, signer: x509.Certificate, csr_der: bytes) -> str:
        digest = hashlib.sha256()
        for part in (str(int(message_type)).encode(), signer.fingerprint(hashes.SHA256()), csr_der):
            digest.update(len(part).to_bytes(4, 'big'))
            digest.update(part)
        return digest.hexdigest()
    def _answer_retry(
        self,
        entry: dict[str, Any],
        message: ParsedPkiMessage,
        signer: x509.Certificate,
        authenticated: _Authenticated,
        request_digest: str,
    ) -> ScepHttpResult:
        if entry.get('message_type') != message.message_type or not hmac.compare_digest(
            str(entry.get('digest', '')), request_digest
        ):
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'The transactionID was already used by a different request.')
        cert_model = CertificateModel.objects.filter(sha256_fingerprint=entry.get('cert_sha256')).first()
        if cert_model is None:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'The issued certificate is no longer available.')
        certificate = cert_model.get_certificate_serializer().as_crypto()
        try:
            IssuedCredentialModel.get_credential_for_certificate(certificate)
        except IssuedCredentialModel.DoesNotExist:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'The issued certificate is no longer available.') from None
        device = authenticated.device
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.SCEP_RETRY,
            target=device,
            target_display=f'Device: {device.common_name} | Domain: {self.domain.unique_name} | Protocol: scep',
            details={'transaction_id': message.transaction_id, 'operation': MessageType(message.message_type).name},
        )
        return self._success_response(
            message,
            [certificate],
            self._recipient(signer, authenticated.config),
        )
    @staticmethod
    def _recipient(signer: x509.Certificate, config: ScepEnrollmentModelMixin) -> KeyTransRecipient | PasswordRecipient:
        """RSA signers receive KeyTransRecipientInfo; ECDSA signers get PasswordRecipientInfo."""
        public_key = signer.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            return KeyTransRecipient(signer)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return PasswordRecipient(config.scep_challenge)
        raise ScepProtocolError(FailInfo.BAD_ALG, 'Unsupported signer key type.')
    def _success_response(
        self,
        message: ParsedPkiMessage,
        certificates: list[x509.Certificate],
        recipient: KeyTransRecipient | PasswordRecipient,
    ) -> ScepHttpResult:
        return ScepHttpResult(
            build_cert_rep(
                server_key=self.server_key,
                server_cert=self.server_cert,
                transaction_id=message.transaction_id,
                recipient_nonce=message.sender_nonce,
                status=PkiStatus.SUCCESS,
                message_data=build_degenerate_certificates_only(certificates),
                recipient=recipient,
            )
        )
    def _failure_response(self, message: ParsedPkiMessage, failure: ScepProtocolError) -> ScepHttpResult:
        return ScepHttpResult(
            build_cert_rep(
                server_key=self.server_key,
                server_cert=self.server_cert,
                transaction_id=message.transaction_id,
                recipient_nonce=message.sender_nonce,
                status=PkiStatus.FAILURE,
                fail_info=failure.fail_info,
                fail_text=failure.text,
            )
        )
    def _audit_rejection(
        self, message: ParsedPkiMessage, failure: ScepProtocolError, device: DeviceModel | None
    ) -> None:
        target = device if device is not None else self.domain
        label = f'Device: {device.common_name} | ' if device is not None else ''
        try:
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.SCEP_REJECTED,
                target=target,
                target_display=f'{label}Domain: {self.domain.unique_name} | Protocol: scep',
                details={
                    'transaction_id': message.transaction_id,
                    'message_type': message.message_type,
                    'fail_info': failure.fail_info.name,
                    'reason': failure.text,
                },
            )
        except Exception:
            self.logger.exception('SCEP: failed to write the rejection audit entry')
