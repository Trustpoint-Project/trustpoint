# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Revocation scope, issuer attribution, atomicity and CRL regression tests."""

from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django.utils import timezone
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules import rfc4210, rfc5280

from devices.models import DeviceModel
from pki.models import CaModel, CertificateModel, CredentialModel, IssuedCredentialModel, RevokedCertificateModel
from pki.models.ca_rollover import CaRolloverModel, CaRolloverState, CaRolloverStrategyType
from pki.models.credential import PrimaryCredentialCertificate
from pki.models.domain import DomainModel
from pki.services.revocation import revoke_certificate, revoke_certificates, revoke_primary_certificate
from pki.tests.managed_ca_helpers import create_managed_root_ca
from pki.util.x509 import CertificateGenerator
from request.message_parser.cmp import CmpRevocationBodyValidation
from request.operation_processor.revoke_cert import CertificateRevocationProcessor
from request.request_context import CmpRevocationRequestContext

pytestmark = pytest.mark.django_db


def _certificate(ca_data: dict[str, Any], name: str, *, days: int = 1) -> CertificateModel:
    """Persist a signed certificate, including expired ones for scope tests."""
    now = timezone.now()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_data['cert'].subject)
        .public_key(ca_data['priv_key'].public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=3))
        .not_valid_after(now + timedelta(days=days))
        .sign(ca_data['priv_key'], hashes.SHA256())
    )
    return CertificateModel.save_certificate(certificate)


def _issued_credential(ca: CaModel, certificate: CertificateModel) -> IssuedCredentialModel:
    """Associate one certificate with a device credential in the CA's domain."""
    domain = DomainModel.objects.create(unique_name='revocation-domain', issuing_ca=ca)
    device = DeviceModel.objects.create(common_name='revocation-device', domain=domain)
    credential = CredentialModel.objects.create(
        certificate=certificate,
        credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
    )
    PrimaryCredentialCertificate.objects.create(credential=credential, certificate=certificate, is_primary=True)
    return IssuedCredentialModel.objects.create(
        common_name='revocation-credential',
        credential=credential,
        device=device,
        domain=domain,
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
    )


def test_repeated_revocation_preserves_original_reason_and_time(issuing_ca_instance: dict[str, Any]) -> None:
    """Repeated requests retain the first record and refresh a cached missing relation."""
    certificate = _certificate(issuing_ca_instance, 'repeat')
    # Populate the reverse-relation cache before another instance writes the revocation.
    assert not hasattr(certificate, 'revoked_certificate')
    ca = issuing_ca_instance['issuing_ca']

    assert revoke_certificate(certificate, reason=x509.ReasonFlags.key_compromise, ca=ca)
    original = certificate.revoked_certificate
    assert not revoke_certificate(certificate, reason=x509.ReasonFlags.superseded, ca=ca)

    assert RevokedCertificateModel.objects.count() == 1
    assert certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED
    assert certificate.revoked_certificate.revocation_reason == 'keyCompromise'
    assert certificate.revoked_certificate.revoked_at == original.revoked_at


@pytest.mark.parametrize('reason', ['', 'invalid', 'key_compromise'])
def test_invalid_reason_does_not_revoke(issuing_ca_instance: dict[str, Any], reason: str) -> None:
    """Reject unsupported reason strings before writing revocation state."""
    certificate = _certificate(issuing_ca_instance, 'invalid-reason')
    with pytest.raises(ValueError, match='is not a valid'):
        revoke_certificate(certificate, reason=reason, ca=issuing_ca_instance['issuing_ca'])
    assert not RevokedCertificateModel.objects.exists()


def test_primary_revocation_reports_missing_certificate(issuing_ca_instance: dict[str, Any]) -> None:
    """A pending credential returns the existing operator-facing error."""
    certificate = _certificate(issuing_ca_instance, 'missing-primary')
    issued = _issued_credential(issuing_ca_instance['issuing_ca'], certificate)
    issued.credential.certificate = None
    issued.credential.save(update_fields=['certificate'])

    assert revoke_primary_certificate(issued.pk, 'superseded') == (
        False,
        'The associated certificate to revoke was not found.',
    )
    assert not RevokedCertificateModel.objects.exists()


def test_primary_revocation_can_resolve_issuer_without_a_domain(issuing_ca_instance: dict[str, Any]) -> None:
    """The verified issuer can supply the CA when the domain was removed."""
    certificate = _certificate(issuing_ca_instance, 'domainless-primary')
    issued = _issued_credential(issuing_ca_instance['issuing_ca'], certificate)
    issued.domain = None
    issued.save(update_fields=['domain'])

    assert revoke_primary_certificate(issued.pk, 'superseded')[0]
    assert RevokedCertificateModel.objects.get(certificate=certificate).ca == issuing_ca_instance['issuing_ca']


@pytest.mark.parametrize('known_ca', [False, True])
def test_unresolved_issuer_retains_the_supplied_ca(issuing_ca_instance: dict[str, Any], *, known_ca: bool) -> None:
    """Imported certificates without a verified issuer retain the caller's attribution."""
    certificate = _certificate(issuing_ca_instance, 'unresolved-issuer')
    CertificateModel.objects.filter(pk=certificate.pk).update(issuer_id=None)
    ca = issuing_ca_instance['issuing_ca'] if known_ca else None

    assert revoke_certificate(certificate, reason='superseded', ca=ca)
    assert RevokedCertificateModel.objects.get(certificate=certificate).ca == ca


def test_primary_scope_leaves_other_credential_certificates_untouched(issuing_ca_instance: dict[str, Any]) -> None:
    """Operator revocation affects only the selected credential's primary certificate."""
    primary = _certificate(issuing_ca_instance, 'primary')
    other = _certificate(issuing_ca_instance, 'other')
    issued = _issued_credential(issuing_ca_instance['issuing_ca'], primary)
    PrimaryCredentialCertificate.objects.create(credential=issued.credential, certificate=other)

    assert revoke_primary_certificate(issued.pk, 'superseded') == (True, 'Certificate successfully revoked.')
    assert list(RevokedCertificateModel.objects.values_list('certificate_id', flat=True)) == [primary.pk]


def test_credential_scope_revokes_all_unexpired_certificates(issuing_ca_instance: dict[str, Any]) -> None:
    """Model revocation includes other unexpired certificates and skips expired ones."""
    primary = _certificate(issuing_ca_instance, 'primary')
    other = _certificate(issuing_ca_instance, 'other')
    expired = _certificate(issuing_ca_instance, 'expired', days=-1)
    issued = _issued_credential(issuing_ca_instance['issuing_ca'], primary)
    for certificate in (other, expired):
        PrimaryCredentialCertificate.objects.create(credential=issued.credential, certificate=certificate)

    issued.revoke()

    assert set(RevokedCertificateModel.objects.values_list('certificate_id', flat=True)) == {primary.pk, other.pk}
    assert set(RevokedCertificateModel.objects.values_list('revocation_reason', flat=True)) == {'cessationOfOperation'}


def test_batch_can_include_expired_certificates_when_requested(issuing_ca_instance: dict[str, Any]) -> None:
    """Callers can explicitly request revocation of an expired certificate."""
    certificate = _certificate(issuing_ca_instance, 'expired', days=-1)
    assert (
        revoke_certificates(
            [certificate],
            reason='superseded',
            ca=issuing_ca_instance['issuing_ca'],
            only_unexpired=False,
        )
        == 1
    )


def test_batch_rolls_back_if_a_later_certificate_disappeared(issuing_ca_instance: dict[str, Any]) -> None:
    """Failure later in a batch rolls back earlier revocations."""
    certificate = _certificate(issuing_ca_instance, 'rollback')
    missing = CertificateModel(pk=certificate.pk + 1000, not_valid_after=certificate.not_valid_after)
    with pytest.raises(CertificateModel.DoesNotExist):
        revoke_certificates(
            [certificate, missing],
            reason='superseded',
            ca=issuing_ca_instance['issuing_ca'],
            only_unexpired=True,
        )
    assert not RevokedCertificateModel.objects.exists()


@pytest.mark.parametrize('state', [CaRolloverState.PREPARATION, CaRolloverState.TRANSITION, CaRolloverState.COMPLETED])
@pytest.mark.parametrize('issued_by_new_ca', [False, True])
def test_rollover_revocation_uses_verified_issuer_even_with_same_subject(
    issuing_ca_instance: dict[str, Any],
    state: CaRolloverState,
    *,
    issued_by_new_ca: bool,
) -> None:
    """Both old and replacement certificates stay attributed to their signing CA."""
    old_ca = issuing_ca_instance['issuing_ca']
    subject_cn = issuing_ca_instance['cert'].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    new_certificate, new_key = create_managed_root_ca(cn=subject_cn)
    new_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=new_certificate,
        private_key=new_key,
        chain=[],
        unique_name='replacement-ca',
        ca_type=old_ca.ca_type,
    )
    CaRolloverModel.objects.create(
        old_issuing_ca=old_ca,
        new_issuing_ca=new_ca,
        state=state,
        strategy_type=CaRolloverStrategyType.IMPORT_CA,
    )
    signer = {'cert': new_certificate, 'priv_key': new_key} if issued_by_new_ca else issuing_ca_instance
    certificate = _certificate(signer, 'rollover-leaf')
    # Completion switches the domain; old certificates must still appear on the old CA's CRL.
    domain_ca = new_ca if state == CaRolloverState.COMPLETED else old_ca
    issued = _issued_credential(domain_ca, certificate)
    context = CmpRevocationRequestContext(
        domain=issued.domain,
        device=issued.device,
        credential_to_revoke=issued,
        revocation_reason=x509.ReasonFlags.key_compromise,
    )

    CertificateRevocationProcessor().process_operation(context)

    expected_ca = new_ca if issued_by_new_ca else old_ca
    revocation = RevokedCertificateModel.objects.get(certificate=certificate)
    assert revocation.ca_id == expected_ca.pk
    assert revocation.revocation_reason == 'keyCompromise'
    assert context.issuer_credential == expected_ca.credential


def test_revocation_schedules_crl_only_for_new_records(issuing_ca_instance: dict[str, Any]) -> None:
    """Idempotent retries preserve normal CRL scheduling without duplicating signals."""
    certificate = _certificate(issuing_ca_instance, 'crl')
    ca = issuing_ca_instance['issuing_ca']
    ca.auto_crl_on_revocation_enabled = True
    ca.save(update_fields=['auto_crl_on_revocation_enabled'])

    with patch.object(CaModel, 'schedule_next_crl_generation') as schedule:
        revoke_certificate(certificate, reason='superseded', ca=ca)
        revoke_certificate(certificate, reason='superseded', ca=ca)

    schedule.assert_called_once_with(post_revocation_crl=True)


@pytest.mark.parametrize('reason', list(x509.ReasonFlags))
def test_cmp_reason_reaches_persisted_revocation(
    issuing_ca_instance: dict[str, Any],
    reason: x509.ReasonFlags,
) -> None:
    """Every supported reason survives ASN.1 decoding and protocol processing."""
    certificate = _certificate(issuing_ca_instance, 'cmp-reason')
    issued = _issued_credential(issuing_ca_instance['issuing_ca'], certificate)
    body = rfc4210.PKIBody()
    body['rr'].setComponentByPosition(0)
    request = body['rr'][0]
    request['certDetails']['serialNumber'] = int(certificate.serial_number, 16)
    extension = request['crlEntryDetails'].componentType.clone()
    extension['extnID'] = '2.5.29.21'
    extension['extnValue'] = der_encode(rfc5280.CRLReason(reason.value))
    request['crlEntryDetails'].append(extension)
    context = CmpRevocationRequestContext(
        domain=issued.domain,
        device=issued.device,
        credential_to_revoke=issued,
    )

    CmpRevocationBodyValidation().parse_rr_body(context, body)
    CertificateRevocationProcessor().process_operation(context)

    assert RevokedCertificateModel.objects.get(certificate=certificate).revocation_reason == reason.value
