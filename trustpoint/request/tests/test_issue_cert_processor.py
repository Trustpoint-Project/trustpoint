# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Focused tests for certificate issuance operation processors."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest
from cryptography import x509

from pki.models import CaModel, IssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from request.operation_processor.issue_cert import (
    CertificateIssueProcessor,
    LocalCaCertificateIssueProcessor,
    RemoteCaCertificateIssueProcessor,
)
from request.request_context import BaseRequestContext, CmpCertificateRequestContext
from request.tests.test_est_client import certificate_and_csr


def _validated_builder() -> x509.CertificateBuilder:
    """Build the minimum profile-validated certificate template for local issuance."""
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'issued-device')]))
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
    )


def test_certificate_issue_dispatch_requires_certificate_context() -> None:
    """Reject contexts that cannot represent certificate requests."""
    with pytest.raises(TypeError, match='BaseCertificateRequestContext'):
        CertificateIssueProcessor().process_operation(BaseRequestContext())


def test_certificate_issue_dispatch_requires_domain_and_issuing_ca() -> None:
    """Reject requests without a domain or configured issuing CA."""
    context = CmpCertificateRequestContext()
    with pytest.raises(ValueError, match='No suitable operation processor'):
        CertificateIssueProcessor().process_operation(context)

    context.domain = Mock(issuing_ca=None)
    with pytest.raises(ValueError, match='No suitable operation processor'):
        CertificateIssueProcessor().process_operation(context)


def test_certificate_issue_dispatch_routes_remote_ca_types(domain_instance: dict[str, object]) -> None:
    """Route each configured remote CA type to its intended processor."""
    domain = domain_instance['domain']
    context = CmpCertificateRequestContext(domain=domain)  # type: ignore[arg-type]
    ca = domain.issuing_ca  # type: ignore[union-attr]

    for ca_type, processor_type in (
        (CaModel.CaTypeChoice.REMOTE_ISSUING_EST, LocalCaCertificateIssueProcessor),
        (CaModel.CaTypeChoice.REMOTE_ISSUING_CMP, LocalCaCertificateIssueProcessor),
        (CaModel.CaTypeChoice.REMOTE_EST_RA, RemoteCaCertificateIssueProcessor),
        (CaModel.CaTypeChoice.REMOTE_CMP_RA, RemoteCaCertificateIssueProcessor),
    ):
        ca.ca_type = ca_type
        with patch.object(processor_type, 'process_operation') as process:
            CertificateIssueProcessor().process_operation(context)
        process.assert_called_once_with(context)


def test_certificate_issue_dispatch_uses_local_processor_for_other_ca_types(
    domain_instance: dict[str, object],
) -> None:
    """Route local CA types to the local certificate processor."""
    context = CmpCertificateRequestContext(domain=domain_instance['domain'])  # type: ignore[arg-type]
    context.domain.issuing_ca.ca_type = CaModel.CaTypeChoice.LOCAL_PKCS11  # type: ignore[union-attr]
    with patch.object(LocalCaCertificateIssueProcessor, 'process_operation') as process:
        CertificateIssueProcessor().process_operation(context)
    process.assert_called_once_with(context)


def test_get_credential_type_for_template_distinguishes_domain_and_application(
    domain_instance: dict[str, object],
) -> None:
    """Classify domain and application certificate profiles correctly."""
    domain = domain_instance['domain']
    domain_profile, _ = CertificateProfileModel.objects.get_or_create(
        unique_name='domain_credential',
        defaults={
            'profile_json': '{"type": "cert_profile", "subj": {"allow":"*"}, "ext": {}, "validity": {"days": 30}}'
        },
    )
    tls_profile, _ = CertificateProfileModel.objects.get_or_create(
        unique_name='tls_server',
        defaults={
            'profile_json': '{"type": "cert_profile", "subj": {"allow":"*"}, "ext": {}, "validity": {"days": 10}}'
        },
    )

    context = CmpCertificateRequestContext(domain=domain, certificate_profile_model=domain_profile)  # type: ignore[arg-type]
    credential_type, display_name = CertificateIssueProcessor._get_credential_type_for_template(context)  # noqa: SLF001
    assert credential_type == IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
    assert display_name == (domain_profile.display_name or domain_profile.unique_name)

    context.certificate_profile_model = tls_profile
    credential_type, display_name = CertificateIssueProcessor._get_credential_type_for_template(context)  # noqa: SLF001
    assert credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert display_name == (tls_profile.display_name or tls_profile.unique_name)

    context.certificate_profile_model = None
    with pytest.raises(ValueError, match='Certificate profile model is required'):
        CertificateIssueProcessor._get_credential_type_for_template(context)  # noqa: SLF001


@pytest.mark.parametrize(
    ('field', 'message'),
    [
        ('device', 'Device must be set'),
        ('domain', 'Domain must be set'),
        ('cert_requested', 'Certificate request must be set'),
    ],
)
def test_local_certificate_issue_validates_required_context(
    field: str,
    message: str,
    device_instance: dict[str, object],
) -> None:
    """Reject local issuance when a required context value is missing."""
    _, _, csr = certificate_and_csr()
    values: dict[str, object] = {
        'device': device_instance['device'],
        'domain': device_instance['domain'],
        'cert_requested': csr,
    }
    values[field] = None
    with pytest.raises(ValueError, match=message):
        LocalCaCertificateIssueProcessor().process_operation(CmpCertificateRequestContext(**values))


def test_local_certificate_issue_saves_issued_credential_and_sets_context(
    device_instance: dict[str, object],
) -> None:
    """Issue a certificate locally and populate the request context."""
    _, _, csr = certificate_and_csr()
    profile, _ = CertificateProfileModel.objects.get_or_create(
        unique_name='domain_credential',
        defaults={
            'profile_json': '{"type": "cert_profile", "subj": {"allow":"*"}, "ext": {}, "validity": {"days": 30}}'
        },
    )
    context = CmpCertificateRequestContext(
        device=device_instance['device'],
        domain=device_instance['domain'],
        cert_requested=csr,
        cert_requested_profile_validated=_validated_builder(),
        certificate_profile_model=profile,
    )
    with patch('request.operation_processor.issue_cert.CredentialSaver') as saver_class, patch(
        'request.operation_processor.issue_cert.AuditLog.create_entry'
    ):
        LocalCaCertificateIssueProcessor().process_operation(context)

    assert context.issued_certificate is not None
    common_name = context.issued_certificate.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME
    )[0].value
    assert common_name == 'issued-device'
    assert context.issued_certificate_chain
    saver_class.return_value.save_keyless_credential.assert_called_once()


def test_local_certificate_issue_rejects_unvalidated_request(
    device_instance: dict[str, object],
) -> None:
    """Reject a CSR that has not passed certificate-profile validation."""
    _, _, csr = certificate_and_csr()
    context = CmpCertificateRequestContext(
        device=device_instance['device'], domain=device_instance['domain'], cert_requested=csr
    )
    with pytest.raises(ValueError, match='has not been validated'):
        LocalCaCertificateIssueProcessor().process_operation(context)


def test_local_certificate_issue_rejects_disabled_domain(device_instance: dict[str, object]) -> None:
    """Do not issue certificates while the device domain is disabled."""
    _, _, csr = certificate_and_csr()
    domain = device_instance['domain']
    domain.is_active = False
    context = CmpCertificateRequestContext(
        device=device_instance['device'], domain=domain, cert_requested=csr,
    )

    with pytest.raises(ValueError, match='currently disabled'):
        LocalCaCertificateIssueProcessor().process_operation(context)


@pytest.mark.parametrize(
    ('attribute', 'message'),
    [
        ('remote_host', 'Remote EST host'),
        ('remote_port', 'Remote EST port'),
        ('remote_path', 'Remote EST path'),
        ('chain_truststore', 'Chain truststore'),
    ],
)
def test_remote_est_configuration_is_validated(
    attribute: str,
    message: str,
) -> None:
    """Reject EST configuration when any required setting is absent."""
    ca = Mock()
    ca.get_ca_type_display.return_value = 'Local-PKCS11'
    ca.ca_type = CaModel.CaTypeChoice.REMOTE_EST_RA
    ca.remote_host = 'est.example.test'
    ca.remote_port = 443
    ca.remote_path = '/.well-known/est/simpleenroll'
    ca.chain_truststore = Mock()
    setattr(ca, attribute, None)

    with pytest.raises(ValueError, match=message):
        RemoteCaCertificateIssueProcessor()._validate_est_enrollment_config(ca)  # noqa: SLF001


def test_remote_est_translates_client_errors_and_does_not_save(
    device_instance: dict[str, object],
) -> None:
    """Translate EST client failures and avoid persistence after network errors."""
    _, _, csr = certificate_and_csr()
    ca = Mock()
    ca.ca_type = CaModel.CaTypeChoice.REMOTE_EST_RA
    ca.remote_host = 'est.example.test'
    ca.remote_port = 443
    ca.remote_path = '/.well-known/est/simpleenroll'
    ca.chain_truststore = Mock()
    domain = Mock(issuing_ca=ca, unique_name='remote-domain')
    context = CmpCertificateRequestContext(
        device=device_instance['device'], domain=domain, cert_requested=csr
    )

    with patch('request.operation_processor.issue_cert.EstClient') as client_class, patch(
        'request.operation_processor.issue_cert.CredentialSaver'
    ) as saver_class:
        client_class.return_value.simple_enroll.side_effect = RuntimeError('connection refused')
        with pytest.raises(ValueError, match='EST enrollment failed: connection refused'):
            RemoteCaCertificateIssueProcessor().process_operation(context)

    saver_class.assert_not_called()


def test_remote_cmp_is_explicitly_unimplemented(
    device_instance: dict[str, object],
    issuing_ca_instance: dict[str, object],
) -> None:
    """Report that remote CMP certificate issuance is not implemented."""
    _, _, csr = certificate_and_csr()
    ca = issuing_ca_instance['issuing_ca']
    ca.ca_type = CaModel.CaTypeChoice.REMOTE_CMP_RA
    context = CmpCertificateRequestContext(
        device=device_instance['device'], domain=device_instance['domain'], cert_requested=csr
    )
    with pytest.raises(NotImplementedError, match='CMP remote certificate issuance'):
        RemoteCaCertificateIssueProcessor(ca_type='cmp').process_operation(context)


def test_local_certificate_issue_rejects_unsupported_request_key(device_instance: dict[str, object]) -> None:
    context = CmpCertificateRequestContext(
        device=device_instance['device'], domain=device_instance['domain'], cert_requested=Mock()
    )
    with patch('request.operation_processor.issue_cert.CaRolloverService.get_active_rollover', return_value=None), patch(
        'request.operation_processor.issue_cert.is_supported_public_key', return_value=False
    ), pytest.raises(TypeError, match='unsupported type'):
        LocalCaCertificateIssueProcessor().process_operation(context)


def test_local_certificate_issue_rejects_ca_without_credential(device_instance: dict[str, object]) -> None:
    _, _, csr = certificate_and_csr()
    ca = Mock()
    ca.get_credential.return_value = None
    domain = Mock(is_active=True, get_issuing_ca_or_value_error=Mock(return_value=ca))
    context = CmpCertificateRequestContext(
        device=device_instance['device'], domain=domain, cert_requested=csr
    )
    with patch('request.operation_processor.issue_cert.CaRolloverService.get_active_rollover', return_value=None), pytest.raises(
        ValueError, match='does not have a credential'
    ):
        LocalCaCertificateIssueProcessor().process_operation(context)


def test_remote_est_context_prefers_configured_truststore(device_instance: dict[str, object]) -> None:
    ca = Mock(
        no_onboarding_config=Mock(est_password='secret', trust_store=Mock()),
        chain_truststore=Mock(), remote_host='est.example.test', remote_port=443,
        remote_path='/enroll', est_username='user',
    )
    context = CmpCertificateRequestContext(device=device_instance['device'], cert_profile_str='tls_client')

    result = RemoteCaCertificateIssueProcessor()._build_est_context(context, ca)  # noqa: SLF001

    assert result.est_password == 'secret'
    assert result.est_server_truststore is ca.no_onboarding_config.trust_store
