from __future__ import annotations

from datetime import datetime, UTC
from unittest.mock import Mock, patch

from workflows2.events.triggers import Triggers
from workflows2.integrations.certificates import (
    emit_certificate_issued_for_record,
    on_certificate_revoked,
    on_issued_credential_created,
)


def _build_certificate_mock() -> Mock:
    certificate = Mock()
    certificate.pk = 101
    certificate.common_name = 'device-01.example.local'
    certificate.serial_number = '04D2A6FF'
    certificate.sha256_fingerprint = 'A1B2C3D4'
    certificate.certificate_status = 'OK'
    certificate.not_valid_before = datetime(2026, 3, 26, 10, 0, tzinfo=UTC)
    certificate.not_valid_after = datetime(2027, 3, 26, 10, 0, tzinfo=UTC)
    return certificate


def _build_issued_record() -> Mock:
    certificate = _build_certificate_mock()

    issuing_ca = Mock()
    issuing_ca.id = 11

    domain = Mock()
    domain.id = 7
    domain.issuing_ca = issuing_ca

    device = Mock()
    device.id = 'device-1'
    device.common_name = 'Device 1'
    device.serial_number = 'SER-1'
    device.domain_id = 7

    credential = Mock()
    credential.certificate = certificate

    record = Mock()
    record.credential = credential
    record.domain = domain
    record.device = device
    record.issued_using_cert_profile = 'TLS Client'
    record.get_issued_credential_type_display.return_value = 'Application Credential'
    return record


@patch('workflows2.integrations.certificates.WorkflowDispatchService')
def test_emit_certificate_issued_for_record_emits_expected_payload(mock_service) -> None:
    record = _build_issued_record()

    emit_certificate_issued_for_record(record)

    kwargs = mock_service.return_value.emit_event.call_args.kwargs
    assert kwargs['on'] == Triggers.CERTIFICATE_ISSUED
    assert kwargs['event']['certificate']['common_name'] == 'device-01.example.local'
    assert kwargs['event']['certificate']['cert_profile'] == 'TLS Client'
    assert kwargs['event']['certificate']['issued_credential_type'] == 'application_credential'
    assert kwargs['event']['device']['id'] == 'device-1'
    assert kwargs['source'].ca_id == 11
    assert kwargs['source'].domain_id == 7
    assert kwargs['source'].device_id == 'device-1'


@patch('workflows2.integrations.certificates.emit_certificate_issued_for_record')
def test_on_issued_credential_created_only_emits_for_new_records(mock_emit) -> None:
    record = _build_issued_record()

    on_issued_credential_created(type(record), record, created=True)
    on_issued_credential_created(type(record), record, created=False)

    mock_emit.assert_called_once_with(record)


@patch('workflows2.integrations.certificates.WorkflowDispatchService')
@patch('workflows2.integrations.certificates._resolve_record_for_certificate')
def test_on_certificate_revoked_emits_expected_payload(mock_resolve_record, mock_service) -> None:
    record = _build_issued_record()
    certificate = record.credential.certificate
    mock_resolve_record.return_value = record

    revoked = Mock()
    revoked.certificate = certificate
    revoked.ca_id = 11
    revoked.revocation_reason = 'cessationOfOperation'

    on_certificate_revoked(type(revoked), revoked, created=True)

    kwargs = mock_service.return_value.emit_event.call_args.kwargs
    assert kwargs['on'] == Triggers.CERTIFICATE_REVOKED
    assert kwargs['event']['certificate']['revocation_reason'] == 'cessationOfOperation'
    assert kwargs['event']['certificate']['common_name'] == 'device-01.example.local'
    assert kwargs['source'].ca_id == 11
    assert kwargs['source'].device_id == 'device-1'
