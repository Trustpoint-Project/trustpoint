# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the RemoteDeviceCredential model."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from queue import Queue
from time import monotonic, sleep
from typing import Any

import pytest
from django.db import connection, connections, transaction

from devices.models import RemoteDeviceCredentialDownloadModel


@pytest.mark.django_db
def test_create_remote_device_credential_from_tls_client_credential(
    tls_client_credential_instance: dict[str, Any],
) -> None:
    """Test the creation of a RemoteDeviceCredentialDownloadModel instance using the `tls_client_credential` fixture."""
    device = tls_client_credential_instance['device']
    issued_credential = tls_client_credential_instance['issued_credential']
    otp_token = 'test-otp-token'  # noqa: S105
    remote_download = RemoteDeviceCredentialDownloadModel.objects.create(
        issued_credential_model=issued_credential,
        otp=otp_token,
        device=device,
    )

    assert remote_download.issued_credential_model == issued_credential, (
        'The issued credential model should match the one used in the creation.'
    )
    assert remote_download.device == device, 'The device should match the one used in the creation.'
    assert remote_download.otp == otp_token, 'The OTP should match the one used during creation.'
    assert remote_download.attempts == 0, 'Initial attempts should be 0.'
    assert remote_download.download_token == '', 'The download token should initially be empty.'
    assert remote_download.token_created_at is None, 'Token created timestamp should initially be None.'

    expected_str = f'RemoteDeviceCredentialDownloadModel(credential={issued_credential.id})'
    assert str(remote_download) == expected_str, f"The string representation should be '{expected_str}'."


#  ----------------------------------- save-----------------------------------


@pytest.mark.django_db
def test_save_generates_otp_if_not_set(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that `save` generates a new OTP if no OTP is set."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']
    remote_device_credential_download.otp = ''
    remote_device_credential_download.save()

    assert remote_device_credential_download.otp != '', 'OTP should be generated if it was not set.'
    assert isinstance(remote_device_credential_download.otp, str), 'Generated OTP should be a string.'


@pytest.mark.django_db
def test_save_does_not_modify_existing_otp(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that `save` does not modify the OTP if it is already set."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    existing_otp = remote_device_credential_download.otp

    remote_device_credential_download.save()

    assert remote_device_credential_download.otp == existing_otp, 'Existing OTP should not be modified.'


#  ----------------------------------- check_token -----------------------------------


@pytest.mark.django_db
def test_check_token_valid(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that `check_token` returns True for a valid token within the validity period."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    assert remote_device_credential_download.check_otp(remote_device_credential_download.otp) is True

    token = remote_device_credential_download.download_token
    assert remote_device_credential_download.check_token(token) is True, (
        'The token should be valid within its validity period.'
    )


@pytest.mark.django_db
def test_check_token_missing_token(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that `check_token` returns False if no token is set."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    assert remote_device_credential_download.download_token == '', 'Token should not be set initially.'
    assert remote_device_credential_download.check_token('some-token') is False, (
        '`check_token` should return False if no token is set.'
    )


@pytest.mark.django_db
def test_check_token_wrong_token(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that `check_token` returns False for an incorrect token."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    assert remote_device_credential_download.check_otp(remote_device_credential_download.otp) is True

    non_sensitive_test_token = 'wrong-token'  # noqa: S105
    assert remote_device_credential_download.check_token(non_sensitive_test_token) is False, (
        '`check_token` should return False for an incorrect token.'
    )


@pytest.mark.django_db
def test_check_token_expired(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that `check_token` returns False for an expired token."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    assert remote_device_credential_download.check_otp(remote_device_credential_download.otp) is True
    token = remote_device_credential_download.download_token

    remote_device_credential_download.token_created_at -= timedelta(
        minutes=RemoteDeviceCredentialDownloadModel.TOKEN_VALIDITY.total_seconds() / 60 + 1
    )
    remote_device_credential_download.save()

    assert remote_device_credential_download.check_token(token) is False, (
        'The token should be invalid after expiration.'
    )
    with pytest.raises(RemoteDeviceCredentialDownloadModel.DoesNotExist):
        RemoteDeviceCredentialDownloadModel.objects.get(pk=remote_device_credential_download.pk)


#  ----------------------------------- check_otp-----------------------------------


@pytest.mark.django_db(transaction=True)
@pytest.mark.skipif(connection.vendor != 'postgresql', reason='Requires PostgreSQL row locks')
def test_check_otp_concurrent_requests_accept_only_once(
    remote_device_credential_download_instance: dict[str, Any],
) -> None:
    """Overlapping connections consume the OTP once and preserve the winner's token."""
    download = remote_device_credential_download_instance['remote_credential']
    otp = download.otp
    backend_pids: Queue[int] = Queue()

    def check_otp() -> tuple[bool, str]:
        try:
            current = RemoteDeviceCredentialDownloadModel.objects.get(pk=download.pk)
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '10s'")
                cursor.execute('SELECT pg_backend_pid()')
                backend_pids.put(cursor.fetchone()[0])
            return current.check_otp(otp), current.download_token
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as pool:
        with transaction.atomic():
            RemoteDeviceCredentialDownloadModel.objects.select_for_update().get(pk=download.pk)
            futures = [pool.submit(check_otp) for _ in range(2)]
            pids = [backend_pids.get(timeout=10) for _ in futures]
            assert len(set(pids)) == 2

            # Hold both requests before writes, so removing the OTP read lock makes both succeed.
            deadline = monotonic() + 5
            with connection.cursor() as cursor:
                while True:
                    cursor.execute(
                        'SELECT cardinality(pg_blocking_pids(%s)), cardinality(pg_blocking_pids(%s))',
                        pids,
                    )
                    if all(cursor.fetchone()):
                        break
                    assert monotonic() < deadline, 'Both OTP requests must overlap while blocked on the row'
                    sleep(0.01)

        results = [future.result(timeout=15) for future in futures]

    assert sum(accepted for accepted, _token in results) == 1
    winning_token = next(token for accepted, token in results if accepted)
    download.refresh_from_db()
    assert download.otp == '-'
    assert download.download_token == winning_token
    assert download.check_token(winning_token)


@pytest.mark.django_db
@pytest.mark.parametrize('valid_attempt', [True, False])
def test_check_otp_stale_copy_cannot_change_used_code(
    remote_device_credential_download_instance: dict[str, Any],
    valid_attempt: bool,
) -> None:
    """A stale request cannot reuse a consumed OTP or overwrite its download token."""
    download = remote_device_credential_download_instance['remote_credential']
    stale_download = RemoteDeviceCredentialDownloadModel.objects.get(pk=download.pk)
    otp = download.otp

    assert download.check_otp(otp)
    token = download.download_token
    token_created_at = download.token_created_at

    assert not stale_download.check_otp(otp if valid_attempt else 'wrong-otp')

    download.refresh_from_db()
    assert download.otp == '-'
    assert download.download_token == token
    assert download.token_created_at == token_created_at
    assert download.attempts == 0


@pytest.mark.django_db
def test_check_otp_stale_copies_share_attempt_limit(
    remote_device_credential_download_instance: dict[str, Any],
) -> None:
    """Independently loaded requests count every failure and cannot revive a deleted OTP."""
    download = remote_device_credential_download_instance['remote_credential']
    otp = download.otp
    copies = [
        RemoteDeviceCredentialDownloadModel.objects.get(pk=download.pk)
        for _ in range(download.BROWSER_MAX_OTP_ATTEMPTS)
    ]

    for attempt, stale_download in enumerate(copies, start=1):
        assert not stale_download.check_otp('wrong-otp')
        if attempt < download.BROWSER_MAX_OTP_ATTEMPTS:
            download.refresh_from_db()
            assert download.attempts == attempt

    assert not RemoteDeviceCredentialDownloadModel.objects.filter(pk=download.pk).exists()
    assert not download.check_otp(otp)
    assert not RemoteDeviceCredentialDownloadModel.objects.filter(pk=download.pk).exists()


@pytest.mark.django_db
def test_check_otp_valid(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that `check_otp` returns True for a valid OTP and invalidates it afterward."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    otp = remote_device_credential_download.otp

    assert remote_device_credential_download.check_otp(otp) is True, 'Valid OTP should return True.'

    assert remote_device_credential_download.check_otp(otp) is False, (
        'OTP should not be reusable after a valid attempt.'
    )
    assert remote_device_credential_download.otp == '-', 'OTP should be marked as invalid after being used.'


@pytest.mark.django_db
def test_check_otp_invalid(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that `check_otp` returns False for an invalid OTP."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    invalid_otp = 'wrong-otp'

    assert remote_device_credential_download.check_otp(invalid_otp) is False, 'Invalid OTP should return False.'
    assert remote_device_credential_download.attempts == 1, 'Incorrect OTP attempts should update the attempts counter.'


@pytest.mark.django_db
def test_check_otp_exceed_max_attempts(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that the OTP is invalidated after exceeding the maximum number of allowed attempts."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    max_attempts = RemoteDeviceCredentialDownloadModel.BROWSER_MAX_OTP_ATTEMPTS
    invalid_otp = 'wrong-otp'

    for attempt in range(max_attempts):
        assert remote_device_credential_download.check_otp(invalid_otp) is False, (
            f'Attempt {attempt + 1}: Invalid OTP should return False.'
        )

    assert remote_device_credential_download.otp == '-', 'OTP should be invalid after exceeding max attempts.'
    with pytest.raises(RemoteDeviceCredentialDownloadModel.DoesNotExist):
        RemoteDeviceCredentialDownloadModel.objects.get(pk=remote_device_credential_download.pk)


@pytest.mark.django_db
def test_check_otp_resets_on_max_attempts(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that the object is deleted after exceeding max OTP attempts."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    max_attempts = RemoteDeviceCredentialDownloadModel.BROWSER_MAX_OTP_ATTEMPTS
    invalid_otp = 'wrong-otp'

    for _ in range(max_attempts):
        remote_device_credential_download.check_otp(invalid_otp)

    with pytest.raises(RemoteDeviceCredentialDownloadModel.DoesNotExist):
        RemoteDeviceCredentialDownloadModel.objects.get(pk=remote_device_credential_download.pk)


@pytest.mark.django_db
def test_check_otp_creates_download_token(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that a valid OTP generates a download token and sets the creation time."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    otp = remote_device_credential_download.otp

    assert remote_device_credential_download.check_otp(otp) is True, 'Valid OTP should return True.'

    assert remote_device_credential_download.download_token != '', 'A valid OTP should generate a download token.'
    assert remote_device_credential_download.token_created_at is not None, (
        'A valid OTP should set the token creation time.'
    )


#  ----------------------------------- get_otp_display-----------------------------------


@pytest.mark.django_db
def test_get_otp_display_valid_otp(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that `get_otp_display` returns the OTP in the correct format when the OTP is valid."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    otp_display = remote_device_credential_download.get_otp_display()
    expected_display = (
        f'{remote_device_credential_download.issued_credential_model.id}.{remote_device_credential_download.otp}'
    )

    assert otp_display == expected_display, f'Expected display format: {expected_display}, got: {otp_display}'


@pytest.mark.django_db
def test_get_otp_display_invalidated_otp(remote_device_credential_download_instance: dict[str, Any]) -> None:
    """Test that `get_otp_display` returns 'OTP no longer valid' when the OTP is invalidated."""
    remote_device_credential_download = remote_device_credential_download_instance['remote_credential']

    remote_device_credential_download.otp = '-'
    remote_device_credential_download.save()

    otp_display = remote_device_credential_download.get_otp_display()
    expected_display = 'OTP no longer valid'

    assert otp_display == expected_display, f'Expected display: {expected_display}, got: {otp_display}'
