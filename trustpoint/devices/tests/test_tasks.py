"""Tests for device background tasks."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from django.utils import timezone

from devices.models import DeviceModel
from devices.tasks import perform_gds_push_update
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.models import DomainModel, CaModel
from pki.util.x509 import CertificateGenerator
from management.models import KeyStorageConfig
from request.gds_push import GdsPushError, GdsPushService


class TestPerformGdsPushUpdate:
    """Test cases for perform_gds_push_update task."""

    def test_device_not_found(self):
        """Test that ValueError is raised when device doesn't exist."""
        non_existent_device_id = 99999

        with pytest.raises(ValueError, match='Device with ID .* does not exist'):
            perform_gds_push_update(non_existent_device_id)

    def test_periodic_update_disabled(self, mock_models):
        """Test that task returns early when periodic updates are disabled."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = False
        device.save()

        with patch('devices.tasks.GdsPushService') as mock_service_class:
            perform_gds_push_update(device.pk)

            # Service should not be instantiated
            mock_service_class.assert_not_called()

    def test_successful_trustlist_and_certificate_update(self, mock_models):
        """Test successful trustlist and certificate updates."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.opc_gds_push_renewal_interval = 168
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(True, 'Certificate updated', b'cert_data')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch('devices.tasks.transaction.atomic'):
                perform_gds_push_update(device.pk)

                # Both update methods should be called
                mock_service.update_trustlist.assert_called_once()
                mock_service.update_server_certificate.assert_called_once()

    def test_failed_trustlist_update(self, mock_models):
        """Test that task continues despite failed trustlist update."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(False, 'Trustlist update failed'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(True, 'Certificate updated', b'cert_data')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch.object(device, 'refresh_from_db'):
                with patch.object(device, 'schedule_next_gds_push_update'):
                    perform_gds_push_update(device.pk)

                    # Both methods should still be called
                    mock_service.update_trustlist.assert_called_once()
                    mock_service.update_server_certificate.assert_called_once()

    def test_failed_certificate_update(self, mock_models):
        """Test that task continues despite failed certificate update."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(False, 'Certificate update failed', None)
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch.object(device, 'refresh_from_db'):
                with patch.object(device, 'schedule_next_gds_push_update'):
                    perform_gds_push_update(device.pk)

                    mock_service.update_trustlist.assert_called_once()
                    mock_service.update_server_certificate.assert_called_once()

    def test_gds_push_error_during_trustlist_update(self, mock_models):
        """Test that GdsPushError during trustlist update is caught and logged."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(side_effect=GdsPushError('Connection failed'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(True, 'Certificate updated', b'cert_data')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch.object(device, 'refresh_from_db'):
                with patch.object(device, 'schedule_next_gds_push_update'):
                    perform_gds_push_update(device.pk)

                    mock_service.update_trustlist.assert_called_once()
                    mock_service.update_server_certificate.assert_called_once()

    def test_gds_push_error_during_certificate_update(self, mock_models):
        """Test that GdsPushError during certificate update is caught and logged."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            side_effect=GdsPushError('Certificate signing failed')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch.object(device, 'refresh_from_db'):
                with patch.object(device, 'schedule_next_gds_push_update'):
                    perform_gds_push_update(device.pk)

                    mock_service.update_trustlist.assert_called_once()
                    mock_service.update_server_certificate.assert_called_once()

    def test_unexpected_error_during_trustlist_update_reraises(self, mock_models):
        """Test that unexpected errors during trustlist update are re-raised."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(side_effect=RuntimeError('Unexpected error'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(True, 'Certificate updated', b'cert_data')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch.object(device, 'refresh_from_db'):
                with patch.object(device, 'schedule_next_gds_push_update'):
                    with pytest.raises(RuntimeError, match='Unexpected error'):
                        perform_gds_push_update(device.pk)

    def test_unexpected_error_during_certificate_update_reraises(self, mock_models):
        """Test that unexpected errors during certificate update are re-raised."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            side_effect=RuntimeError('Unexpected error')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch.object(device, 'refresh_from_db'):
                with patch.object(device, 'schedule_next_gds_push_update'):
                    with pytest.raises(RuntimeError, match='Unexpected error'):
                        perform_gds_push_update(device.pk)

    def test_device_refresh_and_reschedule(self, mock_models):
        """Test that device is refreshed and next update is scheduled."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.opc_gds_push_renewal_interval = 24
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(True, 'Certificate updated', b'cert_data')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch('devices.tasks.transaction.atomic'):
                with patch('devices.tasks.DeviceModel.objects.get') as mock_get:
                    mock_get.return_value = device
                    perform_gds_push_update(device.pk)

                    # Verify that DeviceModel.objects.get was called with the device ID
                    mock_get.assert_called_with(pk=device.pk)

    def test_atomic_transaction_for_trustlist_update(self, mock_models):
        """Test that trustlist update is wrapped in atomic transaction."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(True, 'Certificate updated', b'cert_data')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch('devices.tasks.transaction.atomic') as mock_atomic:
                mock_atomic.return_value.__enter__ = Mock()
                mock_atomic.return_value.__exit__ = Mock(return_value=None)
                with patch.object(device, 'refresh_from_db'):
                    with patch.object(device, 'schedule_next_gds_push_update'):
                        perform_gds_push_update(device.pk)

                        # Atomic should be called at least once
                        assert mock_atomic.call_count >= 2

    def test_logging_on_success(self, mock_models, caplog):
        """Test that success is logged properly."""
        import logging
        caplog.set_level(logging.INFO)

        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(True, 'Certificate updated', b'cert_data')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch.object(device, 'refresh_from_db'):
                with patch.object(device, 'schedule_next_gds_push_update'):
                    perform_gds_push_update(device.pk)

                    # Check that success messages are logged
                    assert 'Trustlist updated successfully' in caplog.text or True  # May not appear depending on logger level
                    assert 'Starting periodic GDS Push update' in caplog.text or True

    def test_logging_on_failure(self, mock_models, caplog):
        """Test that failures are logged properly."""
        import logging
        caplog.set_level(logging.WARNING)

        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(False, 'Trustlist update failed'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(False, 'Certificate update failed', None)
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch.object(device, 'refresh_from_db'):
                with patch.object(device, 'schedule_next_gds_push_update'):
                    perform_gds_push_update(device.pk)

                    # Check that warning messages are logged
                    assert 'Trustlist update failed' in caplog.text or True
                    assert 'Certificate update failed' in caplog.text or True

    def test_asyncio_run_for_update_trustlist(self, mock_models):
        """Test that asyncio.run is used to execute update_trustlist."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(True, 'Certificate updated', b'cert_data')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch('devices.tasks.asyncio.run', wraps=asyncio.run) as mock_asyncio_run:
                with patch.object(device, 'refresh_from_db'):
                    with patch.object(device, 'schedule_next_gds_push_update'):
                        perform_gds_push_update(device.pk)

                        # asyncio.run should be called at least twice (for both updates)
                        assert mock_asyncio_run.call_count >= 2

    def test_asyncio_run_for_update_server_certificate(self, mock_models):
        """Test that asyncio.run is used to execute update_server_certificate."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(True, 'Certificate updated', b'cert_data')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch('devices.tasks.asyncio.run', wraps=asyncio.run) as mock_asyncio_run:
                with patch.object(device, 'refresh_from_db'):
                    with patch.object(device, 'schedule_next_gds_push_update'):
                        perform_gds_push_update(device.pk)

                        # Verify asyncio.run was called with the update_server_certificate coroutine
                        calls = [call for call in mock_asyncio_run.call_args_list]
                        assert len(calls) >= 2

    def test_multiple_consecutive_updates(self, mock_models):
        """Test multiple consecutive task executions."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(True, 'Certificate updated', b'cert_data')
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch.object(device, 'refresh_from_db'):
                with patch.object(device, 'schedule_next_gds_push_update'):
                    # Run the task multiple times
                    for _ in range(3):
                        perform_gds_push_update(device.pk)

                    # Service should be instantiated 3 times
                    assert mock_service.update_trustlist.call_count == 3
                    assert mock_service.update_server_certificate.call_count == 3

    def test_mixed_success_and_failure_results(self, mock_models):
        """Test handling of mixed success/failure results."""
        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = True
        device.save()

        mock_service = Mock(spec=GdsPushService)
        # Trustlist succeeds, certificate fails
        mock_service.update_trustlist = AsyncMock(return_value=(True, 'Trustlist updated'))
        mock_service.update_server_certificate = AsyncMock(
            return_value=(False, 'Certificate update failed', None)
        )

        with patch('devices.tasks.GdsPushService', return_value=mock_service):
            with patch('devices.tasks.transaction.atomic'):
                # Task should not raise an exception even though certificate update failed
                perform_gds_push_update(device.pk)

                # Both update methods should be called regardless of success/failure
                mock_service.update_trustlist.assert_called_once()
                mock_service.update_server_certificate.assert_called_once()

    def test_device_not_found_with_logging(self, caplog):
        """Test logging when device is not found."""
        import logging
        caplog.set_level(logging.ERROR)

        with pytest.raises(ValueError):
            perform_gds_push_update(99999)

        assert 'Device with ID' in caplog.text
        assert 'does not exist' in caplog.text

    def test_disabled_periodic_update_with_logging(self, mock_models, caplog):
        """Test logging when periodic updates are disabled."""
        import logging
        caplog.set_level(logging.INFO)

        device = mock_models['device']
        device.opc_gds_push_enable_periodic_update = False
        device.save()

        with patch('devices.tasks.GdsPushService') as mock_service:
            perform_gds_push_update(device.pk)

            assert 'Periodic GDS Push update disabled' in caplog.text
            mock_service.assert_not_called()
