# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for QR code credential download functionality."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from django.test import RequestFactory
from django.urls import reverse

from devices.models import RemoteDeviceCredentialDownloadModel
from devices.qr_code import QRCODE_AVAILABLE, generate_file_download_qr_url, generate_qr_code
from devices.views.qr_download import QRCodeCredentialDownloadView


class TestQRCodeGeneration:
    """Tests for QR code generation utilities."""

    def test_generate_file_download_qr_url(self) -> None:
        """Test URL generation for QR code downloads."""
        url = generate_file_download_qr_url(
            base_url='https://example.com', credential_id=123, token='test_token', file_format='PKCS12'
        )

        assert url == 'https://example.com/devices/credentials/123/qr-download?token=test_token&format=PKCS12'

    def test_generate_file_download_qr_url_strips_trailing_slash(self) -> None:
        """Test that trailing slashes are removed from base URL."""
        url = generate_file_download_qr_url(
            base_url='https://example.com/', credential_id=123, token='test_token', file_format='PEM_ZIP'
        )

        assert url == 'https://example.com/devices/credentials/123/qr-download?token=test_token&format=PEM_ZIP'

    @pytest.mark.skipif(not QRCODE_AVAILABLE, reason='qrcode library not installed')
    def test_generate_qr_code(self) -> None:
        """Test QR code generation returns base64 data URL."""
        url = 'https://example.com/test'
        qr_code = generate_qr_code(url)

        assert qr_code.startswith('data:image/png;base64,')
        assert len(qr_code) > 100  # Should have substantial base64 content

    @pytest.mark.skipif(QRCODE_AVAILABLE, reason='Test for missing qrcode library')
    def test_generate_qr_code_without_library(self) -> None:
        """Test that missing qrcode library raises ImportError."""
        with pytest.raises(ImportError, match='qrcode library is required'):
            generate_qr_code('https://example.com/test')


@pytest.mark.django_db
class TestQRCodeCredentialDownloadView:
    """Tests for the QR code credential download view."""

    def test_missing_token_returns_404(
        self, issued_credential_instance: dict, domain_credential_est_onboarding: dict
    ) -> None:
        """Test that missing token parameter returns 404."""
        factory = RequestFactory()
        credential_id = issued_credential_instance['issued_credential_model'].id

        request = factory.get(reverse('devices:qr_code_credential_download', kwargs={'pk': credential_id}))

        view = QRCodeCredentialDownloadView.as_view()
        response = view(request, pk=credential_id)

        assert response.status_code == 404

    def test_invalid_token_returns_404(
        self, issued_credential_instance: dict, domain_credential_est_onboarding: dict
    ) -> None:
        """Test that invalid token returns 404."""
        factory = RequestFactory()
        credential_id = issued_credential_instance['issued_credential_model'].id

        # Create CDM but use wrong token
        credential_model = issued_credential_instance['issued_credential_model']
        device = credential_model.device
        cdm = RemoteDeviceCredentialDownloadModel(issued_credential_model=credential_model, device=device)
        cdm.save()

        request = factory.get(
            reverse('devices:qr_code_credential_download', kwargs={'pk': credential_id}), {'token': 'wrong_token'}
        )

        view = QRCodeCredentialDownloadView.as_view()
        response = view(request, pk=credential_id)

        assert response.status_code == 404

    def test_invalid_format_returns_404(
        self, issued_credential_instance: dict, domain_credential_est_onboarding: dict
    ) -> None:
        """Test that invalid file format returns 404."""
        factory = RequestFactory()
        credential_id = issued_credential_instance['issued_credential_model'].id

        credential_model = issued_credential_instance['issued_credential_model']
        device = credential_model.device
        cdm = RemoteDeviceCredentialDownloadModel(issued_credential_model=credential_model, device=device)
        cdm.save()
        cdm.otp = '-'
        cdm.download_token = 'valid_token'
        cdm.save()

        request = factory.get(
            reverse('devices:qr_code_credential_download', kwargs={'pk': credential_id}),
            {'token': 'valid_token', 'format': 'INVALID_FORMAT'},
        )

        view = QRCodeCredentialDownloadView.as_view()
        response = view(request, pk=credential_id)

        assert response.status_code == 404


class TestQRCodeIntegration:
    """Integration tests for QR code functionality in views."""

    @pytest.mark.skipif(not QRCODE_AVAILABLE, reason='qrcode library not installed')
    @pytest.mark.django_db
    def test_otp_view_includes_qr_code(
        self, client: MagicMock, domain_credential_est_onboarding: dict, issued_credential_instance: dict
    ) -> None:
        """Test that OTP view includes QR code when library is available."""
        credential_id = issued_credential_instance['issued_credential_model'].id

        client.login(username='testuser', password='testpass')
        response = client.get(reverse('devices:devices_browser_otp_view', kwargs={'pk': credential_id}))

        assert response.status_code == 200
        assert 'qr_code_available' in response.context
        if QRCODE_AVAILABLE:
            assert response.context['qr_code_available'] is True
            assert 'qr_code_data_url' in response.context
            assert response.context['qr_code_data_url'].startswith('data:image/png;base64,')
