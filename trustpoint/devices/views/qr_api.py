# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""API endpoints for QR code generation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth.decorators import login_not_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views import View

from devices.models import RemoteDeviceCredentialDownloadModel
from devices.qr_code import QRCODE_AVAILABLE, generate_pkcs12_qr_data, generate_qr_code
from pki.models import IssuedCredentialModel

if TYPE_CHECKING:
    from django.http.request import HttpRequest


@method_decorator(login_not_required, name='dispatch')
class GenerateQRCodeAPIView(View):
    """API endpoint to generate QR code with PKCS#12 data for a given password."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest, pk: int) -> JsonResponse:
        """Generate QR code with PKCS#12 embedded for the given password.

        Args:
            request: The Django request object.
            pk: The primary key of the IssuedCredentialModel.

        Returns:
            JsonResponse with QR code data URL or error.
        """
        # Check QR code availability
        if not QRCODE_AVAILABLE:
            return JsonResponse({'error': 'QR code generation not available'}, status=503)

        # Get and validate password
        password = request.POST.get('password', '')
        if not password or len(password) < 12:  # noqa: PLR2004
            return JsonResponse({'error': 'Password must be at least 12 characters'}, status=400)

        # Verify token
        token = request.GET.get('token')
        if not token:
            return JsonResponse({'error': 'Missing token'}, status=401)

        # Get issued credential and verify token
        issued_credential = get_object_or_404(IssuedCredentialModel, pk=pk)

        try:
            cdm = RemoteDeviceCredentialDownloadModel.objects.get(
                issued_credential_model=issued_credential, device=issued_credential.device
            )
        except RemoteDeviceCredentialDownloadModel.DoesNotExist:
            return JsonResponse({'error': 'Invalid session'}, status=401)

        # Check token without deleting it (for subsequent requests)
        if not cdm.download_token or cdm.download_token != token:
            return JsonResponse({'error': 'Invalid or expired token'}, status=401)

        # Generate PKCS#12 with the provided password
        credential_model = issued_credential.credential
        credential_serializer = credential_model.get_credential_serializer()

        try:
            password_bytes = password.encode('utf-8')
            pkcs12_data = credential_serializer.as_pkcs12(password=password_bytes)
            pkcs12_data_uri = generate_pkcs12_qr_data(pkcs12_data)
            qr_code_data_url = generate_qr_code(pkcs12_data_uri)

            return JsonResponse({'qr_code': qr_code_data_url, 'password': password})

        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)
