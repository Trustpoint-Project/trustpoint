# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for QR code-based credential file downloads."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

from django.contrib.auth.decorators import login_not_required
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy
from django.views.generic import View
from trustpoint_core.serializer import CredentialFileFormat

from devices.models import RemoteDeviceCredentialDownloadModel
from devices.qr_code import QRCODE_AVAILABLE, generate_file_download_qr_url, generate_qr_code
from pki.models import IssuedCredentialModel

if TYPE_CHECKING:
    from django.http.request import HttpRequest


@method_decorator(login_not_required, name='dispatch')
class QRCodeCredentialDownloadView(View):
    """View to download a credential file directly via QR code with token authentication.

    This view is designed to work with QR codes that contain a download URL with an embedded
    token. Users scan the QR code which directs them to this endpoint, and the file is
    immediately downloaded to their device without requiring OTP entry or additional steps.
    """

    http_method_names = ('get',)

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Process the QR code download request and serve the credential file.

        Args:
            request: The Django request object containing the token and format parameters.
            pk: The primary key of the IssuedCredentialModel.

        Returns:
            FileResponse with the credential file or Http404 if invalid.

        Raises:
            Http404: If the token is invalid, expired, or the credential cannot be found.
        """
        # Get query parameters
        token = request.GET.get('token')
        file_format_str = request.GET.get('format', 'PKCS12')
        password = request.GET.get('password', '')

        if not token:
            raise Http404(gettext_lazy('Missing download token.'))

        # Get the issued credential
        issued_credential = get_object_or_404(IssuedCredentialModel, pk=pk)

        # Verify the token via RemoteDeviceCredentialDownloadModel
        try:
            cdm = RemoteDeviceCredentialDownloadModel.objects.get(
                issued_credential_model=issued_credential, device=issued_credential.device
            )
        except RemoteDeviceCredentialDownloadModel.DoesNotExist as e:
            raise Http404(gettext_lazy('Invalid or expired download session.')) from e

        # Check token validity
        if not cdm.check_token(token):
            raise Http404(gettext_lazy('Invalid or expired download token.'))

        # Parse file format
        try:
            file_format = CredentialFileFormat[file_format_str]
        except KeyError as e:
            raise Http404(gettext_lazy('Invalid file format specified.')) from e

        # Get the credential model and serializers
        credential_model = issued_credential.credential
        if not credential_model:
            raise Http404(gettext_lazy('Credential not found.'))

        credential_serializer = credential_model.get_credential_serializer()
        private_key_serializer = credential_serializer.get_private_key_serializer()
        certificate_serializer = credential_serializer.get_certificate_serializer()
        cert_collection_serializer = credential_serializer.get_additional_certificates_serializer()

        if not private_key_serializer or not certificate_serializer or not cert_collection_serializer:
            raise Http404(gettext_lazy('Unable to serialize credential.'))

        # Use password if provided, otherwise use empty bytes
        password_bytes = password.encode() if password else b''

        # Generate file based on format
        cert_profile_name = issued_credential.issued_using_cert_profile
        credential_type_name = cert_profile_name.replace(' ', '-').lower().replace('-credential', '')

        if file_format == CredentialFileFormat.PKCS12:
            file_data = credential_serializer.as_pkcs12(password=password_bytes)
            file_stream = io.BytesIO(file_data)

        elif file_format == CredentialFileFormat.PEM_ZIP:
            from trustpoint_core.archiver import Archiver  # noqa: PLC0415

            file_data = Archiver.archive_zip(
                data_to_archive={
                    'private_key.pem': private_key_serializer.as_pkcs8_pem(password=password_bytes),
                    'certificate.pem': certificate_serializer.as_pem(),
                    'certificate_chain.pem': cert_collection_serializer.as_pem(),
                }
            )
            file_stream = io.BytesIO(file_data)

        elif file_format == CredentialFileFormat.PEM_TAR_GZ:
            from trustpoint_core.archiver import Archiver  # noqa: PLC0415

            file_data = Archiver.archive_tar_gz(
                data_to_archive={
                    'private_key.pem': private_key_serializer.as_pkcs8_pem(password=password_bytes),
                    'certificate.pem': certificate_serializer.as_pem(),
                    'certificate_chain.pem': cert_collection_serializer.as_pem(),
                }
            )
            file_stream = io.BytesIO(file_data)

        else:
            raise Http404(gettext_lazy('Unsupported file format.'))

        # Clean up the download model after successful download
        cdm.delete()

        # Return file response
        return FileResponse(
            file_stream,
            content_type=file_format.mime_type,
            as_attachment=True,
            filename=f'trustpoint-{credential_type_name}-credential{file_format.file_extension}',
        )


def get_qr_code_data_url(credential_id: int, request: HttpRequest) -> str | None:
    """Generate QR code data URL for a credential download.

    Args:
        credential_id: The ID of the credential.
        request: The Django request object to build the absolute URI.

    Returns:
        Base64-encoded PNG data URL for the QR code, or None if QR code generation is unavailable.
    """
    if not QRCODE_AVAILABLE:
        return None

    # Get the credential and its download model
    try:
        issued_credential = IssuedCredentialModel.objects.get(pk=credential_id)
        cdm = RemoteDeviceCredentialDownloadModel.objects.get(
            issued_credential_model=issued_credential, device=issued_credential.device
        )
    except (IssuedCredentialModel.DoesNotExist, RemoteDeviceCredentialDownloadModel.DoesNotExist):
        return None

    # Generate the download URL
    base_url = f'{request.scheme}://{request.get_host()}'
    download_url = generate_file_download_qr_url(
        base_url=base_url, credential_id=credential_id, token=cdm.download_token, file_format='PKCS12'
    )

    # Generate and return QR code
    return generate_qr_code(download_url)
