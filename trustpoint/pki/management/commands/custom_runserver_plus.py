# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command to stores the TLS certificate to the database."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from django_extensions.management.commands.runserver_plus import Command as RunServerPlusCommand
from trustpoint_core.serializer import CertificateSerializer, CredentialSerializer, PrivateKeySerializer

from pki.models import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel


class Command(RunServerPlusCommand):
    """Custom runserver_plus command that stores the TLS certificate to the database."""

    def store_tls_certificate(self, cert_file_path: str, key_file_path: str) -> tuple[str, str]:
        """Fetch or create the TLS certificate and key from the database."""
        if not Path(cert_file_path).exists() or not Path(key_file_path).exists():
            self.stdout.write(f'Certificate or key file not found: {cert_file_path}, {key_file_path}')

        active_credential = ActiveTrustpointTlsServerCredentialModel.objects.first()

        if active_credential and active_credential.credential:
            self.stdout.write('Active TLS credential already exists in the database.')
            return None, None

        with Path(cert_file_path).open('rb') as cert_file:
            cert_pem = cert_file.read()
        certificate_serializer = CertificateSerializer.from_pem(cert_pem)

        with Path(key_file_path).open('rb') as key_file:
            key_pem = key_file.read()
        key_serializer = PrivateKeySerializer.from_pem(key_pem)


        tls_server_credential_serializer = CredentialSerializer.from_serializers(
            private_key_serializer=key_serializer,
            certificate_serializer=certificate_serializer,
        )

        trustpoint_tls_server_credential = CredentialModel.save_credential_serializer(
            credential_serializer=tls_server_credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
        )

        active_tls, _ = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
        active_tls.credential = trustpoint_tls_server_credential
        active_tls.save()

        self.stdout.write('Updated ActiveTrustpointTlsServerCredentialModel.')

        return cert_file_path, key_file_path

    def handle(self, *args: Any, **options: Any) -> None:
        """Main command execution logic."""
        cert_file = options.get('cert_path')
        key_file = options.get('key_file_path')

        if cert_file and key_file:
            self.store_tls_certificate(cert_file, key_file)

        # Call the original runserver_plus command
        super().handle(*args, **options)
