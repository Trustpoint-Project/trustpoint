from __future__ import annotations

import os

from typing import Callable
from django_extensions.management.commands.runserver_plus import Command as RunServerPlusCommand
from pki.models import CertificateModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel, TrustpointTlsServerCredentialModel
from trustpoint_core.serializer import CertificateSerializer


class Command(RunServerPlusCommand):
    """Custom runserver_plus command that stores the TLS certificate to the database."""

    def store_tls_certificate(self, cert_file_path, key_file_path):
        """Fetch or create the TLS certificate and key from the database."""
        if not os.path.exists(cert_file_path) or not os.path.exists(key_file_path):
            print(f'Certificate or key file not found: {cert_file_path}, {key_file_path}')

        active_credential = ActiveTrustpointTlsServerCredentialModel.objects.first()

        if active_credential and active_credential.credential:
            print('Active TLS credential already exists in the database.')
            return None, None

        with open(cert_file_path, 'rb') as cert_file:
            cert_pem = cert_file.read()
        certificate_serializer = CertificateSerializer.from_pem(cert_pem)

        with open(key_file_path) as key_file:
            key_pem = key_file.read()

        stored_tls_cert = CertificateModel.save_certificate(certificate_serializer)

        tls_server_credential, _ = TrustpointTlsServerCredentialModel.objects.get_or_create(
            certificate=stored_tls_cert, defaults={'private_key_pem': key_pem}
        )

        active_tls, _ = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
        active_tls.credential = tls_server_credential
        active_tls.save()

        print('Updated ActiveTrustpointTlsServerCredentialModel.')

        return cert_file_path, key_file_path

    def handle(self, *args, **options):
        """Main command execution logic."""
        cert_file = options.get('cert_path')
        key_file = options.get('key_file_path')

        if cert_file and key_file:
            self.store_tls_certificate(cert_file, key_file)

        # Call the original runserver_plus command
        super().handle(*args, **options)
