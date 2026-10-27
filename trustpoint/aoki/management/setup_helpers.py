# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared infrastructure for local AOKI test-environment commands."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from pki.management.commands.base_commands import CertificateCreationCommandMixin
from pki.models import CaModel, CertificateModel, DomainModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel
from pki.util.x509 import CertificateGenerator
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from pathlib import Path


class AokiCommandLoggingMixin(LoggerMixin):
    """Keep the plain console output used by AOKI setup commands."""

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Log a message and print it to stdout.

        :param message: The message to log and print.
        :param level: The log level (``'info'``, ``'warning'``, or ``'error'``).
        """
        print(message)  # noqa: T201
        if level == 'warning':
            self.logger.warning(message)
        elif level == 'error':
            self.logger.error(message)
        else:
            self.logger.info(message)


class EstTestEnvironmentMixin(CertificateCreationCommandMixin, AokiCommandLoggingMixin):
    """Create the CA, domain, and TLS truststore for an EST test environment."""

    ca_unique_name: str
    domain_unique_name: str
    truststore_unique_name: str
    https_server_cert_path: Path

    def _get_or_create_issuing_ca(self) -> CaModel:
        """Return an existing CA or create an RSA-2048 root and issuing CA."""
        if CaModel.objects.filter(unique_name=self.ca_unique_name).exists():
            self.log_and_stdout(f'Issuing CA "{self.ca_unique_name}" already exists, skipping creation.')
            return CaModel.objects.get(unique_name=self.ca_unique_name)

        root_key = self.create_backend_rsa_private_key(alias=f'{self.ca_unique_name}-root', key_size=2048)
        issuing_key = self.create_backend_rsa_private_key(alias=self.ca_unique_name, key_size=2048)

        root_cert, _ = self.create_root_ca(
            f'{self.ca_unique_name} - Root',
            private_key=root_key,
            hash_algorithm=hashes.SHA256(),
        )
        issuing_cert, _ = self.create_issuing_ca(
            issuer_private_key=root_key,
            private_key=issuing_key,
            issuer_cn=f'{self.ca_unique_name} - Root',
            subject_cn=self.ca_unique_name,
            hash_algorithm=hashes.SHA256(),
        )
        issuing_ca = CertificateGenerator.save_issuing_ca(
            issuing_ca_cert=issuing_cert,
            chain=[root_cert],
            private_key=issuing_key,
            unique_name=self.ca_unique_name,
        )
        self.log_and_stdout(f'Created issuing CA "{self.ca_unique_name}".')
        return issuing_ca

    def _get_or_create_domain(self, issuing_ca: CaModel) -> DomainModel:
        """Create the configured domain or update its issuing CA."""
        domain, created = DomainModel.objects.get_or_create(
            unique_name=self.domain_unique_name,
            defaults={'issuing_ca': issuing_ca},
        )
        if created:
            self.log_and_stdout(f'Created domain "{self.domain_unique_name}".')
        else:
            domain.issuing_ca = issuing_ca
            domain.save()
            self.log_and_stdout(f'Domain "{self.domain_unique_name}" already exists, updated issuing CA.')
        return domain

    def _get_or_create_tls_truststore(self) -> TruststoreModel:
        """Create the configured TLS truststore from the HTTPS server certificate."""
        if TruststoreModel.objects.filter(unique_name=self.truststore_unique_name).exists():
            self.log_and_stdout(f'Truststore "{self.truststore_unique_name}" already exists, skipping creation.')
            return TruststoreModel.objects.get(unique_name=self.truststore_unique_name)

        if not self.https_server_cert_path.exists():
            msg = f'HTTPS server certificate not found at {self.https_server_cert_path}'
            raise FileNotFoundError(msg)

        pem_data = self.https_server_cert_path.read_bytes()
        crypto_cert = x509.load_pem_x509_certificate(pem_data)
        cert_model = CertificateModel.save_certificate(crypto_cert)

        truststore = TruststoreModel(
            unique_name=self.truststore_unique_name,
            intended_usage=TruststoreModel.IntendedUsage.TLS,
        )
        truststore.save()
        TruststoreOrderModel.objects.create(
            trust_store=truststore,
            certificate=cert_model,
            order=0,
        )
        self.log_and_stdout(f'Created TLS truststore "{self.truststore_unique_name}".')
        return truststore
