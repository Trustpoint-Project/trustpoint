# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django management command to create the Management CA hierarchy."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from pki.models import CaModel

from .base_commands import CertificateCreationCommandMixin

ROOT_CA_NAME = 'Management Root CA'
ISSUING_CA_NAME = 'Management Issuing CA'


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Create a root CA and one issuing CA for user certificate authentication."""

    help = 'Creates the Management Root CA and Management Issuing CA using the configured crypto backend.'

    @transaction.atomic
    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Create the Management CA hierarchy once, preserving it on subsequent calls."""
        root_ca = CaModel.objects.filter(unique_name=ROOT_CA_NAME).first()
        issuing_ca = CaModel.objects.filter(unique_name=ISSUING_CA_NAME).first()
        if root_ca is not None or issuing_ca is not None:
            if (
                root_ca is None
                or issuing_ca is None
                or root_ca.parent_ca_id is not None
                or issuing_ca.parent_ca_id != root_ca.pk
                or root_ca.credential_id is None
                or issuing_ca.credential_id is None
            ):
                msg = 'The Management CA hierarchy is incomplete or inconsistent.'
                raise CommandError(msg)
            self.stdout.write('Management CA hierarchy already exists, skipping creation.')
            return

        root_ca_key = self.create_backend_ec_private_key(alias='management-root-ca', curve=ec.SECP256R1())
        root_ca_cert, _ = self.create_root_ca(
            cn=ROOT_CA_NAME,
            private_key=root_ca_key,
            hash_algorithm=hashes.SHA256(),
        )
        root_ca = self.save_issuing_ca(
            issuing_ca_cert=root_ca_cert,
            private_key=root_ca_key,
            chain=[],
            unique_name=ROOT_CA_NAME,
        )

        issuing_ca_key = self.create_backend_ec_private_key(alias='management-ca', curve=ec.SECP256R1())
        issuing_ca_cert, _ = self.create_issuing_ca(
            issuer_private_key=root_ca_key,
            issuer_cn=ROOT_CA_NAME,
            subject_cn=ISSUING_CA_NAME,
            private_key=issuing_ca_key,
            hash_algorithm=hashes.SHA256(),
        )
        self.save_issuing_ca(
            issuing_ca_cert=issuing_ca_cert,
            private_key=issuing_ca_key,
            chain=[root_ca_cert],
            unique_name=ISSUING_CA_NAME,
            parent_ca=root_ca,
        )
        self.stdout.write(self.style.SUCCESS('Management CA hierarchy created.'))
