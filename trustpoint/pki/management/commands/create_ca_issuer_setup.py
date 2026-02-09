"""Django management command to create CA issuer setup."""

from __future__ import annotations

import uuid
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
from pki.models import CertificateModel, CredentialModel
from devices.models import DeviceModel
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import models
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.models import CaModel, DomainModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel, TruststoreModel
from trustpoint.logger import LoggerMixin
from trustpoint.settings import DOCKER_CONTAINER
from trustpoint_core.oid import KeyPairGenerator, NamedCurve, PublicKeyAlgorithmOid, PublicKeyInfo
from trustpoint_core.serializer import CredentialSerializer
from pki.util.x509 import CertificateGenerator

from .base_commands import CertificateCreationCommandMixin


class Command(CertificateCreationCommandMixin, LoggerMixin, BaseCommand):
    """Creates an issuing CA, domain, and device for CA issuer."""

    help = 'Creates RSA 2048 issuing CA "ca_issuer", domain, and device "CA Issuer - no onboarding" with CMP and EST enabled.'

    def _create_temp_credential(self) -> CredentialModel:
        """Create and return a temporary credential for the remote CA."""
        # Use RSA-2048 as in the form's default
        public_key_info = PublicKeyInfo(
            public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA,
            key_size=2048
        )

        private_key = KeyPairGenerator.generate_key_pair_for_public_key_info(public_key_info)

        temp_cert, _ = CertificateGenerator.create_root_ca(
            cn=f'Temp-{uuid.uuid4()}',
            validity_days=1,
            private_key=private_key
        )

        cred_serializer = CredentialSerializer(
            certificate=temp_cert,
            private_key=private_key,
            additional_certificates=[]
        )

        return CredentialModel.save_credential_serializer(
            cred_serializer, CredentialModel.CredentialTypeChoice.ISSUING_CA
        )

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Creates the CA issuer setup."""
        # Load certificate profiles
        call_command('create_default_cert_profiles')

        # Enable the issuing_ca profile
        try:
            issuing_ca_profile = CertificateProfileModel.objects.get(unique_name='issuing_ca')
            issuing_ca_profile.is_default = True
            issuing_ca_profile.save()
            self.log_and_stdout('Enabled issuing_ca certificate profile.')
        except CertificateProfileModel.DoesNotExist:
            self.log_and_stdout('issuing_ca certificate profile not found.', level='warning')

        # Create issuing CA
        if CaModel.objects.filter(unique_name='ca_issuer').exists():
            self.log_and_stdout('Issuing CA "ca_issuer" already exists.')
            issuing_ca = CaModel.objects.get(unique_name='ca_issuer')
        else:
            rsa_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rsa_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rsa_root, _ = self.create_root_ca(
                'Root-CA RSA-2048-SHA256 - CA Issuer', private_key=rsa_root_ca_key, hash_algorithm=hashes.SHA256()
            )
            rsa_issuing_ca, _key = self.create_issuing_ca(
                issuer_private_key=rsa_root_ca_key,
                private_key=rsa_issuing_ca_key,
                issuer_cn='Root-CA RSA-2048-SHA256 - CA Issuer',
                subject_cn='CA Issuer',
                hash_algorithm=hashes.SHA256(),
            )
            issuing_ca = self.save_issuing_ca(
                issuing_ca_cert=rsa_issuing_ca,
                private_key=rsa_issuing_ca_key,
                chain=[rsa_root],
                unique_name='ca_issuer',
            )
            self.log_and_stdout('Created issuing CA "ca_issuer".')

        # Create domain
        domain, created = DomainModel.objects.get_or_create(unique_name='ca_issuer', defaults={'issuing_ca': issuing_ca})
        if created:
            self.log_and_stdout('Created domain "ca_issuer".')
        else:
            domain.issuing_ca = issuing_ca
            domain.save()
            self.log_and_stdout('Updated domain "ca_issuer".')

        # Create device
        device = None
        if DeviceModel.objects.filter(common_name='CA Issuer - no onboarding').exists():
            self.log_and_stdout('Device "CA Issuer - no onboarding" already exists.')
            device = DeviceModel.objects.get(common_name='CA Issuer - no onboarding')
        else:
            no_onboarding_config = NoOnboardingConfigModel()
            no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.CMP_SHARED_SECRET, NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD])
            no_onboarding_config.cmp_shared_secret = 'foo123'
            no_onboarding_config.est_password = 'foo123'
            no_onboarding_config.full_clean()
            no_onboarding_config.save()

            device = DeviceModel(
                common_name='CA Issuer - no onboarding',
                serial_number='CAISSUER001',
                domain=domain,
                device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
                no_onboarding_config=no_onboarding_config
            )
            device.full_clean()
            device.save()
            self.log_and_stdout('Created device "CA Issuer - no onboarding".')

        # Create remote issuing CA
        if CaModel.objects.filter(unique_name='Remote issued CA - EST').exists():
            self.log_and_stdout('Remote issuing CA "Remote issued CA - EST" already exists.')
            remote_ca = CaModel.objects.get(unique_name='Remote issued CA - EST')
            # Update trust_store if not set
            if remote_ca.no_onboarding_config and not remote_ca.no_onboarding_config.trust_store:
                # Get or create truststore
                tls_cert = None
                if DOCKER_CONTAINER:
                    tls_cred = ActiveTrustpointTlsServerCredentialModel.objects.first()
                    if tls_cred and tls_cred.credential:
                        tls_cert = tls_cred.credential.certificate
                        self.log_and_stdout('Using active TLS server credential from Docker.')
                    else:
                        self.log_and_stdout('No active TLS server credential found in Docker.', level='error')
                        return
                else:
                    # Load from test files
                    cert_path = Path(__file__).parent.parent.parent.parent.parent / 'tests/data/x509/https_server.crt'
                    key_path = Path(__file__).parent.parent.parent.parent.parent / 'tests/data/x509/https_server.pem'
                    if cert_path.exists() and key_path.exists():
                        with cert_path.open('rb') as f:
                            cert_data = f.read()
                        with key_path.open('rb') as f:
                            key_data = f.read()
                        tls_certificate = x509.load_pem_x509_certificate(cert_data)
                        tls_private_key = serialization.load_pem_private_key(key_data, password=None)
                        tls_cert = CertificateModel.save_certificate(tls_certificate)
                        self.log_and_stdout('Loaded TLS certificate from test files.')
                    else:
                        self.log_and_stdout('TLS certificate files not found.', level='error')
                        return

                truststore, created = TruststoreModel.objects.get_or_create(
                    unique_name='tls-truststore',
                    defaults={'intended_usage': TruststoreModel.IntendedUsage.TLS}
                )
                if created:
                    truststore.certificates.add(tls_cert, through_defaults={'order': 0})
                    self.log_and_stdout('Created TLS truststore.')
                else:
                    if not truststore.certificates.filter(pk=tls_cert.pk).exists():
                        max_order = truststore.truststoreordermodel_set.aggregate(models.Max('order'))['order__max'] or -1
                        truststore.certificates.add(tls_cert, through_defaults={'order': max_order + 1})
                        self.log_and_stdout('Updated TLS truststore.')

                remote_ca.no_onboarding_config.trust_store = truststore
                remote_ca.no_onboarding_config.save()
                self.log_and_stdout('Updated no-onboarding config with TLS truststore.')
        else:
            # Get TLS certificate
            tls_cert = None
            if DOCKER_CONTAINER:
                tls_cred = ActiveTrustpointTlsServerCredentialModel.objects.first()
                if tls_cred and tls_cred.credential:
                    tls_cert = tls_cred.credential.certificate
                    self.log_and_stdout('Using active TLS server credential from Docker.')
                else:
                    self.log_and_stdout('No active TLS server credential found in Docker.', level='error')
                    return
            else:
                # Load from test files
                cert_path = Path(__file__).parent.parent.parent.parent.parent / 'tests/data/x509/https_server.crt'
                key_path = Path(__file__).parent.parent.parent.parent.parent / 'tests/data/x509/https_server.pem'
                if cert_path.exists() and key_path.exists():
                    with cert_path.open('rb') as f:
                        cert_data = f.read()
                    with key_path.open('rb') as f:
                        key_data = f.read()
                    tls_certificate = x509.load_pem_x509_certificate(cert_data)
                    tls_private_key = serialization.load_pem_private_key(key_data, password=None)
                    tls_cert = CertificateModel.save_certificate(tls_certificate)
                    self.log_and_stdout('Loaded TLS certificate from test files.')
                else:
                    self.log_and_stdout('TLS certificate files not found.', level='error')
                    return

            truststore, created = TruststoreModel.objects.get_or_create(
                unique_name='tls-truststore',
                defaults={'intended_usage': TruststoreModel.IntendedUsage.TLS}
            )
            if created:
                truststore.certificates.add(tls_cert, through_defaults={'order': 0})
                self.log_and_stdout('Created TLS truststore.')
            else:
                if not truststore.certificates.filter(pk=tls_cert.pk).exists():
                    max_order = truststore.truststoreordermodel_set.aggregate(models.Max('order'))['order__max'] or -1
                    truststore.certificates.add(tls_cert, through_defaults={'order': max_order + 1})
                    self.log_and_stdout('Updated TLS truststore.')

            # Update the no_onboarding_config to use the truststore for server verification
            device.no_onboarding_config.trust_store = truststore
            device.no_onboarding_config.save()
            self.log_and_stdout('Updated no-onboarding config with TLS truststore.')

            remote_ca = CaModel(
                unique_name='Remote issued CA - EST',
                ca_type=CaModel.CaTypeChoice.REMOTE_ISSUING_EST,
                remote_host='localhost',
                remote_port=443,
                remote_path='/.well-known/est/ca_issuer/issuing_ca/simpleenroll',
                est_username=device.common_name,
                no_onboarding_config=device.no_onboarding_config,
                chain_truststore=truststore,
            )
            # Create a temporary credential for the remote CA
            temp_credential = self._create_temp_credential()
            remote_ca.credential = temp_credential
            remote_ca.full_clean()
            remote_ca.save()
            self.log_and_stdout('Created remote issuing CA "Remote issued CA - EST".')

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Log a message and write it to stdout."""
        log_method = getattr(self.logger, level, self.logger.info)
        log_method(message)

        if level == 'error':
            self.stdout.write(self.style.ERROR(message))
        elif level == 'warning':
            self.stdout.write(self.style.WARNING(message))
        elif level == 'info':
            self.stdout.write(self.style.SUCCESS(message))
        else:
            self.stdout.write(message)
