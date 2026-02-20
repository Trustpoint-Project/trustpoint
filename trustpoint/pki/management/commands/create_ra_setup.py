"""Django management command to create RA (Registration Authority) setup for testing.

This command creates a complete RA testing environment with:
- A local issuing CA
- Domains and devices for EST and CMP protocols
- Remote RA configurations that point back to this Trustpoint instance
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import models

from devices.models import DeviceModel
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.models import CaModel, CertificateModel, CredentialModel, DomainModel, TruststoreModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from trustpoint.logger import LoggerMixin
from trustpoint.settings import DOCKER_CONTAINER
from trustpoint_core.oid import KeyPairGenerator, PublicKeyAlgorithmOid, PublicKeyInfo
from trustpoint_core.serializer import CredentialSerializer

from .base_commands import CertificateCreationCommandMixin


class Command(CertificateCreationCommandMixin, LoggerMixin, BaseCommand):
    """Creates a complete RA (Registration Authority) testing setup."""

    help = 'Creates issuing CAs, domains, devices, and RA configurations for testing RA functionality.'

    def _create_temp_credential(self) -> CredentialModel:
        """Create and return a temporary credential for RAs.

        Uses RSA-2048 as the default key algorithm.
        """
        public_key_info = PublicKeyInfo(
            public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA,
            key_size=2048
        )

        private_key = KeyPairGenerator.generate_key_pair_for_public_key_info(public_key_info)

        cred_serializer = CredentialSerializer(
            private_key=private_key,
            additional_certificates=[]
        )

        return CredentialModel.save_credential_serializer(
            cred_serializer, CredentialModel.CredentialTypeChoice.ISSUING_CA
        )

    def _get_or_create_tls_truststore(self) -> TruststoreModel:
        """Get or create the TLS truststore for EST/CMP RA connections.

        Returns:
            TruststoreModel: The TLS truststore containing the server certificate.
        """
        tls_cert = None
        if DOCKER_CONTAINER:
            tls_cred = ActiveTrustpointTlsServerCredentialModel.objects.first()
            if tls_cred and tls_cred.credential:
                tls_cert = tls_cred.credential.certificate
                self.log_and_stdout('Using active TLS server credential from Docker.')
            else:
                self.log_and_stdout('No active TLS server credential found in Docker.', level='error')
                raise RuntimeError('No TLS server credential available')
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
                serialization.load_pem_private_key(key_data, password=None)
                tls_cert = CertificateModel.save_certificate(tls_certificate)
                self.log_and_stdout('Loaded TLS certificate from test files.')
            else:
                self.log_and_stdout('TLS certificate files not found.', level='error')
                raise RuntimeError('TLS certificate files not found')

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

        return truststore

    def _create_issuing_ca(self, ca_name: str) -> CaModel:
        """Create a local issuing CA.

        Args:
            ca_name: The unique name for the CA.

        Returns:
            CaModel: The created or existing issuing CA.
        """
        if CaModel.objects.filter(unique_name=ca_name).exists():
            self.log_and_stdout(f'Issuing CA "{ca_name}" already exists.')
            return CaModel.objects.get(unique_name=ca_name)

        rsa_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        rsa_root, _ = self.create_root_ca(
            f'{ca_name} - Root',
            private_key=rsa_root_ca_key,
            hash_algorithm=hashes.SHA256()
        )
        rsa_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=rsa_root_ca_key,
            private_key=rsa_issuing_ca_key,
            issuer_cn=f'{ca_name} - Root',
            subject_cn=ca_name,
            hash_algorithm=hashes.SHA256(),
        )
        issuing_ca = self.save_issuing_ca(
            issuing_ca_cert=rsa_issuing_ca,
            private_key=rsa_issuing_ca_key,
            chain=[rsa_root],
            unique_name=ca_name,
        )
        self.log_and_stdout(f'Created issuing CA "{ca_name}".')
        return issuing_ca

    def _create_domain_with_ca(self, domain_name: str, issuing_ca: CaModel) -> DomainModel:
        """Create or update a domain with an issuing CA.

        Args:
            domain_name: The unique name for the domain.
            issuing_ca: The issuing CA to associate with the domain.

        Returns:
            DomainModel: The created or updated domain.
        """
        domain, created = DomainModel.objects.get_or_create(
            unique_name=domain_name,
            defaults={'issuing_ca': issuing_ca}
        )
        if created:
            self.log_and_stdout(f'Created domain "{domain_name}".')
        else:
            domain.issuing_ca = issuing_ca
            domain.save()
            self.log_and_stdout(f'Updated domain "{domain_name}".')
        return domain

    def _create_device(
        self,
        device_name: str,
        domain: DomainModel,
        pki_protocols: list[NoOnboardingPkiProtocol],
        config_dict: dict[str, str] | None = None
    ) -> DeviceModel:
        """Create a device with specified PKI protocol configuration.

        Args:
            device_name: The common name for the device.
            domain: The domain the device belongs to.
            pki_protocols: List of PKI protocols to enable.
            config_dict: Optional configuration dictionary (e.g., {'est_password': 'foo123'}).

        Returns:
            DeviceModel: The created or existing device.
        """
        if DeviceModel.objects.filter(common_name=device_name).exists():
            self.log_and_stdout(f'Device "{device_name}" already exists.')
            return DeviceModel.objects.get(common_name=device_name)

        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols(pki_protocols)

        if config_dict:
            for key, value in config_dict.items():
                if hasattr(no_onboarding_config, key):
                    setattr(no_onboarding_config, key, value)

        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel(
            common_name=device_name,
            serial_number=device_name.replace(' ', '-').upper(),
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config
        )
        device.full_clean()
        device.save()
        self.log_and_stdout(f'Created device "{device_name}".')
        return device

    def _create_est_ra(
        self,
        ra_name: str,
        domain: DomainModel,
        device: DeviceModel,
        issuing_ca: CaModel,
        issuing_ca_domain: DomainModel,
        issuing_ca_device: DeviceModel,
        tls_truststore: TruststoreModel
    ) -> CaModel:
        """Create a remote EST RA configuration.

        Args:
            ra_name: The unique name for the RA.
            domain: The domain associated with the RA.
            device: The device associated with the RA.
            issuing_ca: The issuing CA whose certificate will be used for this RA.
            issuing_ca_domain: The domain for the issuing CA (used to build the remote path).
            issuing_ca_device: The device for the issuing CA (used for authentication).
            tls_truststore: The truststore for TLS verification.

        Returns:
            CaModel: The created or existing EST RA.
        """
        if CaModel.objects.filter(unique_name=ra_name).exists():
            self.log_and_stdout(f'EST RA "{ra_name}" already exists.')
            ra = CaModel.objects.get(unique_name=ra_name)
            # Ensure domain association and certificate are updated
            domain.issuing_ca = ra
            domain.save()
            issuing_ca_cert = issuing_ca.credential.certificate if issuing_ca.credential else None
            if issuing_ca_cert and ra.certificate != issuing_ca_cert:
                ra.certificate = issuing_ca_cert
                ra.save()
            return ra

        # Get the certificate from the issuing CA
        issuing_ca_cert = issuing_ca.credential.certificate if issuing_ca.credential else None
        if not issuing_ca_cert:
            self.log_and_stdout('Issuing CA certificate not found for EST RA.', level='error')
            raise ValueError('CA certificate required for EST RA')

        # Create a truststore for the remote CA's chain
        ca_chain_truststore, created = TruststoreModel.objects.get_or_create(
            unique_name=f'{ra_name}-ca-chain-truststore',
            defaults={'intended_usage': TruststoreModel.IntendedUsage.TLS}
        )
        
        # Add the issuing CA certificate to the chain truststore
        if created or not ca_chain_truststore.certificates.filter(pk=issuing_ca_cert.pk).exists():
            ca_chain_truststore.certificates.add(issuing_ca_cert, through_defaults={'order': 0})
            self.log_and_stdout(f'Created/updated CA chain truststore for "{ra_name}".')

        # Build the remote EST path pointing to the issuing CA's domain-specific endpoint
        remote_est_path = f'/.well-known/est/{issuing_ca_domain.unique_name}/tls_server/simpleenroll'

        # Get the EST password from the issuing CA device's onboarding config
        est_password = None
        if issuing_ca_device.no_onboarding_config:
            est_password = issuing_ca_device.no_onboarding_config.est_password

        ra = CaModel(
            unique_name=ra_name,
            ca_type=CaModel.CaTypeChoice.REMOTE_EST_RA,
            remote_host='localhost',
            remote_port=443,
            remote_path=remote_est_path,
            est_username=issuing_ca_device.common_name,
            certificate=issuing_ca_cert,
            chain_truststore=ca_chain_truststore,
        )
        # RAs don't need a credential (they're not issuers)
        # but they need onboarding config for EST authentication
        if not ra.onboarding_config and not ra.no_onboarding_config:
            # Create a new onboarding config for the RA that uses the issuing CA device's password
            ra_onboarding_config = NoOnboardingConfigModel()
            ra_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD])
            ra_onboarding_config.est_password = est_password
            ra_onboarding_config.trust_store = tls_truststore
            ra_onboarding_config.full_clean()
            ra_onboarding_config.save()
            ra.no_onboarding_config = ra_onboarding_config

        ra.full_clean()
        ra.save()

        # Associate RA with domain
        domain.issuing_ca = ra
        domain.save()

        self.log_and_stdout(f'Created EST RA "{ra_name}" in domain "{domain.unique_name}".')
        return ra

    def _create_cmp_ra(
        self,
        ra_name: str,
        domain: DomainModel,
        device: DeviceModel,
        ca: CaModel,
        tls_truststore: TruststoreModel
    ) -> CaModel:
        """Create a remote CMP RA configuration.

        Args:
            ra_name: The unique name for the RA.
            domain: The domain associated with the RA.
            device: The device associated with the RA.
            ca: The issuing CA whose certificate will be used for this RA.
            tls_truststore: The truststore for TLS verification.

        Returns:
            CaModel: The created or existing CMP RA.
        """
        if CaModel.objects.filter(unique_name=ra_name).exists():
            self.log_and_stdout(f'CMP RA "{ra_name}" already exists.')
            ra = CaModel.objects.get(unique_name=ra_name)
            # Ensure domain association and certificate are updated
            domain.issuing_ca = ra
            domain.save()
            issuing_ca_cert = ca.credential.certificate if ca.credential else None
            if issuing_ca_cert and ra.certificate != issuing_ca_cert:
                ra.certificate = issuing_ca_cert
                ra.save()
            return ra

        # Create CMP-specific chain truststore for this RA (must be separate from EST truststore)
        tls_cert = None
        if DOCKER_CONTAINER:
            tls_cred = ActiveTrustpointTlsServerCredentialModel.objects.first()
            if tls_cred and tls_cred.credential:
                tls_cert = tls_cred.credential.certificate
        else:
            # Load from test files
            cert_path = Path(__file__).parent.parent.parent.parent.parent / 'tests/data/x509/https_server.crt'
            if cert_path.exists():
                with cert_path.open('rb') as f:
                    cert_data = f.read()
                tls_certificate = x509.load_pem_x509_certificate(cert_data)
                tls_cert = CertificateModel.save_certificate(tls_certificate)

        # Create CMP-specific chain truststore
        cmp_chain_truststore, created = TruststoreModel.objects.get_or_create(
            unique_name=f'{ra_name}-chain-truststore',
            defaults={'intended_usage': TruststoreModel.IntendedUsage.TLS}
        )
        if created:
            if tls_cert:
                cmp_chain_truststore.certificates.add(tls_cert, through_defaults={'order': 0})
            self.log_and_stdout(f'Created CMP chain truststore for "{ra_name}".')
        else:
            if tls_cert and not cmp_chain_truststore.certificates.filter(pk=tls_cert.pk).exists():
                max_order = cmp_chain_truststore.truststoreordermodel_set.aggregate(models.Max('order'))['order__max'] or -1
                cmp_chain_truststore.certificates.add(tls_cert, through_defaults={'order': max_order + 1})
                self.log_and_stdout(f'Updated CMP chain truststore for "{ra_name}".')

        # Create CMP-specific onboarding truststore with the CA certificate
        ca_cert = ca.credential.certificate if ca.credential else None
        if not ca_cert:
            self.log_and_stdout('Issuing CA certificate not found for CMP truststore.', level='error')
            raise ValueError('CA certificate required for CMP RA')

        cmp_onboarding_truststore, created = TruststoreModel.objects.get_or_create(
            unique_name=f'{ra_name}-onboarding-truststore',
            defaults={'intended_usage': TruststoreModel.IntendedUsage.TLS}
        )
        if created:
            cmp_onboarding_truststore.certificates.add(ca_cert, through_defaults={'order': 0})
            self.log_and_stdout(f'Created CMP onboarding truststore for "{ra_name}".')
        else:
            if not cmp_onboarding_truststore.certificates.filter(pk=ca_cert.pk).exists():
                max_order = cmp_onboarding_truststore.truststoreordermodel_set.aggregate(models.Max('order'))['order__max'] or -1
                cmp_onboarding_truststore.certificates.add(ca_cert, through_defaults={'order': max_order + 1})
                self.log_and_stdout(f'Updated CMP onboarding truststore for "{ra_name}".')

        device.no_onboarding_config.trust_store = cmp_onboarding_truststore
        device.no_onboarding_config.save()

        ra = CaModel(
            unique_name=ra_name,
            ca_type=CaModel.CaTypeChoice.REMOTE_CMP_RA,
            remote_host='localhost',
            remote_port=443,
            remote_path='/.well-known/cmp/p/ra/certification',
            certificate=ca_cert,
            chain_truststore=cmp_chain_truststore,
        )
        if not ra.onboarding_config and not ra.no_onboarding_config:
            ra.no_onboarding_config = device.no_onboarding_config

        ra.full_clean()
        ra.save()

        # Associate RA with domain
        domain.issuing_ca = ra
        domain.save()

        self.log_and_stdout(f'Created CMP RA "{ra_name}" in domain "{domain.unique_name}".')
        return ra

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Creates the complete RA setup."""
        # Load certificate profiles
        call_command('create_default_cert_profiles')

        # Enable the domain_credential profile
        try:
            domain_cred_profile = CertificateProfileModel.objects.get(unique_name='domain_credential')
            domain_cred_profile.is_default = True
            domain_cred_profile.save()
            self.log_and_stdout('Enabled domain_credential certificate profile.')
        except CertificateProfileModel.DoesNotExist:
            self.log_and_stdout('domain_credential certificate profile not found.', level='warning')

        # Get or create TLS truststore
        tls_truststore = self._get_or_create_tls_truststore()

        # ===== EST Setup =====
        self.log_and_stdout('\n=== Creating EST Issuing CA & RA Setup ===')

        # Create EST issuing CA
        est_ca = self._create_issuing_ca('EST-Issuing-CA')

        # Create EST issuing CA domain
        est_ca_domain = self._create_domain_with_ca('est_issuing_ca', est_ca)

        # Create EST issuing CA device
        est_ca_device = self._create_device(
            device_name='EST-Issuing-CA-Device',
            domain=est_ca_domain,
            pki_protocols=[NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD],
            config_dict={'est_password': 'est_ca_password123', 'trust_store': tls_truststore}
        )
        est_ca_device.no_onboarding_config.trust_store = tls_truststore
        est_ca_device.no_onboarding_config.save()

        # Create EST RA domain (separate from CA domain)
        est_ra_domain = self._create_domain_with_ca('est_ra', est_ca)

        # Create EST RA device (separate from CA device)
        est_ra_device = self._create_device(
            device_name='EST-RA-Device',
            domain=est_ra_domain,
            pki_protocols=[NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD],
            config_dict={'est_password': 'est_ra_password123', 'trust_store': tls_truststore}
        )
        est_ra_device.no_onboarding_config.trust_store = tls_truststore
        est_ra_device.no_onboarding_config.save()

        # Create EST RA (points back to this instance as a Registration Authority)
        self._create_est_ra(
            ra_name='EST-RA',
            domain=est_ra_domain,
            device=est_ra_device,
            issuing_ca=est_ca,
            issuing_ca_domain=est_ca_domain,
            issuing_ca_device=est_ca_device,
            tls_truststore=tls_truststore
        )

        # ===== CMP Setup =====
        self.log_and_stdout('\n=== Creating CMP Issuing CA & RA Setup ===')

        # Create CMP issuing CA
        cmp_ca = self._create_issuing_ca('CMP-Issuing-CA')

        # Create CMP issuing CA domain
        cmp_ca_domain = self._create_domain_with_ca('cmp_issuing_ca', cmp_ca)

        # Create CMP issuing CA device
        self._create_device(
            device_name='CMP-Issuing-CA-Device',
            domain=cmp_ca_domain,
            pki_protocols=[NoOnboardingPkiProtocol.CMP_SHARED_SECRET],
            config_dict={'cmp_shared_secret': 'cmp_ca_secret123'}
        )

        # Create CMP RA domain (separate from CA domain)
        cmp_ra_domain = self._create_domain_with_ca('cmp_ra', cmp_ca)

        # Create CMP RA device (separate from CA device)
        cmp_ra_device = self._create_device(
            device_name='CMP-RA-Device',
            domain=cmp_ra_domain,
            pki_protocols=[NoOnboardingPkiProtocol.CMP_SHARED_SECRET],
            config_dict={'cmp_shared_secret': 'cmp_ra_secret123'}
        )

        # Create CMP RA
        self._create_cmp_ra(
            ra_name='CMP-RA',
            domain=cmp_ra_domain,
            device=cmp_ra_device,
            ca=cmp_ca,
            tls_truststore=tls_truststore
        )

        self.log_and_stdout('\n=== RA Setup Complete ===')
        self.log_and_stdout('EST Issuing CA: est_issuing_ca domain with EST-Issuing-CA-Device')
        self.log_and_stdout('EST RA: est_ra domain with EST-RA-Device, configured at: /.well-known/est/simpleenroll')
        self.log_and_stdout('CMP Issuing CA: cmp_issuing_ca domain with CMP-Issuing-CA-Device')
        self.log_and_stdout('CMP RA: cmp_ra domain with CMP-RA-Device, configured at: /.well-known/cmp/p/ra/certification')

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Log a message and write it to stdout.

        Args:
            message: The message to log.
            level: The logging level ('info', 'warning', 'error').
        """
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
