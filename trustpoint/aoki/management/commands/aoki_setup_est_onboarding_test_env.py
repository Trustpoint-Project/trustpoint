"""Sets up a Trustpoint test environment for DevOwnerID EST onboarding enrollment testing.

This command creates an environment where the device first needs onboarding (obtaining a
Domain Credential) before a DevOwnerID can be issued.  It creates:

- A local issuing CA called ``DevOwnerIDOnboardingCA`` (root + intermediate, RSA-2048).
- A domain ``DevOwnerIDOnboardingDomain`` associated with that CA.
- A device ``DevOwnerIDOnboardingDevice`` in that domain, configured for EST
  username/password **onboarding** with password ``devownerid-onboarding123``.
- A TLS truststore ``DevOwnerIDOnboardingTLSTruststore`` containing the Trustpoint HTTPS
  server cert.
- An ``OwnerCredentialModel`` (``DevOwnerIDOnboardingOwnerCred``) of type
  ``REMOTE_EST_ONBOARDING``, configured for remote EST enrollment via localhost:443
  with two paths:

  - **Domain Credential path**:
    ``/.well-known/est/DevOwnerIDOnboardingDomain/devownerid_domain_credential/simpleenroll``
  - **DevOwnerID path**:
    ``/.well-known/est/DevOwnerIDOnboardingDomain/dev_owner_id/simpleenroll``

  Key type RSA-2048, linked to the TLS truststore above via the ``OnboardingConfigModel``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.management import call_command
from django.core.management.base import BaseCommand

from devices.models import DeviceModel
from onboarding.models import (
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)
from pki.management.commands.base_commands import CertificateCreationCommandMixin
from pki.models import CaModel, CertificateModel, DomainModel
from pki.models.credential import OwnerCredentialModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel
from pki.util.x509 import CertificateGenerator
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from typing import Any

CA_UNIQUE_NAME = 'DevOwnerIDOnboardingCA'
DOMAIN_UNIQUE_NAME = 'DevOwnerIDOnboardingDomain'
DEVICE_COMMON_NAME = 'DevOwnerIDOnboardingDevice'
DEVICE_SERIAL_NUMBER = 'DEVOWNERID-ONBOARDING-001'
EST_PASSWORD = 'devownerid-onboarding123'

OWNER_CRED_UNIQUE_NAME = 'DevOwnerIDOnboardingOwnerCred'
TRUSTSTORE_UNIQUE_NAME = 'DevOwnerIDOnboardingTLSTruststore'
HTTPS_SERVER_CERT_PATH = (
    Path(__file__).resolve().parents[4] / 'tests' / 'data' / 'x509' / 'https_server.crt'
)

REMOTE_HOST = 'localhost'
REMOTE_PORT = 443
REMOTE_PATH_DEV_OWNER_ID = f'/.well-known/est/{DOMAIN_UNIQUE_NAME}/dev_owner_id/simpleenroll'
REMOTE_PATH_DOMAIN_CREDENTIAL = (
    f'/.well-known/est/{DOMAIN_UNIQUE_NAME}/devownerid_domain_credential/simpleenroll'
)
KEY_TYPE = 'RSA-2048'

# ruff: noqa: T201, S105  # use of print is fine in management commands; test password is intentional


class Command(CertificateCreationCommandMixin, LoggerMixin, BaseCommand):
    """Creates a Trustpoint test environment for DevOwnerID EST onboarding testing."""

    help = (
        'Creates a local issuing CA, domain, and device for DevOwnerID EST onboarding testing. '
        'The device requires onboarding (domain credential) before DevOwnerID enrollment.'
    )

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Log a message and print it to stdout.

        :param message: The message to log and print.
        :param level: The log level (``'info'``, ``'warning'``, or ``'error'``).
        """
        print(message)
        if level == 'warning':
            self.logger.warning(message)
        elif level == 'error':
            self.logger.error(message)
        else:
            self.logger.info(message)

    def handle(self, *args: Any, **kwargs: Any) -> None:
        """Execute the command.

        :param args: Additional positional arguments (unused).
        :param kwargs: Additional keyword arguments (unused).
        """
        del args, kwargs  # Unused

        # Ensure certificate profiles exist before creating any domain / device.
        call_command('create_default_cert_profiles')

        issuing_ca = self._get_or_create_issuing_ca()
        domain = self._get_or_create_domain(issuing_ca)
        self._get_or_create_device(domain)
        truststore = self._get_or_create_tls_truststore()
        self._get_or_create_owner_credential(truststore)

        self.log_and_stdout('\n=== AOKI EST onboarding test environment ready ===')
        self.log_and_stdout(f'  CA:                    {CA_UNIQUE_NAME}')
        self.log_and_stdout(f'  Domain:                {DOMAIN_UNIQUE_NAME}')
        self.log_and_stdout(f'  Device:                {DEVICE_COMMON_NAME}  (EST password: [redacted])')
        self.log_and_stdout(f'  Truststore:            {TRUSTSTORE_UNIQUE_NAME}')
        self.log_and_stdout(f'  OwnerCred:             {OWNER_CRED_UNIQUE_NAME}')
        self.log_and_stdout(f'    host:                {REMOTE_HOST}:{REMOTE_PORT}')
        self.log_and_stdout(f'    path (DevOwnerID):   {REMOTE_PATH_DEV_OWNER_ID}')
        self.log_and_stdout(f'    path (DomainCred):   {REMOTE_PATH_DOMAIN_CREDENTIAL}')
        self.log_and_stdout(f'    key type:            {KEY_TYPE}')
        self.log_and_stdout(f'    username:            {DEVICE_COMMON_NAME}')
        self.log_and_stdout('    password:            [redacted]')

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_or_create_issuing_ca(self) -> CaModel:
        """Return an existing CA or create a fresh RSA-2048 root + intermediate CA.

        :returns: The :class:`~pki.models.CaModel` for ``DevOwnerIDOnboardingCA``.
        """
        if CaModel.objects.filter(unique_name=CA_UNIQUE_NAME).exists():
            self.log_and_stdout(f'Issuing CA "{CA_UNIQUE_NAME}" already exists, skipping creation.')
            return CaModel.objects.get(unique_name=CA_UNIQUE_NAME)

        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        root_cert, _ = self.create_root_ca(
            f'{CA_UNIQUE_NAME} - Root',
            private_key=root_key,
            hash_algorithm=hashes.SHA256(),
        )
        issuing_cert, _ = self.create_issuing_ca(
            issuer_private_key=root_key,
            private_key=issuing_key,
            issuer_cn=f'{CA_UNIQUE_NAME} - Root',
            subject_cn=CA_UNIQUE_NAME,
            hash_algorithm=hashes.SHA256(),
        )
        issuing_ca = CertificateGenerator.save_issuing_ca(
            issuing_ca_cert=issuing_cert,
            chain=[root_cert],
            private_key=issuing_key,
            unique_name=CA_UNIQUE_NAME,
        )
        self.log_and_stdout(f'Created issuing CA "{CA_UNIQUE_NAME}".')
        return issuing_ca

    def _get_or_create_domain(self, issuing_ca: CaModel) -> DomainModel:
        """Return an existing domain or create ``DevOwnerIDOnboardingDomain`` linked to *issuing_ca*.

        :param issuing_ca: The issuing CA to associate with the domain.
        :returns: The :class:`~pki.models.DomainModel` for ``DevOwnerIDOnboardingDomain``.
        """
        domain, created = DomainModel.objects.get_or_create(
            unique_name=DOMAIN_UNIQUE_NAME,
            defaults={'issuing_ca': issuing_ca},
        )
        if created:
            self.log_and_stdout(f'Created domain "{DOMAIN_UNIQUE_NAME}".')
        else:
            domain.issuing_ca = issuing_ca
            domain.save()
            self.log_and_stdout(f'Domain "{DOMAIN_UNIQUE_NAME}" already exists, updated issuing CA.')
        return domain

    def _get_or_create_device(self, domain: DomainModel) -> DeviceModel:
        """Return an existing device or create ``DevOwnerIDOnboardingDevice`` in *domain*.

        The device is configured for EST username/password **onboarding** with
        password ``devownerid-onboarding123``.  Unlike the no-onboarding variant
        the device uses an ``OnboardingConfigModel`` with
        ``OnboardingProtocol.EST_USERNAME_PASSWORD``.

        :param domain: The domain to place the device in.
        :returns: The :class:`~devices.models.DeviceModel` for ``DevOwnerIDOnboardingDevice``.
        """
        if DeviceModel.objects.filter(common_name=DEVICE_COMMON_NAME).exists():
            self.log_and_stdout(f'Device "{DEVICE_COMMON_NAME}" already exists, skipping creation.')
            return DeviceModel.objects.get(common_name=DEVICE_COMMON_NAME)

        onboarding_config = OnboardingConfigModel(
            onboarding_status=OnboardingStatus.PENDING,
            onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD,
            est_password=EST_PASSWORD,
        )
        onboarding_config.set_pki_protocols([OnboardingPkiProtocol.EST])
        onboarding_config.full_clean()
        onboarding_config.save()

        device = DeviceModel(
            common_name=DEVICE_COMMON_NAME,
            serial_number=DEVICE_SERIAL_NUMBER,
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            onboarding_config=onboarding_config,
        )
        device.full_clean()
        device.save()
        self.log_and_stdout(f'Created device "{DEVICE_COMMON_NAME}" (onboarding: EST username/password).')
        return device

    def _get_or_create_tls_truststore(self) -> TruststoreModel:
        """Return an existing TLS truststore or create one from the Trustpoint HTTPS server cert.

        The certificate at ``HTTPS_SERVER_CERT_PATH`` is imported into the database and
        added to a :class:`~pki.models.truststore.TruststoreModel` with intended usage
        ``TLS``.

        :returns: The :class:`~pki.models.truststore.TruststoreModel` for
            ``DevOwnerIDOnboardingTLSTruststore``.
        :raises FileNotFoundError: If the HTTPS server certificate file does not exist.
        """
        if TruststoreModel.objects.filter(unique_name=TRUSTSTORE_UNIQUE_NAME).exists():
            self.log_and_stdout(f'Truststore "{TRUSTSTORE_UNIQUE_NAME}" already exists, skipping creation.')
            return TruststoreModel.objects.get(unique_name=TRUSTSTORE_UNIQUE_NAME)

        if not HTTPS_SERVER_CERT_PATH.exists():
            msg = f'HTTPS server certificate not found at {HTTPS_SERVER_CERT_PATH}'
            raise FileNotFoundError(msg)

        pem_data = HTTPS_SERVER_CERT_PATH.read_bytes()
        crypto_cert = x509.load_pem_x509_certificate(pem_data)
        cert_model = CertificateModel.save_certificate(crypto_cert)

        truststore = TruststoreModel(
            unique_name=TRUSTSTORE_UNIQUE_NAME,
            intended_usage=TruststoreModel.IntendedUsage.TLS,
        )
        truststore.save()
        TruststoreOrderModel.objects.create(
            trust_store=truststore,
            certificate=cert_model,
            order=0,
        )
        self.log_and_stdout(f'Created TLS truststore "{TRUSTSTORE_UNIQUE_NAME}".')
        return truststore

    def _get_or_create_owner_credential(self, truststore: TruststoreModel) -> OwnerCredentialModel:
        """Return an existing OwnerCredential or create one configured for EST onboarding enrollment.

        The credential is configured as ``REMOTE_EST_ONBOARDING`` and enroll via::

            Domain Credential: https://localhost:443/.well-known/est/<Domain>/devownerid_domain_credential/simpleenroll
            DevOwnerID:        https://localhost:443/.well-known/est/<Domain>/dev_owner_id/simpleenroll

        using EST username/password (username = device common name, password = EST password)
        and RSA-2048 key pairs.  The provided *truststore* is associated with the
        ``OnboardingConfigModel`` to verify the TLS connection to the remote EST server.

        :param truststore: The TLS truststore to use for verifying the EST server.
        :returns: The :class:`~pki.models.credential.OwnerCredentialModel` for
            ``DevOwnerIDOnboardingOwnerCred``.
        """
        if OwnerCredentialModel.objects.filter(unique_name=OWNER_CRED_UNIQUE_NAME).exists():
            self.log_and_stdout(
                f'OwnerCredential "{OWNER_CRED_UNIQUE_NAME}" already exists, skipping creation.'
            )
            return OwnerCredentialModel.objects.get(unique_name=OWNER_CRED_UNIQUE_NAME)

        onboarding_config = OnboardingConfigModel(
            onboarding_status=OnboardingStatus.PENDING,
            onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD,
            est_password=EST_PASSWORD,
            trust_store=truststore,
        )
        onboarding_config.set_pki_protocols([OnboardingPkiProtocol.EST])
        onboarding_config.full_clean()
        onboarding_config.save()

        owner_cred = OwnerCredentialModel(
            unique_name=OWNER_CRED_UNIQUE_NAME,
            owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST_ONBOARDING,
            remote_host=REMOTE_HOST,
            remote_port=REMOTE_PORT,
            remote_path=REMOTE_PATH_DEV_OWNER_ID,
            remote_path_domain_credential=REMOTE_PATH_DOMAIN_CREDENTIAL,
            est_username=DEVICE_COMMON_NAME,
            key_type=KEY_TYPE,
            onboarding_config=onboarding_config,
        )
        owner_cred.full_clean()
        owner_cred.save()
        self.log_and_stdout(f'Created OwnerCredential "{OWNER_CRED_UNIQUE_NAME}" (onboarding).')
        return owner_cred
