# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

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

from django.core.management import call_command
from django.core.management.base import BaseCommand

from aoki.management.setup_helpers import EstTestEnvironmentMixin
from devices.models import DeviceModel
from onboarding.models import (
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)
from pki.models.credential import OwnerCredentialModel

if TYPE_CHECKING:
    from typing import Any

    from pki.models import DomainModel
    from pki.models.truststore import TruststoreModel

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
    f'/.well-known/est/{DOMAIN_UNIQUE_NAME}/domain_credential/simpleenroll'
)
KEY_TYPE = 'RSA-2048'

# ruff: noqa: S105  # test password is intentional


class Command(EstTestEnvironmentMixin, BaseCommand):
    """Creates a Trustpoint test environment for DevOwnerID EST onboarding testing."""

    help = (
        'Creates a local issuing CA, domain, and device for DevOwnerID EST onboarding testing. '
        'The device requires onboarding (domain credential) before DevOwnerID enrollment.'
    )

    ca_unique_name = CA_UNIQUE_NAME
    domain_unique_name = DOMAIN_UNIQUE_NAME
    truststore_unique_name = TRUSTSTORE_UNIQUE_NAME
    https_server_cert_path = HTTPS_SERVER_CERT_PATH

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
