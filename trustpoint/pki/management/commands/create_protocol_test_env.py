# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Sets up a Trustpoint test environment for CMP / EST / REST enrollment endpoint testing.

Creates a single issuing CA and domain plus six devices, one for each combination of
onboarding mode and PKI protocol:

============================  ================  ==============================
Device                        Onboarding        Application certificate via
============================  ================  ==============================
``est-onboarding-device``     EST user/pass     EST (domain credential / mTLS)
``cmp-onboarding-device``     CMP shared sec.   CMP (domain credential / mTLS)
``rest-onboarding-device``    REST user/pass    REST (domain credential / mTLS)
``est-no-onboarding-device``  none              EST username & password
``cmp-no-onboarding-device``  none              CMP shared secret
``rest-no-onboarding-device`` none              REST username & password
============================  ================  ==============================

The credentials are written as JSON to the path given by ``--output`` so that shell based
integration tests can consume them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from django.core.management import call_command
from django.core.management.base import BaseCommand

from devices.models import DeviceModel
from onboarding.models import (
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)
from pki.management.commands.base_commands import CertificateCreationCommandMixin
from pki.models import CaModel, DomainModel
from pki.util.x509 import CertificateGenerator
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from argparse import ArgumentParser
    from typing import Any

CA_UNIQUE_NAME = 'protocol-test-ca'
DOMAIN_UNIQUE_NAME = 'protocoltest'

EST_PASSWORD = 'protocoltest-est-secret'  # noqa: S105
CMP_SHARED_SECRET = 'protocoltest-cmp-secret'  # noqa: S105

ONBOARDING_DEVICES = {
    'est-onboarding-device': (OnboardingProtocol.EST_USERNAME_PASSWORD, OnboardingPkiProtocol.EST),
    'cmp-onboarding-device': (OnboardingProtocol.CMP_SHARED_SECRET, OnboardingPkiProtocol.CMP),
    'rest-onboarding-device': (OnboardingProtocol.REST_USERNAME_PASSWORD, OnboardingPkiProtocol.REST),
}

NO_ONBOARDING_DEVICES = {
    'est-no-onboarding-device': NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
    'cmp-no-onboarding-device': NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
    'rest-no-onboarding-device': NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD,
}


class Command(CertificateCreationCommandMixin, LoggerMixin, BaseCommand):
    """Creates a Trustpoint test environment for CMP / EST / REST endpoint testing."""

    help = 'Creates an issuing CA, a domain and devices for CMP / EST / REST endpoint testing.'

    def add_arguments(self, parser: ArgumentParser) -> None:
        """Adds the command line arguments.

        Args:
            parser: The argument parser to add the arguments to.
        """
        parser.add_argument(
            '--output',
            type=Path,
            default=None,
            help='Path the JSON description of the created test environment is written to.',
        )

    def handle(self, *_args: Any, **options: Any) -> None:
        """Executes the command.

        Args:
            _args: Additional positional arguments (unused).
            options: The parsed command line arguments.
        """
        call_command('create_default_cert_profiles')

        issuing_ca = self._get_or_create_issuing_ca()
        domain = self._get_or_create_domain(issuing_ca)

        environment: dict[str, Any] = {
            'ca': CA_UNIQUE_NAME,
            'domain': DOMAIN_UNIQUE_NAME,
            'domain_credential_profile': domain.get_domain_credential_profile_name(),
            'devices': {},
        }

        for common_name, (onboarding_protocol, pki_protocol) in ONBOARDING_DEVICES.items():
            device = self._get_or_create_onboarding_device(domain, common_name, onboarding_protocol, pki_protocol)
            environment['devices'][common_name] = {
                'pk': device.pk,
                'onboarding': True,
                'est_password': EST_PASSWORD,
                'cmp_shared_secret': CMP_SHARED_SECRET,
            }

        for common_name, no_onboarding_pki_protocol in NO_ONBOARDING_DEVICES.items():
            device = self._get_or_create_no_onboarding_device(domain, common_name, no_onboarding_pki_protocol)
            environment['devices'][common_name] = {
                'pk': device.pk,
                'onboarding': False,
                'est_password': EST_PASSWORD,
                'cmp_shared_secret': CMP_SHARED_SECRET,
            }

        output: Path | None = options.get('output')
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(environment, indent=2), encoding='utf-8')
            self.stdout.write(f'Wrote test environment description to {output}')

        self.stdout.write(json.dumps(environment, indent=2))

    def _get_or_create_issuing_ca(self) -> CaModel:
        """Returns the existing test CA or creates a fresh RSA-2048 root and issuing CA.

        Returns:
            The issuing CA model instance.
        """
        existing = CaModel.objects.filter(unique_name=CA_UNIQUE_NAME).first()
        if existing:
            self.stdout.write(f'Issuing CA "{CA_UNIQUE_NAME}" already exists.')
            return existing

        root_key = self.create_backend_rsa_private_key(alias=f'{CA_UNIQUE_NAME}-root', key_size=2048)
        issuing_key = self.create_backend_rsa_private_key(alias=CA_UNIQUE_NAME, key_size=2048)

        root_cert, _ = self.create_root_ca(
            f'{CA_UNIQUE_NAME}-root',
            private_key=root_key,
            hash_algorithm=hashes.SHA256(),
        )
        issuing_cert, _ = self.create_issuing_ca(
            issuer_private_key=root_key,
            private_key=issuing_key,
            issuer_cn=f'{CA_UNIQUE_NAME}-root',
            subject_cn=CA_UNIQUE_NAME,
            hash_algorithm=hashes.SHA256(),
        )
        issuing_ca = CertificateGenerator.save_issuing_ca(
            issuing_ca_cert=issuing_cert,
            chain=[root_cert],
            private_key=issuing_key,
            unique_name=CA_UNIQUE_NAME,
        )
        self.stdout.write(f'Created issuing CA "{CA_UNIQUE_NAME}".')
        return issuing_ca

    def _get_or_create_domain(self, issuing_ca: CaModel) -> DomainModel:
        """Returns the existing test domain or creates it, linked to the given issuing CA.

        Args:
            issuing_ca: The issuing CA to associate with the domain.

        Returns:
            The domain model instance.
        """
        domain, created = DomainModel.objects.get_or_create(
            unique_name=DOMAIN_UNIQUE_NAME,
            defaults={'issuing_ca': issuing_ca},
        )
        if not created:
            domain.issuing_ca = issuing_ca
            domain.save()
        self.stdout.write(f'{"Created" if created else "Updated"} domain "{DOMAIN_UNIQUE_NAME}".')
        return domain

    def _get_or_create_onboarding_device(
        self,
        domain: DomainModel,
        common_name: str,
        onboarding_protocol: OnboardingProtocol,
        pki_protocol: OnboardingPkiProtocol,
    ) -> DeviceModel:
        """Returns the existing device or creates one requiring onboarding.

        Args:
            domain: The domain to place the device in.
            common_name: The common name of the device.
            onboarding_protocol: The onboarding protocol the device uses.
            pki_protocol: The PKI protocol allowed for application certificates.

        Returns:
            The device model instance.
        """
        existing = DeviceModel.objects.filter(common_name=common_name).first()
        if existing:
            self.stdout.write(f'Device "{common_name}" already exists.')
            return existing

        onboarding_config = OnboardingConfigModel(
            onboarding_status=OnboardingStatus.PENDING,
            onboarding_protocol=onboarding_protocol,
        )
        onboarding_config.set_pki_protocols([pki_protocol])

        if onboarding_protocol == OnboardingProtocol.CMP_SHARED_SECRET:
            onboarding_config.cmp_shared_secret = CMP_SHARED_SECRET
        else:
            onboarding_config.est_password = EST_PASSWORD

        onboarding_config.save()

        device = DeviceModel(
            common_name=common_name,
            serial_number=common_name.upper(),
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            onboarding_config=onboarding_config,
        )
        device.save()
        self.stdout.write(f'Created device "{common_name}" (onboarding).')
        return device

    def _get_or_create_no_onboarding_device(
        self, domain: DomainModel, common_name: str, pki_protocol: NoOnboardingPkiProtocol
    ) -> DeviceModel:
        """Returns the existing device or creates one that does not require onboarding.

        Args:
            domain: The domain to place the device in.
            common_name: The common name of the device.
            pki_protocol: The PKI protocol allowed for application certificates.

        Returns:
            The device model instance.
        """
        existing = DeviceModel.objects.filter(common_name=common_name).first()
        if existing:
            self.stdout.write(f'Device "{common_name}" already exists.')
            return existing

        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([pki_protocol])

        if pki_protocol == NoOnboardingPkiProtocol.CMP_SHARED_SECRET:
            no_onboarding_config.cmp_shared_secret = CMP_SHARED_SECRET
        else:
            no_onboarding_config.est_password = EST_PASSWORD

        no_onboarding_config.save()

        device = DeviceModel(
            common_name=common_name,
            serial_number=common_name.upper(),
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )
        device.save()
        self.stdout.write(f'Created device "{common_name}" (no onboarding).')
        return device
