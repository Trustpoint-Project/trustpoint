# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Sets up a Trustpoint test environment for CMP / EST / REST enrollment endpoint testing.

Trustpoint requires the end entity key to match the signature suite of the issuing CA, so
each protocol gets its own issuing CA and domain with a different signature algorithm:

========  ==========  ==========================  =========================
Protocol  Algorithm   Issuing CA                  Domain
========  ==========  ==========================  =========================
EST       EC P-256    ``protocol-test-ca-ec``     ``protocoltest-est``
CMP       ML-DSA-65   ``protocol-test-ca-mldsa``  ``protocoltest-cmp``
REST      RSA-2048    ``protocol-test-ca-rsa``    ``protocoltest-rest``
========  ==========  ==========================  =========================

Every domain contains two devices, one that requires onboarding and one that does not.
The credentials are written as JSON to the path given by ``--output`` so that shell based
integration tests can consume them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from django.core.management import call_command
from django.core.management.base import BaseCommand

from crypto.application.private_keys import (
    ManagedECPrivateKey,
    ManagedMLDSAPrivateKey,
    ManagedRSAPrivateKey,
)
from crypto.domain.algorithms import EllipticCurveName
from crypto.domain.specs import MlDsaVariant
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

type ManagedCaPrivateKey = ManagedRSAPrivateKey | ManagedECPrivateKey | ManagedMLDSAPrivateKey

EST_PASSWORD = 'protocoltest-est-secret'  # noqa: S105
CMP_SHARED_SECRET = 'protocoltest-cmp-secret'  # noqa: S105

RSA_KEY_SIZE = 2048
EC_CURVE = EllipticCurveName.SECP256R1
MLDSA_VARIANT = MlDsaVariant.MLDSA65


@dataclass(frozen=True)
class ProtocolSetup:
    """Describes the CA, domain and devices used to test a single enrollment protocol."""

    protocol: str
    key_algorithm: str
    ca_unique_name: str
    domain_unique_name: str
    onboarding_device: str
    onboarding_protocol: OnboardingProtocol
    onboarding_pki_protocol: OnboardingPkiProtocol
    no_onboarding_device: str
    no_onboarding_pki_protocol: NoOnboardingPkiProtocol


PROTOCOL_SETUPS = (
    ProtocolSetup(
        protocol='est',
        key_algorithm='ec',
        ca_unique_name='protocol-test-ca-ec',
        domain_unique_name='protocoltest-est',
        onboarding_device='est-onboarding-device',
        onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD,
        onboarding_pki_protocol=OnboardingPkiProtocol.EST,
        no_onboarding_device='est-no-onboarding-device',
        no_onboarding_pki_protocol=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
    ),
    ProtocolSetup(
        protocol='cmp',
        key_algorithm='mldsa',
        ca_unique_name='protocol-test-ca-mldsa',
        domain_unique_name='protocoltest-cmp',
        onboarding_device='cmp-onboarding-device',
        onboarding_protocol=OnboardingProtocol.CMP_SHARED_SECRET,
        onboarding_pki_protocol=OnboardingPkiProtocol.CMP,
        no_onboarding_device='cmp-no-onboarding-device',
        no_onboarding_pki_protocol=NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
    ),
    ProtocolSetup(
        protocol='rest',
        key_algorithm='rsa',
        ca_unique_name='protocol-test-ca-rsa',
        domain_unique_name='protocoltest-rest',
        onboarding_device='rest-onboarding-device',
        onboarding_protocol=OnboardingProtocol.REST_USERNAME_PASSWORD,
        onboarding_pki_protocol=OnboardingPkiProtocol.REST,
        no_onboarding_device='rest-no-onboarding-device',
        no_onboarding_pki_protocol=NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD,
    ),
)


class Command(CertificateCreationCommandMixin, LoggerMixin, BaseCommand):
    """Creates a Trustpoint test environment for CMP / EST / REST endpoint testing."""

    help = 'Creates issuing CAs, domains and devices for CMP / EST / REST endpoint testing.'

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

        environment: dict[str, Any] = {'protocols': {}}

        for setup in PROTOCOL_SETUPS:
            issuing_ca = self._get_or_create_issuing_ca(setup)
            domain = self._get_or_create_domain(setup, issuing_ca)

            onboarding_device = self._get_or_create_onboarding_device(setup, domain)
            no_onboarding_device = self._get_or_create_no_onboarding_device(setup, domain)

            environment['protocols'][setup.protocol] = {
                'ca': setup.ca_unique_name,
                'domain': setup.domain_unique_name,
                'domain_credential_profile': domain.get_domain_credential_profile_name(),
                'key_algorithm': setup.key_algorithm,
                'devices': {
                    setup.onboarding_device: {
                        'pk': onboarding_device.pk,
                        'onboarding': True,
                        'est_password': EST_PASSWORD,
                        'cmp_shared_secret': CMP_SHARED_SECRET,
                    },
                    setup.no_onboarding_device: {
                        'pk': no_onboarding_device.pk,
                        'onboarding': False,
                        'est_password': EST_PASSWORD,
                        'cmp_shared_secret': CMP_SHARED_SECRET,
                    },
                },
            }

        output: Path | None = options.get('output')
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(environment, indent=2), encoding='utf-8')
            self.stdout.write(f'Wrote test environment description to {output}')

        self.stdout.write(json.dumps(environment, indent=2))

    def _create_ca_key(self, setup: ProtocolSetup, alias: str) -> ManagedCaPrivateKey:
        """Generates a CA signing key matching the signature algorithm of the given setup.

        Args:
            setup: The protocol setup describing the desired algorithm.
            alias: The backend key alias.

        Returns:
            The generated managed private key.
        """
        if setup.key_algorithm == 'rsa':
            return self.create_backend_rsa_private_key(alias=alias, key_size=RSA_KEY_SIZE)
        if setup.key_algorithm == 'ec':
            return self.create_backend_ec_private_key(alias=alias, curve=EC_CURVE)
        if setup.key_algorithm == 'mldsa':
            return self.create_backend_mldsa_private_key(alias=alias, variant=MLDSA_VARIANT)
        msg = f'Unsupported key algorithm {setup.key_algorithm!r}.'
        raise ValueError(msg)

    def _get_or_create_issuing_ca(self, setup: ProtocolSetup) -> CaModel:
        """Returns the existing test CA or creates a root and issuing CA for the given setup.

        Args:
            setup: The protocol setup describing the CA to create.

        Returns:
            The issuing CA model instance.
        """
        existing = CaModel.objects.filter(unique_name=setup.ca_unique_name).first()
        if existing:
            self.stdout.write(f'Issuing CA "{setup.ca_unique_name}" already exists.')
            return existing

        root_key = self._create_ca_key(setup, f'{setup.ca_unique_name}-root')
        issuing_key = self._create_ca_key(setup, setup.ca_unique_name)

        root_cert, _ = self.create_root_ca(f'{setup.ca_unique_name}-root', private_key=root_key)
        issuing_cert, _ = self.create_issuing_ca(
            issuer_private_key=root_key,
            private_key=issuing_key,
            issuer_cn=f'{setup.ca_unique_name}-root',
            subject_cn=setup.ca_unique_name,
        )
        issuing_ca = CertificateGenerator.save_issuing_ca(
            issuing_ca_cert=issuing_cert,
            chain=[root_cert],
            private_key=issuing_key,
            unique_name=setup.ca_unique_name,
        )
        self.stdout.write(f'Created issuing CA "{setup.ca_unique_name}" ({setup.key_algorithm}).')
        return issuing_ca

    def _get_or_create_domain(self, setup: ProtocolSetup, issuing_ca: CaModel) -> DomainModel:
        """Returns the existing domain or creates it, linked to the given issuing CA.

        Args:
            setup: The protocol setup describing the domain to create.
            issuing_ca: The issuing CA to associate with the domain.

        Returns:
            The domain model instance.
        """
        domain, created = DomainModel.objects.get_or_create(
            unique_name=setup.domain_unique_name,
            defaults={'issuing_ca': issuing_ca},
        )
        if not created:
            domain.issuing_ca = issuing_ca
            domain.save()
        self.stdout.write(f'{"Created" if created else "Updated"} domain "{setup.domain_unique_name}".')
        return domain

    def _get_or_create_onboarding_device(self, setup: ProtocolSetup, domain: DomainModel) -> DeviceModel:
        """Returns the existing device or creates one requiring onboarding.

        Args:
            setup: The protocol setup describing the device to create.
            domain: The domain to place the device in.

        Returns:
            The device model instance.
        """
        existing = DeviceModel.objects.filter(common_name=setup.onboarding_device).first()
        if existing:
            self.stdout.write(f'Device "{setup.onboarding_device}" already exists.')
            return existing

        onboarding_config = OnboardingConfigModel(
            onboarding_status=OnboardingStatus.PENDING,
            onboarding_protocol=setup.onboarding_protocol,
        )
        onboarding_config.set_pki_protocols([setup.onboarding_pki_protocol])

        if setup.onboarding_protocol == OnboardingProtocol.CMP_SHARED_SECRET:
            onboarding_config.cmp_shared_secret = CMP_SHARED_SECRET
        else:
            onboarding_config.est_password = EST_PASSWORD

        onboarding_config.save()

        device = DeviceModel(
            common_name=setup.onboarding_device,
            serial_number=setup.onboarding_device.upper(),
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            onboarding_config=onboarding_config,
        )
        device.save()
        self.stdout.write(f'Created device "{setup.onboarding_device}" (onboarding).')
        return device

    def _get_or_create_no_onboarding_device(self, setup: ProtocolSetup, domain: DomainModel) -> DeviceModel:
        """Returns the existing device or creates one that does not require onboarding.

        Args:
            setup: The protocol setup describing the device to create.
            domain: The domain to place the device in.

        Returns:
            The device model instance.
        """
        existing = DeviceModel.objects.filter(common_name=setup.no_onboarding_device).first()
        if existing:
            self.stdout.write(f'Device "{setup.no_onboarding_device}" already exists.')
            return existing

        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([setup.no_onboarding_pki_protocol])

        if setup.no_onboarding_pki_protocol == NoOnboardingPkiProtocol.CMP_SHARED_SECRET:
            no_onboarding_config.cmp_shared_secret = CMP_SHARED_SECRET
        else:
            no_onboarding_config.est_password = EST_PASSWORD

        no_onboarding_config.save()

        device = DeviceModel(
            common_name=setup.no_onboarding_device,
            serial_number=setup.no_onboarding_device.upper(),
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )
        device.save()
        self.stdout.write(f'Created device "{setup.no_onboarding_device}" (no onboarding).')
        return device
