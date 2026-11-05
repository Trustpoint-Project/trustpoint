# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Fixtures for the SCEP tests."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import pytest
from crypto.application.private_keys import generate_managed_signing_private_key
from crypto.domain.algorithms import EllipticCurveName
from crypto.domain.specs import EcKeySpec, RsaKeySpec
from cryptography import x509
from devices.models import DeviceModel, NoOnboardingConfigModel
from onboarding.enums import NoOnboardingPkiProtocol
from pki.models import CaModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.domain import DomainAllowedCertificateProfileModel, DomainModel
from pki.util.x509 import CertificateGenerator

from scep.services import ensure_server_credential


@dataclass
class ScepEnv:
    """A domain with a SCEP server credential, one SCEP device and a provisioned challenge."""

    domain: DomainModel
    device: DeviceModel
    profile: CertificateProfileModel
    server_cert: x509.Certificate
    secret: str
    key_kind: str

    @property
    def url(self) -> str:
        """Endpoint path."""
        return f'/.well-known/scep/{self.domain.unique_name}/{self.profile.unique_name}/'

    @property
    def config(self) -> NoOnboardingConfigModel:
        """The device's current no-onboarding config (fresh from the database)."""
        return NoOnboardingConfigModel.objects.get(pk=self.device.no_onboarding_config_id)

    def new_authorization(self) -> str:
        """Provision (reset) the enrollment secret."""
        self.secret = self.config.provision_scep_challenge()
        return self.secret


def _create_env(settings: Any, key_spec: Any, key_kind: str) -> ScepEnv:
    settings.DEVELOPMENT_ENV = True
    settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.DOCKER_CONTAINER = False
    unique = f'scep-ca-{uuid.uuid4().hex[:8]}'
    key = generate_managed_signing_private_key(alias=f'{unique}-key', key_spec=key_spec)
    cert, key = CertificateGenerator.create_root_ca(cn='SCEP Test Root', private_key=key)
    ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=cert,
        private_key=key,
        chain=[],
        unique_name=unique,
        ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11,
    )
    domain = DomainModel.objects.create(unique_name=f'scep-{uuid.uuid4().hex[:8]}', issuing_ca=ca, is_active=True)
    profile, _ = CertificateProfileModel.objects.get_or_create(
        unique_name='tls_server',
        defaults={'profile_json': '{"type": "cert_profile", "subj": {"allow":"*"}, "ext": {}, "validity": {"days": 10}}'},
    )
    DomainAllowedCertificateProfileModel.objects.update_or_create(
        domain=domain, certificate_profile=profile, defaults={'alias': ''}
    )
    config = NoOnboardingConfigModel()
    config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL, NoOnboardingPkiProtocol.SCEP])
    config.save()
    device = DeviceModel.objects.create(
        common_name=f'scep-device-{uuid.uuid4().hex[:6]}', domain=domain, no_onboarding_config=config
    )
    credential = ensure_server_credential(domain)
    secret = config.provision_scep_challenge()
    return ScepEnv(domain, device, profile, credential.get_certificate(), secret, key_kind)


@pytest.fixture
def rsa_env(settings: Any) -> ScepEnv:
    """RSA-2048 issuing CA."""
    return _create_env(settings, RsaKeySpec(key_size=2048), 'rsa')


@pytest.fixture
def ec_env(settings: Any) -> ScepEnv:
    """P-256 issuing CA."""
    return _create_env(settings, EcKeySpec(curve=EllipticCurveName.SECP256R1), 'p256')
