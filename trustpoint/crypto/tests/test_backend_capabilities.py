# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Backend capability resolution independently of management page rendering."""

from dataclasses import replace
from unittest.mock import Mock

import pytest

from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
from crypto.adapters.rest.capabilities import RestCapabilities
from crypto.adapters.software.backend import SoftwareBackend
from crypto.adapters.software.capabilities import SOFTWARE_CAPABILITIES, SoftwareCapabilities
from crypto.adapters.software.config import SoftwareProviderProfile
from crypto.application.capabilities import BackendCapabilityService
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.specs import MlDsaKeySpec, MlDsaVariant
from crypto.models import BackendKind, CryptoProviderProfileModel
from crypto.repositories import CryptoProviderProfileRepository


@pytest.mark.parametrize('refresh', [False, True])
def test_software_default_and_live_reports_agree(refresh: bool) -> None:
    """The default path uses the same capabilities as a live software probe."""
    profile = CryptoProviderProfileModel(name='software', backend_kind=BackendKind.SOFTWARE)
    repository = Mock(spec=CryptoProviderProfileRepository)
    repository.get_configured_profile.return_value = profile
    backend = SoftwareBackend(profile=SoftwareProviderProfile(name='software', encryption_source='dev_plaintext'))
    factory = Mock()
    factory.build.return_value = backend
    service = BackendCapabilityService(profile_repository=repository, adapter_factory=factory)

    capabilities = backend.probe_capabilities()
    assert capabilities == SOFTWARE_CAPABILITIES
    assert set(capabilities.supported_key_algorithms) == {KeyAlgorithm.RSA, KeyAlgorithm.EC, KeyAlgorithm.MLDSA}
    report = service.active_report(refresh=refresh)
    assert report.available
    assert report.rsa_key_sizes == (2048, 3072, 4096)
    assert len(report.ec_curves) == 3
    assert report.mldsa_variants == ('mldsa44', 'mldsa65', 'mldsa87')
    assert all(report.supports_key_spec(MlDsaKeySpec(variant)) for variant in MlDsaVariant)
    repository.load_current_capabilities.assert_not_called()
    if not refresh:
        factory.build.assert_not_called()


@pytest.mark.parametrize('backend_kind', [BackendKind.SOFTWARE, BackendKind.REST])
@pytest.mark.parametrize('algorithms', [('rsa',), ('ec',), ('rsa', 'ec'), ('mldsa',)])
def test_snapshot_reports_only_advertised_families(backend_kind: BackendKind, algorithms: tuple[str, ...]) -> None:
    """Restricted software and REST snapshots do not acquire unsupported algorithms."""
    profile = CryptoProviderProfileModel(name='restricted', backend_kind=backend_kind)
    repository = Mock(spec=CryptoProviderProfileRepository)
    repository.get_configured_profile.return_value = profile
    capabilities: SoftwareCapabilities | RestCapabilities = replace(
        SOFTWARE_CAPABILITIES, supported_key_algorithms=algorithms
    )
    if backend_kind == BackendKind.REST:
        capabilities = RestCapabilities(
            supported_key_algorithms=algorithms,
            supported_signature_algorithms=(),
            supported_signing_execution_modes=(),
            implemented_operations=(),
        )
    repository.load_current_capabilities.return_value = capabilities
    backend = Mock()
    backend.refresh_capabilities.return_value = capabilities
    factory = Mock()
    factory.build.return_value = backend

    report = BackendCapabilityService(profile_repository=repository, adapter_factory=factory).active_report(
        refresh=backend_kind == BackendKind.SOFTWARE,
    )

    assert bool(report.rsa_key_sizes) == ('rsa' in algorithms)
    assert bool(report.ec_curves) == ('ec' in algorithms)
    assert bool(report.mldsa_variants) == ('mldsa' in algorithms)


def test_pkcs11_snapshot_does_not_advertise_mldsa() -> None:
    """A PKCS#11 snapshot only advertises verified generation and signing capabilities."""
    repository = Mock(spec=CryptoProviderProfileRepository)
    repository.get_configured_profile.return_value = CryptoProviderProfileModel(
        name='pkcs11',
        backend_kind=BackendKind.PKCS11,
    )
    repository.load_current_capabilities.return_value = Pkcs11Capabilities.from_json_dict(
        {
            'mechanisms': {
                'CKM_RSA_PKCS_KEY_PAIR_GEN': {
                    'name': 'CKM_RSA_PKCS_KEY_PAIR_GEN',
                    'code': 0,
                    'flags': [],
                    'min_key_size': 2048,
                    'max_key_size': 4096,
                },
                'CKM_EC_KEY_PAIR_GEN': {
                    'name': 'CKM_EC_KEY_PAIR_GEN',
                    'code': 4160,
                    'flags': [],
                    'min_key_size': 256,
                    'max_key_size': 521,
                },
            },
            'derived_features': {'can_sign_rsa_pkcs1v15': True, 'can_sign_ecdsa': True},
        }
    )

    report = BackendCapabilityService(profile_repository=repository).active_report()

    assert report.capabilities_known
    assert report.available
    assert not report.mldsa_variants
    assert report.rsa_key_sizes == (2048, 3072, 4096)
    assert len(report.ec_curves) == 3


@pytest.mark.parametrize('backend_kind', [BackendKind.PKCS11, BackendKind.REST])
def test_missing_snapshot_does_not_use_software_defaults(backend_kind: BackendKind) -> None:
    """Unprobed non-software backends must not inherit software capability defaults."""
    repository = Mock(spec=CryptoProviderProfileRepository)
    repository.get_configured_profile.return_value = CryptoProviderProfileModel(
        name='unprobed', backend_kind=backend_kind
    )
    repository.load_current_capabilities.return_value = None

    report = BackendCapabilityService(profile_repository=repository).active_report()

    assert not report.capabilities_known
    assert not report.available
    assert not report.mldsa_variants
