"""Capability-gated live key-generation contract tests."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from crypto.domain.algorithms import EllipticCurveName
from crypto.domain.policies import KeyPolicy, KeyUsage
from crypto.domain.specs import EcKeySpec, RsaKeySpec


pytestmark = [pytest.mark.integration, pytest.mark.hsm, pytest.mark.django_db]


@dataclass(frozen=True, slots=True)
class KeygenScenario:
    """A live key-generation contract scenario."""

    name: str
    key_spec: object
    required_features: frozenset[str]
    expected_public_key_type: type


SCENARIOS = (
    KeygenScenario(
        name="rsa_2048",
        key_spec=RsaKeySpec(key_size=2048),
        required_features=frozenset({"can_generate_rsa"}),
        expected_public_key_type=rsa.RSAPublicKey,
    ),
    KeygenScenario(
        name="ec_p256",
        key_spec=EcKeySpec(curve=EllipticCurveName.SECP256R1),
        required_features=frozenset({"can_generate_ec"}),
        expected_public_key_type=ec.EllipticCurvePublicKey,
    ),
)


def _require_features(capabilities, *, scenario_name: str, required_features: frozenset[str]) -> None:
    missing = sorted(
        feature for feature in required_features if not capabilities.derived_features.get(feature, False)
    )
    if missing:
        pytest.skip(
            f"Skipping {scenario_name}: provider lacks required capabilities: {', '.join(missing)}."
        )


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda scenario: scenario.name)
def test_generate_managed_key_and_fetch_public_key(live_pkcs11_backend, live_pkcs11_capabilities, scenario: KeygenScenario) -> None:
    _require_features(
        live_pkcs11_capabilities,
        scenario_name=scenario.name,
        required_features=scenario.required_features,
    )

    alias = f"pytest-{scenario.name}-{secrets.token_hex(6)}"
    key = live_pkcs11_backend.generate_managed_key(
        alias=alias,
        key_spec=scenario.key_spec,
        policy=KeyPolicy(
            usages=frozenset({KeyUsage.SIGN}),
            extractable=False,
            ephemeral=False,
        ),
    )

    public_key = live_pkcs11_backend.get_public_key(key)
    assert public_key is not None
    assert isinstance(public_key, scenario.expected_public_key_type)