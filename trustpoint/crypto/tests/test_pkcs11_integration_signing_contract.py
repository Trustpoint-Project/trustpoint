"""Capability-gated live signing contract tests."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

from crypto.domain.algorithms import EllipticCurveName
from crypto.domain.policies import KeyPolicy, KeyUsage, SigningExecutionMode
from crypto.domain.specs import EcKeySpec, RsaKeySpec, SignRequest


pytestmark = [pytest.mark.integration, pytest.mark.hsm, pytest.mark.django_db]


@dataclass(frozen=True, slots=True)
class SigningScenario:
    """A live signing contract scenario."""

    name: str
    key_spec: object
    sign_request: SignRequest
    signing_execution_mode: SigningExecutionMode
    required_features: frozenset[str]
    verifier_kind: str


SCENARIOS = (
    SigningScenario(
        name="rsa_pkcs1v15_sha256_complete_hsm",
        key_spec=RsaKeySpec(key_size=2048),
        sign_request=SignRequest.rsa_pkcs1v15_sha256(),
        signing_execution_mode=SigningExecutionMode.COMPLETE_HSM,
        required_features=frozenset({"can_generate_rsa", "supports_sign_rsa_pkcs1v15_sha256"}),
        verifier_kind="rsa",
    ),
    SigningScenario(
        name="rsa_pkcs1v15_sha256_allow_software_hash",
        key_spec=RsaKeySpec(key_size=2048),
        sign_request=SignRequest.rsa_pkcs1v15_sha256(),
        signing_execution_mode=SigningExecutionMode.ALLOW_SOFTWARE_HASH,
        required_features=frozenset({"can_generate_rsa", "can_sign_rsa_pkcs1v15"}),
        verifier_kind="rsa",
    ),
    SigningScenario(
        name="ecdsa_p256_sha256_complete_hsm",
        key_spec=EcKeySpec(curve=EllipticCurveName.SECP256R1),
        sign_request=SignRequest.ecdsa_sha256(),
        signing_execution_mode=SigningExecutionMode.COMPLETE_HSM,
        required_features=frozenset({"can_generate_ec", "supports_sign_ecdsa_sha256"}),
        verifier_kind="ec",
    ),
    SigningScenario(
        name="ecdsa_p256_sha256_allow_software_hash",
        key_spec=EcKeySpec(curve=EllipticCurveName.SECP256R1),
        sign_request=SignRequest.ecdsa_sha256(),
        signing_execution_mode=SigningExecutionMode.ALLOW_SOFTWARE_HASH,
        required_features=frozenset({"can_generate_ec", "can_sign_ecdsa"}),
        verifier_kind="ec",
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
def test_signing_contract(live_pkcs11_backend, live_pkcs11_capabilities, scenario: SigningScenario) -> None:
    _require_features(
        live_pkcs11_capabilities,
        scenario_name=scenario.name,
        required_features=scenario.required_features,
    )

    alias = f"pytest-{scenario.name}-{secrets.token_hex(6)}"
    binding = live_pkcs11_backend.generate_managed_key(
        alias=alias,
        key_spec=scenario.key_spec,
        policy=KeyPolicy(
            usages=frozenset({KeyUsage.SIGN}),
            extractable=False,
            ephemeral=False,
            signing_execution_mode=scenario.signing_execution_mode,
        ),
    )

    payload = f"trustpoint-signing-contract:{scenario.name}".encode("utf-8")
    signature = live_pkcs11_backend.sign(
        key=binding,
        data=payload,
        request=scenario.sign_request,
    )

    assert isinstance(signature, bytes)
    assert signature

    public_key = live_pkcs11_backend.get_public_key(binding)

    if scenario.verifier_kind == "rsa":
        public_key.verify(
            signature,
            payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return

    if scenario.verifier_kind == "ec":
        public_key.verify(
            signature,
            payload,
            ec.ECDSA(hashes.SHA256()),
        )
        return

    raise AssertionError(f"Unsupported verifier kind: {scenario.verifier_kind!r}")
