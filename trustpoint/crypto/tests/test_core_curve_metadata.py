# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Core curve metadata preserves PKCS#11 parameters and the existing supported curve set."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pkcs11 import Attribute

from crypto.adapters.pkcs11.mechanisms import ec_parameters_for_curve
from crypto.domain.algorithms import EllipticCurveName
from management.pkcs11_util import Pkcs11ECPrivateKey


@pytest.mark.parametrize(
    ('curve', 'name', 'parameters'),
    [
        (ec.SECP256R1, EllipticCurveName.SECP256R1, bytes.fromhex('06082a8648ce3d030107')),
        (ec.SECP384R1, EllipticCurveName.SECP384R1, bytes.fromhex('06052b81040022')),
        (ec.SECP521R1, EllipticCurveName.SECP521R1, bytes.fromhex('06052b81040023')),
    ],
)
def test_curve_parameters_match_existing_token_encoding(curve, name, parameters):
    """Both adapters keep the exact token parameter bytes and decode them to the same curve."""
    key = object.__new__(Pkcs11ECPrivateKey)
    key._key = {Attribute.EC_PARAMS: parameters}
    assert key._get_curve_params(curve()) == parameters
    assert ec_parameters_for_curve(name) == parameters
    assert isinstance(key.curve, curve)


def test_core_curve_inventory_does_not_expand_token_support():
    """A curve known to Core remains rejected by the legacy token adapter."""
    key = object.__new__(Pkcs11ECPrivateKey)
    key._key_exists = lambda *args: False
    with pytest.raises(ValueError, match='Unsupported curve: secp256k1'):
        key.generate_key(ec.SECP256K1())
    with pytest.raises(ValueError, match='Unsupported curve: secp256k1'):
        key._get_curve_params(ec.SECP256K1())
