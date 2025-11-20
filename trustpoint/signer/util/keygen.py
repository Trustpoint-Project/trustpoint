"""This File contains functions to create Public and Private Keys."""

from typing import TYPE_CHECKING, get_args

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from trustpoint_core.crypto_types import PrivateKey
from trustpoint_core.oid import AlgorithmIdentifier, NamedCurve
from trustpoint_core.serializer import PrivateKeySerializer

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES


def generate_private_key(algorithm_oid_str: str, curve_name: str | None, key_size: int | None) -> str:
    """This Function generates a Private Key. Which later on is used to get public Key.

    Args:
        algorithm_oid_str:  oid string of the algorithm to use.
        curve_name: curve name which is used to generate the private key (either of two is used).
        key_size: length of the private key (either of two is used).

    Returns:
        Gives out the private key. In string pem format.

    """
    private_key: PRIVATE_KEY_TYPES

    algorithm_enum = None
    for enum_member in AlgorithmIdentifier:
        if getattr(enum_member, 'dotted_string', None) == algorithm_oid_str:
            algorithm_enum = enum_member
            break

    if algorithm_enum is None:
        msg = f'Invalid algorithm OID: {algorithm_oid_str}'
        raise ValueError(msg)

    if algorithm_enum.public_key_algo_oid is None:
        msg = 'Public key oid cannot be None.'
        raise ValueError(msg)
    if algorithm_enum.public_key_algo_oid.name == 'ECC':
        if not curve_name:
            msg = 'ECC curve name is required.'
            raise ValueError(msg)

        try:
            curve_obj = next(c.curve for c in NamedCurve if c.ossl_curve_name.lower() == curve_name.lower())
        except StopIteration:
            available = [c.ossl_curve_name for c in NamedCurve]

            msg = f'Unsupported ECC curve: {curve_name}. Available: {available}'
            raise ValueError(msg) from None
        if curve_obj is None:
            msg = 'ECC curve name is required.'
            raise ValueError(msg)
        private_key = ec.generate_private_key(curve_obj())
    else:
        if not key_size:
            x = 'RSA key length is required.'
            raise ValueError(x)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    pem = PrivateKeySerializer(private_key).as_pkcs8_pem()
    return pem.decode('utf-8')


def load_private_key_object(pem_str: str) -> PrivateKey:
    """This function loads a private key from PEM format."""
    private_keyabc = load_pem_private_key(pem_str.encode('utf-8'), password=None)
    if isinstance(private_keyabc, get_args(PrivateKey)):
        return private_keyabc

    err_msg = 'Private key must be of type PrivateKey.'
    raise TypeError(err_msg)
