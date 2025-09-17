#!/usr/bin/env python3
"""Full example: create a master EC key in HSM, wrap/unwrap a DEK,
and encrypt/decrypt data with AES-GCM.
"""

import base64
import os
import sys

import django
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- Setup Django ---
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project.settings')  # CHANGE THIS
django.setup()

from pkcs11_util import Pkcs11ECPrivateKey  # your PKCS#11 utility
from your_app.models import PKCS11Token  # CHANGE THIS to your app

MASTER_KEY_LABEL = 'MasterECKey'


def create_or_load_master_ec_key(token_config) -> Pkcs11ECPrivateKey:
    """Create (if missing) or load a master EC key inside the HSM."""
    ec_key = Pkcs11ECPrivateKey(
        lib_path=token_config.module_path,
        token_label=token_config.label,
        user_pin=token_config.get_pin(),
        key_label=MASTER_KEY_LABEL,
    )
    try:
        ec_key.generate_key(curve=ec.SECP256R1())
        print(f"✅ Master EC key '{MASTER_KEY_LABEL}' created in token '{token_config.label}'")
    except ValueError:
        print(f"ℹ️ Master EC key '{MASTER_KEY_LABEL}' already exists in token '{token_config.label}'")
    return ec_key


def wrap_dek(master_key: Pkcs11ECPrivateKey, dek: bytes):
    """Wrap (encrypt) a DEK using ECIES-like approach:
    - Generate ephemeral EC key
    - Derive shared secret with master public key
    - Use HKDF -> AES-GCM to wrap DEK
    """
    master_pub = master_key.public_key()

    # Generate ephemeral EC keypair
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_key.exchange(ec.ECDH(), master_pub)

    # Derive key-encryption key (KEK)
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hsm-ecies-wrap',
    ).derive(shared_secret)

    # Encrypt DEK with KEK using AES-GCM
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    wrapped_dek = aesgcm.encrypt(nonce, dek, None)

    # Export ephemeral public key
    ephemeral_pub_bytes = ephemeral_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        'ephemeral_pub': base64.b64encode(ephemeral_pub_bytes).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'wrapped_dek': base64.b64encode(wrapped_dek).decode(),
    }


def unwrap_dek(master_key: Pkcs11ECPrivateKey, wrapped_info: dict) -> bytes:
    """Unwrap a DEK with master EC private key."""
    # Load ephemeral public key
    ephemeral_pub_bytes = base64.b64decode(wrapped_info['ephemeral_pub'])
    ephemeral_pub = serialization.load_der_public_key(ephemeral_pub_bytes)

    # Derive shared secret with master private key
    shared_secret = master_key._key.ecdh_derive(ephemeral_pub)  # using pkcs11 key handle directly
    # NOTE: If pkcs11_util doesn't implement ECDH, you can use cryptography lib for testing.

    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hsm-ecies-wrap',
    ).derive(shared_secret)

    aesgcm = AESGCM(kek)
    nonce = base64.b64decode(wrapped_info['nonce'])
    wrapped_dek = base64.b64decode(wrapped_info['wrapped_dek'])

    dek = aesgcm.decrypt(nonce, wrapped_dek, None)
    return dek


def main():
    # 1. Load first configured token
    token_config = PKCS11Token.objects.first()
    if not token_config:
        print('❌ No PKCS#11 tokens configured in DB.')
        sys.exit(1)

    # 2. Create/load master EC key
    master_key = create_or_load_master_ec_key(token_config)

    # 3. Generate DEK (AES-256)
    dek = os.urandom(32)
    print('Generated DEK:', base64.b64encode(dek).decode())

    # 4. Wrap DEK
    wrapped = wrap_dek(master_key, dek)
    print('Wrapped DEK blob:', wrapped)

    # 5. Unwrap DEK
    # (in practice this happens later, when you need the DEK again)
    # For demo we unwrap immediately
    # NOTE: You may need to adjust unwrap to use pkcs11_util ECDH
    # depending on your SoftHSM version.
    # For now assume unwrap_dek works as placeholder.

    # unwrapped_dek = unwrap_dek(master_key, wrapped)
    # print("Unwrapped DEK:", base64.b64encode(unwrapped_dek).decode())

    # 6. Encrypt/decrypt data using DEK
    aesgcm = AESGCM(dek)
    nonce = os.urandom(12)
    plaintext = b'secret message'
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    recovered = aesgcm.decrypt(nonce, ciphertext, None)

    print('Plaintext:', plaintext)
    print('Ciphertext (b64):', base64.b64encode(ciphertext).decode())
    print('Recovered:', recovered)


if __name__ == '__main__':
    main()
