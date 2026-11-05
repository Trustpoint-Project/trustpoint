# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Run inside the built application image with synthetic SQLite/SoftHSM state only."""

import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(tempfile.mkdtemp(prefix='trustpoint-envelope-'))
mode = sys.argv[1] if len(sys.argv) > 1 else 'software'
signing = root / 'signing'
signing.write_text('synthetic-envelope-test-signing-key')
os.environ.update(
    DJANGO_SETTINGS_MODULE='trustpoint.settings',
    DJANGO_SECRET_KEY_FILE=str(signing),
    TRUSTPOINT_PHASE='bootstrap',
    TRUSTPOINT_BOOTSTRAP_DB_PATH=str(root / 'database.sqlite3'),
    TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND='false',
)
sys.path.insert(0, '/var/www/html/trustpoint/trustpoint')
import django

django.setup()
from django.core.management import call_command
from appsecrets.models import AppSecretBackendModel, AppSecretPkcs11ConfigModel, AppSecretSoftwareConfigModel
from appsecrets.service import (
    AppSecretConfigurationError, Pkcs11AppSecretService, SoftwareAppSecretService, clear_app_secret_cache,
)

call_command('migrate', interactive=False, verbosity=0)
if mode == 'software':
    kek_file = root / 'software-kek'
    kek_file.write_text(secrets.token_hex(32))
    kek_file.chmod(0o440)
    os.environ['TRUSTPOINT_SOFTWARE_KEK_FILE'] = str(kek_file)
    backend = AppSecretBackendModel.objects.create(backend_kind='software')
    config = AppSecretSoftwareConfigModel.objects.create(backend=backend)
    service = SoftwareAppSecretService(config)
else:
    import pkcs11

    tokens = root / 'tokens'
    tokens.mkdir()
    conf = root / 'softhsm2.conf'
    conf.write_text(f'directories.tokendir = {tokens}\nobjectstore.backend = file\n')
    os.environ['SOFTHSM2_CONF'] = str(conf)
    os.environ['TRUSTPOINT_SOFTWARE_KEK_FILE'] = str(root / 'deliberately-missing-software-kek')
    pin = root / 'user-pin'
    pin.write_text('synthetic-user-pin')
    subprocess.run(['softhsm2-util', '--init-token', '--free', '--label', 'envelope-test',
                    '--pin', pin.read_text(), '--so-pin', 'synthetic-so-pin'],
                   check=True, capture_output=True)
    module_path = str(Path('/usr/lib/libsofthsm2.so').resolve())
    token = pkcs11.lib(module_path).get_token(token_label='envelope-test')
    backend = AppSecretBackendModel.objects.create(backend_kind='pkcs11')
    config = AppSecretPkcs11ConfigModel.objects.create(
        backend=backend, module_path=module_path, token_label='envelope-test', token_serial=(token.serial.decode() if isinstance(token.serial, bytes) else token.serial),
        auth_source='file', auth_source_ref=str(pin),
    )
    service = Pkcs11AppSecretService(config)

first = service.require_dek()
ciphertext = service.encrypt_text('synthetic persistent database value')
config.refresh_from_db()
wrapped = bytes(config.wrapped_dek)
assert len(first) == 32 and first not in wrapped
clear_app_secret_cache()
assert type(service)(type(config).objects.get()).decrypt_text(ciphertext) == 'synthetic persistent database value'
assert type(service)(type(config).objects.get()).require_dek() == first
if mode == 'software':
    original = kek_file.read_text()
    kek_file.chmod(0o600)
    kek_file.write_text(secrets.token_hex(32))
    try:
        service.require_dek()
    except AppSecretConfigurationError:
        pass
    else:
        raise AssertionError('Wrong KEK must fail even with a cached DEK')
    kek_file.write_text(original)
else:
    token = pkcs11.lib(config.module_path).get_token(token_label='envelope-test')
    with token.open(user_pin=pin.read_text()) as session:
        kek = session.get_key(label=config.kek_label, key_type=pkcs11.KeyType.AES)
        assert kek[pkcs11.Attribute.EXTRACTABLE] is False
        assert kek[pkcs11.Attribute.SENSITIVE] is True
        assert kek[pkcs11.Attribute.PRIVATE] is True
        # Exercise the authenticated encryption fallback against a real provider too.
        session_kek = session.generate_key(
            pkcs11.KeyType.AES, 256, store=False,
            capabilities=pkcs11.MechanismFlag.ENCRYPT | pkcs11.MechanismFlag.DECRYPT,
        )
        encrypted = service._try_encrypt_dek(kek=session_kek, dek=first, attempt_errors=[])
        assert encrypted and service._recover_dek(kek=session_kek, protected_dek=encrypted) == first
        damaged = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        try:
            service._recover_dek(kek=session_kek, protected_dek=damaged)
        except AppSecretConfigurationError:
            pass
        else:
            raise AssertionError('Real HSM GCM must reject tampering')

# Force recovery instead of a cache hit after persisted-envelope corruption.
type(config).objects.filter(pk=config.pk).update(wrapped_dek=wrapped[:-1])
clear_app_secret_cache()
try:
    service.require_dek()
except AppSecretConfigurationError:
    pass
else:
    raise AssertionError('Corrupted envelope must not initialize a new DEK')
assert bytes(type(config).objects.get().wrapped_dek) == wrapped[:-1]
print(f'PASS: {mode} envelope wrapping, recovery, fail-closed behavior, and field roundtrip.')
