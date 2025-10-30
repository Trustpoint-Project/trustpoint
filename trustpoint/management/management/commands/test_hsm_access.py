"""Django management command to test HSM (PKCS#11) access from the Django context."""

import os

from django.core.management.base import BaseCommand

from management.models import PKCS11Token
from management.pkcs11_util import Pkcs11RSAPrivateKey

# For execution
# docker compose exec trustpoint /bin/bash
# cd /var/www/html/trustpoint
# su -s /bin/bash www-data -c "uv run trustpoint/manage.py test_hsm_access"


class Command(BaseCommand):
    help = 'Test HSM access from Django context'

    def handle(self, *args, **options):
        self.stdout.write(f'Current user: {os.getuid()}')
        self.stdout.write(f"SOFTHSM2_CONF: {os.environ.get('SOFTHSM2_CONF')}")

        # Get the PKCS11 token config
        try:
            token_config = PKCS11Token.objects.first()
            if not token_config:
                self.stdout.write(self.style.ERROR('No PKCS11Token configuration found'))
                return

            self.stdout.write(f'Token config found: {token_config.label}')
            self.stdout.write(f'Module path: {token_config.module_path}')

            # Try to create a PKCS11 RSA key handler
            self.stdout.write('Attempting to create PKCS11 RSA key handler...')
            key_handler = Pkcs11RSAPrivateKey(
                lib_path=token_config.module_path,
                token_label=token_config.label,
                user_pin=token_config.get_pin(),
                key_label='test-key-django',
            )

            self.stdout.write(self.style.SUCCESS('PKCS11 RSA key handler created successfully'))
            key_handler.close()

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'ERROR: {e}'))
            import traceback
            self.stdout.write(traceback.format_exc())
