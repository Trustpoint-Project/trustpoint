from django.core.management.base import BaseCommand
from django.core.exceptions import ObjectDoesNotExist
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Test KEK loading and DEK unwrapping for PKCS11Token'

    def add_arguments(self, parser):
        parser.add_argument(
            '--token-label',
            type=str,
            help='Specific token label to test (uses first token if not specified)',
        )

    def handle(self, *args, **options):
        token_label = options.get('token_label')
        from settings.models import PKCS11Token

        try:
            # Get the token
            if token_label:
                try:
                    token = PKCS11Token.objects.get(label=token_label)
                except ObjectDoesNotExist:
                    self.stdout.write(
                        self.style.ERROR(f'Token with label "{token_label}" not found')
                    )
                    return
            else:
                token = PKCS11Token.objects.first()
                if not token:
                    self.stdout.write(
                        self.style.ERROR('No PKCS11 tokens found')
                    )
                    return

            self.stdout.write(f'Testing KEK and DEK for token: {token.label}')

            # Test 1: Load KEK
            self._test_kek_loading(token)

            # Test 2: Unwrap DEK (only if we have one)
            if token.encrypted_dek:
                self._test_dek_unwrapping(token)
            else:
                self.stdout.write(
                    self.style.WARNING(f'No encrypted DEK found for token "{token.label}"')
                )

        except Exception as e:
            logger.error(f'KEK/DEK testing failed: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'Test failed: {str(e)}')
            )
            raise

    def _test_kek_loading(self, token):
        """Test loading the KEK (Key Encryption Key)."""
        self.stdout.write('Testing KEK loading...')

        from pki.models import PKCS11Key

        try:
            # Get the KEK record
            if token.kek:
                kek_record = token.kek
            else:
                try:
                    kek_record = PKCS11Key.objects.get(
                        token_label=token.label,
                        key_label=token.KEK_ENCRYPTION_KEY_LABEL,
                        key_type=PKCS11Key.KeyType.AES
                    )
                except ObjectDoesNotExist:
                    self.stdout.write(
                        self.style.ERROR(f'❌ KEK "{token.KEK_ENCRYPTION_KEY_LABEL}" not found in database')
                    )
                    self.stdout.write('💡 Generate KEK first: token.generate_kek()')
                    return

            # Get the AES key instance
            aes_key = kek_record.get_pkcs11_key_instance(
                lib_path=token.module_path,
                user_pin=token.get_pin()
            )

            try:
                aes_key.load_aes_key()
                self.stdout.write(
                    self.style.SUCCESS(f'✅ KEK "{token.KEK_ENCRYPTION_KEY_LABEL}" loaded successfully')
                )
            finally:
                aes_key.close()

        except Exception as e:
            if "no such key" in str(e).lower():
                self.stdout.write(
                    self.style.ERROR(f'❌ KEK "{token.KEK_ENCRYPTION_KEY_LABEL}" not found in HSM')
                )
                self.stdout.write('💡 Generate KEK first: token.generate_kek()')
            else:
                self.stdout.write(
                    self.style.ERROR(f'❌ KEK loading failed: {e}')
                )
            raise

    def _test_dek_unwrapping(self, token):
        """Test unwrapping the DEK."""
        self.stdout.write('Testing DEK unwrapping...')

        try:
            # Clear any cached DEK to force unwrapping
            token.clear_dek_cache()

            # Unwrap the DEK
            dek = token.get_dek()

            if dek and len(dek) == 32:
                self.stdout.write(
                    self.style.SUCCESS(f'✅ DEK unwrapped successfully ({len(dek)} bytes)')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'❌ Invalid DEK (expected 32 bytes, got {len(dek) if dek else 0})')
                )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ DEK unwrapping failed: {e}')
            )
            raise