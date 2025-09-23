"""Management command to import an EC private key to HSM."""

from cryptography.hazmat.primitives.asymmetric import ec
from django.core.management.base import BaseCommand, CommandError
from management.models import PKCS11Token
from management.pkcs11_util import Pkcs11ECPrivateKey


class Command(BaseCommand):
    """Import an EC private key to HSM for testing."""

    help = 'Import an EC private key to HSM'

    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            '--key-label',
            type=str,
            default='test-ec-key',
            help='Label for the key in HSM'
        )
        parser.add_argument(
            '--curve',
            type=str,
            choices=['secp256r1', 'secp384r1', 'secp521r1'],
            default='secp256r1',
            help='EC curve to use'
        )

    def handle(self, *args, **options):
        """Execute the command."""
        self.stdout.write("Importing EC key to HSM...")

        try:
            # Get token configuration
            token_config = PKCS11Token.objects.first()
            if not token_config:
                raise CommandError("No PKCS11 token configured")

            # Generate EC key
            curve_map = {
                'secp256r1': ec.SECP256R1(),
                'secp384r1': ec.SECP384R1(),
                'secp521r1': ec.SECP521R1(),
            }

            curve = curve_map[options['curve']]
            ec_private_key = ec.generate_private_key(curve)
            self.stdout.write(f"Generated {options['curve']} key")

            # Import to HSM
            ec_key_handler = Pkcs11ECPrivateKey(
                lib_path=token_config.module_path,
                token_label=token_config.label,
                user_pin=token_config.get_pin(),
                key_label=options['key_label']
            )

            success = ec_key_handler.import_private_key_from_crypto(ec_private_key)

            if success:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Successfully imported EC key '{options['key_label']}'"
                    )
                )

                try:
                    ec_key_handler.load_key()
                    self.stdout.write("Key loading test successful")

                    public_key = ec_key_handler.public_key()
                    if public_key:
                        self.stdout.write("Public key retrieval successful")

                except Exception as e:
                    self.stdout.write(f"Warning: Key test failed: {e}")
                finally:
                    ec_key_handler.close()
            else:
                raise CommandError("Failed to import EC key to HSM")

        except Exception as e:
            raise CommandError(f"Error importing EC key: {e}") from e