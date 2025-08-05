import os
import django

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "trustpoint.settings")  # Update if your settings module is named differently
django.setup()

from pkcs11 import lib, KeyType, TokenFlag
from models import PKCS11Token


def initialize_token(
    slot: int,
    label: str,
    so_pin: str,
    user_pin: str,
    module_path: str = "/usr/lib/softhsm/libsofthsm2.so",
) -> None:
    """
    Initializes a new SoftHSM token and stores its metadata in the DB.
    """
    # Load PKCS#11 module
    pkcs11_lib = lib(module_path)

    # Initialize token in specified slot
    pkcs11_lib.init_token(
        slot=slot,
        label=label,
        so_pin=so_pin
    )
    print(f"Token '{label}' initialized in slot {slot}.")

    # Save to Django model
    token_record, created = PKCS11Token.objects.get_or_create(
        label=label,
        defaults={
            "slot": slot,
            "user_pin": user_pin,
            "so_pin": so_pin,
            "module_path": module_path,
        }
    )

    if not created:
        print(f"Token '{label}' already exists in the database.")
    else:
        print(f"Token '{label}' metadata saved to DB.")


if __name__ == "__main__":
    initialize_token(
        slot=0,
        label="trustpoint-token",
        so_pin="1234",
        user_pin="5678"
    )
