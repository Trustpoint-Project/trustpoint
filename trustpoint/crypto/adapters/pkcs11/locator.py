"""Object lookup helpers for PKCS#11-managed keys."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from crypto.adapters.pkcs11.mechanisms import key_type_for_algorithm
from crypto.domain.errors import KeyNotFoundError
from pkcs11 import Attribute, NoSuchKey, ObjectClass, Session  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from crypto.adapters.pkcs11.bindings import Pkcs11ManagedKeyBinding


class Pkcs11ObjectLocator:
    """Find PKCS#11 key objects by their provider-owned identity."""

    def private_key(self, session: Session, key: Pkcs11ManagedKeyBinding) -> object:
        """Find the matching private key object."""
        return self._lookup(
            session,
            key=key,
            object_class=ObjectClass.PRIVATE_KEY,
        )

    def public_key(self, session: Session, key: Pkcs11ManagedKeyBinding) -> object:
        """Find the matching public key object."""
        return self._lookup(
            session,
            key=key,
            object_class=ObjectClass.PUBLIC_KEY,
        )

    def _lookup(
        self,
        session: Session,
        *,
        key: Pkcs11ManagedKeyBinding,
        object_class: ObjectClass,
    ) -> object:
        """Lookup a key strictly by CKA_ID."""
        if not key.key_id:
            msg = 'Managed PKCS#11 key binding is missing a CKA_ID.'
            raise KeyNotFoundError(msg)

        key_type = key_type_for_algorithm(key.algorithm)

        try:
            obj = session.get_key(object_class=object_class, key_type=key_type, id=key.key_id)
        except NoSuchKey as exc:
            raise self._not_found(object_class=object_class, key_id_hex=key.key_id_hex) from exc

        self._assert_id_match(obj, key=key)
        return obj

    def _assert_id_match(self, obj: object, *, key: Pkcs11ManagedKeyBinding) -> None:
        """Verify that the resolved PKCS#11 object still exposes the expected CKA_ID."""
        try:
            actual_id = cast('Any', obj)[Attribute.ID]
        except Exception:
            return

        if bytes(actual_id) != bytes(key.key_id):
            msg = (
                'Located PKCS#11 object for managed key binding '
                f'{key.key_id_hex!r} but its CKA_ID does not match.'
            )
            raise KeyNotFoundError(msg)

    def _not_found(self, *, object_class: ObjectClass, key_id_hex: str) -> KeyNotFoundError:
        object_name = 'private' if object_class == ObjectClass.PRIVATE_KEY else 'public'
        msg = f'Unable to locate {object_name} key for PKCS#11 key id {key_id_hex!r}.'
        return KeyNotFoundError(msg)
