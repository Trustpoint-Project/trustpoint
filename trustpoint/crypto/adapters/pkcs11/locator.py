"""Object lookup helpers for PKCS#11-managed keys."""

from __future__ import annotations

from typing import TYPE_CHECKING

from crypto.adapters.pkcs11.mechanisms import key_type_for_algorithm
from crypto.domain.errors import KeyNotFoundError
from pkcs11 import Attribute, NoSuchKey, ObjectClass, Session

if TYPE_CHECKING:
    from crypto.domain.refs import ManagedKeyRef


def _normalize_pkcs11_text(value: str | None) -> str | None:
    """Normalize fixed-width PKCS#11 text attributes."""
    if value is None:
        return None
    return value.rstrip('\x00 ').strip() or None


class Pkcs11ObjectLocator:
    """Find PKCS#11 key objects.

    New managed-key records should bind by CKA_ID. Optional label fallback
    exists only to support migration from legacy records.
    """

    def private_key(self, session: Session, key: ManagedKeyRef, *, allow_label_fallback: bool = False) -> object:
        """Find the matching private key object."""
        return self._lookup(
            session,
            key=key,
            object_class=ObjectClass.PRIVATE_KEY,
            allow_label_fallback=allow_label_fallback,
        )

    def public_key(self, session: Session, key: ManagedKeyRef, *, allow_label_fallback: bool = False) -> object:
        """Find the matching public key object."""
        return self._lookup(
            session,
            key=key,
            object_class=ObjectClass.PUBLIC_KEY,
            allow_label_fallback=allow_label_fallback,
        )

    def _lookup(
        self,
        session: Session,
        *,
        key: ManagedKeyRef,
        object_class: ObjectClass,
        allow_label_fallback: bool,
    ) -> object:
        """Lookup a key by CKA_ID, optionally falling back to label for migration."""
        key_type = key_type_for_algorithm(key.algorithm)

        if key.key_id:
            try:
                obj = session.get_key(object_class=object_class, key_type=key_type, id=key.key_id)
            except NoSuchKey:
                obj = None
            else:
                self._assert_match(obj, key=key, require_id_match=True)
                return obj

        if allow_label_fallback and key.label:
            try:
                obj = session.get_key(object_class=object_class, key_type=key_type, label=key.label)
            except NoSuchKey as exc:
                raise self._not_found(object_class=object_class, alias=key.alias) from exc

            # If a key_id is present in the ref, do not silently rebind to a
            # different object found only by label.
            self._assert_match(obj, key=key, require_id_match=bool(key.key_id))
            return obj

        raise self._not_found(object_class=object_class, alias=key.alias)

    def _assert_match(self, obj: object, *, key: ManagedKeyRef, require_id_match: bool) -> None:
        """Verify that the resolved PKCS#11 object matches the managed-key ref."""
        actual_id = None
        actual_label = None

        try:
            actual_id = obj[Attribute.ID]
        except Exception:
            actual_id = None

        try:
            actual_label = obj[Attribute.LABEL]
        except Exception:
            actual_label = None

        if require_id_match and key.key_id:
            if actual_id is None or bytes(actual_id) != bytes(key.key_id):
                msg = f'Located PKCS#11 object for alias {key.alias!r} but its CKA_ID does not match the managed key reference.'
                raise KeyNotFoundError(msg)

        if key.label is not None and actual_label is not None:
            if _normalize_pkcs11_text(actual_label) != _normalize_pkcs11_text(key.label):
                msg = f'Located PKCS#11 object for alias {key.alias!r} but its label does not match the managed key reference.'
                raise KeyNotFoundError(msg)

    def _not_found(self, *, object_class: ObjectClass, alias: str) -> KeyNotFoundError:
        object_name = 'private' if object_class == ObjectClass.PRIVATE_KEY else 'public'
        msg = f'Unable to locate {object_name} key for alias {alias!r}.'
        return KeyNotFoundError(msg)
