"""PKCS#11 Utility Functions."""
import contextlib
import types
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Any, ClassVar, Never

import pkcs11  # type: ignore[import-untyped]
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    rsa,
)
from cryptography.hazmat.primitives.asymmetric import (
    padding as asym_padding,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, KeySerializationEncryption, PrivateFormat
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass, lib
from pkcs11.exceptions import NoSuchKey, PKCS11Error  # type: ignore[import-untyped]
from trustpoint.logger import LoggerMixin
from trustpoint_core.oid import NamedCurve


class Pkcs11Utilities(LoggerMixin):
    """Utility class for general PKCS#11 operations not specific to private keys.

    Provides functions for slot/token management, random generation, object destruction, and mechanism listing.
    """

    def __init__(self, lib_path: str) -> None:
        """Initialize the PKCS#11 utility with the specified library path.

        Args:
            lib_path (str): Path to the PKCS#11 library.
        """
        self._lib = lib(lib_path)
        self._slots_cache = None
        self._tokens_cache: list[pkcs11.Token] = []

    def _raise_value_error(self, message: str) -> Never:
        raise ValueError(message)

    def _raise_runtime_error(self, message: str) -> Never:
        raise RuntimeError(message)

    def _raise_type_error(self, message: str) -> Never:
        raise TypeError(message)

    def get_slots(self) -> list[pkcs11.Slot]:
        """Get all available slots in the PKCS#11 library with caching.

        Returns:
            List[pkcs11.Slot]: List of available slots.
        """
        if self._slots_cache is None:
            self._slots_cache = self._lib.get_slots()
        if self._slots_cache is None:
            msg = 'Failed to retrieve PKCS#11 slots from library.'
            self._raise_runtime_error(msg)
        return self._slots_cache

    def get_tokens(self) -> list[pkcs11.Token]:
        """Get all available tokens in the PKCS#11 library with caching.

        Returns:
            List[pkcs11.Token]: List of available tokens.
        """
        if self._tokens_cache is None:
            tokens = []
            for slot in self.get_slots():
                try:
                    if hasattr(slot, 'token') and slot.token is not None:
                        tokens.append(slot.token)
                    elif hasattr(slot, 'get_token'):
                        token = slot.get_token()
                        if token is not None:
                            tokens.append(token)
                except Exception as e:  # noqa: BLE001
                    self.logger.warning('Could not get token from slot %s: %s', slot, e)
                    continue
            self._tokens_cache = tokens
        return self._tokens_cache

    def get_token_by_label(self, token_label: str) -> pkcs11.Token | None:
        """Get a token by its label with optimized lookup.

        Args:
            token_label (str): Label of the token to find.

        Returns:
            pkcs11.Token: The found token.

        Raises:
            ValueError: If no token with the specified label is found.
        """
        for token in self.get_tokens():
            if token.label == token_label:
                return token
        msg = f'Token with label {token_label} not found.'
        self._raise_value_error(msg)
        return None

    def get_slot_id_for_pkcs11_tool_slot(self, pkcs11_tool_slot: int) -> int:
        """Convert pkcs11-tool slot number to Python slot ID.

        Args:
            pkcs11_tool_slot (int): Slot number as used by pkcs11-tool (0, 1, 2, etc.)

        Returns:
            int: Actual slot ID for use with Python pkcs11 library.

        Raises:
            ValueError: If slot not found.
        """
        try:
            slots = self._lib.get_slots(token_present=True)

            if pkcs11_tool_slot >= len(slots):
                available = list(range(len(slots)))
                msg = f'pkcs11-tool slot {pkcs11_tool_slot} not found. Available slots: {available}'
                self._raise_value_error(msg)

            slot_id = slots[pkcs11_tool_slot].slot_id
            if not isinstance(slot_id, int):
                msg = f'Slot ID is not an integer: {slot_id}'
                self._raise_value_error(msg)

        except Exception as e:
            msg = f'Failed to get slot mapping: {e}'
            raise ValueError(msg) from e
        else:
            return slot_id

    def get_mechanisms(self, token_label: str) -> list[Mechanism]:
        """Get all mechanisms supported by the specified token.

        Args:
            token_label (str): Label of the token to check.

        Returns:
            List[Mechanism]: List of supported mechanisms.
        """
        token = self.get_token_by_label(token_label)
        if token is None:
            msg = f'Token with label {token_label} not found.'
            self._raise_value_error(msg)
        return list(token.get_mechanisms())

    def open_session(self, token_label: str, user_pin: str) -> pkcs11.Session:
        """Open a session with the specified token.

        Args:
            token_label (str): Label of the token to open a session with.
            user_pin (str): User PIN for authentication.

        Returns:
            pkcs11.Session: The opened session.
        """
        token = self.get_token_by_label(token_label)
        if token is None:
            msg = f'Token with label {token_label} not found.'
            self._raise_value_error(msg)
        return token.open(user_pin=user_pin, rw=True)

    def generate_random(self, token_label: str, user_pin: str, length: int) -> bytes:
        """Generate cryptographically secure random bytes using the HSM.

        Args:
            token_label (str): Label of the token to use.
            user_pin (str): User PIN for the session.
            length (int): Number of random bytes to generate.

        Returns:
            bytes: Randomly generated bytes.
        """
        with self.open_session(token_label, user_pin) as session:
            random_bytes = session.generate_random(length)
            if not isinstance(random_bytes, bytes):
                msg = 'Generated random data is not of type bytes.'
                self._raise_type_error(msg)
            return bytes(random_bytes)

    def seed_random(self, token_label: str, user_pin: str, seed_data: bytes) -> None:
        """Seed the HSM's random number generator with provided entropy.

        Args:
            token_label (str): Label of the token to use.
            user_pin (str): User PIN for the session.
            seed_data (bytes): Entropy data to seed the RNG.
        """
        with self.open_session(token_label, user_pin) as session:
            session.seed_random(seed_data)

    def destroy_object(
        self, token_label: str, user_pin: str, label: str, key_type: KeyType, object_class: ObjectClass
    ) -> None:
        """Destroy a cryptographic object on the token.

        Args:
            token_label (str): Label of the token containing the object.
            user_pin (str): User PIN for the session.
            label (str): Label of the object to destroy.
            key_type (KeyType): Type of the key (RSA, EC, etc.).
            object_class (ObjectClass): Class of the object (PRIVATE_KEY, PUBLIC_KEY, etc.).

        Raises:
            ValueError: If the object doesn't exist.
        """
        with self.open_session(token_label, user_pin) as session:
            try:
                obj = session.get_key(label=label, key_type=key_type, object_class=object_class)
                obj.destroy()
            except NoSuchKey as e:
                msg = f"Object {object_class} with label '{label}' not found on token '{token_label}'."
                raise ValueError(msg) from e


class Pkcs11PrivateKey(ABC, LoggerMixin):
    """Base class for PKCS#11-backed private keys (RSA, EC)."""

    DIGEST_MECHANISMS: ClassVar[dict[type[hashes.HashAlgorithm], Mechanism]] = {
        hashes.SHA256: Mechanism.SHA256,
        hashes.SHA384: Mechanism.SHA384,
        hashes.SHA512: Mechanism.SHA512,
        hashes.SHA224: Mechanism.SHA224,
    }

    def __init__(
        self, lib_path: str, token_label: str, user_pin: str, key_label: str, slot_id: int | None = None
    ) -> None:
        """Initialize a PKCS#11 private key handler.

        Args:
            lib_path (str): Path to the PKCS#11 library.
            token_label (str): Label of the HSM token.
            user_pin (str): User PIN for the token.
            key_label (str): Label of the private key.
            slot_id (int, optional): Specific slot ID to use. If None, uses token_label to find slot.
        """
        self._lib_path = lib_path
        self._token_label = token_label
        self._user_pin = user_pin
        self._key_label = key_label
        self._slot_id = slot_id
        self._lib = None
        self._token = None
        self._session: pkcs11.Session | None = None
        self._key = None

        self._initialize()

    def _raise_value_error(self, message: str) -> Never:
        raise ValueError(message)

    def _raise_type_error(self, message: str) -> Never:
        raise TypeError(message)

    def _raise_runtime_error(self, message: str) -> Never:
        raise RuntimeError(message)

    def _initialize(self) -> None:
        """Initialize the PKCS#11 library and create a session."""
        try:
            self._lib = pkcs11.lib(self._lib_path)
            if self._lib is None:
                self._raise_runtime_error('PKCS#11 library is not initialized.')
            self._token = self._lib.get_token(token_label=self._token_label)

            self._session = self._token.open(user_pin=self._user_pin, rw=True)
        except pkcs11.exceptions.UserAlreadyLoggedIn:
            if self._token is not None:
                self._session = self._token.open(rw=True)
        except Exception as e:
            msg = f'Failed to initialize PKCS#11 session: {e}; lib_path: {self._lib_path} token: {self._token_label} '
            raise RuntimeError(msg) from e

    def copy_key(
        self,
        source_label: str,
        target_label: str,
        key_type: KeyType,
        object_class: ObjectClass,
        template: dict[Attribute, Any] | None = None,
    ) -> None:
        """Copy a cryptographic key with a new label and attributes.

        Args:
            source_label (str): Label of the source key.
            target_label (str): Label for the copied key.
            key_type (KeyType): Type of the key (RSA, EC, etc.).
            object_class (ObjectClass): Class of the object to copy.
            template (Optional[Dict[Attribute, Any]]): Optional template for new attributes.

        Raises:
            ValueError: If source key doesn't exist.
        """
        if self._session is None:
            self._raise_runtime_error('PKCS#11 session is not initialized.')
        source_key = self._session.get_key(label=source_label, key_type=key_type, object_class=object_class)
        template = template or {}
        template[Attribute.LABEL] = target_label
        source_key.copy(template=template)

    def destroy_object(self, label: str, key_type: KeyType, object_class: ObjectClass) -> None:
        """Destroy a cryptographic object on the token.

        Args:
            label (str): Label of the object to destroy.
            key_type (KeyType): Type of the key (RSA, EC, etc.).
            object_class (ObjectClass): Class of the object (PRIVATE_KEY, PUBLIC_KEY, etc.).

        Raises:
            ValueError: If the object doesn't exist.
        """
        if self._session is None:
            self._raise_runtime_error('PKCS#11 session is not initialized.')
        try:
            obj = self._session.get_key(label=label, key_type=key_type, object_class=object_class)
            obj.destroy()
        except NoSuchKey as e:
            msg = f'Object {object_class} with label {label} not found.'
            raise ValueError(msg) from e

    def digest_data(self, data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        """Perform a cryptographic digest operation on the provided data using the HSM.

        Args:
            data (bytes): Data to be hashed.
            algorithm (hashes.HashAlgorithm): Hash algorithm to use.

        Returns:
            bytes: The resulting hash.

        Raises:
            ValueError: If the algorithm is not supported.
        """
        mechanism = self.DIGEST_MECHANISMS.get(type(algorithm))
        if mechanism is None:
            msg = f'Unsupported digest algorithm: {algorithm.name}'
            self._raise_value_error(msg)

        if self._session is None:
            self._raise_runtime_error('PKCS#11 session is not initialized.')
        digest_result = self._session.digest(mechanism, data)
        if not isinstance(digest_result, bytes):
            msg = 'Digest result is not of type bytes.'
            self._raise_type_error(msg)
        return bytes(digest_result)

    def _key_exists(self, key_type: KeyType, object_class: ObjectClass) -> bool:
        """Check if a key with the specified type and object class exists on the token.

        Args:
            key_type (KeyType): The key type (e.g., RSA, EC).
            object_class (ObjectClass): The object class (PRIVATE_KEY or PUBLIC_KEY).

        Returns:
            bool: True if the key exists, False otherwise.
        """
        if self._session is None:
            self._raise_runtime_error('PKCS#11 session is not initialized.')
        try:
            self._session.get_key(label=self._key_label, key_type=key_type, object_class=object_class)
        except NoSuchKey:
            return False
        else:
            return True

    @abstractmethod
    def sign(self, data: bytes, *args: Any, **kwargs: Any) -> bytes:
        """Sign the provided data using the private key.

        Args:
            data (bytes): Data to be signed.
            *args (Any): Additional positional arguments.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            bytes: The signature.
        """

    @abstractmethod
    def public_key(self) -> RSAPublicKey | ec.EllipticCurvePublicKey:
        """Return the public key associated with this private key.

        Returns:
            Union[RSAPublicKey, ec.EllipticCurvePublicKey]: The public key object.
        """
        ...

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Return the key size in bits.

        Returns:
            int: The key size.
        """
        ...

    def destroy_key(self) -> None:
        """Destroy the current private key and associated public key.

        Raises:
            ValueError: If the key doesn't exist.
        """
        if self._key is None:
            msg = 'Current key does not exist.'
            self._raise_value_error(msg)

        try:
            self._key.destroy()
            self._key = None
            if hasattr(self, '_public_key'):
                self._public_key = None
        except PKCS11Error as e:
            msg = f'Failed to destroy key: {e}'
            raise RuntimeError(msg) from e

    def close(self) -> None:
        """Close the session with the token."""
        if hasattr(self, '_session') and self._session:
            self._session.close()

    def __enter__(self) -> 'Pkcs11PrivateKey':
        """Context manager entry point.

        Returns:
            Pkcs11PrivateKey: The current instance.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> None:
        """Context manager exit point, closes the session.

        Args:
            exc_type (Optional[Type[BaseException]]): Exception type if an error occurred.
            exc_value (Optional[BaseException]]): Exception instance if an error occurred.
            traceback (Optional[types.TracebackType]): Traceback if an error occurred.
        """
        self.close()


class Pkcs11AESKey:
    """PKCS#11 AES symmetric key implementation using python-pkcs11."""

    # AES key lengths in bits
    SUPPORTED_KEY_LENGTHS: ClassVar[list[int]] = [128, 192, 256]

    def __init__(self, lib_path: str, token_label: str, user_pin: str, key_label: str) -> None:
        """Initialize PKCS#11 AES key.

        Args:
            lib_path: Path to PKCS#11 library
            token_label: Token label
            user_pin: User PIN for token authentication
            key_label: Label for the AES key
        """
        self._lib_path: str = lib_path
        self._token_label: str = token_label
        self._user_pin: str = user_pin
        self._key_label: str = key_label
        self._lib: pkcs11.lib | None = None
        self._slot_id: int | None = None
        self._token: pkcs11.token | None = None
        self._session: pkcs11.session | None = None
        self._key: pkcs11.key | None = None
        self._key_length: int | None = None

    def _initialize(self) -> None:
        """Initialize PKCS#11 library and session (copied from parent logic)."""
        try:
            self._lib = pkcs11.lib(self._lib_path)
            self._token = self._lib.get_token(token_label=self._token_label)

            self._session = self._token.open(user_pin=self._user_pin, rw=True)
        except pkcs11.exceptions.UserAlreadyLoggedIn:
            pass
        except Exception as e:
            msg = f'Failed to initialize PKCS#11 session: {e}; lib_path: {self._lib_path} token: {self._token_label} '
            raise RuntimeError(msg) from e

    def load_key(self) -> None:
        """Load an existing AES key from the PKCS#11 token.

        Raises:
            RuntimeError: If the key cannot be loaded or does not exist.
        """
        if self._session is None:
            self._initialize()

        try:
            self._key = self._session.get_key(
                label=self._key_label,
                key_type=pkcs11.KeyType.AES
            )
        except pkcs11.NoSuchKey as e:
            msg = f"AES key with label '{self._key_label}' not found in token '{self._token_label}'."
            raise pkcs11.NoSuchKey(msg) from e
        except Exception as e:
            msg = f"Failed to load AES key '{self._key_label}': {e}"
            raise RuntimeError(msg) from e

    def generate_key(self, key_length: int = 256) -> None:
            """Generate an AES key in the PKCS#11 token.

            Args:
                key_length (int): Length of the AES key in bits (default: 256).

            Raises:
                ValueError: If the key length is not supported.
                RuntimeError: If key generation fails.
            """
            if key_length not in self.SUPPORTED_KEY_LENGTHS:
                msg = f'Unsupported key length: {key_length}. Must be one of {self.SUPPORTED_KEY_LENGTHS}.'
                raise ValueError(msg)

            if self._session is None:
                self._initialize()

            try:
                self._key = self._session.generate_key(
                    pkcs11.KeyType.AES,
                    key_length=key_length,
                    label=self._key_label,
                    store=True
                )
            except Exception as e:
                msg = f'Failed to generate AES key: {e}'
                raise RuntimeError(msg) from e

    def close(self) -> None:
        """Close PKCS#11 session."""
        if self._session:
            with contextlib.suppress(Exception):
                self._session.close()
            self._session = None

    def __enter__(self) -> 'Pkcs11AESKey':
        """Context manager entry."""
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None
    ) -> None:
        """Context manager exit."""
        self.close()

class Pkcs11RSAPrivateKey(Pkcs11PrivateKey, rsa.RSAPrivateKey):
    """PKCS#11-backed RSA private key implementation.

    This class provides methods for generating, importing, and using RSA private keys stored on a PKCS#11 token.
    It implements the cryptography RSAPrivateKey interface and supports signing, encryption,
    and key management operations.
    """

    DEFAULT_PUBLIC_TEMPLATE: ClassVar[dict[Attribute, Any]] = {
        Attribute.CLASS: ObjectClass.PUBLIC_KEY,
        Attribute.KEY_TYPE: KeyType.RSA,
        Attribute.TOKEN: True,
        Attribute.PRIVATE: False,
        Attribute.VERIFY: True,
        Attribute.ENCRYPT: True,
        Attribute.WRAP: False,
    }

    DEFAULT_PRIVATE_TEMPLATE: ClassVar[dict[Attribute, Any]] = {
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        Attribute.KEY_TYPE: KeyType.RSA,
        Attribute.DECRYPT: True,
        Attribute.SIGN: True,
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: False,
        Attribute.MODIFIABLE: True,
        Attribute.TOKEN: True,
    }

    def __init__(
        self, lib_path: str, token_label: str, user_pin: str, key_label: str, slot_id: int | None = None
    ) -> None:
        """Initialize an RSA private key handler for PKCS#11 tokens.

        Args:
            lib_path (str): Path to the PKCS#11 library.
            token_label (str): Label of the HSM token.
            user_pin (str): User PIN for the token.
            key_label (str): Label of the RSA private key.
            slot_id (int, optional): Specific slot ID to use. If None, uses token_label to find slot.
        """
        super().__init__(lib_path, token_label, user_pin, key_label, slot_id)
        self._public_key: ec.EllipticCurvePublicKey | None = None

    def load_key(self) -> None:
        """Load RSA private key from token using the specified label.

        Raises:
            ValueError: If the RSA private key is not found.
        """
        if self._key is not None:
            return
        if self._session is None:
            msg = 'PKCS#11 session is not initialized.'
            self._raise_value_error(msg)

        try:
            self._key = self._session.get_key(
                label=self._key_label, key_type=KeyType.RSA, object_class=ObjectClass.PRIVATE_KEY
            )
        except NoSuchKey as e:
            msg = f"RSA private key with label '{self._key_label}' not found on token '{self._token_label}'."
            raise ValueError(msg) from e

    def generate_key(
        self,
        key_length: int = 2048,
        public_template: dict[Attribute, Any] | None = None,
        private_template: dict[Attribute, Any] | None = None,
    ) -> None:
        """Generate RSA key pair and store handles on the token.

        Args:
            key_length (int): Length of the RSA key in bits (default 2048).
            public_template (Optional[Dict[Attribute, Any]]): Template for public key attributes.
            private_template (Optional[Dict[Attribute, Any]]): Template for private key attributes.

        Raises:
            ValueError: If a key with the same label already exists.
        """
        if self._key_exists(KeyType.RSA, ObjectClass.PRIVATE_KEY):
            token_label = getattr(self._token, 'label', self._token_label)
            msg = f"RSA key with label '{self._key_label}' already exists on token '{token_label}'."
            self._raise_value_error(msg)

        final_public_template = dict(self.DEFAULT_PUBLIC_TEMPLATE).copy()
        final_public_template[Attribute.LABEL] = self._key_label
        if public_template:
            final_public_template.update(public_template)

        final_private_template = dict(self.DEFAULT_PRIVATE_TEMPLATE).copy()
        final_private_template[Attribute.LABEL] = self._key_label
        if private_template:
            final_private_template.update(private_template)

        if self._session is None:
            self._initialize()
        if self._session is None:
            msg = 'PKCS#11 session is not initialized.'
            self._raise_value_error(msg)

        _pub, priv = self._session.generate_keypair(
            KeyType.RSA,
            key_length,
            public_template=final_public_template,
            private_template=final_private_template,
            store=True,
        )

        self._key = priv
        self._public_key = None

    def _raise(self, msg: str, exc_type: type[Exception] = Exception) -> Never:
        raise exc_type(msg)

    def import_private_key_from_crypto(self, private_key: rsa.RSAPrivateKey) -> bool:
        """Import an RSA private key from cryptography RSAPrivateKey object into the HSM.

        Args:
            private_key: The RSA private key object from cryptography library

        Returns:
            bool: True if import was successful, False otherwise
        """
        try:
            if not isinstance(private_key, rsa.RSAPrivateKey):
                self._raise('Expected RSA private key', TypeError)

            private_numbers = private_key.private_numbers()
            public_numbers = private_numbers.public_numbers

            def int_to_bytes(value: int) -> bytes:
                """Convert integer to bytes in big-endian format."""
                bit_length = value.bit_length()
                byte_length = (bit_length + 7) // 8
                return value.to_bytes(byte_length, byteorder='big')

            private_template = {
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.LABEL: self._key_label,
                Attribute.ID: self._key_label.encode(),
                Attribute.TOKEN: True,
                Attribute.PRIVATE: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
                Attribute.SIGN: True,
                Attribute.DECRYPT: True,
                Attribute.UNWRAP: False,
                Attribute.MODULUS: int_to_bytes(public_numbers.n),
                Attribute.PUBLIC_EXPONENT: int_to_bytes(public_numbers.e),
                Attribute.PRIVATE_EXPONENT: int_to_bytes(private_numbers.d),
                Attribute.PRIME_1: int_to_bytes(private_numbers.p),
                Attribute.PRIME_2: int_to_bytes(private_numbers.q),
                Attribute.EXPONENT_1: int_to_bytes(private_numbers.dmp1),
                Attribute.EXPONENT_2: int_to_bytes(private_numbers.dmq1),
                Attribute.COEFFICIENT: int_to_bytes(private_numbers.iqmp),
            }

            public_template = {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.LABEL: self._key_label,
                Attribute.ID: self._key_label.encode(),
                Attribute.TOKEN: True,
                Attribute.PRIVATE: False,
                Attribute.VERIFY: True,
                Attribute.ENCRYPT: True,
                Attribute.WRAP: False,
                Attribute.MODULUS: int_to_bytes(public_numbers.n),
                Attribute.PUBLIC_EXPONENT: int_to_bytes(public_numbers.e),
            }

            if self._key_exists(KeyType.RSA, ObjectClass.PRIVATE_KEY):
                msg = f"Key with label '{self._key_label}' already exists"
                self._raise_value_error(msg)

            if self._session is None:
                self._initialize()
            if self._session is None:
                msg = 'PKCS#11 session is not initialized.'
                self._raise_value_error(msg)

            private_key_obj = self._session.create_object(private_template)

            self._session.create_object(public_template)

        except Exception:
            self.logger.exception('Failed to import RSA private key from PEM')
            return False
        else:
            self._key = private_key_obj
            self._public_key = None

            return True

    def sign(
        self,
        data: bytes | bytearray | memoryview,
        padding: asym_padding.AsymmetricPadding,
        algorithm: hashes.HashAlgorithm | Prehashed,
    ) -> bytes:
        """Sign the provided data using the RSA private key with PKCS#1 v1.5 padding.

        Args:
            data (bytes): Data to be signed.
            padding (asym_padding.AsymmetricPadding): Padding scheme to use (must be PKCS1v15).
            algorithm (hashes.HashAlgorithm): Hash algorithm to use for signing.

        Returns:
            bytes: The RSA signature.

        Raises:
            NotImplementedError: If padding is not PKCS1v15.
            ValueError: If Prehashed digest is used.
        """
        def _raise_unsupported_padding() -> Never:
            msg = 'Only PKCS#1 v1.5 supported.'
            raise NotImplementedError(msg)

        if self._key is None:
            self.load_key()
        if self._key is None:
            msg = 'RSA private key is not loaded.'
            self._raise_value_error(msg)

        if not isinstance(padding, asym_padding.PKCS1v15):
            _raise_unsupported_padding()

        if isinstance(algorithm, Prehashed):
            msg = 'Prehashed digests not supported.'
            raise TypeError(msg)

        digest = hashes.Hash(algorithm)
        digest.update(data)
        digest_bytes = digest.finalize()

        return self._key.sign(digest_bytes, mechanism=Mechanism.RSA_PKCS)

    def public_key(self) -> RSAPublicKey:
        """Return the cached or retrieved RSA public key.

        Returns:
            RSAPublicKey: The RSA public key.

        Raises:
            ValueError: If the public key is not found or invalid.
        """
        if self._public_key:
            return self._public_key  # type: ignore[return-value]
        if self._session is None:
            self._initialize()
        if self._session is None:
            msg = 'PKCS#11 session is not initialized.'
            self._raise_value_error(msg)

        try:
            public = self._session.get_key(
                label=self._key_label, key_type=KeyType.RSA, object_class=ObjectClass.PUBLIC_KEY
            )
        except NoSuchKey as e:
            msg = f"RSA public key with label '{self._key_label}' not found on token '{self._token_label}'."
            raise ValueError(msg) from e

        n = public[Attribute.MODULUS]
        pub_e = public[Attribute.PUBLIC_EXPONENT]
        n = int.from_bytes(n, 'big') if isinstance(n, bytes) else n
        pub_e = int.from_bytes(pub_e, 'big') if isinstance(pub_e, bytes) else pub_e

        return rsa.RSAPublicNumbers(pub_e, n).public_key()

    @property
    def key_size(self) -> int:
        """Return the RSA key size in bits.

        Returns:
            int: The key size.
        """
        if self._key is None:
            self.load_key()
        if self._key is None:
            msg = 'RSA private key is not loaded and key size cannot be determined.'
            self._raise_value_error(msg)
        return self._key.key_length

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt the given plaintext using the RSA public key with PKCS#1 v1.5 padding.

        Args:
            plaintext (bytes): Data to be encrypted.

        Returns:
            bytes: The encrypted ciphertext.

        Raises:
            NoSuchKey: If the public key is not found.
        """
        if self._session is None:
            self._initialize()
        if self._session is None:
            msg = 'PKCS#11 session is not initialized.'
            self._raise_value_error(msg)
        try:
            public_key = self._session.get_key(
                label=self._key_label, key_type=KeyType.RSA, object_class=ObjectClass.PUBLIC_KEY
            )
            encrypted_data = public_key.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS)
            if not isinstance(encrypted_data, bytes):
                msg = 'Encrypted data is not of type bytes.'
                self._raise_type_error(msg)
            return bytes(encrypted_data)
        except NoSuchKey as e:
            msg = f"RSA public key with label '{self._key_label}' not found."
            raise ValueError(msg) from e

    def decrypt(self, ciphertext: bytes, padding: asym_padding.AsymmetricPadding) -> bytes:
        """Decrypt the given ciphertext using the RSA private key.

        Args:
            ciphertext (bytes): Data to be decrypted.
            padding (asym_padding.AsymmetricPadding): Padding scheme to use (PKCS1v15 or OAEP).

        Returns:
            bytes: The decrypted plaintext.

        Raises:
            NotImplementedError: If the padding is not supported.
        """
        if self._key is None:
            self.load_key()

        if self._key is None:
            msg = 'RSA private key is not loaded.'
            self._raise_value_error(msg)

        if isinstance(padding, asym_padding.PKCS1v15):
            mechanism = Mechanism.RSA_PKCS
        elif isinstance(padding, asym_padding.OAEP):
            mechanism = Mechanism.RSA_PKCS_OAEP
        else:
            msg = f'Unsupported padding: {type(padding)}'
            raise NotImplementedError(msg)

        return self._key.decrypt(ciphertext, mechanism=mechanism)

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        """Not implemented for PKCS#11 private keys.

        Raises:
            NotImplementedError: Always.
        """
        msg = 'Private numbers are not accessible.'
        raise NotImplementedError(msg)

    def private_bytes(
        self, encoding: Encoding, format: PrivateFormat, encryption_algorithm: KeySerializationEncryption
    ) -> bytes:
        """Not implemented for PKCS#11 private keys.

        Raises:
            NotImplementedError: Always.
        """
        msg = 'Export of private key bytes is not supported.'
        raise NotImplementedError(msg)

    def __copy__(self) -> 'Pkcs11RSAPrivateKey':
        """Return the same instance since copying is not supported for PKCS#11 keys.

        Returns:
            Pkcs11RSAPrivateKey: The current instance.
        """
        return self


class Pkcs11ECPrivateKey(Pkcs11PrivateKey, ec.EllipticCurvePrivateKey):
    """PKCS#11-backed Elliptic Curve (EC) private key implementation.

    This class provides methods for generating, importing, and using EC private keys stored on a PKCS#11 token.
    It implements the cryptography EllipticCurvePrivateKey interface and supports signing and key management operations.
    """

    CURVE_KEY_LENGTHS: ClassVar[dict[NamedCurve, int]] = {
        NamedCurve.SECP192R1: NamedCurve.SECP192R1.key_size,
        NamedCurve.SECP224R1: NamedCurve.SECP224R1.key_size,
        NamedCurve.SECP256K1: NamedCurve.SECP256K1.key_size,
        NamedCurve.SECP256R1: NamedCurve.SECP256R1.key_size,
        NamedCurve.SECP384R1: NamedCurve.SECP384R1.key_size,
        NamedCurve.SECP521R1: NamedCurve.SECP521R1.key_size,
    }

    EC_MECHANISMS: ClassVar[dict[type[hashes.HashAlgorithm], Mechanism]] = {
        hashes.SHA256: Mechanism.ECDSA_SHA256,
        hashes.SHA384: Mechanism.ECDSA_SHA384,
        hashes.SHA512: Mechanism.ECDSA_SHA512,
    }

    DEFAULT_PUBLIC_TEMPLATE: ClassVar[dict[Attribute, Any]] = {
        Attribute.VERIFY: True,
        Attribute.MODIFIABLE: True,
        Attribute.TOKEN: True,
    }

    DEFAULT_PRIVATE_TEMPLATE: ClassVar[dict[Attribute, Any]] = {
        Attribute.SIGN: True,
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: False,
        Attribute.MODIFIABLE: True,
        Attribute.TOKEN: True,
    }

    def __init__(
        self, lib_path: str, token_label: str, user_pin: str, key_label: str, slot_id: int | None = None
    ) -> None:
        """Initialize an EC private key handler for PKCS#11 tokens.

        Args:
            lib_path (str): Path to the PKCS#11 library.
            token_label (str): Label of the HSM token.
            user_pin (str): User PIN for the token.
            key_label (str): Label of the EC private key.
            slot_id (int, optional): Specific slot ID to use. If None, uses token_label to find slot.
        """
        super().__init__(lib_path, token_label, user_pin, key_label, slot_id)
        self._public_key: ec.EllipticCurvePublicKey | None = None

    def load_key(self) -> None:
        """Load EC private key from token using the specified label.

        Raises:
            ValueError: If the EC private key is not found.
        """
        if self._key is not None:
            return

        if self._session is None:
            self._initialize()
        if self._session is None:
            msg = 'PKCS#11 session is not initialized.'
            self._raise_value_error(msg)

        try:
            self._key = self._session.get_key(
                label=self._key_label, key_type=KeyType.EC, object_class=ObjectClass.PRIVATE_KEY
            )
        except NoSuchKey as e:
            msg = f"EC private key with label '{self._key_label}' not found on token '{self._token_label}'."
            raise ValueError(msg) from e

    def generate_key(
        self,
        curve: ec.EllipticCurve | None = None,
        public_template: dict[Attribute, Any] | None = None,
        private_template: dict[Attribute, Any] | None = None,
    ) -> None:
        """Generate EC key pair and store it on the token.

        Args:
            curve (ec.EllipticCurve): The elliptic curve to use (default SECP256R1).
            public_template (Optional[Dict[Attribute, Any]]): Template for public key attributes.
            private_template (Optional[Dict[Attribute, Any]]): Template for private key attributes.

        Raises:
            ValueError: If a key with the same label already exists or unsupported curve.
        """
        if curve is None:
            curve = ec.SECP256R1()
        if self._key_exists(KeyType.EC, ObjectClass.PRIVATE_KEY):
            token_label = getattr(self._token, 'label', self._token_label)
            msg = f"EC key with label '{self._key_label}' already exists on token '{token_label}'."
            raise ValueError(msg)

        named_curve = NamedCurve.from_curve(type(curve))
        key_length = self.CURVE_KEY_LENGTHS.get(named_curve)
        if key_length is None:
            msg = f'Unsupported curve: {curve.name}'
            raise ValueError(msg)

        # Create templates with label
        final_public_template = self.DEFAULT_PUBLIC_TEMPLATE.copy()
        final_public_template[Attribute.LABEL] = self._key_label
        if public_template:
            final_public_template.update(public_template)

        final_private_template = self.DEFAULT_PRIVATE_TEMPLATE.copy()
        final_private_template[Attribute.LABEL] = self._key_label
        if private_template:
            final_private_template.update(private_template)

        if self._session is None:
            self._initialize()
        if self._session is None:
            msg = 'PKCS#11 session is not initialized.'
            self._raise_value_error(msg)

        _, priv = self._session.generate_keypair(
            KeyType.EC,
            key_length,
            public_template=final_public_template,
            private_template=final_private_template,
            store=True,
        )

        self._key = priv
        self._public_key = None

    def sign(
    self,
    data: bytes | bytearray | memoryview,
    signature_algorithm: ec.EllipticCurveSignatureAlgorithm
) -> bytes:
        """Sign the provided data using the EC private key with ECDSA.

        Args:
            data (bytes): Data to be signed.
            signature_algorithm (ec.EllipticCurveSignatureAlgorithm): The signature algorithm to use for signing.

        Returns:
            bytes: The ECDSA signature.

        Raises:
            ValueError: If unsupported hash algorithm.
            NotImplementedError: If non-ECDSA algorithm is provided.
        """
        if self._key is None:
            self.load_key()

        if not isinstance(signature_algorithm, ec.ECDSA):
            msg = 'Only ECDSA is supported.'
            raise NotImplementedError(msg)

        if isinstance(signature_algorithm.algorithm, Prehashed):
            msg = 'Prehashed not supported.'
            self._raise_value_error(msg)

        digest = hashes.Hash(signature_algorithm.algorithm)
        digest.update(data)
        hashed = digest.finalize()

        if self._key is None:
            msg = 'EC private key is not loaded.'
            self._raise_value_error(msg)

        return self._key.sign(hashed, mechanism=Mechanism.ECDSA)

    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Return the cached or retrieved EC public key.

        Returns:
            ec.EllipticCurvePublicKey: The EC public key.

        Raises:
            ValueError: If the public key is not found or invalid.
        """
        if self._public_key:
            return self._public_key

        if self._session is None:
            self._initialize()
        if self._session is None:
            msg = 'PKCS#11 session is not initialized.'
            self._raise_value_error(msg)

        try:
            public = self._session.get_key(
                label=self._key_label, key_type=KeyType.EC, object_class=ObjectClass.PUBLIC_KEY
            )
        except NoSuchKey as e:
            msg = f"EC public key with label '{self._key_label}' not found on token '{self._token_label}'."
            raise ValueError(msg) from e

        try:
            ec_point = public[Attribute.EC_POINT]

            ec_uncompressed_point_prefix = 0x04
            ec_point_min_length = 3
            if not ec_point or len(ec_point) < ec_point_min_length or ec_point[0] != ec_uncompressed_point_prefix:
                msg = 'EC public key point is missing or has invalid format.'
                raise ValueError(msg)
            curve = self.curve
            coord_size = (curve.key_size + 7) // 8

            point_data = ec_point[1:]  # Skip the 0x04 prefix
            if len(point_data) != 2 * coord_size:
                msg = f'EC point data has invalid length: expected {2 * coord_size}, got {len(point_data)}.'
                raise ValueError(msg)

            x_bytes = point_data[:coord_size]
            y_bytes = point_data[coord_size:]

            x = int.from_bytes(x_bytes, 'big')
            y = int.from_bytes(y_bytes, 'big')

        except (AttributeError, KeyError, IndexError, TypeError) as e:
            msg = f'Failed to extract EC public key point: {e}'
            raise ValueError(msg) from e

        pub_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        self._public_key = pub_numbers.public_key()
        return self._public_key

    def import_private_key_from_crypto(self, private_key: ec.EllipticCurvePrivateKey) -> bool:
        """Import an EC private key from cryptography EllipticCurvePrivateKey object into the HSM.

        Args:
            private_key: The EC private key object from cryptography library

        Returns:
            bool: True if import was successful, False otherwise
        """
        try:
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                msg = 'Expected EC private key'
                self._raise_value_error(msg)

            private_numbers = private_key.private_numbers()
            public_numbers = private_numbers.public_numbers

            curve = private_numbers.public_numbers.curve

            if isinstance(curve, ec.SECP256R1):
                curve_params = b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07'  # secp256r1 OID
            elif isinstance(curve, ec.SECP384R1):
                curve_params = b'\x06\x05\x2b\x81\x04\x00\x22'  # secp384r1 OID
            elif isinstance(curve, ec.SECP521R1):
                curve_params = b'\x06\x05\x2b\x81\x04\x00\x23'  # secp521r1 OID
            else:
                msg = f'Unsupported curve: {curve.name}'
                self._raise_value_error(msg)

            def int_to_bytes(value: int, byte_length: int) -> bytes:
                """Convert integer to bytes in big-endian format with specified length."""
                return value.to_bytes(byte_length, byteorder='big')

            key_size = curve.key_size
            coord_size = (key_size + 7) // 8
            private_value_size = coord_size

            # Encode public key point as uncompressed format (0x04 + x + y)
            public_point = (
                b'\x04' + int_to_bytes(public_numbers.x, coord_size) + int_to_bytes(public_numbers.y, coord_size)
            )

            private_template = {
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.KEY_TYPE: KeyType.EC,
                Attribute.LABEL: self._key_label,
                Attribute.ID: self._key_label.encode(),
                Attribute.TOKEN: True,
                Attribute.PRIVATE: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
                Attribute.SIGN: True,
                Attribute.EC_PARAMS: curve_params,
                Attribute.VALUE: int_to_bytes(private_numbers.private_value, private_value_size),
            }

            public_template = {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.EC,
                Attribute.LABEL: self._key_label,
                Attribute.ID: self._key_label.encode(),
                Attribute.TOKEN: True,
                Attribute.PRIVATE: False,
                Attribute.VERIFY: True,
                Attribute.EC_PARAMS: curve_params,
                Attribute.EC_POINT: public_point,
            }

            if self._key_exists(KeyType.EC, ObjectClass.PRIVATE_KEY):
                msg = f"Key with label '{self._key_label}' already exists"
                self._raise_value_error(msg)

            if self._session is None:
                self._initialize()
            if self._session is None:
                msg = 'PKCS#11 session is not initialized.'
                self._raise_value_error(msg)

            private_key_obj = self._session.create_object(private_template)

            self._session.create_object(public_template)

            self._key = private_key_obj
            self._public_key = None

        except Exception:
            self.logger.exception('Failed to import EC private key from cryptography object')
            return False
        else:
            return True

    @property
    def key_size(self) -> int:
        """Return the EC key size in bits.

        Returns:
            int: The key size.
        """
        if self._key is None:
            self.load_key()
        if self._key is None:
            msg = 'EC private key is not loaded and key size cannot be determined.'
            self._raise_value_error(msg)
        return self._key.key_length

    def encrypt(self, plaintext: bytes) -> None:
        """Not implemented for EC keys.

        Raises:
            NotImplementedError: Always.
        """
        msg = 'EC encryption is not supported by PKCS#11.'
        raise NotImplementedError(msg)

    def decrypt(self, ciphertext: bytes, padding: asym_padding.AsymmetricPadding) -> None:
        """Not implemented for EC keys.

        Raises:
            NotImplementedError: Always.
        """
        msg = 'EC decryption is not supported by PKCS#11.'
        raise NotImplementedError(msg)

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        """Not implemented for PKCS#11 private keys.

        Raises:
            NotImplementedError: Always.
        """
        msg = 'Private numbers not accessible.'
        raise NotImplementedError(msg)

    def private_bytes(
        self, _encoding: Encoding, _format: PrivateFormat, _encryption_algorithm: KeySerializationEncryption
    ) -> bytes:
        """Not implemented for PKCS#11 private keys.

        Raises:
            NotImplementedError: Always.
        """
        msg = 'Export of private key is not supported.'
        raise NotImplementedError(msg)

    def exchange(self, algorithm: Any, peer_public_key: Any) -> bytes:
        """Not implemented for EC keys.

        Raises:
            NotImplementedError: Always.
        """
        msg = 'Key exchange not implemented.'
        raise NotImplementedError(msg)

    @property
    def curve(self) -> ec.EllipticCurve:
        """Return the elliptic curve used by the private key.

        Returns:
            ec.EllipticCurve: The curve object.

        Raises:
            ValueError: If the curve parameters cannot be determined or are not supported.
        """
        if self._key is None:
            self.load_key()
        if self._key is None:
            msg = 'EC private key is not loaded and curve cannot be determined.'
            raise ValueError(msg)

        try:
            curve_params = self._key[Attribute.EC_PARAMS]
        except (KeyError, AttributeError) as e:
            msg = f'Failed to get EC_PARAMS from key: {e}'
            raise ValueError(msg) from e

        curve_oid_map = {
            b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07': ec.SECP256R1(),  # secp256r1
            b'\x06\x05\x2b\x81\x04\x00\x22': ec.SECP384R1(),  # secp384r1
            b'\x06\x05\x2b\x81\x04\x00\x23': ec.SECP521R1(),  # secp521r1
        }

        curve = curve_oid_map.get(curve_params)
        if curve is None:
            msg = f'Unsupported EC curve with params: {curve_params.hex() if curve_params else "None"}'
            raise ValueError(msg)

        return curve

    def __copy__(self) -> 'Pkcs11ECPrivateKey':
        """Return the same instance since copying is not supported for PKCS#11 keys.

        Returns:
            Pkcs11ECPrivateKey: The current instance.
        """
        return self
