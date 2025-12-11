"""Module that contains the CredentialModel."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _
from management.models import KeyStorageConfig, PKCS11Token
from management.pkcs11_util import Pkcs11AESKey, Pkcs11ECPrivateKey, Pkcs11RSAPrivateKey
from trustpoint.logger import LoggerMixin
from trustpoint_core import oid
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeyLocation,
    PrivateKeySerializer,
)
from util.db import CustomDeleteActionModel
from util.encrypted_fields import EncryptedCharField
from util.field import UniqueNameValidator

from pki.models import CertificateModel

if TYPE_CHECKING:
    from typing import Any, ClassVar

    from cryptography.hazmat.primitives import hashes
    from django.db.models import QuerySet
    from trustpoint_core.crypto_types import PrivateKey


__all__ = [
    'CertificateChainOrderModel',
    'CredentialAlreadyExistsError',
    'CredentialModel',
    'IDevIDReferenceModel',
    'OwnerCredentialModel',
    'PKCS11Key',
    'PrimaryCredentialCertificate',
]


class CredentialAlreadyExistsError(ValidationError):
    """The CredentialAlreadyExistsError is raised if a credential already exists in the database."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the CredentialAlreadyExistsError with a default message."""
        super().__init__(_('Credential already exists.'), *args, **kwargs)


class PKCS11Key(models.Model):
    """Model representing a private key stored in a PKCS#11 HSM/token."""

    class KeyType(models.TextChoices):
        """Supported key types in PKCS#11."""
        RSA = 'rsa', _('RSA')
        EC = 'ec', _('Elliptic Curve')
        AES = 'aes', _('AES')

    token_label = models.CharField(
        max_length=255,
        verbose_name=_('Token Label'),
        help_text=_('Label of the HSM token containing the private key')
    )

    key_label = models.CharField(
        max_length=255,
        verbose_name=_('Key Label'),
        help_text=_('Unique label of the private key within the token')
    )

    key_type = models.CharField(
        max_length=10,
        choices=KeyType.choices,
        verbose_name=_('Key Type'),
        help_text=_('Type of the cryptographic key (RSA or EC)')
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        """Meta class to define unique constraints and verbose names for the PKCS11Key model."""

        unique_together: ClassVar = [['token_label', 'key_label']]
        verbose_name = _('PKCS#11 Private Key')
        verbose_name_plural = _('PKCS#11 Private Keys')

    def __str__(self) -> str:
        """Return a string representation of the PKCS11Key instance."""
        return f'{self.token_label}/{self.key_label} ({self.key_type})'

    def get_pkcs11_key_instance(
        self, lib_path: str, user_pin: str
    ) -> Pkcs11RSAPrivateKey | Pkcs11ECPrivateKey | Pkcs11AESKey:
        """Get the appropriate PKCS#11 key instance."""
        if self.key_type == self.KeyType.RSA:
            return Pkcs11RSAPrivateKey(
                lib_path=lib_path,
                token_label=self.token_label,
                user_pin=user_pin,
                key_label=self.key_label
            )
        if self.key_type == self.KeyType.EC:
            return Pkcs11ECPrivateKey(
                lib_path=lib_path,
                token_label=self.token_label,
                user_pin=user_pin,
                key_label=self.key_label
            )
        if self.key_type == self.KeyType.AES:
            return Pkcs11AESKey(
                lib_path=lib_path,
                token_label=self.token_label,
                user_pin=user_pin,
                key_label=self.key_label
            )
        msg = f'Unsupported key type: {self.key_type}'
        raise TypeError(msg)


class CredentialModel(LoggerMixin, CustomDeleteActionModel):
    """The CredentialModel that holds all local credentials used by the Trustpoint.

    This model holds both local unprotected credentials, for which the keys and certificates are stored
    in the DB, but also credentials that are stored within an HSM or TPM utilizing PKCS#11.

    PKCS#11 credentials are not yet supported.
    """

    class CredentialTypeChoice(models.IntegerChoices):
        """The CredentialTypeChoice defines the type of the credential and thus implicitly restricts its usage.

        It is intended to limit the credential usage to specific cases, e.g. usage as Issuing CA.
        The abstractions using the CredentialModel are responsible to check that the credential has
        the correct and expected CredentialTypeChoice.
        """

        TRUSTPOINT_TLS_SERVER = 0, _('Trustpoint TLS Server')
        ROOT_CA = 1, _('Root CA')
        ISSUING_CA = 2, _('Issuing CA')
        ISSUED_CREDENTIAL = 3, _('Issued Credential')
        DEV_OWNER_ID = 4, _('DevOwnerID')
        SIGNER = 5, _('Signer')

    credential_type = models.IntegerField(verbose_name=_('Credential Type'), choices=CredentialTypeChoice)
    private_key = EncryptedCharField(verbose_name=_('Private key (PEM)'), max_length=65536, default='', blank=True)
    pkcs11_private_key = models.ForeignKey(
        PKCS11Key,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name=_('PKCS#11 Private Key'),
        help_text=_('Reference to HSM-stored private key')
    )

    certificate = models.ForeignKey(
        CertificateModel, on_delete=models.PROTECT, related_name='credential_set', blank=False
    )

    certificates = models.ManyToManyField[CertificateModel, 'PrimaryCredentialCertificate'](
        CertificateModel, through='PrimaryCredentialCertificate', blank=False, related_name='credential'
    )
    certificate_chain: models.ManyToManyField[CertificateModel, CertificateChainOrderModel] = models.ManyToManyField(
        CertificateModel, blank=True,
        through='CertificateChainOrderModel',
        through_fields=('credential', 'certificate'),
        related_name='credential_certificate_chains'
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    def __repr__(self) -> str:
        """Returns a string representation of this CredentialModel entry."""
        return f'CredentialModel(credential_type={self.credential_type}, certificate=)'

    def __str__(self) -> str:
        """Returns a human-readable string that represents this CredentialModel entry.

        Returns:
            str: Human-readable string that represents this CredentialModel entry.
        """
        return self.__repr__()

    def clean(self) -> None:
        """Validates the CredentialModel instance."""
        qs = self.primarycredentialcertificate_set.filter(is_primary=True)
        if qs.count() > 1:
            exc_msg = 'A credential can only have one primary certificate.'
            raise ValidationError(exc_msg)

        if qs.get().certificate != self.certificate:
            exc_msg = ('The ForeignKey certificate must be identical to the one '
                       'marked primary in the primarycredentialcertificate_set.')

            raise ValidationError(exc_msg)

    @classmethod
    def save_credential_serializer(
        cls, credential_serializer: CredentialSerializer, credential_type: CredentialModel.CredentialTypeChoice
    ) -> CredentialModel:
        """This method will try to normalize the credential_serializer and then save it to the database.

        Args:
            credential_serializer: The credential serializer to store in the database.
            credential_type: The credential type to set.

        Returns:
            CredentialModel: The stored credential model.
        """
        return cls._save_normalized_credential_serializer(
            normalized_credential_serializer=credential_serializer, credential_type=credential_type
        )

    @property
    def ordered_certificate_chain_queryset(self) -> QuerySet[CertificateChainOrderModel]:
        """Gets the ordered certificate chain queryset."""
        return self.certificatechainordermodel_set.order_by('order')

    @classmethod
    def _import_private_key_to_hsm(
            cls,
            crypto_private_key: PrivateKey,
            token_config: PKCS11Token,
            key_label: str,
    ) -> PKCS11Key:
        """Import a private key to HSM and create corresponding PKCS11Key model.

        Args:
            crypto_private_key: The private key from cryptography library
            key_label: Custom label for the key (auto-generated if None)
            token_config: PKCS11Token configuration

        Returns:
            PKCS11Key: The created model instance referencing the HSM key

        Raises:
            RuntimeError: If HSM import fails
            ValueError: If unsupported key type
            NotImplementedError: If EC key import not yet supported
        """
        if not token_config:
            msg = 'No PKCS#11 token configuration found'
            raise RuntimeError(msg)

        if key_label is None:
            err_msg = 'No Key Label found'
            raise ValueError(err_msg)

        pkcs11_key_handler: Pkcs11RSAPrivateKey | Pkcs11ECPrivateKey | None = None
        try:
            if isinstance(crypto_private_key, rsa.RSAPrivateKey):
                key_type = PKCS11Key.KeyType.RSA

                pkcs11_key_handler = Pkcs11RSAPrivateKey(
                    lib_path=token_config.module_path,
                    token_label=token_config.label,
                    user_pin=token_config.get_pin(),
                    key_label=key_label,
                )

                if not pkcs11_key_handler.import_private_key_from_crypto(crypto_private_key):
                    msg = 'Failed to import RSA private key to HSM'
                    raise RuntimeError(msg)

            elif isinstance(crypto_private_key, ec.EllipticCurvePrivateKey):
                key_type = PKCS11Key.KeyType.EC

                pkcs11_key_handler = Pkcs11ECPrivateKey(
                    lib_path=token_config.module_path,
                    token_label=token_config.label,
                    user_pin=token_config.get_pin(),
                    key_label=key_label,
                )

                if not pkcs11_key_handler.import_private_key_from_crypto(crypto_private_key):
                    msg = 'Failed to import EC private key to HSM'
                    raise RuntimeError(msg)

            else:
                msg = f'Unsupported private key type: {type(crypto_private_key)}'
                raise TypeError(msg)

            return PKCS11Key.objects.create(
                token_label=token_config.label,
                key_label=key_label,
                key_type=key_type
            )


        finally:
            if pkcs11_key_handler:
                pkcs11_key_handler.close()

    @classmethod
    def _create_private_key_in_hsm(
            cls,
            key_type: type[PrivateKey],
            token_config: PKCS11Token,
            key_label: str,
            key_size: int | None = None,
            key_curve: ec.EllipticCurve | None = None,
    ) -> PKCS11Key:
        """Generate a new private key in HSM and create corresponding PKCS11Key model.

        Args:
            key_type: Type of key to generate ('rsa.PrivateKey' or 'ec.PrivateKey')
            token_config: PKCS11Token configuration
            key_label: Label for the new key in HSM
            key_size: For RSA keys: key size in bits (e.g., 2048, 4096)
            key_curve: For EC keys: curve instance (e.g., ec.SECP256R1())

        Returns:
            PKCS11Key: The created model instance referencing the HSM key

        Raises:
            RuntimeError: If HSM key generation fails
            ValueError: If unsupported key type or invalid parameters
            NotImplementedError: If EC key generation not yet supported
        """
        cls._validate_hsm_inputs(token_config, key_label, key_type, key_size, key_curve)

        pkcs11_key_handler = None
        try:
            pkcs11_key_handler, model_key_type = cls._initialize_key_handler(
                key_type, token_config, key_label, key_size, key_curve
            )

            return PKCS11Key.objects.create(
                token_label=token_config.label,
                key_label=key_label,
                key_type=model_key_type
            )


        finally:
            if pkcs11_key_handler:
                pkcs11_key_handler.close()

    @staticmethod
    def _validate_hsm_inputs(
        token_config: PKCS11Token,
        key_label: str,
        key_type: type[PrivateKey],
        key_size: int | None,
        key_curve: ec.EllipticCurve | None,
    ) -> None:
        """Validates the inputs for HSM key creation."""
        if not token_config:
            msg = 'No PKCS#11 token configuration found'
            raise RuntimeError(msg)

        if key_label is None:
            msg = 'No Key Label found'
            raise ValueError(msg)

        if key_type == rsa.RSAPrivateKey:
            if key_size is None:
                msg = 'key_size parameter is required for RSA keys'
                raise ValueError(msg)
            if key_curve is not None:
                msg = 'curve parameter should not be provided for RSA keys'
                raise ValueError(msg)
            min_rsa_key_size = 1024
            if key_size < min_rsa_key_size:
                msg = 'RSA key size must be at least 1024 bits'
                raise ValueError(msg)

        elif key_type == ec.EllipticCurvePrivateKey:
            if key_curve is None:
                msg = 'curve parameter is required for EC keys'
                raise ValueError(msg)
            if key_size is not None:
                msg = 'key_size parameter should not be provided for EC keys'
                raise ValueError(msg)

        else:
            msg = f"Unsupported key type: {key_type}. Supported types: 'rsa', 'ec'"
            raise TypeError(msg)

    @staticmethod
    def _initialize_key_handler(
        key_type: type[PrivateKey],
        token_config: PKCS11Token,
        key_label: str,
        key_size: int | None,
        key_curve: ec.EllipticCurve | None,
    ) -> tuple[Pkcs11RSAPrivateKey | Pkcs11ECPrivateKey, str]:
        """Initializes the PKCS#11 key handler."""
        if key_type == rsa.RSAPrivateKey:
            rsa_pkcs11_key_handler: Pkcs11RSAPrivateKey = Pkcs11RSAPrivateKey(
                lib_path=token_config.module_path,
                token_label=token_config.label,
                user_pin=token_config.get_pin(),
                key_label=key_label,
            )
            if key_size is None:
                msg = 'key_size must be provided for RSA keys.'
                raise ValueError(msg)
            rsa_pkcs11_key_handler.generate_key(key_length=key_size)
            return rsa_pkcs11_key_handler, PKCS11Key.KeyType.RSA

        if key_type == ec.EllipticCurvePrivateKey:
            ec_pkcs11_key_handler: Pkcs11ECPrivateKey = Pkcs11ECPrivateKey(
                lib_path=token_config.module_path,
                token_label=token_config.label,
                user_pin=token_config.get_pin(),
                key_label=key_label,
            )
            ec_pkcs11_key_handler.generate_key(curve=key_curve)
            return ec_pkcs11_key_handler, PKCS11Key.KeyType.EC

        msg = f"Unsupported key type: {key_type}. Supported types: 'rsa', 'ec'"
        raise TypeError(msg)

    @classmethod
    @transaction.atomic
    def _save_normalized_credential_serializer(
        cls,
        normalized_credential_serializer: CredentialSerializer,
        credential_type: CredentialModel.CredentialTypeChoice,
    ) -> CredentialModel:
        """This method will store a credential that is expected to be normalized."""
        cls.logger.info(
            'Starting to save credential of type: %s',
            credential_type
        )
        certificate = cls._validate_and_save_certificate(normalized_credential_serializer)
        pkcs11_private_key, private_key_pem = cls._process_private_key(
            normalized_credential_serializer
        )
        credential_model = cls._create_credential_model(
            certificate, credential_type, private_key_pem, pkcs11_private_key
        )
        cls._save_additional_certificates(
            credential_model, normalized_credential_serializer.additional_certificates
        )
        return credential_model

    @staticmethod
    def _validate_and_save_certificate(
        normalized_credential_serializer: CredentialSerializer
    ) -> CertificateModel:
        """Validates and saves the certificate from the provided serializer.

        Args:
            normalized_credential_serializer (CredentialSerializer): The serializer containing
                the certificate to be validated and saved.

        Raises:
            ValueError: If the certificate in the serializer is None.

        Returns:
            CertificateModel: The saved certificate model instance.
        """
        # TODO(AlexHx8472): Verify that the credential is valid in respect to the credential_type!!!  # noqa: FIX002
        if normalized_credential_serializer.certificate is None:
            msg = 'Certificate cannot be None'
            raise ValueError(msg)
        return CertificateModel.save_certificate(normalized_credential_serializer.certificate)

    @classmethod
    def _process_private_key(
        cls,
        normalized_credential_serializer: CredentialSerializer,
    ) -> tuple[PKCS11Key | None, str]:
        """Processes the private key based on its location and returns the appropriate values."""
        pkcs11_private_key = None
        private_key_pem = ''
        if normalized_credential_serializer.private_key_reference.location in [
            PrivateKeyLocation.HSM_GENERATED, PrivateKeyLocation.HSM_PROVIDED
        ]:
            pkcs11_private_key = cls._handle_hsm_key(normalized_credential_serializer)
        else:
            private_key_serializer = normalized_credential_serializer.get_private_key_serializer()
            if private_key_serializer:
                private_key_pem = private_key_serializer.as_pkcs8_pem().decode()
        return pkcs11_private_key, private_key_pem

    @classmethod
    def _handle_hsm_key(cls, normalized_credential_serializer: CredentialSerializer) -> PKCS11Key:
        """Handles the creation or import of a private key in an HSM (Hardware Security Module)."""
        try:
            storage_config = KeyStorageConfig.get_config()
            if storage_config.storage_type == KeyStorageConfig.StorageType.SOFTWARE:
                msg = (
                    'HSM private key location specified but KeyStorageConfig is set to SOFTWARE. '
                )
                raise ValueError(msg)
        except KeyStorageConfig.DoesNotExist:
            cls.logger.warning('KeyStorageConfig does not exist, proceeding with HSM operation')

        token_config = PKCS11Token.objects.first()
        if not token_config:
            msg = 'No PKCS#11 token config stored'
            raise ValueError(msg)
        hsm_key_reference = normalized_credential_serializer.get_hsm_key_reference()
        if hsm_key_reference is None:
            msg = 'HSM key reference is required for HSM private key locations'
            raise ValueError(msg)
        if hsm_key_reference.key_label is None:
            msg = 'HSM key reference key_label is required for HSM private key locations'
            raise ValueError(msg)
        if normalized_credential_serializer.private_key_reference.location == PrivateKeyLocation.HSM_GENERATED:
            if hsm_key_reference.key_type is None:
                msg = 'key_type must be provided for HSM_GENERATED keys'
                raise ValueError(msg)
            return cls._create_private_key_in_hsm(
                key_type=hsm_key_reference.key_type,
                key_label=hsm_key_reference.key_label,
                key_size=hsm_key_reference.key_size,
                key_curve=cast('ec.EllipticCurve | None', hsm_key_reference.key_curve),
                token_config=token_config
            )
        if normalized_credential_serializer.private_key_reference.location == PrivateKeyLocation.HSM_PROVIDED:
            private_key_serializer = normalized_credential_serializer.get_private_key_serializer()
            if private_key_serializer is None:
                msg = 'Private key serializer is required for HSM_PROVIDED'
                raise ValueError(msg)
            crypto_private_key = private_key_serializer.as_crypto()
            return cls._import_private_key_to_hsm(
                key_label=hsm_key_reference.key_label,
                token_config=token_config,
                crypto_private_key=crypto_private_key
            )
        msg = f'Unsupported HSM location: {normalized_credential_serializer.private_key_reference.location}'
        raise ValueError(msg)

    @classmethod
    def _create_credential_model(
        cls,
        certificate: CertificateModel,
        credential_type: CredentialModel.CredentialTypeChoice,
        private_key_pem: str,
        pkcs11_private_key: PKCS11Key | None,
    ) -> CredentialModel:
        """Creates and saves a CredentialModel instance."""
        credential_model = cls.objects.create(
            certificate=certificate,
            credential_type=credential_type,
            private_key=private_key_pem,
            pkcs11_private_key=pkcs11_private_key
        )
        PrimaryCredentialCertificate.objects.create(
            certificate=certificate, credential=credential_model, is_primary=True
        )
        return credential_model

    @staticmethod
    def _save_additional_certificates(
        credential_model: CredentialModel, additional_certificates: list[x509.Certificate]
    ) -> None:
        """Saves additional certificates in the certificate chain."""
        for order, certificate in enumerate(additional_certificates):
            certificate_model = CertificateModel.save_certificate(certificate)
            CertificateChainOrderModel.objects.create(
                certificate=certificate_model,
                credential=credential_model,
                order=order,
                primary_certificate=credential_model.certificate
            )

    @classmethod
    @transaction.atomic
    def save_keyless_credential(
        cls,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        credential_type: CredentialModel.CredentialTypeChoice,
    ) -> CredentialModel:
        """Stores a credential without a private key."""
        certificate_model = CertificateModel.save_certificate(certificate)

        credential_model = cls.objects.create(
            certificate=certificate_model, credential_type=credential_type, private_key=''
        )

        PrimaryCredentialCertificate.objects.create(
            certificate=certificate_model, credential=credential_model, is_primary=True
        )

        for order, certificate_in_chain in enumerate(certificate_chain):
            certificate_model = CertificateModel.save_certificate(certificate_in_chain)
            CertificateChainOrderModel.objects.create(
                certificate=certificate_model,
                credential=credential_model,
                order=order,
                primary_certificate=credential_model.certificate
            )

        return credential_model

    @transaction.atomic
    def update_keyless_credential(
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
    ) -> None:
        """Updates the primary certificate and certificate chain of the credential.

        Previous certificates are kept as part of the credential.
        """
        certificate_model = CertificateModel.save_certificate(certificate)
        self.certificate = certificate_model

        # Consider adding private key update logic here if needed

        _, _ = PrimaryCredentialCertificate.objects.get_or_create(
            certificate=certificate_model, credential=self, is_primary=True
        )

        # Store the complete chain for each new primary certificate
        for order, certificate_in_chain in enumerate(certificate_chain):
            certificate_model = CertificateModel.save_certificate(certificate_in_chain)
            _, _ = CertificateChainOrderModel.objects.get_or_create(
                certificate=certificate_model, credential=self, order=order, primary_certificate=self.certificate
            )

        self.save()

    def pre_delete(self) -> None:
        """Deletes related models, only allow deletion if there are no more active certificates."""
        # only allow deletion if all certificates are either expired or revoked
        qs = self.certificates.all()
        if self.certificate not in qs:
            exc_msg = f'Primary certificate not in certificate list of credential {self.pk}.'
            raise ValidationError(exc_msg)
        # Issued credentials must be revoked before deletion, not a requirement for CA credentials
        if self.credential_type == CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL:
            for cert in qs:
                if (cert.certificate_status in
                    [CertificateModel.CertificateStatus.OK, CertificateModel.CertificateStatus.NOT_YET_VALID]):
                    exc_msg = f'Cannot delete credential {self} because it still has active certificates.'
                    self.logger.error(exc_msg)
                    raise ValidationError(exc_msg)
        self.certificates.clear()
        # CertificateChainOrderModel is deleted via CASCADE

    def get_private_key(self) -> PrivateKey:
        """Gets an abstraction of the credential private key.

        Note, in the case of keys stored in an HSM or TPM using PKCS#11, it will only be possible to use the
        key abstraction to sign and verify, but not to export the key in any way.

        Returns:
            PrivateKey: The credential private key abstraction.
        """
        if self.private_key:
            return PrivateKeySerializer.from_pem(self.private_key.encode()).as_crypto()

        if self.pkcs11_private_key:
            return self.get_pkcs11_private_key()

        err_msg = 'Failed to get private key information.'
        raise RuntimeError(err_msg)

    def get_pkcs11_private_key(self) -> PrivateKey:
        """Gets the private key abstraction."""
        if self.pkcs11_private_key:
            try:
                token_config = PKCS11Token.objects.get(label=self.pkcs11_private_key.token_label)
                lib_path = token_config.module_path
                user_pin = token_config.get_pin()

                pkcs11_key = self.pkcs11_private_key.get_pkcs11_key_instance(lib_path, user_pin)
                pkcs11_key.load_key()
            except PKCS11Token.DoesNotExist as e:
                msg = f'PKCS#11 token configuration not found: {self.pkcs11_private_key.token_label}'
                raise RuntimeError(msg) from e
            else:
                return cast('PrivateKey', pkcs11_key)

        msg = 'No private key available for this credential.'
        raise RuntimeError(msg)

    def get_private_key_serializer(self) -> PrivateKeySerializer:
        """Gets a serializer of the credential private key.

        For PKCS#11 keys, since the private key cannot be exported, this method returns
        a PrivateKeySerializer constructed from the public key extracted from the certificate.
        This allows code that needs the public key (via .public_key_serializer) to work
        with both software-stored and HSM-stored credentials.

        Returns:
            PrivateKeySerializer: The credential private key serializer.

        Raises:
            RuntimeError: If no private key information is available.
        """
        if self.private_key:
            return PrivateKeySerializer.from_pem(self.private_key.encode())

        if self.pkcs11_private_key:
            # For PKCS#11 keys, we can't export the private key, but we can
            # create a PrivateKeySerializer from the public key in the certificate
            # This allows .public_key_serializer to work correctly
            try:
                pkcs11_key = self.get_pkcs11_private_key()
                # PrivateKeySerializer can wrap the PKCS#11 key object
                return PrivateKeySerializer(pkcs11_key)
            except Exception as e:
                err_msg = f'Failed to get PKCS#11 private key: {e}'
                raise RuntimeError(err_msg) from e

        err_msg = 'Failed to get private key information.'
        raise RuntimeError(err_msg)

    def get_certificate(self) -> x509.Certificate:
        """Gets the credential certificate as x509.Certificate instance.

        Returns:
            x509.Certificate: The credential certificate.
        """
        return self.get_certificate_serializer().as_crypto()

    def get_certificate_chain(self) -> list[x509.Certificate]:
        """Gets the credential certificate chain as a list of x509.Certificate instances.

        Returns:
            list[x509.Certificate]: The credential certificate chain as list of x509.Certificate instances.
        """
        return self.get_certificate_chain_serializer().as_crypto()

    def get_certificate_serializer(self) -> CertificateSerializer:
        """Gets the credential certificate as a CertificateSerializer instance.

        Returns:
            CertificateSerializer: The credential certificate.
        """
        return self.certificate.get_certificate_serializer()

    def get_certificate_chain_serializer(self) -> CertificateCollectionSerializer:
        """Gets the credential certificate chain as a CertificateCollectionSerializer instance.

        Returns:
            CertificateCollectionSerializer: The credential certificate chain.
        """
        certificate_chain_order_models = self.certificatechainordermodel_set.order_by('order')
        return CertificateCollectionSerializer(
            [
                certificate_chain_order_model.certificate.get_certificate_serializer().as_crypto()
                for certificate_chain_order_model in certificate_chain_order_models
            ]
        )

    def get_last_in_chain(self) -> None | CertificateModel:
        """Gets the root ca certificate model, if any."""
        last_certificate_in_chain = self.certificatechainordermodel_set.order_by('order').last()
        if last_certificate_in_chain is None:
            return self.certificate
        return last_certificate_in_chain.certificate

    def get_root_ca_certificate(self) -> None | x509.Certificate:
        """Gets the root CA certificate of the credential certificate chain."""
        root_ca_certificate_serializer = self.get_root_ca_certificate_serializer()
        if root_ca_certificate_serializer:
            return root_ca_certificate_serializer.as_crypto()
        return None

    def get_root_ca_certificate_serializer(self) -> None | CertificateSerializer:
        """Gets the root CA certificate serializer."""
        last_certificate_in_chain = self.certificatechainordermodel_set.order_by('order').last()
        if last_certificate_in_chain is None:
            return self.certificate.get_certificate_serializer()
        if last_certificate_in_chain.certificate.is_root_ca:
            return last_certificate_in_chain.certificate.get_certificate_serializer()
        return None

    def get_credential_serializer(self) -> CredentialSerializer:
        """Gets the serializer for this credential."""
        return CredentialSerializer(
            private_key=self.get_private_key_serializer().as_crypto(),
            certificate=self.get_certificate_serializer().as_crypto(),
            additional_certificates=self.get_certificate_chain_serializer().as_crypto()
        )

    @property
    def signature_suite(self) -> oid.SignatureSuite:
        """Returns the signature suite used by the current credential primary certificate."""
        return oid.SignatureSuite.from_certificate(self.get_certificate_serializer().as_crypto())

    @property
    def public_key_info(self) -> oid.PublicKeyInfo:
        """Returns the PublicKeyInfo the current credential primary certificate."""
        return self.signature_suite.public_key_info

    @property
    def hash_algorithm(self) -> hashes.HashAlgorithm  | None:
        """Returns the hash algorithm used by the current credential."""
        return self.get_certificate().signature_hash_algorithm

    def is_valid_issued_credential(self) -> tuple[bool, str]:
        """Determines if this issued credential is valid.

        This method performs the following checks:
          1. The credential must be of type ISSUED_CREDENTIAL.
          2. A primary certificate must exist.
          3. The certificate's status must be 'OK'.

        Returns:
            tuple[bool, str]: A tuple where:
                          - The first value is True if the credential meets all criteria, False otherwise.
                          - The second value is a reason string explaining why the credential is invalid.
        """
        if self.credential_type != CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL:
            return False, 'Invalid credential type: Must be ISSUED_CREDENTIAL.'

        primary_cert = self.certificate
        if primary_cert is None:
            return False, 'Missing primary certificate.'

        if primary_cert.certificate_status != primary_cert.CertificateStatus.OK:
            return False, f'Invalid certificate status: {primary_cert.certificate_status} (Must be OK).'

        return True, 'Valid issued credential.'


class PrimaryCredentialCertificate(models.Model):
    """Model to store which certificate is the primary certificate of a credential.

    Used as through model for the many-to-many relationship between CredentialModel and CertificateModel.
    """

    credential = models.ForeignKey(CredentialModel, on_delete=models.CASCADE)
    certificate = models.OneToOneField(CertificateModel, on_delete=models.CASCADE)
    is_primary = models.BooleanField(default=False)

    def __repr__(self) -> str:
        """Returns a string representation of this PrimaryCredentialCertificate entry."""
        return (
            f'PrimaryCredentialCertificate(credential={self.credential}, '
            f'certificate={self.certificate}, '
            f'is_primary={self.is_primary})'
        )

    def __str__(self) -> str:
        """Returns a human-readable string that represents this PrimaryCredentialCertificate entry."""
        return self.__repr__()

    def save(self, *args: Any, **kwargs: Any) -> None:
        """If a new certificate is added to a credential, it is set to primary and all others to non-primary."""
        if not self.pk or self.is_primary:
            PrimaryCredentialCertificate.objects.filter(credential=self.credential).update(is_primary=False)

        self.is_primary = True
        super().save(*args, **kwargs)


class CertificateChainOrderModel(models.Model):
    """This Model is used to preserve the order of certificates in credential certificate chains."""

    certificate = models.ForeignKey(CertificateModel, on_delete=models.PROTECT, null=False, blank=False, editable=False)
    credential = models.ForeignKey(CredentialModel, on_delete=models.CASCADE, null=False, blank=False, editable=False)
    order = models.PositiveIntegerField(null=False, blank=False, editable=False)
    primary_certificate = models.ForeignKey(
        CertificateModel, on_delete=models.PROTECT, null=False, blank=False, editable=False,
        related_name = 'primary_certificate_set'
    )

    class Meta:
        """This Meta class add some configuration to the CertificateChainOrderModel.

        Sets the default ordering such that the field order is used.
        Restricts entries such that the tuple (credential, order) is unique.
        """

        ordering: ClassVar = ['order']
        constraints: ClassVar = [models.UniqueConstraint(
            fields=['credential', 'primary_certificate', 'order'], name='unique_group_order'
        )]

    def __repr__(self) -> str:
        """Returns a string representation of this CertificateChainOrderModel entry."""
        return (
            f'CertificateChainOrderModel(credential={self.credential}, '
            f'certificate={self.certificate}, '
            f'primary_certificate={self.primary_certificate}, '
            f'order={self.order})'
        )

    def __str__(self) -> str:
        """Returns a human-readable string that represents this CertificateChainOrderModel entry.

        Returns:
            str: Human-readable string that represents this CertificateChainOrderModel entry.
        """
        return self.__repr__()

    # TODO(AlexHx8472): Validate certificate chain!  # noqa: FIX002
    def save(self, *args: Any, **kwargs: Any) -> None:
        """Stores a CertificateChainOrderModel in the database.

        This is only possible if the order takes the next available value. That is, e.g. if the corresponding
        credential certificate chain has already two certificates stored with order 0 and 1, then the next
        entry to be stored must have order 2.

        Args:
            *args: Positional arguments, passed to super().save()
            **kwargs: Keyword arguments, passed to super().save()

        Returns:
            None

        Raises:
            ValueError:
                If the CertificateChainOrderModel entry to be stored does not have the correct order.
        """
        max_order = self._get_max_order()

        if self.order != max_order + 1:
            err_msg = f'Cannot add Membership with order {self.order}. Expected {max_order + 1}.'
            raise ValidationError(err_msg)
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """Tries to delete the CertificateChainOrderModel entry.

        A CertificateChainOrderModel entry can only be deleted if it has the highest order in the
        corresponding credential certificate chain.

        Args:
            *args: Positional arguments, passed to super().delete()
            **kwargs: Keyword arguments, passed to super().delete()

        Returns:
            tuple[int, dict[str, int]] (returned by parent)

        Raises:
            ValueError:
                If the CertificateChainOrderModel entry does not have the highest order in the corresponding
                credential certificate chain.
        """
        max_order = self._get_max_order()

        if self.order != max_order:
            err_msg = (
                f'Only the Membership with the highest order ({max_order}) '
                f'can be deleted. This Membership has order {self.order}.'
            )
            raise ValidationError(err_msg)

        return super().delete(*args, **kwargs)

    def _get_max_order(self) -> int:
        """Gets highest order of a certificate of a credential certificate chain.

        Returns:
            int: The highest order of a certificate of a credential certificate chain.
        """
        existing_orders = CertificateChainOrderModel.objects.filter(
            credential=self.credential, primary_certificate=self.primary_certificate
        ).values_list(
            'order', flat=True
        )
        return max(existing_orders, default=-1)


class IDevIDReferenceModel(models.Model):
    """Model to store the string referencing an IDevID certificate.

    Obtained from the SAN of the DevOwnerID certificate.
    """
    dev_owner_id = models.ForeignKey(
        'OwnerCredentialModel', related_name='idevid_ref_set', on_delete=models.CASCADE
    )
    idevid_ref = models.CharField(max_length=255, verbose_name=_('IDevID Identifier'))

    def __str__(self) -> str:
        """Returns a human-readable string that represents this IDevIDRefSanModel entry."""
        return f'{self.dev_owner_id.unique_name} - {self.idevid_ref}'

    @property
    def idevid_subject_serial_number(self) -> str:
        """Returns the IDevID Subject Serial Number from the SAN of the DevOwnerID certificate."""
        try:
            return self.idevid_ref.split('.')[0]
        except IndexError:
            return ''

    @property
    def idevid_x509_serial_number(self) -> str:
        """Returns the IDevID X.509 Serial Number from the SAN of the DevOwnerID certificate."""
        try:
            return self.idevid_ref.split('.')[2]
        except IndexError:
            return ''

    @property
    def idevid_sha256_fingerprint(self) -> str:
        """Returns the IDevID SHA256 Fingerprint from the SAN of the DevOwnerID certificate."""
        try:
            return self.idevid_ref.split('.')[3]
        except IndexError:
            return ''



class OwnerCredentialModel(LoggerMixin, CustomDeleteActionModel):
    """Device owner credential model.

    This model is a wrapper to store a DevOwnerID Credential for use by devices to trust the Trustpoint.
    """

    unique_name = models.CharField(
        verbose_name=_('Unique Name'), max_length=100, validators=[UniqueNameValidator()], unique=True
    )
    credential: models.OneToOneField[CredentialModel] = models.OneToOneField(
        CredentialModel, related_name='dev_owner_ids', on_delete=models.PROTECT)

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)


    def __str__(self) -> str:
        """Returns a human-readable string that represents this OwnerCredentialModel entry.

        Returns:
            str: Human-readable string that represents this OwnerCredentialModel entry.
        """
        return self.unique_name

    def __repr__(self) -> str:
        """Returns a string representation of the OwnerCredentialModel instance."""
        return f'OwnerCredentialModel(unique_name={self.unique_name})'

    @classmethod
    def create_new_owner_credential(
        cls,
        unique_name: str,
        credential_serializer: CredentialSerializer,
    ) -> OwnerCredentialModel:
        """Creates a new owner credential model and returns it.

        Args:
            unique_name: The unique name that will be used to identify the Owner Credential.
            credential_serializer:
                The credential as CredentialSerializer instance.

        Returns:
            OwnerCredentialModel: The newly created owner credential model.
        """
        # Extract the IDevID references from the SAN of the DevOwnerID certificate
        # Reference URI format: 'dev-owner:<IDevID_Subj_SN>.<IDevID_x509_SN>.<IDevID_SHA256_Fingerpr>'
        idevid_refs: set[str] = set()
        owner_cert = credential_serializer.certificate
        if not owner_cert:
            err_msg = _('The provided credential is not a valid DevOwnerID; it does not contain a certificate.')
            raise ValidationError(err_msg)
        try:
            san_extension = owner_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound as e:
            err_msg = _('The provided certificate is not a valid DevOwnerID; it does not contain a SAN extension.')
            raise ValidationError(err_msg) from e

        for san in san_extension.value:
            if isinstance(san, x509.UniformResourceIdentifier):
                san_uri_str = san.value
                if san_uri_str.startswith('dev-owner:'):
                    idevid_refs.add(san_uri_str)
        if not idevid_refs:
            raise ValidationError(_(
                'The provided certificate is not a valid DevOwnerID; '
                'it does not contain a valid IDevID reference in the SAN.'
            ))

        credential_type = CredentialModel.CredentialTypeChoice.DEV_OWNER_ID

        credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=credential_serializer, credential_type=credential_type
        )

        owner_credential = cls(
            unique_name=unique_name,
            credential=credential_model,
        )
        owner_credential.save()
        for idevid_ref in idevid_refs:
            IDevIDReferenceModel.objects.create(
                dev_owner_id=owner_credential,
                idevid_ref=idevid_ref
            )

        return owner_credential

    def post_delete(self) -> None:
        """Deletes the credential of this owner credential after deleting it."""
        self.logger.debug('Deleting credential of owner credential %s', self)
        self.credential.delete()

