"""Manages the auto-generated local PKI."""

from __future__ import annotations

import secrets
import threading
from typing import TYPE_CHECKING, cast

from crypto.application.private_keys import (
    ManagedECPrivateKey,
    ManagedRSAPrivateKey,
    generate_managed_signing_private_key,
)
from crypto.domain.algorithms import EllipticCurveName
from crypto.domain.specs import EcKeySpec, KeySpec, RsaKeySpec
from crypto.models import CryptoManagedKeyModel
from pki.models import CaModel, CredentialModel, DomainModel, RevokedCertificateModel
from pki.util.keys import AutoGenPkiKeyAlgorithm, supported_auto_gen_pki_key_algorithms
from pki.util.x509 import CertificateGenerator
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from cryptography import x509

UNIQUE_NAME_PREFIX = 'AutoGenPKI_Issuing_CA'
DOMAIN_NAME_PREFIX = 'AutoGenPKI'
ISSUING_CA_NAME_MIN_PARTS = 4


class AutoGenPki(LoggerMixin):
    """Handles enabling and disabling of auto-generated PKI."""

    _lock: threading.Lock = threading.Lock()

    @staticmethod
    def _key_spec_for_algorithm(key_alg: AutoGenPkiKeyAlgorithm) -> KeySpec:
        """Map AutoGenPKI choices to the backend key-generation contract."""
        if key_alg == AutoGenPkiKeyAlgorithm.RSA2048:
            return RsaKeySpec(key_size=2048)
        if key_alg == AutoGenPkiKeyAlgorithm.RSA4096:
            return RsaKeySpec(key_size=4096)
        if key_alg == AutoGenPkiKeyAlgorithm.SECP256R1:
            return EcKeySpec(curve=EllipticCurveName.SECP256R1)
        msg = f'Unsupported AutoGenPKI key algorithm {key_alg!r}.'
        raise ValueError(msg)

    @staticmethod
    def _generate_private_key(
        key_alg: AutoGenPkiKeyAlgorithm,
        key_label: str,
    ) -> ManagedRSAPrivateKey | ManagedECPrivateKey:
        """Generate an AutoGenPKI key in the active backend."""
        if key_alg not in supported_auto_gen_pki_key_algorithms():
            msg = f'The active crypto backend does not support AutoGenPKI algorithm {key_alg.label}.'
            raise ValueError(msg)

        return generate_managed_signing_private_key(
            alias=key_label,
            key_spec=AutoGenPki._key_spec_for_algorithm(key_alg),
        )

    @staticmethod
    def _managed_key_model(private_key: ManagedRSAPrivateKey | ManagedECPrivateKey) -> CryptoManagedKeyModel:
        """Resolve a generated managed private-key facade to its database model."""
        return CryptoManagedKeyModel.objects.get(pk=private_key.managed_key_ref.id)

    @staticmethod
    def _save_managed_issuing_ca(  # noqa: PLR0913
        *,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        private_key: ManagedRSAPrivateKey | ManagedECPrivateKey,
        unique_name: str,
        ca_type: CaModel.CaTypeChoice,
        parent_ca: CaModel | None = None,
    ) -> CaModel:
        """Persist an issuing CA whose key is owned by the configured crypto backend."""
        credential = CredentialModel.save_managed_key_credential(
            certificate=certificate,
            certificate_chain=list(certificate_chain),
            credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
            managed_key=AutoGenPki._managed_key_model(private_key),
        )
        ca = CaModel(
            unique_name=unique_name,
            credential=credential,
            ca_type=ca_type,
            parent_ca=parent_ca,
        )
        ca.save()
        ca.chain_truststore = CaModel._create_chain_truststore(ca)  # noqa: SLF001
        ca.save(update_fields=['chain_truststore'])
        return ca

    @classmethod
    def get_auto_gen_pki(cls, key_alg: AutoGenPkiKeyAlgorithm | None = None) -> CaModel | None:
        """Retrieves the auto-generated PKI Issuing CA, if it exists."""
        if key_alg is not None:
            return CaModel.objects.filter(
                unique_name__startswith=f'{UNIQUE_NAME_PREFIX}_{key_alg.name}',
                ca_type=CaModel.CaTypeChoice.AUTOGEN,
                is_active=True,
            ).first()
        return CaModel.objects.filter(
            unique_name__startswith=UNIQUE_NAME_PREFIX,
            ca_type=CaModel.CaTypeChoice.AUTOGEN,
            is_active=True,
        ).first()

    @classmethod
    def enable_auto_gen_pki(cls, key_alg: AutoGenPkiKeyAlgorithm) -> None:
        """Enables the auto-generated PKI."""
        with cls._lock:
            cls.logger.warning('! Enabling auto-generated PKI with key algorithm: %s !', key_alg.name)

            unique_suffix = secrets.token_hex(4)
            issuing_ca_unique_name = f'{UNIQUE_NAME_PREFIX}_{key_alg.name}_{unique_suffix}'
            domain_unique_name = f'{DOMAIN_NAME_PREFIX}_{key_alg.name}'

            existing_issuing_ca = cls.get_auto_gen_pki(key_alg)
            if existing_issuing_ca:
                cls.logger.error(
                    'Issuing CA for auto-generated PKI already exists: %s - '
                    'auto-generated PKI was possibly not correctly disabled',
                    existing_issuing_ca.unique_name
                )
                return

            root_ca_name = f'AutoGenPKI_Root_CA_{key_alg.name}'
            # Re-use any existing root CA for the auto-generated PKI and current key type
            try:
                root_ca = CaModel.objects.get(
                    unique_name=root_ca_name, ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT
                )
                root_cert = cast('CredentialModel', root_ca.credential).get_certificate()
                root_1_key = cast('CredentialModel', root_ca.credential).get_private_key()
                cls.logger.info('Reusing existing Root CA: %s', root_ca_name)
            except CaModel.DoesNotExist:
                cls.logger.info('Creating new Root CA: %s', root_ca_name)
                root_private_key = cls._generate_private_key(key_alg, f'{root_ca_name}_{unique_suffix}')
                root_cert, _ = CertificateGenerator.create_root_ca(
                    root_ca_name,
                    private_key=root_private_key,
                )
                root_ca = cls._save_managed_issuing_ca(
                    certificate=root_cert,
                    certificate_chain=[],
                    private_key=root_private_key,
                    unique_name=root_ca_name,
                    ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT,
                )
                root_1_key = cast('CredentialModel', root_ca.credential).get_private_key()
                cls.logger.info('Created new Root CA: %s', root_ca_name)

            cls.logger.info('Creating new Issuing CA with unique name: %s', issuing_ca_unique_name)
            issuing_private_key = cls._generate_private_key(key_alg, issuing_ca_unique_name)
            issuing_1, _ = CertificateGenerator.create_issuing_ca(
                root_1_key,
                root_ca_name,
                issuing_ca_unique_name,
                private_key=issuing_private_key,
                validity_days=50,
            )

            issuing_ca = cls._save_managed_issuing_ca(
                certificate=issuing_1,
                certificate_chain=[root_cert],
                private_key=issuing_private_key,
                unique_name=issuing_ca_unique_name,
                ca_type=CaModel.CaTypeChoice.AUTOGEN,
                parent_ca=root_ca,
            )
            cls.logger.info('Saved new Issuing CA: %s', issuing_ca_unique_name)

            cls.logger.info('Linking to domain: %s', domain_unique_name)
            domain, created = DomainModel.objects.get_or_create(
                unique_name=domain_unique_name,
                defaults={'issuing_ca': issuing_ca},
            )
            cls.logger.info('Domain %s (created=%s, was_active=%s)', domain_unique_name, created, domain.is_active)
            domain.issuing_ca = issuing_ca
            domain.is_active = True
            domain.save()
            cls.logger.info('Domain %s updated and activated', domain_unique_name)

            cls.logger.warning('Auto-generated PKI enabled with key algorithm: %s', key_alg.name)

    @classmethod
    def disable_auto_gen_pki(cls) -> None:
        """Disables the auto-generated PKI.

        Note: This will disable the currently active auto-generated PKI (any key algorithm).
        Managed backend keys are not destroyed - each Issuing CA has a unique name to avoid conflicts.
        """
        with cls._lock:
            issuing_ca = cls.get_auto_gen_pki(key_alg=None)
            if not issuing_ca:
                cls.logger.error(
                    'Issuing CA for auto-generated PKI does not exist - auto-generated PKI possibly not fully disabled'
                )
                return

            cls.logger.warning('! Disabling auto-generated PKI: %s !', issuing_ca.unique_name)

            parts = issuing_ca.unique_name.split('_')
            if len(parts) >= ISSUING_CA_NAME_MIN_PARTS:  # ['AutoGenPKI', 'Issuing', 'CA', 'RSA2048', 'uniqueid']
                key_alg_name = parts[3]
                domain_unique_name = f'{DOMAIN_NAME_PREFIX}_{key_alg_name}'
            else:
                cls.logger.error('Unexpected Issuing CA name format: %s', issuing_ca.unique_name)
                return

            try:
                domain = DomainModel.objects.get(unique_name=domain_unique_name)
                domain.is_active = False
                domain.save()
                cls.logger.info('Deactivated domain: %s', domain_unique_name)
            except DomainModel.DoesNotExist:
                cls.logger.warning('Domain %s does not exist', domain_unique_name)

            issuing_ca.revoke_all_issued_certificates(reason=RevokedCertificateModel.ReasonCode.CESSATION)

            cls.logger.info('Managed key for %s is kept in the configured crypto backend', issuing_ca.unique_name)

            old_unique_name = issuing_ca.unique_name
            issuing_ca.unique_name = f'{old_unique_name}_DISABLED'
            issuing_ca.is_active = False
            issuing_ca.save()
            cls.logger.info('Renamed and deactivated Issuing CA: %s -> %s', old_unique_name, issuing_ca.unique_name)

            root_cert = cast('CredentialModel', issuing_ca.credential).get_root_ca_certificate()
            if root_cert is None:
                cls.logger.error('Root CA certificate not found for auto-generated PKI Issuing CA')
                return
            subject_public_bytes = root_cert.subject.public_bytes().hex().upper()
            try:
                root_ca = CaModel.objects.get(
                    credential__primarycredentialcertificate__certificate__subject_public_bytes=subject_public_bytes,
                    ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT,
                )
                root_ca.revoke_all_issued_certificates(reason=RevokedCertificateModel.ReasonCode.CESSATION)

                cls.logger.info('Keeping Root CA managed key for potential reuse: %s', root_ca.unique_name)

            except CaModel.DoesNotExist:
                exc_msg = 'Root CA for auto-generated PKI Issuing CA not found - cannot revoke the CA certificate'
                cls.logger.error(exc_msg)  # noqa: TRY400
                return

            cls.logger.warning('Auto-generated PKI disabled: %s', old_unique_name)
