"""Manages the auto-generated local PKI."""

from __future__ import annotations

import secrets
import threading

from pki.models import DomainModel, IssuingCaModel, RevokedCertificateModel
from pki.util.keys import AutoGenPkiKeyAlgorithm, KeyGenerator
from pki.util.x509 import CertificateGenerator
from trustpoint.logger import LoggerMixin

UNIQUE_NAME_PREFIX = 'AutoGenPKI_Issuing_CA'
DOMAIN_NAME_PREFIX = 'AutoGenPKI'
ISSUING_CA_NAME_MIN_PARTS = 4


class AutoGenPki(LoggerMixin):
    """Handles enabling and disabling of auto-generated PKI."""

    _lock: threading.Lock = threading.Lock()

    @classmethod
    def get_auto_gen_pki(cls, key_alg: AutoGenPkiKeyAlgorithm | None = None) -> IssuingCaModel | None:
        """Retrieves the auto-generated PKI Issuing CA, if it exists."""
        if key_alg is not None:
            unique_name = f'{UNIQUE_NAME_PREFIX}_{key_alg.name}'
            try:
                return IssuingCaModel.objects.get(unique_name=unique_name)
            except IssuingCaModel.DoesNotExist:
                return None
        else:
            try:
                return IssuingCaModel.objects.filter(
                    unique_name__startswith=UNIQUE_NAME_PREFIX,
                    issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN,
                    is_active=True
                ).first()
            except IssuingCaModel.DoesNotExist:
                return None

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
            public_key_info = key_alg.to_public_key_info()
            key_gen = KeyGenerator()

            # Re-use any existing root CA for the auto-generated PKI and current key type
            try:
                root_ca = IssuingCaModel.objects.get(
                    unique_name=root_ca_name, issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT
                )
                root_cert = root_ca.credential.get_certificate()
                root_1_key = root_ca.credential.get_private_key()
                cls.logger.info('Reusing existing Root CA: %s', root_ca_name)
            except IssuingCaModel.DoesNotExist:
                cls.logger.info('Creating new Root CA: %s', root_ca_name)
                root_cert, root_1_key = CertificateGenerator.create_root_ca(
                    root_ca_name,
                    private_key=key_gen.generate_private_key_for_public_key_info(public_key_info)
                )
                CertificateGenerator.save_issuing_ca(
                    issuing_ca_cert=root_cert,
                    private_key=root_1_key,
                    chain=[],
                    unique_name=root_ca_name,
                    ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT,
                )

            cls.logger.info('Creating new Issuing CA with unique name: %s', issuing_ca_unique_name)
            issuing_1, issuing_1_key = CertificateGenerator.create_issuing_ca(
                root_1_key,
                root_ca_name,
                issuing_ca_unique_name,
                private_key=key_gen.generate_private_key_for_public_key_info(public_key_info),
                validity_days=50,
            )

            issuing_ca = CertificateGenerator.save_issuing_ca(
                issuing_ca_cert=issuing_1,
                private_key=issuing_1_key,
                chain=[root_cert],
                unique_name=issuing_ca_unique_name,
                ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN,
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
        PKCS#11 keys are NOT destroyed - each Issuing CA has a unique name to avoid conflicts.
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

            cls.logger.info('PKCS#11 key for %s is kept in HSM (not destroyed)', issuing_ca.unique_name)

            old_unique_name = issuing_ca.unique_name
            issuing_ca.unique_name = f'{old_unique_name}_DISABLED'
            issuing_ca.is_active = False
            issuing_ca.save()
            cls.logger.info('Renamed and deactivated Issuing CA: %s -> %s', old_unique_name, issuing_ca.unique_name)

            root_cert = issuing_ca.credential.get_root_ca_certificate()
            if root_cert is None:
                cls.logger.error('Root CA certificate not found for auto-generated PKI Issuing CA')
                return
            subject_public_bytes = root_cert.subject.public_bytes().hex().upper()
            try:
                root_ca = IssuingCaModel.objects.get(
                    credential__primarycredentialcertificate__certificate__subject_public_bytes=subject_public_bytes,
                    issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT,
                )
                root_ca.revoke_all_issued_certificates(reason=RevokedCertificateModel.ReasonCode.CESSATION)

                cls.logger.info('Keeping Root CA key for potential reuse: %s', root_ca.unique_name)

            except IssuingCaModel.DoesNotExist:
                exc_msg = 'Root CA for auto-generated PKI Issuing CA not found - cannot revoke the CA certificate'
                cls.logger.error(exc_msg)  # noqa: TRY400
                return

            cls.logger.warning('Auto-generated PKI disabled: %s', old_unique_name)
