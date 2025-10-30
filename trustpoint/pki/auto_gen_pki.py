"""Manages the auto-generated local PKI."""

from __future__ import annotations

import logging
import secrets
import threading

from pki.models import DomainModel, IssuingCaModel, RevokedCertificateModel
from pki.util.keys import AutoGenPkiKeyAlgorithm, KeyGenerator
from pki.util.x509 import CertificateGenerator

log = logging.getLogger('tp.pki')
UNIQUE_NAME = 'AutoGenPKI_Issuing_CA'


class AutoGenPki:
    """Handles enabling and disabling of auto-generated PKI."""

    _lock: threading.Lock = threading.Lock()

    @classmethod
    def get_auto_gen_pki(cls) -> IssuingCaModel | None:
        """Retrieves the auto-generated PKI Issuing CA, if it exists."""
        try:
            return IssuingCaModel.objects.get(unique_name=UNIQUE_NAME)
        except IssuingCaModel.DoesNotExist:
            return None

    @classmethod
    def enable_auto_gen_pki(cls, key_alg: AutoGenPkiKeyAlgorithm) -> None:
        """Enables the auto-generated PKI."""
        with cls._lock:
            log.warning('! Enabling auto-generated PKI !')

            issuing_ca = cls.get_auto_gen_pki()
            if issuing_ca:
                log.error(
                    'Issuing CA for auto-generated PKI already exists - '
                    'auto-generated PKI was possibly not correctly disabled'
                )
                return

            root_ca_name = f'AutoGenPKI_Root_CA_{key_alg}'
            public_key_info = key_alg.to_public_key_info()
            key_gen = KeyGenerator()

            # Re-use any existing root CA for the auto-generated PKI and current key type
            try:
                root_ca = IssuingCaModel.objects.get(
                    unique_name=root_ca_name, issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT
                )
                root_cert = root_ca.credential.get_certificate()
                root_1_key = root_ca.credential.get_private_key()
            except IssuingCaModel.DoesNotExist:
                root_cert, root_1_key = CertificateGenerator.create_root_ca(
                    root_ca_name, private_key=key_gen.generate_private_key_for_public_key_info(public_key_info)
                )
                # Save root CA
                CertificateGenerator.save_issuing_ca(
                    issuing_ca_cert=root_cert,
                    private_key=root_1_key,
                    chain=[],
                    unique_name=root_ca_name,
                    ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT,
                )

            # Create new issuing CA
            issuing_1, issuing_1_key = CertificateGenerator.create_issuing_ca(
                root_1_key,
                root_ca_name,
                UNIQUE_NAME,
                private_key=key_gen.generate_private_key_for_public_key_info(public_key_info),
                validity_days=50,
            )

            # Save issuing CA
            issuing_ca = CertificateGenerator.save_issuing_ca(
                issuing_ca_cert=issuing_1,
                private_key=issuing_1_key,
                chain=[root_cert],
                unique_name=UNIQUE_NAME,
                ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN,
            )

            # Link to domain
            domain, _ = DomainModel.objects.get_or_create(
                unique_name='AutoGenPKI',
                defaults={'issuing_ca': issuing_ca},
            )
            domain.issuing_ca = issuing_ca
            domain.is_active = True
            domain.save()

            log.warning('Auto-generated PKI enabled.')

    @classmethod
    def disable_auto_gen_pki(cls) -> None:
        """Disables the auto-generated PKI."""
        with cls._lock:
            issuing_ca = cls.get_auto_gen_pki()
            if not issuing_ca:
                log.error(
                    'Issuing CA for auto-generated PKI does not exist - auto-generated PKI possibly not fully disabled'
                )
                return

            log.warning('! Disabling auto-generated PKI !')
            # Domain: set as inactive
            try:
                domain = DomainModel.objects.get(unique_name='AutoGenPKI')
                domain.is_active = False
                domain.save()
            except DomainModel.DoesNotExist:
                pass

            # Issuing CA: revoke all issued certificates
            # Rename the issuing CA to something random and hide it from the UI
            issuing_ca.revoke_all_issued_certificates(reason=RevokedCertificateModel.ReasonCode.CESSATION)
            issuing_ca.unique_name = f'{UNIQUE_NAME}_OLD_{secrets.token_hex(16)}'
            issuing_ca.is_active = False
            issuing_ca.save()

            # Root CA: revoke the Issuing CA certificate
            root_cert = issuing_ca.credential.get_root_ca_certificate()
            if root_cert is None:
                log.error('Root CA certificate not found for auto-generated PKI Issuing CA')
                return
            subject_public_bytes = root_cert.subject.public_bytes().hex().upper()
            try:
                root_ca = IssuingCaModel.objects.get(
                    credential__primarycredentialcertificate__certificate__subject_public_bytes=subject_public_bytes,
                    issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT,
                )
                root_ca.revoke_all_issued_certificates(reason=RevokedCertificateModel.ReasonCode.CESSATION)
            except IssuingCaModel.DoesNotExist:
                exc_msg = 'Root CA for auto-generated PKI Issuing CA not found - cannot revoke the CA certificate'
                log.error(exc_msg)  # noqa: TRY400
                return

            # Hide the AutoGenPKI domain from the UI

            # Issuing CA model deletion not feasible due to related model deletion protection

            log.warning('Auto-generated PKI disabled.')
