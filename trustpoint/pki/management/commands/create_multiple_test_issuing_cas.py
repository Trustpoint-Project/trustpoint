"""Django management command for adding issuing CA test data."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.core.management.base import BaseCommand, CommandError

from crypto.application.capabilities import (
    BackendCapabilityReport,
    get_active_backend_capability_report,
    normalize_curve_name,
)
from crypto.application.private_keys import (
    ManagedECPrivateKey,
    ManagedRSAPrivateKey,
    generate_managed_signing_private_key,
)
from crypto.domain.specs import EcKeySpec, KeySpec, RsaKeySpec
from crypto.models import CryptoManagedKeyModel
from management.models import SecurityConfig
from management.models.audit_log import AuditLog
from pki.models import CaModel, CredentialModel
from pki.util.x509 import CertificateVerifier
from trustpoint.logger import LoggerMixin

from .base_commands import CertificateCreationCommandMixin

if TYPE_CHECKING:
    from cryptography import x509


class Command(CertificateCreationCommandMixin, BaseCommand, LoggerMixin):
    """Adds a Root CA, Intermediate CAs, and Issuing CAs to the database."""

    help = 'Adds a Root CA, Intermediate CAs, and Issuing CAs to the database.'
    _capability_report: BackendCapabilityReport | None = None

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Log a message and write it to stdout.

        Parameters
        ----------
        message : str
            The message to log and print.
        level : str
            The logging level ('info', 'warning', 'error', etc.).
        """
        # Log the message
        log_method = getattr(self.logger, level, self.logger.info)
        log_method(message)

        # Write to stdout
        if level == 'error':
            self.stdout.write(self.style.ERROR(message))
        elif level == 'warning':
            self.stdout.write(self.style.WARNING(message))
        elif level == 'info':
            self.stdout.write(self.style.SUCCESS(message))
        else:
            self.stdout.write(message)

    def get_ca_type_from_storage_config(self) -> CaModel.CaTypeChoice:
        """Return the legacy local managed-CA type for generated demo CAs."""
        return CaModel.CaTypeChoice.LOCAL_PKCS11

    def _active_capability_report(self) -> BackendCapabilityReport:
        """Return the active backend capability report once for this command run."""
        if self._capability_report is None:
            self._capability_report = get_active_backend_capability_report()
        return self._capability_report

    def _require_rsa_demo_support(self, key_size: int) -> None:
        """Fail clearly before trying to create unsupported backend-backed RSA demo keys."""
        report = self._active_capability_report()
        if report.supports_rsa_key_size(key_size):
            return
        diagnostics = '; '.join(report.diagnostics) or f'RSA-{key_size} key generation/signing was not reported'
        msg = f'The active crypto backend does not support RSA-{key_size} issuing-CA demo keys: {diagnostics}'
        raise CommandError(msg)

    def _require_ec_demo_support(self, curve: ec.EllipticCurve) -> None:
        """Fail clearly before trying to create unsupported backend-backed EC demo keys."""
        report = self._active_capability_report()
        if report.supports_ec_curve(curve):
            return
        diagnostics = '; '.join(report.diagnostics) or f'{curve.name} key generation/signing was not reported'
        msg = f'The active crypto backend does not support {curve.name} issuing-CA demo keys: {diagnostics}'
        raise CommandError(msg)

    @staticmethod
    def _managed_key_model(private_key: ManagedRSAPrivateKey | ManagedECPrivateKey) -> CryptoManagedKeyModel:
        """Resolve a generated managed key facade to its database model."""
        return CryptoManagedKeyModel.objects.get(pk=private_key.managed_key_ref.id)

    @staticmethod
    def _generate_managed_private_key(
        *,
        alias: str,
        key_spec: KeySpec,
    ) -> ManagedRSAPrivateKey | ManagedECPrivateKey:
        """Generate a demo private key through the configured crypto backend."""
        return generate_managed_signing_private_key(
            alias=alias,
            key_spec=key_spec,
        )

    def _generate_demo_rsa_issuing_key(self, *, unique_name: str, key_size: int) -> rsa.RSAPrivateKey:
        """Generate a demo issuing-CA RSA key in the configured backend."""
        self._require_rsa_demo_support(key_size)
        key_label = f'{unique_name}-{uuid.uuid4().hex[:12]}'
        return self._generate_managed_private_key(alias=key_label, key_spec=RsaKeySpec(key_size=key_size))

    def _generate_demo_ec_issuing_key(
        self, *, unique_name: str, curve: ec.EllipticCurve
    ) -> ec.EllipticCurvePrivateKey:
        """Generate a demo issuing-CA EC key in the configured backend."""
        self._require_ec_demo_support(curve)
        curve_name = normalize_curve_name(curve)
        if curve_name is None:
            msg = f'Unsupported demo EC curve {curve.name!r}.'
            raise CommandError(msg)
        key_label = f'{unique_name}-{uuid.uuid4().hex[:12]}'
        key = self._generate_managed_private_key(
            alias=key_label,
            key_spec=EcKeySpec(curve=curve_name),
        )
        try:
            key.public_key()
        except ValueError as exc:
            msg = (
                f'The active crypto backend generated a {curve.name} key, but Trustpoint could not read the '
                f'public point back from the provider: {exc}'
            )
            raise CommandError(msg) from exc
        return key

    def _save_managed_generated_issuing_ca(
        self,
        *,
        issuing_ca_cert: x509.Certificate,
        chain: list[x509.Certificate],
        private_key: ManagedRSAPrivateKey | ManagedECPrivateKey,
        unique_name: str,
        ca_type: CaModel.CaTypeChoice,
        parent_ca: CaModel | None,
    ) -> CaModel:
        """Persist an issuing CA whose private key already exists in the configured backend."""
        CaModel._validate_ca_certificate(issuing_ca_cert)  # noqa: SLF001
        CaModel._validate_ca_type(ca_type)  # noqa: SLF001
        credential_model = CredentialModel.save_managed_key_credential(
            certificate=issuing_ca_cert,
            certificate_chain=chain,
            credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
            managed_key=self._managed_key_model(private_key),
        )

        issuing_ca = CaModel(
            unique_name=unique_name,
            credential=credential_model,
            ca_type=ca_type,
            parent_ca=parent_ca,
        )
        issuing_ca.save()
        truststore = CaModel._create_chain_truststore(issuing_ca)  # noqa: SLF001
        issuing_ca.chain_truststore = truststore
        issuing_ca.save(update_fields=['chain_truststore'])
        return issuing_ca

    def _save_demo_issuing_ca(
        self,
        *,
        issuing_ca_cert: x509.Certificate,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        chain: list[x509.Certificate],
        unique_name: str,
        ca_type: CaModel.CaTypeChoice,
        parent_ca: CaModel | None,
    ) -> CaModel:
        """Save a demo issuing CA without importing backend-generated keys back into software storage."""
        if isinstance(private_key, (ManagedRSAPrivateKey, ManagedECPrivateKey)):
            return self._save_managed_generated_issuing_ca(
                issuing_ca_cert=issuing_ca_cert,
                chain=chain,
                private_key=private_key,
                unique_name=unique_name,
                ca_type=ca_type,
                parent_ca=parent_ca,
            )
        return self.save_issuing_ca(
            issuing_ca_cert=issuing_ca_cert,
            private_key=private_key,
            chain=chain,
            unique_name=unique_name,
            ca_type=ca_type,
            parent_ca=parent_ca,
        )

    def generate_empty_crl(
        self,
        ca_cert: x509.Certificate,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        hash_algorithm: hashes.HashAlgorithm = hashes.SHA256(),
        crl_validity_hours: int = 2400,
    ) -> str:
        """Generate an empty CRL for a CA.

        Args:
            ca_cert: The CA certificate.
            private_key: The private key of the CA.
            hash_algorithm: The hash algorithm to use.
            crl_validity_hours: Validity period in hours.

        Returns:
            str: The CRL in PEM format.
        """
        from pki.util.crl import generate_empty_crl  # noqa: PLC0415
        return generate_empty_crl(ca_cert, private_key, hash_algorithm, crl_validity_hours)

    def verify_ca_certificate(
        self,
        ca_cert: x509.Certificate,
        issuer_cert: x509.Certificate | None = None,
        ca_name: str = 'CA'
    ) -> bool:
        """Verify a CA certificate against its issuer.

        Args:
            ca_cert: The CA certificate to verify.
            issuer_cert: The issuer CA certificate (for chain verification).
            ca_name: Name of the CA for logging purposes.

        Returns:
            bool: True if verification succeeds, False otherwise.
        """
        try:
            # For root CAs, verify self-signed
            if issuer_cert is None:
                trusted_roots = [ca_cert]
                untrusted_intermediates = []
            else:
                # For intermediate/issuing CAs, verify against issuer
                trusted_roots = [issuer_cert]
                untrusted_intermediates = []

            # Verify as CA certificate
            CertificateVerifier.verify_ca_cert(
                cert=ca_cert,
                trusted_roots=trusted_roots,
                untrusted_intermediates=untrusted_intermediates,
            )

            self.log_and_stdout(f'✓ Certificate verification passed for {ca_name}')
            return True

        except ValueError as e:
            self.log_and_stdout(
                f'✗ Certificate verification failed for {ca_name}: {e}',
                level='error'
            )
            return False
        except Exception as e:
            self.log_and_stdout(
                f'✗ Unexpected error during verification of {ca_name}: {e}',
                level='error'
            )
            return False

    def _audit_ca_created(self, ca: CaModel, label: str) -> None:
        """Log a CA_CREATED audit entry for a CA created by this management command."""
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.CA_CREATED,
            target=ca,
            target_display=f'CA: {label} (demo data)',
            actor=None,
        )

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Adds a Root CA and three issuing CAs to the database."""
        # Initialize default SecurityConfig if not already configured
        security_config, created = SecurityConfig.objects.get_or_create(
            pk=1,
            defaults={
                'security_mode': SecurityConfig.SecurityModeChoices.BROWNFIELD,
            }
        )
        if created:
            security_config.apply_security_settings()
            self.log_and_stdout('Created default SecurityConfig with BROWNFIELD security mode')
        else:
            self.log_and_stdout(f'Using existing SecurityConfig with security mode: {security_config.get_security_mode_display()}')

        # Determine CA type based on storage configuration
        ca_type = self.get_ca_type_from_storage_config()
        self.log_and_stdout(f'Using CA type: {ca_type}')

        self.log_and_stdout('Creating RSA-2048 Root CA, Intermediate CA, and Issuing CA A...')
        rsa2_root_ca_key = self._generate_demo_rsa_issuing_key(unique_name='root-ca-rsa-2048-sha256', key_size=2048)
        rsa2_int_ca_key_1 = self._generate_demo_rsa_issuing_key(unique_name='intermediate-ca-a-1', key_size=2048)
        rsa2_int_ca_key_2 = self._generate_demo_rsa_issuing_key(unique_name='intermediate-ca-a-2', key_size=2048)
        rsa2_issuing_ca_key_1 = self._generate_demo_rsa_issuing_key(unique_name='issuing-ca-a-1', key_size=2048)
        rsa2_issuing_ca_key_2 = self._generate_demo_rsa_issuing_key(unique_name='issuing-ca-a-2', key_size=2048)
        root_validity_days: int = 7300
        intermediate_validity_days: int = 5475
        issuing_validity_days: int = 3650
        rsa2_root, _ = self.create_root_ca(
            'Root-CA RSA-2048-SHA256',
            private_key=rsa2_root_ca_key,
            hash_algorithm=hashes.SHA256(),
            validity_days=root_validity_days,
            path_length=2,  # Allow 2 non-self-issued intermediate CAs (intermediate + issuing)
        )
        rsa2_root_crl = self.generate_empty_crl(rsa2_root, rsa2_root_ca_key, hashes.SHA256(), crl_validity_hours=root_validity_days * 24)
        rsa2_root_ca = self.save_keyless_ca(
            root_ca_cert=rsa2_root,
            unique_name='root-ca-rsa-2048-sha256',
            crl_pem=rsa2_root_crl,
        )
        self._audit_ca_created(rsa2_root_ca, 'Root-CA RSA-2048-SHA256')
        self.verify_ca_certificate(rsa2_root, ca_name='Root-CA RSA-2048-SHA256')

        rsa2_int_ca_1, _key = self.create_issuing_ca(
            issuer_private_key=rsa2_root_ca_key,
            private_key=rsa2_int_ca_key_1,
            issuer_cn='Root-CA RSA-2048-SHA256',
            subject_cn='Intermediate CA A-1',
            hash_algorithm=hashes.SHA256(),
            validity_days=intermediate_validity_days,
            path_length=1,
        )
        rsa2_int_ca_crl = self.generate_empty_crl(rsa2_int_ca_1, rsa2_int_ca_key_1, hashes.SHA256(), crl_validity_hours=intermediate_validity_days * 24)
        rsa2_int_ca_model_1 = self.save_keyless_ca(
            root_ca_cert=rsa2_int_ca_1,
            unique_name='intermediate-ca-a-1',
            crl_pem=rsa2_int_ca_crl,
        )
        rsa2_int_ca_model_1.parent_ca = rsa2_root_ca
        rsa2_int_ca_model_1.save()
        self._audit_ca_created(rsa2_int_ca_model_1, 'Intermediate CA A-1')
        self.verify_ca_certificate(rsa2_int_ca_1, issuer_cert=rsa2_root, ca_name='Intermediate CA A-1')

        rsa2_int_ca_2, _key = self.create_issuing_ca(
            issuer_private_key=rsa2_root_ca_key,
            private_key=rsa2_int_ca_key_2,
            issuer_cn='Root-CA RSA-2048-SHA256',
            subject_cn='Intermediate CA A-2',
            hash_algorithm=hashes.SHA256(),
            validity_days=intermediate_validity_days,
            path_length=1,
        )
        rsa2_int_ca_crl_2 = self.generate_empty_crl(rsa2_int_ca_2, rsa2_int_ca_key_2, hashes.SHA256(), crl_validity_hours=intermediate_validity_days * 24)
        rsa2_int_ca_model_2 = self.save_keyless_ca(
            root_ca_cert=rsa2_int_ca_2,
            unique_name='intermediate-ca-a-2',
            crl_pem=rsa2_int_ca_crl_2,
        )
        rsa2_int_ca_model_2.parent_ca = rsa2_root_ca
        rsa2_int_ca_model_2.save()
        self._audit_ca_created(rsa2_int_ca_model_2, 'Intermediate CA A-2')
        self.verify_ca_certificate(rsa2_int_ca_2, issuer_cert=rsa2_root, ca_name='Intermediate CA A-2')

        rsa2_issuing_ca_1, _key = self.create_issuing_ca(
            issuer_private_key=rsa2_int_ca_key_1,
            private_key=rsa2_issuing_ca_key_1,
            issuer_cn='Intermediate CA A-1',
            subject_cn='Issuing CA A-1',
            hash_algorithm=hashes.SHA256(),
            validity_days=issuing_validity_days,
        )
        rsa2_issuing_ca_model_1 = self._save_demo_issuing_ca(
            issuing_ca_cert=rsa2_issuing_ca_1,
            private_key=rsa2_issuing_ca_key_1,
            chain=[rsa2_root, rsa2_int_ca_1],
            unique_name='issuing-ca-a-1',
            ca_type=ca_type,
            parent_ca=rsa2_int_ca_model_1,
        )
        self._audit_ca_created(rsa2_issuing_ca_model_1, 'Issuing CA A-1')
        self.verify_ca_certificate(rsa2_issuing_ca_1, issuer_cert=rsa2_int_ca_1, ca_name='Issuing CA A-1')

        rsa2_issuing_ca_2, _key = self.create_issuing_ca(
            issuer_private_key=rsa2_int_ca_key_2,
            private_key=rsa2_issuing_ca_key_2,
            issuer_cn='Intermediate CA A-2',
            subject_cn='Issuing CA A-2',
            hash_algorithm=hashes.SHA256(),
            validity_days=issuing_validity_days,
        )
        rsa2_issuing_ca_model_2 = self._save_demo_issuing_ca(
            issuing_ca_cert=rsa2_issuing_ca_2,
            private_key=rsa2_issuing_ca_key_2,
            chain=[rsa2_root, rsa2_int_ca_2],
            unique_name='issuing-ca-a-2',
            ca_type=ca_type,
            parent_ca=rsa2_int_ca_model_2,
        )
        self._audit_ca_created(rsa2_issuing_ca_model_2, 'Issuing CA A-2')
        self.verify_ca_certificate(rsa2_issuing_ca_2, issuer_cert=rsa2_int_ca_2, ca_name='Issuing CA A-2')

        self.log_and_stdout('Creating RSA-3072 Root CA and Issuing CA B...')
        rsa3_root_ca_key = self._generate_demo_rsa_issuing_key(unique_name='root-ca-rsa-3072-sha256', key_size=3072)
        rsa3_issuing_ca_key = self._generate_demo_rsa_issuing_key(unique_name='issuing-ca-b', key_size=3072)
        rsa3_root, _ = self.create_root_ca(
            'Root-CA RSA-3072-SHA256', private_key=rsa3_root_ca_key, hash_algorithm=hashes.SHA256(), validity_days=root_validity_days
        )
        rsa3_root_crl = self.generate_empty_crl(rsa3_root, rsa3_root_ca_key, hashes.SHA256(), crl_validity_hours=root_validity_days * 24)
        rsa3_root_ca = self.save_keyless_ca(
            root_ca_cert=rsa3_root,
            unique_name='root-ca-rsa-3072-sha256',
            crl_pem=rsa3_root_crl,
        )
        self._audit_ca_created(rsa3_root_ca, 'Root-CA RSA-3072-SHA256')
        self.verify_ca_certificate(rsa3_root, ca_name='Root-CA RSA-3072-SHA256')

        rsa3_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=rsa3_root_ca_key,
            private_key=rsa3_issuing_ca_key,
            issuer_cn='Root-CA RSA-3072-SHA256',
            subject_cn='Issuing CA B',
            hash_algorithm=hashes.SHA256(),
            validity_days=issuing_validity_days,
        )
        rsa3_issuing_ca_model = self._save_demo_issuing_ca(
            issuing_ca_cert=rsa3_issuing_ca,
            private_key=rsa3_issuing_ca_key,
            chain=[rsa3_root],
            unique_name='issuing-ca-b',
            ca_type=ca_type,
            parent_ca=rsa3_root_ca,
        )
        self._audit_ca_created(rsa3_issuing_ca_model, 'Issuing CA B')
        self.verify_ca_certificate(rsa3_issuing_ca, issuer_cert=rsa3_root, ca_name='Issuing CA B')

        self.log_and_stdout('Creating RSA-4096 Root CA and Issuing CA C...')
        rsa4_root_ca_key = self._generate_demo_rsa_issuing_key(unique_name='root-ca-rsa-4096-sha256', key_size=4096)
        rsa4_issuing_ca_key = self._generate_demo_rsa_issuing_key(unique_name='issuing-ca-c', key_size=4096)
        rsa4_root, _ = self.create_root_ca(
            'Root-CA RSA-4096-SHA256', private_key=rsa4_root_ca_key, hash_algorithm=hashes.SHA512(), validity_days=root_validity_days
        )
        rsa4_root_crl = self.generate_empty_crl(rsa4_root, rsa4_root_ca_key, hashes.SHA512(), crl_validity_hours=root_validity_days * 24)
        rsa4_root_ca = self.save_keyless_ca(
            root_ca_cert=rsa4_root,
            unique_name='root-ca-rsa-4096-sha256',
            crl_pem=rsa4_root_crl,
        )
        self._audit_ca_created(rsa4_root_ca, 'Root-CA RSA-4096-SHA256')
        self.verify_ca_certificate(rsa4_root, ca_name='Root-CA RSA-4096-SHA256')

        rsa4_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=rsa4_root_ca_key,
            private_key=rsa4_issuing_ca_key,
            issuer_cn='Root-CA RSA-4096-SHA256',
            subject_cn='Issuing CA C',
            hash_algorithm=hashes.SHA512(),
            validity_days=issuing_validity_days,
        )
        rsa4_issuing_ca_model = self._save_demo_issuing_ca(
            issuing_ca_cert=rsa4_issuing_ca,
            private_key=rsa4_issuing_ca_key,
            chain=[rsa4_root],
            unique_name='issuing-ca-c',
            ca_type=ca_type,
            parent_ca=rsa4_root_ca,
        )
        self._audit_ca_created(rsa4_issuing_ca_model, 'Issuing CA C')
        self.verify_ca_certificate(rsa4_issuing_ca, issuer_cert=rsa4_root, ca_name='Issuing CA C')

        self.log_and_stdout('Creating SECP256R1 Root CA and Issuing CA D...')
        ecc1_root_ca_key = self._generate_demo_ec_issuing_key(
            unique_name='root-ca-secp256r1-sha256',
            curve=ec.SECP256R1(),
        )
        ecc1_issuing_ca_key = self._generate_demo_ec_issuing_key(
            unique_name='issuing-ca-d',
            curve=ec.SECP256R1(),
        )
        ecc1_root, _ = self.create_root_ca(
            'Root-CA SECP256R1-SHA256', private_key=ecc1_root_ca_key, hash_algorithm=hashes.SHA256(), validity_days=root_validity_days
        )
        ecc1_root_crl = self.generate_empty_crl(ecc1_root, ecc1_root_ca_key, hashes.SHA256(), crl_validity_hours=root_validity_days * 24)
        ecc1_root_ca = self.save_keyless_ca(
            root_ca_cert=ecc1_root,
            unique_name='root-ca-secp256r1-sha256',
            crl_pem=ecc1_root_crl,
        )
        self._audit_ca_created(ecc1_root_ca, 'Root-CA SECP256R1-SHA256')
        self.verify_ca_certificate(ecc1_root, ca_name='Root-CA SECP256R1-SHA256')

        ecc1_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=ecc1_root_ca_key,
            private_key=ecc1_issuing_ca_key,
            issuer_cn='Root-CA SECP256R1-SHA256',
            subject_cn='Issuing CA D',
            hash_algorithm=hashes.SHA256(),
            validity_days=issuing_validity_days,
        )
        ecc1_issuing_ca_model = self._save_demo_issuing_ca(
            issuing_ca_cert=ecc1_issuing_ca,
            private_key=ecc1_issuing_ca_key,
            chain=[ecc1_root],
            unique_name='issuing-ca-d',
            ca_type=ca_type,
            parent_ca=ecc1_root_ca,
        )
        self._audit_ca_created(ecc1_issuing_ca_model, 'Issuing CA D')
        self.verify_ca_certificate(ecc1_issuing_ca, issuer_cert=ecc1_root, ca_name='Issuing CA D')

        self.log_and_stdout('Creating SECP384R1 Root CA and Issuing CA E...')
        ecc2_root_ca_key = self._generate_demo_ec_issuing_key(
            unique_name='root-ca-secp384r1-sha256',
            curve=ec.SECP384R1(),
        )
        ecc2_issuing_ca_key = self._generate_demo_ec_issuing_key(
            unique_name='issuing-ca-e',
            curve=ec.SECP384R1(),
        )
        ecc2_root, _ = self.create_root_ca(
            'Root-CA SECP384R1-SHA256', private_key=ecc2_root_ca_key, hash_algorithm=hashes.SHA256(), validity_days=root_validity_days
        )
        ecc2_root_crl = self.generate_empty_crl(ecc2_root, ecc2_root_ca_key, hashes.SHA256(), crl_validity_hours=root_validity_days * 24)
        ecc2_root_ca = self.save_keyless_ca(
            root_ca_cert=ecc2_root,
            unique_name='root-ca-secp384r1-sha256',
            crl_pem=ecc2_root_crl,
        )
        self._audit_ca_created(ecc2_root_ca, 'Root-CA SECP384R1-SHA256')
        self.verify_ca_certificate(ecc2_root, ca_name='Root-CA SECP384R1-SHA256')

        ecc2_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=ecc2_root_ca_key,
            private_key=ecc2_issuing_ca_key,
            issuer_cn='Root-CA SECP384R1-SHA256',
            subject_cn='Issuing CA E',
            hash_algorithm=hashes.SHA256(),
            validity_days=issuing_validity_days,
        )
        ecc2_issuing_ca_model = self._save_demo_issuing_ca(
            issuing_ca_cert=ecc2_issuing_ca,
            private_key=ecc2_issuing_ca_key,
            chain=[ecc2_root],
            unique_name='issuing-ca-e',
            ca_type=ca_type,
            parent_ca=ecc2_root_ca,
        )
        self._audit_ca_created(ecc2_issuing_ca_model, 'Issuing CA E')
        self.verify_ca_certificate(ecc2_issuing_ca, issuer_cert=ecc2_root, ca_name='Issuing CA E')

        self.log_and_stdout('Creating SECP521R1 Root CA and Issuing CA F...')
        ecc3_root_ca_key = self._generate_demo_ec_issuing_key(
            unique_name='root-ca-secp521r1-sha256',
            curve=ec.SECP521R1(),
        )
        ecc3_issuing_ca_key = self._generate_demo_ec_issuing_key(
            unique_name='issuing-ca-f',
            curve=ec.SECP521R1(),
        )
        ecc3_root, _ = self.create_root_ca(
            'Root-CA SECP521R1-SHA256', private_key=ecc3_root_ca_key, hash_algorithm=hashes.SHA3_512(), validity_days=root_validity_days
        )
        ecc3_root_crl = self.generate_empty_crl(ecc3_root, ecc3_root_ca_key, hashes.SHA3_512(), crl_validity_hours=root_validity_days * 24)
        ecc3_root_ca = self.save_keyless_ca(
            root_ca_cert=ecc3_root,
            unique_name='root-ca-secp521r1-sha256',
            crl_pem=ecc3_root_crl,
        )
        self._audit_ca_created(ecc3_root_ca, 'Root-CA SECP521R1-SHA256')
        self.verify_ca_certificate(ecc3_root, ca_name='Root-CA SECP521R1-SHA256')

        ecc3_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=ecc3_root_ca_key,
            private_key=ecc3_issuing_ca_key,
            issuer_cn='Root-CA SECP521R1-SHA256',
            subject_cn='Issuing CA F',
            hash_algorithm=hashes.SHA3_512(),
            validity_days=issuing_validity_days,
        )
        ecc3_issuing_ca_model = self._save_demo_issuing_ca(
            issuing_ca_cert=ecc3_issuing_ca,
            private_key=ecc3_issuing_ca_key,
            chain=[ecc3_root],
            unique_name='issuing-ca-f',
            ca_type=ca_type,
            parent_ca=ecc3_root_ca,
        )
        self._audit_ca_created(ecc3_issuing_ca_model, 'Issuing CA F')
        self.verify_ca_certificate(ecc3_issuing_ca, issuer_cert=ecc3_root, ca_name='Issuing CA F')

        self.log_and_stdout('All issuing CAs have been created successfully!')
