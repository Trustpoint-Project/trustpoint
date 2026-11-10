# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared upstream CA enrollment for browser and REST clients."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from django.db import transaction

from onboarding.authorization import PermittedProtocolsAuthorization
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.authorization import PkiSecurityAuthorization
from pki.models import CaModel, CertificateModel, CredentialModel
from pki.models.credential import CertificateChainOrderModel, PrimaryCredentialCertificate
from pki.models.issued_credential import RemoteIssuedCredentialModel
from pki.services.cmp_enrollment import enroll_cmp
from pki.services.est_enrollment import enroll_est
from pki.services.external_csr import certificate_matches_credential
from pki.util.certificate_request import build_ca_request_data
from pki.util.x509 import CertificateVerifier
from request.request_context import CmpCertificateRequestContext, EstCertificateRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from pki.models.cert_profile import CertificateProfileModel
    from pki.models.truststore import TruststoreModel


def validate_ca_enrollment_certificate(ca: CaModel, certificate: x509.Certificate) -> CredentialModel:
    """Reject invalid CA material before attaching it to a managed private key."""
    CaModel._validate_ca_certificate(certificate)  # noqa: SLF001
    if ca.credential is None or not certificate_matches_credential(certificate, ca.credential):
        msg = 'The upstream certificate does not match the managed key.'
        raise ValueError(msg)
    return ca.credential


def finalize_est_issuing_ca(  # noqa: PLR0913 - Mirrors the remote PKI configuration fields.
    *,
    credential: CredentialModel,
    issued_cert: x509.Certificate,
    truststore: TruststoreModel,
    cert_profile: CertificateProfileModel,
    unique_name: str,
    remote_host: str,
    remote_port: int,
    remote_path: str,
    est_username: str,
    est_password: str,
) -> CaModel:
    """Create the Issuing CA from an EST-issued certificate and its pending key."""
    CaModel._validate_ca_certificate(issued_cert)  # noqa: SLF001
    if not certificate_matches_credential(issued_cert, credential):
        msg = 'The upstream certificate does not match the managed key.'
        raise ValueError(msg)

    cert_model = CertificateModel.save_certificate(issued_cert)
    credential.certificate = cert_model
    credential.save(update_fields=['certificate'])
    PrimaryCredentialCertificate.objects.update_or_create(
        credential=credential,
        certificate=cert_model,
        defaults={'is_primary': True},
    )

    no_onboarding_config = NoOnboardingConfigModel.objects.create(
        pki_protocols=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
        est_password=est_password,
        trust_store=truststore,
    )
    ca = CaModel(
        unique_name=unique_name,
        credential=credential,
        ca_type=CaModel.CaTypeChoice.REMOTE_ISSUING_EST,
        remote_host=remote_host,
        remote_port=remote_port,
        remote_path=remote_path,
        est_username=est_username,
        no_onboarding_config=no_onboarding_config,
    )
    PermittedProtocolsAuthorization().check(ca)
    PkiSecurityAuthorization().check(ca)
    ca.save()

    cn_attrs = issued_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    common_name_value = cn_attrs[0].value if cn_attrs else ''
    common_name = common_name_value.decode() if isinstance(common_name_value, bytes) else str(common_name_value)
    remote_issued_credential = RemoteIssuedCredentialModel(
        common_name=common_name,
        issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.LOCAL_CA,
        certificate_profile=cert_profile,
        credential=credential,
        ca=ca,
    )
    remote_issued_credential.full_clean()
    remote_issued_credential.save()
    return ca


@transaction.atomic
def finalize_cmp_issuing_ca(  # noqa: PLR0913 - Mirrors the remote PKI configuration fields.
    *,
    credential: CredentialModel,
    issued_cert: x509.Certificate,
    chain_certs: list[x509.Certificate],
    truststore: TruststoreModel,
    cert_profile: CertificateProfileModel,
    unique_name: str,
    remote_host: str,
    remote_port: int,
    remote_path: str,
    cmp_shared_secret: str,
    cmp_sender_kid: int | None = None,
) -> CaModel:
    """Create the Issuing CA from a CMP-issued certificate and its pending key."""
    no_onboarding_config = NoOnboardingConfigModel.objects.create(
        pki_protocols=NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
        cmp_shared_secret=cmp_shared_secret,
        trust_store=truststore,
    )
    ca = CaModel(
        unique_name=unique_name,
        credential=credential,
        ca_type=CaModel.CaTypeChoice.REMOTE_ISSUING_CMP,
        remote_host=remote_host,
        remote_port=remote_port,
        remote_path=remote_path,
        cmp_sender_kid=cmp_sender_kid,
        no_onboarding_config=no_onboarding_config,
    )
    PermittedProtocolsAuthorization().check(ca)
    PkiSecurityAuthorization().check(ca)
    ca.save()

    CmpCaEnrollmentService()._save_cmp_certificates(ca, issued_cert, chain_certs, cert_profile)  # noqa: SLF001
    return ca


def cmp_issuer_chain(
    issued_cert: x509.Certificate,
    extra_certs: list[x509.Certificate],
    trusted_roots: list[x509.Certificate],
) -> list[x509.Certificate]:
    """Return only issuers on a path to the explicitly configured CMP truststore."""
    chain = CertificateVerifier.verify_ca_cert(issued_cert, trusted_roots, extra_certs)[1:]
    for certificate in chain:
        CaModel._validate_ca_certificate(certificate)  # noqa: SLF001
    return chain


class EstCaEnrollmentService(LoggerMixin):
    """Shared upstream CA enrollment independent of browser sessions."""

    @transaction.atomic
    def enroll(self, ca: CaModel, cert_content_data: dict[str, Any], cert_profile: CertificateProfileModel) -> None:
        """Perform the EST enrollment process."""
        request_data = self._build_request_data_from_form(cert_content_data)
        self.logger.info('Built request data: %s', request_data)

        context = EstCertificateRequestContext(
            operation='simpleenroll',
            protocol='est',
            domain=None,
            cert_profile_str=cert_profile.unique_name,
            certificate_profile_model=cert_profile,
            allow_ca_certificate_request=True,  # Allow CA cert requests for Issuing CA enrollment
            est_server_host=ca.remote_host,
            est_server_port=ca.remote_port,
            est_server_path=ca.remote_path,
            est_username=ca.est_username,
            est_password=(ca.no_onboarding_config.est_password if ca.no_onboarding_config else None),
            est_server_truststore=(ca.no_onboarding_config.trust_store if ca.no_onboarding_config else None),
        )

        context.request_data = request_data
        context.owner_credential = ca.credential

        issued_cert, _ = enroll_est(context)

        credential = validate_ca_enrollment_certificate(ca, issued_cert)
        cert_pem = issued_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
        cert_model = CertificateModel.save_certificate(cert_obj)

        credential.certificate = cert_model
        credential.save(update_fields=['certificate'])
        PrimaryCredentialCertificate.objects.update_or_create(
            credential=credential,
            certificate=cert_model,
            defaults={'is_primary': True},
        )

        cn_attrs = cert_obj.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        common_name_value = cn_attrs[0].value if cn_attrs else ''
        # Ensure common_name is a string
        if isinstance(common_name_value, bytes):
            common_name = common_name_value.decode('utf-8')
        else:
            common_name = str(common_name_value)
        remote_issued_credential = RemoteIssuedCredentialModel(
            common_name=common_name,
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.LOCAL_CA,
            certificate_profile=cert_profile,
            credential=ca.credential,
            ca=ca,
        )
        remote_issued_credential.full_clean()
        remote_issued_credential.save()

    def _build_request_data_from_form(self, cert_content_data: dict[str, Any]) -> dict[str, Any]:
        """Use the shared CA request conversion, including SAN list normalization."""
        self.logger.info('Building request data from: %s', cert_content_data)
        return build_ca_request_data(cert_content_data)


class CmpCaEnrollmentService(LoggerMixin):
    """Shared upstream CA enrollment independent of browser sessions."""

    @transaction.atomic
    def enroll(
        self,
        ca: CaModel,
        cert_content_data: dict[str, Any],
        cert_profile: CertificateProfileModel,
        *,
        sender_kid: int | None = None,
    ) -> None:
        """Perform the CMP enrollment process."""
        request_data = self._build_request_data_from_form(cert_content_data)
        self.logger.info('Built request data: %s', request_data)

        context = CmpCertificateRequestContext(
            operation='certification',
            protocol='cmp',
            domain=None,
            cert_profile_str=cert_profile.unique_name,
            certificate_profile_model=cert_profile,
            allow_ca_certificate_request=True,
            cmp_server_host=ca.remote_host,
            cmp_server_port=ca.remote_port,
            cmp_server_path=ca.remote_path,
            cmp_shared_secret=(ca.no_onboarding_config.cmp_shared_secret if ca.no_onboarding_config else None),
            cmp_server_truststore=(ca.no_onboarding_config.trust_store if ca.no_onboarding_config else None),
        )

        context.request_data = request_data
        context.owner_credential = ca.credential

        issued_cert, chain_certs = enroll_cmp(context, sender_kid=sender_kid)

        self._save_cmp_certificates(ca, issued_cert, chain_certs, cert_profile)

    def _build_request_data_from_form(self, cert_content_data: dict[str, Any]) -> dict[str, Any]:
        """Use the shared CA request conversion, including SAN list normalization."""
        self.logger.info('Building request data from: %s', cert_content_data)
        return build_ca_request_data(cert_content_data)

    def _save_cmp_certificates(
        self,
        ca: CaModel,
        issued_cert: x509.Certificate,
        chain_certs: list[x509.Certificate],
        cert_profile: CertificateProfileModel,
    ) -> None:
        """Save the issued certificate and chain certificates."""
        credential = validate_ca_enrollment_certificate(ca, issued_cert)
        config = ca.no_onboarding_config
        if config is None or config.trust_store is None:
            msg = 'A configured issuer truststore is required for CMP CA enrollment.'
            raise ValueError(msg)
        trusted_roots = config.trust_store.get_certificate_collection_serializer().as_crypto()
        chain_certs = cmp_issuer_chain(issued_cert, chain_certs, trusted_roots)
        cert_model = CertificateModel.save_certificate(issued_cert)

        chain_ca_models = []
        for chain_cert in chain_certs:
            existing_ca = self._find_existing_ca_for_certificate(chain_cert)
            if existing_ca:
                chain_ca_models.append(existing_ca)
            else:
                cn_attrs = chain_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                cn = cn_attrs[0].value if cn_attrs else 'unknown'
                common_name = cn.decode() if isinstance(cn, bytes) else cn
                unique_name = common_name
                counter = 1
                while CaModel.objects.filter(unique_name=unique_name).exists():
                    unique_name = f'{common_name}-{counter}'
                    counter += 1
                keyless_ca = CaModel.create_keyless_ca(
                    unique_name=unique_name,
                    certificate_obj=chain_cert,
                    parent_ca=None,
                )
                chain_ca_models.append(keyless_ca)
                self.logger.info('Created keyless CA %s for chain certificate', keyless_ca.unique_name)

        self._build_ca_hierarchy(chain_ca_models)

        issuer_ca = self._find_issuer_ca(issued_cert, chain_ca_models)
        if issuer_ca:
            ca.parent_ca = issuer_ca
            ca.save()
            self.logger.info('Set parent CA %s for issuing CA %s', issuer_ca.unique_name, ca.unique_name)

        credential.certificate = cert_model
        credential.save(update_fields=['certificate'])
        PrimaryCredentialCertificate.objects.update_or_create(
            credential=credential,
            certificate=cert_model,
            defaults={'is_primary': True},
        )
        self._build_certificate_chain_for_credential(credential, ca.parent_ca)

        # Create a RemoteIssuedCredentialModel to track the issued CA credential
        cn_attrs = issued_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        common_name_value = cn_attrs[0].value if cn_attrs else ''
        # Ensure common_name is a string
        if isinstance(common_name_value, bytes):
            common_name = common_name_value.decode('utf-8')
        else:
            common_name = str(common_name_value)
        remote_issued_credential = RemoteIssuedCredentialModel(
            common_name=common_name,
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.LOCAL_CA,
            certificate_profile=cert_profile,
            credential=ca.credential,
            ca=ca,
        )
        remote_issued_credential.full_clean()
        remote_issued_credential.save()

    def _build_ca_hierarchy(
        self,
        chain_ca_models: list[CaModel],
    ) -> None:
        """Build the CA hierarchy by setting parent-child relationships."""
        for index, ca in enumerate(chain_ca_models):
            cert = ca.get_certificate()
            if cert is None:
                continue
            parent_ca = self._find_issuer_ca(cert, chain_ca_models[index + 1 :])
            if parent_ca is not None and parent_ca != ca.parent_ca:
                ca.parent_ca = parent_ca
                ca.save()
                self.logger.info('Set parent CA %s for CA %s', parent_ca.unique_name, ca.unique_name)

    def _find_issuer_ca(
        self,
        issued_cert: x509.Certificate,
        chain_ca_models: list[CaModel],
    ) -> CaModel | None:
        """Find the CA that issued the certificate."""
        issuer_subject_bytes = issued_cert.issuer.public_bytes().hex()
        for ca in chain_ca_models:
            ca_cert = ca.get_certificate()
            if ca_cert and ca_cert.subject.public_bytes().hex() == issuer_subject_bytes:
                try:
                    issued_cert.verify_directly_issued_by(ca_cert)
                except (InvalidSignature, ValueError, TypeError):
                    continue
                return ca
        return None

    def _build_certificate_chain_for_credential(self, credential: CredentialModel, parent_ca: CaModel | None) -> None:
        """Build the certificate chain for the credential."""
        if not parent_ca or not credential.certificate:
            return
        chain = []
        current: CaModel | None = parent_ca
        while current:
            if current.ca_certificate_model:
                chain.append(current.ca_certificate_model)
            current = current.parent_ca
        credential.certificatechainordermodel_set.all().delete()
        primary_cert = credential.certificate
        for i, cert in enumerate(chain):
            CertificateChainOrderModel.objects.create(
                credential=credential, certificate=cert, order=i, primary_certificate=primary_cert
            )

    def _find_existing_ca_for_certificate(self, cert: x509.Certificate) -> CaModel | None:
        """Find an existing CA that has the given certificate."""
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        keyless_match = CaModel.objects.filter(certificate__sha256_fingerprint=fingerprint).first()
        if keyless_match:
            return keyless_match
        return CaModel.objects.filter(credential__certificate__sha256_fingerprint=fingerprint).first()
