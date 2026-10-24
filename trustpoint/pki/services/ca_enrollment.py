# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared upstream CA enrollment for browser and REST clients."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, NamedTuple, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: TC002

from pki.models import CaModel, CertificateModel, CredentialModel
from pki.models.credential import CertificateChainOrderModel, PrimaryCredentialCertificate
from pki.models.issued_credential import RemoteIssuedCredentialModel
from request.clients import EstClient
from request.clients.cmp_client import CmpClient
from request.message_builder.cmp import CmpMessageBuilder
from request.operation_processor.csr_build import ProfileAwareCsrBuilder
from request.operation_processor.csr_sign import EstDeviceCsrSignProcessor
from request.request_context import CmpCertificateRequestContext, EstCertificateRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from pki.models.cert_profile import CertificateProfileModel


class CmpContextParams(NamedTuple):
    """Parameters for creating a CMP certificate request context."""

    subject: x509.Name
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey | Any  # Any for ML-DSA keys
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | Any  # Any for ML-DSA keys
    recipient_name: str
    extensions: list[x509.Extension[x509.ExtensionType]] | None
    sender_kid: int | None


class EstCaEnrollmentService(LoggerMixin):
    """Shared upstream CA enrollment independent of browser sessions."""

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

        csr_builder = ProfileAwareCsrBuilder()
        csr_builder.process_operation(context)
        csr = csr_builder.get_csr()

        context.cert_requested = csr

        # Use EstDeviceCsrSignProcessor to re-sign the CSR with the proper signature algorithm
        csr_signer = EstDeviceCsrSignProcessor()
        csr_signer.process_operation(context)
        signed_csr = csr_signer.get_signed_csr()

        # Send the re-signed CSR to the remote EST server
        est_client = EstClient(context)
        issued_cert = est_client.simple_enroll(signed_csr)

        cert_pem = issued_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
        cert_model = CertificateModel.save_certificate(cert_obj)

        if ca.credential:
            ca.credential.certificate = cert_model
            ca.credential.save()
        else:
            credential = CredentialModel(
                credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
                certificate=cert_model,
                private_key=ca.credential.private_key if ca.credential else '',
            )
            credential.save()
            credential.certificates.add(cert_model)
            PrimaryCredentialCertificate.objects.create(credential=credential, certificate=cert_model, is_primary=True)
            ca.credential = credential
            ca.save()

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
            issued_using_cert_profile=cert_profile.unique_name,
            credential=ca.credential,
            ca=ca,
        )
        remote_issued_credential.full_clean()
        remote_issued_credential.save()

    def _build_request_data_from_form(self, cert_content_data: dict[str, Any]) -> dict[str, Any]:
        """Build request data structure from form data.

        Args:
            cert_content_data: Form data containing certificate fields.

        Returns:
            Request data in the format expected by the profile verifier.
        """
        self.logger.info('Building request data from: %s', cert_content_data)
        request_data: dict[str, Any] = {'subj': {}, 'ext': {'subject_alternative_name': {}}, 'validity': {}}

        # Subject fields
        required_subject_fields = ['common_name', 'organization_name', 'country_name', 'state_or_province_name']
        for field_name in required_subject_fields:
            value = cert_content_data.get(field_name)
            if value:
                request_data['subj'][field_name] = value

        # SAN fields
        san_fields = {
            'dns_names': 'dns_names',
            'ip_addresses': 'ip_addresses',
            'rfc822_names': 'rfc822_names',
            'uris': 'uris',
        }

        for profile_key, form_key in san_fields.items():
            value = cert_content_data.get(form_key)
            if value is not None:
                request_data['ext']['subject_alternative_name'][profile_key] = value

        # Validity fields
        validity_fields = ['days', 'hours', 'minutes', 'seconds']
        for field in validity_fields:
            value = cert_content_data.get(field)
            if value is not None:
                request_data['validity'][field] = int(value)

        return request_data


class CmpCaEnrollmentService(LoggerMixin):
    """Shared upstream CA enrollment independent of browser sessions."""

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

        csr_builder = ProfileAwareCsrBuilder()
        csr_builder.process_operation(context)
        csr = csr_builder.get_csr()

        if not csr.subject or len(csr.subject) == 0:
            msg = 'CSR does not have a subject - cannot build CMP request'
            raise ValueError(msg)

        self.logger.info('CSR subject: %s', csr.subject.rfc4514_string())

        csr_subject = csr.subject
        csr_public_key = csr.public_key()
        csr_extensions = list(csr.extensions) if csr.extensions else None

        self.logger.info('CSR has %d extensions', len(csr.extensions) if csr.extensions else 0)

        recipient_name = self._get_recipient_name_from_truststore(ca)

        private_key = self._load_private_key(ca)

        cmp_params = CmpContextParams(
            subject=csr_subject,
            public_key=cast('rsa.RSAPublicKey | ec.EllipticCurvePublicKey | Any', csr_public_key),
            private_key=private_key,
            recipient_name=recipient_name,
            extensions=csr_extensions,
            sender_kid=sender_kid,
        )

        cmp_context = self._create_cmp_context(ca, cmp_params)

        cmp_builder = CmpMessageBuilder()
        cmp_builder.build(cmp_context)

        pki_message = cmp_context.parsed_message

        cmp_client = CmpClient(cmp_context)
        issued_cert, chain_certs = cmp_client.send_and_extract_certificate(
            pki_message,
            add_shared_secret_protection=True,
        )

        self._save_cmp_certificates(ca, issued_cert, chain_certs, cert_profile)

    def _build_request_data_from_form(self, cert_content_data: dict[str, Any]) -> dict[str, Any]:
        """Build request data structure from form data.

        Args:
            cert_content_data: Form data containing certificate fields.

        Returns:
            Request data in the format expected by the profile verifier.
        """
        self.logger.info('Building request data from: %s', cert_content_data)
        request_data: dict[str, Any] = {'subj': {}, 'ext': {'subject_alternative_name': {}}, 'validity': {}}

        # Subject fields
        required_subject_fields = ['common_name', 'organization_name', 'country_name', 'state_or_province_name']
        for field_name in required_subject_fields:
            value = cert_content_data.get(field_name)
            if value:
                request_data['subj'][field_name] = value

        # SAN fields
        san_fields = {
            'dns_names': 'dns_names',
            'ip_addresses': 'ip_addresses',
            'rfc822_names': 'rfc822_names',
            'uris': 'uris',
        }

        for profile_key, form_key in san_fields.items():
            value = cert_content_data.get(form_key)
            if value is not None:
                request_data['ext']['subject_alternative_name'][profile_key] = value

        # Validity fields
        validity_fields = ['days', 'hours', 'minutes', 'seconds']
        for field in validity_fields:
            value = cert_content_data.get(field)
            if value is not None:
                request_data['validity'][field] = int(value)

        return request_data

    def _get_recipient_name_from_truststore(self, ca: CaModel) -> str:
        """Extract recipient name from the CA's truststore."""
        if not ca.no_onboarding_config or not ca.no_onboarding_config.trust_store:
            msg = 'No truststore configured for CMP CA - recipient name cannot be determined'
            raise ValueError(msg)

        try:
            truststore_certs = ca.no_onboarding_config.trust_store.truststoreordermodel_set.order_by('order')
            if not truststore_certs.exists():
                msg = 'Truststore contains no certificates - cannot determine recipient name'
                raise ValueError(msg)

            first_cert_model = truststore_certs.first().certificate  # type: ignore[union-attr]
            ca_cert = first_cert_model.get_certificate_serializer().as_crypto()
            recipient_name = ca_cert.subject.rfc4514_string()
            self.logger.info('Using recipient name from truststore: %s', recipient_name)
        except (AttributeError, IndexError) as e:
            msg = f'Failed to extract recipient name from truststore: {e}'
            raise ValueError(msg) from e
        else:
            return recipient_name

    def _load_private_key(self, ca: CaModel) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | Any:
        """Load the private key from the CA's credential."""
        if not ca.credential:
            msg = 'No private key available for CA credential'
            raise ValueError(msg)

        try:
            return cast(
                'rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | Any',
                ca.credential.get_private_key(),
            )
        except (RuntimeError, TypeError, ValueError) as exc:
            msg = 'No usable private key is available for the CA credential.'
            raise ValueError(msg) from exc

    def _create_cmp_context(
        self,
        ca: CaModel,
        params: CmpContextParams,
    ) -> CmpCertificateRequestContext:
        """Create the CMP certificate request context."""
        return CmpCertificateRequestContext(
            protocol='cmp',
            operation='certification',
            cmp_server_host=ca.remote_host,
            cmp_server_port=ca.remote_port,
            cmp_server_path=ca.remote_path,
            cmp_shared_secret=(ca.no_onboarding_config.cmp_shared_secret if ca.no_onboarding_config else None),
            cmp_server_truststore=(ca.no_onboarding_config.trust_store if ca.no_onboarding_config else None),
            request_data={
                'subject': params.subject,
                'public_key': params.public_key,
                'private_key': params.private_key,
                'recipient_name': params.recipient_name,
                'extensions': params.extensions,
                'use_initialization_request': False,
                'add_pop': True,
                'prepare_shared_secret_protection': True,
                'sender_kid': params.sender_kid,
            },
        )

    def _save_cmp_certificates(
        self,
        ca: CaModel,
        issued_cert: x509.Certificate,
        chain_certs: list[x509.Certificate],
        cert_profile: CertificateProfileModel,
    ) -> None:
        """Save the issued certificate and chain certificates."""
        cert_model = CertificateModel.save_certificate(issued_cert)

        chain_ca_models = []
        for chain_cert in chain_certs:
            existing_ca = self._find_existing_ca_for_certificate(chain_cert)
            if existing_ca:
                chain_ca_models.append(existing_ca)
            else:
                cn_attrs = chain_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                cn = cn_attrs[0].value if cn_attrs else 'unknown'
                keyless_ca = CaModel.create_keyless_ca(
                    unique_name=str(cn),
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

        if ca.credential:
            ca.credential.certificate = cert_model
            ca.credential.save()
            self._build_certificate_chain_for_credential(ca.credential, ca.parent_ca)
        else:
            credential = CredentialModel(
                credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
                certificate=cert_model,
                private_key=ca.credential.private_key if ca.credential else '',
            )
            credential.save()
            credential.certificates.add(cert_model)
            PrimaryCredentialCertificate.objects.create(credential=credential, certificate=cert_model, is_primary=True)
            ca.credential = credential
            ca.save()
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
            issued_using_cert_profile=cert_profile.unique_name,
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
        ca_by_subject = {}
        for ca in chain_ca_models:
            cert = ca.get_certificate()
            if cert:
                ca_by_subject[cert.subject.public_bytes().hex()] = ca

        for ca in chain_ca_models:
            cert = ca.get_certificate()
            if not cert:
                continue
            issuer_subject_bytes = cert.issuer.public_bytes().hex()
            if issuer_subject_bytes in ca_by_subject:
                parent_ca = ca_by_subject[issuer_subject_bytes]
                if parent_ca not in (ca, ca.parent_ca):
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
                return ca
        return None

    def _build_certificate_chain_for_credential(self, credential: CredentialModel, parent_ca: CaModel | None) -> None:
        """Build the certificate chain for the credential."""
        if not parent_ca or not credential.certificate:
            return
        chain = []
        current: CaModel | None = parent_ca
        while current:
            if current.certificate:
                chain.append(current.certificate)
            current = current.parent_ca
        credential.certificatechainordermodel_set.all().delete()
        primary_cert = credential.certificate
        for i, cert in enumerate(chain):
            CertificateChainOrderModel.objects.create(
                credential=credential, certificate=cert, order=i, primary_certificate=primary_cert
            )

    def _find_existing_ca_for_certificate(self, cert: x509.Certificate) -> CaModel | None:
        """Find an existing CA that has the given certificate."""
        # TODO(FHK): subject+issuer byte equality is not sufficient for  # noqa: FIX002

        subject_bytes = cert.subject.public_bytes().hex().upper()
        issuer_bytes = cert.issuer.public_bytes().hex().upper()

        keyless_match = CaModel.objects.filter(
            certificate__subject_public_bytes=subject_bytes,
            certificate__issuer_public_bytes=issuer_bytes,
        ).first()
        if keyless_match:
            return keyless_match

        return CaModel.objects.filter(
            credential__certificate__subject_public_bytes=subject_bytes,
            credential__certificate__issuer_public_bytes=issuer_bytes,
        ).first()
