"""REST API ViewSets for Owner Credential (DevOwnerID) and Domain Credential management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from django.db.models import ProtectedError
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    PolymorphicProxySerializer,
    extend_schema,
    inline_serializer,
)
from rest_framework import filters, status, viewsets
from rest_framework import serializers as drf_serializers
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from trustpoint_core.oid import KeyPairGenerator, NamedCurve, PublicKeyAlgorithmOid, PublicKeyInfo
from trustpoint_core.serializer import PrivateKeySerializer

from pki.models import OwnerCredentialModel, RemoteIssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.certificate import CertificateModel
from pki.models.credential import CredentialModel, IDevIDReferenceModel, PrimaryCredentialCertificate
from pki.serializer.owner_credential import (
    CertificateIssuanceContentSerializer,
    OwnerCredentialEstBasicAuthSerializer,
    OwnerCredentialEstMtlsSerializer,
    OwnerCredentialFileImportSerializer,
    OwnerCredentialSerializer,
)
from pki.util.cert_profile import ProfileValidationError
from request.clients import EstClient, EstClientError
from request.operation_processor.csr_build import ProfileAwareCsrBuilder
from request.operation_processor.csr_sign import EstDeviceCsrSignProcessor
from request.request_context import EstCertificateRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from rest_framework.request import Request


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_request_data(cert_content_data: dict[str, Any]) -> dict[str, Any]:
    """Convert flat serializer data into the nested structure expected by the profile verifier."""
    request_data: dict[str, Any] = {
        'subj': {},
        'ext': {'subject_alternative_name': {}},
        'validity': {},
    }
    for field in (
        'common_name', 'organization_name', 'organizational_unit_name',
        'country_name', 'state_or_province_name', 'locality_name', 'email_address',
    ):
        value = cert_content_data.get(field)
        if value:
            request_data['subj'][field] = value
    for field in ('dns_names', 'ip_addresses', 'rfc822_names', 'uris'):
        value = cert_content_data.get(field)
        if value:
            if isinstance(value, list):
                items = [v.strip() for v in value if str(v).strip()]
            else:
                items = [v.strip() for v in str(value).split(',') if v.strip()]
            if items:
                request_data['ext']['subject_alternative_name'][field] = items
    for field in ('days', 'hours', 'minutes', 'seconds'):
        value = cert_content_data.get(field)
        if value is not None:
            request_data['validity'][field] = int(value)
    return request_data


def _public_key_info_from_key_type(key_type: str) -> PublicKeyInfo:
    """Convert a key_type string (e.g. 'RSA-2048', 'ECC-SECP256R1') to a PublicKeyInfo."""
    if key_type.startswith('RSA-'):
        key_size = int(key_type.split('-')[1])
        return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA, key_size=key_size)
    curve_name = key_type.split('-', 1)[1]
    named_curve = NamedCurve[curve_name.upper()]
    return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.ECC, named_curve=named_curve)


def _resolve_cert_profile(
    cert_profile_pk: int | None,
    default_unique_name: str,
) -> CertificateProfileModel:
    """Resolve a certificate profile by pk or by its unique_name default.

    Raises ``CertificateProfileModel.DoesNotExist`` if nothing is found.
    """
    if cert_profile_pk is not None:
        return CertificateProfileModel.objects.get(pk=cert_profile_pk)
    try:
        return CertificateProfileModel.objects.get(unique_name=default_unique_name)
    except CertificateProfileModel.DoesNotExist:
        first = CertificateProfileModel.objects.order_by('display_name', 'unique_name').first()
        if first is None:
            raise
        return first


def _create_key_only_credential(
    owner_credential: OwnerCredentialModel,
    cert_profile: CertificateProfileModel,
    cred_type: RemoteIssuedCredentialModel.RemoteIssuedCredentialType,
    credential_model_type: CredentialModel.CredentialTypeChoice,
) -> RemoteIssuedCredentialModel:
    """Generate a fresh key pair and create a key-only RemoteIssuedCredentialModel."""
    key_type = owner_credential.key_type or 'ECC-SECP256R1'
    private_key = KeyPairGenerator.generate_key_pair_for_public_key_info(
        _public_key_info_from_key_type(key_type)
    )
    private_key_pem = PrivateKeySerializer(private_key).as_pkcs8_pem().decode()
    credential_model = CredentialModel.objects.create(
        credential_type=credential_model_type,
        private_key=private_key_pem,
        certificate=None,
    )
    return RemoteIssuedCredentialModel.objects.create(
        common_name=owner_credential.unique_name,
        issued_credential_type=cred_type,
        issued_using_cert_profile=cert_profile.unique_name,
        credential=credential_model,
        owner_credential=owner_credential,
    )

@extend_schema(tags=['DevOwnerID'])
class DevOwnerIdViewSet(LoggerMixin, viewsets.GenericViewSet[OwnerCredentialModel]):
    """ViewSet for managing DevOwnerID (OwnerCredential) instances via REST API.

    Endpoints
    ---------
    GET    /api/devownerid/                         - list all DevOwnerIDs
    POST   /api/devownerid/                         - create (file-import, est-basic-auth, est-mtls)
    GET    /api/devownerid/{id}/                    - retrieve a single DevOwnerID
    DELETE /api/devownerid/{id}/                    - delete a DevOwnerID
    POST   /api/devownerid/{id}/request/domain_credential/  - enroll a Domain Credential via EST
    POST   /api/devownerid/{id}/request/devownerid/         - enroll a DevOwnerID certificate via EST
    """

    queryset = OwnerCredentialModel.objects.order_by('-created_at')
    serializer_class = OwnerCredentialSerializer
    permission_classes = (IsAuthenticated,)
    filter_backends = (
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    )
    filterset_fields: ClassVar = ['unique_name', 'owner_credential_type']
    search_fields: ClassVar = ['unique_name', 'remote_host']
    ordering_fields: ClassVar = ['unique_name', 'created_at']

    @extend_schema(
        summary='List DevOwnerIDs',
        description='Retrieve all DevOwnerID (OwnerCredential) instances.',
        responses={200: OwnerCredentialSerializer(many=True)},
    )
    def list(self, _request: Request) -> Response:
        """Return all DevOwnerID instances."""
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        summary='Retrieve DevOwnerID',
        description='Retrieve details of a single DevOwnerID by ID.',
        responses={200: OwnerCredentialSerializer},
    )
    def retrieve(self, _request: Request, pk: int | None = None, **_kwargs: Any) -> Response:
        """Return a single DevOwnerID instance."""
        del pk
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        summary='Create DevOwnerID',
        description=(
            'Create a new DevOwnerID. '
            'The ``method`` field selects the creation mode:\n\n'
            '- ``file_import``: Upload PEM certificate + private key files '
            '- ``est_basic_auth``: Configure an EST endpoint authenticated with username/password. '
            'Required fields: ``remote_host``, ``remote_port``, ``remote_path``, '
            '``est_username``, ``est_password``, ``key_type``, ``truststore_id`` (optional).\n'
            '- ``est_mtls``: Configure an EST endpoint with IDevID-based mTLS onboarding. '
            'Required fields: ``remote_host``, ``remote_port``, ``remote_path``, '
            '``remote_path_domain_credential``, ``est_username``, ``est_password``, '
            '``key_type``, ``truststore_id`` (optional).\n\n'
            'The ``unique_name`` field is optional for all methods; '
            'it is derived from the certificate or host if omitted.'
        ),
        request=PolymorphicProxySerializer(
            component_name='DevOwnerIdCreate',
            serializers=[
                OwnerCredentialFileImportSerializer,
                OwnerCredentialEstBasicAuthSerializer,
                OwnerCredentialEstMtlsSerializer,
            ],
            resource_type_field_name='method',
        ),
        responses={
            201: OwnerCredentialSerializer,
            400: OpenApiTypes.OBJECT,
        },
    )
    def create(self, request: Request) -> Response:
        """Dispatch DevOwnerID creation to the appropriate sub-serializer based on ``method``."""
        method = request.data.get('method')
        if method == 'file_import':
            return self._create_file_import(request)
        if method == 'est_basic_auth':
            return self._create_est_basic_auth(request)
        if method == 'est_mtls':
            return self._create_est_mtls(request)
        return Response(
            {'detail': 'Invalid or missing "method". Choose from: file_import, est_basic_auth, est_mtls.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def _create_file_import(self, request: Request) -> Response:
        serializer = OwnerCredentialFileImportSerializer(
            data=request.data, context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(OwnerCredentialSerializer(instance).data, status=status.HTTP_201_CREATED)

    def _create_est_basic_auth(self, request: Request) -> Response:
        serializer = OwnerCredentialEstBasicAuthSerializer(
            data=request.data, context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(OwnerCredentialSerializer(instance).data, status=status.HTTP_201_CREATED)

    def _create_est_mtls(self, request: Request) -> Response:
        serializer = OwnerCredentialEstMtlsSerializer(
            data=request.data, context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(OwnerCredentialSerializer(instance).data, status=status.HTTP_201_CREATED)

    @extend_schema(
        summary='Delete DevOwnerID',
        description='Delete a DevOwnerID and all its associated issued credentials.',
        responses={
            204: None,
            404: OpenApiTypes.OBJECT,
            409: OpenApiTypes.OBJECT,
        },
    )
    def destroy(self, _request: Request, pk: int | None = None, **_kwargs: Any) -> Response:
        """Delete a DevOwnerID instance."""
        del pk
        instance = self.get_object()
        try:
            instance.delete()
        except ProtectedError as exc:
            return Response(
                {'detail': f'Cannot delete DevOwnerID: it is referenced by other objects. {exc}'},
                status=status.HTTP_409_CONFLICT,
            )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        summary='Request Domain Credential via EST',
        description=(
            'Enroll a new Domain Credential for this DevOwnerID using EST basic-auth. '
            'This is only available for DevOwnerIDs of type ``REMOTE_EST_ONBOARDING``. '
            'Mirrors ``POST /pki/owner-credentials/define-cert-content-domain-credential-est/{id}/`` '
            'followed by ``POST /pki/owner-credentials/request-domain-credential-est/{id}/``.\n\n'
            'Provide certificate subject / SAN / validity in the request body. '
            'Optionally pass ``cert_profile_pk`` to select a specific certificate profile '
            '(defaults to ``devownerid_domain_credential`` if it exists).'
        ),
        request=CertificateIssuanceContentSerializer,
        responses={
            200: inline_serializer(
                name='DomainCredentialEnrollResult',
                fields={
                    'message': drf_serializers.CharField(),
                    'issued_credential_id': drf_serializers.IntegerField(),
                    'common_name': drf_serializers.CharField(),
                },
            ),
            400: OpenApiTypes.OBJECT,
            404: OpenApiTypes.OBJECT,
        },
    )
    @action(
        detail=True,
        methods=['post'],
        url_path='request/domain_credential',
        permission_classes=[IsAuthenticated],
    )
    def request_domain_credential(self, request: Request, pk: int | None = None, **_kwargs: Any) -> Response:
        """Enroll a Domain Credential for this DevOwnerID via EST."""
        del pk
        owner_credential: OwnerCredentialModel = self.get_object()

        if (
            owner_credential.owner_credential_type
            != OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST_ONBOARDING
        ):
            return Response(
                {'detail': 'Domain credentials are only available for DevOwnerIDs of type REMOTE_EST_ONBOARDING.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        content_serializer = CertificateIssuanceContentSerializer(
            data=request.data, context={'request': request}
        )
        content_serializer.is_valid(raise_exception=True)
        cert_content = content_serializer.validated_data

        try:
            cert_profile = _resolve_cert_profile(
                cert_content.get('cert_profile_pk'),
                'devownerid_domain_credential',
            )
        except CertificateProfileModel.DoesNotExist:
            return Response(
                {'detail': 'No certificate profiles found. Please create one first.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        pending_issued = _create_key_only_credential(
            owner_credential,
            cert_profile,
            RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DOMAIN_CREDENTIAL,
            CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
        )

        try:
            self._enroll_domain_credential(owner_credential, cert_profile, pending_issued, cert_content)
        except (ValueError, KeyError, ProfileValidationError) as exc:
            pending_issued.delete()
            return Response(
                {'detail': f'Failed to build certificate request: {exc}'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except EstClientError as exc:
            self.logger.exception('EST client error during Domain Credential enrollment')
            pending_issued.delete()
            return Response(
                {'detail': f'Failed to enroll Domain Credential via EST: {exc}'},
                status=status.HTTP_502_BAD_GATEWAY,
            )
        except Exception as exc:
            self.logger.exception('Unexpected error during Domain Credential EST enrollment')
            pending_issued.delete()
            return Response(
                {'detail': f'Unexpected error during enrollment: {exc}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        pending_issued.refresh_from_db()
        return Response(
            {
                'message': (
                    f'Successfully enrolled Domain Credential for "{owner_credential.unique_name}" via EST.'
                ),
                'issued_credential_id': pending_issued.pk,
                'common_name': pending_issued.common_name,
            },
            status=status.HTTP_200_OK,
        )

    def _enroll_domain_credential(
        self,
        owner_credential: OwnerCredentialModel,
        cert_profile: CertificateProfileModel,
        pending_issued: RemoteIssuedCredentialModel,
        cert_content: dict[str, Any],
    ) -> None:
        """Perform the EST enrollment for a Domain Credential."""
        signing_credential = pending_issued.credential
        onboarding_config = owner_credential.onboarding_config

        context = EstCertificateRequestContext(
            operation='simpleenroll',
            protocol='est',
            domain=None,
            cert_profile_str=cert_profile.unique_name,
            certificate_profile_model=cert_profile,
            allow_ca_certificate_request=False,
            est_server_host=owner_credential.remote_host,
            est_server_port=owner_credential.remote_port,
            est_server_path=owner_credential.remote_path_domain_credential,
            est_username=owner_credential.est_username,
            est_password=onboarding_config.est_password if onboarding_config else None,
            est_server_truststore=onboarding_config.trust_store if onboarding_config else None,
        )
        context.request_data = _build_request_data(cert_content)
        context.owner_credential = signing_credential

        csr_builder = ProfileAwareCsrBuilder()
        csr_builder.process_operation(context)
        csr = csr_builder.get_csr()
        context.cert_requested = csr

        csr_signer = EstDeviceCsrSignProcessor()
        csr_signer.process_operation(context)
        signed_csr = csr_signer.get_signed_csr()

        est_client = EstClient(context)
        issued_cert = est_client.simple_enroll(signed_csr)

        cert_pem = issued_cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
        cert_obj = load_pem_x509_certificate(cert_pem.encode())
        cert_model = CertificateModel.save_certificate(cert_obj)

        signing_credential.certificate = cert_model
        signing_credential.save()
        PrimaryCredentialCertificate.objects.get_or_create(
            credential=signing_credential,
            certificate=cert_model,
            defaults={'is_primary': True},
        )

        cn = cert_model.common_name or owner_credential.unique_name
        pending_issued.common_name = cn
        pending_issued.issued_using_cert_profile = cert_profile.unique_name
        pending_issued.save(update_fields=['common_name', 'issued_using_cert_profile'])

    @extend_schema(
        summary='Request DevOwnerID certificate via EST',
        description=(
            'Enroll a new DevOwnerID certificate for this DevOwnerID using EST. '
            'Available for both ``REMOTE_EST`` (basic auth) and ``REMOTE_EST_ONBOARDING`` (mTLS) types. '
            'For mTLS, an existing valid domain credential is required. '
            'Mirrors ``POST /pki/owner-credentials/define-cert-content-est/{id}/`` '
            'followed by ``POST /pki/owner-credentials/request-cert-est/{id}/``.\n\n'
            'Optionally pass ``cert_profile_pk`` to select a specific certificate profile '
            '(defaults to ``dev_owner_id`` if it exists).'
        ),
        request=CertificateIssuanceContentSerializer,
        responses={
            200: inline_serializer(
                name='DevOwnerIdEnrollResult',
                fields={
                    'message': drf_serializers.CharField(),
                    'issued_credential_id': drf_serializers.IntegerField(),
                    'common_name': drf_serializers.CharField(),
                },
            ),
            400: OpenApiTypes.OBJECT,
            404: OpenApiTypes.OBJECT,
        },
    )
    @action(
        detail=True,
        methods=['post'],
        url_path='request/devownerid',
        permission_classes=[IsAuthenticated],
    )
    def request_devownerid(self, request: Request, pk: int | None = None, **_kwargs: Any) -> Response:
        """Enroll a DevOwnerID certificate for this DevOwnerID via EST."""
        del pk
        owner_credential: OwnerCredentialModel = self.get_object()

        allowed_types = (
            OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST,
            OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST_ONBOARDING,
        )
        if owner_credential.owner_credential_type not in allowed_types:
            msg = (
                'DevOwnerID certificate request is only available for '
                'REMOTE_EST or REMOTE_EST_ONBOARDING types.'
            )
            return Response({'detail': msg}, status=status.HTTP_400_BAD_REQUEST)

        content_serializer = CertificateIssuanceContentSerializer(
            data=request.data, context={'request': request}
        )
        content_serializer.is_valid(raise_exception=True)
        cert_content = content_serializer.validated_data

        try:
            cert_profile = _resolve_cert_profile(
                cert_content.get('cert_profile_pk'),
                'dev_owner_id',
            )
        except CertificateProfileModel.DoesNotExist:
            return Response(
                {'detail': 'No certificate profiles found. Please create one first.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        pending_issued = _create_key_only_credential(
            owner_credential,
            cert_profile,
            RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        )

        try:
            self._enroll_devownerid(owner_credential, cert_profile, pending_issued, cert_content)
        except (ValueError, KeyError, ProfileValidationError) as exc:
            pending_issued.delete()
            return Response(
                {'detail': f'Failed to build certificate request: {exc}'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except EstClientError as exc:
            self.logger.exception('EST client error during DevOwnerID enrollment')
            pending_issued.delete()
            return Response(
                {'detail': f'Failed to enroll DevOwnerID certificate via EST: {exc}'},
                status=status.HTTP_502_BAD_GATEWAY,
            )
        except Exception as exc:
            self.logger.exception('Unexpected error during DevOwnerID EST enrollment')
            pending_issued.delete()
            return Response(
                {'detail': f'Unexpected error during enrollment: {exc}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        pending_issued.refresh_from_db()
        return Response(
            {
                'message': (
                    f'Successfully enrolled DevOwnerID certificate for "{owner_credential.unique_name}" via EST.'
                ),
                'issued_credential_id': pending_issued.pk,
                'common_name': pending_issued.common_name,
            },
            status=status.HTTP_200_OK,
        )

    def _build_est_context_kwargs(
        self,
        owner_credential: OwnerCredentialModel,
        cert_profile: CertificateProfileModel,
    ) -> dict[str, Any]:
        """Build keyword arguments for EstCertificateRequestContext."""
        kwargs: dict[str, Any] = {
            'operation': 'simpleenroll',
            'protocol': 'est',
            'domain': None,
            'cert_profile_str': cert_profile.unique_name,
            'certificate_profile_model': cert_profile,
            'allow_ca_certificate_request': True,
            'est_server_host': owner_credential.remote_host,
            'est_server_port': owner_credential.remote_port,
            'est_server_path': owner_credential.remote_path,
        }

        is_onboarding = (
            owner_credential.owner_credential_type
            == OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST_ONBOARDING
        )

        if is_onboarding:
            onboarding_config = owner_credential.onboarding_config
            kwargs['est_server_truststore'] = onboarding_config.trust_store if onboarding_config else None
            domain_cred_issued = owner_credential.domain_credential
            if domain_cred_issued is None or domain_cred_issued.credential is None:
                msg = (
                    'No domain credential found for this owner credential. '
                    'Please issue a domain credential first.'
                )
                raise ValueError(msg)
            dc = domain_cred_issued.credential
            if dc.certificate is None:
                msg = 'The domain credential has no certificate. Please issue a domain credential first.'
                raise ValueError(msg)
            kwargs['est_client_cert_pem'] = dc.certificate.cert_pem
            kwargs['est_client_key_pem'] = dc.private_key
        else:
            no_onboarding = owner_credential.no_onboarding_config
            kwargs['est_username'] = owner_credential.est_username
            kwargs['est_password'] = no_onboarding.est_password if no_onboarding else None
            kwargs['est_server_truststore'] = no_onboarding.trust_store if no_onboarding else None

        return kwargs

    def _enroll_devownerid(
        self,
        owner_credential: OwnerCredentialModel,
        cert_profile: CertificateProfileModel,
        pending_issued: RemoteIssuedCredentialModel,
        cert_content: dict[str, Any],
    ) -> None:
        """Perform the EST enrollment for a DevOwnerID certificate."""
        signing_credential = pending_issued.credential
        est_kwargs = self._build_est_context_kwargs(owner_credential, cert_profile)
        context = EstCertificateRequestContext(**est_kwargs)
        context.request_data = _build_request_data(cert_content)
        context.owner_credential = signing_credential

        csr_builder = ProfileAwareCsrBuilder()
        csr_builder.process_operation(context)
        csr = csr_builder.get_csr()
        context.cert_requested = csr

        csr_signer = EstDeviceCsrSignProcessor()
        csr_signer.process_operation(context)
        signed_csr = csr_signer.get_signed_csr()

        est_client = EstClient(context)
        issued_cert = est_client.simple_enroll(signed_csr)

        cert_pem = issued_cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
        cert_obj = load_pem_x509_certificate(cert_pem.encode())
        cert_model = CertificateModel.save_certificate(cert_obj)

        signing_credential.certificate = cert_model
        signing_credential.save()
        PrimaryCredentialCertificate.objects.get_or_create(
            credential=signing_credential,
            certificate=cert_model,
            defaults={'is_primary': True},
        )

        cn = cert_model.common_name or owner_credential.unique_name
        pending_issued.common_name = cn
        pending_issued.save(update_fields=['common_name'])

        try:
            san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for san in san_ext.value:
                if isinstance(san, x509.UniformResourceIdentifier) and san.value.startswith('dev-owner:'):
                    IDevIDReferenceModel.objects.get_or_create(
                        dev_owner_id=owner_credential,
                        idevid_ref=san.value,
                        defaults={'dev_owner_id_certificate': cert_model},
                    )
        except x509.ExtensionNotFound:
            self.logger.warning(
                'Issued DevOwnerID certificate for "%s" has no SAN; no IDevID refs stored.',
                owner_credential.unique_name,
            )
