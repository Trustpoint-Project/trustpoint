# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""REST management of certificate authorities, CRLs, and CA rollovers."""

from copy import copy
from typing import Any, ClassVar

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.db.models import ProtectedError
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.datastructures import MultiValueDict
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from rest_framework import filters, mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, MethodNotAllowed, ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from management.models import SecurityConfig
from management.models.audit_log import AuditLog
from management.security_change_audit import audit_security_change, security_change, snapshot_security_state
from pki.auto_gen_pki import AutoGenPki
from pki.forms.cert_profiles import CertificateIssuanceForm
from pki.forms.issuing_cas import (
    IssuingCaAddAutoGenForm,
    IssuingCaAddFileImportPkcs12Form,
    IssuingCaAddRequestCmpForm,
    IssuingCaAddRequestEstForm,
    IssuingCaAddRequestExternalCsrForm,
    IssuingCaCrlCycleForm,
    IssuingCaExternalCsrCertificateForm,
    IssuingCaImportMixin,
    IssuingCaTruststoreAssociationForm,
)
from pki.models import CaModel, CertificateModel, CrlModel
from pki.models.ca_rollover import CaRolloverModel, CaRolloverStrategyType
from pki.models.cert_profile import CertificateProfileModel
from pki.models.credential import PrimaryCredentialCertificate
from pki.models.truststore import TruststoreModel
from pki.rollover.generate_keypair import GenerateKeypairCmpRolloverForm, GenerateKeypairEstRolloverForm
from pki.rollover.import_ca import ImportCaRolloverForm, SeparateFilesCaRolloverForm
from pki.serializer.ca_api import (
    CaCertificateSerializer,
    CaCertificateUploadSerializer,
    CaCrlSettingsSerializer,
    CaEnrollmentSerializer,
    CaExternalCsrSerializer,
    CaGenerateSerializer,
    CaPkcs12Serializer,
    CaRemoteSerializer,
    CaRolloverPlanSerializer,
    CaRolloverSerializer,
    CaSerializer,
    CaTruststoreSerializer,
    CrlImportSerializer,
    CrlSerializer,
    EncodingSerializer,
)
from pki.services.ca_enrollment import CmpCaEnrollmentService, EstCaEnrollmentService
from pki.services.ca_rollover import CaRolloverError, CaRolloverService
from pki.services.external_csr import build_external_csr, certificate_matches_credential
from pki.util.cert_profile import ProfileValidationError
from pki.views.issuing_cas import CanManageIssuingCas, IssuingCaViewSet
from request.clients import EstClientError
from request.clients.cmp_client import CmpClientError


class Conflict(APIException):
    """A protected dependency or lifecycle state prevents this operation."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = 'The operation conflicts with the current state.'


class UpstreamError(APIException):
    """The upstream PKI could not complete certificate enrollment."""

    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = 'The upstream PKI could not complete certificate enrollment.'


class PkiApiErrorsMixin(APIView):
    """Translate shared domain validation into stable API errors."""

    def handle_exception(self, exc: Exception) -> Response:
        """Preserve DRF authentication handling and map domain errors."""
        if isinstance(exc, ProtectedError):
            exc = Conflict('The object is referenced by other objects and cannot be deleted.')
        elif isinstance(exc, IntegrityError):
            exc = Conflict('An object with these identifiers already exists.')
        elif isinstance(exc, DjangoValidationError):
            exc = ValidationError(exc.message_dict if hasattr(exc, 'message_dict') else exc.messages)
        elif isinstance(exc, (ProfileValidationError, ValueError)):
            exc = ValidationError(str(exc))
        elif isinstance(exc, CaRolloverError):
            exc = Conflict(str(exc))
        return super().handle_exception(exc)


def validated_form(form: Any) -> Any:
    """Raise on invalid forms so surrounding transactions roll back form side effects."""
    if not form.is_valid():
        raise ValidationError({key: list(errors) for key, errors in form.errors.items()})
    return form


def download_response(content: bytes, filename: str, content_type: str) -> HttpResponse:
    """Build an attachment response with a safe generated filename."""
    safe_name = ''.join(char if char.isalnum() or char in '._-' else '_' for char in filename)
    response = HttpResponse(content, content_type=content_type)
    response['Content-Disposition'] = f'attachment; filename="{safe_name}"'
    return response


class CaInventoryMixin(viewsets.GenericViewSet[CaModel]):
    """Public certificate inspection and guarded deletion shared by both CA inventories."""

    @transaction.atomic
    def perform_destroy(self, instance: CaModel) -> None:
        """Honor model dependency checks and audit the deletion atomically."""
        instance = CaModel.objects.select_for_update().get(pk=instance.pk)
        target = copy(instance)
        before = snapshot_security_state(instance)
        instance.delete()
        audit_security_change(target=target, actor=self.request.user, before=before, action='deleted')

    @extend_schema(parameters=[EncodingSerializer], responses={(200, 'application/octet-stream'): OpenApiTypes.BINARY})
    @action(detail=True, methods=['get'], url_path='certificate')
    def certificate(self, request: Request, pk: str | None = None) -> HttpResponse:
        """Download the CA certificate in PEM or DER encoding."""
        del pk
        ca = self.get_object()
        certificate = ca.ca_certificate_model
        if certificate is None:
            from rest_framework.exceptions import NotFound  # noqa: PLC0415

            msg = 'The CA does not have a certificate yet.'
            raise NotFound(msg)
        query = EncodingSerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        encoding = query.validated_data['encoding']
        crypto_certificate = certificate.get_certificate_serializer().as_crypto()
        return download_response(
            crypto_certificate.public_bytes(
                serialization.Encoding.PEM if encoding == 'pem' else serialization.Encoding.DER
            ),
            f'{ca.unique_name}.{encoding}',
            'application/x-pem-file' if encoding == 'pem' else 'application/pkix-cert',
        )

    @extend_schema(responses=CaCertificateSerializer(many=True))
    @action(detail=True, methods=['get'], url_path='issued-certificates')
    def issued_certificates(self, request: Request, pk: str | None = None) -> Response:
        """List public certificates issued by this CA."""
        del pk
        certificates = self.get_object().get_issued_certificates().order_by('-not_valid_before', 'pk')
        paginator = self.paginator
        page = paginator.paginate_queryset(certificates, request, view=self) if paginator is not None else None
        data = CaCertificateSerializer(page if page is not None else certificates, many=True).data
        return self.get_paginated_response(data) if page is not None else Response(data)


@extend_schema(tags=['CA'])
class CaViewSet(
    PkiApiErrorsMixin,
    CaInventoryMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet[CaModel],
):
    """Read the full CA hierarchy, including keyless and autogenerated roots, or delete an unused CA."""

    queryset = CaModel.objects.select_related('parent_ca', 'certificate', 'credential__certificate').order_by('pk')
    serializer_class = CaSerializer
    permission_classes = (CanManageIssuingCas,)
    filter_backends = (DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter)
    filterset_fields: ClassVar = ['ca_type', 'is_active', 'parent_ca']
    search_fields: ClassVar = ['unique_name']
    ordering_fields: ClassVar = ['unique_name', 'created_at']


class ApiPkcs12Form(IssuingCaAddFileImportPkcs12Form):
    """Capture the CA created by the shared import form, including generated names."""

    def _finalize_issuing_ca_creation(self, *args: Any, **kwargs: Any) -> CaModel:
        self.created_ca = super()._finalize_issuing_ca_creation(*args, **kwargs)
        return self.created_ca


@extend_schema(tags=['Issuing-CA'])
class IssuingCaManagementViewSet(PkiApiErrorsMixin, CaInventoryMixin, IssuingCaViewSet):
    """Extend the existing issuing CA API without changing its PEM import contract."""

    serializer_class = CaSerializer
    http_method_names = ['get', 'post', 'delete', 'patch', 'head', 'options']  # noqa: RUF012

    def retrieve(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Retrieve a CA with DRF's router-provided lookup keyword arguments."""
        return mixins.RetrieveModelMixin.retrieve(self, request, *args, **kwargs)

    @extend_schema(exclude=True)
    def partial_update(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Use dedicated actions for validated CA configuration changes."""
        del request, args, kwargs
        msg = 'PATCH'
        raise MethodNotAllowed(msg)

    def _certificate_content(self, request: Request) -> tuple[CertificateProfileModel, dict[str, Any], int | None]:
        """Validate profile-based content without depending on a browser session."""
        serializer = CaEnrollmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        values = dict(serializer.validated_data)
        profile_pk = values.pop('cert_profile_pk', None)
        sender_kid = values.pop('sender_kid', None)
        profile = (
            get_object_or_404(CertificateProfileModel, pk=profile_pk)
            if profile_pk
            else get_object_or_404(CertificateProfileModel, unique_name='issuing_ca')
        )
        form = validated_form(CertificateIssuanceForm(data=values, profile=profile.profile))
        return profile, form.cleaned_data, sender_kid

    @extend_schema(request=CaEnrollmentSerializer, responses={(200, 'application/pkcs10'): OpenApiTypes.BINARY})
    @action(detail=True, methods=['post'], url_path='csr')
    def csr(self, request: Request, pk: str | None = None) -> HttpResponse:
        """Generate a profile-based CSR using the CA's managed private key."""
        del pk
        ca = self.get_object()
        allowed_types = (
            CaModel.CaTypeChoice.REMOTE_ISSUING_CSR,
            CaModel.CaTypeChoice.REMOTE_ISSUING_EST,
            CaModel.CaTypeChoice.REMOTE_ISSUING_CMP,
        )
        if ca.ca_type not in allowed_types or ca.credential is None or not ca.is_active:
            msg = 'This CA is not configured for a certificate request.'
            raise ValidationError(msg)
        profile, content, _sender_kid = self._certificate_content(request)
        try:
            csr = build_external_csr(ca.credential, profile, content, allow_ca=True)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        return download_response(
            csr.public_bytes(serialization.Encoding.PEM), f'{ca.unique_name}.csr', 'application/pkcs10'
        )

    @extend_schema(request=CaCertificateUploadSerializer, responses=CaSerializer)
    @action(detail=True, methods=['post'], url_path='import-certificate')
    @transaction.atomic
    def import_certificate(self, request: Request, pk: str | None = None) -> Response:
        """Attach a matching CA certificate to a pending managed credential."""
        del pk
        ca = self.get_object()
        ca = CaModel.objects.select_for_update().get(pk=ca.pk)
        allowed_types = (
            CaModel.CaTypeChoice.REMOTE_ISSUING_CSR,
            CaModel.CaTypeChoice.REMOTE_ISSUING_EST,
            CaModel.CaTypeChoice.REMOTE_ISSUING_CMP,
        )
        if ca.ca_type not in allowed_types or not ca.is_active or ca.credential is None:
            msg = 'This CA is not awaiting an externally issued certificate.'
            raise ValidationError(msg)
        if ca.credential.certificate is not None:
            msg = 'The CA already has a certificate. Use a CA rollover to replace it.'
            raise Conflict(msg)
        serializer = CaCertificateUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        form = validated_form(
            IssuingCaExternalCsrCertificateForm(
                files={'certificate': serializer.validated_data['certificate']}, instance=ca
            )
        )
        cert = form.cleaned_data['certificate'].as_crypto()
        IssuingCaImportMixin()._validate_ca_certificate(cert)  # noqa: SLF001
        with security_change(target=ca, actor=request.user):
            ca.credential.certificate = CertificateModel.save_certificate(cert)
            ca.credential.save()
            PrimaryCredentialCertificate.objects.update_or_create(
                credential=ca.credential, defaults={'certificate': ca.credential.certificate, 'is_primary': True}
            )
            CaRolloverService.complete_awaiting_rollover_for_ca(ca)
        return Response(CaSerializer(ca).data)

    @extend_schema(request=CaEnrollmentSerializer, responses=CaSerializer)
    @action(detail=True, methods=['post'], url_path='enroll')
    @transaction.atomic
    def enroll(self, request: Request, pk: str | None = None) -> Response:
        """Request a CA certificate from its configured upstream EST or CMP server."""
        del pk
        ca = self.get_object()
        ca = CaModel.objects.select_for_update().get(pk=ca.pk)
        if ca.ca_type not in (CaModel.CaTypeChoice.REMOTE_ISSUING_EST, CaModel.CaTypeChoice.REMOTE_ISSUING_CMP):
            msg = 'Only remote EST or CMP issuing CAs support enrollment.'
            raise ValidationError(msg)
        if not ca.is_active or ca.credential is None or ca.no_onboarding_config is None:
            msg = 'The CA has no active managed enrollment configuration.'
            raise ValidationError(msg)
        if not ca.no_onboarding_config.trust_store_id:
            msg = 'Associate the upstream truststore before enrollment.'
            raise ValidationError(msg)
        if ca.credential.certificate is not None:
            msg = 'The CA already has a certificate. Use a CA rollover to replace it.'
            raise Conflict(msg)
        profile, content, sender_kid = self._certificate_content(request)
        with security_change(target=ca, actor=request.user):
            try:
                if ca.ca_type == CaModel.CaTypeChoice.REMOTE_ISSUING_EST:
                    EstCaEnrollmentService().enroll(ca, content, profile)
                else:
                    CmpCaEnrollmentService().enroll(ca, content, profile, sender_kid=sender_kid)
            except (EstClientError, CmpClientError) as exc:
                raise UpstreamError from exc
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            certificate_model = ca.credential.certificate
            if certificate_model is None:
                raise UpstreamError
            cert = certificate_model.get_certificate_serializer().as_crypto()
            IssuingCaImportMixin()._validate_ca_certificate(cert)  # noqa: SLF001
            if not certificate_matches_credential(cert, ca.credential):
                msg = 'The upstream certificate does not match the managed key.'
                raise ValidationError(msg)
            CaRolloverService.complete_awaiting_rollover_for_ca(ca)
        return Response(CaSerializer(ca).data)

    @extend_schema(request=CaGenerateSerializer, responses={201: CaSerializer})
    @action(detail=False, methods=['post'])
    @transaction.atomic
    def generate(self, request: Request) -> Response:
        """Generate the local AutoGenPKI when enabled by the security policy."""
        serializer = CaGenerateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        form = validated_form(IssuingCaAddAutoGenForm(serializer.validated_data))
        config = SecurityConfig.objects.select_for_update().first()
        if config is None or not config.auto_gen_pki:
            msg = 'Auto-generated PKI creation is disabled in the Security Settings.'
            raise ValidationError(msg)
        if AutoGenPki.get_auto_gen_pki() is not None:
            msg = 'An auto-generated PKI is already active.'
            raise Conflict(msg)
        try:
            ca = AutoGenPki.enable_auto_gen_pki(form.cleaned_data['key_type'])
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        if ca is None:
            msg = 'An auto-generated PKI is already active.'
            raise Conflict(msg)
        return self._created(ca)

    def _created(self, ca: CaModel) -> Response:
        """Audit creation and return the complete public CA representation."""
        audit_security_change(target=ca, actor=self.request.user, before=None, action='created')
        return Response(CaSerializer(ca).data, status=status.HTTP_201_CREATED)

    @extend_schema(request=CaPkcs12Serializer, responses={201: CaSerializer})
    @action(detail=False, methods=['post'], url_path='import-pkcs12')
    @transaction.atomic
    def import_pkcs12(self, request: Request) -> Response:
        """Import a CA from a multipart PKCS#12 upload."""
        serializer = CaPkcs12Serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        values = dict(serializer.validated_data)
        file = values.pop('pkcs12_file')
        form = validated_form(ApiPkcs12Form(values, MultiValueDict({'pkcs12_file': [file]})))
        return self._created(form.created_ca)

    def _configure_remote(self, request: Request, protocol: str) -> Response:
        """Reuse UI validation and managed-key creation for upstream configurations."""
        serializer = CaRemoteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        values = dict(serializer.validated_data)
        is_ra_mode = values.pop('is_ra_mode')
        form_class = IssuingCaAddRequestEstForm if protocol == 'est' else IssuingCaAddRequestCmpForm
        values['ca_type'] = (
            CaModel.CaTypeChoice.REMOTE_ISSUING_EST if protocol == 'est' else CaModel.CaTypeChoice.REMOTE_ISSUING_CMP
        )
        form = validated_form(form_class(values))
        return self._created(form.save(is_ra_mode=is_ra_mode))

    @extend_schema(request=CaRemoteSerializer, responses={201: CaSerializer})
    @action(detail=False, methods=['post'], url_path='configure-est')
    @transaction.atomic
    def configure_est(self, request: Request) -> Response:
        """Configure a remote EST CA or RA; associate its truststore next."""
        return self._configure_remote(request, 'est')

    @extend_schema(request=CaRemoteSerializer, responses={201: CaSerializer})
    @action(detail=False, methods=['post'], url_path='configure-cmp')
    @transaction.atomic
    def configure_cmp(self, request: Request) -> Response:
        """Configure a remote CMP CA or RA; associate its truststore next."""
        return self._configure_remote(request, 'cmp')

    @extend_schema(request=CaExternalCsrSerializer, responses={201: CaSerializer})
    @action(detail=False, methods=['post'], url_path='configure-external-csr')
    @transaction.atomic
    def configure_external_csr(self, request: Request) -> Response:
        """Create a managed key for an externally signed issuing CA."""
        serializer = CaExternalCsrSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        values = {**serializer.validated_data, 'ca_type': CaModel.CaTypeChoice.REMOTE_ISSUING_CSR}
        form = validated_form(IssuingCaAddRequestExternalCsrForm(values))
        return self._created(form.save())

    @extend_schema(request=CaCrlSettingsSerializer, responses=CaSerializer)
    @action(detail=True, methods=['patch'], url_path='crl-settings')
    @transaction.atomic
    def crl_settings(self, request: Request, pk: str | None = None) -> Response:
        """Update CRL scheduling and validity using the UI's policy checks."""
        del pk
        ca = self.get_object()
        ca = CaModel.objects.select_for_update().get(pk=ca.pk)
        serializer = CaCrlSettingsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        values = {field: getattr(ca, field) for field in IssuingCaCrlCycleForm.Meta.fields}
        values.update(serializer.validated_data)
        form = validated_form(IssuingCaCrlCycleForm(values, instance=ca))
        with security_change(target=ca, actor=request.user):
            form.save()
        return Response(CaSerializer(ca).data)

    @extend_schema(request=CaTruststoreSerializer, responses=CaSerializer)
    @action(detail=True, methods=['post'], url_path='truststore')
    @transaction.atomic
    def truststore(self, request: Request, pk: str | None = None) -> Response:
        """Associate an upstream truststore, including RA certificate/chain extraction."""
        del pk
        ca = self.get_object()
        ca = CaModel.objects.select_for_update().get(pk=ca.pk)
        serializer = CaTruststoreSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        form = validated_form(IssuingCaTruststoreAssociationForm(serializer.validated_data, instance=ca))
        with security_change(target=ca, actor=request.user):
            form.save()
            if ca.ca_type in (CaModel.CaTypeChoice.REMOTE_EST_RA, CaModel.CaTypeChoice.REMOTE_CMP_RA):
                store = form.cleaned_data['trust_store']
                if store.intended_usage == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN:
                    orders = list(store.truststoreordermodel_set.order_by('order'))
                    if not orders:
                        msg = 'The CA chain truststore contains no certificates.'
                        raise ValidationError(msg)
                    ca.certificate = orders[0].certificate
                    if len(orders) > 1:
                        ca.parent_ca = CaModel.objects.filter(certificate=orders[1].certificate).first()
                    ca.chain_truststore = store
                    ca.save(update_fields=['certificate', 'parent_ca', 'chain_truststore'])
        return Response(CaSerializer(ca).data)

    @extend_schema(request=None, responses=OpenApiTypes.OBJECT)
    @action(detail=True, methods=['post'], url_path='generate-crl')
    @transaction.atomic
    def generate_crl(self, _request: Request, pk: int | None = None, **_kwargs: Any) -> Response:  # type: ignore[override]
        """Generate a CRL without truncating fractional validity hours."""
        del pk, _kwargs
        ca = self.get_object()
        ca = CaModel.objects.select_for_update().get(pk=ca.pk)
        if not ca.is_active:
            msg = 'Cannot generate a CRL for a deactivated CA.'
            raise Conflict(msg)
        if ca.issue_crl(crl_validity_hours=ca.crl_validity_hours):
            return Response(
                {
                    'message': f'CRL generated successfully for Issuing CA "{ca.unique_name}".',
                    'last_crl_issued_at': ca.last_crl_issued_at,
                }
            )
        msg = 'This CA cannot generate a CRL with the current configuration.'
        raise ValidationError(msg)


@extend_schema(tags=['CRL'])
class CrlViewSet(
    PkiApiErrorsMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet[CrlModel],
):
    """Inspect, import, download, and delete CRLs, including historical and unassociated CRLs."""

    queryset = CrlModel.objects.select_related('ca').order_by('-this_update', '-pk')
    serializer_class = CrlSerializer
    permission_classes = (CanManageIssuingCas,)
    filter_backends = (DjangoFilterBackend, filters.OrderingFilter)
    filterset_fields: ClassVar = ['ca', 'is_active', 'crl_number']
    ordering_fields: ClassVar = ['this_update', 'next_update', 'created_at', 'crl_number']

    @extend_schema(request=CrlImportSerializer, responses={201: CrlSerializer})
    @transaction.atomic
    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Import a PEM/DER CRL and check its issuer/signature when a CA is supplied."""
        del args, kwargs
        serializer = CrlImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        content = data['crl_file'].read()
        try:
            crl = x509.load_pem_x509_crl(content) if b'-----BEGIN' in content else x509.load_der_x509_crl(content)
        except ValueError as exc:
            raise ValidationError({'crl_file': 'Unable to parse CRL. Expected PEM or DER.'}) from exc
        ca = data.get('ca')
        if ca is not None:
            ca = CaModel.objects.select_for_update().get(pk=ca.pk)
        model = CrlModel.create_from_pem(
            ca=ca,
            crl_pem=crl.public_bytes(serialization.Encoding.PEM).decode(),
            set_active=data['set_active'] and ca is not None,
        )
        return Response(CrlSerializer(model).data, status=status.HTTP_201_CREATED)

    @transaction.atomic
    def perform_destroy(self, instance: CrlModel) -> None:
        """Delete the selected CRL through the model's dependency checks."""
        instance.delete()

    @extend_schema(parameters=[EncodingSerializer], responses={(200, 'application/octet-stream'): OpenApiTypes.BINARY})
    @action(detail=True, methods=['get'])
    def download(self, request: Request, pk: str | None = None) -> HttpResponse:
        """Download a CRL by its own identifier, without ambiguous CA-ID fallback."""
        del pk
        model = self.get_object()
        query = EncodingSerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        encoding = query.validated_data['encoding']
        return download_response(
            model.get_crl_as_crypto().public_bytes(
                serialization.Encoding.PEM if encoding == 'pem' else serialization.Encoding.DER
            ),
            f'crl-{model.pk}.{encoding}',
            'application/x-pem-file' if encoding == 'pem' else 'application/pkix-crl',
        )


@extend_schema(tags=['CA Rollover'])
class CaRolloverViewSet(
    PkiApiErrorsMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    viewsets.GenericViewSet[CaRolloverModel],
):
    """Plan CA rollovers and execute audited lifecycle transitions."""

    queryset = CaRolloverModel.objects.select_related('old_issuing_ca', 'new_issuing_ca').order_by('-planned_at')
    serializer_class = CaRolloverSerializer
    permission_classes = (CanManageIssuingCas,)
    filter_backends = (DjangoFilterBackend,)
    filterset_fields: ClassVar = ['old_issuing_ca', 'new_issuing_ca', 'state']

    @extend_schema(request=CaRolloverPlanSerializer, responses={201: CaRolloverSerializer})
    @transaction.atomic
    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Acquire replacement credentials and plan a rollover atomically."""
        del args, kwargs
        serializer = CaRolloverPlanSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = dict(serializer.validated_data)
        ca = data.pop('old_issuing_ca')
        ca = CaModel.objects.select_for_update().get(pk=ca.pk)
        if ca.ca_type not in (
            CaModel.CaTypeChoice.AUTOGEN,
            CaModel.CaTypeChoice.LOCAL_UNPROTECTED,
            CaModel.CaTypeChoice.LOCAL_PKCS11,
        ):
            msg = 'Only locally managed issuing CAs can be rolled over.'
            raise ValidationError(msg)
        # Check lifecycle constraints before form validation, since import forms persist credentials.
        if CaRolloverService.get_active_rollover(ca) or CaRolloverService.has_completed_rollover(ca):
            msg = 'This CA already has an active or completed rollover.'
            raise Conflict(msg)
        method = data.pop('method')
        form_class = {
            'pkcs12': ImportCaRolloverForm,
            'separate_files': SeparateFilesCaRolloverForm,
            'est': GenerateKeypairEstRolloverForm,
            'cmp': GenerateKeypairCmpRolloverForm,
        }[method]
        if method in ('est', 'cmp'):
            data['ca_type'] = (
                CaModel.CaTypeChoice.REMOTE_ISSUING_EST if method == 'est' else CaModel.CaTypeChoice.REMOTE_ISSUING_CMP
            )
        files = {
            key: data.pop(key)
            for key in list(data)
            if key.endswith('_file') or key in ('ca_certificate', 'ca_certificate_chain')
        }
        form = validated_form(form_class(data, MultiValueDict({key: [value] for key, value in files.items()})))
        strategy = (
            CaRolloverStrategyType.IMPORT_CA
            if method in ('pkcs12', 'separate_files')
            else CaRolloverStrategyType.GENERATE_KEYPAIR
        )
        rollover = CaRolloverService.plan_rollover(
            ca, strategy, form, initiated_by=request.user if request.user.is_authenticated else None
        )
        self._audit(rollover, AuditLog.OperationType.CA_ROLLOVER_PLANNED)
        return Response(CaRolloverSerializer(rollover).data, status=status.HTTP_201_CREATED)

    def _audit(self, rollover: CaRolloverModel, operation: str) -> None:
        """Record the same lifecycle audit events as the Web UI."""
        AuditLog.create_entry(
            operation_type=operation,
            target=rollover,
            target_display=f'CA Rollover: {rollover.old_issuing_ca} → {rollover.new_issuing_ca}',
            actor=self.request.user if self.request.user.is_authenticated else None,
        )

    @transaction.atomic
    def _transition(self, operation: str) -> Response:
        """Lock and validate a rollover before applying a state transition."""
        instance = self.get_object()
        rollover = CaRolloverModel.objects.select_for_update().get(pk=instance.pk)
        try:
            if operation == 'start':
                CaRolloverService.execute_rollover(rollover)
            elif operation == 'transition':
                rollover.transition_to_transition()
            elif operation == 'complete':
                CaRolloverService.finalize_rollover(rollover)
            else:
                CaRolloverService.cancel_rollover(rollover)
        except ValueError as exc:
            raise Conflict(str(exc)) from exc
        audit_operation = {
            'start': AuditLog.OperationType.CA_ROLLOVER_STARTED,
            'transition': AuditLog.OperationType.CA_ROLLOVER_TRANSITIONED,
            'complete': AuditLog.OperationType.CA_ROLLOVER_COMPLETED,
            'cancel': AuditLog.OperationType.CA_ROLLOVER_CANCELLED,
        }[operation]
        self._audit(rollover, audit_operation)
        return Response(CaRolloverSerializer(rollover).data)

    @extend_schema(request=None, responses=CaRolloverSerializer)
    @action(detail=True, methods=['post'])
    def start(self, request: Request, pk: str | None = None) -> Response:
        """Start a planned rollover."""
        del request, pk
        return self._transition('start')

    @extend_schema(request=None, responses=CaRolloverSerializer)
    @action(detail=True, methods=['post'])
    def transition(self, request: Request, pk: str | None = None) -> Response:
        """Move from preparation to transition."""
        del request, pk
        return self._transition('transition')

    @extend_schema(request=None, responses=CaRolloverSerializer)
    @action(detail=True, methods=['post'])
    def complete(self, request: Request, pk: str | None = None) -> Response:
        """Finalize the rollover and apply its domain/activation changes."""
        del request, pk
        return self._transition('complete')

    @extend_schema(request=None, responses=CaRolloverSerializer)
    @action(detail=True, methods=['post'])
    def cancel(self, request: Request, pk: str | None = None) -> Response:
        """Cancel an unfinished rollover."""
        del request, pk
        return self._transition('cancel')
