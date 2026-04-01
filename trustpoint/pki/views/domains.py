"""Views for managing Domains."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.forms import BaseModelForm
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic import DeleteView
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, FormView
from django.views.generic.list import ListView
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import filters, status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from management.models.audit_log import AuditLog
from pki.forms import DevIdAddMethodSelectForm, DevIdRegistrationForm
from pki.models import (
    CaModel,
    CertificateModel,
    CertificateProfileModel,
    DevIdRegistration,
    DomainModel,
)
from pki.models.truststore import TruststoreModel
from pki.serializer.devid_registration import DevIdRegistrationDetailSerializer, DevIdRegistrationSerializer
from pki.serializer.domain import DomainDetailSerializer, DomainSerializer
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    ListInDetailView,
    SortableTableMixin,
)

if TYPE_CHECKING:
    from typing import ClassVar

    from django.db.models import QuerySet
    from django.forms import Form
    from django.http import HttpRequest
    from rest_framework.request import Request


class DomainContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'domains'


class DomainTableView(DomainContextMixin, SortableTableMixin[DomainModel], ListView[DomainModel]):
    """Domain Table View."""

    model = DomainModel
    template_name = 'pki/domains/domain.html'  # Template file
    context_object_name = 'domain-new'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'unique_name'


class DomainCreateView(DomainContextMixin, CreateView[DomainModel, BaseModelForm[DomainModel]]):
    """View to create a new domain."""

    model = DomainModel
    fields = '__all__'
    template_name = 'pki/domains/add.html'
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')

    def get_form(self, _form_class: Any = None) -> Any:
        """Override get_form to filter out keyless CAs and autogen root CAs.

        Only issuing CAs (those with credentials that can sign certificates) should be assignable to domains.
        """
        form = super().get_form()
        form.fields['issuing_ca'].queryset = CaModel.objects.filter(  # type: ignore[attr-defined]
            is_active=True
        ).exclude(
            ca_type__in=[
                CaModel.CaTypeChoice.AUTOGEN_ROOT,
                CaModel.CaTypeChoice.KEYLESS,
            ]
        )
        form.fields['issuing_ca'].empty_label = None  # type: ignore[attr-defined]
        del form.fields['is_active']
        if 'domain_credential_profile' in form.fields:
            del form.fields['domain_credential_profile']
        return form

    def form_valid(self, form: BaseModelForm[DomainModel]) -> HttpResponse:
        """Handle the case where the form is valid."""
        domain = form.save()
        messages.success(
            self.request,
            _('Successfully created domain {name}.').format(name=domain.unique_name),
        )
        actor = self.request.user if self.request.user.is_authenticated else None
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.DOMAIN_CREATED,
            target=domain,
            target_display=f'Domain: {domain.unique_name}',
            actor=actor,
        )
        return super().form_valid(form)


class DomainDevIdRegistrationTableMixin(SortableTableMixin[DevIdRegistration], ListInDetailView):
    """Mixin to add a table of DevID Registrations to the domain config view."""

    model = DevIdRegistration
    paginate_by = UIConfig.paginate_by
    context_object_name = 'devid_registrations'
    default_sort_param = 'unique_name'

    def get_queryset(self) -> QuerySet[DevIdRegistration]:
        """Gets the queryset for the DevID Registration table."""
        domain: DomainModel = cast('DomainModel', self.get_object())
        self.queryset = DevIdRegistration.objects.filter(domain=domain)
        return super().get_queryset()


class DomainConfigView(DomainContextMixin, DomainDevIdRegistrationTableMixin, ListInDetailView):
    """View to configure a domain, allows adding DevID registration patterns."""

    detail_model = DomainModel
    template_name = 'pki/domains/config.html'
    detail_context_object_name = 'domain'
    success_url = reverse_lazy('pki:domains')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds additional context data."""
        context = super().get_context_data(**kwargs)
        domain: DomainModel = cast('DomainModel', self.get_object())

        issued_credentials = domain.issued_credentials.all()

        certificates = CertificateModel.objects.filter(
            credential__in=[issued_credential.credential for issued_credential in issued_credentials]
        )

        context['profile_data'] = {
            profile.id: {
                'unique_name': profile.unique_name,
                'alias': '',
                'is_allowed': False
            }
            for profile in CertificateProfileModel.objects.all()
        }

        for allowed_profile in domain.certificate_profiles.all():
            profile_id = allowed_profile.certificate_profile.id
            context['profile_data'][profile_id]['alias'] = allowed_profile.alias
            context['profile_data'][profile_id]['is_allowed'] = True

        all_profiles = list(CertificateProfileModel.objects.all())
        context['domain_credential_profiles'] = all_profiles
        context['current_domain_credential_profile_id'] = (
            domain.domain_credential_profile.id if domain.domain_credential_profile else None
        )

        context['certificates'] = certificates
        context['domain_options'] = {}
        context['domain_help_texts'] = {}
        context['domain_verbose_name'] = {}

        return context

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle config form submission."""
        del args
        del kwargs

        domain: DomainModel = cast('DomainModel', self.get_object())

        domain_cred_profile_id = request.POST.get('domain_credential_profile', '')
        if domain_cred_profile_id:
            try:
                profile = CertificateProfileModel.objects.get(pk=int(domain_cred_profile_id))
                domain.domain_credential_profile = profile
            except (CertificateProfileModel.DoesNotExist, ValueError):
                messages.error(request, _('Invalid domain credential profile selected.'))
                return HttpResponseRedirect(reverse('pki:domains-config', kwargs={'pk': domain.pk}))
        else:
            domain.domain_credential_profile = None

        # Handle assignments of  allowed certificate profiles in domain
        # get fields from request POST
        allowed_profile_data = {}
        for key in request.POST:
            if key.startswith('cert_p_allowed_'):
                profile_id = key.removeprefix('cert_p_allowed_')
                alias = request.POST.get(f'cert_p_alias_{profile_id}', '').strip()
                allowed_profile_data[profile_id] = alias

        rejected_aliases = domain.set_allowed_cert_profiles(allowed_profile_data)
        for alias_value, profile_name in rejected_aliases:
            messages.warning(
                request,
                _('Alias "{alias}" not applied for profile {profile} as it is already in use. '
                'Please use an unique domain alias for each Certificate Profile.').format(
                    alias=alias_value,
                    profile=profile_name
                )
            )

        domain.save()

        messages.success(request, _('Settings updated successfully.'))
        return HttpResponseRedirect(self.success_url)


class DomainDetailView(DomainContextMixin, DomainDevIdRegistrationTableMixin, ListInDetailView):
    """View to display domain details."""

    detail_model = DomainModel
    template_name = 'pki/domains/details.html'
    detail_context_object_name = 'domain'


class DomainCaBulkDeleteConfirmView(DomainContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple Domains."""

    model = DomainModel
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')
    template_name = 'pki/domains/confirm_delete.html'
    context_object_name = 'domains'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, _('No domains selected for deletion.'))
            return HttpResponseRedirect(self.success_url)
        return super().get(request, *args, **kwargs)

    def form_valid(self, form: Form) -> HttpResponse:
        """Attempt to delete domains if the form is valid."""
        queryset = self.get_queryset()
        deleted_count = queryset.count()
        domains_to_delete = list(queryset)

        try:
            response = super().form_valid(form)
        except ProtectedError:
            messages.error(
                self.request, _('Cannot delete the selected Domain(s) because they are referenced by other objects.')
            )
            return HttpResponseRedirect(self.success_url)
        except ValidationError as exc:
            messages.error(self.request, exc.message)
            return HttpResponseRedirect(self.success_url)

        actor = self.request.user if self.request.user.is_authenticated else None
        for domain in domains_to_delete:
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.DOMAIN_DELETED,
                target=domain,
                target_display=f'Domain: {domain.unique_name}',
                actor=actor,
            )

        messages.success(self.request, _('Successfully deleted {count} Domains.').format(count=deleted_count))

        return response


class DevIdRegistrationCreateView(DomainContextMixin, FormView[DevIdRegistrationForm]):
    """View to create a new DevID Registration."""

    http_method_names = ('get', 'post')

    template_name = 'pki/devid_registration/add.html'
    form_class = DevIdRegistrationForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        domain = self.get_domain()
        context['domain'] =domain
        truststore_id = self.kwargs.get('truststore_id')
        if not truststore_id:
            truststore_id = self.request.GET.get('truststore_id')
        if truststore_id:
            context['truststore'] = self.get_truststore(truststore_id)
        else:
            context['truststore'] = None

        return context

    def get_initial(self) -> dict[str, Any]:
        """Initialize the form with default values."""
        initial = super().get_initial()
        domain = self.get_domain()
        if domain:
            initial['domain'] = domain
        truststore_id = self.kwargs.get('truststore_id')
        if not truststore_id:
            truststore_id = self.request.GET.get('truststore_id')
        if truststore_id:
            initial['truststore'] = self.get_truststore(truststore_id)
        else:
            initial['truststore'] = None
        return initial

    def get_form_kwargs(self) -> dict[str, Any]:
        """Provide additional arguments to the form."""
        form_kwargs = super().get_form_kwargs()
        form_kwargs['initial'] = self.get_initial()
        return form_kwargs

    def get_domain(self) -> DomainModel | None:
        """Get domain from URL pk (GET) or form data (POST)."""
        pk = self.kwargs.get('pk')
        if pk:
            try:
                return DomainModel.objects.get(pk=pk)
            except DomainModel.DoesNotExist as err:
                msg = 'Domain does not exist.'
                raise Http404(msg) from err
        if self.request.method == 'POST':
            domain_id = self.request.POST.get('domain')
            if domain_id:
                try:
                    return DomainModel.objects.get(pk=domain_id)
                except (DomainModel.DoesNotExist, ValueError) as err:
                    msg = 'Domain does not exist.'
                    raise Http404(msg) from err

        return None



    def get_truststore(self, truststore_id: int) -> TruststoreModel:
        """Fetch the truststore based on the primary key passed in the URL."""
        try:
            return TruststoreModel.objects.get(pk=truststore_id)
        except TruststoreModel.DoesNotExist as e:
            exc_msg = 'This Truststore does not exist.'
            raise Http404(exc_msg) from e

    def form_valid(self, form: DevIdRegistrationForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        dev_id_registration = form.save()
        self.object = dev_id_registration
        messages.success(
            self.request,
            _('Successfully created DevID registration pattern {name}.').format(name=dev_id_registration.unique_name),
        )
        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Return the URL to redirect to upon successful form submission."""
        if self.kwargs.get('pk'):
            domain = get_object_or_404(DomainModel, pk=self.kwargs['pk'])
            return cast('str', reverse_lazy('pki:domains-config', kwargs={'pk': domain.id}))
        return cast('str', reverse_lazy('devices:devices'))


class DevIdRegistrationDeleteView(DomainContextMixin, DeleteView[DevIdRegistration, Any]):
    """View to delete a DevID Registration."""

    model = DevIdRegistration
    template_name = 'pki/devid_registration/confirm_delete.html'
    success_url = reverse_lazy('pki:domains')

    def delete(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Override delete method to add a success message."""
        response = super().delete(request, *args, **kwargs)
        messages.success(request, _('DevID Registration Pattern deleted successfully.'))
        return response


class DevIdMethodSelectView(DomainContextMixin, FormView[DevIdAddMethodSelectForm]):
    """View to select the method to add a DevID Registration pattern."""

    template_name = 'pki/devid_registration/method_select.html'
    form_class = DevIdAddMethodSelectForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        pk = self.kwargs.get('pk')

        if pk:
            context['domain'] = DomainModel.objects.get(pk=pk)
        else:
            context['domain'] = None
        return context

    def form_valid(self, form: DevIdAddMethodSelectForm) -> HttpResponseRedirect:
        """Redirect to the view for the selected method."""
        method_select = form.cleaned_data.get('method_select')
        domain_pk = self.kwargs.get('pk')  # Get domain ID

        if method_select == 'import_truststore':
            if domain_pk:
                return HttpResponseRedirect(reverse('pki:truststores-add-with-pk', kwargs={'pk': domain_pk}))
            return HttpResponseRedirect(reverse('pki:truststores-add'))

        if method_select == 'configure_pattern':
            return HttpResponseRedirect(reverse('pki:devid_registration_create', kwargs={'pk': domain_pk}))

        # Try again if none or invalid method was selected
        return HttpResponseRedirect(reverse('pki:devid_registration-method_select', kwargs={'pk': domain_pk}))


class IssuedCertificatesView(ContextDataMixin, ListView[CertificateModel]):
    """View to list certificates issued by a specific Issuing CA for a Domain."""

    model = CertificateModel
    template_name = 'pki/domains/issued_certificates.html'
    context_object_name = 'issued_certificates'

    def get_queryset(self) -> QuerySet[CertificateModel]:
        """Return only certificates associated with the domain's issued credentials."""
        domain: DomainModel = self.get_domain()
        if domain.issuing_ca is None:
            msg = 'Domain has no issuing CA configured.'
            raise Http404(msg)
        if domain.issuing_ca.credential is None:
            msg = 'Issuing CA has no credential configured.'
            raise Http404(msg)
        # TODO(AlexHx8472): This must be limited to the actual domain.  # noqa: FIX002
        return CertificateModel.objects.filter(
            issuer_public_bytes=domain.issuing_ca.credential.certificate_or_error.subject_public_bytes
        )

    def get_domain(self) -> DomainModel:
        """Get the domain object based on the URL parameter."""
        domain_id = self.kwargs.get('pk')
        return DomainModel.objects.get(pk=domain_id)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Pass additional context data to the template."""
        context = super().get_context_data(**kwargs)
        domain = self.get_domain()
        context['domain'] = domain
        return context

class OnboardingMethodSelectIdevidHelpView(DomainContextMixin, DetailView[DevIdRegistration]):
    """View to select the protocol for IDevID enrollment."""

    template_name = 'pki/domains/idevid_method_select.html'
    context_object_name = 'devid_registration'
    model = DevIdRegistration

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the required context for the template."""
        context = super().get_context_data(**kwargs)
        context['pk'] = self.object.pk

        return context

@extend_schema(tags=['Domain'])
@extend_schema_view(
    list=extend_schema(description='Retrieve a list of all domains.'),
    retrieve=extend_schema(description='Retrieve a single domain by id.'),
    create=extend_schema(description='Create a domain.'),
    update=extend_schema(description='Update an existing domain.'),
    partial_update=extend_schema(description='Partially update an existing domain.'),
    destroy=extend_schema(description='Delete a domain.')
)
class DomainViewSet(viewsets.ModelViewSet[DomainModel]):
    """ViewSet for managing Domain instances.

    Supports standard CRUD operations such as list, retrieve,
    create, update, and delete.
    """

    queryset = DomainModel.objects.all()
    serializer_class = DomainSerializer

    def get_serializer_class(self) -> type[DomainDetailSerializer | DomainSerializer]:
        """Return the detail serializer for retrieve, and the list serializer for all other actions."""
        if self.action == 'retrieve':
            return DomainDetailSerializer
        return DomainSerializer


@extend_schema(tags=['DevID Registration'])
@extend_schema_view(
    list=extend_schema(description='Retrieve a list of all DevID registrations.'),
    retrieve=extend_schema(description='Retrieve a single DevID registration by id.'),
    create=extend_schema(description='Create a new DevID registration.'),
    update=extend_schema(description='Update an existing DevID registration.'),
    partial_update=extend_schema(description='Partially update an existing DevID registration.'),
    destroy=extend_schema(description='Delete a DevID registration.'),
)
class DevIdRegistrationViewSet(viewsets.ModelViewSet[DevIdRegistration]):
    """ViewSet for managing DevIdRegistration instances via REST API.

    Supports standard CRUD operations such as list, retrieve,
    create, update, and delete.
    """

    queryset = DevIdRegistration.objects.all()
    serializer_class = DevIdRegistrationSerializer
    permission_classes = (IsAuthenticated,)
    filter_backends = (DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter)
    filterset_fields: ClassVar = ['domain', 'truststore']
    search_fields: ClassVar = ['unique_name', 'serial_number_pattern']
    ordering_fields: ClassVar = ['unique_name']

    def get_serializer_class(
        self,
    ) -> type[DevIdRegistrationDetailSerializer | DevIdRegistrationSerializer]:
        """Return the detail serializer for retrieve, and the list serializer for all other actions."""
        if self.action == 'retrieve':
            return DevIdRegistrationDetailSerializer
        return DevIdRegistrationSerializer

    def create(self, request: Request, *_args: Any, **_kwargs: Any) -> Response:
        """Create a new DevID registration.

        If ``unique_name`` is blank the truststore's name is used as default.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        unique_name: str = serializer.validated_data.get('unique_name', '')
        if not unique_name:
            truststore = serializer.validated_data.get('truststore')
            if truststore is not None:
                serializer.validated_data['unique_name'] = truststore.unique_name

        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def destroy(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Delete a DevID registration."""
        del request, args, kwargs
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


