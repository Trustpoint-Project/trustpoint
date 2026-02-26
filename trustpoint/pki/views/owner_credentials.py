"""Views for Owner Credential (DevOwnerID) management."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView
from trustpoint_core.serializer import PrivateKeySerializer

from devices.models import IssuedCredentialModel
from pki.forms import (
    OwnerCredentialAddRequestEstNoOnboardingForm,
    OwnerCredentialAddRequestEstOnboardingForm,
    OwnerCredentialFileImportForm,
    OwnerCredentialTruststoreAssociationForm,
)
from pki.models import OwnerCredentialModel
from pki.models.certificate import CertificateModel
from pki.models.credential import CredentialModel
from trustpoint.logger import LoggerMixin
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    SortableTableMixin,
)

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.forms import Form


_OWNER_CREDENTIAL_ADD_METHODS = [
    'local_file_import',
]


class OwnerCredentialContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'owner_credentials'


class OwnerCredentialTableView(
    OwnerCredentialContextMixin, SortableTableMixin[OwnerCredentialModel], ListView[OwnerCredentialModel]):
    """Owner Credential Table View."""

    model = OwnerCredentialModel
    template_name = 'pki/owner_credentials/owner_credentials.html'  # Template file
    context_object_name = 'owner_credential'
    paginate_by = UIConfig.paginate_by  # Number of items per page
    default_sort_param = 'unique_name'


class OwnerCredentialDetailView(LoggerMixin, OwnerCredentialContextMixin, DetailView[OwnerCredentialModel]):
    """View to display the details of an Issuing CA."""

    http_method_names = ('get',)

    model = OwnerCredentialModel
    success_url = reverse_lazy('pki:owner_credentials')
    ignore_url = reverse_lazy('pki:owner_credentials')
    template_name = 'pki/owner_credentials/details.html'
    context_object_name = 'owner_credential'

    # add idevid refs to the context
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the issued certificates to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data()

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        owner_credential = self.get_object()
        idevid_refs: list[dict[str,str]] = []
        if owner_credential:
            idevid_refs.extend(
                {
                    'idevid_subj_sn': ref.idevid_subject_serial_number,
                    'idevid_x509_sn': ref.idevid_x509_serial_number,
                    'idevid_sha256_fingerprint': ref.idevid_sha256_fingerprint,
                } for ref in owner_credential.idevid_ref_set.all()
            )

        context['idevid_refs'] = idevid_refs
        return context


class OwnerCredentialAddMethodSelectView(OwnerCredentialContextMixin, FormView[OwnerCredentialFileImportForm]):
    """View to select the method for adding a new DevOwnerID."""

    template_name = 'pki/owner_credentials/add/method_select.html'
    # Use the file-import form as a lightweight stand-in so FormView machinery is satisfied.
    form_class = OwnerCredentialFileImportForm

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Render the method selection page (no form processing needed)."""
        return self.render_to_response(self.get_context_data())

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Redirect based on the chosen method."""
        method = request.POST.get('method_select')
        if method == 'local_file_import':
            return HttpResponseRedirect(reverse_lazy('pki:owner_credentials-add-file_import'))
        return HttpResponseRedirect(reverse_lazy('pki:owner_credentials-add'))


class OwnerCredentialFileImportView(OwnerCredentialContextMixin, FormView[OwnerCredentialFileImportForm]):
    """View to import a DevOwnerID from separate PEM files."""

    template_name = 'pki/owner_credentials/add/file_import.html'
    form_class = OwnerCredentialFileImportForm
    success_url = reverse_lazy('pki:owner_credentials')

    def form_valid(self, form: OwnerCredentialFileImportForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        messages.success(
            self.request,
            _('Successfully added DevOwnerID {name}.').format(name=form.cleaned_data['unique_name']),
        )
        action = self.request.POST.get('action', 'add_only')
        if action == 'add_with_truststore':
            return HttpResponseRedirect(reverse('pki:truststores-add'))
        return super().form_valid(form)


# Keep old name as alias so any external references continue to work
OwnerCredentialAddView = OwnerCredentialFileImportView


class OwnerCredentialAddRequestEstMethodSelectView(
    OwnerCredentialContextMixin, FormView[OwnerCredentialFileImportForm]
):
    """View to select between onboarding and no-onboarding for EST-based DevOwnerID enrollment."""

    template_name = 'pki/owner_credentials/add/est_method_select.html'
    form_class = OwnerCredentialFileImportForm

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Render the EST method selection page."""
        return self.render_to_response(self.get_context_data())

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Redirect based on whether onboarding or no-onboarding is chosen."""
        method = request.POST.get('method_select')
        if method == 'no_onboarding':
            return HttpResponseRedirect(reverse_lazy('pki:owner_credentials-add-est-no-onboarding'))
        if method == 'onboarding':
            return HttpResponseRedirect(reverse_lazy('pki:owner_credentials-add-est-onboarding'))
        return HttpResponseRedirect(reverse_lazy('pki:owner_credentials-add-est'))


class OwnerCredentialAddRequestEstNoOnboardingView(
    OwnerCredentialContextMixin, FormView[OwnerCredentialAddRequestEstNoOnboardingForm]
):
    """View to request a DevOwnerID via EST using username/password (no IDevID onboarding)."""

    template_name = 'pki/owner_credentials/add/est_request.html'
    form_class = OwnerCredentialAddRequestEstNoOnboardingForm
    success_url = reverse_lazy('pki:owner_credentials')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add heading context."""
        context = super().get_context_data(**kwargs)
        context['form_title'] = _('Request DevOwnerID via EST — No Onboarding (Username / Password)')
        context['back_url'] = reverse_lazy('pki:owner_credentials-add-est')
        return context

    def form_valid(self, form: OwnerCredentialAddRequestEstNoOnboardingForm) -> HttpResponse:
        """Save a CredentialModel (key only) + OwnerCredentialModel, then redirect to truststore association."""
        private_key_pem = PrivateKeySerializer(form.cleaned_data['_private_key']).as_pkcs8_pem().decode()

        credential_model = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
            private_key=private_key_pem,
            certificate=None,
        )

        owner_credential = OwnerCredentialModel.objects.create(
            unique_name=form.cleaned_data['unique_name'],
            credential=credential_model,
            no_onboarding_config=form.cleaned_data['_no_onboarding_config'],
            remote_host=form.cleaned_data['_remote_host'],
            remote_port=form.cleaned_data['_remote_port'],
            remote_path=form.cleaned_data['_remote_path'],
            est_username=form.cleaned_data['_est_username'],
        )
        messages.success(
            self.request,
            _(
                'DevOwnerID configuration "{name}" saved. '
                'Now associate the TLS server certificate trust store.'
            ).format(name=owner_credential.unique_name),
        )
        return HttpResponseRedirect(
            reverse('pki:owner_credentials-truststore-association', kwargs={'pk': owner_credential.pk})
        )

    def form_invalid(self, form: OwnerCredentialAddRequestEstNoOnboardingForm) -> HttpResponse:
        """Show form-level errors as Django messages."""
        for error in form.non_field_errors():
            messages.error(self.request, error)
        return super().form_invalid(form)


class OwnerCredentialAddRequestEstOnboardingView(
    OwnerCredentialContextMixin, FormView[OwnerCredentialAddRequestEstOnboardingForm]
):
    """View to request a DevOwnerID via EST using IDevID-based onboarding (mTLS client certificate)."""

    template_name = 'pki/owner_credentials/add/est_request.html'
    form_class = OwnerCredentialAddRequestEstOnboardingForm
    success_url = reverse_lazy('pki:owner_credentials')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add heading context."""
        context = super().get_context_data(**kwargs)
        context['form_title'] = _('Request DevOwnerID via EST — Onboarding (IDevID)')
        context['back_url'] = reverse_lazy('pki:owner_credentials-add-est')
        return context

    def form_valid(self, form: OwnerCredentialAddRequestEstOnboardingForm) -> HttpResponse:
        """Store the prepared config and show success."""
        messages.success(
            self.request,
            _(
                'EST onboarding configuration for DevOwnerID "{name}" saved. '
                'Step 1: the IDevID will be used to request a client certificate from the remote EST server. '
                'Step 2: that client certificate will then be used to request the DevOwnerID.'
            ).format(name=form.cleaned_data['unique_name']),
        )
        return super().form_valid(form)

    def form_invalid(self, form: OwnerCredentialAddRequestEstOnboardingForm) -> HttpResponse:
        """Show form-level errors as Django messages."""
        for error in form.non_field_errors():
            messages.error(self.request, error)
        return super().form_invalid(form)


class OwnerCredentialTruststoreAssociationView(
    OwnerCredentialContextMixin, FormView[OwnerCredentialTruststoreAssociationForm]
):
    """View for associating a TLS truststore with a DevOwnerID EST no-onboarding configuration."""

    form_class = OwnerCredentialTruststoreAssociationForm
    template_name = 'pki/owner_credentials/truststore_association.html'

    def get_owner_credential(self) -> OwnerCredentialModel:
        """Get the OwnerCredentialModel from the URL pk."""
        return get_object_or_404(OwnerCredentialModel, pk=self.kwargs['pk'])

    def get_form_kwargs(self) -> dict[str, Any]:
        """Pass the OwnerCredentialModel instance to the form."""
        kwargs = super().get_form_kwargs()
        kwargs['instance'] = self.get_owner_credential()
        truststore_id = self.request.GET.get('truststore_id')
        if truststore_id:
            from pki.models.truststore import TruststoreModel  # noqa: PLC0415
            try:
                truststore = TruststoreModel.objects.get(pk=truststore_id)
                kwargs.setdefault('initial', {})['trust_store'] = truststore
            except TruststoreModel.DoesNotExist:
                pass
        return kwargs

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle both association and truststore-import form submissions."""
        if 'trust_store_file' in request.FILES:
            return self._handle_import(request)
        return super().post(request, *args, **kwargs)

    def _handle_import(self, request: HttpRequest) -> HttpResponse:
        """Import a truststore from the modal form and redirect back with its id pre-selected."""
        from pki.forms import TruststoreAddForm  # noqa: PLC0415
        from pki.models.truststore import TruststoreModel  # noqa: PLC0415

        import_form = TruststoreAddForm(request.POST, request.FILES)
        owner_credential = self.get_owner_credential()

        if import_form.is_valid():
            truststore = import_form.cleaned_data['truststore']
            if truststore.intended_usage != TruststoreModel.IntendedUsage.TLS:
                usage_name = TruststoreModel.IntendedUsage(TruststoreModel.IntendedUsage.TLS).label
                import_form.add_error(
                    'intended_usage',
                    _('Only "{usage}" truststores can be associated here.').format(usage=usage_name),
                )
                context = self.get_context_data()
                context['import_form'] = import_form
                return self.render_to_response(context)

            messages.success(
                request,
                _('Successfully imported truststore {name}.').format(name=truststore.unique_name),
            )
            return HttpResponseRedirect(
                reverse(
                    'pki:owner_credentials-truststore-association',
                    kwargs={'pk': owner_credential.pk},
                ) + f'?truststore_id={truststore.pk}'
            )

        context = self.get_context_data()
        context['import_form'] = import_form
        return self.render_to_response(context)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the owner credential and import form to the context."""
        from pki.forms import TruststoreAddForm  # noqa: PLC0415
        from pki.models.truststore import TruststoreModel  # noqa: PLC0415

        context = super().get_context_data(**kwargs)
        owner_credential = self.get_owner_credential()
        context['owner_credential'] = owner_credential

        import_form = TruststoreAddForm()
        intended_usage_field = import_form.fields['intended_usage']
        intended_usage_field.choices = [  # type: ignore[union-attr]
            choice for choice in intended_usage_field.choices  # type: ignore[union-attr]
            if isinstance(choice, tuple) and choice[0] == TruststoreModel.IntendedUsage.TLS
        ]
        context['import_form'] = import_form
        return context

    def form_valid(self, form: OwnerCredentialTruststoreAssociationForm) -> HttpResponse:
        """Associate the selected truststore and redirect to the credential list."""
        form.save()
        owner_credential = self.get_owner_credential()
        messages.success(
            self.request,
            _('Successfully associated TLS truststore with DevOwnerID "{name}".').format(
                name=owner_credential.unique_name
            ),
        )
        return HttpResponseRedirect(reverse_lazy('pki:owner_credentials'))


class OwnerCredentialCLMView(OwnerCredentialContextMixin, DetailView[OwnerCredentialModel]):
    """Certificate Lifecycle Management view for a DevOwnerID credential."""

    http_method_names = ('get',)
    model = OwnerCredentialModel
    template_name = 'pki/owner_credentials/clm.html'
    context_object_name = 'owner_credential'

    @staticmethod
    def _get_expires_in(record: IssuedCredentialModel) -> str:
        """Returns a human-readable string of the time remaining until the credential expires."""
        cert = record.credential.certificate_or_error
        if cert.certificate_status != CertificateModel.CertificateStatus.OK:
            return str(cert.certificate_status.label)
        now = datetime.datetime.now(datetime.UTC)
        expire_timedelta = cert.not_valid_after - now
        days = expire_timedelta.days
        hours, remainder = divmod(expire_timedelta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f'{days} days, {hours}:{minutes:02d}:{seconds:02d}'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds issued credentials with computed display fields to the context."""
        context = super().get_context_data(**kwargs)
        issued_creds: QuerySet[IssuedCredentialModel] = IssuedCredentialModel.objects.filter(
            owner_credential=self.object
        ).select_related('credential__certificate')

        for cred in issued_creds:
            cred.expires_in = self._get_expires_in(cred)  # type: ignore[attr-defined]
            cred.expiration_date = cred.credential.certificate_or_error.not_valid_after  # type: ignore[attr-defined]

        context['issued_credentials'] = issued_creds
        context['back_url'] = reverse_lazy('pki:owner_credentials')
        return context


class OwnerCredentialBulkDeleteConfirmView(OwnerCredentialContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple owner credentials."""

    model = OwnerCredentialModel
    success_url = reverse_lazy('pki:owner_credentials')
    ignore_url = reverse_lazy('pki:owner_credentials')
    template_name = 'pki/owner_credentials/confirm_delete.html'
    context_object_name = 'owner_credentials'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, _('No owner credentials selected for deletion.'))
            return HttpResponseRedirect(self.success_url)
        return super().get(request, *args, **kwargs)

    def form_valid(self, form: Form) -> HttpResponse:
        """Delete the selected credentials on valid form."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0

        try:
            response = super().form_valid(form)
        except ProtectedError:
            messages.error(
                self.request,
                _('Cannot delete the selected DevOwnerID(s) because they are referenced by other objects.'),
            )
            return HttpResponseRedirect(self.success_url)
        except ValidationError as exc:
            messages.error(self.request, exc.message)
            return HttpResponseRedirect(self.success_url)

        messages.success(self.request, _('Successfully deleted {count} DevOwnerID(s).').format(count=deleted_count))

        return response
