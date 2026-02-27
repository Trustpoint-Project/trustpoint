"""Views for Owner Credential (DevOwnerID) management."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Any

from cryptography import x509
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView
from trustpoint_core.oid import KeyPairGenerator, NamedCurve, PublicKeyAlgorithmOid, PublicKeyInfo
from trustpoint_core.serializer import PrivateKeySerializer

from devices.models import IssuedCredentialModel
from pki.forms import (
    CertificateIssuanceForm,
    OwnerCredentialAddRequestEstNoOnboardingForm,
    OwnerCredentialAddRequestEstOnboardingForm,
    OwnerCredentialFileImportForm,
    OwnerCredentialTruststoreAssociationForm,
)
from pki.models import OwnerCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.certificate import CertificateModel
from pki.models.credential import CredentialModel, IDevIDReferenceModel, PrimaryCredentialCertificate
from pki.util.cert_profile import ProfileValidationError
from request.clients import EstClient, EstClientError
from request.operation_processor.csr_build import ProfileAwareCsrBuilder
from request.operation_processor.csr_sign import EstDeviceCsrSignProcessor
from request.request_context import EstCertificateRequestContext
from trustpoint.logger import LoggerMixin
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    SortableTableMixin,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from django.db.models import QuerySet
    from django.forms import Form

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
        """Adds the IDevID reference list to the context.

        Each entry in ``idevid_refs`` is an :class:`~pki.models.credential.IDevIDReferenceModel`
        instance.  The ``dev_owner_id_certificate`` FK on each ref points directly to the
        :class:`~pki.models.certificate.CertificateModel` of the DevOwnerID certificate whose
        SAN contained this reference (or ``None`` for locally uploaded credentials where the
        certificate was not stored separately), so no extra DB lookup is needed here.
        """
        context = super().get_context_data(**kwargs)
        owner_credential = self.get_object()
        context['idevid_refs'] = list(
            owner_credential.idevid_ref_set.select_related('dev_owner_id_certificate').all()
        )
        return context


class OwnerCredentialAddMethodSelectView(OwnerCredentialContextMixin, FormView[OwnerCredentialFileImportForm]):
    """View to select the method for adding a new DevOwnerID."""

    template_name = 'pki/owner_credentials/add/method_select.html'
    # Use the file-import form as a lightweight stand-in so FormView machinery is satisfied.
    form_class = OwnerCredentialFileImportForm

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Render the method selection page (no form processing needed)."""
        del request, args, kwargs
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

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Render the EST method selection page."""
        del request, args, kwargs
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
        """Save the OwnerCredentialModel with its EST configuration.

        The key pair and IssuedCredentialModel are created later when the user
        triggers an actual DevOwnerID issuance via the CLM page.
        """
        owner_credential = OwnerCredentialModel.objects.create(
            unique_name=form.cleaned_data['unique_name'],
            no_onboarding_config=form.cleaned_data['_no_onboarding_config'],
            remote_host=form.cleaned_data['_remote_host'],
            remote_port=form.cleaned_data['_remote_port'],
            remote_path=form.cleaned_data['_remote_path'],
            est_username=form.cleaned_data['_est_username'],
            key_type=form.cleaned_data.get('key_type', 'ECC-SECP256R1'),
            owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST,
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
            messages.error(self.request, str(error))
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
        """Save the OwnerCredentialModel with its EST onboarding configuration.

        Creates the ``OwnerCredentialModel`` with all remote-endpoint fields and redirects
        to the truststore-association step, mirroring the no-onboarding workflow.
        """
        owner_credential = OwnerCredentialModel.objects.create(
            unique_name=form.cleaned_data['unique_name'],
            onboarding_config=form.cleaned_data['_onboarding_config'],
            remote_host=form.cleaned_data['_remote_host'],
            remote_port=form.cleaned_data['_remote_port'],
            remote_path=form.cleaned_data['_remote_path'],
            remote_path_domain_credential=form.cleaned_data['_remote_path_domain_credential'],
            est_username=form.cleaned_data['_est_username'],
            key_type=form.cleaned_data.get('key_type', 'ECC-SECP256R1'),
            owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST_ONBOARDING,
        )

        messages.success(
            self.request,
            _(
                'DevOwnerID onboarding configuration "{name}" saved. '
                'Now associate the TLS server certificate trust store.'
            ).format(name=owner_credential.unique_name),
        )
        return HttpResponseRedirect(
            reverse('pki:owner_credentials-truststore-association', kwargs={'pk': owner_credential.pk})
        )

    def form_invalid(self, form: OwnerCredentialAddRequestEstOnboardingForm) -> HttpResponse:
        """Show form-level errors as Django messages."""
        for error in form.non_field_errors():
            messages.error(self.request, str(error))
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
                pass  # Invalid truststore_id in query param — skip pre-selection silently.
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
        raw_choices: Iterable[Any] = import_form.fields['intended_usage'].choices  # type: ignore[assignment]
        import_form.fields['intended_usage'].choices = [
            choice for choice in raw_choices
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
            owner_credential=self.object,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DEV_OWNER_ID,
        ).select_related('credential__certificate').order_by('-created_at')

        for cred in issued_creds:
            if cred.credential.certificate is not None:
                cred.expires_in = self._get_expires_in(cred)  # type: ignore[attr-defined]
                cred.expiration_date = cred.credential.certificate.not_valid_after  # type: ignore[attr-defined]
            else:
                cred.expires_in = _('Pending enrollment')  # type: ignore[attr-defined]
                cred.expiration_date = '—'  # type: ignore[attr-defined]

        context['issued_credentials'] = issued_creds
        context['back_url'] = reverse_lazy('pki:owner_credentials')

        owner_credential: OwnerCredentialModel = self.object
        tls_trust_store = None
        if owner_credential.no_onboarding_config is not None:
            tls_trust_store = owner_credential.no_onboarding_config.trust_store
        elif owner_credential.onboarding_config is not None:
            tls_trust_store = owner_credential.onboarding_config.trust_store
        context['tls_trust_store'] = tls_trust_store

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


class IssuedCredentialDeleteView(LoggerMixin, OwnerCredentialContextMixin, DetailView[IssuedCredentialModel]):
    """Confirm and delete a single :class:`~devices.models.IssuedCredentialModel` (DEV_OWNER_ID).

    Only credentials owned by an ``OwnerCredentialModel`` are accessible via this view.
    The parent ``OwnerCredentialModel`` is resolved from the URL ``owner_pk`` parameter
    so the back-link can always return to the correct CLM page.
    """

    http_method_names = ('get', 'post')
    model = IssuedCredentialModel
    template_name = 'pki/owner_credentials/confirm_delete_issued_credential.html'
    context_object_name = 'issued_credential'

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Verify the IssuedCredential belongs to the given OwnerCredential."""
        self.owner_credential = get_object_or_404(OwnerCredentialModel, pk=kwargs['owner_pk'])
        issued: IssuedCredentialModel = get_object_or_404(
            IssuedCredentialModel,
            pk=kwargs['pk'],
            owner_credential=self.owner_credential,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DEV_OWNER_ID,
        )
        self.issued_credential = issued
        return super().dispatch(request, *args, **kwargs)  # type: ignore[return-value]

    def get_object(self, queryset: Any = None) -> IssuedCredentialModel:  # noqa: ARG002
        """Return the pre-fetched issued credential."""
        return self.issued_credential

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the parent OwnerCredential to the template context."""
        context = super().get_context_data(**kwargs)
        context['owner_credential'] = self.owner_credential
        return context

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Delete the issued credential and redirect back to the CLM page."""
        issued = self.issued_credential
        cn = issued.common_name
        try:
            issued.pre_delete()
        except Exception as exc:  # broad catch to surface any deletion error to the user
            self.logger.exception('Failed to delete IssuedCredentialModel pk=%s', issued.pk)
            messages.error(
                request,
                _('Failed to delete credential "{cn}": {error}').format(cn=cn, error=str(exc)),
            )
        else:
            messages.success(
                request,
                _('DevOwnerID credential "{cn}" has been deleted.').format(cn=cn),
            )
        return redirect('pki:owner_credentials-clm', pk=self.owner_credential.pk)


# ---------------------------------------------------------------------------
# DevOwnerID EST certificate issuance (define content → request)
# ---------------------------------------------------------------------------

class OwnerCredentialDefineCertContentEstView(
    LoggerMixin, OwnerCredentialContextMixin, FormView[CertificateIssuanceForm]
):
    """Step 1 - Define the certificate content for a new DevOwnerID EST enrollment.

    On every GET/POST a fresh EC P-256 key pair is generated and a key-only
    :class:`~devices.models.IssuedCredentialModel` (type ``DEV_OWNER_ID``) is
    created.  Its primary key is stored in the session together with the
    certificate content so that Step 2 can fetch exactly this credential.

    Loads the ``dev_owner_id`` certificate profile, renders the
    :class:`~pki.forms.CertificateIssuanceForm`, and stores the validated
    field values in the session under ``dev_owner_id_cert_content_<pk>``.
    """

    form_class = CertificateIssuanceForm
    template_name = 'pki/owner_credentials/define_cert_content_est.html'

    def _pending_session_key(self, owner_credential: OwnerCredentialModel) -> str:
        return f'dev_owner_id_cert_content_{owner_credential.pk}'

    def _public_key_info_from_key_type(self, key_type: str) -> PublicKeyInfo:
        """Convert a key_type string (e.g. 'RSA-2048', 'ECC-SECP256R1') to a PublicKeyInfo."""
        if key_type.startswith('RSA-'):
            key_size = int(key_type.split('-')[1])
            return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA, key_size=key_size)
        curve_name = key_type.split('-', 1)[1]
        named_curve = NamedCurve[curve_name.upper()]
        return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.ECC, named_curve=named_curve)

    def _delete_orphan_pending_credentials(self, exclude_pk: int | None) -> None:
        """Delete all key-only (certificate-less) DEV_OWNER_ID credentials for this owner.

        These are credentials created during a previous "define cert content" visit that
        were never enrolled (the user navigated away or the session expired).  Keeping
        them creates confusing "Pending enrollment" rows in the CLM.

        Args:
            exclude_pk: If given, the credential with this pk is kept (it is the one
                currently in use by the active session).
        """
        qs = IssuedCredentialModel.objects.filter(
            owner_credential=self.owner_credential,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DEV_OWNER_ID,
            credential__certificate__isnull=True,
        )
        if exclude_pk is not None:
            qs = qs.exclude(pk=exclude_pk)
        for orphan in qs.select_related('credential'):
            try:
                credential = orphan.credential
                orphan.delete()
                if credential is not None:
                    credential.delete()
            except Exception:  # noqa: BLE001
                self.logger.warning('Could not delete orphan pending credential pk=%s', orphan.pk)

    def _create_pending_issued_credential(self) -> IssuedCredentialModel:
        """Generate a fresh key pair and create a key-only IssuedCredentialModel.

        The key algorithm is taken from ``owner_credential.key_type`` so that every
        IssuedCredential for a given DevOwnerID always uses the same algorithm.
        """
        key_type = self.owner_credential.key_type or 'ECC-SECP256R1'
        private_key = KeyPairGenerator.generate_key_pair_for_public_key_info(
            self._public_key_info_from_key_type(key_type)
        )
        private_key_pem = PrivateKeySerializer(private_key).as_pkcs8_pem().decode()
        credential_model = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
            private_key=private_key_pem,
            certificate=None,
        )
        return IssuedCredentialModel.objects.create(
            common_name=self.owner_credential.unique_name,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DEV_OWNER_ID,
            issued_using_cert_profile='dev_owner_id',
            credential=credential_model,
            owner_credential=self.owner_credential,
        )

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Resolve the OwnerCredentialModel and the dev_owner_id certificate profile.

        On each visit a fresh key-only IssuedCredentialModel is created.  If there
        is already a pending (certificate-less) credential from a previous visit its
        pk is reused so we do not accumulate orphan credentials.
        """
        self.owner_credential = get_object_or_404(OwnerCredentialModel, pk=kwargs['pk'])
        try:
            self.cert_profile = CertificateProfileModel.objects.get(unique_name='dev_owner_id')
        except CertificateProfileModel.DoesNotExist:
            messages.error(
                request,
                _('Certificate profile "dev_owner_id" not found. Please create it first.'),
            )
            return redirect('pki:owner_credentials-clm', pk=self.owner_credential.pk)

        # Reuse an existing pending (certificate-less) credential if one exists,
        # otherwise generate a fresh key pair and create a new one.
        session_key = self._pending_session_key(self.owner_credential)
        existing_pk = (request.session.get(session_key) or {}).get('issued_credential_pk')
        if existing_pk:
            try:
                self.pending_issued = IssuedCredentialModel.objects.select_related('credential').get(
                    pk=existing_pk,
                    owner_credential=self.owner_credential,
                    issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DEV_OWNER_ID,
                    credential__certificate__isnull=True,
                )
                # Delete any other orphan pending credentials (from even older aborted sessions)
                self._delete_orphan_pending_credentials(exclude_pk=existing_pk)
            except IssuedCredentialModel.DoesNotExist:
                self._delete_orphan_pending_credentials(exclude_pk=None)
                self.pending_issued = self._create_pending_issued_credential()
        else:
            # Clean up any leftover key-only credentials from previous aborted sessions
            # before creating the new one.
            self._delete_orphan_pending_credentials(exclude_pk=None)
            self.pending_issued = self._create_pending_issued_credential()

        return super().dispatch(request, *args, **kwargs)  # type: ignore[return-value]

    def get_form_kwargs(self) -> dict[str, Any]:
        """Inject the profile into the form."""
        kwargs = super().get_form_kwargs()
        kwargs['profile'] = self.cert_profile.profile
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add owner credential and profile to template context."""
        context = super().get_context_data(**kwargs)
        context['owner_credential'] = self.owner_credential
        context['cert_profile'] = self.cert_profile
        return context

    def form_invalid(self, form: CertificateIssuanceForm) -> HttpResponse:
        """Show field errors as Django messages."""
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(self.request, f'{field}: {error}')
        return super().form_invalid(form)

    def form_valid(self, form: CertificateIssuanceForm) -> HttpResponse:
        """Store certificate content and pending credential pk in session, then proceed to Step 2."""
        session_key = self._pending_session_key(self.owner_credential)
        session_data = dict(form.cleaned_data)
        session_data['issued_credential_pk'] = self.pending_issued.pk
        self.request.session[session_key] = session_data
        messages.success(
            self.request,
            _('Certificate content defined. Please proceed to request the DevOwnerID via EST.'),
        )
        return redirect('pki:owner_credentials-request-cert-est', pk=self.owner_credential.pk)


class OwnerCredentialRequestCertEstView(
    LoggerMixin, OwnerCredentialContextMixin, DetailView[OwnerCredentialModel]
):
    """Step 2 - Review and trigger the EST enrollment for a new DevOwnerID certificate.

    Reads the certificate content stored by
    :class:`OwnerCredentialDefineCertContentEstView`, builds a CSR using the
    ``dev_owner_id`` profile, signs it with the existing DevOwnerID key, sends
    it to the configured EST server and stores the issued certificate back in
    the :class:`~devices.models.IssuedCredentialModel`.
    """

    http_method_names = ('get', 'post')
    model = OwnerCredentialModel
    template_name = 'pki/owner_credentials/request_cert_est.html'
    context_object_name = 'owner_credential'

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _session_key(self, owner_credential: OwnerCredentialModel) -> str:
        return f'dev_owner_id_cert_content_{owner_credential.pk}'

    def _get_pending_issued(
        self, owner_credential: OwnerCredentialModel, cert_content_data: dict[str, Any]
    ) -> IssuedCredentialModel:
        """Fetch the pending IssuedCredentialModel whose pk was stored in the session by Step 1.

        :raises ValueError: if no matching pending credential is found.
        """
        issued_pk = cert_content_data.get('issued_credential_pk')
        if issued_pk:
            try:
                return IssuedCredentialModel.objects.select_related('credential').get(
                    pk=issued_pk,
                    owner_credential=owner_credential,
                    issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DEV_OWNER_ID,
                )
            except IssuedCredentialModel.DoesNotExist:
                pass  # pk no longer valid; fall through to raise ValueError below.
        msg = _('No pending DevOwnerID credential found. Please re-define the certificate content.')
        raise ValueError(msg)

    def _build_request_data(self, cert_content_data: dict[str, Any]) -> dict[str, Any]:
        """Convert the flat form data into the nested structure expected by the profile verifier."""
        request_data: dict[str, Any] = {
            'subj': {},
            'ext': {'subject_alternative_name': {}},
            'validity': {},
        }
        for field in ('common_name', 'organization_name', 'organizational_unit_name',
                      'country_name', 'state_or_province_name', 'locality_name', 'email_address'):
            value = cert_content_data.get(field)
            if value:
                request_data['subj'][field] = value
        for field in ('dns_names', 'ip_addresses', 'rfc822_names', 'uris'):
            value = cert_content_data.get(field)
            if value:
                # The value may be a comma-separated string (directly from the form) or already
                # a list (after a JSON session round-trip). Normalise to list in both cases.
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

    def _build_cert_content_summary(self, cert_data: dict[str, Any]) -> dict[str, Any]:
        """Return a human-readable summary dict suitable for template rendering."""
        summary: dict[str, Any] = {'subject': {}, 'san': {}, 'validity': ''}
        for key, label in (
            ('common_name', 'Common Name (CN)'),
            ('organization_name', 'Organization (O)'),
            ('organizational_unit_name', 'Organizational Unit (OU)'),
            ('country_name', 'Country (C)'),
            ('state_or_province_name', 'State/Province (ST)'),
            ('locality_name', 'Locality (L)'),
            ('email_address', 'Email Address'),
        ):
            if cert_data.get(key):
                summary['subject'][label] = cert_data[key]
        for key, label in (
            ('dns_names', 'DNS Names'),
            ('ip_addresses', 'IP Addresses'),
            ('rfc822_names', 'Email Addresses (RFC 822)'),
            ('uris', 'URIs'),
        ):
            if cert_data.get(key):
                summary['san'][label] = cert_data[key]
        parts = [f'{cert_data[unit]} {unit}' for unit in ('days', 'hours', 'minutes', 'seconds') if cert_data.get(unit)]
        summary['validity'] = ', '.join(parts) if parts else _('Not specified')
        return summary

    # ------------------------------------------------------------------
    # GET
    # ------------------------------------------------------------------

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add cert-content summary and profile to the template context."""
        context = super().get_context_data(**kwargs)
        owner_credential: OwnerCredentialModel = self.get_object()
        cert_content_data = self.request.session.get(self._session_key(owner_credential))
        if cert_content_data:
            context['has_cert_content'] = True
            context['cert_content_summary'] = self._build_cert_content_summary(cert_content_data)
        else:
            context['has_cert_content'] = False
            context['cert_content_summary'] = None
        try:
            context['cert_profile'] = CertificateProfileModel.objects.get(unique_name='dev_owner_id')
        except CertificateProfileModel.DoesNotExist:
            context['cert_profile'] = None
        return context

    # ------------------------------------------------------------------
    # POST - perform EST enrollment
    # ------------------------------------------------------------------

    def _perform_est_enrollment(
        self, owner_credential: OwnerCredentialModel, cert_content_data: dict[str, Any]
    ) -> None:
        """Build a CSR, sign it with the DevOwnerID key and enroll via EST.

        On success the issued certificate is stored in the existing
        ``IssuedCredentialModel(DEV_OWNER_ID)`` that holds the private key.
        """
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

        cert_profile = CertificateProfileModel.objects.get(unique_name='dev_owner_id')

        # Fetch the specific pending IssuedCredentialModel created in Step 1.
        # We use the pk stored in the session to avoid ambiguity when multiple
        # DevOwnerID credentials exist for the same OwnerCredentialModel.
        pending_issued = self._get_pending_issued(owner_credential, cert_content_data)
        if pending_issued.credential is None:
            msg = _('No pending DevOwnerID credential found. Please re-define the certificate content.')
            raise ValueError(msg)

        signing_credential = pending_issued.credential  # CredentialModel (key-only so far)

        no_onboarding = owner_credential.no_onboarding_config
        context = EstCertificateRequestContext(
            operation='simpleenroll',
            protocol='est',
            domain=None,
            cert_profile_str='dev_owner_id',
            certificate_profile_model=cert_profile,
            allow_ca_certificate_request=True,
            est_server_host=owner_credential.remote_host,
            est_server_port=owner_credential.remote_port,
            est_server_path=owner_credential.remote_path,
            est_username=owner_credential.est_username,
            est_password=no_onboarding.est_password if no_onboarding else None,
            est_server_truststore=no_onboarding.trust_store if no_onboarding else None,
        )
        context.request_data = self._build_request_data(cert_content_data)
        context.owner_credential = signing_credential  # used by EstDeviceCsrSignProcessor

        # Build CSR from profile + request data
        csr_builder = ProfileAwareCsrBuilder()
        csr_builder.process_operation(context)
        csr = csr_builder.get_csr()
        context.cert_requested = csr

        # Re-sign the CSR with the DevOwnerID private key
        csr_signer = EstDeviceCsrSignProcessor()
        csr_signer.process_operation(context)
        signed_csr = csr_signer.get_signed_csr()

        # Send to remote EST server
        est_client = EstClient(context)
        issued_cert = est_client.simple_enroll(signed_csr)

        # Persist the issued certificate back into the existing CredentialModel
        from cryptography.x509 import load_pem_x509_certificate  # noqa: PLC0415
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

        # Update the IssuedCredentialModel common_name from the certificate CN
        cn = cert_model.common_name or owner_credential.unique_name
        pending_issued.common_name = cn
        pending_issued.save(update_fields=['common_name'])

        # Extract IDevID references from the SAN of the issued DevOwnerID certificate
        # and persist them so the list view can display the correct count.
        # Each URI with the "dev-owner:" scheme encodes the IDevID identity.
        # cert_model is the DevOwnerID CertificateModel just saved above, so we link it
        # directly on the IDevIDReferenceModel to avoid fingerprint-based lookups later.
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
                'Issued DevOwnerID certificate for "%s" has no SAN extension; '
                'no IDevID references stored.',
                owner_credential.unique_name,
            )

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Perform the EST enrollment and redirect to the CLM view."""
        owner_credential: OwnerCredentialModel = self.get_object()
        session_key = self._session_key(owner_credential)
        cert_content_data = request.session.get(session_key)

        if not cert_content_data:
            messages.error(
                request,
                _('Certificate content data not found. Please define the certificate content first.'),
            )
            return redirect('pki:owner_credentials-define-cert-content-est', pk=owner_credential.pk)

        try:
            self._perform_est_enrollment(owner_credential, cert_content_data)
            del request.session[session_key]
            messages.success(
                request,
                _('Successfully enrolled DevOwnerID certificate for "{name}" via EST.').format(
                    name=owner_credential.unique_name
                ),
            )
            return redirect('pki:owner_credentials-clm', pk=owner_credential.pk)
        except (ValueError, KeyError, ProfileValidationError) as exc:
            messages.error(request, _('Failed to build certificate request: {error}').format(error=str(exc)))
            return redirect('pki:owner_credentials-define-cert-content-est', pk=owner_credential.pk)
        except CertificateProfileModel.DoesNotExist:
            messages.error(request, _('Certificate profile "dev_owner_id" not found.'))
            return redirect('pki:owner_credentials-clm', pk=owner_credential.pk)
        except EstClientError as exc:
            self.logger.exception('EST client error during DevOwnerID enrollment')
            messages.error(
                request,
                _('Failed to enroll DevOwnerID certificate via EST: {error}').format(error=str(exc)),
            )
            return redirect('pki:owner_credentials-request-cert-est', pk=owner_credential.pk)
        except Exception as exc:
            self.logger.exception('Unexpected error during DevOwnerID EST enrollment')
            messages.error(
                request,
                _('Unexpected error during enrollment: {error}').format(error=str(exc)),
            )
            return redirect('pki:owner_credentials-request-cert-est', pk=owner_credential.pk)
