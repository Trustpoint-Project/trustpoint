# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for DevOwnerID (Zero-Touch Credential) management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import ProtectedError
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView

from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from devices.presentation import credential_expiry_display
from pki.forms import (
    CertificateIssuanceForm,
    OwnerCredentialAddManagementCaForm,
    OwnerCredentialExternalCsrCertificateForm,
    OwnerCredentialExternalCsrKeyForm,
    OwnerCredentialFileImportForm,
    OwnerCredentialOnboardingSetupForm,
    OwnerCredentialPkcs12ImportForm,
)
from pki.models import RemoteIssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.credential import CredentialModel
from pki.services.csr import parse_csr
from pki.services.external_csr import build_external_csr, csr_download_response
from pki.services.key_generation import generate_pending_credential
from pki.services.owner_credential import (
    create_pending_dev_owner_id,
    issue_owner_credential_from_management_ca,
    persist_owner_credential_certificate,
)
from pki.util.cert_profile import ProfileValidationError
from pki.util.certificate_request import build_cert_content_summary
from pki.views.mixins import CertificateProfileSelectionMixin
from request.clients import EstClientError
from request.clients.cmp_client import CmpClientError
from shared.views import FormErrorMessageMixin
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import DEVICES_PAGE_CATEGORY, DEVICES_PAGE_ZERO_TOUCH_SUBCATEGORY
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    SortableTableMixin,
    UserPermissionRequiredMixin,
)
from users.permissions import AppPermissions

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.forms import Form

DEV_OWNER_ID = RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID


def _dev_owner_id_credentials() -> QuerySet[RemoteIssuedCredentialModel]:
    """Return DevOwnerID credential rows."""
    return RemoteIssuedCredentialModel.objects.filter(issued_credential_type=DEV_OWNER_ID)


class OwnerCredentialContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> DevOwnerID pages."""

    context_page_category = 'pki'
    context_page_name = 'owner_credentials'


class ZeroTouchContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the Devices -> Zero-Touch Credentials pages."""

    context_page_category = DEVICES_PAGE_CATEGORY
    context_page_name = DEVICES_PAGE_ZERO_TOUCH_SUBCATEGORY


class OwnerCredentialTableView(
    ZeroTouchContextMixin, SortableTableMixin[RemoteIssuedCredentialModel], ListView[RemoteIssuedCredentialModel]
):
    """DevOwnerID table view (Devices -> Zero-Touch Credentials)."""

    template_name = 'devices/zero_touch_credentials/zero_touch_credentials.html'
    model = RemoteIssuedCredentialModel
    context_object_name = 'owner_credentials'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'common_name'

    def get_queryset(self) -> QuerySet[RemoteIssuedCredentialModel]:
        """Return DevOwnerID credential rows with their certificate information."""
        sort_param = self.request.GET.get('sort', self.default_sort_param)
        return _dev_owner_id_credentials().select_related('credential__certificate', 'ca').order_by(sort_param)


class OwnerCredentialDetailView(LoggerMixin, ZeroTouchContextMixin, DetailView[RemoteIssuedCredentialModel]):
    """View to display the details of a DevOwnerID (Devices section)."""

    http_method_names = ('get',)

    success_url = reverse_lazy('devices:zero_touch_credentials')
    ignore_url = reverse_lazy('devices:zero_touch_credentials')
    template_name = 'devices/zero_touch_credentials/details.html'
    context_object_name = 'owner_credential'

    def get_queryset(self) -> QuerySet[RemoteIssuedCredentialModel]:
        """Limit detail access to DevOwnerID rows."""
        return _dev_owner_id_credentials().select_related('credential__certificate', 'ca')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the IDevID reference list to the context."""
        context = super().get_context_data(**kwargs)
        owner_credential = self.get_object()
        context['idevid_refs'] = list(owner_credential.idevid_ref_set.select_related('dev_owner_id_certificate').all())
        return context


class OwnerCredentialAddMethodSelectView(ZeroTouchContextMixin, FormView[OwnerCredentialFileImportForm]):
    """View to select the method for adding a new DevOwnerID."""

    template_name = 'devices/zero_touch_credentials/add/method_select.html'
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
            return HttpResponseRedirect(reverse_lazy('devices:zero_touch_credentials-add-file_import'))
        return HttpResponseRedirect(reverse_lazy('devices:zero_touch_credentials-add'))


class OwnerCredentialFileImportView(
    UserPermissionRequiredMixin, ZeroTouchContextMixin, FormView[OwnerCredentialFileImportForm]
):
    """View to import a DevOwnerID from separate PEM files."""

    template_name = 'devices/zero_touch_credentials/add/file_import.html'
    form_class = OwnerCredentialFileImportForm
    permission_required = AppPermissions.MANAGE_DEVICES
    success_url = reverse_lazy('devices:zero_touch_credentials')

    def form_valid(self, form: OwnerCredentialFileImportForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        credential = form.cleaned_data['_dev_owner_id_credential']
        messages.success(
            self.request,
            _('Successfully added Zero-Touch Credential {name}.').format(name=credential.common_name),
        )
        action = self.request.POST.get('action', 'add_only')
        if action == 'add_with_truststore':
            return HttpResponseRedirect(
                reverse(
                    'devices:zero_touch_credentials-onboarding-setup',
                    kwargs={'pk': credential.pk},
                )
            )
        return super().form_valid(form)


class OwnerCredentialPkcs12ImportView(OwnerCredentialFileImportView):
    """Import a DevOwnerID from a PKCS#12 file."""

    form_class = OwnerCredentialPkcs12ImportForm  # type: ignore[assignment]


# Keep old name as alias so any external references continue to work
OwnerCredentialAddView = OwnerCredentialFileImportView


class OwnerCredentialAddManagementCaView(
    UserPermissionRequiredMixin, ZeroTouchContextMixin, FormView[OwnerCredentialAddManagementCaForm]
):
    """Create a pending DevOwnerID issued or forwarded by a selected management CA."""

    template_name = 'devices/zero_touch_credentials/add/est_request.html'
    form_class = OwnerCredentialAddManagementCaForm
    permission_required = AppPermissions.MANAGE_DEVICES
    success_url = reverse_lazy('devices:zero_touch_credentials')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add heading and navigation context."""
        return super().get_context_data(**kwargs) | {
            'form_title': _('Issue DevOwnerID from Management CA'),
            'back_url': reverse_lazy('devices:zero_touch_credentials-add'),
        }

    def form_valid(self, form: OwnerCredentialAddManagementCaForm) -> HttpResponse:
        """Create the pending DevOwnerID and continue to certificate content."""
        ca = form.cleaned_data['management_ca']
        try:
            pending = create_pending_dev_owner_id(ca)
        except (ValidationError, ValueError) as exc:
            form.add_error(None, str(exc))
            return self.form_invalid(form)
        messages.success(
            self.request,
            _('Define the certificate content for the new DevOwnerID.'),
        )
        return redirect('devices:zero_touch_credentials-define-cert-content-management-ca', pk=pending.pk)


class OwnerCredentialExternalCsrKeyView(
    UserPermissionRequiredMixin, ZeroTouchContextMixin, FormView[OwnerCredentialExternalCsrKeyForm]
):
    """Generate a DevOwnerID key and prepare an external CSR."""

    template_name = 'devices/zero_touch_credentials/add/est_request.html'
    form_class = OwnerCredentialExternalCsrKeyForm
    permission_required = AppPermissions.MANAGE_DEVICES

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add heading and navigation context."""
        return super().get_context_data(**kwargs) | {
            'form_title': _('Generate DevOwnerID CSR'),
            'back_url': reverse_lazy('devices:zero_touch_credentials-add'),
        }

    def form_valid(self, form: OwnerCredentialExternalCsrKeyForm) -> HttpResponse:
        """Create the pending DevOwnerID key and CSR workflow state."""
        try:
            credential = generate_pending_credential(
                alias=f'dev-owner-csr/{uuid4().hex}',
                key_type=form.cleaned_data['key_type'],
                credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
                policy=KeyPolicy.managed_signing_key(
                    signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
                ),
            )
            pending = RemoteIssuedCredentialModel.objects.create(
                common_name='',
                issued_credential_type=DEV_OWNER_ID,
                certificate_profile=None,
                credential=credential,
            )
        except (ValidationError, ValueError, RuntimeError) as exc:
            form.add_error(None, str(exc))
            return self.form_invalid(form)
        self.request.session[f'dev_owner_id_external_csr_{pending.pk}'] = {
            'credential_pk': credential.pk,
        }
        return redirect('devices:zero_touch_credentials-external-csr-content', pk=pending.pk)


class OwnerCredentialExternalCsrContentView(
    UserPermissionRequiredMixin,
    FormErrorMessageMixin,
    CertificateProfileSelectionMixin,
    LoggerMixin,
    ZeroTouchContextMixin,
    FormView[CertificateIssuanceForm],
):
    """Define the DevOwnerID certificate content and build its CSR."""

    default_profile_name = 'dev_owner_id'
    permission_required = AppPermissions.ISSUE_CERTIFICATES
    form_class = CertificateIssuanceForm
    template_name = 'devices/zero_touch_credentials/define_cert_content_est.html'
    available_profiles: list[CertificateProfileModel]

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Load the pending DevOwnerID and selected profile."""
        if not self.has_permission():
            raise PermissionDenied
        self.owner_credential = get_object_or_404(_dev_owner_id_credentials(), pk=kwargs['pk'])
        self.state = request.session.get(f'dev_owner_id_external_csr_{self.owner_credential.pk}') or {}
        if not self.state.get('credential_pk'):
            messages.error(request, _('The DevOwnerID key is missing. Start the CSR flow again.'))
            return redirect('devices:zero_touch_credentials-add')
        self.credential = get_object_or_404(CredentialModel, pk=self.state['credential_pk'])
        resolved = self._resolve_cert_profile(request)
        if resolved is None:
            messages.error(request, _('No certificate profiles found. Please create one first.'))
            return redirect('devices:zero_touch_credentials')
        self.cert_profile = resolved
        return super().dispatch(request, *args, **kwargs)  # type: ignore[return-value]

    def get_form_kwargs(self) -> dict[str, Any]:
        """Inject the selected profile into the form."""
        return super().get_form_kwargs() | {'profile': self.cert_profile.profile}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add owner credential, profile and profile list to the context."""
        return super().get_context_data(**kwargs) | {
            'owner_credential': self.owner_credential,
            'cert_profile': self.cert_profile,
            'available_profiles': self.available_profiles,
        }

    def form_valid(self, form: CertificateIssuanceForm) -> HttpResponse:
        """Build and store the CSR, then continue to the certificate upload page."""
        content = dict(form.cleaned_data)
        try:
            csr = build_external_csr(self.credential, self.cert_profile, content, allow_ca=True)
        except (ValueError, ProfileValidationError) as exc:
            form.add_error(None, str(exc))
            return self.form_invalid(form)
        self.owner_credential.certificate_profile = self.cert_profile
        self.owner_credential.save(update_fields=['certificate_profile'])
        self.state.update(
            {
                'profile_pk': self.cert_profile.pk,
                'content': content,
                'csr_pem': csr.public_bytes(serialization.Encoding.PEM).decode('ascii'),
            }
        )
        self.request.session[f'dev_owner_id_external_csr_{self.owner_credential.pk}'] = self.state
        return redirect('devices:zero_touch_credentials-external-csr', pk=self.owner_credential.pk)


class OwnerCredentialExternalCsrView(
    UserPermissionRequiredMixin, LoggerMixin, ZeroTouchContextMixin, FormView[OwnerCredentialExternalCsrCertificateForm]
):
    """Download the DevOwnerID CSR and upload the certificate issued for it."""

    template_name = 'devices/zero_touch_credentials/external_csr.html'
    form_class = OwnerCredentialExternalCsrCertificateForm
    permission_required = AppPermissions.ISSUE_CERTIFICATES

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Load the pending DevOwnerID, key, CSR and state."""
        if not self.has_permission():
            raise PermissionDenied
        self.owner_credential = get_object_or_404(_dev_owner_id_credentials(), pk=kwargs['pk'])
        self.state = request.session.get(f'dev_owner_id_external_csr_{self.owner_credential.pk}') or {}
        if not self.state.get('credential_pk') or not self.state.get('csr_pem'):
            messages.error(request, _('The DevOwnerID CSR is missing. Start the CSR flow again.'))
            return redirect('devices:zero_touch_credentials-add')
        self.credential = get_object_or_404(CredentialModel, pk=self.state['credential_pk'])
        self.csr = parse_csr(self.state['csr_pem'].encode('ascii'), encoding='pem')
        return super().dispatch(request, *args, **kwargs)  # type: ignore[return-value]

    def get_form_kwargs(self) -> dict[str, Any]:
        """Bind the upload form to the pending key and CSR."""
        return super().get_form_kwargs() | {'credential': self.credential, 'csr': self.csr}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Expose the DevOwnerID and CSR download URL."""
        return super().get_context_data(**kwargs) | {'owner_credential': self.owner_credential}

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Serve the CSR as a download when requested."""
        if request.GET.get('download') == '1':
            return csr_download_response(self.csr, f'devownerid-{self.owner_credential.pk}')
        return super().get(request, *args, **kwargs)

    def form_valid(self, form: OwnerCredentialExternalCsrCertificateForm) -> HttpResponse:
        """Persist the uploaded certificate and finish the CSR flow."""
        profile = get_object_or_404(CertificateProfileModel, pk=self.state.get('profile_pk'))
        certificate = form.cleaned_data['certificate'].as_crypto()
        persist_owner_credential_certificate(
            self.owner_credential,
            profile,
            self.csr,
            certificate,
            form.chain,
            logger=self.logger,
        )
        del self.request.session[f'dev_owner_id_external_csr_{self.owner_credential.pk}']
        messages.success(
            self.request,
            _('Successfully imported DevOwnerID certificate for "{name}".').format(
                name=self.owner_credential.common_name
            ),
        )
        return redirect('devices:zero_touch_credentials-clm', pk=self.owner_credential.pk)


class OwnerCredentialOnboardingSetupView(
    UserPermissionRequiredMixin, LoggerMixin, ZeroTouchContextMixin, FormView[OwnerCredentialOnboardingSetupForm]
):
    """Set up AOKI zero-touch onboarding after DevOwnerID file import.

    Handles truststore import, domain association, and DevID registration pattern
    creation in a single step. Pre-populates the serial number pattern from the
    IDevID references found in the DevOwnerID certificate's SAN.
    """

    form_class = OwnerCredentialOnboardingSetupForm
    permission_required = AppPermissions.MANAGE_DEVICES
    template_name = 'devices/zero_touch_credentials/onboarding_setup.html'
    success_url = reverse_lazy('devices:zero_touch_credentials')

    def has_permission(self) -> bool:
        """Setup creates a global truststore as well as device registration state."""
        return super().has_permission() and self.request.user.has_perm(AppPermissions.MANAGE_TRUSTSTORES)

    def get_owner_credential(self) -> RemoteIssuedCredentialModel:
        """Get the DevOwnerID credential from the URL pk."""
        return get_object_or_404(_dev_owner_id_credentials(), pk=self.kwargs['pk'])

    def get_form_kwargs(self) -> dict[str, Any]:
        """Pass the DevOwnerID credential instance to the form."""
        kwargs = super().get_form_kwargs()
        kwargs['owner_credential'] = self.get_owner_credential()
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the DevOwnerID and IDevID references to the context."""
        context = super().get_context_data(**kwargs)
        owner_credential = self.get_owner_credential()
        context['owner_credential'] = owner_credential

        idevid_refs = list(owner_credential.idevid_ref_set.all())
        idevid_reference_strs = [ref.idevid_subj_sn_or_san_uri for ref in idevid_refs if ref.idevid_subj_sn_or_san_uri]
        context['idevid_reference_strs'] = idevid_reference_strs
        context['idevid_refs'] = idevid_refs

        if idevid_reference_strs:
            import re  # noqa: PLC0415

            escaped = [re.escape(sn) for sn in idevid_reference_strs]
            if len(escaped) == 1:
                context['suggested_pattern'] = f'^{escaped[0]}$'
            else:
                context['suggested_pattern'] = '^(' + '|'.join(escaped) + ')$'
        else:
            context['suggested_pattern'] = ''

        return context

    def form_valid(self, form: OwnerCredentialOnboardingSetupForm) -> HttpResponse:
        """Show success messages and redirect to the zero-touch credentials list."""
        owner_credential = self.get_owner_credential()
        truststore = form.cleaned_data.get('_truststore')
        dev_id_registration = form.cleaned_data.get('_dev_id_registration')

        if truststore and dev_id_registration:
            messages.success(
                self.request,
                _(
                    'AOKI onboarding setup complete for "{name}": '
                    'truststore "{ts}" and registration pattern "{reg}" created '
                    'in domain "{domain}".'
                ).format(
                    name=owner_credential.common_name,
                    ts=truststore.unique_name,
                    reg=dev_id_registration.unique_name,
                    domain=dev_id_registration.domain.unique_name,
                ),
            )

        return super().form_valid(form)

    def form_invalid(self, form: OwnerCredentialOnboardingSetupForm) -> HttpResponse:
        """Show form-level errors as Django messages."""
        for error in form.non_field_errors():
            messages.error(self.request, str(error))
        return super().form_invalid(form)


class OwnerCredentialCLMView(ZeroTouchContextMixin, DetailView[RemoteIssuedCredentialModel]):
    """Certificate Lifecycle Management view for one DevOwnerID certificate."""

    http_method_names = ('get',)
    template_name = 'devices/zero_touch_credentials/clm.html'
    context_object_name = 'owner_credential'

    _get_expires_in = staticmethod(credential_expiry_display)

    def get_queryset(self) -> QuerySet[RemoteIssuedCredentialModel]:
        """Limit CLM access to DevOwnerID rows."""
        return _dev_owner_id_credentials().select_related('credential__certificate', 'certificate_profile', 'ca')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add computed expiry information."""
        context = super().get_context_data(**kwargs)
        credential: RemoteIssuedCredentialModel = self.object
        if credential.credential.certificate is not None:
            credential.expires_in = self._get_expires_in(credential)  # type: ignore[attr-defined]
            credential.expiration_date = credential.credential.certificate.not_valid_after  # type: ignore[attr-defined]
        else:
            credential.expires_in = _('Pending enrollment')  # type: ignore[attr-defined]
            credential.expiration_date = '—'  # type: ignore[attr-defined]
        context['idevid_refs'] = list(credential.idevid_ref_set.select_related('dev_owner_id_certificate').all())
        context['back_url'] = reverse_lazy('devices:zero_touch_credentials')
        return context


class OwnerCredentialBulkDeleteConfirmView(UserPermissionRequiredMixin, ZeroTouchContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple DevOwnerID credentials."""

    permission_required = AppPermissions.MANAGE_DEVICES
    model = RemoteIssuedCredentialModel
    success_url = reverse_lazy('devices:zero_touch_credentials')
    ignore_url = reverse_lazy('devices:zero_touch_credentials')
    template_name = 'devices/zero_touch_credentials/confirm_delete.html'
    context_object_name = 'owner_credentials'

    def get_queryset(self) -> QuerySet[RemoteIssuedCredentialModel]:
        """Limit deletion to DevOwnerID rows."""
        return super().get_queryset().filter(issued_credential_type=DEV_OWNER_ID)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, _('No DevOwnerIDs selected for deletion.'))
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


class IssuedCredentialDeleteView(
    UserPermissionRequiredMixin, LoggerMixin, ZeroTouchContextMixin, DetailView[RemoteIssuedCredentialModel]
):
    """Confirm and delete a single DevOwnerID credential."""

    http_method_names = ('get', 'post')
    permission_required = AppPermissions.MANAGE_DEVICES
    template_name = 'devices/zero_touch_credentials/confirm_delete_issued_credential.html'
    context_object_name = 'owner_credential'

    def get_queryset(self) -> QuerySet[RemoteIssuedCredentialModel]:
        """Limit deletion to DevOwnerID rows."""
        return _dev_owner_id_credentials()

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Delete the DevOwnerID credential and redirect back to the list."""
        credential = self.get_object()
        cn = credential.common_name
        try:
            credential.delete()
        except Exception as exc:  # broad catch to surface any deletion error to the user
            self.logger.exception('Failed to delete RemoteIssuedCredentialModel pk=%s', credential.pk)
            messages.error(
                request,
                _('Failed to delete credential "{cn}": {error}').format(cn=cn, error=str(exc)),
            )
        else:
            messages.success(
                request,
                _('DevOwnerID credential "{cn}" has been deleted.').format(cn=cn),
            )
        return redirect('devices:zero_touch_credentials')


# ---------------------------------------------------------------------------
# DevOwnerID management CA issuance (define content -> request)
# ---------------------------------------------------------------------------


class OwnerCredentialDefineCertContentManagementCaView(
    UserPermissionRequiredMixin,
    FormErrorMessageMixin,
    CertificateProfileSelectionMixin,
    LoggerMixin,
    ZeroTouchContextMixin,
    FormView[CertificateIssuanceForm],
):
    """Define the certificate content for a DevOwnerID issued by a management CA.

    The default profile is ``dev_owner_id``. The pending key-only credential was
    created by the add view and already carries the selected management CA.
    """

    default_profile_name = 'dev_owner_id'
    permission_required = AppPermissions.ISSUE_CERTIFICATES
    request_cert_url_name: ClassVar[str] = 'devices:zero_touch_credentials-request-cert-management-ca'

    form_class = CertificateIssuanceForm
    template_name = 'devices/zero_touch_credentials/define_cert_content_est.html'
    available_profiles: list[CertificateProfileModel]

    def _pending_session_key(self, credential: RemoteIssuedCredentialModel) -> str:
        return f'dev_owner_id_cert_content_{credential.pk}'

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Resolve the pending credential and profile."""
        if not self.has_permission():
            raise PermissionDenied
        self.owner_credential = get_object_or_404(_dev_owner_id_credentials(), pk=kwargs['pk'])
        if self.owner_credential.ca is None:
            messages.error(request, _('Select a management CA before issuing a DevOwnerID.'))
            return redirect('devices:zero_touch_credentials')
        if self.owner_credential.credential.certificate is not None:
            messages.info(request, _('This DevOwnerID already has a certificate.'))
            return redirect('devices:zero_touch_credentials-clm', pk=self.owner_credential.pk)

        resolved_profile = self._resolve_cert_profile(request)
        if resolved_profile is None:
            messages.error(request, _('No certificate profiles found. Please create one first.'))
            return redirect('devices:zero_touch_credentials')
        self.cert_profile = resolved_profile
        return super().dispatch(request, *args, **kwargs)  # type: ignore[return-value]

    def get_form_kwargs(self) -> dict[str, Any]:
        """Inject the selected profile into the form."""
        return super().get_form_kwargs() | {'profile': self.cert_profile.profile}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the DevOwnerID, profile and profile list to the template context."""
        return super().get_context_data(**kwargs) | {
            'owner_credential': self.owner_credential,
            'cert_profile': self.cert_profile,
            'available_profiles': self.available_profiles,
        }

    def form_valid(self, form: CertificateIssuanceForm) -> HttpResponse:
        """Store certificate content and proceed to enrollment."""
        self.owner_credential.certificate_profile = self.cert_profile
        self.owner_credential.save(update_fields=['certificate_profile'])
        session_data = dict(form.cleaned_data)
        session_data['cert_profile_unique_name'] = self.cert_profile.unique_name
        self.request.session[self._pending_session_key(self.owner_credential)] = session_data
        messages.success(self.request, _('Certificate content defined. Proceed to request the DevOwnerID.'))
        return redirect(self.request_cert_url_name, pk=self.owner_credential.pk)


class OwnerCredentialRequestCertManagementCaView(
    UserPermissionRequiredMixin, LoggerMixin, ZeroTouchContextMixin, DetailView[RemoteIssuedCredentialModel]
):
    """Review and issue a DevOwnerID locally or through an external management CA."""

    http_method_names = ('get', 'post')
    permission_required = AppPermissions.ISSUE_CERTIFICATES
    template_name = 'devices/zero_touch_credentials/request_cert_est.html'
    context_object_name = 'owner_credential'
    protocol_name: ClassVar[str] = 'Management CA'
    client_error_types: ClassVar[tuple[type[Exception], ...]] = (EstClientError, CmpClientError)
    define_content_url_name: ClassVar[str] = 'devices:zero_touch_credentials-define-cert-content-management-ca'
    request_cert_url_name: ClassVar[str] = 'devices:zero_touch_credentials-request-cert-management-ca'

    def get_queryset(self) -> QuerySet[RemoteIssuedCredentialModel]:
        """Limit access to DevOwnerID rows."""
        return _dev_owner_id_credentials().select_related('credential__certificate', 'ca')

    def _session_key(self, credential: RemoteIssuedCredentialModel) -> str:
        return f'dev_owner_id_cert_content_{credential.pk}'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add protocol name, content summary and profile to the context."""
        context = super().get_context_data(**kwargs)
        context['protocol_name'] = self.protocol_name
        credential: RemoteIssuedCredentialModel = self.get_object()
        cert_content_data = self.request.session.get(self._session_key(credential))
        if cert_content_data:
            context['has_cert_content'] = True
            context['cert_content_summary'] = build_cert_content_summary(cert_content_data)
        else:
            context['has_cert_content'] = False
            context['cert_content_summary'] = None
        profile_name = (cert_content_data or {}).get('cert_profile_unique_name', 'dev_owner_id')
        try:
            context['cert_profile'] = CertificateProfileModel.objects.get(unique_name=profile_name)
        except CertificateProfileModel.DoesNotExist:
            context['cert_profile'] = None
        return context

    def _perform_enrollment(self, credential: RemoteIssuedCredentialModel, cert_content_data: dict[str, Any]) -> None:
        """Issue or forward the pending DevOwnerID using its selected management CA."""
        profile_name = cert_content_data.get('cert_profile_unique_name', 'dev_owner_id')
        cert_profile = CertificateProfileModel.objects.get(unique_name=profile_name)
        if credential.credential is None:
            msg = _('No pending DevOwnerID credential found. Please re-define the certificate content.')
            raise ValueError(msg)
        ca = credential.ca
        if ca is None:
            msg = _('No management CA selected for this DevOwnerID.')
            raise ValueError(msg)
        issue_owner_credential_from_management_ca(
            credential,
            cert_profile,
            cert_content_data,
            ca,
            logger=self.logger,
        )

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Perform enrollment and return to the CLM view."""
        credential: RemoteIssuedCredentialModel = self.get_object()
        session_key = self._session_key(credential)
        cert_content_data = request.session.get(session_key)
        if not cert_content_data:
            messages.error(request, _('Certificate content data not found. Please define it first.'))
            return redirect(self.define_content_url_name, pk=credential.pk)
        try:
            self._perform_enrollment(credential, cert_content_data)
            del request.session[session_key]
            credential.refresh_from_db()
            messages.success(
                request,
                _('Successfully issued DevOwnerID certificate for "{name}".').format(name=credential.common_name),
            )
            return redirect('devices:zero_touch_credentials-clm', pk=credential.pk)
        except (ValueError, KeyError, ProfileValidationError) as exc:
            messages.error(request, _('Failed to build certificate request: {error}').format(error=str(exc)))
            return redirect(self.define_content_url_name, pk=credential.pk)
        except CertificateProfileModel.DoesNotExist:
            messages.error(request, _('Certificate profile "dev_owner_id" not found.'))
            return redirect('devices:zero_touch_credentials')
        except self.client_error_types as exc:
            self.logger.exception('%s client error during DevOwnerID enrollment', self.protocol_name)
            messages.error(
                request,
                _('Failed to enroll DevOwnerID certificate via {protocol}: {error}').format(
                    protocol=self.protocol_name, error=str(exc)
                ),
            )
            return redirect(self.request_cert_url_name, pk=credential.pk)
        except Exception as exc:
            self.logger.exception('Unexpected error during DevOwnerID enrollment')
            messages.error(request, _('Unexpected error during enrollment: {error}').format(error=str(exc)))
            return redirect(self.request_cert_url_name, pk=credential.pk)
