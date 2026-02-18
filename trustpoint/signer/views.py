"""Contains all the views of Signer App."""

from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError, QuerySet
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views import View
from django.views.generic import DetailView, ListView
from django.views.generic.edit import FormView

from signer.forms import (
    SignerAddFileImportPkcs12Form,
    SignerAddFileImportSeparateFilesForm,
    SignerAddFileTypeSelectForm,
    SignerAddMethodSelectForm,
    SignHashForm,
)
from signer.models import SignedMessageModel, SignerModel
from trustpoint.logger import LoggerMixin
from trustpoint.settings import UIConfig
from trustpoint.views.base import BulkDeleteView, ContextDataMixin, SortableTableMixin


class SignerContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the Signer pages."""

    context_page_category = 'signer'


class SignerTableView(SignerContextMixin, SortableTableMixin[SignerModel], ListView[SignerModel]):
    """Signer Table View."""

    model = SignerModel
    template_name = 'signer/signers.html'
    context_object_name = 'signers'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'unique_name'


class SignerAddMethodSelectView(SignerContextMixin, FormView[SignerAddMethodSelectForm]):
    """View to select the method to add a Signer."""

    template_name = 'signer/add/method_select.html'
    form_class = SignerAddMethodSelectForm

    def form_valid(self, form: SignerAddMethodSelectForm) -> HttpResponseRedirect:
        """Redirect to the next step based on the selected method."""
        method_select = form.cleaned_data.get('method_select')
        if not method_select:
            return HttpResponseRedirect(reverse_lazy('signer:signer-add-method_select'))

        if method_select and method_select == 'local_file_import':
            return HttpResponseRedirect(reverse_lazy('signer:signer-add-file_import-file_type_select'))

        return HttpResponseRedirect(reverse_lazy('signer:signer-add-method_select'))


class SignerAddFileImportFileTypeSelectView(SignerContextMixin, FormView[SignerAddFileTypeSelectForm]):
    """View to select the file type when importing a Signer."""

    template_name = 'signer/add/file_type_select.html'
    form_class = SignerAddFileTypeSelectForm

    def form_valid(self, form: SignerAddFileTypeSelectForm) -> HttpResponseRedirect:
        """Redirect to the next step based on the selected file type."""
        method_select = form.cleaned_data.get('method_select')
        if not method_select:
            return HttpResponseRedirect(reverse_lazy('signer:signer-add-file_import-file_type_select'))

        if method_select == 'pkcs_12':
            return HttpResponseRedirect(reverse_lazy('signer:signer-add-file_import-pkcs12'))
        if method_select == 'other':
            return HttpResponseRedirect(reverse_lazy('signer:signer-add-file_import-separate_files'))

        return HttpResponseRedirect(reverse_lazy('signer:signer-add-file_import-file_type_select'))


class SignerAddFileImportPkcs12View(SignerContextMixin, FormView[SignerAddFileImportPkcs12Form]):
    """View to import an Issuing CA from a PKCS12 file."""

    template_name = 'signer/add/file_import.html'
    form_class = SignerAddFileImportPkcs12Form
    success_url = reverse_lazy('signer:signer_list')

    def form_valid(self, form: SignerAddFileImportPkcs12Form) -> HttpResponse:
        """Handle the case where the form is valid."""
        messages.success(
            self.request,
            _('Successfully added Signer {name}.').format(name=form.cleaned_data['unique_name']),
        )
        return super().form_valid(form)


class SignerAddFileImportSeparateFilesView(SignerContextMixin, FormView[SignerAddFileImportSeparateFilesForm]):
    """View to import a Signer from separate PEM files."""

    template_name = 'signer/add/file_import.html'
    form_class = SignerAddFileImportSeparateFilesForm
    success_url = reverse_lazy('signer:signer_list')

    def form_valid(self, form: SignerAddFileImportSeparateFilesForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        messages.success(
            self.request,
            _('Successfully added Signer {name}.').format(name=form.cleaned_data['unique_name']),
        )
        return super().form_valid(form)


class SignerConfigView(LoggerMixin, SignerContextMixin, DetailView[SignerModel]):
    """View to display the details of a Signer."""

    http_method_names = ('get',)

    model = SignerModel
    success_url = reverse_lazy('signer:signer_list')
    ignore_url = reverse_lazy('signer:signer_list')
    template_name = 'signer/signer_config.html'
    context_object_name = 'signer'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the issued certificates to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data()

        Returns:
            The context to render the page.
        """
        return super().get_context_data(**kwargs)


class SignedMessagesListView(SignerContextMixin, ListView[SignedMessageModel]):
    """View to display all signed messages by a specific Signer."""

    model = SignedMessageModel
    template_name = 'signer/signed_messages.html'
    context_object_name = 'signed_messages'

    def get_queryset(self) -> QuerySet[SignedMessageModel]:
        """Gets the required and filtered QuerySet.

        Returns:
            The filtered QuerySet.
        """
        signer = get_object_or_404(SignerModel, pk=self.kwargs['pk'])

        return SignedMessageModel.objects.filter(signer=signer).order_by('-created_at')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the signer model object to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data()

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        context['signer'] = get_object_or_404(SignerModel, pk=self.kwargs['pk'])
        return context


class SignerBulkDeleteConfirmView(SignerContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple Signers."""

    model = SignerModel
    success_url = reverse_lazy('signer:signer_list')
    ignore_url = reverse_lazy('signer:signer_list')
    template_name = 'signer/confirm_delete.html'
    context_object_name = 'signers'

    def form_valid(self, form: Any) -> HttpResponse:
        """Delete the selected Signers on valid form."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0

        try:
            response = super().form_valid(form)
        except (ProtectedError, ValidationError):
            messages.error(
                self.request,
                _('Cannot delete the selected Signer(s) because they are referenced by other objects.'),
            )
            return HttpResponseRedirect(self.ignore_url)

        messages.success(
            self.request,
            _('Successfully deleted {count} Signer(s).').format(count=deleted_count),
        )
        return response


class SignHashView(LoggerMixin, SignerContextMixin, FormView[SignHashForm]):
    """View for signing a hash value with a selected signer."""

    template_name = 'signer/sign_hash.html'
    form_class = SignHashForm
    success_url = reverse_lazy('signer:signer_list')

    def form_valid(self, form: SignHashForm) -> HttpResponse:
        """Sign the hash and display the signature."""
        try:
            signer = form.cleaned_data['signer']
            hash_value = form.cleaned_data['hash_value']

            hash_algorithm_name = signer.hash_algorithm

            hash_bytes = bytes.fromhex(hash_value)

            private_key = signer.credential.get_private_key()

            hash_algo = getattr(hashes, hash_algorithm_name.upper())()

            prehashed_algo = Prehashed(hash_algo)

            if isinstance(private_key, rsa.RSAPrivateKey):
                signature = private_key.sign(hash_bytes, padding.PKCS1v15(), prehashed_algo)
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                signature = private_key.sign(hash_bytes, ec.ECDSA(prehashed_algo))
            else:
                messages.error(self.request, _('Unsupported key algorithm.'))
                return self.form_invalid(form)

            signature_hex = signature.hex()

            SignedMessageModel.objects.create(signer=signer, hash_value=hash_value, signature=signature_hex)

            messages.success(
                self.request,
                _('Hash successfully signed with signer "{signer_name}".').format(signer_name=signer.unique_name),
            )

            self.request.session['last_signature'] = {
                'signer_name': signer.unique_name,
                'hash_algorithm': hash_algorithm_name,
                'hash_value': hash_value,
                'signature': signature_hex,
            }

            return HttpResponseRedirect(reverse_lazy('signer:sign_hash_success'))

        except Exception as e:
            self.logger.exception('Failed to sign hash')
            messages.error(self.request, _('Failed to sign hash: {error}').format(error=str(e)))
            return self.form_invalid(form)


class SignHashSuccessView(SignerContextMixin, View):
    """View to display the signature result."""

    template_name = 'signer/sign_hash_success.html'

    def get(self, request: HttpRequest) -> HttpResponse:
        """Display the signature result.

        Args:
            request: The HTTP request.

        Returns:
            HttpResponse with the signature result.
        """
        signature_data = request.session.pop('last_signature', None)

        if not signature_data:
            messages.warning(request, _('No signature data available.'))
            return HttpResponseRedirect(reverse_lazy('signer:sign_hash'))

        context = self.get_context_data()
        context.update(signature_data)
        return render(request, self.template_name, context)

    def get_context_data(self, **kwargs: Any) -> dict[Any, Any]:
        """Get context data for the view."""
        del kwargs
        context = super().get_context_data() if hasattr(super(), 'get_context_data') else {}
        context['context_page_category'] = 'signer'
        return context
