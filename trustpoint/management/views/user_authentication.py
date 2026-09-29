# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""View for the user authentication configuration page."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.password_validation import CommonPasswordValidator
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import CommandError
from django.db import DatabaseError, transaction
from django.db.models import ProtectedError
from django.http import FileResponse, Http404
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views import View
from django.views.generic.edit import FormView

from crypto.domain.errors import CryptoError
from management.forms import CertificateAuthenticationEnabledForm, ManagementCAActionForm, PasswordPolicyForm
from management.models import CertificateAuthenticationConfig, PasswordPolicy
from pki.services.management_ca import ManagementCAService
from trustpoint.logger import LoggerMixin
from trustpoint.views.base import ContextDataMixin, SuperuserRequiredMixin
from users.permissions import AppPermissions

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


class UserAuthenticationView(
    ContextDataMixin, LoginRequiredMixin, SuperuserRequiredMixin, FormView[CertificateAuthenticationEnabledForm],
):
    """Display authentication settings and persist the certificate authentication preference."""

    template_name = 'management/user_authentication.html'
    form_class = CertificateAuthenticationEnabledForm
    success_url = reverse_lazy('management:user_authentication')
    context_page_category = 'management'
    context_page_name = 'user_authentication'
    http_method_names = ('get', 'post')

    def get_initial(self) -> dict[str, Any]:
        """Read the saved switch without creating configuration on a page visit."""
        initial = super().get_initial()
        root_ca, issuing_ca = ManagementCAService.get_hierarchy()
        if issuing_ca is not None and ManagementCAService.is_complete(root_ca, issuing_ca):
            initial['issuing_ca_id'] = issuing_ca.pk
            initial['enabled'] = CertificateAuthenticationConfig.objects.filter(
                issuing_ca=issuing_ca, enabled=True,
            ).exists()
        return initial

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Make the switch available once the management CA hierarchy is generated."""
        context = super().get_context_data(**kwargs)
        root_ca, issuing_ca = ManagementCAService.get_hierarchy()
        context['management_ca_complete'] = ManagementCAService.is_complete(root_ca, issuing_ca)
        return context

    def form_valid(self, form: CertificateAuthenticationEnabledForm) -> HttpResponse:
        """Store the switch value without activating a CA or changing login behavior."""
        if not self.request.user.has_perm(AppPermissions.MANAGE_SECURITY_CONFIGURATION):
            raise PermissionDenied
        with transaction.atomic():
            root_ca, issuing_ca = ManagementCAService.get_hierarchy(lock=True)
            if issuing_ca is None or not ManagementCAService.is_complete(root_ca, issuing_ca):
                form.add_error(None, _('Generate the management CA before enabling certificate authentication.'))
            elif issuing_ca.pk != form.cleaned_data['issuing_ca_id']:
                form.add_error(None, _('The management CA has changed. Reload the page and try again.'))
            else:
                CertificateAuthenticationConfig.objects.update_or_create(
                    issuing_ca=issuing_ca, defaults={'enabled': form.cleaned_data['enabled']},
                )
                messages.success(self.request, _('Certificate authentication setting saved.'))
                return super().form_valid(form)
        return self.form_invalid(form)


class CertificateAuthenticationConfigureView(
    ContextDataMixin, LoginRequiredMixin, SuperuserRequiredMixin, LoggerMixin, FormView[ManagementCAActionForm],
):
    """Configure the management CA used for user certificate authentication."""

    template_name = 'management/certificate_authentication.html'
    form_class = ManagementCAActionForm
    success_url = reverse_lazy('management:certificate_authentication')
    context_page_category = 'management'
    context_page_name = 'user_authentication'
    http_method_names = ('get', 'post')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Show the current hierarchy without creating CA records on a page visit."""
        context = super().get_context_data(**kwargs)
        root_ca, issuing_ca = ManagementCAService.get_hierarchy()
        context['root_ca'] = root_ca
        context['issuing_ca'] = issuing_ca
        context['management_ca_exists'] = root_ca is not None or issuing_ca is not None
        context['management_ca_complete'] = ManagementCAService.is_complete(root_ca, issuing_ca)
        return context

    def form_valid(self, form: ManagementCAActionForm) -> HttpResponse:
        """Apply the requested lifecycle operation and report actionable errors."""
        if not self.request.user.has_perm(AppPermissions.MANAGE_CAS):
            raise PermissionDenied
        try:
            ManagementCAService.apply(
                form.cleaned_data['action'],
                root_ca_id=form.cleaned_data['root_ca_id'],
                issuing_ca_id=form.cleaned_data['issuing_ca_id'],
            )
        except ProtectedError:
            form.add_error(None, _('The management CA is still referenced by other objects and cannot be removed.'))
        except ValidationError as exc:
            form.add_error(None, exc)
        except (CommandError, CryptoError, DatabaseError, RuntimeError, TypeError, ValueError):
            self.logger.exception('Management CA operation failed.')
            form.add_error(None, _('The management CA operation failed. Check the crypto backend and try again.'))
        else:
            success_messages = {
                'generate': _('Management CA generated successfully.'),
                'replace': _('Management CA replaced successfully.'),
                'delete': _('Management CA deleted successfully.'),
            }
            messages.success(self.request, success_messages[form.cleaned_data['action']])
            return super().form_valid(form)
        return self.form_invalid(form)


class PasswordPolicyConfigureView(
    ContextDataMixin, LoginRequiredMixin, SuperuserRequiredMixin, FormView[PasswordPolicyForm],
):
    """Edit the policy used for password creation and changes."""

    template_name = 'management/password_policy.html'
    form_class = PasswordPolicyForm
    success_url = reverse_lazy('management:user_authentication')
    context_page_category = 'management'
    context_page_name = 'user_authentication'
    selected_list_name = ''
    uses_default_list = True

    def get_form_kwargs(self) -> dict[str, Any]:
        """Bind to the saved policy, or model defaults if a policy has not been saved yet."""
        kwargs = super().get_form_kwargs()
        policy = PasswordPolicy.objects.filter(pk=PasswordPolicy.SINGLETON_ID).first() or PasswordPolicy()
        # Keep the saved list label even when an invalid form mutates its model instance.
        self.selected_list_name = policy.common_password_list_name
        self.uses_default_list = policy.uses_default_common_password_list
        kwargs['instance'] = policy
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Describe the saved list that the download action will return."""
        context = super().get_context_data(**kwargs)
        context['uses_default_list'] = self.uses_default_list
        context['selected_list_name'] = Path(self.selected_list_name).name
        return context

    def form_valid(self, form: PasswordPolicyForm) -> HttpResponse:
        """Save the policy used by subsequent password validation calls."""
        form.save()
        messages.success(self.request, _('Password policy saved.'))
        return super().form_valid(form)


class PasswordPolicyListDownloadView(LoginRequiredMixin, SuperuserRequiredMixin, View):
    """Download the list selected in the saved policy, including Django's default."""

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> FileResponse:
        """Return the selected file as an attachment without creating or updating the policy."""
        policy = PasswordPolicy.objects.filter(pk=PasswordPolicy.SINGLETON_ID).first() or PasswordPolicy()
        try:
            if policy.uses_default_common_password_list:
                password_file = CommonPasswordValidator().DEFAULT_PASSWORD_LIST_PATH.open('rb')
                filename = 'django-common-passwords.txt.gz'
            else:
                password_file = BytesIO(bytes(policy.common_password_list_data))
                filename = Path(policy.common_password_list_name).name
        except OSError as exc:
            raise Http404(_('The selected password list is not available.')) from exc

        response = FileResponse(
            password_file, as_attachment=True, filename=filename, content_type='application/octet-stream',
        )
        response['Cache-Control'] = 'private, no-store'
        response['X-Content-Type-Options'] = 'nosniff'
        return response
