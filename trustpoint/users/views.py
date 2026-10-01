# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for the users application."""

from __future__ import annotations

import base64
import hashlib
import time
from io import BytesIO
from typing import TYPE_CHECKING, cast
from urllib.parse import quote, urlencode
from typing import TYPE_CHECKING, Any, cast

from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, PasswordChangeView
from django.core.exceptions import ValidationError
from django.core.management import CommandError
from django.db import DatabaseError, IntegrityError, transaction
from django.db.models import ProtectedError
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render, resolve_url
from django.urls import reverse_lazy
from django.utils.crypto import constant_time_compare
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView, UpdateView
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp import login as otp_login
from django_otp.qr import write_qrcode_image
from trustpoint_core.serializer import CredentialFileFormat, CredentialSerializer

from crypto.domain.errors import CryptoError
from management.models import CertificateAuthenticationConfig, PasswordPolicy
from pki.management.commands.create_user_client_certificate import create_user_client_certificate
from pki.models import CertificateModel
from pki.services.management_ca import ManagementCAService
from setup_wizard.models import SetupWizardCompletedModel
from trustpoint.views.base import ContextDataMixin
from users.authentication import CERTIFICATE_LOGIN_ERROR_SESSION_KEY, REJECTED_CERTIFICATE_SESSION_KEY
from users.form import TrustpointUserDetailsForm, UserClientCertificateForm
from users.models import MAX_TOKEN_LENGTH, TrustpointUser, UserClientCertificate, UserOTPDevice, new_otp_key
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView
from django.core.exceptions import PermissionDenied
from django.db import DatabaseError
from django.shortcuts import redirect
from django.utils import timezone, translation
from django.utils.translation import gettext
from django.views.generic import FormView, UpdateView

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from typing import Any

    from cryptography import x509
    from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
    from django.db.models import QuerySet
    from django.http import HttpRequest, HttpResponse

from setup_wizard.models import SetupWizardCompletedModel
from users.permissions import AppPermissions

from .form import TrustpointPasswordChangeForm, TrustpointPasswordSetForm, TrustpointUserProfileForm
from .models import TrustpointUser


class PasswordChangeRequiredView(LoginRequiredMixin, FormView[TrustpointPasswordChangeForm]):
    """View shown when a user must change their password before continuing."""

    template_name = 'users/password_change_required.html'
    form_class = TrustpointPasswordChangeForm
    success_url = '/'

    def get_form_kwargs(self) -> dict[str, Any]:
        """Bind the password form to the authenticated user."""
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form: TrustpointPasswordChangeForm) -> HttpResponse:
        """Change the password, clear the requirement, and keep the session active."""
        user = cast('TrustpointUser', self.request.user)
        form.save()
        user.must_change_password = False
        user.save(update_fields=['must_change_password'])
        update_session_auth_hash(self.request, user)
        messages.success(self.request, gettext('Password changed successfully.'))
        return super().form_valid(form)


class TrustpointProfileView(LoginRequiredMixin, UpdateView[TrustpointUser, TrustpointUserProfileForm]):
    """Dedicated profile page for the current user and their preferences."""

    form_class = TrustpointUserProfileForm
    template_name = 'users/profile.html'
    success_url = '/users/profile/'

    def get_object(self, _queryset: QuerySet[TrustpointUser] | None = None) -> TrustpointUser:
        """Return the requested user when self-editing or managing users."""
        current_user = cast('TrustpointUser', self.request.user)
        target_pk = self.kwargs.get('pk')
        if target_pk is None or target_pk == current_user.pk:
            return current_user
        if not current_user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied
        return TrustpointUser.objects.get(pk=target_pk)

    def get_form_kwargs(self) -> dict[str, Any]:
        """Pass the current user so role/organization fields can be permission-aware."""
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the separate account-security form to the profile page."""
        context = super().get_context_data(**kwargs)
        profile_user = self.object
        context['can_change_password'] = (
            profile_user.pk == self.request.user.pk
            or self.request.user.has_perm(AppPermissions.MANAGE_USERS)
        )
        context['can_manage_account_security'] = (
            context['can_change_password']
            or self.request.user.has_perm(AppPermissions.MANAGE_USERS)
        )
        context['failed_login_blocked'] = bool(profile_user.blocked_by_failed_logins)
        context['can_unblock_failed_login'] = (
            profile_user.blocked_by_failed_logins
            and self.request.user.has_perm(AppPermissions.MANAGE_USERS)
        )
        if context['can_change_password']:
            if profile_user.pk == self.request.user.pk:
                context.setdefault('password_form', TrustpointPasswordChangeForm(user=profile_user))
            else:
                context.setdefault('password_form', TrustpointPasswordSetForm(user=profile_user))
        return context

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle either profile preferences or account-security updates."""
        if request.POST.get('form_name') == 'password_change':
            return self._post_password_change(request)

        if request.POST.get('form_name') == 'require_password_change':
            self.object = self.get_object()
            if self.object.pk == request.user.pk or request.user.has_perm(AppPermissions.MANAGE_USERS):
                self.object.must_change_password = True
                self.object.save(update_fields=['must_change_password'])
                if self.object.pk == request.user.pk:
                    request.session['password_change_current_session'] = True
                messages.success(
                    request,
                    gettext('The user will be required to change their password at their next login.'),
                )
            return redirect(request.path)

        if request.POST.get('form_name') == 'unblock_failed_login':
            self.object = self.get_object()
            if not request.user.has_perm(AppPermissions.MANAGE_USERS):
                raise PermissionDenied
            if self.object.blocked_by_failed_logins:
                self.object.is_active = True
                self.object.failed_login_attempts = 0
                self.object.blocked_by_failed_logins = False
                self.object.save(
                    update_fields=['is_active', 'failed_login_attempts', 'blocked_by_failed_logins'],
                )
                messages.success(request, gettext('The user has been unblocked and can log in again.'))
            return redirect(request.path)

        return super().post(request, *args, **kwargs)

    def _post_password_change(self, request: HttpRequest) -> HttpResponse:
        """Change the current user's or a managed user's password."""
        self.object = self.get_object()
        is_self_change = self.object.pk == request.user.pk
        if not is_self_change and not request.user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied

        if is_self_change:
            password_form: TrustpointPasswordChangeForm | TrustpointPasswordSetForm = TrustpointPasswordChangeForm(
                user=self.object,
                data=request.POST,
            )
        else:
            password_form = TrustpointPasswordSetForm(user=self.object, data=request.POST)

        if not password_form.is_valid():
            return self.render_to_response(self.get_context_data(password_form=password_form))

        password_form.save()
        if is_self_change:
            update_session_auth_hash(request, self.object)
        messages.success(request, gettext('Password changed successfully.'))
        return redirect(request.path)

    def form_valid(self, form: TrustpointUserProfileForm) -> HttpResponse:
        """Persist the user and apply the chosen language/timezone immediately."""
        super().form_valid(form)
        user = cast('TrustpointUser', self.request.user)
        translation.activate(user.language)
        timezone.activate(user.timezone)
        if self.object.pk == user.pk:
            return redirect('home:index')
        return redirect(self.request.path)


class UserProfileMixin(ContextDataMixin, LoginRequiredMixin):
    """Share profile navigation and bind its context to the signed-in user."""

    template_name = 'users/profile_form.html'
    context_page_category = 'users'
    context_page_name = 'profile'
    success_url = reverse_lazy('users:profile')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Use the authenticated user for the profile's configuration links."""
        context = super().get_context_data(**kwargs)
        context['object'] = self.request.user
        return context


class UserProfileView(UserProfileMixin, TemplateView):
    """Display a separate profile page for the signed-in user."""

    template_name = 'users/profile.html'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Show certificate authentication configuration when it is enabled."""
        context = super().get_context_data(**kwargs)
        context['certificate_authentication_enabled'] = CertificateAuthenticationConfig.objects.filter(
            enabled=True,
        ).exists()
        return context


@method_decorator(never_cache, name='dispatch')
class UserProfileCertificateAuthenticationView(UserProfileMixin, FormView[UserClientCertificateForm]):
    """List the user's client certificates and download newly generated credentials once."""

    template_name = 'users/profile_certificate_authentication.html'
    form_class = UserClientCertificateForm

    def get_form_kwargs(self) -> dict[str, Any]:
        """Bind the new certificate association to the authenticated user only."""
        kwargs = super().get_form_kwargs()
        kwargs['instance'] = UserClientCertificate(user=self.request.user)
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Show only certificates owned by the current user."""
        context = super().get_context_data(**kwargs)
        context['client_certificates'] = UserClientCertificate.objects.filter(
            user=self.request.user,
        ).select_related('certificate').order_by('identifier')
        context['certificate_authentication_enabled'] = CertificateAuthenticationConfig.objects.filter(
            enabled=True,
        ).exists()
        return context

    @staticmethod
    def _get_issuing_certificate() -> x509.Certificate:
        """Lock and validate the enabled management CA inside the creation transaction."""
        root_ca, issuing_ca = ManagementCAService.get_hierarchy(lock=True)
        if issuing_ca is None or not ManagementCAService.is_complete(root_ca, issuing_ca):
            raise ValidationError(_('The management CA is not ready.'))
        if not CertificateAuthenticationConfig.objects.filter(issuing_ca=issuing_ca, enabled=True).exists():
            raise ValidationError(_('Certificate based authentication is not enabled.'))
        issuing_certificate = issuing_ca.get_certificate()
        if issuing_certificate is None:
            raise ValidationError(_('The management CA has no certificate.'))
        return issuing_certificate

    @sensitive_variables()
    def form_valid(self, form: UserClientCertificateForm) -> HttpResponse:
        """Serialize the key in memory and persist only the certificate and its user association."""
        identifier = form.cleaned_data['identifier']
        try:
            with transaction.atomic():
                user = get_object_or_404(TrustpointUser.objects.select_for_update(), pk=self.request.user.pk)
                if UserClientCertificate.objects.filter(user=user, identifier=identifier).exists():
                    form.add_error('identifier', _('You already have a client certificate with this identifier.'))
                    return self.form_invalid(form)
                issuing_certificate = self._get_issuing_certificate()
                certificate, private_key = create_user_client_certificate(user.pk, identifier)
                credential = CredentialSerializer(
                    private_key=private_key, certificate=certificate, additional_certificates=[issuing_certificate],
                )
                pkcs12_data = credential.as_pkcs12(friendly_name=identifier.encode('utf-8'))
                certificate_model = CertificateModel.save_certificate(certificate)
                association = UserClientCertificate.objects.create(
                    user=user, certificate=certificate_model, identifier=identifier, is_active=True,
                )
        except ValidationError as exc:
            form.add_error(None, exc)
        except IntegrityError:
            if UserClientCertificate.objects.filter(user=self.request.user, identifier=identifier).exists():
                form.add_error('identifier', _('You already have a client certificate with this identifier.'))
            else:
                form.add_error(None, _('The client certificate could not be created.'))
        except CommandError as exc:
            form.add_error(None, str(exc))
        except (CryptoError, ValueError, RuntimeError):
            form.add_error(
                None, _('The client certificate could not be created. Check the management CA configuration.'),
            )
        else:
            response = FileResponse(
                BytesIO(pkcs12_data), as_attachment=True,
                filename=f'trustpoint-client-certificate-{user.pk}-{association.pk}.p12',
                content_type=CredentialFileFormat.PKCS12.mime_type,
            )
            response['Cache-Control'] = 'private, no-store'
            response['X-Content-Type-Options'] = 'nosniff'
            return cast('HttpResponse', response)
        return self.form_invalid(form)


class UserProfileClientCertificateActionView(UserProfileMixin, View):
    """Enable, disable, or delete a certificate belonging to the current user."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest, pk: int, action: str) -> HttpResponse:
        """Apply an explicit action after checking ownership on the server."""
        if action not in {'enable', 'disable', 'delete'}:
            raise Http404
        with transaction.atomic():
            association = get_object_or_404(
                UserClientCertificate.objects.select_for_update(), pk=pk, user=request.user,
            )
            if action == 'delete':
                certificate = association.certificate
                association.delete()
                try:
                    with transaction.atomic():
                        certificate.delete()
                except ProtectedError:
                    # Keep public certificates that are still referenced elsewhere in the PKI.
                    pass
            else:
                association.is_active = action == 'enable'
                association.save(update_fields=['is_active'])
        success_messages = {
            'enable': _('Client certificate enabled.'),
            'disable': _('Client certificate disabled.'),
            'delete': _('Client certificate deleted.'),
        }
        messages.success(request, success_messages[action])
        return redirect('users:profile_certificate_authentication')


class UserProfileDetailsView(UserProfileMixin, UpdateView[TrustpointUser, TrustpointUserDetailsForm]):
    """Allow a user to edit only their own name and email address."""

    form_class = TrustpointUserDetailsForm
    page_title = _('Details')

    def get_object(self, queryset: QuerySet[TrustpointUser] | None = None) -> TrustpointUser:
        """Ignore supplied user IDs and always load the authenticated user."""
        if queryset is None:
            queryset = TrustpointUser.objects.all()
        return get_object_or_404(queryset, pk=self.request.user.pk)

    def form_valid(self, form: TrustpointUserDetailsForm) -> HttpResponse:
        """Save the current user's personal details."""
        response = super().form_valid(form)
        messages.success(self.request, _('Your details have been saved.'))
        return response


class UserProfileRoleView(UserProfileMixin, TemplateView):
    """Show the current user's assigned role and organization without allowing self-promotion."""

    template_name = 'users/profile_role.html'


class UserProfilePasswordChangeView(UserProfileMixin, PasswordChangeView):
    """Change only the signed-in user's password, requiring their current password."""

    page_title = _('Change Password')

    def get_form(self, form_class: type[PasswordChangeForm] | None = None) -> PasswordChangeForm:
        """Hide password requirements help text to match the original form."""
        form = super().get_form(form_class)
        form.fields['new_password1'].help_text = ''
        return form

    def form_valid(self, form: PasswordChangeForm) -> HttpResponse:
        """Save the password and keep the current session authenticated."""
        response = super().form_valid(form)
        messages.success(self.request, _('Your password has been changed.'))
        return response


class UserProfileResetOTPView(UserProfileMixin, View):
    """Reset only the signed-in user's authenticator and recovery codes."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Remove the current user's authenticator while holding their user row lock."""
        with transaction.atomic():
            user = get_object_or_404(TrustpointUser.objects.select_for_update(), pk=request.user.pk)
            device = UserOTPDevice.objects.select_for_update().filter(user=user).first()
            if device is not None:
                device.delete()
        messages.success(request, _('Your authenticator has been reset. Set it up again when signing in.'))
        return redirect('users:profile')


class TrustpointLoginView(LoginView):
    """Login view for the trustpoint application."""

    http_method_names = ('get', 'post')

    def form_valid(self, form: AuthenticationForm) -> HttpResponse:
        """Finish password login only when the configured OTP requirement is satisfied."""
        user = form.get_user()
        if user.account_type != 'HUMAN':
            form.add_error(None, _('Service accounts cannot sign in to the web interface.'))
            return self.form_invalid(form)
        if PasswordPolicy.is_otp_required():
            return begin_otp_login(self.request, user, self.get_success_url())
        self.request.session.pop(PENDING_OTP_SESSION_KEY, None)
        self.request.session.pop(DEVICE_ID_SESSION_KEY, None)
        return super().form_valid(form)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add context about initial bootstrap login if applicable."""
        context = super().get_context_data(**kwargs)
        context['certificate_login_error'] = self.request.session.pop(CERTIFICATE_LOGIN_ERROR_SESSION_KEY, None)

        username = getattr(settings, 'TRUSTPOINT_BOOTSTRAP_USERNAME', 'admin')
        user_model = get_user_model()

        try:
            setup_completed = SetupWizardCompletedModel.setup_wizard_completed()
            if not setup_completed:
                bootstrap_user = user_model.objects.get(username=username)
                if bootstrap_user.last_login is None:
                    context['show_bootstrap_hint'] = True
                    context['bootstrap_username'] = username
        except (user_model.DoesNotExist, DatabaseError):
            pass

        return context

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Redirects to the appropriate startup wizard section if the setup wizard is not completed.

        Args:
            request: The django request object.
            *args: All positional arguments are passed to super().get().
            **kwargs: All keyword arguments are passed to super().get().

        Returns:
            The HttpResponse object, which may be a redirect.
        """
        self.request.session.pop(PENDING_OTP_SESSION_KEY, None)
        for _message in messages.get_messages(self.request):
            pass

        return super().get(request, *args, **kwargs)


    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Redirects to the appropriate startup wizard section if the setup wizard is not completed.

        Args:
            request: The django request object.
            *args: All positional arguments are passed to super().post().
            **kwargs: All keyword arguments are passed to super().post().

        Returns:
            The HttpResponse object, which may be a redirect.
        """
        self.request.session.pop(PENDING_OTP_SESSION_KEY, None)
        for _message in messages.get_messages(self.request):
            pass

        return super().post(request, *args, **kwargs)


PENDING_OTP_SESSION_KEY = 'pending_password_otp'
OTP_LOGIN_TIMEOUT = 300


class OTPTokenForm(forms.Form):
    """Accept an authenticator code or a single-use recovery code."""

    token = forms.CharField(
        label=_('Verification code'), max_length=MAX_TOKEN_LENGTH,
        widget=forms.TextInput(attrs={'autocomplete': 'one-time-code', 'autofocus': True}),
    )


@sensitive_variables()
def begin_otp_login(request: HttpRequest, user: TrustpointUser, next_url: str) -> HttpResponse:
    """Keep password proof in a short-lived anonymous session until OTP succeeds."""
    with transaction.atomic():
        current_user = TrustpointUser.objects.select_for_update().get(pk=user.pk)
        if (
            not current_user.is_active or current_user.account_type != 'HUMAN'
            or not constant_time_compare(current_user.get_session_auth_hash(), user.get_session_auth_hash())
        ):
            return redirect('users:login')
        device, created = UserOTPDevice.objects.select_for_update().get_or_create(user=current_user)
        if not created and not device.confirmed:
            # A new password login supersedes abandoned enrollment, without resetting throttling.
            device.key = new_otp_key()
            device.last_t = -1
            device.save(update_fields=['key', 'last_t'])
        rejected_certificate = request.session.get(REJECTED_CERTIFICATE_SESSION_KEY)
        request.session.flush()
        if rejected_certificate:
            request.session[REJECTED_CERTIFICATE_SESSION_KEY] = rejected_certificate
        request.session[PENDING_OTP_SESSION_KEY] = {
            'user_id': user.pk,
            'backend': user.backend,
            'auth_hash': user.get_session_auth_hash(),
            'issued_at': time.time(),
            'next': next_url,
            'device_id': device.pk,
            'key_hash': hashlib.sha256(device.key.encode('ascii')).hexdigest(),
            'enrolling': not device.confirmed,
        }
    return redirect('users:otp')


@method_decorator(never_cache, name='dispatch')
@method_decorator(csrf_protect, name='dispatch')
@method_decorator(sensitive_post_parameters('token'), name='dispatch')
class OTPLoginView(FormView[OTPTokenForm]):
    """Confirm a new authenticator or verify an existing one before logging in."""

    form_class = OTPTokenForm
    template_name = 'users/otp.html'
    http_method_names = ('get', 'post')

    @sensitive_variables()
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Validate password proof and lock the user and device for the entire OTP operation."""
        self.pending = request.session.get(PENDING_OTP_SESSION_KEY)
        if (
            not PasswordPolicy.is_otp_required() or not self.pending
            or not 0 <= time.time() - self.pending['issued_at'] < OTP_LOGIN_TIMEOUT
            or self.pending['backend'] not in settings.AUTHENTICATION_BACKENDS
        ):
            return self.restart_login()
        with transaction.atomic():
            self.user = TrustpointUser.objects.select_for_update().filter(
                pk=self.pending['user_id'], is_active=True, account_type='HUMAN',
            ).first()
            if self.user is None or not constant_time_compare(
                self.user.get_session_auth_hash(), self.pending['auth_hash'],
            ):
                return self.restart_login()
            self.device = UserOTPDevice.objects.select_for_update().filter(
                pk=self.pending['device_id'], user=self.user, confirmed=not self.pending['enrolling'],
            ).first()
            if self.device is None or not constant_time_compare(
                hashlib.sha256(self.device.key.encode('ascii')).hexdigest(), self.pending['key_hash'],
            ):
                return self.restart_login()
            return super().dispatch(request, *args, **kwargs)

    def restart_login(self) -> HttpResponse:
        """Discard expired or superseded password proof."""
        self.request.session.pop(PENDING_OTP_SESSION_KEY, None)
        return redirect('users:login')

    @sensitive_variables()
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Create a QR code only for the current password-verified enrollment session."""
        context = super().get_context_data(**kwargs)
        context['enrolling'] = self.pending['enrolling']
        if self.pending['enrolling']:
            label = quote(f'Trustpoint:{self.user.get_username()}', safe='')
            params = urlencode({
                'secret': base64.b32encode(bytes.fromhex(self.device.key)).decode('ascii'),
                'issuer': 'Trustpoint',
                'algorithm': 'SHA1',
                'digits': 6,
                'period': 30,
            })
            image = BytesIO()
            write_qrcode_image(f'otpauth://totp/{label}?{params}', image)
            context['qr_code_url'] = 'data:image/svg+xml;base64,' + base64.b64encode(image.getvalue()).decode('ascii')
        return context

    @sensitive_variables()
    def form_valid(self, form: OTPTokenForm) -> HttpResponse:
        """Consume the code, confirm enrollment if needed, and establish the authenticated session."""
        if not self.device.verify_token(form.cleaned_data['token']):
            form.add_error('token', _('Invalid or already used code. Wait briefly, then try a new code.'))
            return self.form_invalid(form)

        recovery_codes = None
        if self.pending['enrolling']:
            self.device.confirmed = True
            self.device.save(update_fields=['confirmed'])
            recovery_codes = self.device.generate_recovery_codes()

        next_url = self.pending['next']
        if not url_has_allowed_host_and_scheme(
            next_url, allowed_hosts={self.request.get_host()}, require_https=self.request.is_secure(),
        ):
            next_url = resolve_url(settings.LOGIN_REDIRECT_URL)
        self.request.session.pop(PENDING_OTP_SESSION_KEY, None)
        login(self.request, self.user, backend=self.pending['backend'])
        otp_login(self.request, self.device)
        if recovery_codes is not None:
            # Render once: plaintext recovery codes are never stored in the session or database.
            return render(self.request, 'users/otp_recovery_codes.html', {
                'recovery_codes': recovery_codes, 'next_url': next_url,
            })
        return redirect(next_url)
