# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for the users application."""

from __future__ import annotations

import base64
import hashlib
import time
from io import BytesIO
from typing import TYPE_CHECKING
from urllib.parse import quote, urlencode

from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.views import LoginView
from django.db import DatabaseError, transaction
from django.shortcuts import redirect, render, resolve_url
from django.utils.crypto import constant_time_compare
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.generic.edit import FormView
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp import login as otp_login
from django_otp.qr import write_qrcode_image

from management.models import PasswordPolicy
from setup_wizard.models import SetupWizardCompletedModel
from users.models import MAX_TOKEN_LENGTH, TrustpointUser, UserOTPDevice, new_otp_key

if TYPE_CHECKING:
    from typing import Any

    from django.contrib.auth.forms import AuthenticationForm
    from django.http import HttpRequest, HttpResponse


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
        request.session.flush()
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
