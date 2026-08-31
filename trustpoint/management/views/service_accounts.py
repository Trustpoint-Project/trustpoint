# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Service account management views."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView

from users.models import Role, ServiceAccountCredential, TrustpointUser

if TYPE_CHECKING:
    from typing import Any

    from django.db.models import QuerySet
    from django.http import HttpRequest, HttpResponse


class ServiceAccountListView(LoginRequiredMixin, PermissionRequiredMixin, ListView[TrustpointUser]):
    """List all service accounts."""

    model = TrustpointUser
    template_name = 'management/service_accounts/service_account_list.html'
    context_object_name = 'service_accounts'
    permission_required = 'users.view_trustpointuser'
    paginate_by = 50

    def get_queryset(self) -> QuerySet[TrustpointUser]:
        """Return only service accounts."""
        return TrustpointUser.objects.filter(
            account_type=TrustpointUser.AccountType.SERVICE
        ).select_related('role', 'organization').prefetch_related('service_credentials').order_by('-date_joined')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add page context."""
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'management'
        context['page_name'] = 'service_accounts'
        return context


class ServiceAccountDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView[TrustpointUser]):
    """View service account details and credentials."""

    model = TrustpointUser
    template_name = 'management/service_accounts/service_account_detail.html'
    context_object_name = 'service_account'
    permission_required = 'users.view_trustpointuser'

    def get_queryset(self) -> QuerySet[TrustpointUser]:
        """Return only service accounts."""
        return TrustpointUser.objects.filter(
            account_type=TrustpointUser.AccountType.SERVICE
        ).prefetch_related('service_credentials')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add credentials and page context."""
        context = super().get_context_data(**kwargs)
        context['credentials'] = self.object.service_credentials.all().order_by('-created_at')
        context['page_category'] = 'management'
        context['page_name'] = 'service_accounts'
        return context


class ServiceAccountCreateView(
    LoginRequiredMixin,
    PermissionRequiredMixin,
    CreateView[TrustpointUser, forms.ModelForm[TrustpointUser]]
):
    """Create a new service account with API credentials."""

    model = TrustpointUser
    template_name = 'management/service_accounts/service_account_create.html'
    permission_required = 'users.add_trustpointuser'
    fields = ['username', 'organization']  # noqa: RUF012

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the fixed service role and page context."""
        context = super().get_context_data(**kwargs)
        context['default_service_role'] = Role.get_service_group()
        context['page_category'] = 'management'
        context['page_name'] = 'service_accounts'
        return context

    @transaction.atomic
    def form_valid(self, form: Any) -> HttpResponse:
        """Create service account and generate API credentials."""
        # Create the service account
        service_account = form.save(commit=False)
        service_account.account_type = TrustpointUser.AccountType.SERVICE
        service_account.role = Role.get_service_group()
        service_account.set_unusable_password()
        service_account.save()

        # Generate API credentials
        client_id = ServiceAccountCredential.generate_client_id()
        secret = ServiceAccountCredential.generate_secret()
        hashed_secret = make_password(secret)

        ServiceAccountCredential.objects.create(
            service_account=service_account,
            client_id=client_id,
            hashed_secret=hashed_secret,
            description=f'API key for {service_account.username}',
        )

        # Store the plaintext secret in session for display (one-time only)
        self.request.session['new_service_account'] = {
            'pk': service_account.pk,
            'username': service_account.username,
            'client_id': client_id,
            'secret': secret,
        }

        messages.success(
            self.request,
            f'Service account "{service_account.username}" created successfully!'
        )

        return redirect(reverse('management:service_account_created'))

    def get_success_url(self) -> str:
        """Redirect to credential display page."""
        return reverse('management:service_account_created')


@login_required
@permission_required('users.view_trustpointuser', raise_exception=True)
def service_account_created_view(request: HttpRequest) -> HttpResponse:
    """Display newly created service account credentials (one-time view)."""
    credentials = request.session.pop('new_service_account', None)

    if not credentials:
        messages.warning(request, 'No new service account credentials to display.')
        return redirect(reverse('management:service_account_list'))

    # Get the service account object
    service_account = get_object_or_404(TrustpointUser, pk=credentials['pk'])

    return render(request, 'management/service_accounts/service_account_created.html', {
        'service_account': service_account,
        'client_id': credentials['client_id'],
        'secret': credentials['secret'],
        'page_category': 'management',
        'page_name': 'service_accounts',
    })


@login_required
@permission_required('users.change_serviceaccountcredential', raise_exception=True)
def revoke_credential_view(request: HttpRequest, pk: int) -> HttpResponse:
    """Revoke a service account credential."""
    credential = get_object_or_404(ServiceAccountCredential, pk=pk)

    if request.method == 'POST':
        credential.is_active = False
        credential.save()

        messages.success(
            request,
            f'Credential {credential.client_id} has been revoked.'
        )
        return redirect(reverse('management:service_account_detail', kwargs={'pk': credential.service_account.pk}))

    return render(request, 'management/service_accounts/revoke_credential_confirm.html', {
        'credential': credential,
        'page_category': 'management',
        'page_name': 'service_accounts',
    })


@login_required
@permission_required('users.add_serviceaccountcredential', raise_exception=True)
@transaction.atomic
def generate_credential_view(request: HttpRequest, pk: int) -> HttpResponse:
    """Generate a new credential for an existing service account."""
    service_account = get_object_or_404(
        TrustpointUser.objects.filter(account_type=TrustpointUser.AccountType.SERVICE),
        pk=pk
    )

    # Generate new API credentials
    client_id = ServiceAccountCredential.generate_client_id()
    secret = ServiceAccountCredential.generate_secret()
    hashed_secret = make_password(secret)

    ServiceAccountCredential.objects.create(
        service_account=service_account,
        client_id=client_id,
        hashed_secret=hashed_secret,
        description=f'Additional API key for {service_account.username}',
    )

    # Store the plaintext secret in session for display (one-time only)
    request.session['new_service_account'] = {
        'pk': service_account.pk,
        'username': service_account.username,
        'client_id': client_id,
        'secret': secret,
    }

    messages.success(
        request,
        f'New credential generated for service account "{service_account.username}"!'
    )

    return redirect(reverse('management:service_account_created'))


class ServiceAccountDeleteView(LoginRequiredMixin, PermissionRequiredMixin, DeleteView[TrustpointUser, forms.Form]):
    """Delete a service account."""

    model = TrustpointUser
    template_name = 'management/service_accounts/delete_service_account_confirm.html'
    success_url = reverse_lazy('management:service_account_list')
    permission_required = 'users.delete_trustpointuser'
    context_object_name = 'service_account'

    def get_queryset(self) -> QuerySet[TrustpointUser]:
        """Return only service accounts."""
        return TrustpointUser.objects.filter(
            account_type=TrustpointUser.AccountType.SERVICE
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add page context."""
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'management'
        context['page_name'] = 'service_accounts'
        return context

    def form_valid(self, form: Any) -> HttpResponse:
        """Delete the service account and show success message."""
        self.object = self.get_object()
        username = self.object.username

        messages.success(
            self.request,
            f'Service account "{username}" deleted successfully.'
        )
        return super().form_valid(form)
