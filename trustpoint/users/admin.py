# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django admin configuration for the users app."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _

from .models import ServiceAccountCredential, TrustpointUser


@admin.register(TrustpointUser)
class TrustpointUserAdmin(UserAdmin[TrustpointUser]):
    """Admin view for TrustpointUser with role and account_type columns."""

    # Append 'role' and 'account_type' after the standard UserAdmin columns.
    list_display = (*UserAdmin.list_display, 'role', 'account_type')  # type: ignore[misc]
    list_filter = (*UserAdmin.list_filter, 'account_type')  # type: ignore[misc]

    # Add a Trustpoint fieldset so role and account_type are editable in the detail view.
    fieldsets = (
        *UserAdmin.fieldsets,  # type: ignore[misc]
        ('Trustpoint', {'fields': ('role', 'account_type', 'organization')}),
    )


@admin.register(ServiceAccountCredential)
class ServiceAccountCredentialAdmin(admin.ModelAdmin[ServiceAccountCredential]):
    """Admin interface for service account credentials."""

    list_display = ('client_id', 'service_account', 'is_active', 'created_at', 'expires_at', 'last_used')
    list_filter = ('is_active', 'created_at', 'expires_at')
    search_fields = ('client_id', 'service_account__username', 'description')
    readonly_fields = ('client_id', 'hashed_secret', 'created_at', 'last_used')
    fieldsets = (
        (None, {
            'fields': ('service_account', 'client_id', 'hashed_secret')
        }),
        (_('Status'), {
            'fields': ('is_active', 'created_at', 'expires_at', 'last_used')
        }),
        (_('Details'), {
            'fields': ('description',)
        }),
    )

    def has_add_permission(self, request: object) -> bool:  # noqa: ARG002
        """Disable adding credentials through admin (use management command instead)."""
        return False
