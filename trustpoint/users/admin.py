"""Django admin configuration for the users app."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import TrustpointUser


@admin.register(TrustpointUser)
class TrustpointUserAdmin(UserAdmin[TrustpointUser]):
    """Admin view for TrustpointUser with role column in the list display."""

    # Append 'role' after the standard UserAdmin columns.
    list_display = (*UserAdmin.list_display, 'role')  # type: ignore[misc]

    # Add a Trustpoint fieldset so role is editable in the detail view.
    fieldsets = (
        *UserAdmin.fieldsets,  # type: ignore[misc]
        ('Trustpoint', {'fields': ('role',)}),
    )
