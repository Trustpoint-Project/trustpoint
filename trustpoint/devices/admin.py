"""Registrations for Django Admin."""

from django.contrib import admin

from .models import DeviceModel, IssuedCredentialModel


class DeviceModelAdmin(admin.ModelAdmin[DeviceModel]):
    """Registers the DeviceModel with Django Admin."""


class IssuedCredentialModelAdmin(admin.ModelAdmin[IssuedCredentialModel]):
    """Registers the IssuedCredentialModelAdmin with Django Admin."""


admin.site.register(DeviceModel, DeviceModelAdmin)
admin.site.register(IssuedCredentialModel, IssuedCredentialModelAdmin)
