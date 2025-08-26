"""Registrations for Django Admin."""

from django.contrib import admin

from .models import (
    DeviceModel,
    IssuedCredentialModel,
    NoOnboardingConfigModel,
    OnboardingConfigModel,
    RemoteDeviceCredentialDownloadModel,
)


class DeviceModelAdmin(admin.ModelAdmin[DeviceModel]):
    """Registers the DeviceModel with Django Admin."""


class IssuedCredentialModelAdmin(admin.ModelAdmin[IssuedCredentialModel]):
    """Registers the IssuedCredentialModelAdmin with Django Admin."""


class RemoteDeviceCredentialDownloadModelAdmin(admin.ModelAdmin[RemoteDeviceCredentialDownloadModel]):
    """Registers the RemoteDeviceCredentialDownloadModel with Django Admin."""


class NoOnboardingConfigModelAdmin(admin.ModelAdmin[NoOnboardingConfigModel]):
    """Registers the NoOnboardingConfigModelAdmin with Django Admin."""


class OnboardingConfigModelAdmin(admin.ModelAdmin[OnboardingConfigModel]):
    """Registers the OnboardingConfigModelAdmin with Django Admin."""


admin.site.register(DeviceModel, DeviceModelAdmin)
admin.site.register(IssuedCredentialModel, IssuedCredentialModelAdmin)
admin.site.register(RemoteDeviceCredentialDownloadModel, RemoteDeviceCredentialDownloadModelAdmin)
admin.site.register(NoOnboardingConfigModel, NoOnboardingConfigModelAdmin)
admin.site.register(OnboardingConfigModel, OnboardingConfigModelAdmin)
