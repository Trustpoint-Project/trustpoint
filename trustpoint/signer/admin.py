"""Admin configuration for Signer app."""

from django.contrib import admin

from signer.models import SignedMessageModel, SignerModel


class SignerAdmin(admin.ModelAdmin[SignerModel]):
    """Admin interface for SignerModel."""

    list_display = ('unique_name', 'is_active', 'created_at', 'updated_at')
    list_filter = ('is_active', 'created_at', 'updated_at')
    search_fields = ('unique_name',)
    readonly_fields = ('created_at', 'updated_at')


class SignedMessageAdmin(admin.ModelAdmin[SignedMessageModel]):
    """Admin interface for SignedMessageModel."""

    list_display = ('signer', 'hash_value', 'created_at')
    list_filter = ('signer', 'created_at')
    search_fields = ('signer__unique_name', 'hash_value')
    readonly_fields = ('signer_public_bytes', 'created_at')


admin.site.register(SignerModel, SignerAdmin)
admin.site.register(SignedMessageModel, SignedMessageAdmin)
