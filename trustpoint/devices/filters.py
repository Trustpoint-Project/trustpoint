"""Devices filters.

Defines the `DeviceFilter` used to filter the devices list view.
"""
import django_filters
from django import forms
from django.db.models import QuerySet
from django.utils.translation import gettext_lazy as _

from devices.dashboard_filters import (
    filter_devices_with_active_application_certificates,
    filter_devices_with_expired_or_revoked_application_certificates,
    filter_devices_with_expired_or_revoked_domain_credential,
    filter_devices_with_expiring_domain_credential,
    filter_devices_with_valid_domain_credential,
    filter_devices_without_application_certificates,
    filter_devices_without_domain_credential,
    filter_expired_or_revoked_devices,
    filter_no_onboarding_devices,
    filter_onboarded_devices,
    filter_pending_devices,
)
from devices.models import DeviceModel
from pki.models import DomainModel


class DeviceFilter(django_filters.FilterSet):
    """FilterSet for the devices list page."""
    common_name = django_filters.CharFilter(
        label='Device',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-sm',
            'placeholder': _('Search…')
        })
    )
    domain = django_filters.ModelChoiceFilter(
        queryset=DomainModel.objects.all(),
        label='Domain',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'})
    )
    serial_number = django_filters.CharFilter(
        label='Serial',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-sm',
            'placeholder': _('Serial…')
        })
    )
    created_at_from = django_filters.DateFilter(
        field_name='created_at',
        label=_('Created from'),
        lookup_expr='date__gte',
        widget=forms.DateInput(attrs={
            'class': 'form-control form-control-sm',
            'type': 'date',
        })
    )
    created_at_to = django_filters.DateFilter(
        field_name='created_at',
        label=_('Created to'),
        lookup_expr='date__lte',
        widget=forms.DateInput(attrs={
            'class': 'form-control form-control-sm',
            'type': 'date',
        })
    )
    enrollment_state = django_filters.ChoiceFilter(
        label=_('Enrollment'),
        choices=(
            ('no_onboarding', _('No onboarding')),
            ('pending', _('Pending')),
            ('onboarded', _('Onboarded')),
        ),
        method='filter_enrollment_state',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'})
    )
    domain_credential_state = django_filters.ChoiceFilter(
        label=_('Domain credential'),
        choices=(
            ('none', _('None')),
            ('valid', _('Valid')),
            ('expiring', _('Expiring')),
            ('expired', _('Expired')),
        ),
        method='filter_domain_credential_state',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'})
    )
    application_certificate_state = django_filters.ChoiceFilter(
        label=_('Application certificates'),
        choices=(
            ('none', _('None')),
            ('active', _('Active')),
            ('expired', _('Expired')),
        ),
        method='filter_application_certificate_state',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'})
    )
    expired_device = django_filters.CharFilter(
        method='filter_expired_device',
        widget=forms.HiddenInput(),
    )

    def filter_enrollment_state(self, queryset: QuerySet[DeviceModel], name: str, value: str) -> QuerySet[DeviceModel]:
        """Filter devices by enrollment state."""
        del name

        if value == 'no_onboarding':
            return filter_no_onboarding_devices(queryset)
        if value == 'pending':
            return filter_pending_devices(queryset)
        if value == 'onboarded':
            return filter_onboarded_devices(queryset)
        return queryset

    def filter_domain_credential_state(
        self,
        queryset: QuerySet[DeviceModel],
        name: str,
        value: str,
    ) -> QuerySet[DeviceModel]:
        """Filter devices by domain-credential state."""
        del name

        if value == 'none':
            return filter_devices_without_domain_credential(queryset)
        if value == 'valid':
            return filter_devices_with_valid_domain_credential(queryset)
        if value == 'expiring':
            return filter_devices_with_expiring_domain_credential(queryset)
        if value == 'expired':
            return filter_devices_with_expired_or_revoked_domain_credential(queryset)
        return queryset

    def filter_application_certificate_state(
        self,
        queryset: QuerySet[DeviceModel],
        name: str,
        value: str,
    ) -> QuerySet[DeviceModel]:
        """Filter devices by application-certificate state."""
        del name

        if value == 'none':
            return filter_devices_without_application_certificates(queryset)
        if value == 'active':
            return filter_devices_with_active_application_certificates(queryset)
        if value == 'expired':
            return filter_devices_with_expired_or_revoked_application_certificates(queryset)
        return queryset

    def filter_expired_device(
        self,
        queryset: QuerySet[DeviceModel],
        name: str,
        value: str,
    ) -> QuerySet[DeviceModel]:
        """Filter devices using the dashboard's composite expired-or-revoked semantics."""
        del name

        if value:
            return filter_expired_or_revoked_devices(queryset)
        return queryset

    class Meta:
        """Meta class configuration."""

        model = DeviceModel
        fields = (
            'common_name',
            'domain',
            'serial_number',
            'created_at_from',
            'created_at_to',
            'enrollment_state',
            'domain_credential_state',
            'application_certificate_state',
        )
