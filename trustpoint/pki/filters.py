"""PKI filters."""
from datetime import timedelta

import django_filters
from django import forms
from django.db.models import QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from pki.models import CertificateModel
from pki.models.truststore import TruststoreModel


class CertificateFilter(django_filters.FilterSet):
    """FilterSet for the certificates list page."""

    common_name = django_filters.CharFilter(
        label='Certificate',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-sm',
            'placeholder': _('Search…')
        })
    )
    status = django_filters.ChoiceFilter(
        label=_('Status'),
        choices=(
            ('ok', _('OK')),
            ('expired', _('Expired')),
            ('revoked', _('Revoked')),
            ('not_yet_valid', _('Not Yet Valid')),
        ),
        method='filter_status',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'})
    )
    expiry_window = django_filters.ChoiceFilter(
        label=_('Expires In'),
        choices=(
            ('today', _('Today')),
            ('tomorrow', _('Tomorrow')),
            ('7_days', _('Within 7 Days')),
            ('30_days', _('Within 30 Days')),
            ('after_30_days', _('After 30 Days')),
        ),
        method='filter_expiry_window',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'})
    )
    is_self_signed = django_filters.ChoiceFilter(
        label=_('Self-Signed'),
        choices=(
            ('true', _('Yes')),
            ('false', _('No')),
        ),
        method='filter_is_self_signed',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'})
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

    def filter_status(
        self,
        queryset: QuerySet[CertificateModel],
        name: str,
        value: str,
    ) -> QuerySet[CertificateModel]:
        """Filter certificates by their current status."""
        del name

        now = timezone.now()

        if value == 'ok':
            return queryset.filter(
                revoked_certificate__isnull=True,
                not_valid_before__lte=now,
                not_valid_after__gt=now,
            )
        if value == 'expired':
            return queryset.filter(
                revoked_certificate__isnull=True,
                not_valid_after__lte=now,
            )
        if value == 'revoked':
            return queryset.filter(revoked_certificate__isnull=False)
        if value == 'not_yet_valid':
            return queryset.filter(
                revoked_certificate__isnull=True,
                not_valid_before__gt=now,
            )
        return queryset

    def filter_expiry_window(
        self,
        queryset: QuerySet[CertificateModel],
        name: str,
        value: str,
    ) -> QuerySet[CertificateModel]:
        """Filter certificates by expiry horizon."""
        del name

        now = timezone.now()
        next_1_day = now + timedelta(days=1)
        next_2_days = now + timedelta(days=2)
        next_7_days = now + timedelta(days=7)
        next_30_days = now + timedelta(days=30)

        base_queryset = queryset.filter(
            revoked_certificate__isnull=True,
            not_valid_before__lte=now,
            not_valid_after__gt=now,
        )

        if value == 'today':
            return base_queryset.filter(not_valid_after__lte=next_1_day)
        if value == 'tomorrow':
            return base_queryset.filter(
                not_valid_after__gt=next_1_day,
                not_valid_after__lte=next_2_days,
            )
        if value == '7_days':
            return base_queryset.filter(not_valid_after__lte=next_7_days)
        if value == '30_days':
            return base_queryset.filter(not_valid_after__lte=next_30_days)
        if value == 'after_30_days':
            return base_queryset.filter(not_valid_after__gt=next_30_days)
        return queryset

    def filter_is_self_signed(
        self,
        queryset: QuerySet[CertificateModel],
        name: str,
        value: str,
    ) -> QuerySet[CertificateModel]:
        """Filter certificates by self-signed flag."""
        del name

        if value == 'true':
            return queryset.filter(is_self_signed=True)
        if value == 'false':
            return queryset.filter(is_self_signed=False)
        return queryset

    class Meta:
        """Meta class configuration."""

        model = CertificateModel
        fields = (
            'common_name',
            'status',
            'expiry_window',
            'is_self_signed',
            'created_at_from',
            'created_at_to',
        )


class TruststoreFilter(django_filters.FilterSet):
    """FilterSet for the truststores list page.

    Exposes two fields:
      * unique_name: case-insensitive substring match
      * intended_usage: exact match via dropdown
    """
    unique_name = django_filters.CharFilter(
        label='Truststore',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-sm',
            'placeholder': _('Search…')
        })
    )
    intended_usage = django_filters.ChoiceFilter(
        choices=TruststoreModel.IntendedUsage.choices,
        label='Intended Usage',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'})
    )

    class Meta:
        """Meta class configuration."""

        model = TruststoreModel
        fields = ('unique_name', 'intended_usage')
