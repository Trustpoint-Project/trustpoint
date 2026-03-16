"""PKI filters."""
import django_filters
from django import forms
from django.utils.translation import gettext_lazy as _

from pki.models.truststore import TruststoreModel


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
