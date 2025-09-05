# devices/filters.py
import django_filters
from django import forms
from django.utils.translation import gettext_lazy as _
from pki.models import DomainModel

from devices.models import DeviceModel


class DeviceFilter(django_filters.FilterSet):
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


    class Meta:
        model = DeviceModel
        fields = [
            'common_name',
            'domain',
            'serial_number',
        ]
