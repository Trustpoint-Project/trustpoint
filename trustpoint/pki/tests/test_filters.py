"""Tests for pki.filters module."""

import pytest
from django.test import RequestFactory

from pki.filters import TruststoreFilter
from pki.models.truststore import TruststoreModel


@pytest.mark.django_db
class TestTruststoreFilter:
    """Test the TruststoreFilter class."""

    @pytest.fixture
    def truststore_instances(self):
        """Create test truststore instances."""
        # Create truststores with different intended usages
        ts1 = TruststoreModel.objects.create(
            unique_name='test_truststore_1',
            intended_usage=TruststoreModel.IntendedUsage.TLS
        )
        ts2 = TruststoreModel.objects.create(
            unique_name='test_truststore_2',
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        )
        ts3 = TruststoreModel.objects.create(
            unique_name='another_truststore',
            intended_usage=TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
        )
        return [ts1, ts2, ts3]

    def test_filter_by_unique_name_exact_match(self, truststore_instances):
        """Test filtering by exact unique name."""
        request_factory = RequestFactory()
        request = request_factory.get('/?unique_name=test_truststore_1')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 1
        assert filterset.qs.first().unique_name == 'test_truststore_1'

    def test_filter_by_unique_name_icontains(self, truststore_instances):
        """Test case-insensitive substring filtering by unique name."""
        request_factory = RequestFactory()
        request = request_factory.get('/?unique_name=test')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 2
        unique_names = [ts.unique_name for ts in filterset.qs]
        assert 'test_truststore_1' in unique_names
        assert 'test_truststore_2' in unique_names

    def test_filter_by_unique_name_case_insensitive(self, truststore_instances):
        """Test that unique_name filtering is case-insensitive."""
        request_factory = RequestFactory()
        request = request_factory.get('/?unique_name=TEST')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 2

    def test_filter_by_intended_usage(self, truststore_instances):
        """Test filtering by intended usage."""
        request_factory = RequestFactory()
        request = request_factory.get(f'/?intended_usage={TruststoreModel.IntendedUsage.TLS}')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 1
        assert filterset.qs.first().intended_usage == TruststoreModel.IntendedUsage.TLS

    def test_filter_by_issuing_ca_chain_usage(self, truststore_instances):
        """Test filtering by ISSUING_CA_CHAIN intended usage."""
        request_factory = RequestFactory()
        request = request_factory.get(f'/?intended_usage={TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN}')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 1
        assert filterset.qs.first().intended_usage == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
        assert filterset.qs.first().unique_name == 'another_truststore'

    def test_combined_filters(self, truststore_instances):
        """Test combining unique_name and intended_usage filters."""
        request_factory = RequestFactory()
        request = request_factory.get(f'/?unique_name=another&intended_usage={TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN}')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 1
        assert filterset.qs.first().unique_name == 'another_truststore'
        assert filterset.qs.first().intended_usage == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN

    def test_combined_filters_no_match(self, truststore_instances):
        """Test combining filters that don't match anything."""
        request_factory = RequestFactory()
        request = request_factory.get(f'/?unique_name=test&intended_usage={TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN}')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 0

    def test_no_filters(self, truststore_instances):
        """Test that no filters returns all truststores."""
        request_factory = RequestFactory()
        request = request_factory.get('/')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 3

    def test_empty_filters(self, truststore_instances):
        """Test that empty filter values don't filter anything."""
        request_factory = RequestFactory()
        request = request_factory.get('/?unique_name=&intended_usage=')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 3

    def test_filter_form_attributes(self, truststore_instances):
        """Test that form widgets have correct CSS classes."""
        filterset = TruststoreFilter(queryset=TruststoreModel.objects.all())
        
        # Check that unique_name field has the correct widget class
        assert 'form-control' in filterset.form.fields['unique_name'].widget.attrs['class']
        
        # Check that intended_usage field has the correct widget class
        assert 'form-select' in filterset.form.fields['intended_usage'].widget.attrs['class']
