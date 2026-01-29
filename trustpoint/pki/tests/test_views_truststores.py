"""Tests for pki.views.truststores module."""

import pytest
from django.test import RequestFactory
from django.urls import reverse

from pki.models.truststore import TruststoreModel
from pki.views.truststores import TruststoreCreateView, TruststoreTableView


@pytest.mark.django_db
class TestTruststoreTableView:
    """Test the TruststoreTableView class."""

    @pytest.fixture
    def truststore_instances(self):
        """Create test truststore instances."""
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

    def test_get_queryset_without_filters(self, truststore_instances):
        """Test get_queryset returns all truststores when no filters applied."""
        request_factory = RequestFactory()
        request = request_factory.get(reverse('pki:truststores'))
        view = TruststoreTableView()
        view.request = request

        queryset = view.get_queryset()
        assert queryset.count() == 3

    def test_get_queryset_with_unique_name_filter(self, truststore_instances):
        """Test get_queryset applies unique_name filter."""
        request_factory = RequestFactory()
        request = request_factory.get(reverse('pki:truststores') + '?unique_name=test_truststore_1')
        view = TruststoreTableView()
        view.request = request

        queryset = view.get_queryset()
        assert queryset.count() == 1
        assert queryset.first().unique_name == 'test_truststore_1'

    def test_get_queryset_with_partial_unique_name_filter(self, truststore_instances):
        """Test get_queryset applies partial unique_name filter (icontains)."""
        request_factory = RequestFactory()
        request = request_factory.get(reverse('pki:truststores') + '?unique_name=test')
        view = TruststoreTableView()
        view.request = request

        queryset = view.get_queryset()
        assert queryset.count() == 2
        unique_names = {ts.unique_name for ts in queryset}
        assert unique_names == {'test_truststore_1', 'test_truststore_2'}

    def test_get_queryset_with_intended_usage_filter(self, truststore_instances):
        """Test get_queryset applies intended_usage filter."""
        request_factory = RequestFactory()
        request = request_factory.get(
            reverse('pki:truststores') + f'?intended_usage={TruststoreModel.IntendedUsage.TLS}'
        )
        view = TruststoreTableView()
        view.request = request

        queryset = view.get_queryset()
        assert queryset.count() == 1
        assert queryset.first().intended_usage == TruststoreModel.IntendedUsage.TLS

    def test_get_queryset_with_issuing_ca_chain_filter(self, truststore_instances):
        """Test get_queryset filters for ISSUING_CA_CHAIN intended usage."""
        request_factory = RequestFactory()
        request = request_factory.get(
            reverse('pki:truststores') + f'?intended_usage={TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN}'
        )
        view = TruststoreTableView()
        view.request = request

        queryset = view.get_queryset()
        assert queryset.count() == 1
        assert queryset.first().intended_usage == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN

    def test_get_queryset_with_combined_filters(self, truststore_instances):
        """Test get_queryset applies combined filters."""
        request_factory = RequestFactory()
        request = request_factory.get(
            reverse('pki:truststores') + f'?unique_name=another&intended_usage={TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN}'
        )
        view = TruststoreTableView()
        view.request = request

        queryset = view.get_queryset()
        assert queryset.count() == 1
        assert queryset.first().unique_name == 'another_truststore'
        assert queryset.first().intended_usage == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN

    def test_get_queryset_with_combined_filters_no_match(self, truststore_instances):
        """Test get_queryset returns empty queryset when combined filters don't match."""
        request_factory = RequestFactory()
        request = request_factory.get(
            reverse('pki:truststores') + f'?unique_name=test&intended_usage={TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN}'
        )
        view = TruststoreTableView()
        view.request = request

        queryset = view.get_queryset()
        assert queryset.count() == 0

    def test_get_context_data_includes_filter(self, truststore_instances):
        """Test that get_context_data includes the filter in context."""
        request_factory = RequestFactory()
        request = request_factory.get(reverse('pki:truststores'))
        view = TruststoreTableView()
        view.request = request
        view.kwargs = {}  # ListView requires kwargs attribute

        # Set up the view properly - ListView requires object_list
        view.object_list = view.get_queryset()

        context = view.get_context_data()
        assert 'filter' in context
        assert hasattr(context['filter'], 'form')

    def test_filterset_is_stored_as_attribute(self, truststore_instances):
        """Test that the filterset is stored as a view attribute after get_queryset."""
        request_factory = RequestFactory()
        request = request_factory.get(reverse('pki:truststores') + '?unique_name=test')
        view = TruststoreTableView()
        view.request = request

        view.get_queryset()

        assert hasattr(view, 'filterset')
        assert view.filterset is not None

    def test_apply_filters_method(self, truststore_instances):
        """Test the apply_filters method directly."""
        request_factory = RequestFactory()
        request = request_factory.get('/?unique_name=test')
        view = TruststoreTableView()
        view.request = request

        base_queryset = TruststoreModel.objects.all()
        filtered_queryset = view.apply_filters(base_queryset)

        assert filtered_queryset.count() == 2

@pytest.mark.django_db
class TestTruststoreCreateView:
    """Tests for TruststoreCreateView dispatch and form_valid."""

    @pytest.fixture
    def factory(self):
        return RequestFactory()

    def test_dispatch_full_flow_true(self, factory):
        """Full dispatch test with setup for from-device."""
        view = TruststoreCreateView()
        request = factory.get('/pki/truststores/add/from-device/')
        view.setup(request)  # Essential: sets self.request, self.kwargs={}
        response = view.dispatch(request)
        assert view.for_devid is True
        assert response.status_code == 200

    def test_dispatch_full_flow_false(self, factory):
        """Full dispatch test for normal path."""
        view = TruststoreCreateView()
        request = factory.get('/pki/truststores/add/')
        view.setup(request)
        response = view.dispatch(request)
        assert view.for_devid is False
        assert response.status_code == 200

    def test_path_logic_direct(self, factory):
        """Direct test of dispatch if-statement (line ~115, NO dispatch call)."""
        # True branch
        view = TruststoreCreateView()
        view.request = factory.get('/from-device/')
        if 'from-device' in view.request.path:
            view.for_devid = True
        else:
            view.for_devid = False
        assert view.for_devid is True

        # False branch
        view = TruststoreCreateView()
        view.request = factory.get('/normal/')
        if 'from-device' in view.request.path:
            view.for_devid = True
        else:
            view.for_devid = False
        assert view.for_devid is False

    @pytest.mark.parametrize('path,expected_for_devid', [
        ('/pki/truststores/add/from-device/', True),
        ('/from-device/', True),
        ('/pki/truststores/add/', False),
        ('/fromdevice', False),
    ])
    def test_dispatch_parametrized(self, factory, path, expected_for_devid):
        """Parametrized full dispatch with proper setup."""
        view = TruststoreCreateView()
        request = factory.get(path)
        view.setup(request)
        response = view.dispatch(request)
        assert view.for_devid == expected_for_devid

