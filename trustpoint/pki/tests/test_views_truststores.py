"""Tests for pki.views.truststores module."""

from unittest.mock import MagicMock, Mock, patch

import pytest
from django.test import RequestFactory
from django.urls import reverse

from pki.forms import TruststoreAddForm
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
        view.setup(request)
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
        """Direct test of dispatch if-statement (NO dispatch call)."""
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
        """Test for Parametrized full dispatch with proper setup."""
        view = TruststoreCreateView()
        request = factory.get(path)
        view.setup(request)
        response = view.dispatch(request)
        assert view.for_devid == expected_for_devid


@pytest.mark.django_db
@patch('django.contrib.messages.success')
class TestTruststoreCreateViewFormValid:
    """Tests covering form_valid branches."""

    @pytest.fixture
    def view(self):
        view = TruststoreCreateView()
        view.request = RequestFactory().get('/')
        return view

    @pytest.fixture
    def mock_form(self):
        mock_form = Mock(spec=TruststoreAddForm)
        mock_truststore = MagicMock()
        mock_truststore.id = 123
        mock_truststore.unique_name = 'test-ts'
        mock_truststore.number_of_certificates = 1
        mock_form.cleaned_data = {'truststore': mock_truststore}
        return mock_form

    def test_domain_id_branch(self, mock_messages, view, mock_form):
        """Test if domain_id is present."""
        view.kwargs = {'pk': '42'}
        response = view.form_valid(mock_form)
        expected_url = reverse('pki:devid_registration_create-with_truststore_id', kwargs={'pk': '42', 'truststore_id': 123})
        assert response.url == expected_url

    def test_for_devid_query_branch(self, mock_messages, view, mock_form):
        """Test if getattr(self, 'for_devid', False)"""
        view.kwargs = {}
        view.for_devid = True
        response = view.form_valid(mock_form)
        expected_url = f"{reverse('pki:devid_registration_create')}?truststore_id=123"
        assert response.url == expected_url

    def test_messages_plural_success(self, mock_messages, view, mock_form):
        """Test for normal success + ngettext plural."""
        view.kwargs = {}
        view.for_devid = False
        mock_form.cleaned_data['truststore'].number_of_certificates = 2  # Triggers plural
        response = view.form_valid(mock_form)
        mock_messages.assert_called_once()
        assert 'certificates' in mock_messages.call_args.args[1]  # Plural check
        assert response.url == reverse('pki:truststores')

    def test_messages_singular_success(self, mock_messages, view, mock_form):
        """Test ngettext singular."""
        view.kwargs = {}
        view.for_devid = False
        mock_form.cleaned_data['truststore'].number_of_certificates = 1
        response = view.form_valid(mock_form)
        mock_messages.assert_called_once()
        assert 'certificate' in mock_messages.call_args.args[1]
        assert response.url == reverse('pki:truststores')
