"""Tests for the SortableTableMixin class."""
from typing import Any

from devices.models import DeviceModel
from django.db.models import Model, QuerySet
from django.http import HttpRequest
from django.test import RequestFactory, TestCase

from trustpoint.views.base import SortableTableMixin


class SortableTableView(SortableTableMixin):
    """Simple view class inheriting from SortableTableMixin."""

    def __init__(self,
                 queryset: QuerySet[Any] | None = None,
                 model: type[Model] | None = None,
                 default_sort_param: str ='id'
                 ) -> None:
        """"Initialize the view with optional queryset, model, and default sort parameter."""
        self.queryset = queryset
        self.model = model
        self.default_sort_param = default_sort_param
        self.request = HttpRequest()

    def get_context_data(self, **kwargs: dict[str, Any]) -> dict[str, Any]:
        """Call get_context_data from SortableTableMixin."""
        return super().get_context_data(**kwargs)


class TestSortableTableMixin(TestCase):
    """Test cases for SortableTableMixin."""

    @classmethod
    def setUpTestData(cls) -> None:
        """Create test data for the test class."""
        cls.device1 = DeviceModel.objects.create(common_name='Device A', serial_number='12345')
        cls.device2 = DeviceModel.objects.create(common_name='Device C', serial_number='67890')
        cls.device3 = DeviceModel.objects.create(common_name='Device B', serial_number='54321')

        cls.device_list = [
            {'common_name': 'Device A', 'serial_number': '12345'},
            {'common_name': 'Device C', 'serial_number': '67890'},
            {'common_name': 'Device B', 'serial_number': '54321'},
        ]

    def setUp(self) -> None:
        """Set up the test environment for each test case."""
        self.factory = RequestFactory()

    def test_sort_queryset_ascending(self) -> None:
        """Test sorting of queryset in ascending order."""
        view = SortableTableView(queryset=DeviceModel.objects.all(),
                                 model=DeviceModel, default_sort_param='common_name')
        view.request = self.factory.get('/?sort=common_name')

        sorted_queryset = view.get_queryset()
        expected_queryset = DeviceModel.objects.all().order_by('common_name')
        self.assertQuerySetEqual(
            sorted_queryset, expected_queryset, transform=lambda x: x,
            msg="Queryset should be sorted by 'common_name' ascending."
        )

    def test_sort_queryset_descending(self) -> None:
        """Test sorting of queryset in descending order."""
        view = SortableTableView(queryset=DeviceModel.objects.all(),
                                 model=DeviceModel, default_sort_param='common_name')
        view.request = self.factory.get('/?sort=-common_name')

        sorted_queryset = view.get_queryset()
        expected_queryset = DeviceModel.objects.all().order_by('-common_name')
        self.assertQuerySetEqual(
            sorted_queryset, expected_queryset, transform=lambda x: x,
            msg="Queryset should be sorted by 'common_name' descending."
        )

    def test_sort_list_of_dicts(self) -> None:
        """Test sorting of a list of dictionaries."""
        view = SortableTableView(queryset=self.device_list, default_sort_param='common_name')
        view.request = self.factory.get('/?sort=common_name')

        sorted_list = view.get_queryset()
        expected_list = sorted(self.device_list, key=lambda x: x['common_name'], reverse=False)
        assert sorted_list == expected_list, "List of dictionaries should be sorted by 'common_name' ascending."

    def test_sort_list_of_dicts_descending(self) -> None:
        """Test sorting of a list of dictionaries in descending order."""
        view = SortableTableView(queryset=self.device_list, default_sort_param='common_name')
        view.request = self.factory.get('/?sort=-common_name')

        sorted_list = view.get_queryset()
        expected_list = sorted(self.device_list, key=lambda x: x['common_name'], reverse=True)
        assert sorted_list ==expected_list, \
            "List of dictionaries should be sorted by 'common_name' descending."

    def test_default_sort_param(self) -> None:
        """Test sorting using the default sort parameter."""
        view = SortableTableView(queryset=self.device_list, default_sort_param='serial_number')
        view.request = self.factory.get('/')  # No sort parameter in the URL

        sorted_list = view.get_queryset()
        expected_list = sorted(self.device_list, key=lambda x: x['serial_number'], reverse=False)
        assert sorted_list == expected_list, \
            "List of dictionaries should be sorted by default 'serial_number' ascending."


