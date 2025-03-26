"""Contains test cases to ensure the functionality and correctness of the Home application."""

from http import HTTPStatus

import pytest
from bs4 import BeautifulSoup
from devices.models import DeviceModel
from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client
from django.urls import reverse

from .models import NotificationModel


@pytest.fixture
def setup_client(client: Client) -> Client:
    """Fixture to run the management command to setup notifications."""
    user = User.objects.create_user(username='admin', password='testing321')
    client.force_login(user)
    return client

@pytest.fixture
def setup_notifications() -> NotificationModel | None:
    """Fixture to run the management command to setup notifications."""
    call_command('trustpoint_setup_notifications')
    return NotificationModel.objects.first()

@pytest.fixture
def setup_domain_and_devices() -> DeviceModel | None:
    """Fixture to run the management command to setup domain and devices."""
    call_command('add_domains_and_devices')
    return DeviceModel.objects.first()

@pytest.mark.django_db
def test_dashboard_view(setup_client: Client) -> None:
    """Test that the dashboard page is accessible and contain table and charts."""
    response = setup_client.get(reverse('home:dashboard'))
    assert response.status_code == HTTPStatus.OK, 'dashboard page is not accessible'

    soup = BeautifulSoup(response.content, 'html.parser')

    table = soup.find('table', {'class': 'table'})

    assert table is not None, 'Dashboard table not found!'

    # Validate headers
    headers = [th.text.strip() for th in table.find_all('th')]
    expected_headers = ['Type', 'Description', 'Details']
    assert all(h in headers for h in expected_headers), 'Missing table headers'
    # Check if divs with specific IDs exist
    div_ids = ['deviceChartTab', 'certChartTab', 'caChartTab']

    for canvas_id in div_ids:
        div = soup.find('div', {'id': canvas_id})
        assert div is not None, f"Div with id '{canvas_id}' not found!"

    # Check if canvases with specific IDs exist
    canvas_ids = ['devicesByOSLineChart', 'devicesByDomainDonutChart', 'devicesByOPBarChart',
        'certsByStatusLineChart', 'certsByDomainPieChart', 'certsByTemplateBarChart',
        'certsByIssuingCADonutChart', 'certsByDateStackChart', 'issuingCAsByTypePieChart'
        ]

    for canvas_id in canvas_ids:
        div = soup.find('canvas', {'id': canvas_id})
        assert div is not None, f"canvas with id '{canvas_id}' not found!"

@pytest.mark.django_db
def test_notification_details_view(setup_notifications:NotificationModel, setup_client: Client) -> None:
    """Test that the notification details page is accessible for a logged-in user."""
    assert setup_notifications is not None, 'No notification was created by the command'
    response = setup_client.get(reverse('home:notification_details', args=[1]))
    assert response.status_code == HTTPStatus.OK

@pytest.mark.django_db
def test_dashboard_chart_view(setup_domain_and_devices:DeviceModel, setup_client: Client) -> None:
    """Test that the dashboard chart data is accessible for a logged-in user."""
    assert setup_domain_and_devices is not None, 'No domain and device were created by the command'
    response = setup_client.get(reverse('home:dashboard_data'))
    assert response.status_code == HTTPStatus.OK
    dashboard_data = response.json()
    required_keys = {'device_counts', 'cert_counts', 'issuing_ca_counts',
        'device_counts_by_os', 'device_counts_by_op', 'cert_counts_by_status',
        'cert_counts_by_issuing_ca', 'cert_counts_by_issuing_ca_and_date',
        'ca_counts_by_type'}
    assert required_keys.issubset(dashboard_data.keys()), f'Missing keys: {required_keys - dashboard_data.keys()}'
