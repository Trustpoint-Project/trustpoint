"""Contains test cases to ensure the functionality and correctness of the Home application."""

import pytest
from django.urls import reverse
from django.contrib.auth.models import User
from bs4 import BeautifulSoup
from django.core.management import call_command
from .models import NotificationModel

@pytest.fixture
def dashboard_response(client):
    user = User.objects.create_user(username="admin", password="testing321")
    client.force_login(user)
    response = client.get(reverse("home:dashboard"))
    return response


@pytest.fixture
def setup_notifications():
    """Fixture to run the setup notification management command before tests."""

    call_command("trustpoint_setup_notifications")
    return NotificationModel.objects.first()

@pytest.fixture
def notification_response(client):
    """Fixture to get notification details for the first notification."""

    user = User.objects.create_user(username="admin", password="testing321")
    client.force_login(user)
    response = client.get(reverse("home:notification_details", args=[1]))
    return response

@pytest.mark.django_db
def test_notification_details_view(setup_notifications, notification_response):

    """Test that the notification details page is accessible for a logged-in user."""
    assert setup_notifications is not None, "No notification was created by the command"
    assert notification_response.status_code == 200

@pytest.mark.django_db
def test_dashboard_view(dashboard_response):
    """Test that the dashboard page is accessible for a logged-in user."""

    assert dashboard_response.status_code == 200
    assert "Summary" in dashboard_response.content.decode()
    assert "Certificates" in dashboard_response.content.decode()
    assert "Notifications" in dashboard_response.content.decode()
    assert "Filter" in dashboard_response.content.decode()
    assert "Charts" in dashboard_response.content.decode()
    assert "Device" in dashboard_response.content.decode()

@pytest.mark.django_db
def test_notification_table(dashboard_response):
    """Test that the dashboard contains the notification table."""

    assert dashboard_response.status_code == 200

    soup = BeautifulSoup(dashboard_response.content, "html.parser")
    table = soup.find("table", {"class": "table"})
    
    assert table is not None, "Dashboard table not found!"

    # Validate headers
    headers = [th.text.strip() for th in table.find_all("th")]
    expected_headers = ["Type", "Description", "Details"]
    assert all(h in headers for h in expected_headers), "Missing table headers"

@pytest.mark.django_db
def test_charts(dashboard_response):
    """Test that the dashboard contains the notification table."""

    assert dashboard_response.status_code == 200

    soup = BeautifulSoup(dashboard_response.content, "html.parser")
    # Check if divs with specific IDs exist
    div_ids = ["deviceChartTab", "certChartTab", "caChartTab"]

    for canvas_id in div_ids:
        div = soup.find("div", {"id": canvas_id})
        assert div is not None, f"Div with id '{canvas_id}' not found!"

    # Check if canvases with specific IDs exist
    canvas_ids = ["devicesByOSLineChart", "devicesByDomainDonutChart", "devicesByOPBarChart", 
        "certsByStatusLineChart", "certsByDomainPieChart", "certsByTemplateBarChart",
        "certsByIssuingCADonutChart", "certsByDateStackChart", "issuingCAsByTypePieChart"
        ]

    for canvas_id in canvas_ids:
        div = soup.find("canvas", {"id": canvas_id})
        assert div is not None, f"canvas with id '{canvas_id}' not found!"
