"""Python steps for F_002"""  # noqa: INP001

from behave import given, runner, then, when

from django.contrib.auth.models import User
from django.urls import reverse
from selenium.webdriver.common.by import By
import time

@given('the NTEU log-in')
def step_impl(context: runner.Context) -> None:
    """NTEU log-in.
    Args:
        context (runner.Context): The Behave context.
    Returns:
        None
    """
    # Create NTEU user if doesn't exist
    username = "admin"
    password = "testing321"
    if not User.objects.filter(username=username).exists():
        User.objects.create_user(username=username, password=password)

    # Log in through the browser
    login_url = context.test.live_server_url + reverse("users:login")
    print("login", login_url)
    context.browser.get(login_url)

    context.browser.find_element(By.NAME, "username").send_keys(username)
    context.browser.find_element(By.NAME, "password").send_keys(password)
    context.browser.find_element(By.XPATH, "//button[contains(text(), 'Login')]").click()

    time.sleep(1)  # Allow redirect to complete

@when('the NTEU navigates to dashboard page')
def step_impl(context: runner.Context) -> None:

    dashboard_url = context.test.live_server_url + reverse("home:dashboard")  # Adjust to your actual URL name
    context.browser.get(dashboard_url)
    time.sleep(1)  # Let page load

@then('4 panels with title Certificates, Expiring Certificates, Devices and Issuing CAs should be visible')
def step_impl(context: runner.Context) -> None:
    """Verifies that panels for device and certificates exist.

    Args:
        context (runner.Context): The Behave context.

    Returns:
        None
    """
    expected_titles = ["Certificates", "Expiring Certificates", "Devices", "Issuing CAs"]
    page = context.browser.page_source
    for title in expected_titles:
        assert title in page, f"Panel '{title}' not found on page"

@then('a notification table should be displayed')
def step_impl(context: runner.Context) -> None:
    """Verifies that notification tables exists.

    Args:
        context (runner.Context): The Behave context.

    Returns:
        None
    """
    table = context.browser.find_element(By.CLASS_NAME, "table")
    assert table.is_displayed(), "Notification table is not visible"

@then('3 chart tabs named, Device, Certificate and CA should be visible')
def step_impl(context: runner.Context) -> None:
    """Verifies that chart navigation tab exits.

    Args:
        context (runner.Context): The Behave context.

    Returns:
        None
    """
    expected_tabs = ["Device", "Certificate", "CA"]
    tab_elements = context.browser.find_elements(By.CLASS_NAME, "nav-alert")

    tab_names = [tab.text.strip() for tab in tab_elements if tab.text.strip()]
    for expected in expected_tabs:
        assert expected in tab_names, f"Chart tab '{expected}' not found"

