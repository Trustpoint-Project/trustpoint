"""Contains views that handle HTTP requests and return appropriate responses for the application."""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from devices.models import DeviceModel, IssuedCredentialModel
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db.models import Case, Count, F, IntegerField, Q, QuerySet, Value, When
from django.db.models.functions import TruncDate
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import dateparse, timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.views.generic.base import RedirectView, TemplateView
from django.views.generic.list import ListView
from pki.models import CertificateModel, IssuingCaModel

from trustpoint.settings import UIConfig
from trustpoint.views.base import SortableTableMixin

from .filters import NotificationFilter
from .models import NotificationModel, NotificationStatus

if TYPE_CHECKING:
    from django.utils.safestring import SafeString

SUCCESS = 25
ERROR = 40


class IndexView(RedirectView):
    """Redirects authenticated users to the dashboard page."""

    permanent = False
    pattern_name = 'home:dashboard'


class DashboardView(SortableTableMixin, ListView[NotificationModel]):
    """Renders the dashboard page for authenticated users. Uses the 'home/dashboard.html' template."""

    template_name = 'home/dashboard.html'
    model = NotificationModel
    context_object_name = 'notifications'
    default_sort_param = '-created_at'
    paginate_by = UIConfig.notifications_paginate_by

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the parent class with the given arguments and keyword arguments.

        It initialize the last_week_dates objects with list of string of last week dates.

        Args:
            *args: Positional arguments passed to super().__init__.
            **kwargs: Keyword arguments passed to super().__init__.

        Returns:
            It returns nothing.
        """
        super().__init__(*args, **kwargs)
        self.last_week_dates = self.generate_last_week_dates()

    def get_notifications(self) -> QuerySet[NotificationModel]:
        """Fetch notification data for the table.

        Returns:
            A `QuerySet` containing all notifications.
        """
        return NotificationModel.objects.all()

    def generate_last_week_dates(self) -> list[str]:
        """Generates date strings for last one week.

        Returns:
            A list of date strings from last one week.
        """
        end_date = timezone.now()
        start_date = end_date - timedelta(days=6)
        return [(start_date + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]

    def get_queryset(self) -> Any:
        """Returns a queryset of NotificationModel instances.

        Returns:
            A `QuerySet` containing filtered notifications.
        """
        all_notifications = NotificationModel.objects.all()

        notification_filter = NotificationFilter(self.request.GET, queryset=all_notifications)
        self.queryset = notification_filter.qs
        return super().get_queryset()

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Fetch context data.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)

        for notification in context['notifications']:
            notification.type_badge = self._render_notification_type(notification)
            notification.created = self._render_created_at(notification)

        context['page_category'] = 'home'
        context['page_name'] = 'dashboard'
        return context

    @staticmethod
    def _render_created_at(record: NotificationModel) -> SafeString:
        """Render the created_at field with a badge if the status is 'New'.

        Args:
            record: The corresponding NotificationModel.

        Returns:
            The HTML of the created at display span.
        """
        created_at_display = record.created_at.strftime('%Y-%m-%d %H:%M:%S')

        if record.statuses.filter(status=NotificationStatus.StatusChoices.NEW).exists():
            return format_html('{} <span class="badge bg-secondary">{}</span>', created_at_display, _('New'))

        return format_html('{}', created_at_display)

    @staticmethod
    def _render_notification_type(record: NotificationModel) -> SafeString:
        """Render the notification type with a badge according to the type.

        Args:
            record: The corresponding NotificationModel.

        Returns:
            The HTML of the span with class badge to display notification type.
        """
        type_display = record.get_notification_type_display() # type: ignore[attr-defined]

        if record.notification_type == NotificationModel.NotificationTypes.CRITICAL:
            badge_class = 'bg-danger'
        elif record.notification_type == NotificationModel.NotificationTypes.WARNING:
            badge_class = 'bg-warning'
        elif record.notification_type == NotificationModel.NotificationTypes.INFO:
            badge_class = 'bg-info'
        else:  # Setup or other types default to secondary
            badge_class = 'bg-secondary'

        return format_html('<span class="badge {}">{}</span>', badge_class, type_display)


@login_required
def notification_details_view(request: HttpRequest, pk: int | str) -> HttpResponse:
    """Renders notification details view.

    Args:
        request: The Django request object.
        pk: The primary key.

    Returns:
        A redirect to the notification details page.
    """
    notification = get_object_or_404(NotificationModel, pk=pk)

    notification_statuses = notification.statuses.values_list('status', flat=True)

    new_status, created = NotificationStatus.objects.get_or_create(status='NEW')
    solved_status, created = NotificationStatus.objects.get_or_create(status='SOLVED')
    is_solved = solved_status in notification.statuses.all()

    if new_status and new_status in notification.statuses.all():
        notification.statuses.remove(new_status)

    context = {
        'notification': notification,
        'NotificationStatus': NotificationStatus,
        'notification_statuses': notification_statuses,
        'is_solved': is_solved,
    }

    return render(request, 'home/notification_details.html', context)


@login_required
def mark_as_solved(request: HttpRequest, pk: int | str) -> HttpResponse:
    """View to mark the notification as Solved.

    Args:
        request: The Django request object.
        pk: The primary key.

    Returns:
        A redirect to the notification details page.
    """
    notification = get_object_or_404(NotificationModel, pk=pk)

    solved_status, created = NotificationStatus.objects.get_or_create(status='SOLVED')
    is_solved = solved_status in notification.statuses.all()

    if solved_status:
        notification.statuses.add(solved_status)

    notification_statuses = notification.statuses.values_list('status', flat=True)

    context = {
        'notification': notification,
        'NotificationStatus': NotificationStatus,
        'notification_statuses': notification_statuses,
        'is_solved': is_solved,
    }

    return render(request, 'home/notification_details.html', context)


class AddDomainsAndDevicesView(TemplateView):
    """View to execute the add_domains_and_devices management command and pass status to the template."""

    _logger = logging.getLogger(__name__)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseRedirect:
        """Handles GET requests and redirects to the dashboard.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The response that redirects the user to home:dashboard.
        """
        del args
        del kwargs

        try:
            call_command('add_domains_and_devices')
            messages.add_message(request, SUCCESS, 'Successfully added test data.')
        except CommandError:
            messages.add_message(request, ERROR, 'Test data already available in the Database.')

        return redirect('home:dashboard')


class DashboardChartsAndCountsView(TemplateView):
    """View to mark the notification as Solved."""

    _logger = logging.getLogger(__name__)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        """Get dashboard data for panels, tables and charts.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The JSON response containing dashboard data.
        """
        start_date: str | None = request.GET.get('start_date', None)

        del args
        del kwargs

        start_date_object: datetime = timezone.now()
        # Parse the date string into a datetime.date object
        if start_date:
            parsed_date = dateparse.parse_datetime(start_date)  # Returns a datetime object
            if not parsed_date:
                return JsonResponse({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=400)
            start_date_object = parsed_date
        dashboard_data: dict[str, Any] = {}

        start_date_object = timezone.make_aware(datetime.combine(start_date_object.date(), datetime.min.time()))
        device_counts = self.get_device_count_by_onboarding_status(start_date_object)
        dashboard_data['device_counts'] = device_counts
        self._logger.debug('device counts %s', device_counts)

        cert_counts = self.get_cert_counts()
        if cert_counts:
            dashboard_data['cert_counts'] = cert_counts

        issuing_ca_counts = self.get_issuing_ca_counts()
        if issuing_ca_counts:
            dashboard_data['issuing_ca_counts'] = issuing_ca_counts

        self.get_device_charts_data(dashboard_data, start_date_object)
        self.get_cert_charts_data(dashboard_data, start_date_object)
        self.get_ca_charts_data(dashboard_data, start_date_object)

        return JsonResponse(dashboard_data)

    def get_device_charts_data(self, dashboard_data: dict[str, Any], start_date_object: datetime) -> None:
        """Fetch data from database for device charts and add to dashboard data object.

        Args:
            dashboard_data: The dashboard data object.
            start_date_object: The start date for fetching device data.

        Returns:
            It returns nothing. It adds the device related data in dashboard_data object.
        """
        device_counts_by_os = self.get_device_count_by_onboarding_status(start_date_object)
        if device_counts_by_os:
            dashboard_data['device_counts_by_os'] = device_counts_by_os

        device_counts_by_op = self.get_device_count_by_onboarding_protocol(start_date_object)
        if device_counts_by_op:
            dashboard_data['device_counts_by_op'] = device_counts_by_op

        device_counts_by_domain = self.get_device_count_by_domain(start_date_object)
        if device_counts_by_domain:
            dashboard_data['device_counts_by_domain'] = device_counts_by_domain

    def get_cert_charts_data(self, dashboard_data: dict[str, Any], start_date_object: datetime) -> None:
        """Fetch data from database for certificate charts and add to dashboard data object.

        Args:
            dashboard_data: The dashboard data object.
            start_date_object: The start date for fetching certificate data.

        Returns:
            It returns nothing. It adds the certificate related data in dashboard_data object.
        """
        cert_counts_by_status = self.get_cert_counts_by_status(start_date_object)
        if cert_counts_by_status:
            dashboard_data['cert_counts_by_status'] = cert_counts_by_status

        cert_counts_by_domain = self.get_cert_counts_by_domain(start_date_object)
        if cert_counts_by_domain:
            dashboard_data['cert_counts_by_domain'] = cert_counts_by_domain

        cert_counts_by_template = self.get_cert_counts_by_template(start_date_object)
        if cert_counts_by_template:
            dashboard_data['cert_counts_by_template'] = cert_counts_by_template

    def get_ca_charts_data(self, dashboard_data: dict[str, Any], start_date_object: datetime) -> None:
        """Fetch data from database for issuing ca charts and add to dashboard data object.

        Args:
            dashboard_data: The dashboard data object.
            start_date_object: The start date for fetching issuing ca data.

        Returns:
            It returns nothing. It adds the issuing ca related data in dashboard_data object.
        """
        cert_counts_by_issuing_ca = self.get_cert_counts_by_issuing_ca(start_date_object)
        if cert_counts_by_issuing_ca:
            dashboard_data['cert_counts_by_issuing_ca'] = cert_counts_by_issuing_ca

        cert_counts_by_issuing_ca_and_date = self.get_cert_counts_by_issuing_ca_and_date(start_date_object)
        if cert_counts_by_issuing_ca_and_date:
            dashboard_data['cert_counts_by_issuing_ca_and_date'] = cert_counts_by_issuing_ca_and_date

        issuing_ca_counts_by_type = self.get_issuing_ca_counts_by_type(start_date_object)
        if issuing_ca_counts_by_type:
            dashboard_data['ca_counts_by_type'] = issuing_ca_counts_by_type

    def get_device_count_by_onboarding_status(self, start_date: datetime) -> dict[str, Any]:
        """Fetch device count by onboarding status from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns device counts grouped by device onboarding status.
        """
        device_os_counts = {str(status): 0 for _, status in DeviceModel.OnboardingStatus.choices}
        try:
            device_os_qr = (
                DeviceModel.objects.filter(created_at__gt=start_date)
                .values('onboarding_status')
                .annotate(count=Count('onboarding_status'))
            )
            # Mapping from short code to human-readable name
            protocol_mapping = {key: str(value) for key, value in DeviceModel.OnboardingStatus.choices}
            device_os_counts = {protocol_mapping[item['onboarding_status']]: item['count'] for item in device_os_qr}

            for protocol in protocol_mapping.values():
                device_os_counts.setdefault(protocol, 0)
            device_os_counts['total'] = sum(device_os_counts.values())
        except Exception:
            self._logger.exception('Error occurred in device count by onboarding protocol query')

        return device_os_counts

    def get_cert_counts(self) -> dict[str, Any]:
        """Fetch certificate count from database.

        Returns:
            It returns certificate counts.
        """
        cert_counts = {}
        # Get the current date and the dates for 7 days and 1 day ahead
        now = timezone.now()
        next_7_days = now + timedelta(days=7)
        next_1_day = now + timedelta(days=1)
        try:
            cert_counts = CertificateModel.objects.aggregate(
                total=Count('id'),
                active=Count('id', filter=Q(not_valid_after__gt=now)),
                expired=Count('id', filter=Q(not_valid_after__lt=now)),
                expiring_in_7_days=Count('id', filter=Q(not_valid_after__gt=now, not_valid_after__lte=next_7_days)),
                expiring_in_1_day=Count('id', filter=Q(not_valid_after__gt=now, not_valid_after__lte=next_1_day)),
            )
        except Exception:
            self._logger.exception('Error occurred in certificate count query')
        return cert_counts

    def get_cert_counts_by_status_and_date(self) -> list[dict[str, Any]]:
        """Fetch certificate counts grouped by issue date and certificate status from database.

        Returns:
            It returns certificate counts grouped by issue date and certificate status.
        """
        cert_counts_by_status = []
        try:
            cert_status_qr = (
                CertificateModel.objects.annotate(issue_date=TruncDate('not_valid_before'))
                .values('issue_date', 'certificate_status')
                .annotate(cert_count=Count('id'))
                .order_by('issue_date', 'certificate_status')
            )
            # Mapping von Status-Code zu lesbarem Namen
            status_mapping = dict(CertificateModel.CertificateStatus.choices)
            # Konvertiere das QuerySet in eine Liste und formatiere die Werte
            cert_counts_by_status = [
                {
                    'issue_date': item['issue_date'].strftime('%Y-%m-%d'),
                    'certificate_status': status_mapping.get(item['certificate_status'], item['certificate_status']),
                    'cert_count': item['cert_count'],
                }
                for item in cert_status_qr
            ]
        except Exception:
            self._logger.exception('Error occurred in certificate count by status query')
        return cert_counts_by_status

    def get_cert_counts_by_status(self, start_date: datetime) -> dict[str, Any]:
        """Fetch certs count by onboarding status from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns device counts grouped by device onboarding status.
        """
        cert_status_counts = {str(status): 0 for _, status in CertificateModel.CertificateStatus.choices}
        try:
            cert_status_qr = CertificateModel.objects.filter(created_at__gt=start_date)
            status_counts = Counter(str(cert.certificate_status.value) for cert in cert_status_qr)
            # Mapping from short code to human-readable name
            status_mapping = {key: str(value) for key, value in CertificateModel.CertificateStatus.choices}
            cert_status_counts = {status_mapping[key]: value for key, value in status_counts.items()}
        except Exception:
            self._logger.exception('Error occurred in cert counts by status query')
        return cert_status_counts

    def get_issuing_ca_counts(self) -> dict[str, Any]:
        """Fetch issuing CA count from database.

        Returns:
            It returns total, active and expired issuing CA counts.
        """
        # Current date
        today = timezone.make_aware(datetime.combine(timezone.now().date(), datetime.min.time()))
        issuing_ca_counts = {}
        try:
            # Query to get total, active, and expired Issuing CAs
            issuing_ca_counts = IssuingCaModel.objects.aggregate(
                total=Count('id'),
                active=Count(
                    Case(
                        When(credential__certificates__not_valid_after__gt=today, then=Value(1)),
                        output_field=IntegerField(),
                    )
                ),
                expired=Count(
                    Case(
                        When(credential__certificates__not_valid_after__lte=today, then=Value(1)),
                        output_field=IntegerField(),
                    )
                ),
            )
        except Exception:
            self._logger.exception('Error occurred in issuing ca count query')

        return issuing_ca_counts

    def get_device_counts_by_date_and_status(self) -> list[dict[str, Any]]:
        """Fetch device count by date and onboarding status from database.

        Returns:
            It returns device count grouped by date and onboarding status.
        """
        device_counts_by_date_and_os = []
        try:
            device_date_os_qr = (
                DeviceModel.objects.annotate(issue_date=TruncDate('created_at'))
                .values('issue_date', onboarding_status=F('onboarding_status'))
                .annotate(device_count=Count('id'))
                .order_by('issue_date', 'onboarding_status')
            )
            # Convert the queryset to a list
            device_counts_by_date_and_os = list(device_date_os_qr)
        except Exception:
            self._logger.exception('Error occurred in device count by date and onboarding status')
        return device_counts_by_date_and_os

    def get_device_count_by_onboarding_protocol(self, start_date: datetime) -> dict[str, Any]:
        """Fetch device count by onboarding protocol from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns device count by onboarding protocol.
        """
        device_op_counts = {str(status): 0 for _, status in DeviceModel.OnboardingProtocol.choices}
        try:
            device_op_qr = (
                DeviceModel.objects.filter(created_at__gt=start_date)
                .values('onboarding_protocol')
                .annotate(count=Count('onboarding_protocol'))
            )
            # Mapping from short code to human-readable name
            protocol_mapping = {key: str(value) for key, value in DeviceModel.OnboardingProtocol.choices}
            device_op_counts = {protocol_mapping[item['onboarding_protocol']]: item['count'] for item in device_op_qr}

        except Exception:
            self._logger.exception('Error occurred in device count by onboarding protocol query')
        return device_op_counts

    def get_device_count_by_domain(self, start_date: datetime) -> list[dict[str, Any]]:
        """Fetch onboarded devices count grouped by domain from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns onboarded devices count grouped by domain.
        """
        try:
            device_domain_qr = (
                DeviceModel.objects.filter(
                    Q(onboarding_status=DeviceModel.OnboardingStatus.ONBOARDED) & Q(created_at__gte=start_date)
                )
                .values(domain_name=F('domain__unique_name'))
                .annotate(onboarded_device_count=Count('id'))
            )

            # Convert the queryset to a list
            return list(device_domain_qr)
        except Exception:
            self._logger.exception('Error occurred in device count by domain query')
            return []

    def get_cert_counts_by_issuing_ca(self, start_date: datetime) -> list[dict[str, Any]]:
        """Fetch certificate count grouped by issuing ca from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns certificate count grouped by issuing ca.
        """
        cert_counts_by_issuing_ca = []
        try:
            cert_issuing_ca_qr = (
                CertificateModel.objects.filter(issuer__isnull=False)
                .filter(created_at__gt=start_date)
                .values(ca_name=F('issuer__value'))
                .annotate(cert_count=Count('id'))
            )
            # Convert the queryset to a list
            cert_counts_by_issuing_ca = list(cert_issuing_ca_qr)
        except Exception:
            self._logger.exception('Error occurred in certificate count by issuing ca query')

        return cert_counts_by_issuing_ca

    def get_cert_counts_by_issuing_ca_and_date(self, start_date: datetime) -> list[dict[str, Any]]:
        """Fetch certificate count grouped by issuing ca and date from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns certificate count grouped by issuing ca and date.
        """
        cert_counts_by_issuing_ca_and_date = []
        try:
            cert_issuing_ca_and_date_qr = (
                CertificateModel.objects.filter(issuer__isnull=False)
                .filter(created_at__gt=start_date)
                .annotate(issue_date=TruncDate('created_at'))
                .values('issue_date', name=F('issuer__value'))
                .annotate(cert_count=Count('id'))
                .order_by('issue_date', 'name')
            )
            # Convert the queryset to a list
            cert_counts_by_issuing_ca_and_date = list(cert_issuing_ca_and_date_qr)
        except Exception:
            self._logger.exception('Error occurred in certificate count by issuing ca query')
        return cert_counts_by_issuing_ca_and_date

    def get_cert_counts_by_domain(self, start_date: datetime) -> list[dict[str, Any]]:
        """Fetch certificate count grouped by domain from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns certificate count grouped by domain.
        """
        cert_counts_by_domain = []
        try:
            cert_counts_domain_qr = (
                IssuedCredentialModel.objects.filter(created_at__gt=start_date)
                .values(domain_name=F('domain__unique_name'))
                .annotate(cert_count=Count('id'))
            )

            # Convert the queryset to a list
            cert_counts_by_domain = list(cert_counts_domain_qr)
        except Exception:
            self._logger.exception('Error occurred in certificate count by issuing ca query')
        return cert_counts_by_domain

    def get_cert_counts_by_template(self, start_date: datetime) -> dict[str, Any]:
        """Fetch certificate count grouped by template from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns certificate count grouped by template.
        """
        cert_counts_by_template = {
            str(status): 0 for _, status in IssuedCredentialModel.IssuedCredentialPurpose.choices
        }
        try:
            cert_template_qr = (
                IssuedCredentialModel.objects.filter(credential__certificates__created_at__gt=start_date)
                .values(cert_type=F('issued_credential_purpose'))
                .annotate(count=Count('credential__certificates'))
            )
            # Mapping from short code to human-readable name
            template_mapping = {key: str(value) for key, value in IssuedCredentialModel.IssuedCredentialPurpose.choices}
            cert_counts_by_template = {template_mapping[item['cert_type']]: item['count'] for item in cert_template_qr}
        except Exception:
            self._logger.exception('Error occurred in certificate count by template query')
        return cert_counts_by_template

    def get_issuing_ca_counts_by_type(self, start_date: datetime) -> dict[str, Any]:
        """Get issuing ca counts by type from database."""
        """Fetch issuing ca counts grouped by type from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns issuing ca counts grouped by type.
        """
        issuing_ca_type_counts = {str(cert_type): 0 for _, cert_type in IssuingCaModel.IssuingCaTypeChoice.choices}
        try:
            ca_type_qr = (
                IssuingCaModel.objects.filter(created_at__gt=start_date)
                .values('issuing_ca_type')
                .annotate(count=Count('issuing_ca_type'))
            )
            # Mapping from short code to human-readable name
            protocol_mapping = {key: str(value) for key, value in IssuingCaModel.IssuingCaTypeChoice.choices}
            issuing_ca_type_counts = {protocol_mapping[item['issuing_ca_type']]: item['count'] for item in ca_type_qr}

        except Exception:
            self._logger.exception('Error occurred in ca counts by type query')
        return issuing_ca_type_counts
