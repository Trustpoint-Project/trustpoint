"""Contains views that handle HTTP requests and return appropriate responses for the application."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db.models import Case, Count, F, IntegerField, Q, Value, When
from django.db.models.functions import TruncDate
from django.http import HttpRequest, HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect
from django.utils import dateparse, timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.views.generic.base import RedirectView, TemplateView
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView

from devices.models import DeviceModel, IssuedCredentialModel, OnboardingProtocol, OnboardingStatus
from notifications.models import NotificationModel, NotificationStatus
from pki.models import CertificateModel, CertificateProfileModel, IssuingCaModel
from trustpoint.logger import LoggerMixin
from trustpoint.settings import UIConfig
from trustpoint.views.base import SortableTableMixin

from .filters import NotificationFilter

if TYPE_CHECKING:
    from django.utils.safestring import SafeString

SUCCESS = 25
ERROR = 40


class IndexView(RedirectView):
    """Redirects authenticated users to the dashboard page."""

    permanent = False
    pattern_name = 'home:dashboard'


class DashboardView(SortableTableMixin[NotificationModel], ListView[NotificationModel]):
    """Renders the dashboard page for authenticated users. Uses the 'home/dashboard.html' template."""

    template_name = 'home/dashboard.html'
    model = NotificationModel
    context_object_name = 'notifications'
    default_sort_param = '-created_at'
    paginate_by = UIConfig.notifications_paginate_by

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the parent class with the given arguments and keyword arguments.

        It initializes the last_week_dates objects with list of string of last week dates.

        Args:
            *args: Positional arguments passed to super().__init__.
            **kwargs: Keyword arguments passed to super().__init__.

        Returns:
            It returns nothing.
        """
        super().__init__(*args, **kwargs)
        self.last_week_dates = self.generate_last_week_dates()

    @staticmethod
    def generate_last_week_dates() -> list[str]:
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
            # noinspection PyDeprecation
            return format_html('{} <span class="badge bg-secondary">{}</span>', created_at_display, _('New'))

        # noinspection PyDeprecation
        return format_html('{}', created_at_display)

    @staticmethod
    def _render_notification_type(record: NotificationModel) -> SafeString:
        """Render the notification type with a badge according to the type.

        Args:
            record: The corresponding NotificationModel.

        Returns:
            The HTML of the span with class badge to display notification type.
        """
        type_display = record.get_notification_type_display()

        if record.notification_type == NotificationModel.NotificationTypes.CRITICAL:
            badge_class = 'bg-danger'
        elif record.notification_type == NotificationModel.NotificationTypes.WARNING:
            badge_class = 'bg-warning'
        elif record.notification_type == NotificationModel.NotificationTypes.INFO:
            badge_class = 'bg-info'
        else:
            badge_class = 'bg-secondary'

        # noinspection PyDeprecation
        return format_html('<span class="badge {}">{}</span>', badge_class, type_display)


class NotificationDetailsView(DetailView[NotificationModel]):
    """Renders the notification details page for authenticated users."""

    template_name = 'home/notification_details.html'
    model = NotificationModel
    context_object_name = 'notification'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the statuses of the Notification.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)

        # TODO(AlexHx8472): This should be generated automatically by utilizing a migration # noqa: FIX002
        new_status, _created = NotificationStatus.objects.get_or_create(status='NEW')
        solved_status, _created = NotificationStatus.objects.get_or_create(status='SOLVED')

        if new_status and new_status in self.object.statuses.all():
            self.object.statuses.remove(new_status)

        context['is_solved'] = solved_status in self.object.statuses.all()
        context['notification_statuses'] = self.object.statuses.values_list('status', flat=True)
        return context


class NotificationMarkSolvedView(DetailView[NotificationModel]):
    """Mark notification as solved when viewed in the notification details page."""

    template_name = 'home/notification_details.html'
    model = NotificationModel
    context_object_name = 'notification'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the solved status of the notification.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)

        # TODO(AlexHx8472): This should be generated automatically by utilizing a migration # noqa: FIX002
        solved_status, _ = NotificationStatus.objects.get_or_create(status='SOLVED')

        if solved_status:
            self.object.statuses.add(solved_status)

        context['is_solved'] = solved_status in self.object.statuses.all()
        return context


class AddDomainsAndDevicesView(LoggerMixin, TemplateView):
    """View to execute the add_domains_and_devices management command and pass status to the template."""

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


class DashboardChartsAndCountsView(LoggerMixin, TemplateView):
    """View to mark the notification as Solved."""

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

        if start_date:
            parsed_date = dateparse.parse_datetime(start_date)
            if not parsed_date:
                return JsonResponse({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=400)
            start_date_object = parsed_date
        dashboard_data: dict[str, Any] = {}

        start_date_object = timezone.make_aware(datetime.combine(start_date_object.date(), datetime.min.time()))
        device_counts = self.get_device_count_by_onboarding_status(start_date_object)
        dashboard_data['device_counts'] = device_counts
        self.logger.debug('device counts %s', device_counts)

        cert_counts = self.get_cert_counts()
        if cert_counts:
            dashboard_data['cert_counts'] = cert_counts

        issuing_ca_counts = self.get_issuing_ca_counts()
        if issuing_ca_counts:
            dashboard_data['issuing_ca_counts'] = issuing_ca_counts

        expiring_device_counts = self.get_expiring_device_counts()
        if expiring_device_counts:
            dashboard_data['expiring_device_counts'] = expiring_device_counts

        expired_device_counts = self.get_expired_device_counts()
        if expired_device_counts:
            dashboard_data['expired_device_counts'] = expired_device_counts

        expiring_issuing_ca_counts = self.get_expiring_issuing_ca_counts()
        if expiring_issuing_ca_counts:
            dashboard_data['expiring_issuing_ca_counts'] = expiring_issuing_ca_counts

        self.get_device_charts_data(dashboard_data, start_date_object)
        self.get_cert_charts_data(dashboard_data, start_date_object)
        self.get_ca_charts_data(dashboard_data, start_date_object)

        return JsonResponse(dashboard_data)

    def get_device_charts_data(self, dashboard_data: dict[str, Any], start_date: datetime) -> None:
        """Fetch data from database for device charts and add to dashboard data object.

        Args:
            dashboard_data: The dashboard data object.
            start_date: The start date for fetching device data.

        Returns:
            It returns nothing. It adds the device related data in dashboard_data object.
        """
        device_counts_by_os = self.get_device_count_by_onboarding_status(start_date)
        if device_counts_by_os:
            dashboard_data['device_counts_by_os'] = device_counts_by_os

        device_counts_by_op = self.get_device_count_by_onboarding_protocol(start_date)
        if device_counts_by_op:
            dashboard_data['device_counts_by_op'] = device_counts_by_op

        device_counts_by_domain = self.get_device_count_by_domain(start_date)
        if device_counts_by_domain:
            dashboard_data['device_counts_by_domain'] = device_counts_by_domain

    def get_cert_charts_data(self, dashboard_data: dict[str, Any], start_date: datetime) -> None:
        """Fetch data from database for certificate charts and add to dashboard data object.

        Args:
            dashboard_data: The dashboard data object.
            start_date: The start date for fetching certificate data.

        Returns:
            It returns nothing. It adds the certificate related data in dashboard_data object.
        """
        cert_counts_by_status = self.get_cert_counts_by_status(start_date)
        if cert_counts_by_status:
            dashboard_data['cert_counts_by_status'] = cert_counts_by_status

        cert_counts_by_domain = self.get_cert_counts_by_domain(start_date)
        if cert_counts_by_domain:
            dashboard_data['cert_counts_by_domain'] = cert_counts_by_domain

        cert_counts_by_profile = self.get_cert_counts_by_profile(start_date)
        if cert_counts_by_profile:
            dashboard_data['cert_counts_by_profile'] = cert_counts_by_profile

    def get_ca_charts_data(self, dashboard_data: dict[str, Any], start_date: datetime) -> None:
        """Fetch data from database for issuing ca charts and add to dashboard data object.

        Args:
            dashboard_data: The dashboard data object.
            start_date: The start date for fetching issuing ca data.

        Returns:
            It returns nothing. It adds the issuing ca related data in dashboard_data object.
        """
        cert_counts_by_issuing_ca = self.get_cert_counts_by_issuing_ca(start_date)
        if cert_counts_by_issuing_ca:
            dashboard_data['cert_counts_by_issuing_ca'] = cert_counts_by_issuing_ca

        cert_counts_by_issuing_ca_and_date = self.get_cert_counts_by_issuing_ca_and_date(start_date)
        if cert_counts_by_issuing_ca_and_date:
            dashboard_data['cert_counts_by_issuing_ca_and_date'] = cert_counts_by_issuing_ca_and_date

        issuing_ca_counts_by_type = self.get_issuing_ca_counts_by_type(start_date)
        if issuing_ca_counts_by_type:
            dashboard_data['ca_counts_by_type'] = issuing_ca_counts_by_type

    def get_device_count_by_onboarding_status(self, start_date: datetime) -> dict[str, Any]:
        """Fetch device count by onboarding status from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns device counts grouped by device onboarding status.
        """
        device_os_counts = {str(status): 0 for _, status in OnboardingStatus.choices}
        try:
            device_os_qr = (
                DeviceModel.objects.filter(created_at__gt=start_date, onboarding_config__isnull=False)
                .values('onboarding_config__onboarding_status')
                .annotate(count=Count('onboarding_config__onboarding_status'))
            )

            protocol_mapping = {key: str(value) for key, value in OnboardingStatus.choices}
            device_os_counts = {
                protocol_mapping[item['onboarding_config__onboarding_status']]:
                item['count'] for item in device_os_qr
            }

            for protocol in protocol_mapping.values():
                device_os_counts.setdefault(protocol, 0)
            device_os_counts['total'] = sum(device_os_counts.values())
        except Exception as exception:
            err_msg = f'Error occurred in device count by onboarding protocol query: {exception}'
            self.logger.exception(err_msg)

        return device_os_counts

    def get_cert_counts(self) -> dict[str, Any]:
        """Fetch certificate count from database.

        Returns:
            It returns certificate counts.
        """
        cert_counts = {}

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
        except Exception as exception:
            err_msg = f'Error occurred in certificate count query: {exception}'
            self.logger.exception(err_msg)

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

            status_mapping = dict(CertificateModel.CertificateStatus.choices)

            cert_counts_by_status = [
                {
                    'issue_date': item['issue_date'].strftime('%Y-%m-%d'),
                    'certificate_status': status_mapping.get(item['certificate_status'], item['certificate_status']),
                    'cert_count': item['cert_count'],
                }
                for item in cert_status_qr
            ]
        except Exception as exception:
            err_msg = f'Error occurred in certificate count by status query: {exception}'
            self.logger.exception(err_msg)
        return cert_counts_by_status

    def get_cert_counts_by_status(self, start_date: datetime) -> dict[str, Any]:
        """Fetch certs count by onboarding status from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns device counts grouped by device onboarding status.
        """
        cert_status_counts = {str(status): 0 for status, _ in CertificateModel.CertificateStatus.choices}
        try:
            cert_status_qr = CertificateModel.objects.filter(created_at__gt=start_date)
            status_counts = Counter(str(cert.certificate_status.value) for cert in cert_status_qr)

            status_mapping = {key: str(value) for key, value in CertificateModel.CertificateStatus.choices}
            cert_status_counts = {status_mapping[key]: value for key, value in status_counts.items()}
        except Exception as exception:
            err_msg = f'Error occurred in cert counts by status query: {exception}'
            self.logger.exception(err_msg)
        return cert_status_counts

    def get_issuing_ca_counts(self) -> dict[str, Any]:
        """Fetch issuing CA count from database.

        Returns:
            It returns total, active and expired issuing CA counts.
        """
        today = timezone.make_aware(datetime.combine(timezone.now().date(), datetime.min.time()))
        issuing_ca_counts = {}
        try:
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
        except Exception as exception:
            err_msg = f'Error occurred in issuing ca count query: {exception}'
            self.logger.exception(err_msg)

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

            device_counts_by_date_and_os = list(device_date_os_qr)
        except Exception as exception:
            err_msg = f'Error occurred in device count by date and onboarding status: {exception}'
            self.logger.exception(err_msg)
        return device_counts_by_date_and_os

    def get_device_count_by_onboarding_protocol(self, start_date: datetime) -> dict[str, Any]:
        """Fetch device count by onboarding protocol from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            It returns device count by onboarding protocol.
        """
        device_op_counts = {str(status): 0 for _, status in OnboardingProtocol.choices}
        try:
            device_op_qr = (
                DeviceModel.objects.filter(created_at__gt=start_date, onboarding_config__isnull=False)
                .values('onboarding_config__onboarding_protocol')
                .annotate(count=Count('onboarding_config__onboarding_protocol'))
            )

            protocol_mapping = {key: str(value) for key, value in OnboardingProtocol.choices}
            device_op_counts = {
                protocol_mapping[item['onboarding_config__onboarding_protocol']]:
                item['count'] for item in device_op_qr
            }

        except Exception as exception:
            err_msg = f'Error occurred in device count by onboarding protocol query: {exception}'
            self.logger.exception(err_msg)

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
                    Q(onboarding_config__onboarding_status=OnboardingStatus.ONBOARDED) & Q(created_at__gte=start_date)
                )
                .values(domain_name=F('domain__unique_name'))
                .annotate(onboarded_device_count=Count('id'))
            )

        except Exception as exception:
            err_msg = f'Error occurred in device count by domain query: {exception}'
            self.logger.exception(err_msg)
            return []

        return list(device_domain_qr)

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

            cert_counts_by_issuing_ca = list(cert_issuing_ca_qr)
        except Exception as exception:
            err_msg = f'Error occurred in certificate count by issuing ca query: {exception}'
            self.logger.exception(err_msg)

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

            cert_counts_by_issuing_ca_and_date = list(cert_issuing_ca_and_date_qr)
        except Exception as exception:
            err_msg = f'Error occurred in certificate count by issuing ca query: {exception}'
            self.logger.exception(err_msg)

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

            cert_counts_by_domain = list(cert_counts_domain_qr)
        except Exception as exception:
            err_msg = f'Error occurred in certificate count by issuing ca query: {exception}'
            self.logger.exception(err_msg)

        return cert_counts_by_domain

    def get_cert_counts_by_profile(self, start_date: datetime) -> dict[str, Any]:
        """Fetch certificate count grouped by profile from database.

        Args:
            start_date: The start date for fetching data.

        Returns:
            Dict of certificate count for each certificate profile.
        """
        profiles = CertificateProfileModel.objects.all()
        profile_mapping = {profile.id: profile.display_name for profile in profiles}
        cert_counts_by_profile = {profile.display_name: 0 for profile in profiles}
        try:
            cert_profile_qr = (
                IssuedCredentialModel.objects.filter(credential__certificates__created_at__gt=start_date)
                .values(cert_type=F('issued_using_cert_profile'))
                .annotate(count=Count('credential__certificates'))
            )

            for item in cert_profile_qr:
                profile_id = item['cert_type']
                display_name = profile_mapping.get(profile_id, str(profile_id))
                cert_counts_by_profile[display_name] = item['count']
        except Exception as exception:
            err_msg = f'Error occurred in certificate count by profile query: {exception}'
            self.logger.exception(err_msg)

        return cert_counts_by_profile

    def get_issuing_ca_counts_by_type(self, start_date: datetime) -> dict[str, Any]:
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

            protocol_mapping = {key: str(value) for key, value in IssuingCaModel.IssuingCaTypeChoice.choices}
            issuing_ca_type_counts = {protocol_mapping[item['issuing_ca_type']]: item['count'] for item in ca_type_qr}

        except Exception as exception:
            err_msg = f'Error occurred in ca counts by type query: {exception}'
            self.logger.exception(err_msg)
        return issuing_ca_type_counts

    def get_expiring_device_counts(self) -> dict[str, Any]:
        """Fetch expiring device counts from database.

        Returns:
            It returns counts of devices with expiring certificates.
        """
        now = timezone.now()
        next_7_days = now + timedelta(days=7)
        next_24_hours = now + timedelta(hours=24)
        expiring_device_counts = {}
        try:
            expiring_device_counts = {
                'expiring_in_24_hours': DeviceModel.objects.filter(
                    issued_credentials__credential__certificate__not_valid_after__gt=now,
                    issued_credentials__credential__certificate__not_valid_after__lte=next_24_hours
                ).distinct().count(),
                'expiring_in_7_days': DeviceModel.objects.filter(
                    issued_credentials__credential__certificate__not_valid_after__gt=now,
                    issued_credentials__credential__certificate__not_valid_after__lte=next_7_days
                ).distinct().count(),
            }
        except Exception as exception:
            err_msg = f'Error occurred in expiring device count query: {exception}'
            self.logger.exception(err_msg)

        return expiring_device_counts

    def get_expired_device_counts(self) -> dict[str, Any]:
        """Fetch expired device counts from database.

        Returns:
            It returns counts of devices with expired certificates.
        """
        now = timezone.now()
        last_7_days = now - timedelta(days=7)
        expired_device_counts = {}
        try:
            expired_device_counts = {
                'total_expired': DeviceModel.objects.filter(
                    issued_credentials__credential__certificate__not_valid_after__lt=now
                ).distinct().count(),
                'expired_in_last_7_days': DeviceModel.objects.filter(
                    issued_credentials__credential__certificate__not_valid_after__gte=last_7_days,
                    issued_credentials__credential__certificate__not_valid_after__lt=now
                ).distinct().count(),
            }
        except Exception as exception:
            err_msg = f'Error occurred in expired device count query: {exception}'
            self.logger.exception(err_msg)

        return expired_device_counts

    def get_expiring_issuing_ca_counts(self) -> dict[str, Any]:
        """Fetch expiring issuing CA counts from database.

        Returns:
            It returns counts of issuing CAs with expiring certificates.
        """
        now = timezone.now()
        next_7_days = now + timedelta(days=7)
        next_24_hours = now + timedelta(hours=24)
        expiring_issuing_ca_counts = {}
        try:
            expiring_issuing_ca_counts = {
                'expiring_in_24_hours': IssuingCaModel.objects.filter(
                    credential__certificate__not_valid_after__gt=now,
                    credential__certificate__not_valid_after__lte=next_24_hours
                ).count(),
                'expiring_in_7_days': IssuingCaModel.objects.filter(
                    credential__certificate__not_valid_after__gt=now,
                    credential__certificate__not_valid_after__lte=next_7_days
                ).count(),
            }
        except Exception as exception:
            err_msg = f'Error occurred in expiring issuing CA count query: {exception}'
            self.logger.exception(err_msg)

        return expiring_issuing_ca_counts


