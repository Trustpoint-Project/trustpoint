"""Contains views that handle HTTP requests and return appropriate responses for the application."""

from __future__ import annotations

from datetime import datetime, time, timedelta
from typing import Any

from django.contrib import messages
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db.models import Case, CharField, Count, F, IntegerField, Q, QuerySet, Value, When
from django.db.models.functions import TruncDate
from django.http import HttpRequest, HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect
from django.utils import dateparse, timezone
from django.views.generic.base import RedirectView, TemplateView

from devices.dashboard_filters import (
    filter_active_devices,
    filter_devices_with_active_application_certificates,
    filter_devices_with_expired_or_revoked_application_certificates,
    filter_devices_with_expired_or_revoked_domain_credential,
    filter_devices_with_expiring_domain_credential,
    filter_devices_with_expiring_domain_credential_in_1_day,
    filter_devices_with_expiring_domain_credential_in_7_days,
    filter_devices_with_valid_domain_credential,
    filter_devices_without_application_certificates,
    filter_devices_without_domain_credential,
    filter_expired_or_revoked_devices,
    filter_no_onboarding_devices,
    filter_onboarded_devices,
    filter_pending_devices,
)
from devices.models import DeviceModel
from onboarding.models import OnboardingProtocol, OnboardingStatus
from pki.models import CaModel, CertificateModel, CertificateProfileModel, IssuedCredentialModel
from trustpoint.logger import LoggerMixin

SUCCESS = 25
ERROR = 40


class IndexView(RedirectView):
    """Redirects authenticated users to the dashboard page."""

    permanent = False
    pattern_name = 'home:dashboard'


class DashboardView(TemplateView):
    """Renders the dashboard page for authenticated users. Uses the 'home/dashboard.html' template."""

    template_name = 'home/dashboard.html'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Fetch context data.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'home'
        context['page_name'] = 'dashboard'
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

    @staticmethod
    def _parse_dashboard_query_date(value: str, default_time: time) -> datetime | None:
        """Parse a dashboard query date from either YYYY-MM-DD or an ISO datetime string."""
        parsed_datetime = dateparse.parse_datetime(value)
        if parsed_datetime:
            if timezone.is_naive(parsed_datetime):
                return timezone.make_aware(parsed_datetime)
            return parsed_datetime

        parsed_date = dateparse.parse_date(value)
        if parsed_date:
            return timezone.make_aware(datetime.combine(parsed_date, default_time))

        return None

    @staticmethod
    def _apply_created_at_date_range(
        queryset: QuerySet[Any],
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> QuerySet[Any]:
        """Apply an inclusive created-at date range to a queryset."""
        if start_date is not None:
            queryset = queryset.filter(created_at__gte=start_date)

        if end_date is not None:
            queryset = queryset.filter(created_at__lt=end_date + timedelta(days=1))

        return queryset

    def _get_dashboard_dates(
        self,
        request: HttpRequest,
    ) -> tuple[datetime | None, datetime | None, datetime] | JsonResponse:
        """Parse and validate the dashboard date query parameters."""
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        reference_date = request.GET.get('reference_date')
        current_time = timezone.now()
        start_date_object: datetime | None = None
        end_date_object: datetime | None = None
        reference_date_object = timezone.make_aware(datetime.combine(current_time.date(), current_time.time()))

        if start_date:
            parsed_start_date = self._parse_dashboard_query_date(start_date, datetime.min.time())
            if not parsed_start_date:
                return JsonResponse({'error': 'Invalid start_date format. Use YYYY-MM-DD.'}, status=400)
            start_date_object = timezone.make_aware(datetime.combine(parsed_start_date.date(), datetime.min.time()))

        if end_date:
            parsed_end_date = self._parse_dashboard_query_date(end_date, datetime.min.time())
            if not parsed_end_date:
                return JsonResponse({'error': 'Invalid end_date format. Use YYYY-MM-DD.'}, status=400)
            end_date_object = timezone.make_aware(datetime.combine(parsed_end_date.date(), datetime.min.time()))

        if start_date_object is not None and end_date_object is not None and start_date_object > end_date_object:
            return JsonResponse({'error': 'start_date must be on or before end_date.'}, status=400)

        if reference_date:
            parsed_reference_date = self._parse_dashboard_query_date(reference_date, current_time.time())
            if not parsed_reference_date:
                return JsonResponse({'error': 'Invalid reference_date format. Use YYYY-MM-DD.'}, status=400)
            reference_date_object = parsed_reference_date
        elif end_date_object is not None:
            reference_date_object = timezone.make_aware(datetime.combine(end_date_object.date(), time.max))
        elif start_date_object is not None:
            reference_date_object = timezone.make_aware(
                datetime.combine(start_date_object.date(), current_time.time())
            )

        return start_date_object, end_date_object, reference_date_object

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        """Get dashboard data for panels, tables and charts.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The JSON response containing dashboard data.
        """
        del args
        del kwargs

        parsed_dates = self._get_dashboard_dates(request)
        if isinstance(parsed_dates, JsonResponse):
            return parsed_dates
        start_date_object, end_date_object, reference_date_object = parsed_dates
        dashboard_data: dict[str, Any] = {}

        device_dashboard_counts = self.get_device_dashboard_card_counts(reference_date_object)
        if device_dashboard_counts:
            dashboard_data['device_dashboard_counts'] = device_dashboard_counts

        device_counts = self.get_device_count_by_onboarding_status(start_date_object)

        expiring_device_counts = self.get_expiring_domain_credential_counts(reference_date_object)
        if expiring_device_counts:
            device_counts.update(expiring_device_counts)

        dashboard_data['device_counts'] = device_counts
        self.logger.debug('device counts %s', device_counts)

        cert_counts = self.get_cert_counts(reference_date_object)
        if cert_counts:
            dashboard_data['cert_counts'] = cert_counts

        issuing_ca_counts = self.get_issuing_ca_counts(reference_date_object)
        if issuing_ca_counts:
            dashboard_data['issuing_ca_counts'] = issuing_ca_counts

        expiring_issuing_ca_counts = self.get_expiring_issuing_ca_counts(reference_date_object)
        if expiring_issuing_ca_counts:
            dashboard_data['expiring_issuing_ca_counts'] = expiring_issuing_ca_counts

        self.get_device_charts_data(dashboard_data, start_date_object, reference_date_object)
        self.get_cert_charts_data(dashboard_data, start_date_object, end_date_object, reference_date_object)
        self.get_ca_charts_data(dashboard_data, start_date_object, end_date_object)

        return JsonResponse(dashboard_data)

    def get_device_charts_data(
        self,
        dashboard_data: dict[str, Any],
        start_date: datetime | None,
        reference_date: datetime,
    ) -> None:
        """Fetch data from database for device charts and add to dashboard data object.

        Args:
            dashboard_data: The dashboard data object.
            start_date: The start date for fetching device data.
            reference_date: The reference date for expiry-based device data.

        Returns:
            It returns nothing. It adds the device related data in dashboard_data object.
        """
        device_enrollment_counts = self.get_device_enrollment_counts(start_date)
        if device_enrollment_counts:
            dashboard_data['device_enrollment_counts'] = device_enrollment_counts

        device_domain_credential_counts = self.get_device_domain_credential_counts(reference_date)
        if device_domain_credential_counts:
            dashboard_data['device_domain_credential_counts'] = device_domain_credential_counts

        device_application_certificate_counts = self.get_device_application_certificate_counts(reference_date)
        if device_application_certificate_counts:
            dashboard_data['device_application_certificate_counts'] = device_application_certificate_counts

        expiring_application_certificate_counts = self.get_expiring_application_certificate_counts(reference_date)
        if expiring_application_certificate_counts:
            dashboard_data['expiring_application_certificate_counts'] = expiring_application_certificate_counts

        device_counts_by_op = self.get_device_count_by_onboarding_protocol(start_date)
        if device_counts_by_op:
            dashboard_data['device_counts_by_op'] = device_counts_by_op

        device_counts_by_domain = self.get_device_count_by_domain(start_date)
        if device_counts_by_domain:
            dashboard_data['device_counts_by_domain'] = device_counts_by_domain

    def get_cert_charts_data(
        self,
        dashboard_data: dict[str, Any],
        start_date: datetime | None,
        end_date: datetime | None,
        reference_date: datetime,
    ) -> None:
        """Fetch data from database for certificate charts and add to dashboard data object.

        Args:
            dashboard_data: The dashboard data object.
            start_date: The start date for fetching certificate data.
            end_date: The optional inclusive end date for period-based certificate charts.
            reference_date: The reference date for expiry-based certificate data.

        Returns:
            It returns nothing. It adds the certificate related data in dashboard_data object.
        """
        cert_counts_by_status = self.get_cert_counts_by_status(start_date, end_date, reference_date)
        if cert_counts_by_status:
            dashboard_data['cert_counts_by_status'] = cert_counts_by_status

        cert_counts_by_profile = self.get_cert_counts_by_profile(start_date, end_date)
        if cert_counts_by_profile:
            dashboard_data['cert_counts_by_profile'] = cert_counts_by_profile

    def get_ca_charts_data(
        self,
        dashboard_data: dict[str, Any],
        start_date: datetime | None,
        end_date: datetime | None,
    ) -> None:
        """Fetch data from database for issuing ca charts and add to dashboard data object.

        Args:
            dashboard_data: The dashboard data object.
            start_date: The start date for fetching issuing ca data.
            end_date: The optional inclusive end date for period-based issuing CA charts.

        Returns:
            It returns nothing. It adds the issuing ca related data in dashboard_data object.
        """
        cert_counts_by_issuing_ca = self.get_cert_counts_by_issuing_ca(start_date, end_date)
        if cert_counts_by_issuing_ca:
            dashboard_data['cert_counts_by_issuing_ca'] = cert_counts_by_issuing_ca

    def get_device_dashboard_card_counts(self, reference_date: datetime | None = None) -> dict[str, Any]:
        """Fetch device dashboard card counts based on real table filters."""
        try:
            devices = DeviceModel.objects.all()
            reference_time = reference_date or timezone.now()
            next_7_days = reference_time + timedelta(days=7)
            next_30_days = reference_time + timedelta(days=30)
            expiring_in_1_day = filter_devices_with_expiring_domain_credential_in_1_day(
                devices, reference_time
            ).count()
            expiring_in_7_days = filter_devices_with_expiring_domain_credential_in_7_days(
                devices, reference_time
            ).count()
            expiring_in_30_days = DeviceModel.objects.filter(
                issued_credentials__issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
                issued_credentials__credential__certificate__not_valid_after__gt=next_7_days,
                issued_credentials__credential__certificate__not_valid_after__lte=next_30_days,
            ).exclude(
                issued_credentials__issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
                issued_credentials__credential__certificate__not_valid_after__gt=next_30_days,
            ).exclude(
                issued_credentials__issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
                issued_credentials__credential__certificate__not_valid_after__gt=reference_time,
                issued_credentials__credential__certificate__not_valid_after__lte=next_7_days,
            ).distinct().count()

            return {
                'pending': filter_pending_devices(devices).count(),
                'valid': filter_devices_with_valid_domain_credential(devices, reference_time).count(),
                'expiring_in_1_day': expiring_in_1_day,
                'expiring_in_7_days': expiring_in_7_days,
                'expiring_in_30_days': expiring_in_30_days,
                'expired': filter_expired_or_revoked_devices(devices, reference_time).count(),
                'expiring': expiring_in_1_day + expiring_in_7_days + expiring_in_30_days,
            }
        except Exception as exception:
            err_msg = f'Error occurred in device dashboard card count query: {exception}'
            self.logger.exception(err_msg)
            return {}

    def get_device_enrollment_counts(self, start_date: datetime | None) -> dict[str, Any]:
        """Fetch device counts grouped by enrollment state."""
        try:
            del start_date
            devices = DeviceModel.objects.all()
            no_onboarding_count = filter_no_onboarding_devices(devices).count()
            pending_count = filter_pending_devices(devices).count()
            onboarded_count = filter_onboarded_devices(devices).count()

            return {
                'no_onboarding': no_onboarding_count,
                'pending': pending_count,
                'onboarded': onboarded_count,
                'total': no_onboarding_count + pending_count + onboarded_count,
            }
        except Exception as exception:
            err_msg = f'Error occurred in device enrollment count query: {exception}'
            self.logger.exception(err_msg)
            return {}

    def get_device_domain_credential_counts(self, reference_date: datetime | None = None) -> dict[str, Any]:
        """Fetch domain-credential states for devices that use onboarding."""
        try:
            devices = DeviceModel.objects.filter(onboarding_config__isnull=False)
            reference_time = reference_date or timezone.now()
            no_domain_credential_count = filter_devices_without_domain_credential(devices).count()
            valid_count = filter_devices_with_valid_domain_credential(devices, reference_time).count()
            expiring_count = filter_devices_with_expiring_domain_credential(devices, reference_time).count()
            expired_or_revoked_count = filter_devices_with_expired_or_revoked_domain_credential(
                devices, reference_time
            ).count()

            return {
                'none': no_domain_credential_count,
                'valid': valid_count,
                'expiring': expiring_count,
                'expired': expired_or_revoked_count,
                'total': no_domain_credential_count + valid_count + expiring_count + expired_or_revoked_count,
            }
        except Exception as exception:
            err_msg = f'Error occurred in device domain credential count query: {exception}'
            self.logger.exception(err_msg)
            return {}

    def get_device_application_certificate_counts(self, reference_date: datetime | None = None) -> dict[str, Any]:
        """Fetch application-certificate states for devices without onboarding."""
        try:
            devices = filter_no_onboarding_devices(DeviceModel.objects.all())
            reference_time = reference_date or timezone.now()
            none_count = filter_devices_without_application_certificates(devices).count()
            active_count = filter_devices_with_active_application_certificates(devices, reference_time).count()
            expired_or_revoked_count = filter_devices_with_expired_or_revoked_application_certificates(
                devices, reference_time
            ).count()

            return {
                'none': none_count,
                'active': active_count,
                'expired': expired_or_revoked_count,
                'total': none_count + active_count + expired_or_revoked_count,
            }
        except Exception as exception:
            err_msg = f'Error occurred in device application certificate count query: {exception}'
            self.logger.exception(err_msg)
            return {}

    def get_device_count_by_onboarding_status(self, start_date: datetime | None) -> dict[str, Any]:
        """Fetch device count by onboarding status from database.

        Active devices: Devices with NoOnboardingConfigModel OR OnboardingConfigModel with ONBOARDED status
        Pending devices: Devices with OnboardingConfigModel with PENDING status

        Args:
            start_date: The start date for fetching data.
            end_date: The optional inclusive end date for the created-at range.

        Returns:
            It returns device counts grouped by device onboarding status.
        """
        try:
            device_counts_expiring = self.get_expiring_device_counts(start_date or timezone.now())
            devices_after_start = self._apply_created_at_date_range(DeviceModel.objects.all(), start_date)
            device_counts_expired = self.get_expired_or_revoked_device_counts(devices_after_start)

            active_count = filter_active_devices(devices_after_start).count()
            pending_count = filter_pending_devices(devices_after_start).count()

            device_os_counts = {
                'Onboarded': active_count,
                'Pending': pending_count,
            }

            device_os_counts.update(device_counts_expiring)
            device_os_counts.update(device_counts_expired)
            device_os_counts['total'] = active_count + pending_count

            device_os_counts['active'] = active_count
            device_os_counts['pending'] = pending_count
            device_os_counts['expiring'] = (
                device_counts_expiring.get('expiring_in_1_day', 0) +
                device_counts_expiring.get('expiring_in_7_days', 0) +
                device_counts_expiring.get('expiring_in_30_days', 0)
            )
            device_os_counts['expired'] = device_counts_expired.get('expired', 0)

        except Exception as exception:
            err_msg = f'Error occurred in device count by onboarding protocol query: {exception}'
            self.logger.exception(err_msg)
            device_os_counts = {}

        return device_os_counts

    def get_cert_counts(self, reference_date: datetime | None = None) -> dict[str, Any]:
        """Fetch certificate count from database.

        Args:
            reference_date: The reference date to calculate expiration windows from.
                          If None, uses current time.

        Returns:
            It returns certificate counts.
        """
        cert_counts = {}

        now = reference_date or timezone.now()
        next_30_days = now + timedelta(days=30)
        next_7_days = now + timedelta(days=7)
        next_1_day = now + timedelta(days=1)
        next_2_days = now + timedelta(days=2)
        try:
            cert_counts = CertificateModel.objects.aggregate(
                total=Count('id'),
                active=Count(
                    'id',
                    filter=Q(
                        revoked_certificate__isnull=True,
                        not_valid_before__lte=now,
                        not_valid_after__gt=next_30_days,
                    ),
                ),
                expiring_in_1_day=Count(
                    'id',
                    filter=Q(
                        revoked_certificate__isnull=True,
                        not_valid_before__lte=now,
                        not_valid_after__gt=now,
                        not_valid_after__lte=next_1_day,
                    ),
                ),
                expiring_tomorrow=Count(
                    'id',
                    filter=Q(
                        revoked_certificate__isnull=True,
                        not_valid_before__lte=now,
                        not_valid_after__gt=next_1_day,
                        not_valid_after__lte=next_2_days,
                    ),
                ),
                expiring_in_7_days=Count(
                    'id',
                    filter=Q(
                        revoked_certificate__isnull=True,
                        not_valid_before__lte=now,
                        not_valid_after__gt=next_1_day,
                        not_valid_after__lte=next_7_days,
                    ),
                ),
                expiring_in_30_days=Count(
                    'id',
                    filter=Q(
                        revoked_certificate__isnull=True,
                        not_valid_before__lte=now,
                        not_valid_after__gt=next_7_days,
                        not_valid_after__lte=next_30_days,
                    ),
                ),
                expired=Count(
                    'id',
                    filter=Q(
                        revoked_certificate__isnull=True,
                        not_valid_after__lte=now,
                    ),
                ),
            )
        except Exception as exception:
            err_msg = f'Error occurred in certificate count query: {exception}'
            self.logger.exception(err_msg)

        return cert_counts

    def get_expiring_certificate_counts(self, reference_date: datetime | None = None) -> dict[str, int]:
        """Return only the expiring-certificate windows for charting."""
        cert_counts = self.get_cert_counts(reference_date)
        return {
            'expiring_in_1_day': cert_counts.get('expiring_in_1_day', 0),
            'expiring_tomorrow': cert_counts.get('expiring_tomorrow', 0),
            'expiring_in_7_days': cert_counts.get('expiring_in_7_days', 0),
            'expiring_in_30_days': cert_counts.get('expiring_in_30_days', 0),
        }

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

    def get_cert_counts_by_status(
        self,
        start_date: datetime | None,
        end_date: datetime | None = None,
        reference_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Fetch certs count by onboarding status from database.

        Args:
            start_date: The start date for fetching data.
            end_date: The optional inclusive end date for the created-at range.
            end_date: The inclusive end date for fetching data.
            reference_date: The point in time to evaluate certificate status at.

        Returns:
            It returns device counts grouped by device onboarding status.
        """
        status_mapping = {key: str(value) for key, value in CertificateModel.CertificateStatus.choices}
        cert_status_counts = dict.fromkeys(status_mapping.values(), 0)
        try:
            as_of_date = reference_date or end_date or timezone.now()
            cert_queryset = self._apply_created_at_date_range(
                CertificateModel.objects.all(),
                start_date,
                end_date,
            )
            cert_status_qr = (
                cert_queryset.annotate(
                    status_as_of=Case(
                        When(
                            revoked_certificate__revoked_at__lte=as_of_date,
                            then=Value(CertificateModel.CertificateStatus.REVOKED),
                        ),
                        When(
                            not_valid_before__gt=as_of_date,
                            then=Value(CertificateModel.CertificateStatus.NOT_YET_VALID),
                        ),
                        When(
                            not_valid_after__lte=as_of_date,
                            then=Value(CertificateModel.CertificateStatus.EXPIRED),
                        ),
                        default=Value(CertificateModel.CertificateStatus.OK),
                        output_field=CharField(),
                    )
                )
                .values('status_as_of')
                .annotate(cert_count=Count('id'))
            )
            cert_status_counts.update({
                status_mapping[item['status_as_of']]: item['cert_count'] for item in cert_status_qr
            })
        except Exception as exception:
            err_msg = f'Error occurred in cert counts by status query: {exception}'
            self.logger.exception(err_msg)
        return cert_status_counts

    def get_issuing_ca_counts(self, reference_date: datetime | None = None) -> dict[str, Any]:
        """Fetch issuing CA count from database.

        Args:
            reference_date: The reference date to calculate expiration windows from.
                If None, uses current time.

        Returns:
            It returns total, active and expired issuing CA counts.
        """
        reference_time = reference_date or timezone.now()
        issuing_ca_counts = {}
        try:
            expiring_issuing_ca_counts = self.get_expiring_issuing_ca_counts(reference_time)
            next_30_days = reference_time + timedelta(days=30)
            issuing_ca_counts = CaModel.objects.aggregate(
                total=Count('id'),
                active=Count(
                    Case(
                        When(credential__certificates__not_valid_after__gt=next_30_days, then=Value(1)),
                        output_field=IntegerField(),
                    )
                ),
                expired=Count(
                    Case(
                        When(credential__certificates__not_valid_after__lte=reference_time, then=Value(1)),
                        output_field=IntegerField(),
                    )
                ),
            )
            issuing_ca_counts.update(expiring_issuing_ca_counts)
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

    def get_device_count_by_onboarding_protocol(self, start_date: datetime | None) -> dict[str, Any]:
        """Fetch device count by onboarding protocol from database.

        Args:
            start_date: The start date for fetching data.
            end_date: The optional inclusive end date for the created-at range.

        Returns:
            It returns device count by onboarding protocol.
        """
        device_op_counts = {str(status): 0 for _, status in OnboardingProtocol.choices}
        try:
            device_op_qr = (
                self._apply_created_at_date_range(
                    DeviceModel.objects.filter(onboarding_config__isnull=False),
                    start_date,
                )
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

    def get_device_count_by_domain(self, start_date: datetime | None) -> list[dict[str, Any]]:
        """Fetch onboarded devices count grouped by domain from database.

        Args:
            start_date: The start date for fetching data.
            end_date: The optional inclusive end date for the created-at range.

        Returns:
            It returns onboarded devices count grouped by domain.
        """
        try:
            device_domain_qr = (
                self._apply_created_at_date_range(
                    DeviceModel.objects.filter(Q(onboarding_config__onboarding_status=OnboardingStatus.ONBOARDED)),
                    start_date,
                )
                .values(domain_name=F('domain__unique_name'))
                .annotate(onboarded_device_count=Count('id'))
            )

        except Exception as exception:
            err_msg = f'Error occurred in device count by domain query: {exception}'
            self.logger.exception(err_msg)
            return []

        return list(device_domain_qr)

    def get_cert_counts_by_issuing_ca(
        self,
        start_date: datetime | None,
        end_date: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch certificate count grouped by issuing ca from database.

        Args:
            start_date: The start date for fetching data.
            end_date: The optional inclusive end date for the created-at range.

        Returns:
            It returns certificate count grouped by the issuing CA model.
        """
        cert_counts_by_issuing_ca = []
        try:
            issuing_cas = CaModel.objects.filter(credential__isnull=False).exclude(
                ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT,
            ).order_by('unique_name')

            cert_counts_by_issuing_ca = [
                {
                    'ca_name': issuing_ca.unique_name,
                    'cert_count': self._apply_created_at_date_range(
                        issuing_ca.get_issued_certificates().filter(
                            Q(basic_constraints_extension__ca=False) | Q(basic_constraints_extension__isnull=True),
                            credential_set__issued_credential__isnull=False,
                        ),
                        start_date,
                        end_date,
                    ).distinct().count(),
                }
                for issuing_ca in issuing_cas
            ]
        except Exception as exception:
            err_msg = f'Error occurred in certificate count by issuing ca query: {exception}'
            self.logger.exception(err_msg)

        return cert_counts_by_issuing_ca

    def get_cert_counts_by_issuing_ca_and_date(
        self,
        start_date: datetime | None,
        end_date: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch certificate count grouped by issuing ca and date from database.

        Args:
            start_date: The start date for fetching data.
            end_date: The optional inclusive end date for the created-at range.

        Returns:
            It returns certificate count grouped by the issuing CA model and date.
        """
        cert_counts_by_issuing_ca_and_date = []
        try:
            issuing_cas = CaModel.objects.filter(credential__isnull=False).exclude(
                ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT,
            ).order_by('unique_name')

            for issuing_ca in issuing_cas:
                date_counts = (
                    self._apply_created_at_date_range(
                        issuing_ca.get_issued_certificates().filter(
                            Q(basic_constraints_extension__ca=False) | Q(basic_constraints_extension__isnull=True),
                            credential_set__issued_credential__isnull=False,
                        ),
                        start_date,
                        end_date,
                    )
                    .annotate(issue_date=TruncDate('created_at'))
                    .values('issue_date')
                    .annotate(cert_count=Count('id', distinct=True))
                    .order_by('issue_date')
                )

                cert_counts_by_issuing_ca_and_date.extend([
                    {
                        'issue_date': item['issue_date'],
                        'name': issuing_ca.unique_name,
                        'cert_count': item['cert_count'],
                    }
                    for item in date_counts
                ])
        except Exception as exception:
            err_msg = f'Error occurred in certificate count by issuing ca query: {exception}'
            self.logger.exception(err_msg)

        return cert_counts_by_issuing_ca_and_date

    def get_cert_counts_by_domain(
        self,
        start_date: datetime | None,
        end_date: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch certificate count grouped by domain from database.

        Args:
            start_date: The start date for fetching data.
            end_date: The optional inclusive end date for the created-at range.

        Returns:
            It returns certificate count grouped by domain.
        """
        cert_counts_by_domain = []
        try:
            cert_counts_domain_qr = (
                self._apply_created_at_date_range(
                    IssuedCredentialModel.objects.all(),
                    start_date,
                    end_date,
                )
                .values(domain_name=F('domain__unique_name'))
                .annotate(cert_count=Count('id'))
            )

            cert_counts_by_domain = list(cert_counts_domain_qr)
        except Exception as exception:
            err_msg = f'Error occurred in certificate count by issuing ca query: {exception}'
            self.logger.exception(err_msg)

        return cert_counts_by_domain

    def get_cert_counts_by_profile(
        self,
        start_date: datetime | None,
        end_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Fetch certificate count grouped by profile from database.

        Args:
            start_date: The start date for fetching data.
            end_date: The optional inclusive end date for the created-at range.

        Returns:
            Dict of certificate count for each certificate profile, plus CA certificates.
        """
        profiles = CertificateProfileModel.objects.all()
        profile_mapping = {profile.id: profile.display_name for profile in profiles}
        cert_counts_by_profile = {profile.display_name: 0 for profile in profiles}
        try:
            # Count device certificates by profile
            cert_profile_qr = (
                self._apply_created_at_date_range(
                    IssuedCredentialModel.objects.all(),
                    start_date,
                    end_date,
                ).filter(credential__certificates__isnull=False)
                .values(cert_type=F('issued_using_cert_profile'))
                .annotate(count=Count('credential__certificates', distinct=True))
            )

            for item in cert_profile_qr:
                profile_id = item['cert_type']
                display_name = profile_mapping.get(profile_id, str(profile_id))
                cert_counts_by_profile[display_name] = item['count']

            ca_cert_count = self._apply_created_at_date_range(
                CertificateModel.objects.all(),
                start_date,
                end_date,
            ).exclude(
                credential__issued_credential__isnull=False
            ).distinct().count()
            if ca_cert_count > 0:
                cert_counts_by_profile['CA Certificates'] = ca_cert_count
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
        ca_type_counts = {str(cert_type): 0 for _, cert_type in CaModel.CaTypeChoice.choices}
        try:
            ca_type_qr = (
                CaModel.objects.filter(created_at__gt=start_date)
                .values('ca_type')
                .annotate(count=Count('ca_type'))
            )

            protocol_mapping = {key: str(value) for key, value in CaModel.CaTypeChoice.choices}
            ca_type_counts = {protocol_mapping[item['ca_type']]: item['count'] for item in ca_type_qr}

        except Exception as exception:
            err_msg = f'Error occurred in ca counts by type query: {exception}'
            self.logger.exception(err_msg)
        return ca_type_counts

    def get_expiring_device_counts(self, reference_date: datetime | None = None) -> dict[str, Any]:
        """Fetch expiring domain credential counts from database.

        Args:
            reference_date: The reference date for calculating expiration windows. If None, uses current time.

        Returns:
            It returns counts of domain credentials with expiring certificates (not devices).
            expiring_in_1_day: 0-24 hours
            expiring_in_7_days: 1-7 days (excluding the 24-hour window)
        """
        if reference_date is None:
            reference_date = timezone.now()

        next_24_hours = reference_date + timedelta(hours=24)
        next_7_days = reference_date + timedelta(days=7)
        next_30_days = reference_date + timedelta(days=30)
        expiring_device_counts = {}
        try:
            expiring_device_counts = {
                'expiring_in_1_day': IssuedCredentialModel.objects.filter(
                    issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
                    credential__certificate__not_valid_after__gt=reference_date,
                    credential__certificate__not_valid_after__lte=next_24_hours
                ).count(),
                'expiring_in_7_days': IssuedCredentialModel.objects.filter(
                    issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
                    credential__certificate__not_valid_after__gt=next_24_hours,
                    credential__certificate__not_valid_after__lte=next_7_days
                ).count(),
                'expiring_in_30_days': IssuedCredentialModel.objects.filter(
                    issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
                    credential__certificate__not_valid_after__gt=next_7_days,
                    credential__certificate__not_valid_after__lte=next_30_days,
                ).count(),
            }
        except Exception as exception:
            err_msg = f'Error occurred in expiring domain credential count query: {exception}'
            self.logger.exception(err_msg)

        return expiring_device_counts

    def get_expiring_domain_credential_counts(self, reference_date: datetime | None = None) -> dict[str, Any]:
        """Return expiring domain-credential windows for charting."""
        return self.get_expiring_device_counts(reference_date)

    def get_expiring_application_certificate_counts(self, reference_date: datetime | None = None) -> dict[str, Any]:
        """Fetch expiring application-certificate counts from database."""
        if reference_date is None:
            reference_date = timezone.now()

        next_24_hours = reference_date + timedelta(hours=24)
        next_7_days = reference_date + timedelta(days=7)
        next_30_days = reference_date + timedelta(days=30)
        expiring_application_certificate_counts = {}
        try:
            expiring_application_certificate_counts = {
                'expiring_in_1_day': IssuedCredentialModel.objects.filter(
                    issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
                    credential__certificate__not_valid_after__gt=reference_date,
                    credential__certificate__not_valid_after__lte=next_24_hours,
                ).count(),
                'expiring_in_7_days': IssuedCredentialModel.objects.filter(
                    issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
                    credential__certificate__not_valid_after__gt=next_24_hours,
                    credential__certificate__not_valid_after__lte=next_7_days,
                ).count(),
                'expiring_in_30_days': IssuedCredentialModel.objects.filter(
                    issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
                    credential__certificate__not_valid_after__gt=next_7_days,
                    credential__certificate__not_valid_after__lte=next_30_days,
                ).count(),
            }
        except Exception as exception:
            err_msg = f'Error occurred in expiring application certificate count query: {exception}'
            self.logger.exception(err_msg)

        return expiring_application_certificate_counts

    def get_expiring_issuing_ca_counts(self, reference_date: datetime | None = None) -> dict[str, Any]:
        """Fetch expiring issuing CA counts from database.

        Args:
            reference_date: The reference date for calculating expiration windows. If None, uses current time.

        Returns:
            It returns counts of issuing CAs with expiring certificates.
            expiring_in_1_day: 0-24 hours
            expiring_tomorrow: 24-48 hours
            expiring_in_7_days: 2-7 days
            expiring_in_30_days: 8-30 days
            expiring_in_365_days: 31-365 days
        """
        now = reference_date or timezone.now()
        next_24_hours = now + timedelta(hours=24)
        next_48_hours = now + timedelta(hours=48)
        next_7_days = now + timedelta(days=7)
        next_30_days = now + timedelta(days=30)
        next_365_days = now + timedelta(days=365)
        expiring_issuing_ca_counts = {}
        try:
            expiring_issuing_ca_counts = {
                'expiring_in_1_day': CaModel.objects.filter(
                    credential__certificate__revoked_certificate__isnull=True,
                    credential__certificate__not_valid_before__lte=now,
                    credential__certificate__not_valid_after__gt=now,
                    credential__certificate__not_valid_after__lte=next_24_hours
                ).distinct().count(),
                'expiring_tomorrow': CaModel.objects.filter(
                    credential__certificate__revoked_certificate__isnull=True,
                    credential__certificate__not_valid_before__lte=now,
                    credential__certificate__not_valid_after__gt=next_24_hours,
                    credential__certificate__not_valid_after__lte=next_48_hours,
                ).distinct().count(),
                'expiring_in_7_days': CaModel.objects.filter(
                    credential__certificate__revoked_certificate__isnull=True,
                    credential__certificate__not_valid_before__lte=now,
                    credential__certificate__not_valid_after__gt=next_24_hours,
                    credential__certificate__not_valid_after__lte=next_7_days
                ).distinct().count(),
                'expiring_in_30_days': CaModel.objects.filter(
                    credential__certificate__revoked_certificate__isnull=True,
                    credential__certificate__not_valid_before__lte=now,
                    credential__certificate__not_valid_after__gt=next_7_days,
                    credential__certificate__not_valid_after__lte=next_30_days,
                ).distinct().count(),
                'expiring_in_365_days': CaModel.objects.filter(
                    credential__certificate__revoked_certificate__isnull=True,
                    credential__certificate__not_valid_before__lte=now,
                    credential__certificate__not_valid_after__gt=next_30_days,
                    credential__certificate__not_valid_after__lte=next_365_days,
                ).distinct().count(),
            }
        except Exception as exception:
            err_msg = f'Error occurred in expiring issuing CA count query: {exception}'
            self.logger.exception(err_msg)

        return expiring_issuing_ca_counts

    def get_expired_or_revoked_device_counts(
        self,
        queryset: Any = None,
        reference_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Fetch expired-or-revoked device counts from database.

        Expired devices either lost their last usable domain credential or, for
        non-onboarding devices, only have expired or revoked application certificates left.

        Returns:
            It returns counts of expired devices.
        """
        expired_device_counts = {}
        try:
            device_queryset = queryset if queryset is not None else DeviceModel.objects.all()
            expired_device_counts = {
                'expired': filter_expired_or_revoked_devices(device_queryset, reference_date).count()
            }
        except Exception as exception:
            err_msg = f'Error occurred in expired device count query: {exception}'
            self.logger.exception(err_msg)

        return expired_device_counts
