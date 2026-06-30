"""Manually reprobe a crypto provider and persist the capability snapshot."""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from crypto.application.backend_factory import DefaultBackendAdapterFactory
from crypto.application.capabilities import BackendCapabilityService
from crypto.domain.errors import CryptoError
from crypto.models import CryptoProviderProfileModel
from crypto.repositories import CryptoProviderProfileRepository


class Command(BaseCommand):
    """Reprobe a configured crypto provider profile and persist the capability snapshot."""

    help = "Reprobe a crypto provider profile and persist the capability snapshot."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--profile",
            type=str,
            help="Provider profile name. If omitted, the configured instance backend profile is used.",
        )

    def handle(self, *args, **options):
        profile_name = options.get("profile")
        repository = CryptoProviderProfileRepository()
        adapter_factory = DefaultBackendAdapterFactory()

        if profile_name:
            try:
                profile = CryptoProviderProfileModel.objects.get(name=profile_name)
            except CryptoProviderProfileModel.DoesNotExist as exc:
                raise CommandError(f"Provider profile {profile_name!r} does not exist.") from exc
        else:
            try:
                profile = repository.get_configured_profile()
            except CryptoProviderProfileModel.DoesNotExist as exc:
                raise CommandError("No configured crypto backend profile exists for this Trustpoint instance.") from exc

        try:
            backend = adapter_factory.build(profile)
            try:
                capabilities = backend.refresh_capabilities()
                result = repository.record_probe_success(profile=profile, capabilities=capabilities)
            finally:
                backend.close()
            report = None
            if not profile_name:
                report = BackendCapabilityService(
                    profile_repository=repository,
                    adapter_factory=adapter_factory,
                ).active_report()
        except CryptoError as exc:
            repository.record_probe_failure(profile=profile, error_summary=str(exc))
            raise CommandError(f"Provider reprobe failed: {exc}") from exc

        report_details = ''
        if report is not None:
            report_details = (
                f" rsa_key_sizes={','.join(str(size) for size in report.rsa_key_sizes) or '-'} "
                f"ec_curves={','.join(curve.value for curve in report.ec_curves) or '-'}"
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Reprobe succeeded for profile {profile.name!r}. "
                f"backend_kind={profile.backend_kind} "
                f"snapshot_id={result.snapshot_id} changed={result.changed} hash={result.probe_hash}"
                f"{report_details}"
            )
        )
