"""Manually reprobe a crypto provider and persist the capability snapshot."""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from crypto.application.backend_factory import DefaultBackendAdapterFactory
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
        except CryptoError as exc:
            repository.record_probe_failure(profile=profile, error_summary=str(exc))
            raise CommandError(f"Provider initialization failed: {exc}") from exc

        try:
            capabilities = backend.refresh_capabilities()
            result = repository.record_probe_success(profile=profile, capabilities=capabilities)
        except CryptoError as exc:
            repository.record_probe_failure(profile=profile, error_summary=str(exc))
            raise CommandError(f"Provider reprobe failed: {exc}") from exc
        finally:
            backend.close()

        self.stdout.write(
            self.style.SUCCESS(
                f"Reprobe succeeded for profile {profile.name!r}. "
                f"backend_kind={profile.backend_kind} "
                f"snapshot_id={result.snapshot_id} changed={result.changed} hash={result.probe_hash}"
            )
        )
