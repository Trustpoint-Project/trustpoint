# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Persist profile-issued credentials and associate them with devices and domains."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast

from pki.models.credential import CredentialModel
from pki.models.issued_credential import IssuedCredentialModel, RemoteIssuedCredentialModel
from trustpoint.logger import LoggerMixin
from workflows2.integrations.certificates import emit_certificate_issued_for_record

if TYPE_CHECKING:
    from collections.abc import Callable

    from cryptography import x509
    from trustpoint_core.serializer import CredentialSerializer

    from devices.models import DeviceModel
    from pki.models.cert_profile import CertificateProfileModel
    from pki.models.domain import DomainModel


TKeylessSavedRecord = TypeVar('TKeylessSavedRecord', bound=object)


@dataclass(frozen=True)
class KeylessCredentialSaveConfig(Generic[TKeylessSavedRecord]):  # noqa: UP046
    """Configuration for saving a keyless credential record."""

    certificate: x509.Certificate
    certificate_chain: list[x509.Certificate]
    existing_records: Any
    create_record: Callable[[], TKeylessSavedRecord]
    certificate_profile: CertificateProfileModel
    success_log: str


class SaveCredentialToDbMixin(LoggerMixin):
    """Mixin to handle saving credentials to the database."""

    @property
    def device(self) -> DeviceModel:
        """Abstract property that has to be implemented by the derived class."""
        raise NotImplementedError

    @property
    def domain(self) -> DomainModel:
        """Abstract property that has to be implemented by the derived class."""
        raise NotImplementedError

    def _save(
        self,
        credential: CredentialSerializer,
        common_name: str,
        issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
        certificate_profile: CertificateProfileModel,
    ) -> IssuedCredentialModel:
        """Saves the issued credential in the database.

        Args:
            credential: The credential serializer instance.
            common_name: The common name for the credential.
            issued_credential_type: The type of issued credential.
            certificate_profile: The profile used for issuing the credential.

        Returns:
            The saved issued credential model.
        """
        self.logger.info(
            "Saving credential for device '%s' (ID: %s) in domain '%s' - CN: '%s', Type: %s, Profile: %s",
            self.device.common_name,
            self.device.pk,
            self.domain.unique_name,
            common_name,
            issued_credential_type.label,
            certificate_profile,
        )
        try:
            credential_model = CredentialModel.save_credential_serializer(
                credential_serializer=credential, credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
            )

            issued_credential_model = IssuedCredentialModel(
                issued_credential_type=issued_credential_type,
                certificate_profile=certificate_profile,
                common_name=common_name,
                credential=credential_model,
                device=self.device,
                domain=self.domain,
            )

            issued_credential_model.save()

        except Exception:
            self.logger.exception(
                "Failed to save credential for device '%s' (ID: %s)",
                self.device.common_name,
                self.device.pk,
            )
            raise
        else:
            self.logger.info(
                "Successfully saved IssuedCredentialModel (ID: %s) for device '%s'",
                issued_credential_model.pk,
                self.device.common_name,
            )
            return issued_credential_model

    def _save_or_update_keyless_credential_record(
        self,
        save_config: KeylessCredentialSaveConfig[TKeylessSavedRecord],
    ) -> TKeylessSavedRecord:
        """Save or update a keyless credential record while preserving the existing record semantics."""
        try:
            existing_record = save_config.existing_records.first()
            if existing_record is not None:
                cred_model = existing_record.credential
                cred_model.update_keyless_credential(save_config.certificate, save_config.certificate_chain)
                cred_model.save()

                existing_record.certificate_profile = save_config.certificate_profile
                existing_record.save(update_fields=['certificate_profile'])
                emit_certificate_issued_for_record(existing_record)
                return existing_record  # type: ignore[no-any-return]

            saved_record = save_config.create_record()
        except Exception:
            self.logger.exception(
                "Failed to save keyless credential for device '%s' (ID: %s)",
                self.device.common_name,
                self.device.pk,
            )
            raise

        self.logger.info(
            save_config.success_log,
            saved_record.pk,  # type: ignore[attr-defined]
            self.device.common_name,
        )
        return saved_record

    def _save_keyless_credential(  # noqa: PLR0913
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        common_name: str,
        issued_credential_type: (
            IssuedCredentialModel.IssuedCredentialType
            | RemoteIssuedCredentialModel.RemoteIssuedCredentialType
        ),
        certificate_profile: CertificateProfileModel,
        *,
        remote: bool = False,
    ) -> IssuedCredentialModel | RemoteIssuedCredentialModel:
        record_model = RemoteIssuedCredentialModel if remote else IssuedCredentialModel

        self.logger.info(
            "Saving %skeyless credential for device '%s' (ID: %s) in domain '%s' - CN: '%s', Type: %s, Profile: %s",
            'remote ' if remote else '',
            self.device.common_name,
            self.device.pk,
            self.domain.unique_name,
            common_name,
            issued_credential_type.label,
            certificate_profile,
        )

        def create_record() -> IssuedCredentialModel | RemoteIssuedCredentialModel:
            credential_model = CredentialModel.save_keyless_credential(
                certificate=certificate,
                certificate_chain=certificate_chain,
                credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
            )
            record = record_model(
                issued_credential_type=issued_credential_type,
                certificate_profile=certificate_profile,
                common_name=common_name,
                credential=credential_model,
                device=self.device,
                domain=self.domain,
            )
            record.save()
            return record

        return self._save_or_update_keyless_credential_record(
            KeylessCredentialSaveConfig(
                certificate=certificate,
                certificate_chain=certificate_chain,
                existing_records=record_model.objects.filter(
                    device=self.device,
                    domain=self.domain,
                    issued_credential_type=issued_credential_type,
                    common_name=common_name,
                ),
                create_record=create_record,
                certificate_profile=certificate_profile,
                success_log=(
                    "Successfully saved keyless RemoteIssuedCredentialModel (ID: %s) for device '%s'"
                    if remote
                    else "Successfully saved keyless IssuedCredentialModel (ID: %s) for device '%s'"
                ),
            )
        )


class CredentialSaver(SaveCredentialToDbMixin):
    """A basic class for saving credentials to the database."""

    def __init__(self, device: DeviceModel, domain: DomainModel) -> None:
        """Initializes the Credential Saver.

        Args:
            device: The device for which the credential is saved.
            domain: The domain associated with the credential.
        """
        self._device = device
        self._domain = domain

    @property
    def device(self) -> DeviceModel:
        """Gets the device associated with this credential saver.

        Returns:
            DeviceModel: The device linked to the issued credential.
        """
        return self._device

    @property
    def domain(self) -> DomainModel:
        """Gets the domain associated with this credential saver.

        Returns:
            DomainModel: The domain linked to the issued credential.
        """
        return self._domain

    def save_credential(
        self,
        credential: CredentialSerializer,
        common_name: str,
        issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
        certificate_profile: CertificateProfileModel,
    ) -> IssuedCredentialModel:
        """Saves a credential with a private key to the database."""
        return self._save(
            credential,
            common_name,
            issued_credential_type,
            certificate_profile,
        )

    def save_keyless_credential(
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        common_name: str,
        issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
        certificate_profile: CertificateProfileModel,
    ) -> IssuedCredentialModel:
        """Saves a keyless (i.e. private key stays on requesting device) credential to the database."""
        return cast(
            'IssuedCredentialModel',
            self._save_keyless_credential(
                certificate, certificate_chain, common_name, issued_credential_type, certificate_profile
            ),
        )

    def save_remote_keyless_credential(
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        common_name: str,
        certificate_profile: CertificateProfileModel,
    ) -> RemoteIssuedCredentialModel:
        """Saves a keyless credential issued via a remote/RA CA as a RemoteIssuedCredentialModel."""
        return cast(
            'RemoteIssuedCredentialModel',
            self._save_keyless_credential(
                certificate,
                certificate_chain,
                common_name,
                RemoteIssuedCredentialModel.RemoteIssuedCredentialType.RA_DEVICE,
                certificate_profile,
                remote=True,
            ),
        )
