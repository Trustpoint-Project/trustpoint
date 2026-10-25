# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Persist profile-issued credentials and associate them with devices and domains."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from pki.models.credential import CredentialModel
from pki.models.issued_credential import IssuedCredentialModel, RemoteIssuedCredentialModel
from trustpoint.logger import LoggerMixin
from workflows2.integrations.certificates import emit_certificate_issued_for_record

if TYPE_CHECKING:
    from collections.abc import Callable

    from cryptography import x509
    from trustpoint_core.serializer import CredentialSerializer

    from devices.models import DeviceModel
    from pki.models.domain import DomainModel


TKeylessSavedRecord = TypeVar('TKeylessSavedRecord', bound=object)


@dataclass(frozen=True)
class KeylessCredentialSaveConfig(Generic[TKeylessSavedRecord]):  # noqa: UP046
    """Configuration for saving a keyless credential record."""

    certificate: x509.Certificate
    certificate_chain: list[x509.Certificate]
    existing_records: Any
    create_record: Callable[[], TKeylessSavedRecord]
    issued_using_cert_profile: str
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
        issued_using_cert_profile: str,
    ) -> IssuedCredentialModel:
        """Saves the issued credential in the database.

        Args:
            credential: The credential serializer instance.
            common_name: The common name for the credential.
            issued_credential_type: The type of issued credential.
            issued_using_cert_profile: The profile used for issuing the credential.

        Returns:
            The saved issued credential model.
        """
        self.logger.info(
            "Saving credential for device '%s' (ID: %s) "
            "in domain '%s' - CN: '%s', "
            "Type: %s, Profile: %s",
            self.device.common_name,
            self.device.pk,
            self.domain.unique_name,
            common_name,
            issued_credential_type.label,
            issued_using_cert_profile,
        )
        try:
            credential_model = CredentialModel.save_credential_serializer(
                credential_serializer=credential, credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
            )

            issued_credential_model = IssuedCredentialModel(
                issued_credential_type=issued_credential_type,
                issued_using_cert_profile=issued_using_cert_profile,
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
                self.device.common_name
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

                if hasattr(existing_record, 'issued_using_cert_profile'):
                    existing_record.issued_using_cert_profile = save_config.issued_using_cert_profile
                    existing_record.save()
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

    def _save_keyless_credential(
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        common_name: str,
        issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
        issued_using_cert_profile: str,
    ) -> IssuedCredentialModel:

        self.logger.info(
            "Saving keyless credential for device '%s' (ID: %s) "
            "in domain '%s' - CN: '%s', "
            "Type: %s, Profile: %s",
            self.device.common_name,
            self.device.pk,
            self.domain.unique_name,
            common_name,
            issued_credential_type.label,
            issued_using_cert_profile,
        )

        def create_record() -> IssuedCredentialModel:
            credential_model = CredentialModel.save_keyless_credential(
                certificate=certificate,
                certificate_chain=certificate_chain,
                credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
            )

            issued_credential_model = IssuedCredentialModel(
                issued_credential_type=issued_credential_type,
                issued_using_cert_profile=issued_using_cert_profile,
                common_name=common_name,
                credential=credential_model,
                device=self.device,
                domain=self.domain,
            )

            issued_credential_model.save()
            return issued_credential_model

        return self._save_or_update_keyless_credential_record(
            KeylessCredentialSaveConfig(
                certificate=certificate,
                certificate_chain=certificate_chain,
                existing_records=IssuedCredentialModel.objects.filter(
                    device=self.device,
                    domain=self.domain,
                    issued_credential_type=issued_credential_type,
                    common_name=common_name,
                ),
                create_record=create_record,
                issued_using_cert_profile=issued_using_cert_profile,
                success_log="Successfully saved keyless IssuedCredentialModel (ID: %s) for device '%s'",
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
        cert_profile_disp_name: str,
    ) -> IssuedCredentialModel:
        """Saves a credential with a private key to the database."""
        return self._save(
            credential,
            common_name,
            issued_credential_type,
            cert_profile_disp_name,
        )

    def save_keyless_credential(
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        common_name: str,
        issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
        cert_profile_disp_name: str,
    ) -> IssuedCredentialModel:
        """Saves a keyless (i.e. private key stays on requesting device) credential to the database."""
        return self._save_keyless_credential(
            certificate, certificate_chain, common_name, issued_credential_type, cert_profile_disp_name)

    def save_remote_keyless_credential(
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        common_name: str,
        issued_using_cert_profile: str,
    ) -> RemoteIssuedCredentialModel:
        """Saves a keyless credential issued via a remote/RA CA as a RemoteIssuedCredentialModel."""
        self.logger.info(
            "Saving remote keyless credential for device '%s' (ID: %s) "
            "in domain '%s' - CN: '%s', Profile: %s",
            self._device.common_name,
            self._device.pk,
            self._domain.unique_name,
            common_name,
            issued_using_cert_profile,
        )

        def create_record() -> RemoteIssuedCredentialModel:
            credential_model = CredentialModel.save_keyless_credential(
                certificate=certificate,
                certificate_chain=certificate_chain,
                credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
            )
            remote_issued = RemoteIssuedCredentialModel(
                issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.RA_DEVICE,
                issued_using_cert_profile=issued_using_cert_profile,
                common_name=common_name,
                credential=credential_model,
                device=self._device,
                domain=self._domain,
            )
            remote_issued.save()
            return remote_issued

        return self._save_or_update_keyless_credential_record(
            KeylessCredentialSaveConfig(
                certificate=certificate,
                certificate_chain=certificate_chain,
                existing_records=RemoteIssuedCredentialModel.objects.filter(
                    device=self._device,
                    domain=self._domain,
                    issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.RA_DEVICE,
                    common_name=common_name,
                ),
                create_record=create_record,
                issued_using_cert_profile=issued_using_cert_profile,
                success_log="Successfully saved RemoteIssuedCredentialModel (ID: %s) for device '%s'",
            )
        )
