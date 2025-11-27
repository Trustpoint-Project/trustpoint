"""This module contains classes and functions used by all help pages."""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.http import Http404
from django.urls import reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _non_lazy
from django.utils.translation import gettext_lazy as _
from pki.models.domain import DomainAllowedCertificateProfileModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel

from help_pages.commands import KeyGenCommandBuilder
from help_pages.help_section import HelpRow, HelpSection, ValueRenderType

if TYPE_CHECKING:
    from typing import Self

    from devices.models import DeviceModel
    from pki.models import DevIdRegistration
    from pki.models.domain import DomainModel
    from trustpoint_core import oid


# ----------------------------------------- Application Certificate Profiles ------------------------------------------


@dataclass(frozen=True)
class ApplicationCertificateProfileData:
    """The application certificate profile data class that holds both profile_name and profile_label."""

    profile_name: str
    profile_label: str


class ApplicationCertificateProfile(enum.Enum):
    """Allowed application credential profiles."""

    TLS_CLIENT = ApplicationCertificateProfileData('tls_client', 'TLS-Client Certificate')
    TLS_SERVER = ApplicationCertificateProfileData('tls_server', 'TLS-Server Certificate')
    OPC_UA_CLIENT = ApplicationCertificateProfileData('opc_ua_client', 'OPC-UA-Client Certificate')
    OPC_UA_SERVER = ApplicationCertificateProfileData('opc_ua_server', 'OPC-UA-Server Certificate')

    @property
    def profile_name(self) -> str:
        """Return the name of the profile.

        Returns:
            The name of the profile.
        """
        return self.value.profile_name

    @property
    def profile_label(self) -> str:
        """Return the label of the profile.

        Returns:
            The label of the profile.
        """
        return self.value.profile_label

    @classmethod
    def from_profile_name(cls, profile_name: str) -> Self:
        """Gets the ApplicationCertificateProfile matching the name.

        Returns:
            The matching ApplicationCertificateProfile.

        Raises:
            ValueError: If no matching ApplicationCertificateProfile is found for the profile name provided.
        """
        for member in cls:
            if member.value.profile_name == profile_name:
                return member
        err_msg = f'No ApplicationCertificateProfile with profile_name={profile_name} found.'
        raise ValueError(err_msg)

    @classmethod
    def from_label(cls, profile_label: str) -> Self:
        """Gets the ApplicationCertificateProfile matching the label.

        Returns:
            The matching ApplicationCertificateProfile.

        Raises:
            ValueError: If no matching ApplicationCertificateProfile is found for the label provided.
        """
        for member in cls:
            if member.value.profile_label == profile_label:
                return member
        err_msg = f'No ApplicationCertificateProfile with profile_label={profile_label} found.'
        raise ValueError(err_msg)

    def __str__(self) -> str:
        """Gets the profile_label as human-readable string.

        Returns:
            The profile_label.
        """
        return self.profile_label


# --------------------------------------------------- Base Classes ----------------------------------------------------


class HelpPageStrategy(abc.ABC):
    """Abstract base class for help page strategies."""

    @abc.abstractmethod
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        """Builds the required sections."""


@dataclass(frozen=True)
class HelpContext:
    """Holds shared context data."""

    domain: DomainModel
    domain_unique_name: str
    allowed_app_profiles: list[DomainAllowedCertificateProfileModel]
    public_key_info: oid.PublicKeyInfo
    host_base: str  # https://IP:PORT
    host_cmp_path: str  # {host_base}/.well-known/cmp/p/{domain.unique_name}
    host_est_path: str  # {host_base}/.well-known/est/{domain.unique_name}
    cred_count: int  # Running number to avoid overriding files on the client side
    device: None | DeviceModel = None
    devid_registration: None | DevIdRegistration = None

    def get_device_or_http_404(self) -> DeviceModel:
        """Gets the device or throws an HTTP404 error.

        Raises:
            Http404: If the device does not exist.

        Returns:
            The DeviceModel.
        """
        if self.device is None:
            err_msg = 'Device not found.'
            raise Http404(err_msg)
        return self.device

    def get_devid_registration_or_http_404(self) -> DevIdRegistration:
        """Gets the DevidRegistration or throws an HTTP404 error.

        Raises:
            Http404: If the DevidRegistration does not exist.

        Returns:
            The DevidRegistration.
        """
        if self.devid_registration is None:
            err_msg = 'DevidRegistration not found.'
            raise Http404(err_msg)
        return self.devid_registration


# ----------------------------------------- Reusable section build functions ------------------------------------------


def build_keygen_section(help_context: HelpContext, file_name: str) -> HelpSection:
    """Builds the key-generation section.

    Args:
        help_context: The help context which will
        file_name: The file_name to use if the default shall not be used. Defaults to None.

    Returns:
        The key-generation section.
    """
    cmd = KeyGenCommandBuilder.get_key_gen_command(
        public_key_info=help_context.public_key_info, cred_number=help_context.cred_count, key_name=file_name
    )
    return HelpSection(
        _non_lazy('Key Generation'), [HelpRow(_non_lazy('Generate Key-Pair'), cmd, ValueRenderType.CODE)]
    )


def build_profile_select_section(app_cert_profiles: list[DomainAllowedCertificateProfileModel]) -> HelpSection:
    """Builds the profile select section.

    Returns:
        The profile select section.
    """
    options = mark_safe('')
    for i, profile in enumerate(app_cert_profiles):
        name = profile.alias or profile.certificate_profile.unique_name
        title = profile.certificate_profile.display_name or name
        options += format_html(
            '<option value="{}"{}>{}</option>',
            name,
            ' selected' if i == 0 else '',
            title,
        )

    if not options:
        options = format_html('<option value="" selected disabled>{}</option>',
                              _('No application certificate profiles allowed in domain.'))
    select = format_html(
        '<select id="cert-profile-select" class="form-select" aria-label="Certificate Profile Select">{}</select>',
        options,
    )
    return HelpSection(
        _non_lazy('Certificate Profile Selection'),
        [HelpRow(_non_lazy('Certificate Profile'), select, ValueRenderType.PLAIN)],
    )


def build_tls_trust_store_section() -> HelpSection:
    """Builds the TLS trust-store section.

    Raises:
        Http404: If no active Trustpoint TLS-server credential is found or the root CA cert is missing.

    Returns:
        The TLS trust-store section.
    """
    tls = ActiveTrustpointTlsServerCredentialModel.objects.first()
    if not tls or not tls.credential:
        return HelpSection(
            _non_lazy('TLS not available'),
            [HelpRow(_non_lazy('TLS not available'), '-', ValueRenderType.PLAIN)],
        )

    root = tls.credential.get_last_in_chain()
    if not root:
        raise Http404(_('Root CA certificate is missing.'))
    url = reverse(
        'pki:certificate-file-download-file-name',
        kwargs={'file_format': 'pem', 'pk': root.pk, 'file_name': 'trustpoint-tls-trust-store.pem'},
    )
    btn = format_html('<a class="btn btn-primary w-100" href="{}">{}</a>', url, _('Download TLS Trust-Store'))
    return HelpSection(
        _non_lazy('Download TLS Trust-Store'),
        [HelpRow(_non_lazy('Download TLS Trust-Store'), btn, ValueRenderType.PLAIN)],
    )


def build_cmp_signer_trust_store_section(domain: DomainModel) -> HelpSection:
    """Builds the CMP-signer trust-store section.

    Returns:
        The CMP-signer trust-store section.
    """
    issuing_ca = domain.issuing_ca
    if not issuing_ca:
        err_msg = 'Issuing CA not configured'
        raise ValueError(err_msg)
    root_ca_model = issuing_ca.credential.get_last_in_chain()
    if not root_ca_model:
        err_msg = 'No Root CA certificate found.'
        raise ValueError(err_msg)
    cmp_signer_pk = root_ca_model.pk

    download_tls_truststore_row = HelpRow(
        key=_non_lazy('Download CMP-Signer Trust-Store'),
        value=format_html(
            '<a href="{}" class="btn btn-primary w-100">{}</a>',
            reverse(
                'pki:certificate-file-download-file-name',
                kwargs={'file_format': 'pem', 'pk': cmp_signer_pk, 'file_name': 'domain-credential-full-chain.pem'},
            ),
            _non_lazy('Download CMP-Signer Trust-Store'),
        ),
        value_render_type=ValueRenderType.PLAIN,
    )

    return HelpSection(heading=_non_lazy('Download CMP-Signer Trust-Store'), rows=[download_tls_truststore_row])


def build_issuing_ca_cert_section(domain: DomainModel) -> HelpSection:
    """Builds the Issuing CA Certificate section.

    Returns:
        The Issuing CA Certificate section.
    """
    issuing_ca = domain.issuing_ca
    if not issuing_ca:
        err_msg = 'Issuing CA not configured'
        raise ValueError(err_msg)
    issuing_ca_pk = issuing_ca.pk

    download_issuing_ca_cert_row = HelpRow(
        key=_non_lazy('Download Issuing CA Certificate'),
        value=format_html(
            '<a href="{}" class="btn btn-primary w-100">{}</a>',
            reverse(
                'pki:certificate-file-download-file-name',
                kwargs={'file_format': 'pem', 'pk': issuing_ca_pk, 'file_name': 'issuing_ca_cert.pem'},
            ),
            _non_lazy('Download Issuing CA Certificate'),
        ),
        value_render_type=ValueRenderType.PLAIN,
    )

    return HelpSection(heading=_non_lazy('Download Issuing CA Certificate'), rows=[download_issuing_ca_cert_row])


def build_extract_files_from_p12_section() -> HelpSection:
    """Builds the extract files form P12 section.

    Returns:
        The extract files form P12 section.
    """
    intro_row = HelpRow(
        key=_non_lazy('Instructions'),
        value=_non_lazy(
            'If only a .p12 or .pfx file is available, you need to extract the certificate and '
            'private key to use it with the OpenSSL CMP command.'
        ),
        value_render_type=ValueRenderType.PLAIN,
    )

    p12_cert_row = HelpRow(
        key=_non_lazy('PKCS#12 IDevID Certificate Extraction'),
        value='openssl pkcs12 -in idevid.p12 -clcerts -nokeys -out idevid.pem',
        value_render_type=ValueRenderType.CODE,
    )

    p12_cert_chain_row = HelpRow(
        key=_non_lazy('PKCS#12 IDevID Certificate Chain Extraction'),
        value='openssl pkcs12 -in idevid.p12 -cacerts -nokeys -chain -out idevid_chain.pem',
        value_render_type=ValueRenderType.CODE,
    )

    p12_priv_key_row = HelpRow(
        key=_non_lazy('PKCS#12 IDevID Private Key Extraction'),
        value='openssl pkcs12 -in idevid.p12 -out idevid.key -nodes -nocerts',
        value_render_type=ValueRenderType.CODE,
    )

    remarks_row = HelpRow(
        key=_non_lazy('Remarks'),
        value=_non_lazy(
            'Please make sure that the root CA certificate is not included in the chain. '
            'If it is, you should remove it manually, e.g. using a text editor.'
        ),
        value_render_type=ValueRenderType.CODE,
    )

    return HelpSection(
        heading=_non_lazy('PKCS#12 or PFX convertion'),
        rows=[intro_row, p12_cert_row, p12_cert_chain_row, p12_priv_key_row, remarks_row],
    )
