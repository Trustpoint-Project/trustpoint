"""Classes for handling IDevID certificates according to IEEE 802.1AR."""

from __future__ import annotations

import contextlib
import re
import secrets
import uuid
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.x509.verification import Criticality, ExtensionPolicy, PolicyBuilder, Store, VerificationError

from devices.models import DeviceModel
from onboarding.models import (
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)
from pki.models import DevIdRegistration, DomainModel, TruststoreModel
from pki.util.x509 import NginxTLSClientCertExtractor
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from django.http import HttpRequest


class IDevIDAuthenticationError(Exception):
    """Exception raised for IDevID authentication failures."""

class IDevIDExtensionPolicy:
    """Builder for IDevID extension policies."""

    @staticmethod
    def _idevid_base_policy() -> ExtensionPolicy:
        """Create an extension policy for all certificates in a IDevID PKI."""
        policy = ExtensionPolicy.permit_all()
        # Require the presence of the Authority Key Identifier extension as per IEEE 802.1AR 8.10.1
        return policy.require_present(
            x509.AuthorityKeyIdentifier, Criticality.AGNOSTIC, None
        )

    @staticmethod
    def idevid_ee_policy() -> ExtensionPolicy:
        """Create an extension policy for IDevID end-entity certificates."""
        return IDevIDExtensionPolicy._idevid_base_policy()

    @staticmethod
    def idevid_ca_policy() -> ExtensionPolicy:
        """Create an extension policy for IDevID CA certificates."""
        policy = IDevIDExtensionPolicy._idevid_base_policy()
        # Require the presence of the Subject Key Identifier extension as per IEEE 802.1AR 8.10.2
        policy = policy.require_present(
            x509.SubjectKeyIdentifier, Criticality.AGNOSTIC, None
        )
        # Require the presence of the Basic Constraints extension as per RFC 5280
        # Note: There are conflicting requirements in RFC 5280 and IEEE 802.1AR 8.10
        # with respect to CA Basic Constraints being critical
        return policy.require_present(
            x509.BasicConstraints, Criticality.CRITICAL, None
        )


class IDevIDVerifier(LoggerMixin):
    """Verifies IDevID certificates as used e.g. by EST with mutual TLS auth."""

    @classmethod
    def verify_idevid_against_truststore(
        cls, idevid_cert: x509.Certificate, intermediate_cas: list[x509.Certificate], truststore: TruststoreModel
    ) -> bool:
        """Verify the IDevID certificate against the provided truststore."""
        # Need to check whether truststore has intended usage IDevID?
        if truststore.intended_usage != TruststoreModel.IntendedUsage.IDEVID:
            cls.logger.warning('Truststore %s is not intended for IDevID verification', truststore.unique_name)
            return False
        cls.logger.info('Verifying IDevID certificate against truststore %s', truststore.unique_name)
        certificates = truststore.get_certificate_collection_serializer().as_crypto()
        cls.logger.debug('Certificates in truststore: %s', certificates)
        store = Store(certificates)
        builder = PolicyBuilder().store(store)
        builder = builder.max_chain_depth(2)
        builder = builder.extension_policies(
           ca_policy=IDevIDExtensionPolicy.idevid_ca_policy(),
           ee_policy=IDevIDExtensionPolicy.idevid_ee_policy(),
        )
        verifier = builder.build_client_verifier()
        try:
            _verified_client = verifier.verify(idevid_cert, intermediate_cas)
        except VerificationError as e:
            cls.logger.warning('IDevID verification failed for truststore %s: %s', truststore.unique_name, e)
            return False
        return True


class IDevIDAuthenticator(LoggerMixin):
    """Authenticates IDevID certificates as used e.g. by EST with mutual TLS auth."""

    @staticmethod
    def _get_matching_registrations(candidate_reg_strings: list[str], domain: DomainModel | None
                                    ) -> list[DevIdRegistration]:
        """Get DevIdRegistration patters matching the given domain and serial number."""
        domain_name = domain.unique_name if domain else 'Any'
        if domain:
            domain_registrations = DevIdRegistration.objects.filter(domain=domain)
        else:
            domain_registrations = DevIdRegistration.objects.all()
        if not domain_registrations.exists():
            error_message = f'No registration patterns for requested domain {domain_name}.'
            raise IDevIDAuthenticationError(error_message)

        matching_registrations = [
            r for r in domain_registrations
            if any(re.fullmatch(r.serial_number_pattern, candidate) for candidate in candidate_reg_strings)
        ]
        if not matching_registrations:
            error_message = (f'No DevID registration pattern matching refs {candidate_reg_strings} '
                             f'for requested domain {domain_name}.')
            raise IDevIDAuthenticationError(error_message)
        return matching_registrations

    @staticmethod
    def _auto_create_device_from_idevid(  # noqa: PLR0913 (multiple args are cleaner here than re-extracting values from idevid again)
        idevid_cert: x509.Certificate, idevid_subj_sn: str, idevid_uuid: str | None,
        domain: DomainModel,
        pki_protocol: OnboardingPkiProtocol,
        onboarding_protocol: OnboardingProtocol,
    ) -> DeviceModel:
        """Auto-create a new DeviceModel from the IDevID certificate."""
        try:
            cn_b = idevid_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            common_name = cn_b.decode() if isinstance(cn_b, bytes) else cn_b
        except (ValueError, IndexError):
            common_name = 'AutoGenDevice'

        if DeviceModel.objects.filter(common_name=common_name, domain=domain).exists():
            common_name += f'_{secrets.token_hex(4)}'

        onboarding_config_model = OnboardingConfigModel(
            onboarding_status=OnboardingStatus.PENDING,
            onboarding_protocol=onboarding_protocol,
        )
        onboarding_config_model.set_pki_protocols([pki_protocol])
        device = DeviceModel(
            serial_number=idevid_subj_sn,
            common_name=common_name,
            domain=domain,
            onboarding_config=onboarding_config_model,
        )
        # if a device with the same UUID already exists (e.g. in a different domain),
        # this will violate the unique constraint, so a random UUID is assigned instead
        if idevid_uuid and not DeviceModel.objects.filter(rfc_4122_uuid=idevid_uuid).exists():
            device.rfc_4122_uuid = idevid_uuid
        onboarding_config_model.full_clean()
        onboarding_config_model.save()
        device.full_clean()
        device.save()

        return device

    @staticmethod
    def get_subject_serial_number(idevid_cert: x509.Certificate) -> str | None:
        """Get the serial number from the subject of the IDevID certificate."""
        try:
            sn_b = idevid_cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
        except (ValueError, IndexError):
            return None

        return sn_b.decode() if isinstance(sn_b, bytes) else sn_b

    @staticmethod
    def get_idevid_san_uris(idevid_cert: x509.Certificate) -> list[str] | None:
        """Get the Owner ID SAN URI(s) from the IDevID certificate SAN, or None if there is no URI in the IDevID SAN."""
        try:
            san_ext = idevid_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return None
        return san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)

    @staticmethod
    def get_idevid_uuid(idevid_cert: x509.Certificate) -> str | None:
        """Get the first valid UUID from the IDevID certificate SAN, or None if no valid UUID in the IDevID SAN."""
        san_uris = IDevIDAuthenticator.get_idevid_san_uris(idevid_cert)
        if not san_uris:
            return None
        for uri in san_uris:
            if uri.startswith('urn:uuid:'):
                uri_candidate = uri.removeprefix('urn:uuid:')
                try:
                    return str(uuid.UUID(uri_candidate))
                except ValueError:
                    continue
        return None

    @classmethod
    def authenticate_idevid_from_x509_no_device(
        cls, idevid_cert: x509.Certificate, intermediate_cas: list[x509.Certificate], domain: DomainModel | None = None
    ) -> tuple[DomainModel, str | None]:
        """Authenticate client using an IDevID certificate."""
        idevid_subj_sn = cls.get_subject_serial_number(idevid_cert)
        idevid_san_uris = cls.get_idevid_san_uris(idevid_cert)
        if not idevid_subj_sn and not idevid_san_uris:
            error_message = ('IDevID certificates without a Subject DN Serial Number '
                             'or a unique SAN URI for registration are not supported.')
            cls.logger.warning(error_message)
            raise IDevIDAuthenticationError(error_message)

        candidate_reg_strings = [idevid_subj_sn] if idevid_subj_sn else []
        if idevid_san_uris:
            candidate_reg_strings.extend(idevid_san_uris)

        matching_registrations = cls._get_matching_registrations(candidate_reg_strings, domain)

        # verify IDevID against Truststore
        for registration in matching_registrations:
            if (IDevIDVerifier.verify_idevid_against_truststore(
                idevid_cert=idevid_cert,
                intermediate_cas=intermediate_cas,
                truststore=registration.truststore,
            )):
                cls.logger.info(
                    'IDevID certificate with SN %s successfully verified against truststore %s',
                    idevid_subj_sn,
                    registration.truststore.unique_name
                )
                return (registration.domain, idevid_subj_sn)

        error_message = (f'IDevID with SN {idevid_subj_sn} could not be verified against any truststore.')
        cls.logger.warning(error_message)
        raise IDevIDAuthenticationError(error_message)

    @classmethod
    def authenticate_idevid_from_x509(
        cls,
        idevid_cert: x509.Certificate,
        intermediate_cas: list[x509.Certificate],
        domain: DomainModel | None = None,
        onboarding_protocol: OnboardingProtocol = OnboardingProtocol.EST_IDEVID,
        pki_protocol: OnboardingPkiProtocol = OnboardingPkiProtocol.EST,
    ) -> DeviceModel:
        """Authenticate client using IDevID certificate for Domain Credential request and create a device."""
        domain, idevid_subj_sn = cls.authenticate_idevid_from_x509_no_device(
            idevid_cert=idevid_cert, intermediate_cas=intermediate_cas, domain=domain
        )
        # Check if we have an existing device with the same UUID in the domain already
        idevid_uuid = cls.get_idevid_uuid(idevid_cert)
        if idevid_uuid:
            existing_device = None
            with contextlib.suppress(DeviceModel.DoesNotExist):
                existing_device = DeviceModel.objects.get(
                    domain=domain,
                    rfc_4122_uuid=idevid_uuid,
                )
            # Multiple objects returned can not happen since rfc_4122_uuid is unique,
            # but if it does, error out (MultipleObjectsReturned)
            # TODO(Air): This may be an issue onboarding the same physical device to multiple domains,  #noqa: FIX002
            # since the same IDevID certificate with the same UUID would be used for onboarding in each domain.
            # Therefore, support for one device onboarding to multiple domains in the future,
            # rather than creating a new device for each domain in Trustpoint may be desirable.

            if existing_device:
                return existing_device
        # Check if we have an existing device with the same serial number in the domain already
        if idevid_subj_sn:
            existing_device = None
            try:
                existing_device = DeviceModel.objects.get(
                    domain=domain,
                    serial_number=idevid_subj_sn,

                )
            except DeviceModel.DoesNotExist:
                pass
            except DeviceModel.MultipleObjectsReturned:
                error_message = (f'Multiple devices with the same serial number {idevid_subj_sn} '
                                f'found in domain {domain.unique_name}.')
                cls.logger.warning(error_message)
                cls.logger.warning('Auto-creating new device.')

            if existing_device:
                return existing_device

        return cls._auto_create_device_from_idevid(
            idevid_cert=idevid_cert,
            idevid_subj_sn=idevid_subj_sn or '',
            idevid_uuid=idevid_uuid,
            domain=domain,
            onboarding_protocol=onboarding_protocol,
            pki_protocol=pki_protocol
        )

    @classmethod
    def authenticate_idevid(cls, request: HttpRequest, domain: DomainModel | None = None) -> DeviceModel:
        """Authenticate client using IDevID certificate for Domain Credential request."""
        idevid_cert, intermediate_cas = NginxTLSClientCertExtractor.get_client_cert_as_x509(request)

        return cls.authenticate_idevid_from_x509(
            idevid_cert=idevid_cert,
            intermediate_cas=intermediate_cas,
            domain=domain
        )
