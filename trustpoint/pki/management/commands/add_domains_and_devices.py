"""Adds Issuing CAs, Domains and Devices with different onboarding protocols."""

# ruff: noqa: T201  # print is fine in management commands

import random
import secrets
import string

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from devices.models import DeviceModel
from onboarding.models import OnboardingConfigModel, NoOnboardingConfigModel
from django.core.management import call_command
from django.core.management.base import BaseCommand
from management.models import KeyStorageConfig
from pki.models import CaModel, DevIdRegistration, DomainModel, CaModel, TruststoreModel
from pki.util.x509 import CertificateGenerator
from onboarding.models import OnboardingPkiProtocol, NoOnboardingPkiProtocol, OnboardingProtocol, OnboardingStatus
from signer.models import SignerModel
from trustpoint_core.serializer import CredentialSerializer, PrivateKeyLocation, PrivateKeyReference


ALLOWED_CHARS = allowed_chars = string.ascii_letters + string.digits


def _get_secret(number_of_symbols: int = 16) -> str:
    """Generates a secret with the number of symbols provided.

    Args:
        number_of_symbols: Number of symbols of the generated secret. Defaults to 16.

    Returns:
        The generated secret.
    """
    return ''.join(secrets.choice(allowed_chars) for _ in range(number_of_symbols))


def get_random_no_onboarding_pki_protocols() -> list[NoOnboardingPkiProtocol]:
    """Gets random allowed PkiProtocols.

    Args:
        include_protocol: This protocol will be included in the allowed list.

    Returns:
        A list of PkiProtocols.
    """
    protocols = list(NoOnboardingPkiProtocol)
    num_choices = secrets.randbelow(len(protocols)) + 1
    return random.sample(protocols, k=num_choices)


def get_random_onboarding_pki_protocols(
        include_protocol: OnboardingPkiProtocol | None = None) -> list[OnboardingPkiProtocol]:
    """Gets random allowed PkiProtocols.

    Args:
        include_protocol: This protocol will be included in the allowed list.

    Returns:
        A list of PkiProtocols.
    """
    protocols = list(OnboardingPkiProtocol)
    if OnboardingPkiProtocol.OPC_GDS_PUSH in protocols:
        protocols.remove(OnboardingPkiProtocol.OPC_GDS_PUSH)
    if include_protocol:
        protocols.remove(include_protocol)
    num_choices = secrets.randbelow(len(protocols)) + 1
    random_protocols = random.sample(protocols, k=num_choices)
    if include_protocol:
        random_protocols.append(include_protocol)
    return random_protocols


def _get_private_key_location_from_config() -> PrivateKeyLocation:
    """Determine the appropriate PrivateKeyLocation based on KeyStorageConfig."""
    try:
        storage_config = KeyStorageConfig.get_config()
        if storage_config.storage_type in [
            KeyStorageConfig.StorageType.SOFTHSM,
            KeyStorageConfig.StorageType.PHYSICAL_HSM
        ]:
            return PrivateKeyLocation.HSM_PROVIDED
    except KeyStorageConfig.DoesNotExist:
        pass

    return PrivateKeyLocation.SOFTWARE


def create_signer_for_domain(
    domain_name: str,
    issuing_ca: CaModel
) -> SignerModel:
    """Creates a signer certificate for a domain using the domain's issuing CA."""
    issuing_ca_private_key = issuing_ca.credential.get_private_key_serializer().as_crypto()
    issuing_ca_cert = issuing_ca.credential.get_certificate_serializer().as_crypto()
    issuing_ca_cn = issuing_ca.common_name

    if isinstance(issuing_ca_private_key, rsa.RSAPrivateKey):
        key_size = issuing_ca_private_key.key_size
        signer_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif isinstance(issuing_ca_private_key, ec.EllipticCurvePrivateKey):
        curve = issuing_ca_private_key.curve
        signer_key = ec.generate_private_key(curve=curve)
    else:
        raise ValueError('Unsupported issuing CA private key type.')

    digital_signature_extension = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        decipher_only=False,
        encipher_only=False,
    )

    signer_cert, signer_key = CertificateGenerator.create_ee(
        issuer_private_key=issuing_ca_private_key,
        issuer_name=issuing_ca_cert.subject,
        subject_name=f'Signer-{domain_name}',
        private_key=signer_key,
        extensions=[(digital_signature_extension, True)],
        validity_days=365,
    )

    credential_serializer = CredentialSerializer(
        private_key=signer_key,
        certificate=signer_cert,
        additional_certificates=[issuing_ca_cert],
    )

    private_key_location = _get_private_key_location_from_config()
    credential_serializer.private_key_reference = PrivateKeyReference.from_private_key(
        private_key=signer_key,
        key_label=f'signer-{domain_name}',
        location=private_key_location,
    )

    signer = SignerModel.create_new_signer(
        unique_name=f'signer-{domain_name}',
        credential_serializer=credential_serializer,
    )

    return signer


from trustpoint.logger import LoggerMixin


class Command(BaseCommand, LoggerMixin):
    """Add domains and associated device names with random onboarding protocol and serial number."""

    help = 'Add domains and associated device names with random onboarding protocol and serial number'

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Log a message and write it to stdout.

        Parameters
        ----------
        message : str
            The message to log and print.
        level : str
            The logging level ('info', 'warning', 'error', etc.).
        """
        log_method = getattr(self.logger, level, self.logger.info)
        log_method(message)

        if level == 'error':
            self.stdout.write(self.style.ERROR(message))
        elif level == 'warning':
            self.stdout.write(self.style.WARNING(message))
        elif level == 'info':
            self.stdout.write(self.style.SUCCESS(message))
        else:
            self.stdout.write(message)

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Execute the command."""
        if not CaModel.objects.filter(unique_name__startswith='issuing-ca').exists():
            call_command('create_multiple_test_issuing_cas')
        else:
            self.log_and_stdout('Issuing CAs already exist, skipping creation.')
        call_command('import_idevid_truststores')

        data = {
            'arburg': [
                'ALLROUNDER-Injection-Molding-Machine',
                'freeformer-3D-Printer',
                'SELOGICA-Control-System',
                'MULTILIFT-Robotic-Systems',
                'ARBIDRIVE-Servo-Motor',
                'ALS_Arburg-Leitrechner-System',
            ],
            'diebold_nixdorf': [
                'ATM-Service',
                'Kiosk-System',
            ],
            'homag': [
                'CENTATEQ-CNC-Processing-Center',
                'EDGETEQ-Edge-Banding-Machine',
                'powerTouch-Control',
                'intelliGuide-Assist-System',
                'DRILLTEQ-Drilling-and-Dowel-Insertion-Machine',
                'STORETEQ-Storage-System',
            ],
            'belden': [
                'Hirschmann-Industrial-Ethernet-Switches',
                'Lumberg-Automation-Connectors',
                'GarrettCom-Magnum-Routers',
                'TROMPETER-Coaxial-Connectors',
                'Belden-I_O-Modules',
            ],
            'siemens': [
                'SIMATIC-PLC',
                'SINAMICS-Drive-Systems',
                'SIRIUS-Control-Devices',
                'SIMOTICS-Electric-Motors',
                'SIMATIC-HMI-Panels',
                'SITOP-Power-Supplies',
            ],
            'phoenix_contact': [
                'CLIPLINE-Terminal-Blocks',
                'QUINT-Power-Supplies',
                'PLCnext-Control',
                'TERMITRAB-Surge-Protection',
                'CONTACTRON-Motor-Starters',
                'ME-PLC_Modular-Controller',
            ],
            'schmalz': [
                'Vacuum-Generators',
                'Vacuum-Grippers',
                'Vacuum-Clamping-Systems',
                'Suction-Pads',
                'Vacuum-Layer-Grippers',
                'Vacuum-Ejectors',
            ],
        }

        domain_ca_truststore_map = {
            'arburg': ('issuing-ca-a-1', 'idevid-truststore-RSA-2048'),
            'diebold_nixdorf': ('issuing-ca-a-2', 'idevid-truststore-RSA-2048'),
            'homag': ('issuing-ca-b', 'idevid-truststore-RSA-3072'),
            'siemens': ('issuing-ca-c', 'idevid-truststore-RSA-4096'),
            'belden': ('issuing-ca-d', 'idevid-truststore-EC-256'),
            'phoenix_contact': ('issuing-ca-e', 'idevid-truststore-EC-384'),
            'schmalz': ('issuing-ca-f', 'idevid-truststore-EC-521'),
        }

        onboarding_protocols = list(OnboardingProtocol)
        onboarding_protocols.remove(OnboardingProtocol.AOKI)
        onboarding_protocols.remove(OnboardingProtocol.BRSKI)
        onboarding_protocols.remove(OnboardingProtocol.MANUAL)
        onboarding_protocols.remove(OnboardingProtocol.CMP_IDEVID)
        onboarding_protocols.remove(OnboardingProtocol.EST_IDEVID)
        onboarding_protocols.remove(OnboardingProtocol.OPC_GDS_PUSH)

        self.log_and_stdout('Starting the process of adding domains and devices...\n')

        for domain_name, devices in data.items():
            issuing_ca_name, truststore_name = domain_ca_truststore_map[domain_name]

            ca = CaModel.objects.get(unique_name=issuing_ca_name, credential__isnull=False)
            issuing_ca = ca
            truststore = TruststoreModel.objects.get(unique_name=truststore_name)

            domain, created = DomainModel.objects.get_or_create(unique_name=domain_name)
            domain.issuing_ca = issuing_ca
            domain.save()

            if created:
                self.log_and_stdout(f'Created new domain: {domain_name}')
            else:
                self.log_and_stdout(f'Domain already exists: {domain_name}')

            devid_reg, devid_created = DevIdRegistration.objects.get_or_create(
                unique_name=f'devid-reg-{domain_name}',
                domain=domain,
                truststore=truststore,
                serial_number_pattern='^.*$',
            )

            if devid_created:
                self.log_and_stdout(
                    f"Created DevIdRegistration for domain '{domain_name}' and issuing CA "
                    f"'{issuing_ca_name}' with truststore '{truststore_name}'"
                )
            else:
                self.log_and_stdout(
                    f"DevIdRegistration already exists for domain '{domain_name}' "
                    f"and issuing CA '{issuing_ca_name}'"
                )

            signer_unique_name = f'signer-{domain_name}'
            if not SignerModel.objects.filter(unique_name=signer_unique_name).exists():
                try:
                    signer = create_signer_for_domain(domain_name, issuing_ca)
                    self.log_and_stdout(
                        f"Created signer '{signer.unique_name}' for domain '{domain_name}' "
                        f"with CN '{signer.common_name}' issued by '{issuing_ca_name}'"
                    )
                except Exception as e:  # noqa: BLE001
                    self.log_and_stdout(
                        f"Failed to create signer for domain '{domain_name}': {e}",
                        level='error'
                    )
            else:
                self.log_and_stdout(f"Signer '{signer_unique_name}' already exists for domain '{domain_name}'")

            device_uses_onboarding = random.choice([True, False])  # noqa: S311

            for device_name in devices:

                if DeviceModel.objects.filter(common_name=device_name).exists():
                    self.log_and_stdout(f"Device '{device_name}' already exists, skipping.")
                    continue

                random_device_type = random.choice( # noqa: S311
                        [DeviceModel.DeviceType.GENERIC_DEVICE, DeviceModel.DeviceType.OPC_UA_GDS])
                serial_number = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))  # noqa: S311

                if device_uses_onboarding:

                    onboarding_protocol = random.choice(onboarding_protocols)  # noqa: S311
                    print(f"Creating device '{device_name}' in domain '{domain_name}' with:")
                    print(f'  - Serial Number: {serial_number}')
                    print(f'  - Onboarding Protocol: {onboarding_protocol}')

                    if onboarding_protocol == OnboardingProtocol.MANUAL:
                        onboarding_pki_protocols = get_random_onboarding_pki_protocols()
                    elif onboarding_protocol in [
                            OnboardingProtocol.EST_IDEVID,
                            OnboardingProtocol.EST_USERNAME_PASSWORD]:
                        onboarding_pki_protocols = get_random_onboarding_pki_protocols(OnboardingPkiProtocol.EST)
                    elif onboarding_protocol in [
                            OnboardingProtocol.CMP_IDEVID,
                            OnboardingProtocol.CMP_SHARED_SECRET]:
                        onboarding_pki_protocols = get_random_onboarding_pki_protocols(OnboardingPkiProtocol.CMP)
                    else:
                        err_msg = 'Unknown onboarding protocol found.'
                        raise ValueError(err_msg)

                    idevid_trust_store = (
                        truststore
                        if onboarding_protocol in [OnboardingProtocol.CMP_IDEVID, OnboardingProtocol.EST_IDEVID]
                        else None
                    )
                    onboarding_config_model = OnboardingConfigModel(
                        onboarding_status=OnboardingStatus.PENDING,
                        onboarding_protocol=onboarding_protocol,
                        idevid_trust_store=idevid_trust_store
                    )
                    onboarding_config_model.set_pki_protocols(onboarding_pki_protocols)

                    if onboarding_protocol == OnboardingProtocol.CMP_SHARED_SECRET:
                        onboarding_config_model.cmp_shared_secret = _get_secret()

                    if onboarding_protocol == OnboardingProtocol.EST_USERNAME_PASSWORD:
                        onboarding_config_model.est_password = _get_secret()

                    onboarding_config_model.full_clean()

                    device_model = DeviceModel(
                        common_name=device_name,
                        serial_number=serial_number,
                        domain=domain,
                        device_type=random_device_type,
                        onboarding_config=onboarding_config_model
                    )

                    device_model.full_clean()

                    onboarding_config_model.save()
                    device_model.save()


                else:

                    serial_number = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))  # noqa: S311

                    no_onboarding_pki_protocols = get_random_no_onboarding_pki_protocols()

                    no_onboarding_config_model = NoOnboardingConfigModel()
                    no_onboarding_config_model.set_pki_protocols(no_onboarding_pki_protocols)

                    if NoOnboardingPkiProtocol.CMP_SHARED_SECRET in no_onboarding_pki_protocols:
                        no_onboarding_config_model.cmp_shared_secret = _get_secret()

                    if NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD in no_onboarding_pki_protocols:
                        no_onboarding_config_model.est_password = _get_secret()

                    no_onboarding_config_model.full_clean()

                    device_model = DeviceModel(
                        common_name=device_name,
                        serial_number=serial_number,
                        domain=domain,
                        device_type=random_device_type
                    )

                    device_model.no_onboarding_config = no_onboarding_config_model
                    device_model.full_clean()

                    no_onboarding_config_model.save()
                    device_model.save()
                    try:
                        device_model.save()
                        if device_model.pk:
                            onboarding_protocol_display = (
                                device_model.onboarding_config.get_onboarding_protocol_display()
                                if device_model.onboarding_config
                                else 'No Onboarding'
                            )
                            pki_protocols = (
                                device_model.onboarding_config.get_pki_protocols()
                                if device_model.onboarding_config
                                else device_model.no_onboarding_config.get_pki_protocols()
                                if device_model.no_onboarding_config
                                else []
                            )

                            self.log_and_stdout(
                                f"Creating device '{device_model.common_name}' (ID {device_model.pk}) "
                                f"in domain '{device_model.domain}' with Serial Number: {device_model.serial_number}; "
                                f"Onboarding Protocol: {onboarding_protocol_display}; "
                                f"PKI Protocols: {[p.label for p in pki_protocols]}"
                            )
                        else:
                            self.log_and_stdout(f"Device '{device_name}' was not saved correctly.", level='warning')
                    except Exception as e:  # noqa: BLE001
                        self.log_and_stdout(f"Failed to create device '{device_name}': {e}", level='error')

        self.log_and_stdout('Process completed. All domains and devices have been added.')
