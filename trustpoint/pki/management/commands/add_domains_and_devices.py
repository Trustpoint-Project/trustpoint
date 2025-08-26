"""Adds Issuing CAs, Domains and Devices with different onboarding protocols."""

# ruff: noqa: T201  # print is fine in management commands

import random
import secrets
import string

from devices.models import DeviceModel, OnboardingConfigModel, NoOnboardingConfigModel
from django.core.management import call_command
from django.core.management.base import BaseCommand
from pki.models import DevIdRegistration, DomainModel, IssuingCaModel, TruststoreModel
from devices.models import OnboardingPkiProtocol, NoOnboardingPkiProtocol, OnboardingProtocol, OnboardingStatus


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
    if include_protocol:
        protocols.remove(include_protocol)
    num_choices = secrets.randbelow(len(protocols)) + 1
    random_protocols = random.sample(protocols, k=num_choices)
    if include_protocol:
        random_protocols.append(include_protocol)
    return random_protocols


class Command(BaseCommand):
    """Add domains and associated device names with random onboarding protocol and serial number."""

    help = 'Add domains and associated device names with random onboarding protocol and serial number'

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Execute the command."""
        call_command('create_multiple_test_issuing_cas')
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
            'arburg': ('issuing-ca-a', 'idevid-truststore-RSA-2048'),
            'homag': ('issuing-ca-b', 'idevid-truststore-RSA-3072'),
            'siemens': ('issuing-ca-c', 'idevid-truststore-RSA-4096'),
            'belden': ('issuing-ca-d', 'idevid-truststore-EC-256'),
            'phoenix_contact': ('issuing-ca-e', 'idevid-truststore-EC-283'),
            'schmalz': ('issuing-ca-f', 'idevid-truststore-EC-570'),
        }

        onboarding_protocols = list(OnboardingProtocol)
        onboarding_protocols.remove(OnboardingProtocol.AOKI)
        onboarding_protocols.remove(OnboardingProtocol.BRSKI)
        onboarding_protocols.remove(OnboardingProtocol.MANUAL)
        onboarding_protocols.remove(OnboardingProtocol.CMP_IDEVID)
        onboarding_protocols.remove(OnboardingProtocol.EST_IDEVID)

        print('Starting the process of adding domains and devices...\n')

        for domain_name, devices in data.items():
            issuing_ca_name, truststore_name = domain_ca_truststore_map[domain_name]

            issuing_ca = IssuingCaModel.objects.get(unique_name=issuing_ca_name)
            truststore = TruststoreModel.objects.get(unique_name=truststore_name)

            domain, created = DomainModel.objects.get_or_create(unique_name=domain_name)
            domain.issuing_ca = issuing_ca
            domain.save()

            if created:
                print(f'Created new domain: {domain_name}')
            else:
                print(f'Domain already exists: {domain_name}')

            devid_reg, devid_created = DevIdRegistration.objects.get_or_create(
                unique_name=f'devid-reg-{domain_name}',
                domain=domain,
                truststore=truststore,
                serial_number_pattern='^.*$',
            )

            if devid_created:
                print(f"Created DevIdRegistration for domain '{domain_name}' with truststore '{truststore_name}'")
            else:
                print(f"DevIdRegistration already exists for domain '{domain_name}'")

            print(f'Domain({domain_name}, Issuing CA: {domain.issuing_ca})')

            device_uses_onboarding = random.choice([True, False])  # noqa: S311

            for device_name in devices:

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
                        onboarding_config_model.onboarding_cmp_shared_secret = _get_secret()

                    if onboarding_protocol == OnboardingProtocol.EST_USERNAME_PASSWORD:
                        onboarding_config_model.onboarding_est_password = _get_secret()

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
                    print(f"Creating device '{device_name}' in domain '{domain_name}' with:")
                    print(f'  - Serial Number: {serial_number}')
                    print('  - No Onboarding')

                    no_onboarding_pki_protocols = get_random_no_onboarding_pki_protocols()

                    no_onboarding_config_model = NoOnboardingConfigModel()
                    no_onboarding_config_model.set_pki_protocols(no_onboarding_pki_protocols)

                    if NoOnboardingPkiProtocol.CMP_SHARED_SECRET in no_onboarding_pki_protocols:
                        no_onboarding_config_model.cmp_shared_secret = _get_secret()

                    if NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD in no_onboarding_pki_protocols:
                        no_onboarding_config_model.est_username_password = _get_secret()

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

            print(f'Device {device_name} created and saved.')



        print('\nProcess completed. All domains and devices have been added.')
