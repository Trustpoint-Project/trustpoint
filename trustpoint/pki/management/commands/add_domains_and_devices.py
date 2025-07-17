"""Adds Issuing CAs, Domains and Devices with different onboarding protocols."""

# ruff: noqa: T201  # print is fine in management commands

import random
import secrets
import string

from devices.models import DeviceModel
from django.core.management import call_command
from django.core.management.base import BaseCommand
from pki.models import DevIdRegistration, DomainModel, IssuingCaModel, TruststoreModel


def get_random_pki_protocol(include_protocol: DeviceModel.PkiProtocol | None = None) -> list[DeviceModel.PkiProtocol]:
    """Gets random allowed PkiProtocols.

    Args:
        include_protocol: This protocol will be included in the allowed list.

    Returns:
        A list of PkiProtocols.
    """
    protocols = list(DeviceModel.PkiProtocol)
    protocols.remove(DeviceModel.PkiProtocol.NO_ONBOARDING)
    protocols.remove(DeviceModel.PkiProtocol.MANUAL)
    if include_protocol:
        protocols.remove(include_protocol)
    num_choices = secrets.randbelow(len(protocols) + 1)
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

        onboarding_protocols = [
            DeviceModel.OnboardingProtocol.NO_ONBOARDING.value,
            DeviceModel.OnboardingProtocol.CMP_IDEVID.value,
            DeviceModel.OnboardingProtocol.CMP_SHARED_SECRET.value,
            DeviceModel.OnboardingProtocol.EST_IDEVID.value,
            DeviceModel.OnboardingProtocol.EST_PASSWORD.value
        ]

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

            for device_name in devices:
                onboarding_protocol = random.choice(onboarding_protocols)  # noqa: S311

                serial_number = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))  # noqa: S311

                print(f"Creating device '{device_name}' in domain '{domain_name}' with:")
                print(f'  - Serial Number: {serial_number}')
                print(f'  - Onboarding Protocol: {onboarding_protocol}')

                onboarding_status = (
                    DeviceModel.OnboardingStatus.NO_ONBOARDING
                    if onboarding_protocol == DeviceModel.OnboardingProtocol.NO_ONBOARDING
                    else DeviceModel.OnboardingStatus.PENDING
                )

                domain_credential_onboarding = onboarding_protocol != DeviceModel.OnboardingProtocol.NO_ONBOARDING

                if domain_credential_onboarding:
                    if onboarding_protocol == DeviceModel.OnboardingProtocol.MANUAL:
                        pki_protocols = get_random_pki_protocol()
                    elif onboarding_protocol in [
                            DeviceModel.OnboardingProtocol.EST_IDEVID,
                            DeviceModel.OnboardingProtocol.EST_PASSWORD]:
                        pki_protocols = get_random_pki_protocol(DeviceModel.PkiProtocol.EST)
                    elif onboarding_protocol in [
                            DeviceModel.OnboardingProtocol.CMP_IDEVID,
                            DeviceModel.OnboardingProtocol.CMP_SHARED_SECRET]:
                        pki_protocols = get_random_pki_protocol(DeviceModel.PkiProtocol.CMP)
                    else:
                        err_msg = 'Unknown onboarding protocol found.'
                        raise ValueError(err_msg)

                else:
                    pki_protocols = []

                cmp_shared_secret = (
                    secrets.token_urlsafe(16)
                    if onboarding_protocol == DeviceModel.OnboardingProtocol.CMP_SHARED_SECRET
                    else ''
                )

                idevid_trust_store = (
                    truststore if onboarding_protocol == DeviceModel.OnboardingProtocol.CMP_IDEVID.value else None
                )

                dev = DeviceModel(
                    common_name=device_name,
                    serial_number=serial_number,
                    domain=domain,
                    onboarding_protocol=onboarding_protocol,
                    onboarding_status=onboarding_status,
                    domain_credential_onboarding=domain_credential_onboarding,
                    cmp_shared_secret=cmp_shared_secret,
                    idevid_trust_store=idevid_trust_store,
                )

                print(pki_protocols)
                dev.set_pki_protocols(pki_protocols)

                try:
                    dev.save()
                    if dev.pk:
                        print(f"Creating device '{dev.common_name}' (ID {dev.pk}) in domain '{dev.domain}' with:")
                        print(f'  - Serial Number: {dev.serial_number}')
                        print(f'  - Onboarding Protocol: {dev.onboarding_protocol}')
                        print(f'  - PKI Protocol: {dev.set_pki_protocols}')
                    else:
                        print(f"Device '{device_name}' was not saved correctly.")
                except Exception as e:  # noqa: BLE001
                    print(f"Failed to create device '{device_name}': {e}")

        print('\nProcess completed. All domains and devices have been added.')
