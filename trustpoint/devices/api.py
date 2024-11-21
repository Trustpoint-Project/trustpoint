"""API endpoints for the devices app."""
from __future__ import annotations

from django.http import HttpRequest  # noqa: TCH002
from django.shortcuts import get_object_or_404
from ninja import Router, Schema

from devices import DeviceOnboardingStatus
from devices.models import Device
from pki.models import DomainModel
from trustpoint.schema import ErrorSchema, SuccessSchema

router = Router()


class DeviceInfoSchema(Schema):
    """Schema for the device information."""

    id: int
    name: str
    serial_number: str
    onboarding_protocol: str
    onboarding_status: str


class DeviceCreateSchema(Schema):
    """Schema for creating a new device."""

    name: str
    serial_number: str = ''
    onboarding_protocol: Device.OnboardingProtocol


class DeviceUpdateSchema(Schema):
    """Schema for updating an existing device."""

    name: str
    serial_number: str


def device_api_dict(dev: Device) -> dict:
    """Gets a dict with device details corresponding to DeviceInfoSchema."""
    return {
        'id': dev.pk,
        'name': dev.device_name,
        'serial_number': dev.device_serial_number,
        # TODO(Air): Prefer using the enum key instead of the label
        # (e.g. so that we can change the label for i18n without breaking the API)
        'onboarding_protocol': str(Device.OnboardingProtocol(dev.onboarding_protocol).label),
        'onboarding_status': str(DeviceOnboardingStatus(dev.device_onboarding_status).label),
    }

@router.get('/domain-certificates/{domain_id}/', summary='Get domain certificates')
def get_domain_certificates(request, domain_id: int):
    """Returns active certs for a domain ."""
    domain = get_object_or_404(DomainModel, id=domain_id)
    devices = domain.devices.all()

    certificates = []
    for device in devices:
        certs = device.get_all_active_certs_by_domain(domain)
        if certs['ldevid']:
            certificates.append({
                'type': 'LDevID',
                'expiration_date': certs['ldevid'].not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
                'status': certs['ldevid'].certificate_status,
                'revoke_url': f"/certificates/revoke/{certs['ldevid'].pk}/"
            })
        for issued_cert in certs['other']:
            certificates.append({
                'type': issued_cert.certificate_type,
                'expiration_date': issued_cert.certificate.not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
                'status': issued_cert.certificate.certificate_status,
                'revoke_url': f'/certificates/revoke/{issued_cert.certificate.pk}/'
            })

    return {'certificates': certificates}

@router.get('/', response=list[DeviceInfoSchema], exclude_none=True)
def devices(request: HttpRequest) -> list[dict]:
    """Get a list of all devices."""
    _ = request
    qs = Device.objects.all()
    return [device_api_dict(dev) for dev in qs]


@router.get('/{device_id}', response={200: DeviceInfoSchema, 404: ErrorSchema}, exclude_none=True)
def device(request: HttpRequest, device_id: int) -> tuple[int, dict]:
    """Returns details about a device with a given ID."""
    _ = request
    dev = Device.get_by_id(device_id)
    if not dev:
        return 404, {'error': 'Device not found.'}

    return 200, device_api_dict(dev)


@router.post('/', response={201: DeviceInfoSchema, 400: ErrorSchema}, exclude_none=True)
def create_device(request: HttpRequest, data: DeviceCreateSchema) -> tuple[int, dict]:
    """Creates a new device."""
    _ = request
    dev = Device(device_name=data.name, serial_number=data.serial_number, onboarding_protocol=data.onboarding_protocol)
    # TODO(Air): Set domain
    # TODO(Air): String validation (e.g. not empty, max. length)
    dev.save()
    return 201, device_api_dict(dev)


@router.patch('/{device_id}', response={200: DeviceInfoSchema, 404: ErrorSchema, 422: ErrorSchema}, exclude_none=True)
def update_device(request: HttpRequest, device_id: int, data: DeviceUpdateSchema) -> tuple[int, dict]:
    """Updates a device with a given ID."""
    _ = request
    dev = Device.get_by_id(device_id)
    if not dev:
        return 404, {'error': 'Device not found.'}

    if data.name:
        dev.device_name = data.name

    if data.serial_number:
        if dev.device_serial_number:
            return 422, {'error': 'Serial number cannot be changed once set.'}
        dev.device_serial_number = data.serial_number

    dev.save()
    return 200, device_api_dict(dev)


@router.delete('/{device_id}', response={200: SuccessSchema, 404: ErrorSchema}, exclude_none=True)
def delete_device(request: HttpRequest, device_id: int) -> tuple[int, dict]:
    """Deletes a device with a given ID."""
    _ = request
    dev = Device.get_by_id(device_id)
    if not dev:
        return 404, {'error': 'Device not found.'}

    dev.delete()
    return 200, {'success': True}
