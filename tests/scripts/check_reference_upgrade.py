# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Run through manage.py shell after restoring and upgrading the v1.0.0 fixture."""

# ruff: noqa: INP001, T201

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from django.conf import settings
from django.contrib.auth import authenticate
from packaging.version import Version

from devices.models import DeviceModel
from management.models import AppVersion
from pki.models import CertificateModel, DomainModel

assert authenticate(username='admin', password='reference-demo-only-321') is not None  # noqa: S106 - public demo fixture.
assert Version(AppVersion.objects.get(pk=1).version) == Version(str(settings.APP_VERSION))

domain = DomainModel.objects.get(unique_name='arburg')
assert domain.issuing_ca.unique_name == 'issuing-ca-a-1'
assert DeviceModel.objects.filter(domain=domain).exists()
assert CertificateModel.objects.exists()

credential = domain.issuing_ca.credential
message = b'Trustpoint v1.0.0 reference upgrade check'
signature = credential.get_private_key().sign(message, padding.PKCS1v15(), hashes.SHA256())
credential.get_certificate().public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())

print('Reference upgrade verified: admin authentication, version, demo domain/devices, certificates, and CA signing.')
