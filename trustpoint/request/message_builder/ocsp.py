"""OCSP message builder for Trustpoint (RFC 6960)."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key
from cryptography.x509.ocsp import OCSPCertStatus, OCSPRequest, OCSPResponseBuilder
from django.utils import timezone
from trustpoint.pki.models.ca import CaModel
from trustpoint.pki.models.certificate import CertificateModel, RevokedCertificateModel

def build_ocsp_response(ocsp_req: OCSPRequest) -> bytes:
    """Build a DER-encoded OCSP response for the given OCSPRequest."""
    builder = OCSPResponseBuilder()
    for req in ocsp_req:
        issuer_key_hash = req.issuer_key_hash
        serial_number = req.serial_number
        ca = _find_ca_by_issuer_key_hash(issuer_key_hash)
        cert: CertificateModel | None = None
        if ca is None:
            cert_status = OCSPCertStatus.UNKNOWN
            revocation_time = None
            revocation_reason = None
        else:
            cert = CertificateModel.objects.filter(serial_number=serial_number, ca=ca).first()
            if cert is None:
                cert_status = OCSPCertStatus.UNKNOWN
                revocation_time = None
                revocation_reason = None
            elif RevokedCertificateModel.objects.filter(certificate=cert).exists():
                revoked = RevokedCertificateModel.objects.get(certificate=cert)
                cert_status = OCSPCertStatus.REVOKED
                revocation_time = revoked.revoked_at
                revocation_reason = revoked.reason
            else:
                cert_status = OCSPCertStatus.GOOD
                revocation_time = None
                revocation_reason = None
        builder = builder.add_response(
            cert=cert,
            issuer=ca.get_certificate() if ca else None,
            algorithm=hashes.SHA256(),
            cert_status=cert_status,
            this_update=timezone.now(),
            next_update=timezone.now() + timezone.timedelta(hours=24),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
    ca = _find_ca_by_issuer_key_hash(req.issuer_key_hash)
    issuer_cert = ca.get_certificate() if ca else None
    issuer_key = ca.get_credential().get_private_key() if ca and ca.get_credential() else _get_dummy_key()
    response = builder.sign(
        private_key=issuer_key,
        algorithm=hashes.SHA256(),
        responder_id=issuer_cert.subject if issuer_cert else None,
        certificates=[issuer_cert] if issuer_cert else None,
    )
    return response.public_bytes(serialization.Encoding.DER)

def _find_ca_by_issuer_key_hash(issuer_key_hash: bytes) -> CaModel | None:
    for ca in CaModel.objects.filter(is_active=True):
        cert = ca.get_certificate()
        if cert is not None:
            pubkey = cert.public_key()
            pubkey_bytes = pubkey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            digest = hashes.Hash(hashes.SHA256())
            digest.update(pubkey_bytes)
            if digest.finalize() == issuer_key_hash:
                return ca
    return None

def _get_dummy_key() -> RSAPrivateKey:
    return generate_private_key(public_exponent=65537, key_size=2048)
