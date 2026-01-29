
import asyncio
import logging
from asyncua.crypto import uacrypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def test_load_cert():
    # Create a dummy self-signed cert to get some bytes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    import datetime

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    
    logger.info(f"Generated cert bytes: {len(cert_der)} bytes")
    logger.info(f"Type: {type(cert_der)}")

    # Test 1: Direct bytes
    logger.info("--- Test 1: load_certificate with bytes directly ---")
    try:
        loaded = await uacrypto.load_certificate(cert_der)
        logger.info(f"Success! Loaded: {type(loaded)}")
    except Exception as e:
        logger.error(f"Failed: {e}", exc_info=True)

    # Test 2: CertProperties with bytes
    logger.info("--- Test 2: load_certificate with CertProperties(bytes) ---")
    props = uacrypto.CertProperties(cert_der, 'der')
    try:
        loaded = await uacrypto.load_certificate(props.path_or_content, props.extension)
        logger.info(f"Success! Loaded: {type(loaded)}")
    except Exception as e:
        logger.error(f"Failed: {e}", exc_info=True)
    
    # Test 3: What if I verify get_content behavior?
    logger.info("--- Test 3: get_content behavior ---")
    content = await uacrypto.get_content(cert_der)
    logger.info(f"get_content returned type: {type(content)}")
    if content is None:
        logger.error("get_content returned None!")

    # Test 4: Explicit x509 load to mimic failure
    logger.info("--- Test 4: Explicit x509 load ---")
    try:
        x509.load_der_x509_certificate(content, default_backend())
        logger.info("Explicit load success")
    except Exception as e:
        logger.error(f"Explicit load failed: {e}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(test_load_cert())
