import base64

import requests
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7


tests_data_path = Path(__file__).parent.parent / Path('data/issuing_ca')


def load_request() -> bytes:
    with open(tests_data_path / Path('csr0.pem'), 'rb') as f:
        raw_pem_csr = f.read()

    loaded_csr = x509.load_pem_x509_csr(raw_pem_csr)
    abc = base64.b64encode(loaded_csr.public_bytes(encoding=serialization.Encoding.DER))
    x = base64.b64decode(abc)
    return abc


def request_certificate(csr_: bytes):
    response = requests.post(
        'http://localhost:8000/.well-known/est/my-issuing-ca/simpleenroll/',
        data=csr_,
        headers={'Content-Type': 'application/pkcs10', 'content-transfer-encoding': 'base64'},
    )
    return response


if __name__ == '__main__':
    csr = load_request()
    resp = request_certificate(csr)
    if resp.status_code != 200:
        print(resp)
        print(resp.content)
    else:
        pkcs7_resp = base64.b64decode(resp.content)
        cert = pkcs7.load_der_pkcs7_certificates(pkcs7_resp)
        if cert:
            print(f'{resp.status_code} OK : {cert}')
