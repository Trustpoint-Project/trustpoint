import requests
from requests.auth import HTTPBasicAuth
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

import base64

est_url = "https://192.168.88.242/.well-known/est/arburg/tlsserver/simpleenroll"

username = "PLCnext"
password = "foo123"

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "PhoenixContact-OpcClient-2"),
])).sign(private_key, hashes.SHA256())

csr_der = csr.public_bytes(encoding=Encoding.DER)
csr_base64 = base64.b64encode(csr_der).decode("utf-8")

headers = {
    "Content-Type": "application/pkcs10",
}

try:

    session = requests.Session()
    session.auth = HTTPBasicAuth(username, password)
    response = session.post(
        est_url,
        headers=headers,
        data=csr_base64,
        verify='server_cert.pem'
    )

    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        print("Certificate successfully enrolled.")
        with open("trustpoint_enrolled_cert.p7b", "wb") as f:
            f.write(response.content)
        print("Certificate saved as trustpoint_enrolled_cert.p7b")
    else:
        print("Enrollment failed:", response.text)

except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
