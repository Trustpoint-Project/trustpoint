"""Apache TLS configuration paths."""

from pathlib import Path

# Define paths for Apache TLS files
APACHE_PATH = Path(__file__).parent.parent.parent / 'docker/trustpoint/apache/tls'
APACHE_KEY_PATH = APACHE_PATH / Path('apache-tls-server-key.key')
APACHE_CERT_PATH = APACHE_PATH / Path('apache-tls-server-cert.pem')
APACHE_CERT_CHAIN_PATH = APACHE_PATH / Path('apache-tls-server-cert-chain.pem')
