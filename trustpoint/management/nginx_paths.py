"""Nginx TLS configuration paths."""

from pathlib import Path

# Define paths for Nginx TLS files
NGINX_PATH = Path(__file__).parent.parent.parent / 'docker/trustpoint/nginx/tls'
NGINX_KEY_PATH = NGINX_PATH / Path('nginx-tls-server-key.key')
NGINX_CERT_PATH = NGINX_PATH / Path('nginx-tls-server-cert.pem')
NGINX_CERT_CHAIN_PATH = NGINX_PATH / Path('nginx-tls-server-cert-chain.pem')
