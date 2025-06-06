#!/bin/bash

# Go to project directory
cd /var/www/html/trustpoint/trustpoint/

export DJANGO_SETTINGS_MODULE=trustpoint.settings

echo "[$(date)] Running scheduled Django management commands..."

uv run python manage.py trustpoint_setup_notifications
uv run python manage.py check_system_health
uv run python manage.py check_for_security_vulnerabilities
uv run python manage.py check_certificate_validity
uv run python manage.py check_issuing_ca_validity
uv run python manage.py check_domain_issuing_ca
uv run python manage.py check_non_onboarded_devices
uv run python manage.py check_for_weak_signature_algorithms
uv run python manage.py check_for_insufficient_key_length
uv run python manage.py check_for_weak_ecc_curves