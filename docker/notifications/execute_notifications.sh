#!/bin/bash

# Go to project directory
cd /var/www/html/trustpoint/trustpoint/

export DJANGO_SETTINGS_MODULE=trustpoint.settings

uv run python -c "from django.conf import settings; print(settings.DATABASES['default'])"

echo "[$(date)] Running scheduled Django management commands..."
env >> /tmp/notifications_cron_debug.log
pwd >> /tmp/notifications_cron_debug.log

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