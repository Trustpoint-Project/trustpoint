# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Application-wide permission constants for Trustpoint."""

APP_LABEL = 'users'


class AppPermissions:
    """Canonical Django permission identifiers used throughout Trustpoint."""

    # -------------------------------------------------------------------------
    # User and access management
    # -------------------------------------------------------------------------
    MANAGE_USERS = f'{APP_LABEL}.manage_users' #ok
    MANAGE_ROLES = f'{APP_LABEL}.manage_roles'#ok
    MANAGE_ORGANIZATIONS = f'{APP_LABEL}.manage_organizations' #ok
    MANAGE_SERVICE_ACCOUNTS = f'{APP_LABEL}.manage_service_accounts' #ok

    # -------------------------------------------------------------------------
    # PKI configuration
    # -------------------------------------------------------------------------
    MANAGE_CAS = f'{APP_LABEL}.manage_cas'
    MANAGE_RAS = f'{APP_LABEL}.manage_ras'
    MANAGE_DOMAINS = f'{APP_LABEL}.manage_domains'
    MANAGE_TRUSTSTORES = f'{APP_LABEL}.manage_truststores'
    MANAGE_CERTIFICATE_PROFILES = f'{APP_LABEL}.manage_certificate_profiles'
    MANAGE_CRYPTO_BACKENDS = f'{APP_LABEL}.manage_crypto_backends'

    # -------------------------------------------------------------------------
    # Certificate lifecycle
    # -------------------------------------------------------------------------
    ISSUE_CERTIFICATES = f'{APP_LABEL}.issue_certificates'
    REVOKE_CERTIFICATES = f'{APP_LABEL}.revoke_certificates'
    DOWNLOAD_CREDENTIALS = f'{APP_LABEL}.download_credentials'
    VIEW_HELP_PAGES = f'{APP_LABEL}.view_help_pages'

    # -------------------------------------------------------------------------
    # Device lifecycle
    # -------------------------------------------------------------------------
    MANAGE_DEVICES = f'{APP_LABEL}.manage_devices'

    # -------------------------------------------------------------------------
    # Automation and integration
    # -------------------------------------------------------------------------
    MANAGE_CERTIFICATE_DISCOVERY = (
        f'{APP_LABEL}.manage_certificate_discovery'
    )
    MANAGE_SIGNER = f'{APP_LABEL}.manage_signer'

    # -------------------------------------------------------------------------
    # Workflow engine
    # -------------------------------------------------------------------------
    MANAGE_WORKFLOWS = f'{APP_LABEL}.manage_workflows' # OK
    APPROVE_WORKFLOWS = f'{APP_LABEL}.approve_workflows' # OK

    # -------------------------------------------------------------------------
    # System administration
    # -------------------------------------------------------------------------
    MANAGE_SYSTEM_CONFIGURATION = (
        f'{APP_LABEL}.manage_system_configuration'
    )
    MANAGE_SECURITY_CONFIGURATION = (
        f'{APP_LABEL}.manage_security_configuration'
    ) #ok
    MANAGE_TLS_WEBSERVER_CONFIGURATION = (
        f'{APP_LABEL}.manage_tls_webserver_configuration'
    ) #ok
    MANAGE_BACKUPS = f'{APP_LABEL}.manage_backups' #ok
    MANAGE_NOTIFICATIONS = f'{APP_LABEL}.manage_notifications' #ok

    # -------------------------------------------------------------------------
    # Monitoring and audit
    # -------------------------------------------------------------------------
    VIEW_AUDIT_LOG = f'{APP_LABEL}.view_audit_log'#ok
    VIEW_SYSTEM_LOGS = f'{APP_LABEL}.view_system_logs' #ok
    VIEW_METRICS = f'{APP_LABEL}.view_metrics' #ok
