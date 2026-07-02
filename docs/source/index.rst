.. Trustpoint documentation master file, created by
   sphinx-quickstart on Thu Feb  8 11:05:54 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. image:: /_static/trustpoint_banner.png
   :align: center

======================================
Welcome to Trustpoint's documentation!
======================================

.. warning::

      Trustpoint is currently in a technology preview (beta) state. Do not use it in production.


.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   getting_started/introduction
   getting_started/quickstart_setup
   getting_started/quickstart_operate
   getting_started/usage_guide
   getting_started/community_support
   getting_started/faq
   getting_started/glossary


.. toctree::
   :maxdepth: 3
   :caption: Features

   features/apis/index
   features/apis/est
   features/apis/rest
   features/apis/cmp
   features/apis/rest_api


   features/aoki/index
   features/aoki/mdns

   features/devices/onboarding

   features/pki/index
   features/pki/cas_ras
   features/pki/add_cas
   features/pki/add_ras
   features/pki/certificate_profiles
   features/pki/crl_management
   features/pki/crls
   features/pki/domains
   features/pki/issued_certificates

   features/management/index
   features/management/settings
   features/management/logging
   features/management/audit_logs
   features/management/tls_settings
   features/management/backups
   features/management/notifications

   features/security/db_encryption
   features/security/pkcs11

   features/workflows/index


.. toctree::
   :maxdepth: 2
   :caption: EU Cyber Resilience Act

   cra/CRA_COMPLIANCE
   cra/THREAT_MODEL
   cra/RISK_REGISTER
   cra/CONTROLS


.. toctree::
   :maxdepth: 3
   :caption: Development

   development/development
   development/architecture/credentials
   development/architecture/backup_restore
   development/architecture/crypto_redesign
   development/architecture/crypto_implementation_plan
   development/auto_restore
   development/sbom
   development/pipeline
   development/release-checklist
   development/rest_api
   development/testing/test_plan
   development/testing/ci_cd
   development/testing/test_report
