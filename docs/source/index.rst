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


.. toctree::
   :maxdepth: 3
   :caption: Devices

   devices/onboarding
   devices/aoki
   devices/certificate_profiles

.. toctree::
   :maxdepth: 2
   :caption: Security

   security/pkcs11
   security/db_encryption

.. toctree::
   :maxdepth: 2
   :caption: EU Cyber Resilience Act

   cra/CRA_COMPLIANCE
   cra/THREAT_MODEL
   cra/RISK_REGISTER
   cra/CONTROLS


.. toctree::
   :maxdepth: 3
   :caption: Features

   features/pki/index
   features/pki/cas_ras
   features/pki/add_cas
   features/pki/add_ras

   features/pki/certificate_profiles
   features/pki/crl_management
   features/pki/crls
   features/pki/domains

   features/management/index
   features/management/audit_logs
   features/management/backups
   features/management/tls_settings


   features/mdns
   Workflow Engine <features/workflows>


.. toctree::
   :maxdepth: 2
   :caption: Indices and Tables

   indices_and_tables/glossary
   indices_and_tables/issued_certificates


.. toctree::
   :maxdepth: 2
   :caption: Testing

   testing/test_plan
   testing/ci_cd
   testing/test_report


.. toctree::
   :maxdepth: 2
   :caption: Development

   development/development
   development/architecture/credentials
   development/architecture/backup_restore
   development/architecture/crypto_redesign
   development/architecture/crypto_implementation_plan
   development/auto_restore
   development/sbom
   development/pipeline
   release-checklist
   development/rest_api
