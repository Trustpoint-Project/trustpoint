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

   features/aoki/index
   features/aoki/mdns

   features/devices/onboarding
   features/devices/agents

   features/pki/index

   features/management/index

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

   development/index
   development/architecture/index
   development/auto_restore
   development/sbom
   development/pipeline
   development/release-checklist
   development/rest_api
   development/testing/test_plan
   development/testing/ci_cd
   development/testing/test_report
