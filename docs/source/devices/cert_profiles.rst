.. _certificate-profiles:

====================
Certificate Profiles
====================

Certificate profiles define defaults and constraints of certificate requests to Trustpoint (e.g. via CMP or EST).
They are used to validate the content of certificate requests and to ensure that the issued certificates meet specific, customizable requirements.

The following diagram illustrates the process of certificate profile validation:

.. plantuml:: ../diagrams/cert_profile_overview.puml
    :caption: Certificate Profile validation process