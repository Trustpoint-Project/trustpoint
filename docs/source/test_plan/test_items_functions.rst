This chapter lists all needed requirements of Trustpoint, e.g. creating certificates.
These requirements are only back-end requirements.

------
Actors
------

First, we define all needed actors to be as specific as needed.

.. _Trustpoint-Actors-Table:

.. csv-table:: Trustpoint Actors
   :header: "ID", "Name", "Description"
   :widths: 10 30 60

   "TPC_Web", "Trustpoint Core Web Interface", "The website of Trustpoint."
   "TP_Client", "Trustpoint Client", "The Trustpoint client program to be installed on clients."
   "Admin", "Admin", "The admin user of this specific Trustpoint environment."
   "NTEU", "Non-technically experienced user", "A user who is not necessarily technically experienced. This could also be an admin."
   "TEU", "Technically experienced user", "A user who does know at least a little bit about programming and PKI."

------------
Requirements
------------

Next, we list all requirements.
Note that this list could (and will be) incomplete.

^^^^^^^^^^^^^^^^^^^^^^^
Functional Requirements
^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table:: Functional Requirements
   :header: "Name (Identifier)", "Title", "Description", "Component(s)", "Importance"
   :widths: 10, 25, 60, 30, 10

   _`R_001`, "Create, view, edit and delete an identity", "TPC_Web must provide a way to create, view, edit and delete a digital identity.", "TPC_Web, Admin", "High"
   _`R_002`, "Usage of any zero touch onboarding protocol", "Any zero touch onboarding protocol should be used, preferably the Bootstrapping Remote Secure Key Infrastructure (BRSKI) process, while connecting a new device to the network.", "TP_Client", "High"
   _`R_003`, "Certificate Lifecycle Management", "Enable complete lifecycle management for certificates, including renewal and revocation.", "All components", "High"
   _`R_004`, "REST API", "Provide a REST API for interacting with Trustpoint programmatically.", "TPC_Web", "High"
   _`R_005`, "Docker Container Support", "Distribute Trustpoint within a fully-configured Docker container for deployment.", "TPC_Web", "Medium"
   _`R_006`, "Backup, Restore, and Update Mechanisms", "Implement backup, restoration, and update features to ensure data and system resilience.", "TPC_Web, Admin", "High"
   _`R_007`, "Logging Capabilities", "Provide detailed and configurable logging for system events and actions.", "TPC_Web, TP_Client", "High"
   _`R_008`, "Auto-Generated :term:`Issuing CA`s", "Automatically generate Issuing Certificate Authorities based on configuration.", "TPC_Web", "High"
   _`R_009`, "High Availability", "Ensure system availability using redundancy or failover mechanisms.", "TPC_Web, TP_Client", "High"
   _`R_010`, ":term:`CMP` Endpoint for Onboarded Devices", "Provide a :term:`CMP` endpoint for device onboarding.", "All components", "High"
   _`R_011`, ":term:`EST` Endpoint for Onboarded Devices", "Provide an :term:`EST` endpoint for device onboarding.", "All components", "High"
   _`R_012`, "Language Selection and Translation", "Support multi-language UI options for global usability.", "TPC_Web, TP_Client", "Medium"
   _`R_013`, "Remote Credential Download", "Enable credential downloads from a remote device using a one-time password.", "TPC_Web", "High"

^^^^^^^^^^^^^^^^^^^^^
Security Requirements
^^^^^^^^^^^^^^^^^^^^^

.. csv-table:: Security Requirements
   :header: "Name (Identifier)", "Title", "Description", "Component(s)", "Importance"
   :widths: 10, 25, 60, 30, 10

   _`R_101`, "Devices are only allowed to communicate with valid certificates", "Machines or devices in the network are only allowed to communicate with a valid certificate.", "TP_Client (multiple)", "High"
   _`R_102`, "Encrypted Communication", "The communication between machines has to be encrypted with the given algorithm.", "TP_Client (multiple)", "High"
   _`R_103`, "Security Level Configuration", "Allow administrators to configure security levels for different Trustpoint components.", "Admin, TPC_Web", "Medium"
   _`R_104`, "Certificate Template Security", "Enforce access control and secure handling for certificate templates.", "TPC_Web", "High"