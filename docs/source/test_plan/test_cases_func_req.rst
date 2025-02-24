^^^^^
R_001
^^^^^

This testcase is related to requirement `R_001`_.

"""""""""
Test Idea
"""""""""

To test the requirement of creating, viewing, editing, and deleting digital identities using the TPC_Web interface,
the focus will be on validating the complete lifecycle of identity management through the web platform.

The test would start with an admin user creating a new digital identity through the web interface.
This process involves navigating to the appropriate page, filling out the required fields (e.g., name and identifier),
and submitting the form. Once the identity is created,
the test would verify that it appears in the list of identities and that all details are accurately displayed on its details page.

Following the creation, the admin user would edit the identity's details,
such as updating the name or identifier, and save the changes.
The test should confirm that the modifications are reflected immediately and correctly in both the details view and any listings.

Finally, the test would validate the deletion process,
where the admin removes the identity through the web interface.
Once deleted, the system should ensure that the identity is no longer accessible or visible in any lists or details pages.
Additional negative tests could confirm appropriate handling when attempting to access or manipulate a non-existent or already-deleted identity.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_001_CRUD.feature
   :language: gherkin

^^^^^
R_002
^^^^^

This testcase is related to requirement `R_002`_.

"""""""""
Test Idea
"""""""""

""""""""""""
Feature File
""""""""""""

^^^^^
R_003
^^^^^

This testcase is related to requirement `R_003`_.

"""""""""
Test Idea
"""""""""

To test the complete lifecycle management of certificates,
the focus will be on ensuring that admin users can successfully perform actions such as renewing and revoking certificates via the TPC_Web interface.

The test begins by identifying an existing certificate.
Using TPC_Web, the admin initiates the renewal process,
and the system updates the expiration date.
Similarly, the admin navigates to the certificate management page and initiates a revocation process.
The system should confirm the action and reflect the certificate's updated status as revoked.

Edge cases include attempting to renew or revoke non-existent certificates or
performing actions on certificates in invalid states (e.g., already revoked certificates).
The system should handle these scenarios gracefully, with appropriate error messages or restrictions.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_003_certificate_lifecycle.feature
   :language: gherkin

^^^^^
R_004
^^^^^

This testcase is related to requirement `R_004`_.

"""""""""
Test Idea
"""""""""

To test the REST API for interacting with Trustpoint programmatically,
we focus on verifying CRUD operations (Create, Read, Update, Delete) and additional actions like querying and filtering.
We begin by validating that authorized API clients can authenticate successfully and perform each operation on digital identities.
This includes creating a new identity,
retrieving its details, updating its attributes, and deleting it.
Each API response should include appropriate status codes and payloads.

Error handling should also be tested, such as attempting operations with invalid data,
unauthorized access, or on non-existent resources.
Edge cases, such as rate limits or concurrent requests, should be addressed to confirm robustness.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_004_REST_API.feature
   :language: gherkin

^^^^^
R_005
^^^^^

This testcase is related to requirement `R_005`_.

"""""""""
Test Idea
"""""""""

This requirement states that we want to distribute Trustpoint in a fully-configured Docker container.
The idea for testing would be to build the container,
run it on a production system and then check all other requirements manually or build a test suite and check the requirements automatically.
Since the code is the same, just executed in a Docker environment, we see no need to let those tests run automatically.
Therefore, we will pass the test for this requirement if the container can be built and ran on another system.

""""""""""""
Feature File
""""""""""""

Nonexistent.

^^^^^
R_006
^^^^^

This testcase is related to requirement `R_006`_.

"""""""""
Test Idea
"""""""""

To verify the implementation of backup, restoration, and update mechanisms for ensuring system resilience:

#. Backup Verification:
    - An admin initiates a system backup via the TPC_Web interface.
    - The system confirms that the backup process completes successfully.
    - The backup file is retrievable and valid.

#. Restore Verification:
    - An admin uploads a valid backup file through the TPC_Web interface.
    - The system restores the data and confirms the restoration is successful.
    - Restored data is consistent with the backup file contents.

#. System Update Verification:
    - An admin triggers a system update via the TPC_Web interface.
    - The system downloads and applies the update.
    - Post-update, the system verifies the integrity and functionality of the application.

Edge cases include:

- Handling a corrupt backup file during restoration.
- Attempting to perform operations with insufficient admin privileges.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_006_backup_restore_update.feature
   :language: gherkin

^^^^^
R_007
^^^^^

This testcase is related to requirement `R_007`_.

"""""""""
Test Idea
"""""""""

To verify that the system provides detailed and configurable logging for system events and actions,
we will test the following scenarios:

#. Logging of User Actions
    - The admin performs actions such as creating, updating, and deleting identities.
    - The system logs these actions with relevant details (timestamp, user ID, action type, and outcome).

#. Log Retrieval & Filtering
    - The admin retrieves system logs via the TPC_Web interface.
    - Logs can be filtered by time range, user, or event type.

#. Log Configuration Management
    - The admin modifies the logging configuration to change verbosity levels.
    - The system applies the new logging settings and updates log output accordingly.

#. Log Storage & Integrity
    - Logs are stored persistently and are not lost between system restarts.
    - Unauthorized users cannot modify or delete logs.

Edge cases:

- Verifying how the system handles an excessive number of log entries.
- Testing logging behavior when storage space is low.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_007_logging.feature
   :language: gherkin

^^^^^
R_008
^^^^^

This testcase is related to requirement `R_008`_.

"""""""""
Test Idea
"""""""""

To verify that the system automatically generates Issuing CAs based on configuration, we will test the following scenarios:

#. Successful Auto-Generation of an Issuing CA
    - The admin configures the system with predefined settings for an Issuing CA.
    - The system automatically generates the CA without manual intervention.
    - The CA appears in the list of available CAs.

#. Auto-Generation with Different Configurations
    - The admin sets different parameters for CA generation (e.g., key size, validity period).
    - The system creates the CA using the specified configuration.
    - The generated CA matches the given settings.

#. Failure Handling in CA Generation
    - The system prevents generation if required parameters are missing.
    - The system logs errors when CA generation fails.

#. Verification of Generated CA Details
    - The generated CA contains the expected attributes (issuer name, serial number, key usage, etc.).
    - The CA is functional and can issue end-entity certificates.

Edge cases:

- Attempting to generate a CA with invalid parameters.
- Generating multiple CAs in quick succession.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_008_auto_issuing_ca.feature
   :language: gherkin

^^^^^
R_009
^^^^^

This testcase is related to requirement `R_009`_.

"""""""""
Test Idea
"""""""""

There is no High Availability Concept for Trustpoint yet,
so that the test needs to be redesigned after we decided on which concept top use.
For now, the test assumes a multi-server setup.

To verify that the system ensures high availability through redundancy and failover mechanisms,
we will test the following scenarios:

#. Failover Mechanism Activation
    - Simulate a primary server failure.
    - Verify that the system seamlessly switches to a secondary server.
    - Ensure no data loss or service interruption.

#. Load Balancing Under High Traffic
    - Simulate multiple concurrent users accessing the system.
    - Verify that traffic is distributed across multiple nodes.
    - Ensure response times remain within acceptable limits.

#. Recovery After a Server Crash
    - Simulate a server crash and restart.
    - Ensure the system restores its previous state without manual intervention.
    - Verify that logs and transactions remain intact.

#. Database Replication Consistency
    - Ensure that database replication maintains consistency across multiple nodes.
    - Test whether changes made on one node propagate to others correctly.

Edge cases:

- Sudden simultaneous failure of multiple components.
- Failover switching back to the primary server after recovery.
- Performance degradation during failover.

""""""""""""
Feature File
""""""""""""

Nonexistent.

^^^^^
R_010
^^^^^

This testcase is related to requirement `R_010`_.

"""""""""
Test Idea
"""""""""

To verify that the system provides a :term:`CMP` endpoint for onboarding devices, we will test the following scenarios:

#. Device Registration and Certificate Enrollment
    - A new device initiates a :term:`CMP` request to the endpoint.
    - The system processes the request and issues a certificate.
    - The device successfully receives and stores the issued certificate.

#. Certificate Renewal for an Onboarded Device
    - An onboarded device requests certificate renewal.
    - The system validates the request and issues a new certificate.
    - The device replaces its old certificate with the new one.

#. Handling Unauthorized Requests
    - A device with invalid credentials tries to access the :term:`CMP` endpoint.
    - The system rejects the request with an appropriate error response.

#. Certificate Revocation for a Compromised Device
    - An admin requests certificate revocation for a specific device.
    - The system revokes the certificate and updates the revocation list.
    - The revoked device is unable to authenticate using its certificate.

#. High Load Handling
    - Simulate multiple devices requesting certificate issuance simultaneously.
    - Verify that the system handles high traffic without performance degradation.

Edge cases:

- Expired certificates being used for renewal.
- Partial network outages during certificate issuance.
- Unexpected payloads being sent to the :term:`CMP` endpoint.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_010_cmp_endpoint.feature
   :language: gherkin

^^^^^
R_011
^^^^^

This testcase is related to requirement `R_011`_.
Note that :term:`EST` and :term:`CMP` could be tested the same way.
This is still w.i.p.

"""""""""
Test Idea
"""""""""

To verify that the system provides an :term:`EST` endpoint for onboarding devices, we will test the following scenarios:

#. Device Registration and Certificate Enrollment
    - A new device initiates an :term:`EST` request to the endpoint.
    - The system processes the request and issues a certificate.
    - The device successfully receives and stores the issued certificate.

#. Certificate Renewal for an Onboarded Device
    - An onboarded device requests certificate renewal using :term:`EST`.
    - The system validates the request and issues a new certificate.
    - The device replaces its old certificate with the new one.

#. Handling Unauthorized Requests
    - A device with invalid credentials tries to access the :term:`EST` endpoint.
    - The system rejects the request with an appropriate error response.

#. Certificate Revocation for a Compromised Device
    - An admin requests certificate revocation for a specific device.
    - The system revokes the certificate and updates the revocation list.
    - The revoked device is unable to authenticate using its certificate.

#. High Load Handling
    - Simulate multiple devices requesting certificate issuance simultaneously via :term:`EST`.
    - Verify that the system handles high traffic without performance degradation.

Edge cases:

- Expired certificates being used for renewal.
- Partial network outages during certificate issuance.
- Unexpected payloads being sent to the :term:`EST` endpoint.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_011_est_endpoint.feature
   :language: gherkin

^^^^^
R_012
^^^^^

This testcase is related to requirement `R_012`_.

"""""""""
Test Idea
"""""""""

To verify that the system provides multi-language UI options, we will test the following scenarios:

#. Default Language Selection
    - A new user accesses the system.
    - The system detects the browser's language settings and applies the appropriate default language.
    - If no supported language is detected, the system defaults to English.

#. Manual Language Selection
    - A user manually selects a different language from the UI settings.
    - The system updates all UI elements to reflect the chosen language.
    - The language setting persists across sessions.

#. Language Persistence
    - A user selects a language and logs out.
    - Upon re-login, the system retains the user's language preference.

#. UI Translation Accuracy
    - Verify that key UI elements (menus, buttons, notifications) are translated correctly for each supported language.
    - Ensure that dynamic text (e.g., form labels, user-generated content) remains unaffected.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_012_multi_language_support.feature
   :language: gherkin

^^^^^
R_013
^^^^^

This testcase is related to requirement `R_013`_.

"""""""""
Test Idea
"""""""""

The Remote Credential Download feature allows users to download an issued application credential
from a remote device using a one-time password (OTP).
The test covers the following scenarios:

#. Admin Generates One-Time Password
    - An admin successfully generates a one-time password (OTP) for a specific issued credential.
    - The OTP is displayed in the "Download on Device Browser" view.
    - The OTP should be valid for a limited time.

#. User Enters OTP Correctly
    - The user visits the "/devices/browser" endpoint.
    - They enter a valid OTP.
    - The system grants access to a page where the user can select the format for the credential download.

#. User Enters OTP Incorrectly
    - The user visits the "/devices/browser" endpoint.
    - They enter an invalid OTP.
    - The system displays a warning message indicating the OTP is incorrect.
    - The user is not granted access to download the credential.

#. User Downloads Credential
    - The user is on the credential download page.
    - The download token is still valid (not expired).
    - The user enters a password to encrypt the private key.
    - The user selects a file format.
    - The credential is successfully downloaded in the selected format.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_013_remote_credential_download.feature
   :language: gherkin