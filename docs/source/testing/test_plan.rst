.. _test_plan:

*********
Test Plan
*********

This document is providing a test plan for Trustpoint
using the IEEE 829 standard for structuring this plan.

============
Introduction
============

The purpose of this test plan should be to test all required functions which are briefly described
inside the `GitHub repository <https://github.com/TrustPoint-Project/trustpoint>`_.
Also, there is a separation between functionality and user experience.
Since the project is heavily relying on securing networks as simple as possible,
the user experience should be as important as the functionality.

Summarized, this test plan is intended to ensure, through the execution and documentation of all tests, the

- functionality,
- usability,
- security and
- integration capability

of Trustpoint.
This is done by specifying and implementing the above-mentioned requirements in software tests.

.. _test-items-functions:

======================
Test Items (Functions)
======================

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
   _`R_008`, "Auto-Generated :term:`Issuing CA`'s", "Automatically generate Issuing Certificate Authorities based on configuration.", "TPC_Web", "High"
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

====================
Software Risk Issues
====================

All software testing involves risks, which are listed below in order to minimize them.

- *Incomplete requirements:*
    As Trustpoint is a research project,
    it can happen that requirements are incomplete and only become apparent in retrospect that they would have been important.

- *Incomplete test coverage:*
    Although we strive to keep the test coverage as high as possible,
    sometimes not everything can be tested.
    As a result, some execution paths may be left out,
    with the resulting problems only becoming apparent during productive operation.

- *Lack of time for testing:*
    It could well happen that the test plan is too long and complex,
    so that we run out of time with the software tests.

- *Problems with the test environment:*
    Not every (automated) test can be carried out on a real environment.
    Therefore, simulation components are likely to be used,
    but these will probably not represent exactly the same devices as they will look like in the production environment.
    An example of this would be the simulation or integration of older machines which do not provide a certificate signed by the manufacturer.

- *User-friendliness:*
    The testers of the program's interface (acceptance testing) should be people with as little technical knowledge as possible,
    as otherwise the tests may give a false picture when tested by people from the development team.

- *Problems with manual testing:*
    We should thrive for automatic testing, although not every requirement can be tested automatically.
    That is, because the manual testing techniques are sometimes but not always the root of an error.

=====================
Features To Be Tested
=====================

This chapter lists all needed requirements of Trustpoint, e.g. creating certificates.
These requirements are now front-end requirements as well as user experience.
This is also the main difference between chapter :ref:`test-items-functions` and this chapter.
The `table of all actors <Trustpoint-Actors-Table>`_ is still used though.

.. csv-table:: Features To Be Tested
   :header: "Name (Identifier)", "Title", "Description", "Component(s)", "Importance"
   :widths: 10, 25, 60, 30, 10

    "F_001", "NTEU must be able to execute R_001 and R_002.", "NTEU must be able to log in to the TCP_Web app and carry out the processes described in R_001 and R_002.  ", "TPC_Web, NTEU", "High"

=========================
Features Not To Be Tested
=========================

There are no features present right now which we do not want to test.

===================
Approach (Strategy)
===================

--------------
Testing Levels
--------------

The testing will consist of Unit, System/Integration (combined), and Acceptance test levels.

^^^^^^^^^^^^
Unit Testing
^^^^^^^^^^^^

Unit testing will be conducted by the developers and approved by another developer.
Before unit testing is considered complete and the components are passed on for further testing,
developers must provide evidence of successful testing. This includes:

- A list of test cases executed
- Sample output
- Input data sets
- Documentation of identified and resolved defects

Note that this can be done automatically.

All unit test artifacts will also be shared with the test engineer for validation and record-keeping.
The focus of unit testing will be on verifying the functionality of individual modules of Trustpoint.

^^^^^^^^^^^^^^^^^^^^^^^^^^
System/Integration Testing
^^^^^^^^^^^^^^^^^^^^^^^^^^

System/Integration testing will be carried out by the test developer and the full development team.
The primary goal at this stage is to ensure that all Trustpoint modules work together seamlessly,
emphasizing interoperability, data consistency, and security.

Also, testing the software under high load and in a larger system should be performed. (Scalability)
(It could be the case that those tests are not feasible, because we cannot create such a broad testing environment.)

^^^^^^^^^^^^^^^^^^
Acceptance Testing
^^^^^^^^^^^^^^^^^^

Acceptance testing will be conducted by the end-users with assistance from the test manager or one of the developers.
This phase will focus on validating the Trustpoint system’s usability, reliability,
and alignment with user expectations in a production-like environment.
The testing process will involve:

- Evaluating user workflows,
- trust validation,
- and secure interactions to ensure the system meets all functional requirements.

Programs will enter acceptance testing only after all critical and major defects have been resolved.

Note that we are able to test user workflows automatically at the integration test phase
but there needs to be another acceptance test phase where we actually provide manual tests.

----------
Test Tools
----------

The testing for the Trustpoint project will utilize modern testing frameworks
and tools to ensure robust and efficient validation of the application’s functionality across all levels.

^^^^^^^^^^^^
Unit Testing
^^^^^^^^^^^^

Unit testing for the core functionalities of Trustpoint will be implemented using `pytest <https://docs.pytest.org/en/stable/>`_,
a widely adopted Python testing framework.
This ensures comprehensive and automated validation of the smallest testable units.
Tests will be integrated into the defined GitHub pipelines to enable continuous integration and delivery (CI/CD).
These pipelines will ensure that any changes to the codebase are thoroughly tested before merging,
reducing the risk of regressions and enhancing development agility.

^^^^^^^^^^^^^^^^^^^^^^^^^^
Integration/System Testing
^^^^^^^^^^^^^^^^^^^^^^^^^^

Integration testing will leverage :term:`behave` to create :term:`BDD` test scenarios.
This approach will allow us to define tests in plain language
that are easy to understand for both technical and non-technical stakeholders.
The scenarios will focus on validating the interactions between Trustpoint components,
ensuring that they function cohesively as a system.

^^^^^^^^^^^^^^^^^^
Acceptance Testing
^^^^^^^^^^^^^^^^^^

The tool for acceptance testing has not been finalized at this stage.
However, efforts are underway to evaluate suitable tools that align with the requirements of end-user testing.
In the interim, manual acceptance testing will be performed in collaboration with end users
to validate the system's readiness for production.

^^^^^^^^^^^^^^^
Data Management
^^^^^^^^^^^^^^^

Data for testing will primarily be sourced from production-like datasets
to simulate real-world scenarios effectively.
Where necessary, synthetic data will be generated or modified using Python-based utilities to ensure test completeness.
Under no circumstances will changes be made directly to actual production data during testing activities.

=======================
Item Pass/Fail Criteria
=======================

The test process for the Trustpoint project will be considered complete once the following criteria have been met:

#. Core Functionalities Validation:
    - All critical and major defects identified during unit, integration, and system testing must be resolved.
    - The core functionalities of Trustpoint, such as certificate issuance, renewal, revocation, and domain validation, must operate reliably without workarounds.

#. Integration Testing Success:
    - The PKI components must demonstrate seamless interaction, with no critical or major integration issues.
    - Simulated high-volume certificate management scenarios should execute without performance degradation or system crashes.

#. Acceptance Testing Completion:
    - The platform must pass acceptance testing by end users, ensuring it meets their operational requirements.
    - All critical and major defects discovered during this phase must be corrected, verified, and closed.

#. Data Integrity Verification:
    - Test data generated during the system/integration and acceptance phases must validate correctly against expected outcomes, ensuring the platform’s reliability and accuracy in managing certificates.
    - Production-like scenarios must confirm data consistency across all Trustpoint modules.

#. PKI Compliance Validation:
    - Trustpoint’s processes must comply with PKI standards and security protocols.
    - Certificate data exchanges and storage must adhere to security best practices.

#. Deployment Readiness:
    - The system must pass GitHub pipeline tests, including automated unit and integration tests executed through pytest and :term:`behave`, with 100% of critical tests passing.
    - The staging environment must match the production setup, with successful parallel runs simulating live scenarios for a predefined period (e.g., two weeks).

Once these criteria are satisfied, Trustpoint will be considered ready for live deployment.
Following this, any additional configurations, user onboarding,
or domain activations will occur incrementally as per readiness and validation.

===============================================
Suspension Criteria And Resumption Requirements
===============================================

.. csv-table:: Suspension Criteria And Resumption Requirements
   :header: "Title", "Suspension", "Resumption"
   :widths: 30, 50, 50

    "Unavailability of CA or Domain Validation Services", "Testing will be paused if the certificate authority (CA) or domain validation services are unavailable, as these are critical for validating PKI-related functionalities.", "Testing will resume once the CA or validation services are operational, and any interrupted test cases will be re-executed to ensure completeness."
    "Critical Defect Identified in Core Functionality", "If a critical defect in core features (e.g., certificate issuance, revocation, or renewal) is identified during testing, further testing will be suspended until the issue is resolved.", "Testing will resume once the defect is fixed and verified in the development environment."
    "Test Environment Instability", "Testing will pause if the staging or testing environment becomes unstable or misconfigured, as this could lead to unreliable results.", "Testing will resume after the environment is restored to a stable and functional state, and necessary validations have been performed."
    "Unavailability of Required Test Data", "If critical test data (e.g., domain configurations, certificate requests) is unavailable or incomplete, testing will be suspended for the affected areas.", "Testing will resume once sufficient test data has been prepared and verified."
    "Staffing or Resource Constraints", "If key personnel (e.g., test managers or developers) or resources (e.g., access to tools or infrastructure) are unavailable, testing may be delayed for impacted areas.", "Testing will resume once adequate staffing and resources are available to continue the process effectively."

=================
Test Deliverables
=================

The following consolidated deliverable will be provided at the conclusion of the Trustpoint testing process:

*Comprehensive Test Report:*

This single document will include the following components:

#. Unit Test Results:
    - Summary of pytest executions, including test case descriptions, pass/fail status, and defect details.
    - Logs and outputs from automated tests executed through GitHub pipelines.

#. Integration Test Results:
    - Results from :term:`BDD` tests using the :term:`behave` framework.
    - Detailed logs of test scenarios, their outcomes, and any identified issues.

#. Defect and Incident Reports:
    - A summary of defects encountered during testing phases, their resolution status, and associated incident logs.

#. Acceptance Testing Summary:
    - Results of acceptance tests, including user feedback and final approval status.
    - Any open issues and their planned resolutions (if applicable).

#. Coverage Metrics:
    - Test coverage statistics to demonstrate the completeness of testing efforts.

====================
Remaining Test Tasks
====================

.. csv-table:: Remaining Test Tasks
   :header: "Task", "Assigned To", "Status"
   :widths: 60, 20, 15

   "Collect and finalize testing requirements (e.g., PKI workflows, certificate lifecycle scenarios).", "TM, PM, Client", "In Progress"
   "Define and finalize acceptance criteria for Trustpoint’s features.", "TM, PM, Client", "Pending"
   "Configure and validate the test environments (development and staging).", "TM, Dev", "In Progress"
   "Develop unit tests using pytest for core functionalities (e.g., certificate issuance, renewal, and revocation).", "Dev", "In Progress"
   "Develop integration tests using :term:`behave` for end-to-end workflows.", "TM, Dev", "Pending"
   "Execute system/integration tests in the staging environment.", "TM, Dev", "Not Started"
   "Document results from unit, integration, and acceptance tests for inclusion in the comprehensive test report.", "TM", "Not Started"
   "Conduct acceptance testing with end users (e.g., system administrators, security teams).", "TM, Client", "Not Started"
   "Resolve defects identified during testing and retest as needed.", "Dev", "Ongoing"
   "Finalize and deliver the comprehensive test report (including test results and coverage).", "TM", "Not Started"

===================
Environmental Needs
===================

The following elements are required to support the testing effort at all levels within the Trustpoint project:

#. Access to Development and Staging Environments:
    - A dedicated development environment for initial testing, debugging, and iterative fixes.
    - A staging environment that mirrors the production setup for system, integration, and acceptance testing.

#. Certificate Authority (CA) Setup:
    - Access to a functional CA system to validate PKI-related features such as certificate issuance, renewal, and revocation.

#. GitHub CI/CD Pipeline Configuration:
    - An operational GitHub pipeline to automate testing and deployment workflows. This pipeline will execute unit and integration tests using pytest and :term:`behave` frameworks.

#. Database Access:
    - Availability of a testing database populated with production-like data to simulate realistic scenarios.
    - A clear separation between testing and production data to ensure no overlap or accidental data modification.

#. Secure Networking Configuration:
    - A secure network environment for testing interactions between Trustpoint components, including domain validation and security protocol testing.

#. Access to Backup/Recovery Processes:
    - Access to nightly backup and recovery tools for safeguarding test environment data.

#. Testing Tools:
    - Functional installations of pytest and :term:`behave` for automated testing.
    - Additional tools may be added as acceptance testing needs evolve.

This streamlined setup ensures an effective and efficient testing process while minimizing redundancy and complexity.

===========================
Staffing And Training Needs
===========================

#. Staffing Requirements
    - At least one dedicated tester should be assigned for the integration and acceptance testing phases to ensure thorough and independent validation.
    - In the absence of a dedicated tester, the test manager will assume this role with support from the development team.
    - Developers will assist in test case creation and debugging during the unit testing and integration testing phases.

#. Training Needs
    - Developers and Testers:
        - Familiarity with Trustpoint’s core functionality, including certificate issuance, renewal, revocation, and domain validation workflows.
        - Training on pytest for unit testing and :term:`behave` for integration testing, including understanding the GitHub pipeline integration.

    - End Users:
        - Training on navigating Trustpoint’s user interfaces, configuring domains, and interpreting system-generated reports.

================
Responsibilities
================

.. csv-table:: Responsibilities
   :header: "Responsibility", "TM", "PM", "Dev", "Test Team", "Client"
   :widths: 40, 10, 10, 10, 15, 10

   "Acceptance Test Documentation & Execution", "X", "X", "", "X", "X"
   "System/Integration Test Documentation & Execution", "X", "X", "X", "X", ""
   "Unit Test Documentation & Execution", "X", "", "X", "", ""
   "System Design Reviews", "X", "X", "X", "X", "X"
   "Detailed Design Reviews", "X", "X", "X", "X", ""
   "Test Procedures and Rules", "X", "X", "X", "X", ""
   "Change Control and Regression Testing", "X", "X", "X", "X", ""
   "Certificate Lifecycle Scenarios Review", "X", "X", "X", "", "X"

========
Schedule
========

The following schedule outlines the remaining testing activities.
These activities are aligned with the project's current progress and emphasize completing testing efficiently and effectively.
Specific dates and durations should be detailed in the project timeline managed by the project manager
in collaboration with development and test leads.

.. csv-table:: Testing Schedule Table
   :header: "Activity", "Responsibility", "Duration/Timeline", "Details"
   :widths: 30, 30, 20, 60

   "Review Requirements Document", "Test Team, Dev, PM", "1 Week", "Review requirements to ensure complete understanding and alignment of test objectives."
   "Finalize and Review Requirements", "TM, PM, Test Team", "1 Week", "Develop and review the requirements needed for writing the acceptance tests."
   "Review System Design Document", "Test Team, Dev", "3 Days", "Enhance understanding of the system structure and refine test objectives."
   "Conduct Unit Tests", "Dev", "Ongoing until code completion", "Verify individual methods/functions as they are completed; results reviewed by the development lead."
   "System/Integration Testing", "Test Team, Dev", "2 Weeks", "Validate module interactions, data flow, and PKI processes in a staging environment."
   "Acceptance Testing", "Test Team, End Users, PM", "2 Weeks", "Perform final user-driven testing to ensure Trustpoint meets functional and usability expectations."

================================
Planning Risks And Contingencies
================================

.. csv-table:: Planning Risks And Contingencies
   :header: "Risk", "Description", "Contingency Plan"
   :widths: 30, 50, 50

   "Limited Staff Availability for Testing", "Key stakeholders or end users may have limited availability during acceptance testing.", "Schedule testing in advance; assign a test team representative if stakeholders are unavailable."
   "Incomplete or Changing Requirements", "Requirements may evolve or be incomplete, leading to rework or missed test cases.", "Conduct iterative reviews; adopt agile testing practices to adapt dynamically to changes."
   "Test Environment Instability", "The staging or test environment may become misconfigured or unavailable, causing delays.", "Maintain backup environments; use configuration checklists to ensure reliable setups."
   "Delays in Defect Resolution", "Defects may take longer to resolve, impacting subsequent testing phases.", "Prioritize critical defects; allocate additional resources for prompt resolution."
   "Dependence on External Systems", "External PKI components (e.g., Certificate Authorities) may be unavailable during testing.", "Use mock services or simulators; coordinate with service providers to ensure availability."
   "Inadequate Test Data", "Insufficient or unrealistic test data may result in incomplete testing or missed edge cases.", "Generate synthetic data using Python utilities; use anonymized production-like datasets for validation."

=========
Approvals
=========

==========
Test Cases
==========

Since we are using the :term:`BDD` principle for system and integration testing,
we decided on specifying the tests directly inside the :term:`Cucumber` feature files.
This has the advantage of removing the need to keep two or more documents updated at the same time.
Also, :term:`Gherkin` is a well organized language such that the test ideas and steps
are possible to read - even for people without a background in software engineering.
That being said, we state the feature files in the following and provide a brief description on the test ideas.

-----------------------
Functional Requirements
-----------------------

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

#. Successful Auto-Generation of an :term:`Issuing CA`
    - The admin configures the system with predefined settings for an :term:`Issuing CA`.
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

---------------------
Security Requirements
---------------------

^^^^^
R_101
^^^^^

This testcase is related to requirement `R_101`_.

"""""""""
Test Idea
"""""""""

To verify that only devices with valid certificates can communicate, we will test the following scenarios:

#. Device with a Valid Certificate Can Communicate
    - A device is provisioned with a valid certificate.
    - The system allows the device to establish communication.

#. Device with an Expired Certificate is Denied
    - A device presents an expired certificate.
    - The system denies communication and logs the attempt.

#. Device with a Revoked Certificate is Denied
    - A certificate is revoked by the system administrator.
    - A device attempting to communicate with the revoked certificate is rejected.

#. Device with a Self-Signed or Untrusted Certificate is Denied
    - A device presents a self-signed certificate.
    - The system denies communication.

#. Device with a Tampered Certificate is Denied
    - A device presents a certificate with altered data.
    - The system detects the tampering and blocks communication.

#. Device Attempts Communication Without a Certificate
    - A device attempts to communicate without presenting any certificate.
    - The system rejects the request.

#. Logging of Authentication Failures
    - Every failed authentication attempt due to an invalid, expired, or revoked certificate is logged.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_101_device_cert_validation.feature
   :language: gherkin

^^^^^
R_102
^^^^^

This testcase is related to requirement `R_102`_.

"""""""""
Test Idea
"""""""""

To verify that communication between machines is encrypted using the given algorithm, we will test the following scenarios:

#. Valid Encrypted Communication
    - Two machines establish a communication session.
    - The communication is encrypted using the specified encryption algorithm.
    - The system successfully verifies encryption.

#. Communication with No Encryption is Rejected
    - A machine attempts to communicate without encryption.
    - The system detects the unencrypted communication and blocks it.
    - The system logs the rejected attempt.

#. Communication Using an Unsupported Encryption Algorithm is Rejected
    - A machine attempts to use an encryption algorithm that is not approved.
    - The system rejects the communication.
    - The system logs the failed attempt.

#. Communication Using a Weak Encryption Algorithm is Rejected
    - A machine attempts to use a weak or deprecated encryption algorithm.
    - The system denies the communication.
    - The system logs the failure with a warning.

#. Communication is Encrypted with the Correct Key Exchange Mechanism
    - Two machines establish a secure session using the correct key exchange protocol.
    - The system verifies that the encryption is correctly applied.

#. Communication is Tamper-Resistant
    - A third party attempts to modify an encrypted message.
    - The system detects the tampering and terminates the connection.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_102_encrypted_communication.feature
   :language: gherkin

^^^^^
R_103
^^^^^

This testcase is related to requirement `R_103`_.

"""""""""
Test Idea
"""""""""

To verify that administrators can configure security levels for different Trustpoint components, we will test the following scenarios:

#. Set Security Level for a Component
    - The admin selects a Trustpoint component.
    - The admin sets the security level to "High".
    - The system successfully applies and saves the security level.

#. Modify an Existing Security Level
    - The admin updates the security level of a component from "Medium" to "High".
    - The system correctly applies and reflects the change.

#. Invalid Security Level Input is Rejected
    - The admin attempts to set an invalid security level.
    - The system rejects the input and displays an error.

#. Security Level Persists After System Restart
    - The admin configures a security level for a component.
    - The system is restarted.
    - The security level remains correctly applied.

#. Security Level Affects System Behavior
    - A component with a high-security level enforces stricter access control.
    - A component with a low-security level has more lenient settings.
    - The system behaves accordingly.

#. Security Configuration is Logged
    - Every change to security levels is logged.
    - The log contains details such as timestamp, admin ID, and old/new security levels.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_103_security_configuration.feature
   :language: gherkin

^^^^^
R_104
^^^^^

This testcase is related to requirement `R_104`_.

"""""""""
Test Idea
"""""""""

To verify that certificate template security is enforced properly, we will test the following scenarios:

#. Only Authorized Users Can Access Certificate Templates
    - A user with admin privileges accesses the certificate templates.
    - A regular user attempts to access certificate templates but is denied.

#. Secure Handling of Certificate Templates
    - A certificate template is created with restricted access.
    - The system prevents unauthorized modifications.
    - The system encrypts stored templates.

#. Modification of Certificate Templates
    - An admin updates a certificate template.
    - Unauthorized users attempt modifications but are denied.

#. Deletion Restrictions
    - Only authorized users can delete certificate templates.
    - Unauthorized users receive an error when attempting deletion.

#. Logging of Access and Modifications
    - The system logs every access and modification of certificate templates.

#. Secure Export of Certificate Templates
    - The system ensures that exported templates are encrypted.
    - Unauthorized export attempts are blocked.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_104_certificate_template_security.feature
   :language: gherkin

--------------------
Feature Requirements
--------------------

^^^^^
F_001
^^^^^

This testcase is related to requirement `F_001`_.

"""""""""
Test Idea
"""""""""

To verify that an NTEU (Non-Technical Experienced User) can successfully execute `R_001`_ and `R_002`_ in TPC_Web, we will test the following scenarios:

#. NTEU Logs into the System
    - A valid NTEU logs into the system successfully.
    - An invalid NTEU login attempt fails.

#. Identity Management (`R_001`_)
    - NTEU creates a digital identity.
    - NTEU views an existing digital identity.
    - NTEU edits an existing digital identity.
    - NTEU deletes a digital identity.

#. Zero-Touch Onboarding (`R_002`_)
    - NTEU initiates device onboarding.
    - The system automatically uses a zero-touch onboarding protocol.
    - The onboarding process completes successfully.

#. UI Accessibility and User Experience
    - The UI provides clear instructions and feedback.
    - Error messages are understandable for an NTEU.
    - The onboarding and identity management workflows are intuitive.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/F_001_nteu_identity_onboarding.feature
   :language: gherkin

========
Glossary
========

.. csv-table:: Glossary
   :header: "Abbreviation", "Definition"
   :widths: 50, 50

    "TM", "Test Manager"
    "PM", "Project Manager"
    "Dev", "Development Team"
    "Client", "Stakeholders or End Users"
