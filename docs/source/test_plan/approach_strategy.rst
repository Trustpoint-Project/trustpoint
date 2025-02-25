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