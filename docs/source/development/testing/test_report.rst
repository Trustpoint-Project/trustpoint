.. _test_report:

***********
Test Report
***********

This document is providing a test report for Trustpoint.
It should be updated with every version bump.

.. warning::
    This is still w.i.p.!

=================
Unit Test Results
=================

For a summary of all pytest executions please see the output of the GitHub action
that provides an action to run every pytest.
This action can be found here:
`pytest action <https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml>`_.

The current status of all test executions is |pytest|.

.. |pytest| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml/badge.svg
    :alt: Pytest
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml

========================
Integration Test Results
========================

Since we are using :term:`BDD` to define the tests,
we provide the test runs by leveraging the :term:`behave` framework.
The summary of the tests can be seen in the following table.
For more detailed output please visit the corresponding github action pages.

.. csv-table:: Functional Requirements
   :header: "Name (Identifier)", "Title", "Status of the behave tests"
   :widths: 10, 60, 30

   _`R_001`, "Create, view, edit and delete a device", "|R_001_badge|"
   _`R_002`, "Usage of any zero touch onboarding protocol", "No test present."
   _`R_003`, "Certificate Lifecycle Management", "|R_003_badge|"
   _`R_004`, "REST API", "|R_004_badge|"
   _`R_005`, "Docker Container Support", "|R_005_badge|"
   _`R_006`, "Backup, Restore, and Update Mechanisms", "|R_006_badge|"
   _`R_007`, "Logging Capabilities", "|R_007_badge|"
   _`R_008`, "Auto-Generated :term:`Issuing CA`'s", "|R_008_badge|"
   _`R_009`, "High Availability", "No test present."
   _`R_010`, ":term:`CMP` Endpoint for Onboarded Devices", "|R_010_badge|"
   _`R_011`, ":term:`EST` Endpoint for Onboarded Devices", "|R_011_badge|"
   _`R_012`, "Language Selection and Translation", "|R_012_badge|"
   _`R_013`, "Remote Credential Download", "|R_013_badge|"
   _`R_101`, "Security Level Configuration", "|R_101_badge|"
   _`R_102`, "Certificate Template Security", "|R_102_badge|"
   _`R_103`, "Create, view, and delete a domain", "|R_103_badge|"
   _`R_104`, "Create, view, and delete a truststore", "|R_104_badge|"
   _`F_001`, "NTEU must be able to execute R_001 and R_002.", "|F_001_badge|"


.. |R_001_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_001_feature_test.yml/badge.svg
    :alt: R_001_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_001_feature_test.yml

.. |R_003_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_003_feature_test.yml/badge.svg
    :alt: R_003_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_003_feature_test.yml

.. |R_004_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_004_feature_test.yml/badge.svg
    :alt: R_004_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_004_feature_test.yml

.. |R_005_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/docker-test-compose.yml/badge.svg
    :alt: R_005_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/docker-test-compose.yml

.. |R_006_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_006_feature_test.yml/badge.svg
    :alt: R_006_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_006_feature_test.yml

.. |R_007_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_007_feature_test.yml/badge.svg
    :alt: R_007_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_007_feature_test.yml

.. |R_008_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_008_feature_test.yml/badge.svg
    :alt: R_008_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_008_feature_test.yml

.. |R_010_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_010_feature_test.yml/badge.svg
    :alt: R_010_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_010_feature_test.yml

.. |R_011_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_011_feature_test.yml/badge.svg
    :alt: R_011_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_011_feature_test.yml

.. |R_012_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_012_feature_test.yml/badge.svg
    :alt: R_012_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_012_feature_test.yml

.. |R_013_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_013_feature_test.yml/badge.svg
    :alt: R_013_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_013_feature_test.yml

.. |R_101_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_101_feature_test.yml/badge.svg
    :alt: R_101_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_101_feature_test.yml

.. |R_102_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_102_feature_test.yml/badge.svg
    :alt: R_102_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_102_feature_test.yml

.. |R_103_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_103_feature_test.yml/badge.svg
    :alt: R_103_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_103_feature_test.yml

.. |R_104_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_104_feature_test.yml/badge.svg
    :alt: R_104_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/r_104_feature_test.yml

.. |F_001_badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/f_001_feature_test.yml/badge.svg
    :alt: F_001_badge
    :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/f_001_feature_test.yml

===========================
Defect and Incident Reports
===========================

Here, the following should be provided:

- A summary of defects identified during testing.
- Resolution status of each defect.
- Associated logs for debugging.

==========================
Acceptance Testing Summary
==========================

Here, the following should be provided:

- Results of acceptance tests conducted with end users.
- User feedback and final approval status.
- Any open issues and their planned resolutions.

================
Coverage Metrics
================

The coverage metrics and the current coverage can be seen on `Codecov <https://app.codecov.io/>`_.
As of now, there is a coverage of |codecoverage|.

.. |codecoverage| image:: https://codecov.io/gh/Trustpoint-Project/trustpoint/graph/badge.svg?token=0N31L1QWPE
    :alt: Coverage
    :target: https://app.codecov.io/gh/Trustpoint-Project/trustpoint

=========================
Test Environment Details
=========================

To set up the test environment one can basically use the :ref:`trustpoint_dev_env_setup`.
The pipelines for running the tests are explained in the :ref:`ci_cd` chapter.

====================
Remaining Test Tasks
====================

Here, the following should be provided:

- Any pending testing activities or unresolved issues.
- Plan for further improvements, if applicable.
