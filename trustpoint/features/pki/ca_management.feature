@requirement.R_008
@capability.pki
@allure.label.epic:PKI
@allure.label.suite:CA_Management
Feature: Certificate Authority management
  Administrators can configure issuing CAs through supported Trustpoint workflows.

  Background:
    Given the admin user is logged into Trustpoint

  Scenario: Import an issuing CA from PKCS12
    When the admin imports PKCS12 issuing CA "behave-imported-ca" from the test data
    Then the response status code is 200
    And issuing CA "behave-imported-ca" exists

  Scenario: Local managed CA is shown in the issuing CA list
    Given a local issuing CA named "behave-local-ca" exists
    When the admin opens the issuing CA list
    Then the response status code is 200
    And the issuing CA list contains "behave-local-ca"

  Scenario: Add Issuing CA page offers separate generation workflows
    When the admin opens the Add Issuing CA method selection
    Then the response status code is 200
    And the response contains "Import existing Issuing CA"
    And the response contains "Generate CSR"
    And the response contains "Auto-generated PKI"
