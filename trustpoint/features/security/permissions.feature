@requirement.R_102
@capability.security
@allure.label.epic:Security
@allure.label.suite:Permissions
Feature: Role and API permissions
  Trustpoint protects administrative capabilities with explicit permissions.

  Scenario: Service account receives REST API permission
    Given an active service account credential exists
    Then the service account has REST API permission

  Scenario: Non-privileged user cannot manage certificate profiles
    Given a non-privileged human user named "behave-operator" exists
    When that user attempts to manage a certificate profile
    Then access to the protected page is denied
