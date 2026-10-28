@requirement.R_003
@capability.pki
@capability.certificate_lifecycle
@allure.label.epic:PKI
@allure.label.suite:Certificate_Lifecycle
Feature: Certificate lifecycle
  Trustpoint tracks certificate revocation as a persisted lifecycle state.

  Background:
    Given the admin user is logged into Trustpoint

  Scenario: Revoke an active certificate
    Given an active issued credential exists
    When the admin revokes the issued credential for key compromise
    Then the response status code is 200
    And the certificate is marked as revoked

  Scenario: Reject revocation of an already revoked certificate
    Given an active issued credential exists
    When the admin revokes the issued credential for key compromise
    Then the certificate is marked as revoked
    When the admin revokes the same issued credential again
    Then the lifecycle operation is rejected with status 422
