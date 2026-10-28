@requirement.R_004
@capability.api
@capability.pki
@allure.label.epic:API
@allure.label.suite:REST_PKI
Feature: REST PKI API authorization
  The REST PKI management endpoints must reject unauthenticated callers before certificate operations are executed.

  Scenario: Unauthenticated enrollment is rejected
    When an unauthenticated client posts to the REST PKI enroll endpoint
    Then the response is an authentication failure

  Scenario: Unauthenticated revocation is rejected
    When an unauthenticated client posts to the REST PKI revoke endpoint
    Then the response is an authentication failure

  Scenario: Authenticated enrollment reports a missing target device
    Given an active service account credential exists
    When the service account requests an OAuth2 token with client credentials
    Then the response status code is 200
    When the authenticated service account enrolls for missing device 999999
    Then the response status code is 404
    And the response contains "Device with id 999999 not found."
