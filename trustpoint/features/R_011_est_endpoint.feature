@allure.label.owner:Aircoookie
@allure.label.epic:Features
@allure.label.suite:R_011_EST_Endpoint_for_Onboarded_Devices
@allure.label.package:R_011_EST_Endpoint_for_Onboarded_Devices
Feature: R_011 EST Endpoint for Onboarded Devices
  The system must provide an EST endpoint to securely onboard devices.

  Background:
    Given the EST endpoint is available

  Scenario: A device successfully requests a certificate
    Given a new device with identifier "Device123"
    When the device sends a EST request for a new certificate
    Then the system should issue a new certificate for "Device123"
    And the device should store the issued certificate

  Scenario: An onboarded device renews its certificate
    Given an onboarded device with identifier "Device456" and an active certificate
    When the device sends a EST request for certificate renewal
    Then the system should issue a new certificate for "Device456"
    And the device should replace its old certificate with the new one

  Scenario: Unauthorized device attempts to access the EST endpoint
    Given a device with invalid credentials
    When the device sends a EST request
    Then the system should reject the request with an "Unauthorized" error

  Scenario: Admin revokes a device certificate
    Given a registered device with identifier "Device789" and a valid certificate
    When an admin revokes the certificate for "Device789"
    Then the system should update the revocation list
    And "Device789" should no longer authenticate using its certificate

  Scenario Outline: High load certificate issuance
    Given <num_devices> devices are requesting certificates simultaneously via EST
    When the EST endpoint processes the requests
    Then all certificates should be issued within <max_response_time> milliseconds

    Examples:
      | num_devices | max_response_time |
      | 100        | 500               |
      | 1000       | 1000              |
