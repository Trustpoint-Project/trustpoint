Feature: Device Certificate Validation
  Devices in the network are only allowed to communicate with a valid certificate.

  Background:
    Given the system enforces certificate validation for all devices

  Scenario: Device with a valid certificate is allowed to communicate
    Given a device has a valid certificate
    When the device attempts to establish communication
    Then the system should allow the communication

  Scenario: Device with an expired certificate is denied communication
    Given a device has a expired certificate
    When the device attempts to establish communication
    Then the system should "deny" the communication
    And log the authentication failure with reason "Expired Certificate"

  Scenario: Device with a revoked certificate is denied communication
    Given a device has a revoked certificate
    When the device attempts to establish communication
    Then the system should "deny" the communication
    And log the authentication failure with reason "Revoked Certificate"

  Scenario: Device with a self-signed certificate is denied communication
    Given a device has a self-signed certificate
    When the device attempts to establish communication
    Then the system should "deny" the communication
    And log the authentication failure with reason "Untrusted Certificate Authority"

  Scenario: Device with a tampered certificate is denied communication
    Given a device has a tampered certificate
    When the device attempts to establish communication
    Then the system should "deny" the communication
    And log the authentication failure with reason "Certificate Integrity Violation"

  Scenario: Device attempts communication without a certificate
    Given a device does not present a certificate
    When the device attempts to establish communication
    Then the system should "deny" the communication
    And log the authentication failure with reason "Missing Certificate"
