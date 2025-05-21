Feature: Encrypted Communication
  The communication between machines must be encrypted using the specified algorithm.

  Background:
    Given the system enforces encrypted communication with algorithm "AES-256"

  Scenario: Communication using the correct encryption algorithm
    Given a machine attempts to communicate using "AES-256"
    When the system verifies the encryption
    Then the communication should be "allowed"

  Scenario: Communication without encryption is blocked
    Given a machine attempts to communicate without encryption
    When the system verifies the encryption
    Then the communication should be "denied"
    And log the failure with reason "Unencrypted Communication Attempt"

  Scenario: Communication using an unsupported encryption algorithm is blocked
    Given a machine attempts to communicate using "RC4"
    When the system verifies the encryption
    Then the communication should be "denied"
    And log the failure with reason "Unsupported Encryption Algorithm"

  Scenario: Communication using a weak encryption algorithm is blocked
    Given a machine attempts to communicate using "DES"
    When the system verifies the encryption
    Then the communication should be "denied"
    And log the failure with reason "Weak Encryption Algorithm"

  Scenario: Communication uses the correct key exchange mechanism
    Given two machines establish a secure session using "ECDH"
    When the system verifies the key exchange
    Then the communication should be allowed

  Scenario: Communication is tamper-resistant
    Given an encrypted message is tampered with
    When the system detects tampering
    Then the communication should be "terminated"
    And log the failure with reason "Message Integrity Violation"
