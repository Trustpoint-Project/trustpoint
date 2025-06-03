@allure.label.owner:Aircoookie
@allure.label.epic:Features
@allure.label.suite:R_011_EST_Endpoint_for_Onboarded_Devices
@allure.label.package:R_011_EST_Endpoint_for_Onboarded_Devices
Feature: R_011 EST Endpoint for Onboarded Devices
  The system must provide an EST endpoint to securely onboard devices.

  Background:
    Given the EST endpoint is available

  Scenario Outline: Credential enrollment with a client certificate
    Given a new device with serial number "<serial_number>"
    And the IDevID Truststore and serial number registration pattern is configured in Trustpoint
    When the device sends an EST simpleenroll request for a new <credential_type> credential using its <client_cert_type> cert
    Then the request should <outcome>
    And if successful issue a new <credential_type> credential for "<serial_number>"
    And if failed the error message should be "<error_message>"

    Examples:
      | serial_number | client_cert_type | credential_type  | outcome | error_message |
      | Device123     | idevid           | domaincredential | succeed | -             |
      | Device234     | domaincredential | tlsserver        | succeed | -             |
      | Device345     | idevid           | tlsserver        | fail    | (any)         |
      | Device456     | tlsserver        | tlsserver        | fail    | must be DOMAIN_CREDENTIAL |
      | Device567     | idevid           | tlsserver        | fail    | must be DOMAIN_CREDENTIAL |
      | Device678     | tlsserver        | domaincredential | fail    | (any)         |

  Scenario: A device requests a second domain credential with its IDevID
    Given an onboarded device with serial number "Device123" and an issued valid domain credential
    When the device sends a EST request for a new domain credential using its IDevID
    Then the system should reject the request
    And if failed the error message should be "Device already onboarded"

  Scenario: A device successfully requests an application credential with username and password
    Given a new device with serial number "Device234"
    And the device is added to Trustpoint and the password is known to the device
    When the device sends a EST request for a new certificate
    Then the system should issue a new certificate for "Device234"
    And the device should store the issued certificate

  Scenario: An onboarded device renews its certificate
    Given an onboarded device with identifier "Device456" and an active certificate
    When the device sends a EST simplereenroll request for certificate renewal
    Then the system should issue a new certificate for "Device456"
    And the device should replace its old certificate with the new one

  Scenario: A device attempts to renew a different certificate
    Given an onboarded device with identifier "Device567" and an active certificate
    When the device sends a EST simplereenroll request where the CSR signer is different from the TLS client certificate
    Then the system should reject the request

  Scenario: A device attempts to renew an expired certificate
    Given an onboarded device with identifier "Device567" and an active certificate
    And the certificate has expired
    When the device sends a EST simplereenroll request for certificate renewal
    Then the system should reject the request

  Scenario: A device attempts to renew a revoked certificate
    Given an onboarded device with identifier "Device567" and an active certificate
    And an admin revokes the certificate for "Device567"
    When the device sends a EST simplereenroll request for certificate renewal
    Then the system should reject the request

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
