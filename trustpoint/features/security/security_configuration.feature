@requirement.R_101
@capability.security
@allure.label.epic:Security
@allure.label.suite:Security_Configuration
Feature: Security configuration
  As a Trustpoint administrator
  I want to configure system-wide security requirements
  So that cryptographic and enrollment behavior follows the required security policy.

  Background:
    Given the admin user is logged into Trustpoint
    And a security configuration exists

  @smoke
  Scenario: Open the security configuration
    When the admin opens the security configuration
    Then the response status code is 200
    And the security configuration form is displayed

  @critical
  Scenario Outline: Apply a security level preset
    When the admin selects security mode "<mode>"
    Then the security mode is "<mode>"
    And the minimum RSA key size is "<rsa_key_size>"
    And the maximum certificate validity is "<certificate_validity>" days
    And the maximum CRL validity is "<crl_validity>" days

    Examples:
      | mode        | rsa_key_size | certificate_validity | crl_validity |
      | BROWNFIELD  | 1024         | 1825                 | 365          |
      | INDUSTRIAL  | 3072         | 365                  | 180          |
      | HARDENED    | 4096         | 365                  | 90           |
      | CRITICAL    | NONE         | 180                  | 90           |

  @normal
  Scenario: Lab mode allows unrestricted certificate validity
    When the admin selects security mode "LAB"
    Then the security mode is "LAB"
    And no maximum certificate validity is configured
    And no maximum CRL validity is configured

  @security
  Scenario: Critical Infrastructure mode disables RSA
    When the admin selects security mode "CRITICAL"
    Then RSA is not permitted
    And the minimum RSA key size is "NONE"

  @security
  Scenario: Hardened Production disables imported private keys
    When the admin selects security mode "HARDENED"
    Then imported private keys are not permitted
    And self-signed certificate authorities are not permitted
    And automatic PKI creation is not permitted

  @security
  Scenario: Critical Infrastructure disables imported private keys
    When the admin selects security mode "CRITICAL"
    Then imported private keys are not permitted
    And self-signed certificate authorities are not permitted
    And automatic PKI creation is not permitted

  @security
  Scenario: Lab mode permits imported private keys
    When the admin selects security mode "LAB"
    Then imported private keys are permitted
    And self-signed certificate authorities are permitted
    And automatic PKI creation is permitted

  @security
  Scenario: Industrial mode rejects legacy signature algorithms
    When the admin selects security mode "INDUSTRIAL"
    Then hash algorithm "MD5" is not permitted
    And hash algorithm "SHA1" is not permitted

  @security
  Scenario: Hardened mode applies stronger signature restrictions
    When the admin selects security mode "HARDENED"
    Then hash algorithm "MD5" is not permitted
    And hash algorithm "SHA1" is not permitted
    And hash algorithm "SHA224" is not permitted

  @security
  Scenario: Critical Infrastructure applies the strongest signature restrictions
    When the admin selects security mode "CRITICAL"
    Then hash algorithm "MD5" is not permitted
    And hash algorithm "SHA1" is not permitted
    And hash algorithm "SHA224" is not permitted
    And hash algorithm "SHA256" is not permitted

  @security
  Scenario: Hardened mode limits onboarding credential lifetime
    When the admin selects security mode "HARDENED"
    Then the onboarding credential TTL is 600 seconds

  @security
  Scenario: Critical Infrastructure limits onboarding credential lifetime
    When the admin selects security mode "CRITICAL"
    Then the onboarding credential TTL is 600 seconds

  @validation
  Scenario: Reject a zero onboarding credential TTL
    Given security mode "LAB" is active
    When the admin sets the onboarding credential TTL to 0 seconds
    Then the security configuration is rejected
    And the security configuration contains an error for "credential_ttl_seconds"

  @validation
  Scenario: Reject an excessive credential TTL in Hardened mode
    Given security mode "HARDENED" is active
    When the admin sets the onboarding credential TTL to 601 seconds
    Then the security configuration is rejected
    And the security configuration contains an error for "credential_ttl_seconds"

  @normal
  Scenario: Store custom protocol allow-lists
    Given security mode "LAB" is active
    When the admin permits the following no-onboarding PKI protocols:
      | protocol          |
      | CMP_SHARED_SECRET |
      | MANUAL            |
    And the admin permits the following onboarding protocols:
      | protocol               |
      | MANUAL                 |
      | REST_USERNAME_PASSWORD |
    Then the permitted no-onboarding PKI protocols are:
      | protocol          |
      | CMP_SHARED_SECRET |
      | MANUAL            |
    And the permitted onboarding protocols are:
      | protocol               |
      | MANUAL                 |
      | REST_USERNAME_PASSWORD |

  @integration
  Scenario: Capabilities API reflects the configured protocol policy
    Given security mode "LAB" is active
    And only no-onboarding PKI protocol "EST_USERNAME_PASSWORD" is permitted
    And only onboarding protocol "EST_IDEVID" is permitted
    When the capabilities API is requested
    Then the response status code is 200
    And no-onboarding capability "est_username_password" is enabled
    And no-onboarding capability "cmp_shared_secret" is disabled
    And no-onboarding capability "manual" is disabled
    And no-onboarding capability "rest_username_password" is disabled
    And onboarding capability "est_idevid" is enabled
    And onboarding capability "cmp_shared_secret" is disabled
    And onboarding capability "rest_username_password" is disabled

  @security
  Scenario: BRSKI cannot be enabled through the security configuration
    When the admin opens the security configuration
    Then onboarding protocol "BRSKI" is not offered

  @authorization
  Scenario: User without security configuration permission cannot change the security policy
    Given a user without the "manage_security_configuration" permission is logged in
    When the user attempts to change the security mode to "HARDENED"
    Then the response status code is 403
    And the security mode was not changed