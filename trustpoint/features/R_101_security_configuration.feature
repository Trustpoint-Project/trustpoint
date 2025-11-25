@allure.label.epic:Features
@allure.label.suite:R_101_Security_Configuration
@allure.label.package:R_101_Security_Configuration
Feature: Security Level Configuration
  Administrators can configure security levels for different Trustpoint components.

  Background:
    Given the admin user is logged into TPC_Web

  Scenario Outline: Admin sets security level for a component
    Given the Trustpoint component <component> is selected
    When the admin sets the security level to <security_level>
    Then the system should apply the security level <security_level>
    And the system should log the security level change with details

    Examples:
      | component    | security_level |
      | TP_Client_01 | High           |
      | TP_Client_02 | Medium         |
      | TP_Client_03 | Low            |

  Scenario: Admin modifies an existing security level
    Given the Trustpoint component "TP_Client_01" has security level "Medium"
    When the admin sets the security level to "High"
    Then the system should apply the security level "High"
    And the system should log the security level change with details

  Scenario: Invalid security level input is rejected
    Given the Trustpoint component "TP_Client_01" is selected
    When the admin sets the security level to "UltraSecure"
    Then the system should reject the input with error "Invalid security level"

  Scenario: Security level persists after system restart
    Given the Trustpoint component "TP_Client_01" has security level "High"
    When the system is restarted
    Then the Trustpoint component "TP_Client_01" should still have security level "High"

  Scenario: Security level affects system behavior
    Given the Trustpoint component "TPC_Web" has security level "High"
    When an unauthorized user attempts access
    Then access should be denied

  Scenario: Security configuration changes are logged
    Given the Trustpoint component "TP_Client_01" is selected
    When the admin sets the security level to "High"
    Then the system should log the security level change with details
