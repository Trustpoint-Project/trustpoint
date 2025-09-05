@allure.label.epic:Features
@allure.label.suite:R_102_Certificate_Template_Security
@allure.label.package:R_102_Certificate_Template_Security
Feature: Certificate Template Security
  Enforce access control and secure handling for certificate templates.

  Background:
    Given the admin user is logged into TPC_Web

  Scenario Outline: Authorized user accesses certificate templates
    Given the user has role <role>
    When the user attempts to access certificate templates
    Then access should be <access_outcome>

    Examples:
      | role  | access_outcome |
      | Admin | granted        |
      | User  | denied         |

  Scenario Outline: Unauthorized user attempts to modify a certificate template
    Given the user has role <role>
    And a certificate template named <template_name> exists
    When the user attempts to modify the certificate template
    Then modification should be <modification_outcome>

    Examples:
      | role  | template_name   | modification_outcome |
      | Admin | Secure_Template | allowed              |
      | User  | Secure_Template | denied               |

  Scenario: Secure handling of certificate templates
    Given a certificate template named "Sensitive_Template" exists
    When an unauthorized user attempts to access it
    Then access should be denied
    And the attempt should be logged

  Scenario: Unauthorized deletion attempt
    Given a certificate template named "HighSecurity_Template" exists
    When a non-admin user attempts to delete it
    Then the deletion should be rejected
    And an error message "Permission denied" should be shown

  Scenario: Secure export of certificate templates
    Given a certificate template named "Exportable_Template" exists
    When an admin exports the template
    Then the exported template should be encrypted

  Scenario: Unauthorized export attempt
    Given a certificate template named "Exportable_Template" exists
    When a non-admin user attempts to export the template
    Then export should be denied
    And the attempt should be logged
