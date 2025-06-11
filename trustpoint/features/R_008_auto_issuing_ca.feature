@allure.label.epic:Features
@allure.label.suite:R_008_Auto_generated_Issuing_CAs
@allure.label.package:R_008_Auto_generated_Issuing_CAs
Feature: Auto-Generated Issuing CAs
  The system must automatically generate Issuing Certificate Authorities (CAs) based on configuration.

  Background:
    Given the admin user is logged into TPC_Web

  Scenario: Successful auto-generation of an issuing CA
    When the admin configures the system for auto-generation of an Issuing CA
    Then the system automatically generates the CA
    And the generated CA appears in the list of available CAs

  Scenario Outline: Auto-generation with different configurations
    When the admin sets the following CA configuration:
      | key_size   | validity_period | subject_name   |
      | <key_size> | <validity>      | <subject_name> |
    Then the system generates a CA with:
      | key_size   | validity_period | subject_name   |
      | <key_size> | <validity>      | <subject_name> |

    Examples:
      | key_size | validity | subject_name |
      | 2048     | 365      | CA_Test1     |
      | 4096     | 730      | Secure_CA    |

  Scenario: Handling missing parameters during CA generation
    When the admin attempts to generate an Issuing CA with incomplete configuration
    Then the system prevents the CA from being generated
    And an appropriate error message is logged

  Scenario: Verification of generated CA details
    When the admin inspects the generated CA details
    Then the CA should contain:
      | attribute     | expected_value   |
      | issuer name   | TPC_Web_CA       |
      | key usage     | Certificate Sign |
      | serial number | Auto-Generated   |

  Scenario: Ensuring the CA can issue certificates
    When the admin attempts to issue a certificate using the generated CA
    Then the certificate issuance should succeed
