@requirement.R_103
@capability.pki
@allure.label.epic:PKI
@allure.label.suite:Domain_Management
Feature: Domain management
  Administrators manage domains and their issuing authority through the Trustpoint web interface.

  Background:
    Given the admin user is logged into Trustpoint
    And a local issuing CA named "domain-test-ca" exists

  Scenario: Create a domain
    When the admin creates domain "factory-floor" using authority "domain-test-ca"
    Then the response status code is 200
    And domain "factory-floor" exists
    And domain "factory-floor" uses that authority

  Scenario: Delete a domain
    When that authority is assigned to domain "delete-domain"
    And the admin deletes domain "delete-domain"
    Then the response status code is 200
    And domain "delete-domain" no longer exists

  Scenario: Reject a duplicate domain name
    Given that authority is assigned to domain "existing-domain"
    When the admin creates domain "existing-domain" using authority "domain-test-ca"
    Then the response status code is 200
    And only one domain named "existing-domain" exists

  Scenario: Allow a certificate profile in a domain
    Given that authority is assigned to domain "profile-domain"
    And certificate profile "behave-domain-profile" exists
    When the admin allows profile "behave-domain-profile" with alias "factory-profile" in domain "profile-domain"
    Then the response status code is 200
    And domain "profile-domain" allows profile "behave-domain-profile" with alias "factory-profile"
