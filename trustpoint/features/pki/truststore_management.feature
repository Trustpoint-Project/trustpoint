@requirement.R_104
@capability.pki
@allure.label.epic:PKI
@allure.label.suite:Truststore_Management
Feature: Truststore management
  Administrators can import and remove truststores through the public web interface.

  Background:
    Given the admin user is logged into Trustpoint

  Scenario: Import a TLS truststore
    Given a truststore file named "trust_store.pem" from the test data
    When the admin creates truststore "behave-tls-truststore" for intended usage "TLS"
    Then the response status code is 200
    And truststore "behave-tls-truststore" exists

  Scenario: Delete an existing truststore
    Given a truststore file named "trust_store.pem" from the test data
    When the admin creates truststore "delete-truststore" for intended usage "TLS"
    Then truststore "delete-truststore" exists
    When the admin deletes truststore "delete-truststore"
    Then the response status code is 200
    And truststore "delete-truststore" no longer exists
