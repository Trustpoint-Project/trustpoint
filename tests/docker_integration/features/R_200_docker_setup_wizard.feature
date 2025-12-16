@allure.label.epic:Features
@allure.label.suite:R_200_Docker_Setup_Wizard
@allure.label.package:R_200_Docker_Setup_Wizard
Feature: Docker Setup Wizard
  As a new user deploying Trustpoint via Docker
  I want to complete the initial setup wizard
  So that I can configure the system and start using Trustpoint

  Scenario: Complete initial setup wizard with file system storage
    Given a fresh Trustpoint Docker container is running
    When the user accesses the setup wizard
    Then the wizard should be at the crypto storage setup step
    When the user selects "File System" as crypto storage
    And the user submits the form
    Then the wizard should be at the setup mode step
    When the user clicks "Start Fresh Setup"
    Then the wizard should be at the TLS server credential selection step
    When the user clicks "Generate Certificate"
    Then the wizard should be at the TLS certificate generation step
    When the user submits the SAN form with default values
    Then the wizard should be at the TLS apply step
    When the user clicks "Apply TLS configuration"
    And the user waits for the server to restart
    Then the wizard should be at the demo data step
    When the user clicks "Continue without Demo Data"
    Then the wizard should be at the superuser creation step
    When the user creates a superuser with username "admin" and password "AdminPass123!"
    Then the setup should be complete
    And the user should be redirected to the login page
    When the user logs in with username "admin" and password "AdminPass123!"
    Then the user should successfully access the dashboard

    # Navigate to main views to verify they load without errors
    When the user navigates to "/devices/"
    Then the page should load without errors

    When the user navigates to "/pki/domains/"
    Then the page should load without errors

    When the user navigates to "/pki/issuing-cas/"
    Then the page should load without errors

    When the user navigates to "/pki/certificates/"
    Then the page should load without errors

    When the user navigates to "/pki/truststores/"
    Then the page should load without errors

    When the user navigates to "/pki/owner-credentials/"
    Then the page should load without errors

    When the user navigates to "/pki/cert-profiles/"
    Then the page should load without errors

    When the user navigates to "/signer/"
    Then the page should load without errors

    When the user navigates to "/management/settings/"
    Then the page should load without errors

    When the user navigates to "/management/tls/"
    Then the page should load without errors

    When the user navigates to "/management/logging/files/"
    Then the page should load without errors

    When the user navigates to "/management/backups/"
    Then the page should load without errors

    When the user navigates to "/management/key_storage/"
    Then the page should load without errors

    When the user navigates to "/management/help/"
    Then the page should load without errors

    When the user navigates to "/home/"
    Then the page should load without errors

    When the user navigates to "/home/dashboard/"
    Then the page should load without errors

    When the user navigates to "/devices/opc-ua-gds/"
    Then the page should load without errors

    When the user navigates to "/workflows/"
    Then the page should load without errors

    When the user navigates to "/swagger/"
    Then the page should load without errors

    When the user navigates to "/redoc/"
    Then the page should load without errors

  Scenario: Add a new device with no onboarding and enable PKI protocols
    When the user navigates to "/devices/create/no-onboarding/"
    Then the page should load without errors
    When the user fills the device form with:
      | name         | TestDevice01         |
      | description  | Device for PKI test |
      | enable_cmp   | true                |
      | enable_est   | true                |
      | enable_manual| true                |
    And the user enables CMP shared secret
    And the user enables EST username password
    And the user enables Manual enrollment
    And the user submits the form
    Then the device should be created successfully
    And the device should have PKI protocols enabled:
      | protocol     |
      | CMP         |
      | EST         |
      | Manual      |
