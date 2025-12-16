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
