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
    And the user proceeds to the next step
    Then the wizard should be at the setup mode selection step
    When the user selects "Setup with Test Mode" setup mode option
    And the user proceeds to the next step
    Then the wizard should be at the TLS server credential step
    When the user selects "Generate Self-Signed Certificate" TLS certificate option
    And the user proceeds to the next step
    Then the wizard should be at the demo data step
    When the user chooses to skip demo data
    And the user proceeds to the next step
    Then the wizard should be at the superuser creation step
    When the user creates admin account with username "admin" and password "AdminPass123!"
    And the user submits the setup wizard
    Then the setup wizard should be completed
    And the user should be redirected to the login page
    When the user logs in with username "admin" and password "AdminPass123!"
    Then the user should successfully access the dashboard
