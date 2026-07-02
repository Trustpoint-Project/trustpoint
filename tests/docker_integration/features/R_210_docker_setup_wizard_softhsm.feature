@allure.label.epic:Features
@allure.label.suite:R_210_Docker_Setup_Wizard_SoftHSM
@allure.label.package:R_210_Docker_Setup_Wizard_SoftHSM
Feature: Docker Setup Wizard with SoftHSM
  As a new user deploying Trustpoint with PKCS#11 storage
  I want to complete the setup wizard against SoftHSM
  So that HSM-backed bootstrap and managed-key operations are covered in CI

  Scenario: Complete initial setup wizard with SoftHSM storage
    Given a fresh Trustpoint Docker container is running
    When the user accesses the setup wizard
    Then the wizard should be at the setup mode step
    When the user clicks "Setup Trustpoint from Scratch"
    Then the wizard should be at the superuser creation step
    When the user creates a superuser with username "admin" and password "R210SetupPass47!Copper"
    Then the wizard should be at the database setup step
    When the user submits the database form with default values
    Then the wizard should be at the crypto storage setup step
    When the user selects "HSM Storage" as crypto storage
    And the user submits the form
    Then the wizard should be at the backend config step
    When the user submits the SoftHSM backend form
    Then the wizard should be at the demo data step
    When the user selects "Yes" for demo data
    And the user submits the form
    Then the wizard should be at the TLS server credential selection step
    When the user selects "Generate credential" as the TLS mode
    And the user submits the SAN form with default values
    Then the wizard should be at the summary step
    When the user clicks "Apply and Continue"
    And the user waits for the server to restart
    Then the user should be redirected to the login page
    When the user logs in with username "admin" and password "R210SetupPass47!Copper"
    Then the setup should be complete
    And the user should successfully access the dashboard

    When the user navigates to "/management/backend-configuration/"
    Then the page should load without errors
    And the page should contain "PKCS#11"
