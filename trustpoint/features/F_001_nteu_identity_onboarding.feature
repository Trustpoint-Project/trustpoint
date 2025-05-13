@allure.label.epic:Features
@allure.label.suite:F_001_NTEU_Identity_Management_and_Zero-Touch_Onboarding
@allure.label.package:F_001_NTEU_Identity_Management_and_Zero-Touch_Onboarding
Feature: NTEU Identity Management and Zero-Touch Onboarding
  NTEU must be able to log in to the TPC_Web app and perform identity management (R_001) and zero-touch onboarding (R_002).

  Background:
    Given the TPC_Web application is running

  Scenario Outline: NTEU logs into the system
    Given the user is an NTEU with username <username> and password <password>
    When the user attempts to log in
    Then login should be <login_outcome>

    Examples:
      | username     | password   | login_outcome |
      | valid_user   | correct_pw | successful    |
      | invalid_user | wrong_pw   | failed        |

  Scenario: NTEU creates a digital identity
    Given the NTEU is logged in
    When the NTEU navigates to the identity creation page
    And the NTEU enters valid identity details
    And submits the form
    Then the identity should be successfully created

  Scenario: NTEU views an existing digital identity
    Given the NTEU is logged in
    When the NTEU navigates to the identity list
    And selects an identity
    Then the identity details should be displayed

  Scenario: NTEU edits a digital identity
    Given the NTEU is logged in
    And a digital identity exists
    When the NTEU edits the identity details
    And submits the form
    Then the identity should be updated successfully

  Scenario: NTEU deletes a digital identity
    Given the NTEU is logged in
    And a digital identity exists
    When the NTEU deletes the identity
    Then the identity should be removed

  Scenario: NTEU initiates device onboarding using a zero-touch protocol
    Given the NTEU is logged in
    When the NTEU starts the device onboarding process
    Then the system should automatically use a zero-touch onboarding protocol
    And the onboarding process should complete successfully

  Scenario: UI provides clear feedback to the NTEU
    Given the NTEU is on any action page
    When the NTEU enters invalid information
    Then the system should display a clear error message
    And provide guidance for correction
