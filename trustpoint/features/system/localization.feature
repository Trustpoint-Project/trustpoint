@requirement.R_012
@capability.system
@allure.label.epic:System
@allure.label.suite:Localization
Feature: Localization
  Trustpoint renders the user interface in its supported languages.

  Background:
    Given Trustpoint supports English and German

  Scenario Outline: Login page follows the selected language
    When a user opens the login page using language "<language>"
    Then the response status code is 200
    And the login page is rendered in that language

    Examples:
      | language |
      | English  |
      | German   |
