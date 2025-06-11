@allure.label.epic:Features
@allure.label.suite:R_012_Multi_language_support
@allure.label.package:R_012_Multi_language_support
Feature: Language Selection and Translation
  The system should support multi-language UI options for global usability.

  Background:
    Given the system supports the following languages:
      | language |
      | English  |
      | German   |

  Scenario Outline: Default language selection based on browser settings
    Given a new user accesses the system with browser language <language>
    Then the system should display the UI in <language>

    Examples:
      | language |
      | English  |
      | German   |

  Scenario Outline: User manually selects a different language
    Given a logged-in user
    When the user selects <language> from the language settings
    Then the system should display the UI in <language>

    Examples:
      | language |
      | English  |
      | German   |

  Scenario Outline: Language setting persists after logout
    Given a logged-in user
    When the user selects <language> from the language settings
    and the user logs out and logs back in
    Then the system should display the UI in <language>

    Examples:
      | language |
      | English  |
      | German   |

  Scenario Outline: Verify UI elements are translated correctly
    Given a logged-in user
    When the user selects <language> from the language settings
    Then the system should display the UI in <language>

    Examples:
      | language |
      | English  |
      | German   |
