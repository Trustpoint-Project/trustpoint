@allure.label.epic:Features
@allure.label.suite:R_001_Manage_digital_identities_via_TPC_Web
@allure.label.package:R_001_Manage_digital_identities_via_TPC_Web
Feature: Manage digital identities via TPC_Web
  As an admin user
  I want to create, view, edit, and delete digital identities
  So that I can manage trusted identities effectively through the web interface.

  Background:
    Given the admin user is logged into TPC_Web

  Scenario Outline: Create a new identity
    When the admin navigates to the "Create Identity" page
    And the admin fills in the identity details with <name> and <identifier>
    And the admin submits the form
    Then the system should display a confirmation message
    And the new identity <name> with <identifier> should appear in the identity list

    Examples:
      | name         | identifier |
      | AliceID      | ID1234     |
      | BobID        | ID5678     |

  Scenario Outline: View an existing identity
    Given the identity <name> with <identifier> exists
    When the admin navigates to the identity details page for <name>
    Then the system should display the correct details for <name> and <identifier>

    Examples:
      | name         | identifier |
      | AliceID      | ID1234     |
      | BobID        | ID5678     |

  Scenario Outline: Edit an existing identity
    Given the identity <old_name> with <old_identifier> exists
    When the admin navigates to the identity details page for <old_name>
    And the admin updates the name to <new_name> and identifier to <new_identifier>
    And the admin saves the changes
    Then the system should display a confirmation message
    And the updated identity <new_name> with <new_identifier> should appear in the identity list

    Examples:
      | old_name     | old_identifier | new_name      | new_identifier |
      | AliceID      | ID1234         | AliceUpdated  | ID5678         |
      | BobID        | ID5678         | BobUpdated    | ID9101         |

  Scenario Outline: Delete an existing identity
    Given the identity <name> with <identifier> exists
    When the admin navigates to the identity details page for <name>
    And the admin deletes the identity with the name <name>
    Then the system should display a confirmation message
    And the identity <name> should no longer appear in the identity list

    Examples:
      | name         | identifier |
      | AliceUpdated | ID5678     |
      | BobUpdated   | ID9101     |

  Scenario: Handle non-existent identities
    When the admin attempts to view the details of a non-existent identity "NonExistentID"
    Then the system should display an error message stating "Identity not found"
