@allure.label.epic:Features
@allure.label.suite:R_103_Domain_Management
@allure.label.package:R_103_Domain_Management
Feature: Manage domains via TPC_Web
  As an admin user
  I want to create, view, edit, and delete domains
  So that I can manage domains effectively through the web interface.

  Background:
    Given the admin user is logged into TPC_Web
    And the issuing ca with unique name "test_CA" with pkcs12 file exist

  Scenario Outline: Add a new domain
    When the admin navigates to the "Add new Domain" page
    And the admin fills in the domain details with <name> and issuing CA "test_CA"
    And the admin clicks on "Add new Domain"
    Then the system should display a confirmation message stating "Successfully created domain"
    And the new domain with <name> and issuing CA "test_CA" should appear in the domain list

    Examples:
      | name    |
      | arburg  |
      | homag   |

  Scenario Outline: Delete an existing domain
    Given a domain <name> with issuing ca "test_CA" exist
    When the admin navigates to the "domain list" page
    And the admin deletes the domain with the name <name>
    Then the system should display a confirmation message stating "Successfully deleted"
    And the domain <name> should no longer appear in the domain list

    Examples:
      | name    |
      | arburg  |
      | homag   |

  Scenario: Handle non-existent domains
    When the admin attempts to view the details of a non-existent domain "NonExistentID"
    Then the system should display an error message
