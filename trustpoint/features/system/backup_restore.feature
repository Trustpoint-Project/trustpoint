@requirement.R_006
@capability.system
@allure.label.epic:System
@allure.label.suite:Backup
Feature: Backup management
  Administrators can trigger Trustpoint database backups through the management interface.

  Background:
    Given the admin user is logged into Trustpoint

  Scenario: Open backup management
    When the admin opens the backup management page
    Then the response status code is 200

  Scenario: Trigger a local database backup
    When the admin creates a local database backup
    Then the response status code is 200
    And the backup service was invoked
